#!/usr/bin/env python3
"""
Tests for the cairn server. Standard library only — no pytest, no playwright.

    python3 tests/test_server.py

Builds a throwaway vault in a temp directory, starts the real server against
it on a scratch port, and exercises the HTTP surface. Never touches your notes.

These cover the server: auth, path safety, writes, backups, conflicts, TLS.
The browser side (markdown rendering, editor interactions) is NOT covered
here — see CLAUDE.md, "Testing", for what that would take.
"""

import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "notes-server.py")

PASS, FAIL = [], []


def check(label, cond, detail=""):
    (PASS if cond else FAIL).append(label)
    print("  %-48s %s %s" % (label, "ok" if cond else "FAIL", detail))
    return bool(cond)


# --------------------------------------------------------------------------

def make_vault():
    d = tempfile.mkdtemp(prefix="cairn-test-")
    os.makedirs(os.path.join(d, "Notes"))
    os.makedirs(os.path.join(d, "attachments"))
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write("---\ntitle: Readme\ntags: [meta]\nupdated: 2020-01-01\n---\n\n"
                "# Readme\n\nLinks to [[Alpha]].\n")
    with open(os.path.join(d, "Notes", "Alpha.md"), "w") as f:
        f.write("---\ntitle: Alpha\ntags: [x, y]\nupdated: 2020-01-01\n---\n\n"
                "# Alpha\n\nBody text.\n")
    with open(os.path.join(d, "Notes", "Beta.md"), "w") as f:
        f.write("# Beta\n\nNo frontmatter here.\n")
    # bin/ was once in a hardcoded skip list, which silently hid real notes.
    os.makedirs(os.path.join(d, "bin"))
    with open(os.path.join(d, "bin", "Gamma.md"), "w") as f:
        f.write("# Gamma\n\nIn a folder called bin.\n")
    # ...while genuinely hidden directories must still stay out of the listing.
    os.makedirs(os.path.join(d, ".backups"))
    with open(os.path.join(d, ".backups", "Old.md"), "w") as f:
        f.write("# Old\n\nA backup, not a note.\n")
    # node_modules is the one non-hidden directory that stays skipped: a real
    # one carries thousands of package READMEs into the /api/notes payload.
    os.makedirs(os.path.join(d, "node_modules", "leftpad"))
    with open(os.path.join(d, "node_modules", "leftpad", "README.md"), "w") as f:
        f.write("# leftpad\n\nA package readme, not a note.\n")
    # 1x1 png
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
        "890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082")
    with open(os.path.join(d, "attachments", "pic.png"), "wb") as f:
        f.write(png)
    return d


def start(vault, port, extra=()):
    # -u matters: the server's banner is short, so on a pipe it would sit in
    # stdio's buffer and the readline() below would block forever.
    p = subprocess.Popen(
        [sys.executable, "-u", SERVER, "--vault", vault, "--port", str(port),
         "--no-browser"] + list(extra),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    log, token, deadline = [], None, time.time() + 15
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        log.append(line)
        m = re.search(r"token=([A-Za-z0-9_\-]+)", line)
        if m and not token:
            token = m.group(1)
        if "Ctrl-C to stop" in line:
            break
    return p, token, "".join(log)


def client(tls=False):
    """An opener that remembers cookies, like a browser would."""
    jar, handlers = {}, []
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))

    class Jar(urllib.request.BaseHandler):
        def http_response(self, req, resp):
            for k, v in resp.headers.items():
                if k.lower() == "set-cookie":
                    name, _, rest = v.partition("=")
                    jar[name] = rest.split(";")[0]
            return resp

        def http_request(self, req):
            if jar:
                req.add_header("Cookie", "; ".join("%s=%s" % kv for kv in jar.items()))
            return req
        https_response = http_response
        https_request = http_request

    handlers.append(Jar())
    return urllib.request.build_opener(*handlers), jar


def call(op, url, data=None, method=None, headers=None, raw=False):
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with op.open(r, timeout=10) as resp:
            body = resp.read()
            return resp.status, body if raw else body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, body if raw else body.decode("utf-8", "replace")


def form(op, base, token):
    return call(op, base + "/unlock", data=("token=" + token).encode(), method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"})


# --------------------------------------------------------------------------

def test_auth(vault, port):
    print("\nauth")
    p, token, _ = start(vault, port)
    try:
        op, jar = client()
        base = "http://127.0.0.1:%d" % port
        s, b = call(op, base + "/")
        check("locked root serves the unlock page", s == 200 and 'name="token"' in b)
        s, _ = call(op, base + "/api/notes")
        check("api without a session is refused", s == 403)
        s, b = call(op, base + "/unlock", data=b"token=wrong-token", method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("wrong token rejected", "doesn't match" in b)
        check("wrong token sets no cookie", "notes_session" not in jar)
        form(op, base, token)
        check("right token sets the session cookie", jar.get("notes_session") == token)
        s, b = call(op, base + "/api/notes")
        check("session unlocks the api", s == 200)
        s, b = call(op, base + "/")
        check("editor page leaks no token", token not in b)
        s, _ = call(op, base + "/api/notes", headers={"Origin": "https://evil.example"})
        check("cross-origin request refused", s == 403)
        s, _ = call(op, base + "/nope")
        check("unknown endpoint 404s", s == 404)
    finally:
        p.terminate(); p.wait(timeout=5)


def test_read(vault, port):
    print("\nreading")
    p, token, _ = start(vault, port)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        s, b = call(op, base + "/api/notes")
        d = json.loads(b)
        titles = sorted(n["title"] for n in d["notes"])
        check("lists every note", titles == ["Alpha", "Beta", "Gamma", "Readme"], titles)
        check("a folder named bin is not skipped", "bin/Gamma.md" in
              [n["path"] for n in d["notes"]])
        check("hidden directories stay out of the listing", "Old" not in titles)
        check("node_modules stays skipped", "leftpad" not in titles, titles)
        beta = next(n for n in d["notes"] if n["title"] == "Beta")
        check("note without frontmatter falls back to filename", beta["title"] == "Beta")
        alpha = next(n for n in d["notes"] if n["title"] == "Alpha")
        check("parses tags from frontmatter", alpha["tags"] == ["x", "y"], alpha["tags"])
        check("reports the folder", alpha["folder"] == "Notes", alpha["folder"])
        check("finds images", "pic.png" in d["images"])
        s, b = call(op, base + "/media/attachments/pic.png", raw=True)
        check("serves an image", s == 200 and b[:8] == b"\x89PNG\r\n\x1a\n")
        s, _ = call(op, base + "/media/notes/Alpha.md")
        check("refuses non-images from /media", s == 400)
    finally:
        p.terminate(); p.wait(timeout=5)


def test_write(vault, port):
    print("\nwriting")
    p, token, _ = start(vault, port)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        s, b = call(op, base + "/api/notes")
        alpha = next(n for n in json.loads(b)["notes"] if n["title"] == "Alpha")
        original = alpha["raw"]

        body = json.dumps({"path": alpha["path"], "content": original + "\nadded\n",
                           "mtime": alpha["mtime"]}).encode()
        s, b = call(op, base + "/api/note", data=body, method="PUT",
                    headers={"Content-Type": "application/json"})
        disk = open(os.path.join(vault, alpha["path"]), encoding="utf-8").read()
        check("save writes to disk", s == 200 and "added" in disk)
        check("save stamps updated:", "updated: 2020-01-01" not in disk)

        kept = json.loads(b)["backup"]
        check("backup recorded", bool(kept), str(kept))
        check("backup holds the pre-edit version",
              open(os.path.join(vault, kept), encoding="utf-8").read() == original)

        # stale mtime must be refused
        stale = json.dumps({"path": alpha["path"], "content": "clobbered",
                            "mtime": alpha["mtime"]}).encode()
        s, b = call(op, base + "/api/note", data=stale, method="PUT",
                    headers={"Content-Type": "application/json"})
        disk2 = open(os.path.join(vault, alpha["path"]), encoding="utf-8").read()
        check("stale write refused", s == 409 and disk2 == disk)

        # create
        s, b = call(op, base + "/api/new",
                    data=json.dumps({"path": "Notes/Gamma.md", "title": "Gamma"}).encode(),
                    method="POST", headers={"Content-Type": "application/json"})
        check("creates a note", s == 200 and os.path.isfile(os.path.join(vault, "Notes/Gamma.md")))
        s, _ = call(op, base + "/api/new",
                    data=json.dumps({"path": "Notes/Gamma.md", "title": "Gamma"}).encode(),
                    method="POST", headers={"Content-Type": "application/json"})
        check("refuses a duplicate name", s == 409)

        # trash
        s, b = call(op, base + "/api/trash",
                    data=json.dumps({"path": "Notes/Gamma.md"}).encode(),
                    method="POST", headers={"Content-Type": "application/json"})
        moved = json.loads(b).get("trashed", "")
        check("trash moves rather than deletes",
              s == 200
              and not os.path.exists(os.path.join(vault, "Notes/Gamma.md"))
              and os.path.isfile(os.path.join(vault, moved)))
    finally:
        p.terminate(); p.wait(timeout=5)


def test_path_safety(vault, port):
    print("\npath safety")
    p, token, _ = start(vault, port)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        outside = os.path.join(tempfile.gettempdir(), "cairn-escape.md")
        if os.path.exists(outside):
            os.remove(outside)
        for label, path in [
            ("traversal with ..", "../../cairn-escape.md"),
            ("absolute path", "/tmp/cairn-escape.md"),
            ("non-markdown target", "notes-server.py"),
            ("dotdot in the middle", "Notes/../../cairn-escape.md"),
        ]:
            s, _ = call(op, base + "/api/note",
                        data=json.dumps({"path": path, "content": "x"}).encode(),
                        method="PUT", headers={"Content-Type": "application/json"})
            check("rejects %s" % label, s == 400)
        check("nothing was written outside the vault", not os.path.exists(outside))
    finally:
        p.terminate(); p.wait(timeout=5)


def test_tls(vault, port):
    print("\ntls + lan")
    if not shutil.which("openssl"):
        print("  (skipped: openssl not on PATH)")
        return
    p, token, log = start(vault, port, ["--lan", "--tls"])
    try:
        check("prints a cert fingerprint", "fingerprint" in log.lower())
        check("no plaintext warning when tls is on", "PLAIN HTTP ON THE NETWORK" not in log)
        key = os.path.join(vault, ".certs", "server.key")
        check("private key is mode 600", os.path.exists(key)
              and oct(os.stat(key).st_mode)[-3:] == "600")
        op, _ = client(tls=True)
        base = "https://127.0.0.1:%d" % port
        form(op, base, token)
        s, _ = call(op, base + "/api/notes")
        check("api works over tls", s == 200)
    finally:
        p.terminate(); p.wait(timeout=5)

    p, token, log = start(vault, port + 1, ["--lan"])
    try:
        check("warns loudly on plaintext lan", "PLAIN HTTP ON THE NETWORK" in log)
    finally:
        p.terminate(); p.wait(timeout=5)


# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# The terminal endpoint. No window is ever opened here: $CAIRN_TERMINAL points
# the server at a shim that records what it was asked to launch. The last check
# then runs the real rcfile under a pty and proves the command is typed rather
# than executed, which is the whole promise of the feature.

SHIM = """#!/bin/bash
{ echo "argv: $*"; echo "cwd: $PWD"; echo "cmd: $CAIRN_CMD"; } > "$CAIRN_RECORD"
for a in "$@"; do
  [ -f "$a" ] && cp "$a" "$CAIRN_RECORD.rc"   # the rcfile deletes itself; keep a copy
done
"""


def wait_for(path, seconds=5):
    """The server launches the terminal and answers; the shim writes a moment
    later. Every check below reads that file, so wait for it to land."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        if os.path.exists(path) and os.path.getsize(path):
            time.sleep(0.1)
            return True
        time.sleep(0.05)
    return False


def typed_not_run(rc, command, home):
    """Drive bash with the real rcfile through a pty. Returns what got typed."""
    import fcntl
    import pty
    import select
    import struct
    import termios
    env = dict(os.environ, CAIRN_CMD=command, CAIRN_RC_DIR=os.path.join(home, "gone"),
               HOME=home, TERM="xterm", PS1="$ ")
    pid, fd = pty.fork()
    if pid == 0:                                    # child: the shell under test
        os.execvpe("bash", ["bash", "--rcfile", rc, "-i"], env)
    # Wide window: readline wraps what it types at the terminal width, and a
    # wrapped line would look like a different string to the check below.
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 400, 0, 0))
    buf, deadline = b"", time.time() + 6
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd not in r:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if b"\x1b[5n" in chunk:                     # play the terminal emulator
            os.write(fd, b"\x1b[0n")
    try:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    except OSError:
        pass
    os.close(fd)
    return buf.decode("utf-8", "replace")


def test_terminal(vault, port):
    print("\nopen in terminal")
    shim = os.path.join(vault, "fake-terminal")
    record = os.path.join(vault, "launched.txt")
    home = os.path.join(vault, "home")
    os.makedirs(home, exist_ok=True)
    with open(shim, "w") as f:
        f.write(SHIM)
    os.chmod(shim, 0o755)
    os.environ["CAIRN_TERMINAL"] = shim
    os.environ["CAIRN_RECORD"] = record

    p, token, _ = start(vault, port, ["--terminal-cwd", vault])
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        url = base + "/api/terminal"
        hdr = {"Content-Type": "application/json"}

        s, _ = call(op, url, data=b'{"command":"echo hi"}', method="POST", headers=hdr)
        check("terminal endpoint needs a session", s == 403)
        check("nothing launched while locked", not os.path.exists(record))

        form(op, base, token)
        s, b = call(op, base + "/api/notes")
        check("capability advertised to the client", json.loads(b)["terminal"] is True)

        # A note is just text, and text can be hostile. This one tries to break
        # out of the quoting and run something; it must arrive as characters.
        nasty = 'foo"; touch %s/PWNED; echo "' % vault
        s, b = call(op, url, data=json.dumps({"command": nasty}).encode(),
                    method="POST", headers=hdr)
        check("opens a terminal", s == 200 and json.loads(b)["ok"] is True)
        check("the emulator was actually launched", wait_for(record))
        rec = open(record).read() if os.path.exists(record) else ""
        check("launched at the requested directory", ("cwd: " + vault) in rec)
        check("starts an interactive shell, runs no command", "bash --rcfile" in rec
              and "-i" in rec and "-c" not in rec)
        check("command travels in the environment, not argv",
              ("cmd: " + nasty) in rec and nasty not in rec.split("cmd:")[0])
        rc = record + ".rc"
        body = open(rc).read() if os.path.exists(rc) else ""
        check("command is not written into the rcfile", bool(body) and nasty not in body)
        check("rcfile deleted itself from /tmp", not os.path.isdir("/tmp/cairn-term-x"))

        s, _ = call(op, url, data=b'{"command":"   "}', method="POST", headers=hdr)
        check("empty command refused", s == 400)
        s, _ = call(op, url, data=b'{"nope":1}', method="POST", headers=hdr)
        check("malformed body refused", s == 400)

        # The load-bearing one: run that same rcfile for real.
        out = typed_not_run(rc, nasty, home)
        check("hostile command is typed, not run", not os.path.exists(vault + "/PWNED"))
        check("hostile command arrives verbatim", nasty in re.sub(r"[\r\n]", "", out))
        out = typed_not_run(rc, "cd /tmp\nls -la", home)
        check("multi-line block lands as one buffer",
              "cd /tmp" in out and "ls -la" in out and "total " not in out)
    finally:
        p.terminate(); p.wait(timeout=5)
        for f in (record, record + ".rc"):
            if os.path.exists(f):
                os.remove(f)

    p, token, _ = start(vault, port, ["--no-terminal"])
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        s, _ = call(op, base + "/api/terminal", data=b'{"command":"echo hi"}',
                    method="POST", headers={"Content-Type": "application/json"})
        check("--no-terminal refuses the endpoint", s == 403)
        s, b = call(op, base + "/api/notes")
        check("--no-terminal hides the button", json.loads(b)["terminal"] is False)
        check("--no-terminal launched nothing", not os.path.exists(record))
    finally:
        p.terminate(); p.wait(timeout=5)
        os.environ.pop("CAIRN_TERMINAL", None)
        os.environ.pop("CAIRN_RECORD", None)


def main():
    if not os.path.isfile(SERVER):
        sys.exit("notes-server.py not found next to tests/ — run from the repo")
    vault = make_vault()
    print("temp vault: %s" % vault)
    try:
        test_auth(vault, 8931)
        test_read(vault, 8932)
        test_write(vault, 8933)
        test_path_safety(vault, 8934)
        test_tls(vault, 8935)
        test_terminal(vault, 8936)
    finally:
        shutil.rmtree(vault, ignore_errors=True)

    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
