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

# Every server in these tests gets $XDG_STATE_HOME pointed here, so backups,
# trash, certs and sync.json never land in the real ~/.local/state/cairn.
STATE = None


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
    os.makedirs(os.path.join(d, ".obsidian"))
    with open(os.path.join(d, ".obsidian", "Old.md"), "w") as f:
        f.write("# Old\n\nEditor config, not a note.\n")
    # An older cairn wrote these inside the vault. The first start moves them
    # out — test_state checks that, and runs before anything else does.
    os.makedirs(os.path.join(d, ".backups", "Notes"))
    with open(os.path.join(d, ".backups", "Notes", "Alpha.20200101-000000.md"), "w") as f:
        f.write("# Alpha\n\nAn old version.\n")
    os.makedirs(os.path.join(d, ".trash"))
    with open(os.path.join(d, ".trash", "Gone.20200101-000000.md"), "w") as f:
        f.write("# Gone\n\nDeleted once.\n")
    os.makedirs(os.path.join(d, ".certs"))
    with open(os.path.join(d, ".certs", "server.key"), "w") as f:
        # Not key-shaped on purpose: the repo's commit hook scans for that.
        f.write("stand-in for a key the old cairn left in the vault\n")
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


def start(vault, port, extra=(), env=None):
    if env is None:
        env = dict(os.environ, XDG_STATE_HOME=STATE)
    # -u matters: the server's banner is short, so on a pipe it would sit in
    # stdio's buffer and the readline() below would block forever.
    p = subprocess.Popen(
        [sys.executable, "-u", SERVER, "--vault", vault, "--port", str(port),
         "--no-browser"] + list(extra),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        env=env)
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


def state_dir(log):
    """The state directory the server announced in its banner."""
    m = re.search(r"(?m)^  state : (.+)$", log)
    return m.group(1).strip() if m else ""


def outside(path, vault):
    return bool(path) and os.path.isabs(path) and \
        not os.path.abspath(path).startswith(os.path.abspath(vault) + os.sep)


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

def test_state(vault, port):
    print("\nstate directory")
    p, token, log = start(vault, port)
    try:
        state = state_dir(log)
        check("state dir is outside the vault", outside(state, vault), state)
        check("state dir is under $XDG_STATE_HOME/cairn",
              state.startswith(os.path.join(STATE, "cairn") + os.sep))
        check("state dir is not world-readable",
              os.path.isdir(state) and oct(os.stat(state).st_mode)[-3:] == "700")
        # Migration of a pre-state-dir vault.
        check("old .backups/ moved out of the vault",
              not os.path.exists(os.path.join(vault, ".backups"))
              and os.path.isfile(os.path.join(state, "backups", "Notes",
                                              "Alpha.20200101-000000.md")))
        check("old .trash/ moved out of the vault",
              not os.path.exists(os.path.join(vault, ".trash"))
              and os.path.isfile(os.path.join(state, "trash", "Gone.20200101-000000.md")))
        check("old .certs/ (the private key) moved out of the vault",
              not os.path.exists(os.path.join(vault, ".certs"))
              and os.path.isfile(os.path.join(state, "certs", "server.key")))
        check("migration is announced", ".backups -> " in log and ".certs -> " in log)
        # A fake key must not be trusted by --tls later on.
        os.remove(os.path.join(state, "certs", "server.key"))
    finally:
        p.terminate(); p.wait(timeout=5)

    # A second vault at another path must not share the first one's state.
    other = tempfile.mkdtemp(prefix="cairn-test-other-")
    with open(os.path.join(other, "One.md"), "w") as f:
        f.write("# One\n")
    p, _, log2 = start(other, port)
    try:
        check("another vault gets its own state dir",
              state_dir(log2) and state_dir(log2) != state)
    finally:
        p.terminate(); p.wait(timeout=5)
        shutil.rmtree(other, ignore_errors=True)

    # --state-dir: refused where it would be listed as notes, allowed hidden.
    p, _, log3 = start(vault, port, ["--state-dir", os.path.join(vault, "state")])
    p.wait(timeout=5)
    check("--state-dir visible inside the vault is refused",
          p.returncode != 0 and "not hidden" in log3)
    hidden = os.path.join(vault, ".cairn")
    p, _, log4 = start(vault, port, ["--state-dir", hidden])
    try:
        check("--state-dir under a dot-directory in the vault is allowed",
              p.returncode is None and state_dir(log4) == hidden)
        check("in-vault state dir migrates nothing",
              os.path.isfile(os.path.join(state, "trash", "Gone.20200101-000000.md")))
    finally:
        p.terminate(); p.wait(timeout=5)
        shutil.rmtree(hidden, ignore_errors=True)
    p, _, log5 = start(vault, port, ["--state-dir", os.path.dirname(vault)])
    p.wait(timeout=5)
    check("--state-dir containing the vault is refused",
          p.returncode != 0 and "contains the vault" in log5)


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
        check("backup lives outside the vault", outside(kept, vault), str(kept))
        check("backup holds the pre-edit version",
              open(kept, encoding="utf-8").read() == original)

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
              and os.path.isfile(moved))
        check("trash lives outside the vault", outside(moved, vault), moved)
        check("trash keeps the note's folder",
              os.path.basename(os.path.dirname(moved)) == "Notes"
              and os.path.basename(moved).startswith("Gamma."))
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
        key = os.path.join(state_dir(log), "certs", "server.key")
        check("private key is outside the vault", outside(key, vault), key)
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


def test_sync(vault, port):
    print("\nsync command")

    # Point the server's state file at a scratch directory. Without this the
    # test would overwrite the real ~/.local/state/cairn/sync.json.
    state = tempfile.mkdtemp(prefix="cairn-test-state-")
    env = dict(os.environ, XDG_STATE_HOME=state)
    marker = os.path.join(state, "ran.txt")

    good = os.path.join(state, "sync-ok.sh")
    with open(good, "w") as f:
        f.write("#!/bin/sh\n"
                "echo \"argc=$#\" > %s\n"
                "echo \"args=$*\" >> %s\n"
                "echo \"cwd=$PWD\" >> %s\n"
                "echo synced\n" % (marker, marker, marker))
    os.chmod(good, 0o755)

    bad = os.path.join(state, "sync-bad.sh")
    with open(bad, "w") as f:
        f.write("#!/bin/sh\necho 'it went wrong' >&2\nexit 3\n")
    os.chmod(bad, 0o755)

    # --- off unless asked for ------------------------------------------
    p, token, _ = start(vault, port, env=env)
    try:
        op, _jar = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        code, body = call(op, base + "/api/sync", data=b"", method="POST")
        check("POST /api/sync is 404 without --sync-cmd", code == 404, code)
        code, body = call(op, base + "/api/sync/status")
        check("status reports disabled without --sync-cmd",
              code == 200 and json.loads(body)["sync"]["enabled"] is False)
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- refuses a command it cannot run, at startup --------------------
    p, token, log = start(vault, port, extra=("--sync-cmd", os.path.join(state, "nope.sh")),
                          env=env)
    p.wait(timeout=10)
    check("exits when --sync-cmd is missing", p.returncode != 0)

    plain = os.path.join(state, "not-exec.sh")
    with open(plain, "w") as f:
        f.write("#!/bin/sh\ntrue\n")
    os.chmod(plain, 0o644)
    p, token, log = start(vault, port, extra=("--sync-cmd", plain), env=env)
    p.wait(timeout=10)
    check("exits when --sync-cmd is not executable", p.returncode != 0)

    # --- enabled -------------------------------------------------------
    p, token, _ = start(vault, port, extra=("--sync-cmd", good), env=env)
    try:
        op, _jar = client()
        base = "http://127.0.0.1:%d" % port

        # Auth first: this route runs a subprocess, so it must be behind the
        # token like everything else.
        code, _ = call(op, base + "/api/sync", data=b"", method="POST")
        check("POST /api/sync refused when locked", code == 403, code)
        code, _ = call(op, base + "/api/sync/status")
        check("sync status refused when locked", code == 403, code)

        form(op, base, token)

        # The request body is attacker-shaped: if any of it reached the
        # command line, argc would not be 0.
        payload = json.dumps({"cmd": "rm -rf /", "args": ["--delete"],
                              "path": "; touch /tmp/pwned"}).encode()
        code, body = call(op, base + "/api/sync", data=payload, method="POST",
                          headers={"Content-Type": "application/json"})
        ok = code == 200 and json.loads(body)["sync"]["ok"] is True
        check("sync runs the configured command", ok, code)

        ran = open(marker).read() if os.path.isfile(marker) else ""
        check("the command actually ran", "cwd=" in ran)
        check("no arguments from the request reach it", "argc=0" in ran, ran.split("\n")[0])
        # $PWD on a Mac is /private/var/..., the resolved form of the temp dir.
        check("it runs in the vault",
              "cwd=%s" % vault in ran or "cwd=%s" % os.path.realpath(vault) in ran)

        code, body = call(op, base + "/api/sync/status")
        st = json.loads(body)["sync"]
        check("status reports enabled", st["enabled"] is True)
        check("status records the last run", bool(st["last"]) and st["last"]["ok"] is True)
        check("status has no next run without --sync-timer", st["next"] is None)
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- a failing script is reported, not swallowed --------------------
    p, token, _ = start(vault, port, extra=("--sync-cmd", bad), env=env)
    try:
        op, _jar = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        code, body = call(op, base + "/api/sync", data=b"", method="POST")
        rec = json.loads(body)["sync"]
        check("a failing sync still answers 200", code == 200, code)
        check("a failing sync is marked not ok", rec["ok"] is False)
        check("the exit code is passed through", rec["code"] == 3, rec["code"])
        check("its output is kept for the user", "went wrong" in rec["output"])
    finally:
        p.terminate(); p.wait(timeout=5)

    shutil.rmtree(state, ignore_errors=True)


# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# The terminal endpoint. No window is ever opened here: the server is pointed
# at a shim that records what it was asked to launch. On Linux $CAIRN_TERMINAL
# names that shim; on macOS the terminal is an application reached through
# `open`, so $CAIRN_TERMINAL (an app name there) can't be a script -- instead a
# fake `open` shadows the real one on PATH. Either way the shim writes the same
# record. The pty checks then run the real launcher script and prove the
# command is typed rather than executed, which is the whole promise.

SHIM = """#!/bin/bash
{ echo "argv: $*"; echo "cwd: $PWD"; echo "env-cmd: ${CAIRN_CMD-none}"; } > "$CAIRN_RECORD"
for a in "$@"; do
  [ -f "$a" ] && cp -R "$(dirname "$a")" "$CAIRN_RECORD.dir"   # it deletes itself later
done
"""


def load_server():
    """Import notes-server.py, for the few things worth checking without HTTP."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("cairn_server", SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def launch(op, url, command, record):
    """Ask the server to open a terminal; return what the shim caught."""
    for f in (record, record + ".dir"):
        shutil.rmtree(f, ignore_errors=True) if os.path.isdir(f) else None
        if os.path.isfile(f):
            os.remove(f)
    s, b = call(op, url, data=json.dumps({"command": command}).encode(), method="POST",
                headers={"Content-Type": "application/json"})
    deadline = time.time() + 5
    while time.time() < deadline:
        if os.path.exists(record) and os.path.getsize(record):
            time.sleep(0.1)
            break
        time.sleep(0.05)
    rec = open(record).read() if os.path.exists(record) else ""
    argv = rec.split("\n")[0][len("argv: "):].split() if rec else []
    return s, rec, (argv[-1] if argv else ""), record + ".dir"


def typed_not_run(launcher, home):
    """Run the launcher the emulator was given, through a pty, as the emulator
    would. Returns everything the shell drew on the screen."""
    import fcntl
    import pty
    import select
    import struct
    import termios
    env = dict(os.environ, HOME=home, TERM="xterm", PS1="$ ")
    env.pop("CAIRN_CMD", None)                      # nothing may depend on it
    pid, fd = pty.fork()
    if pid == 0:                                    # child: the shell under test
        os.execvpe(launcher, [launcher], env)
    # Wide window: readline wraps what it types at the terminal width, and a
    # wrapped line would look like a different string to the checks below.
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
    record = os.path.join(vault, "launched.txt")
    home = os.path.join(vault, "home")
    os.makedirs(home, exist_ok=True)
    os.environ["CAIRN_RECORD"] = record

    mac = sys.platform == "darwin"
    saved_path = os.environ["PATH"]
    if mac:
        fakebin = os.path.join(vault, "fakebin")
        os.makedirs(fakebin, exist_ok=True)
        shim = os.path.join(fakebin, "open")
        os.environ.pop("CAIRN_TERMINAL", None)          # server resolves "Terminal"
        os.environ["PATH"] = fakebin + os.pathsep + saved_path
    else:
        shim = os.path.join(vault, "fake-terminal")
        os.environ["CAIRN_TERMINAL"] = shim
    with open(shim, "w") as f:
        f.write(SHIM)
    os.chmod(shim, 0o755)

    mod = load_server()
    check("macOS opens an app rather than running a binary",
          mod.terminal_argv("Terminal", None, "/tmp/t/launch", "/home/u")
          == ["open", "-a", "Terminal", "/tmp/t/launch"])
    check("elsewhere the emulator is given the launcher",
          mod.terminal_argv("konsole", ["--workdir", "{cwd}", "-e"], "/tmp/t/launch", "/home/u")
          == ["konsole", "--workdir", "/home/u", "-e", "/tmp/t/launch"])
    rc_name = mod.shell_parts()[0]                      # "rc.bash" or ".zshrc"

    # The window has to come up as the user's own, which means reading the file
    # the platform's terminal would have read. A Mac running bash keeps its
    # prompt and its PATH in ~/.bash_profile, never in the ~/.bashrc a Linux
    # emulator reads. Marking that file proves the right one was loaded.
    user_rc = ".zshrc" if rc_name == ".zshrc" else (".bash_profile" if mac else ".bashrc")
    with open(os.path.join(home, user_rc), "w") as f:
        f.write("PS1='cairn-prompt$ '\n")

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
        s, rec, launcher, copied = launch(op, url, nasty, record)
        cwds = ("cwd: " + vault, "cwd: " + os.path.realpath(vault))
        check("opens a terminal", s == 200)
        check("the emulator was actually launched", bool(rec))
        check("launched at the requested directory", any(c in rec for c in cwds))
        check("emulator is given the launcher script", launcher.endswith("/launch"))
        check("command is not in the emulator's argv", nasty not in rec.split("\n")[0])
        check("command is not in the environment either", "env-cmd: none" in rec)

        body = {f: open(os.path.join(copied, f)).read() for f in os.listdir(copied)}
        exec_line = body["launch"].strip().splitlines()[-1]
        check("launcher runs an interactive shell, no command",
              exec_line.startswith("exec ") and " -c " not in body["launch"]
              and (exec_line.endswith(" -i") or exec_line.endswith(" -il")))
        check("launcher starts in the requested directory",
              ("cd " + vault) in body["launch"]
              or ("cd " + os.path.realpath(vault)) in body["launch"])
        check("command lives in its own file, verbatim", body["cmd"] == nasty)
        check("command is not written into the rcfile", nasty not in body[rc_name])
        check("nothing is left world-readable",
              all(oct(os.stat(os.path.join(copied, f)).st_mode)[-3:] in ("600", "700")
                  for f in body))

        # The load-bearing one: run that launcher exactly as konsole would.
        out = typed_not_run(launcher, home)
        check("hostile command is typed, not run", not os.path.exists(vault + "/PWNED"))
        check("hostile command arrives verbatim", nasty in re.sub(r"[\r\n]", "", out))
        check("the shell cleaned up after itself", not os.path.isdir(os.path.dirname(launcher)))
        check("the window loads the user's own " + user_rc, "cairn-prompt$" in out)

        s, _, launcher, _ = launch(op, url, "cd /tmp\nls -la", record)
        out = typed_not_run(launcher, home)
        check("multi-line block lands as one buffer",
              "cd /tmp" in out and "ls -la" in out and "total " not in out)

        s, _ = call(op, url, data=b'{"command":"   "}', method="POST", headers=hdr)
        check("empty command refused", s == 400)
        s, _ = call(op, url, data=b'{"nope":1}', method="POST", headers=hdr)
        check("malformed body refused", s == 400)
    finally:
        p.terminate(); p.wait(timeout=5)
        shutil.rmtree(record + ".dir", ignore_errors=True)
        if os.path.exists(record):
            os.remove(record)

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
        os.environ["PATH"] = saved_path


def main():
    if not os.path.isfile(SERVER):
        sys.exit("notes-server.py not found next to tests/ — run from the repo")
    global STATE
    vault = make_vault()
    STATE = tempfile.mkdtemp(prefix="cairn-test-state-")
    print("temp vault: %s" % vault)
    try:
        test_state(vault, 8930)
        test_auth(vault, 8931)
        test_read(vault, 8932)
        test_write(vault, 8933)
        test_path_safety(vault, 8934)
        test_tls(vault, 8935)
        test_terminal(vault, 8936)
        test_sync(vault, 8937)
    finally:
        shutil.rmtree(vault, ignore_errors=True)
        shutil.rmtree(STATE, ignore_errors=True)

    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
