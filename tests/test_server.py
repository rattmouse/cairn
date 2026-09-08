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
    finally:
        shutil.rmtree(vault, ignore_errors=True)

    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
