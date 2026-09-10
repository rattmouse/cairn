#!/usr/bin/env python3
"""
Tests for the cairn server. Standard library only — no pytest, no playwright.

    python3 tests/test_server.py

Builds a throwaway vault in a temp directory, starts the real server against
it on a scratch port, and exercises the HTTP surface. Never touches your notes.

These cover the server: auth, path safety, writes, the git repository cairn
keeps them in, conflicts, TLS.
The browser side (markdown rendering, editor interactions) is NOT covered
here — see CLAUDE.md, "Testing", for what that would take.
"""

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
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


def git(vault, *args):
    """One git command in a test vault, as a stripped string."""
    p = subprocess.run(("git", "-C", vault) + args, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    return p.stdout.strip()


def git_init(path, email="t@example.com", name="Test"):
    for args in (("init", "-q", "-b", "main"), ("config", "user.email", email),
                 ("config", "user.name", name)):
        git(path, *args)


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

        # History is git now, not .backups/ — the commit is checked in
        # test_git; here it is enough that the save reports the sha it made.
        sha = json.loads(b).get("commit")
        check("save reports the commit it made", bool(sha), str(sha))
        check("nothing is written to a backups directory",
              not os.path.isdir(os.path.join(vault, ".backups")))

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
        check("the removal is committed too",
              json.loads(b).get("uncommitted") is None
              and git(vault, "log", "-1", "--format=%s") == "Delete Gamma",
              git(vault, "log", "-1", "--format=%s"))
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


def san(cert):
    """subjectAltName entries of a cert on disk, in openssl's display form.

    Parsed here rather than by importing the server's own parser, so that a
    bug in that parser cannot make these checks agree with it.
    """
    out = subprocess.run(["openssl", "x509", "-in", cert, "-noout",
                          "-ext", "subjectAltName"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         text=True).stdout
    # Drop the "X509v3 Subject Alternative Name:" header the values follow.
    out = out.split("Name:", 1)[-1]
    return {p.strip() for p in out.replace("\n", " ").split(",") if ":" in p}


def server_fn(name, *args):
    """Call one function from notes-server.py in a fresh interpreter.

    The module has a hyphen in its name and starts a server at import time
    only under __main__, so importlib is both necessary and safe here.
    """
    code = ("import importlib.util as u;"
            "s=u.spec_from_file_location('ns',%r);m=u.module_from_spec(s);"
            "s.loader.exec_module(m);print(repr(m.%s(*%r)))" % (SERVER, name, args))
    return eval(subprocess.run([sys.executable, "-c", code],
                               stdout=subprocess.PIPE, text=True).stdout.strip())


def test_cert_names(vault, port):
    print("\ntls certificate names")
    if not shutil.which("openssl"):
        print("  (skipped: openssl not on PATH)")
        return

    # An explicit --state-dir so the cert's path is known before the server
    # has printed its banner.
    sd = tempfile.mkdtemp(prefix="cairn-test-certstate-", dir=STATE)
    certs = os.path.join(sd, "certs")
    cert = os.path.join(certs, "server.crt")
    tls = ["--lan", "--tls", "--state-dir", sd]

    # A VPN tunnel and a libvirt bridge are both addresses this machine really
    # has and neither is one another device can reach. Pinning the cert to one
    # is the bug this whole test exists for.
    every = server_fn("enumerate_ipv4")
    offered = server_fn("lan_ips")
    check("enumerates more than loopback", any(i != "lo" for i, _ in every)
          or not every, str(every))
    check("loopback is never offered as a lan address",
          not [a for a in offered if a.startswith("127.")], str(offered))
    virtual = [ip for i, ip in every
               if i.startswith(("virbr", "vnet", "docker", "veth", "br-",
                                "tun", "tap", "wg", "proton", "utun"))
               and not ip.startswith("127.")]
    check("virtual and tunnel interfaces are excluded",
          not (set(virtual) & set(offered)),
          "virtual=%s offered=%s" % (virtual, offered))

    shutil.rmtree(certs, ignore_errors=True)
    p, token, log = start(vault, port, tls)
    try:
        got = san(cert)
        check("cert covers loopback", "IP Address:127.0.0.1" in got, str(got))
        check("cert covers localhost", "DNS:localhost" in got, str(got))
        host = socket.gethostname().split(".")[0]
        check("cert covers the mDNS name", "DNS:%s.local" % host in got, str(got))
        check("cert covers no tunnel or bridge address",
              not {"IP Address:%s" % ip for ip in virtual} & got,
              "virtual=%s san=%s" % (virtual, got))
        for ip in offered:
            check("cert covers the real lan address %s" % ip,
                  "IP Address:%s" % ip in got, str(got))
        check("banner offers the mDNS url", ".local:%d" % port in log)
    finally:
        p.terminate(); p.wait(timeout=5)

    # The cache-forever bug: a cert that no longer covers this machine used to
    # be reused verbatim, so a VPN-pinned cert stayed broken across restarts.
    before = open(cert).read()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", os.path.join(certs, "server.key"), "-out", cert,
                    "-days", "1", "-subj", "/CN=notes-server",
                    "-addext", "subjectAltName=IP:203.0.113.9"],
                   check=True, capture_output=True)
    p, token, log = start(vault, port + 1, tls)
    try:
        check("regenerates a cert that stopped fitting", "regenerating" in log)
        check("says the old trust is void", "trust this one" in log)
        got = san(cert)
        check("the replacement covers loopback again",
              "IP Address:127.0.0.1" in got, str(got))
    finally:
        p.terminate(); p.wait(timeout=5)

    # A cert that already fits must be left alone -- regenerating on every
    # start would void the trust the user set up on each device.
    kept = open(cert).read()
    p, token, log = start(vault, port + 2, tls)
    try:
        check("a cert that still fits is reused",
              open(cert).read() == kept and "regenerating" not in log,
              "unchanged=%s regenerated=%s" % (open(cert).read() == kept,
                                               "regenerating" in log))
    finally:
        p.terminate(); p.wait(timeout=5)


def test_token_persists(vault, port):
    """The token has to outlive the process.

    When it was generated per start, every restart logged out every device
    and the token had to be retyped on the phone. These check both halves:
    that it comes back, and that --new-token can still throw it away.
    """
    print("\ntoken across restarts")
    sd = tempfile.mkdtemp(prefix="cairn-test-token-", dir=STATE)
    # --lan because the "stays paired" note is addressed to other devices,
    # and so is printed with the rest of the other-device instructions.
    keep = ["--lan", "--state-dir", sd]
    tokenfile = os.path.join(sd, "token")

    p, first, log = start(vault, port, keep)
    try:
        check("a token is issued", bool(first))
        check("the token is saved in the state dir", os.path.isfile(tokenfile))
        check("the token file is mode 600", os.path.exists(tokenfile)
              and oct(os.stat(tokenfile).st_mode)[-3:] == "600")
        check("the token file is outside the vault", outside(tokenfile, vault))
    finally:
        p.terminate(); p.wait(timeout=5)

    p, second, log = start(vault, port + 1, keep)
    try:
        check("the same token comes back after a restart", second == first,
              "%s vs %s" % (second, first))
        check("the banner says the pairing survives", "stays paired" in log)
        # The point of all this: a device that pasted the old token is still
        # unlocked, without anyone reading the terminal again.
        op, _ = client()
        base = "http://127.0.0.1:%d" % (port + 1)
        code, _ = form(op, base, first)
        s2, _ = call(op, base + "/api/notes")
        check("the token from the previous run still unlocks", s2 == 200, str(s2))
    finally:
        p.terminate(); p.wait(timeout=5)

    p, third, log = start(vault, port + 2, keep + ["--new-token"])
    try:
        check("--new-token issues a different one", third and third != first)
        check("--new-token is what is now on disk",
              open(tokenfile).read().strip() == third)
        op, _ = client()
        base = "http://127.0.0.1:%d" % (port + 2)
        form(op, base, first)
        s2, _ = call(op, base + "/api/notes")
        check("the old token is dead after --new-token", s2 == 403, str(s2))
    finally:
        p.terminate(); p.wait(timeout=5)


def test_cert_download(vault, port):
    """/cert exists so a phone can install the certificate.

    Unauthenticated on purpose -- it is the same public certificate the TLS
    handshake already hands out. The test that matters is the one below it:
    the private key must not come with it.
    """
    print("\ncertificate download")
    if not shutil.which("openssl"):
        print("  (skipped: openssl not on PATH)")
        return
    sd = tempfile.mkdtemp(prefix="cairn-test-certdl-", dir=STATE)
    cert = os.path.join(sd, "certs", "server.crt")

    p, token, log = start(vault, port, ["--lan", "--tls", "--state-dir", sd])
    try:
        # No token, no cookie: a device that cannot connect cleanly yet is
        # exactly the one that needs this file.
        op, _ = client(tls=True)
        base = "https://127.0.0.1:%d" % port
        code, body = call(op, base + "/cert")
        check("/cert answers without a token", code == 200, str(code))
        check("/cert returns a PEM certificate",
              body.startswith("-----BEGIN CERTIFICATE-----"), body[:40])
        check("/cert matches the cert on disk", body == open(cert).read())
        check("/cert does not leak the private key", "PRIVATE KEY" not in body)
        check("the banner points devices at /cert", "/cert" in log)
    finally:
        p.terminate(); p.wait(timeout=5)

    p, token, log = start(vault, port + 1, ["--lan"])
    try:
        op, _ = client()
        code, _ = call(op, "http://127.0.0.1:%d/cert" % (port + 1))
        check("/cert is 404 without --tls", code == 404, str(code))
    finally:
        p.terminate(); p.wait(timeout=5)


def test_git(vault, port):
    """The repository cairn owns: a commit per save, and a refusal that
    leaves nothing behind."""
    print("\ngit")

    if not shutil.which("git"):
        check("git is installed to test against", False, "skipped")
        return

    p, token, log = start(vault, port)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)

        branch = git(vault, "rev-parse", "--abbrev-ref", "HEAD")
        check("the vault is a repository", os.path.isdir(os.path.join(vault, ".git")))
        check("checked out on a branch named for this machine",
              branch.startswith("host/"), branch)
        check("the branch is announced", "branch: " + branch in log, branch)
        check("the tree agrees with HEAD at startup",
              git(vault, "status", "--porcelain") == "",
              git(vault, "status", "--porcelain"))

        # --- one save, one commit ------------------------------------
        s_, b = call(op, base + "/api/notes")
        alpha = next(n for n in json.loads(b)["notes"] if n["title"] == "Alpha")
        before = int(git(vault, "rev-list", "--count", "HEAD"))
        body = json.dumps({"path": alpha["path"], "content": alpha["raw"] + "\none\n",
                           "mtime": alpha["mtime"]}).encode()
        s_, b = call(op, base + "/api/note", data=body, method="PUT",
                     headers={"Content-Type": "application/json"})
        after = int(git(vault, "rev-list", "--count", "HEAD"))
        check("a save makes exactly one commit", after == before + 1,
              "%d -> %d" % (before, after))
        check("the commit says what it did",
              git(vault, "log", "-1", "--format=%s") == "Update Alpha",
              git(vault, "log", "-1", "--format=%s"))
        check("the note's path is in the commit body",
              alpha["path"] in git(vault, "log", "-1", "--format=%b"))
        check("the working tree is clean afterwards",
              git(vault, "status", "--porcelain") == "")
        check("the save reports the sha",
              json.loads(b)["commit"] == git(vault, "log", "-1", "--format=%h"))

        # A save that changes nothing is a success with nothing to record.
        note = json.loads(call(op, base + "/api/notes")[1])["notes"]
        alpha = next(n for n in note if n["title"] == "Alpha")
        same = json.dumps({"path": alpha["path"], "content": alpha["raw"],
                           "mtime": alpha["mtime"], "stamp": False}).encode()
        n_before = int(git(vault, "rev-list", "--count", "HEAD"))
        s_, _ = call(op, base + "/api/note", data=same, method="PUT",
                     headers={"Content-Type": "application/json"})
        check("re-saving identical bytes commits nothing",
              s_ == 200 and int(git(vault, "rev-list", "--count", "HEAD")) == n_before)

        # --- a new note is committed too -----------------------------
        s_, _ = call(op, base + "/api/new",
                     data=json.dumps({"path": "Notes/Fresh.md", "title": "Fresh"}).encode(),
                     method="POST", headers={"Content-Type": "application/json"})
        check("/api/new commits the note it created",
              git(vault, "log", "-1", "--format=%s") == "Add Fresh",
              git(vault, "log", "-1", "--format=%s"))

        # --- concurrent saves serialize rather than racing the index --
        # Two threads, two notes, one index. Without the lock this is where
        # git would report "index.lock: File exists" and lose a commit.
        listing = json.loads(call(op, base + "/api/notes")[1])["notes"]
        pair = [n for n in listing if n["title"] in ("Alpha", "Fresh")]
        n_before = int(git(vault, "rev-list", "--count", "HEAD"))
        results = []

        def press(n):
            op2, _ = client()
            form(op2, base, token)
            results.append(call(op2, base + "/api/note",
                                data=json.dumps({"path": n["path"],
                                                 "content": n["raw"] + "\nboth\n",
                                                 "mtime": n["mtime"]}).encode(),
                                method="PUT",
                                headers={"Content-Type": "application/json"})[0])

        threads = [threading.Thread(target=press, args=(n,)) for n in pair]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        check("concurrent saves both succeed", results == [200, 200], results)
        check("and both are committed, one commit each",
              int(git(vault, "rev-list", "--count", "HEAD")) == n_before + 2,
              git(vault, "log", "-3", "--format=%s"))
        check("with nothing left staged or dirty",
              git(vault, "status", "--porcelain") == "",
              git(vault, "status", "--porcelain"))
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- the hook can refuse a save ----------------------------------
    # The vault this was built for has a pre-commit hook that blocks
    # credential-shaped strings, and cairn must never pass --no-verify. A
    # refused save has to leave *nothing*: no commit, no half-written file.
    hook = os.path.join(vault, ".git", "hooks", "pre-commit")
    with open(hook, "w") as f:
        f.write("#!/bin/sh\n"
                "git diff --cached | grep -q NOT-A-REAL-TOKEN || exit 0\n"
                "echo 'BLOCKED: Notes/Alpha.md:7 looks like a credential' >&2\n"
                "exit 1\n")
    os.chmod(hook, 0o755)

    p, token, _ = start(vault, port)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        listing = json.loads(call(op, base + "/api/notes")[1])["notes"]
        alpha = next(n for n in listing if n["title"] == "Alpha")
        head = git(vault, "rev-parse", "HEAD")
        was = open(os.path.join(vault, alpha["path"]), encoding="utf-8").read()

        s_, b = call(op, base + "/api/note",
                     data=json.dumps({"path": alpha["path"],
                                      "content": was + "\nNOT-A-REAL-TOKEN\n",
                                      "mtime": alpha["mtime"]}).encode(),
                     method="PUT", headers={"Content-Type": "application/json"})
        r = json.loads(b)
        now = open(os.path.join(vault, alpha["path"]), encoding="utf-8").read()
        check("a refused save answers 422", s_ == 422, s_)
        check("it carries the hook's own words",
              "looks like a credential" in (r.get("refused") or ""), r.get("refused"))
        check("the note is byte-for-byte what it was", now == was)
        check("and that is what the client is told it has",
              r.get("content") == was)
        check("no commit was made", git(vault, "rev-parse", "HEAD") == head)
        check("nothing is left staged", git(vault, "diff", "--cached", "--name-only") == "")
        check("and nothing is left dirty", git(vault, "status", "--porcelain") == "",
              git(vault, "status", "--porcelain"))

        # A brand-new note the hook refuses must not survive either.
        s_, b = call(op, base + "/api/new",
                     data=json.dumps({"path": "Notes/NOT-A-REAL-TOKEN.md",
                                      "title": "NOT-A-REAL-TOKEN"}).encode(),
                     method="POST", headers={"Content-Type": "application/json"})
        check("a refused new note answers 422", s_ == 422, s_)
        check("and leaves no file behind",
              not os.path.exists(os.path.join(vault, "Notes", "NOT-A-REAL-TOKEN.md")))
        check("still no commit", git(vault, "rev-parse", "HEAD") == head)
    finally:
        p.terminate(); p.wait(timeout=5)
        os.remove(hook)

    # --- a dirty tree at startup is adopted, in one commit -------------
    with open(os.path.join(vault, "Notes", "Outside.md"), "w") as f:
        f.write("# Outside\n\nWritten by something that is not cairn.\n")
    before = int(git(vault, "rev-list", "--count", "HEAD"))
    p, token, log = start(vault, port)
    try:
        check("a tree that was dirty at startup is committed",
              git(vault, "status", "--porcelain") == "",
              git(vault, "status", "--porcelain"))
        check("in a single commit that says so",
              int(git(vault, "rev-list", "--count", "HEAD")) == before + 1
              and git(vault, "log", "-1", "--format=%s") == "Adopt changes made outside cairn",
              git(vault, "log", "-1", "--format=%s"))
        check("and it is announced", "already in the vault" in log)
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- no git without git ------------------------------------------
    bare_path = dict(os.environ, XDG_STATE_HOME=STATE, PATH="/nonexistent")
    p, _, log = start(vault, port, env=bare_path)
    p.wait(timeout=10)
    check("without git on PATH, cairn refuses to start",
          p.returncode != 0 and "git is not on PATH" in log, log.strip()[-120:])

    # --- every git command is scoped to the vault ---------------------
    # Read off the module rather than a subprocess: the property is that no
    # command can run anywhere else, and that lives in one function.
    srv = load_server()
    srv.VAULT = vault
    seen = []

    class Fake:
        returncode = 0
        stdout = ""

    real = srv.subprocess.run
    srv.subprocess.run = lambda argv, **kw: (seen.append(argv), Fake())[1]
    try:
        srv.git("status", "--porcelain")
        srv._git("log", "-1")
    finally:
        srv.subprocess.run = real
    check("every git command is run inside the vault",
          bool(seen) and all(tuple(a[:3]) == ("git", "-C", vault) for a in seen),
          seen[:1])
    check("and none of them goes through a shell",
          all(isinstance(a, tuple) and "shell" not in str(a) for a in seen))


def test_sync(vault, port):
    """Sync: this machine's branch out, the other machines' branches in."""
    print("\nsync")

    if not shutil.which("git"):
        check("git is installed to test against", False, "skipped")
        return

    state = tempfile.mkdtemp(prefix="cairn-test-state-")
    env = dict(os.environ, XDG_STATE_HOME=state)

    # --- off, and refused, until there is somewhere to sync to ---------
    p, token, _ = start(vault, port, env=env)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        code, _ = call(op, base + "/api/sync", data=b"", method="POST")
        check("POST /api/sync refused when locked", code == 403, code)
        code, _ = call(op, base + "/api/sync/status")
        check("sync status refused when locked", code == 403, code)
        form(op, base, token)
        code, body = call(op, base + "/api/sync", data=b"", method="POST")
        check("POST /api/sync is 404 with no origin remote", code == 404, code)
        check("and says why", "origin" in body, body[:80])
        code, body = call(op, base + "/api/sync/status")
        st = json.loads(body)["sync"]
        check("status reports sync disabled with no origin", st["enabled"] is False)
        check("but still names the branch it would push",
              (st["branch"] or "").startswith("host/"), st.get("branch"))
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- a bare repository is the transport ----------------------------
    home = tempfile.mkdtemp(prefix="cairn-test-remote-")
    bare = os.path.join(home, "notes.git")
    subprocess.run(("git", "init", "-q", "--bare", bare),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    git(vault, "remote", "add", "origin", bare)

    p, token, _ = start(vault, port, env=env)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        branch = git(vault, "rev-parse", "--abbrev-ref", "HEAD")

        # The request body is attacker-shaped. Nothing in it can reach git:
        # every command is a fixed argv list built here, not there.
        payload = json.dumps({"cmd": "rm -rf /", "branch": "; touch /tmp/pwned",
                              "args": ["--force"]}).encode()
        code, body = call(op, base + "/api/sync", data=payload, method="POST",
                          headers={"Content-Type": "application/json"})
        rec = json.loads(body)["sync"] if code == 200 else {}
        check("a sync with a remote runs", code == 200 and rec.get("ok") is True,
              rec.get("output", code))
        check("nothing from the request reaches git",
              not os.path.exists("/tmp/pwned")
              and "rm -rf" not in rec.get("output", ""))
        check("this machine's branch is on the remote",
              branch in subprocess.run(("git", "-C", bare, "branch", "--list"),
                                       stdout=subprocess.PIPE, text=True).stdout,
              branch)
        check("the run is recorded", json.loads(
            call(op, base + "/api/sync/status")[1])["sync"]["last"]["ok"] is True)

        # --- another machine's branch is merged back ------------------
        peer = os.path.join(home, "peer")
        subprocess.run(("git", "clone", "-q", bare, peer),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git_init_peer = (("config", "user.email", "p@example.com"),
                         ("config", "user.name", "Peer"),
                         ("checkout", "-q", "-b", "host/other", "origin/" + branch))
        for args in git_init_peer:
            git(peer, *args)
        note = os.path.join(peer, "Notes", "Shared.md")
        os.makedirs(os.path.dirname(note), exist_ok=True)
        with open(note, "w") as f:
            f.write("# Shared\n\nfrom the other machine\n")
        git(peer, "add", "-A")
        git(peer, "commit", "-qm", "Add Shared")
        git(peer, "push", "-q", "origin", "host/other")

        code, body = call(op, base + "/api/sync", data=b"", method="POST")
        rec = json.loads(body)["sync"]
        check("a peer's branch is merged in", rec["ok"] is True
              and os.path.isfile(os.path.join(vault, "Notes", "Shared.md")),
              rec["output"][-200:])
        check("the merge is pushed back",
              subprocess.run(("git", "-C", bare, "log", "-1", "--format=%s", branch),
                             stdout=subprocess.PIPE, text=True).stdout.strip() ==
              git(vault, "log", "-1", "--format=%s"))
        code, body = call(op, base + "/api/status")
        check("the footer is told how many other machines there are",
              json.loads(body)["sync"]["peers"] == 1, json.loads(body)["sync"]["peers"])

        # --- the later writer wins, whichever machine that is ---------
        # The peer writes, then this machine writes. Merging with -X theirs
        # would hand it to the peer; ordering is what makes it the later one.
        conflict = "Notes/Shared.md"
        with open(os.path.join(peer, conflict), "w") as f:
            f.write("# Shared\n\nPEER WROTE THIS\n")
        git(peer, "commit", "-qam", "Update Shared")
        git(peer, "push", "-q", "origin", "host/other")
        time.sleep(1.1)                       # commit times are whole seconds
        listing = json.loads(call(op, base + "/api/notes")[1])["notes"]
        shared = next(n for n in listing if n["path"].endswith("Shared.md"))
        call(op, base + "/api/note",
             data=json.dumps({"path": shared["path"],
                              "content": "# Shared\n\nTHIS MACHINE WROTE THIS\n",
                              "mtime": shared["mtime"], "stamp": False}).encode(),
             method="PUT", headers={"Content-Type": "application/json"})
        code, body = call(op, base + "/api/sync", data=b"", method="POST")
        rec = json.loads(body)["sync"]
        text = open(os.path.join(vault, conflict), encoding="utf-8").read()
        check("this machine wrote last, so this machine's line survives",
              rec["ok"] is True and "THIS MACHINE" in text, text.strip()[-60:])
        check("and the losing version is still in the history",
              "PEER WROTE THIS" in git(vault, "log", "-p", "--all"))

        # Now the other way round: the peer writes after this machine.
        time.sleep(1.1)
        with open(os.path.join(peer, conflict), "w") as f:
            f.write("# Shared\n\nPEER WROTE THIS LAST\n")
        git(peer, "fetch", "-q", "origin")
        git(peer, "merge", "-q", "--no-edit", "-X", "ours", "origin/" + branch)
        with open(os.path.join(peer, conflict), "w") as f:
            f.write("# Shared\n\nPEER WROTE THIS LAST\n")
        git(peer, "commit", "-qam", "Update Shared")
        git(peer, "push", "-q", "origin", "host/other")
        code, body = call(op, base + "/api/sync", data=b"", method="POST")
        rec = json.loads(body)["sync"]
        text = open(os.path.join(vault, conflict), encoding="utf-8").read()
        check("the peer wrote last, so the peer's line survives",
              rec["ok"] is True and "PEER WROTE THIS LAST" in text, text.strip()[-60:])

        # --- the transcript reaches the activity panel ----------------
        code, body = call(op, base + "/api/run/log?since=0")
        lines = [l["text"] for l in json.loads(body)["lines"]]
        check("the activity panel sees the git commands",
              any(l.startswith("git push") for l in lines)
              and any(l.startswith("git fetch") for l in lines), lines[:3])
        check("and a line for the run finishing",
              any("finished in" in l for l in lines))
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- a sync that cannot reach its remote is reported, not swallowed
    git(vault, "remote", "set-url", "origin", os.path.join(home, "gone.git"))
    p, token, _ = start(vault, port, env=env)
    try:
        op, _ = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        code, body = call(op, base + "/api/sync", data=b"", method="POST")
        rec = json.loads(body)["sync"]
        check("a failing sync still answers 200", code == 200, code)
        check("a failing sync is marked not ok", rec["ok"] is False)
        check("its output is kept for the user", "gone.git" in rec["output"],
              rec["output"][-120:])
        check("the vault is left on its own branch, clean",
              git(vault, "status", "--porcelain") == "",
              git(vault, "status", "--porcelain"))
    finally:
        p.terminate(); p.wait(timeout=5)

    git(vault, "remote", "remove", "origin")
    shutil.rmtree(home, ignore_errors=True)
    shutil.rmtree(state, ignore_errors=True)


# --------------------------------------------------------------------------
def test_status(vault, port):
    """The footer's own endpoints: /api/status and the activity log."""
    print("\nstatus and activity")

    state = tempfile.mkdtemp(prefix="cairn-test-state-")
    env = dict(os.environ, XDG_STATE_HOME=state)

    p, token, log = start(vault, port, env=env)
    where = state_dir(log)
    try:
        op, _jar = client()
        base = "http://127.0.0.1:%d" % port

        code, _ = call(op, base + "/api/status")
        check("/api/status refused when locked", code == 403, code)
        code, _ = call(op, base + "/api/run/log")
        check("/api/run/log refused when locked", code == 403, code)

        form(op, base, token)

        code, body = call(op, base + "/api/status")
        st = json.loads(body) if code == 200 else {}
        check("/api/status answers", code == 200, code)
        check("it carries all three sections",
              all(k in st for k in ("sync", "git", "cloud")))
        check("and the version the page shows in its footer",
              re.match(r"^\d+\.\d+\.\d+$", st.get("version") or ""), st.get("version"))
        # cairn made this a repository itself at startup. The temp vault is
        # still nobody's sync folder, and saying so is the point -- a missing
        # key would leave the footer unable to tell absent from broken.
        check("git reports the repository cairn keeps",
              st.get("git", {}).get("repo") is True, st.get("git"))
        check("on this machine's branch",
              (st.get("git", {}).get("branch") or "").startswith("host/"),
              st.get("git", {}).get("branch"))
        check("with no origin, so no sync",
              st["git"]["remote"] is None and st["sync"]["enabled"] is False)
        check("no sync folder is detected",
              st.get("cloud", {}).get("detected") is False, st.get("cloud"))

        code, body = call(op, base + "/api/run/log")
        log = json.loads(body)
        check("the log starts empty", log["lines"] == [] and log["seq"] == 0)
        check("nothing is running", log["running"] is False)
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- a run is visible while it is still going ----------------------
    # A pre-commit hook that sleeps is the honest way to hold a sync open:
    # the run really is in flight, and the panel really is being polled.
    home = tempfile.mkdtemp(prefix="cairn-test-remote-")
    bare = os.path.join(home, "notes.git")
    subprocess.run(("git", "init", "-q", "--bare", bare),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    git(vault, "remote", "add", "origin", bare)
    hook = os.path.join(vault, ".git", "hooks", "pre-commit")
    with open(hook, "w") as f:
        f.write("#!/bin/sh\nsleep 3\n")
    os.chmod(hook, 0o755)
    with open(os.path.join(vault, "Notes", "Slow.md"), "w") as f:
        f.write("# Slow\n\nSomething for the sync to commit.\n")

    p, token, log = start(vault, port, env=env)
    where = state_dir(log)
    try:
        op, _jar = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        # Startup adopted the dirty tree through the slow hook already; make
        # it dirty again so the sync itself has something to commit.
        with open(os.path.join(vault, "Notes", "Slow.md"), "a") as f:
            f.write("\nAnd another line.\n")

        done = []

        def press():
            op2, _ = client()
            form(op2, base, token)
            done.append(call(op2, base + "/api/sync", data=b"", method="POST"))

        t = threading.Thread(target=press)
        t.start()

        seen, running, deadline = [], False, time.time() + 10
        while time.time() < deadline and not done:
            code, body = call(op, base + "/api/run/log?since=0")
            r = json.loads(body)
            seen = [l["text"] for l in r["lines"]]
            running = running or r["running"]
            if any("sync on host/" in l for l in seen):
                break
            time.sleep(0.2)

        check("the first line arrives before the sync ends",
              any("sync on host/" in l for l in seen) and not done,
              "lines=%s finished=%s" % (seen[:2], bool(done)))
        check("a run in flight is reported as running", running)
        t.join(timeout=40)

        code, body = call(op, base + "/api/run/log?since=0")
        r = json.loads(body)
        texts = [l["text"] for l in r["lines"]]
        kinds = [l["kind"] for l in r["lines"]]
        check("the whole transcript is in the log",
              any(l.startswith("git push") for l in texts), texts[:3])
        check("the run opens the log", kinds and kinds[0] == "start", kinds[:1])
        check("the run is marked finished", "end" in kinds, kinds)
        check("nothing is running afterwards", r["running"] is False)

        # --- since= is what keeps a poll small -------------------------
        newest = r["seq"]
        code, body = call(op, base + "/api/run/log?since=%d" % newest)
        check("since= returns only what is newer", json.loads(body)["lines"] == [])
        code, body = call(op, base + "/api/run/log?since=nonsense")
        check("a junk since= is treated as 0",
              len(json.loads(body)["lines"]) == len(texts), code)

        code, body = call(op, base + "/api/status")
        check("the finished run reaches /api/status",
              json.loads(body)["sync"]["last"]["ok"] is True)

        # One shared file would mean a failed sync of one vault showing up in
        # another vault's footer.
        check("the record is kept per vault",
              os.path.isfile(os.path.join(where, "sync.json")), where)
        check("not in one file shared by every vault",
              not os.path.isfile(os.path.join(state, "cairn", "sync.json")))
    finally:
        p.terminate(); p.wait(timeout=5)
        os.remove(hook)
        git(vault, "remote", "remove", "origin")
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(state, ignore_errors=True)


def test_status_in_repo(vault, port):
    """A vault inside a provider's sync folder, with a history of its own."""
    print("\nstatus in a repo")

    if not shutil.which("git"):
        check("git is installed to test against", False, "skipped")
        return

    # The provider folder is a directory name, so a fake one is a real test:
    # this is exactly what cairn looks at on a machine with the real client.
    home = tempfile.mkdtemp(prefix="cairn-test-cloud-")
    cloud = os.path.join(home, "ProtonDrive-someone@proton.me-folder")
    repo = os.path.join(cloud, "vault")
    os.makedirs(repo)
    with open(os.path.join(repo, "Note.md"), "w") as f:
        f.write("# Note\n")
    git_init(repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "First note")
    # Edited and added since that commit: cairn adopts both at startup rather
    # than serving a tree that disagrees with the history it is about to add
    # to. A save that carried someone else's half-finished edit along with it
    # would make "one save, one commit" a lie.
    with open(os.path.join(repo, "Note.md"), "a") as f:
        f.write("\nEdited since the commit.\n")
    with open(os.path.join(repo, "Fresh.md"), "w") as f:
        f.write("# Fresh\n")

    p, token, _ = start(repo, port)
    try:
        op, _jar = client()
        base = "http://127.0.0.1:%d" % port
        form(op, base, token)
        st = json.loads(call(op, base + "/api/status")[1])

        g = st["git"]
        check("the repository is found", g["repo"] is True)
        check("cairn moved it onto a branch of its own",
              (g["branch"] or "").startswith("host/"), g.get("branch"))
        check("the existing history is still there",
              "First note" in git(repo, "log", "--format=%s"))
        check("the edits made outside cairn were adopted",
              g["changed"] == 0 and g["untracked"] == 0, (g["changed"], g["untracked"]))
        check("so the tree is clean", g["clean"] is True)
        check("the adopting commit is the one reported",
              g["last"]["subject"] == "Adopt changes made outside cairn",
              g.get("last"))
        check("there is no upstream to be ahead of", g["upstream"] is None)

        c = st["cloud"]
        check("the sync folder is detected", c["detected"] is True)
        check("the provider is named", c["provider"] == "Proton Drive", c.get("provider"))
        check("the account is read off the folder",
              c["account"] == "someone@proton.me", c.get("account"))
        check("the folder is there", c["present"] is True)
        check("where the vault sits inside it", c["inside"] == "vault", c.get("inside"))
    finally:
        p.terminate(); p.wait(timeout=5)

    # --- a vault below a repository's root is refused -------------------
    # cairn commits on a branch per machine; doing that to a repository the
    # vault only sits inside would move a branch that is not cairn's to move.
    nested = os.path.join(repo, "inner")
    os.makedirs(nested)
    with open(os.path.join(nested, "Deep.md"), "w") as f:
        f.write("# Deep\n")
    p, _, log = start(nested, port)
    p.wait(timeout=10)
    check("a vault below the repository root is refused",
          p.returncode != 0 and "not at its root" in log, log.strip()[-120:])

    shutil.rmtree(home, ignore_errors=True)


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
        test_cert_names(vault, 8950)
        test_token_persists(vault, 8955)
        test_cert_download(vault, 8960)
        test_terminal(vault, 8936)
        test_git(vault, 8951)
        test_sync(vault, 8937)
        test_status(vault, 8938)
        test_status_in_repo(vault, 8939)
    finally:
        shutil.rmtree(vault, ignore_errors=True)
        shutil.rmtree(STATE, ignore_errors=True)

    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
