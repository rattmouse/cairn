#!/usr/bin/env python3
"""
notes-server.py — a small local editor for this notes vault.

Just this machine (default):

    python3 bin/notes-server.py

Reachable from other devices on your LAN, encrypted:

    python3 bin/notes-server.py --lan --tls

Serving a vault that lives somewhere else:

    python3 notes-server.py --vault ~/Documents/notes

Stop it with Ctrl-C.

Python standard library only: no pip install, no dependencies, no internet.

How access works
----------------
A token is generated fresh every time the server starts and printed in the
terminal. Opening the printed URL on this machine logs you in automatically.
On another device you open the plain URL and paste the token once; the server
sets a session cookie (HttpOnly, SameSite=Strict) and the token never appears
in a URL, browser history, or the page source.

Safety
------
* Defaults to 127.0.0.1. Reaching it from elsewhere requires --lan explicitly.
* Every request needs the token. Without it a random website open in another
  tab could POST to the server and rewrite your notes. Cross-origin requests
  are refused outright, and the cookie is SameSite=Strict.
* --tls encrypts the connection with a self-signed certificate. WITHOUT IT,
  everything -- your notes and the token -- crosses the network in the clear,
  readable by anyone else on the same wifi.
* Writes are atomic (temp file + os.replace), so an interrupted save can't
  leave a half-written note.
* The previous version of every note you save is kept in .backups/.
* Deleting moves the file to .trash/ -- nothing is actually unlinked.
* Paths are resolved and checked against the vault root, so a crafted request
  can't read or write outside it, and only .md files can be written.
"""

import argparse
import hashlib
import http.cookies
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
EDITOR_HTML = os.path.join(HERE, "editor.html")

# Which vault to serve. Resolution order, set properly in main():
#   --vault PATH  >  $NOTES_VAULT  >  the directory containing this script's parent
# The last case is the "script still lives in the vault's bin/" layout.
VAULT = os.path.abspath(os.environ.get("NOTES_VAULT") or os.path.join(HERE, os.pardir))
CERT_DIR = os.path.join(VAULT, ".certs")

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
}

TOKEN = secrets.token_urlsafe(24)
COOKIE = "notes_session"


# --------------------------------------------------------------------------
# vault helpers
# --------------------------------------------------------------------------

def safe_path(rel, must_exist=False, suffix=".md"):
    """Resolve a vault-relative path, refusing anything that escapes the root."""
    if not rel or rel.startswith(("/", "\\")) or "\x00" in rel:
        raise ValueError("bad path")
    full = os.path.abspath(os.path.join(VAULT, rel))
    if not full.startswith(VAULT + os.sep):
        raise ValueError("path escapes vault")
    if suffix and not full.lower().endswith(suffix):
        raise ValueError("unexpected file type")
    if must_exist and not os.path.isfile(full):
        raise ValueError("no such file")
    return full


def parse_frontmatter(text):
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 3)
    if end == -1:
        return {}, text
    meta = {}
    for line in text[4:end].split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, text[end + 5:]


def list_notes():
    out = []
    for root, dirs, files in os.walk(VAULT):
        # Hidden directories are the whole skip rule: it covers this server's
        # own .backups/, .trash/ and .certs/ as well as .git/ and .obsidian/.
        # Nothing else is hidden from the vault — a folder named bin/ or
        # node_modules/ used to be skipped here, which silently swallowed any
        # notes inside it.
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in sorted(files):
            if not f.endswith(".md"):
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, VAULT)
            try:
                raw = open(full, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            meta, _ = parse_frontmatter(raw)
            tags = [t.strip() for t in meta.get("tags", "").strip("[]").split(",") if t.strip()]
            out.append({
                "path": rel,
                "title": meta.get("title") or os.path.splitext(f)[0],
                "folder": os.path.dirname(rel) or "(root)",
                "tags": tags,
                "updated": meta.get("updated", ""),
                "mtime": os.path.getmtime(full),
                "raw": raw,
            })

    def key(n):
        top = n["folder"].split("/")[0] if n["folder"] != "(root)" else ""
        order = {"": 0, "0 - Projects": 1, "1 - Areas": 2,
                 "2 - Resources": 3, "3 - Archives": 4}
        return (order.get(top, 9), n["folder"], n["title"].lower())

    out.sort(key=key)
    return out


def list_images():
    found = {}
    for root, dirs, files in os.walk(VAULT):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            if os.path.splitext(f)[1].lower() in IMAGE_EXT:
                found.setdefault(f, os.path.relpath(os.path.join(root, f), VAULT))
    return found


def backup(full):
    """Keep the version we are about to overwrite."""
    if not os.path.isfile(full):
        return None
    rel = os.path.relpath(full, VAULT)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(VAULT, ".backups", os.path.dirname(rel),
                        "%s.%s.md" % (os.path.basename(rel)[:-3], stamp))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(full, dest)
    return os.path.relpath(dest, VAULT)


def atomic_write(full, text):
    os.makedirs(os.path.dirname(full), exist_ok=True)
    tmp = full + ".tmp-%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, full)


def touch_updated(text):
    """Keep the `updated:` frontmatter field honest when a note is saved."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---\n", 3)
    if end == -1:
        return text
    fm, body = text[4:end], text[end + 5:]
    if re.search(r"(?m)^updated:", fm):
        fm = re.sub(r"(?m)^updated:.*$", "updated: " + today, fm)
    else:
        fm = fm.rstrip("\n") + "\nupdated: " + today
    return "---\n" + fm + "\n---\n" + body


# --------------------------------------------------------------------------
# network / tls
# --------------------------------------------------------------------------

def lan_ips():
    """Best-effort list of this machine's LAN addresses."""
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))          # TEST-NET-1, never actually sent
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    return sorted(ips)


def ensure_cert(hosts):
    """Self-signed cert in .certs/, regenerated if missing. Needs openssl."""
    os.makedirs(CERT_DIR, exist_ok=True)
    cert = os.path.join(CERT_DIR, "server.crt")
    key = os.path.join(CERT_DIR, "server.key")
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key

    if not shutil.which("openssl"):
        sys.exit("--tls needs the `openssl` command, which isn't on your PATH.\n"
                 "Install it (sudo apt install openssl) or run without --tls.")

    alt = ["DNS:localhost", "IP:127.0.0.1"] + ["IP:%s" % h for h in hosts if h[0].isdigit()]
    print("  generating a self-signed certificate in .certs/ …")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "825",
         "-subj", "/CN=notes-server",
         "-addext", "subjectAltName=" + ",".join(alt)],
        check=True, capture_output=True)
    os.chmod(key, 0o600)
    return cert, key


def cert_fingerprint(cert):
    try:
        out = subprocess.run(["openssl", "x509", "-in", cert, "-noout",
                              "-fingerprint", "-sha256"],
                             check=True, capture_output=True, text=True).stdout
        return out.strip().split("=", 1)[-1]
    except Exception:
        try:
            der = ssl.PEM_cert_to_DER_cert(open(cert).read())
            h = hashlib.sha256(der).hexdigest().upper()
            return ":".join(h[i:i + 2] for i in range(0, len(h), 2))
        except Exception:
            return "(could not read)"


# --------------------------------------------------------------------------
# unlock page
# --------------------------------------------------------------------------

UNLOCK = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Notes — unlock</title>
<style>
:root{--bg:#fbfaf8;--panel:#f2efea;--edge:#e2ddd4;--ink:#22201d;--dim:#6d675e;--accent:#8a5a2b;--bad:#a5433a}
@media(prefers-color-scheme:dark){:root{--bg:#17161a;--panel:#1e1d22;--edge:#32303a;--ink:#e6e2dc;--dim:#98938c;--accent:#d69a63;--bad:#e08a80}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
 background:var(--bg);color:var(--ink);font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",system-ui,sans-serif}
form{background:var(--panel);border:1px solid var(--edge);border-radius:12px;padding:28px;width:min(400px,92vw)}
h1{margin:0 0 6px;font-size:17px}
p{margin:0 0 18px;font-size:13px;color:var(--dim)}
label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.05em;
 color:var(--dim);font-weight:700;margin-bottom:6px}
input{width:100%;padding:10px 12px;font:inherit;font-family:ui-monospace,Menlo,monospace;font-size:13px;
 background:var(--bg);color:var(--ink);border:1px solid var(--edge);border-radius:8px;outline:none}
input:focus{border-color:var(--accent)}
button{margin-top:14px;width:100%;padding:10px;font:inherit;font-weight:600;background:var(--accent);
 color:#fff;border:0;border-radius:8px;cursor:pointer}
.err{margin-top:12px;color:var(--bad);font-size:13px;min-height:18px}
.warn{margin-top:16px;padding:10px 12px;border-left:3px solid var(--accent);
 background:var(--bg);font-size:12px;color:var(--dim);border-radius:0 8px 8px 0}
</style></head><body>
<form method="POST" action="/unlock">
  <h1>Notes</h1>
  <p>Paste the token printed in the terminal where the server is running.</p>
  <label for="t">Token</label>
  <input id="t" name="token" autocomplete="off" autofocus spellcheck="false">
  <button type="submit">Unlock</button>
  <div class="err">__ERR__</div>
  __WARN__
</form></body></html>"""

INSECURE_WARN = ('<div class="warn">This connection is plain HTTP. Anyone else on this '
                 'network can read what you send, including this token. Restart the server '
                 'with <code>--tls</code> to encrypt it.</div>')


# --------------------------------------------------------------------------
# http
# --------------------------------------------------------------------------

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "notes-server"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s  %s  %s\n" %
                         (time.strftime("%H:%M:%S"), self.client_address[0], fmt % args))

    # --- plumbing -------------------------------------------------------
    def send(self, code, body=b"", ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, code, obj):
        self.send(code, json.dumps(obj, ensure_ascii=False))

    def fail(self, code, msg):
        self.send_json(code, {"ok": False, "error": msg})

    def redirect(self, to, extra=None):
        head = {"Location": to}
        head.update(extra or {})
        self.send(303, b"", "text/plain", head)

    def cookie_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        try:
            jar = http.cookies.SimpleCookie()
            jar.load(raw)
            return jar[COOKIE].value if COOKIE in jar else ""
        except Exception:
            return ""

    def query_token(self):
        return urllib.parse.parse_qs(
            urllib.parse.urlparse(self.path).query).get("token", [""])[0]

    def authed(self):
        """Token gate. Also refuses cross-origin requests outright."""
        origin = self.headers.get("Origin")
        if origin:
            host = self.headers.get("Host", "")
            if urllib.parse.urlparse(origin).netloc != host:
                return False
        for given in (self.headers.get("X-Notes-Token"), self.cookie_token(), self.query_token()):
            if given and secrets.compare_digest(given, TOKEN):
                return True
        return False

    def set_session(self):
        secure = "; Secure" if self.server.tls else ""
        return {"Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Strict%s"
                              % (COOKIE, TOKEN, secure)}

    def unlock_page(self, err=""):
        html = UNLOCK.replace("__ERR__", err)
        risky = self.server.exposed and not self.server.tls
        html = html.replace("__WARN__", INSECURE_WARN if risky else "")
        self.send(200, html, "text/html; charset=utf-8")

    def body_bytes(self, limit=8 * 1024 * 1024):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > limit:
            raise ValueError("bad body size")
        return self.rfile.read(length)

    def body_json(self):
        return json.loads(self.body_bytes().decode("utf-8"))

    # --- routes ---------------------------------------------------------
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(url.path)

        if path == "/favicon.ico":
            return self.send(204, b"", "image/x-icon")

        if path == "/":
            if not self.authed():
                return self.unlock_page()
            # Token arrived in the URL: convert it to a cookie and drop it from
            # the address bar so it never lands in history.
            if self.query_token():
                return self.redirect("/", self.set_session())
            try:
                html = open(EDITOR_HTML, encoding="utf-8").read()
            except OSError:
                return self.send(500, "editor.html is missing from bin/",
                                 "text/plain; charset=utf-8")
            return self.send(200, html, "text/html; charset=utf-8", self.set_session())

        if path == "/unlock":
            return self.unlock_page()

        if path == "/api/notes":
            if not self.authed():
                return self.fail(403, "not unlocked")
            return self.send_json(200, {"ok": True, "notes": list_notes(),
                                        "images": list_images(), "vault": VAULT})

        if path.startswith("/media/"):
            if not self.authed():
                return self.fail(403, "not unlocked")
            try:
                full = safe_path(path[len("/media/"):], must_exist=True, suffix=None)
            except ValueError as e:
                return self.fail(400, str(e))
            ext = os.path.splitext(full)[1].lower()
            if ext not in IMAGE_EXT:
                return self.fail(400, "not an image")
            with open(full, "rb") as fh:
                return self.send(200, fh.read(), MIME.get(ext, "application/octet-stream"))

        return self.fail(404, "no such endpoint")

    def do_PUT(self):
        if not self.authed():
            return self.fail(403, "not unlocked")
        if urllib.parse.urlparse(self.path).path != "/api/note":
            return self.fail(404, "no such endpoint")
        try:
            data = self.body_json()
            full = safe_path(data["path"])
            content = data["content"]
            if not isinstance(content, str):
                raise ValueError("content must be a string")
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            return self.fail(400, str(e))

        seen = data.get("mtime")
        if seen is not None and os.path.isfile(full):
            if abs(os.path.getmtime(full) - float(seen)) > 0.001:
                return self.fail(409, "changed on disk since you opened it")

        if data.get("stamp", True):
            content = touch_updated(content)
        kept = backup(full)
        atomic_write(full, content)
        return self.send_json(200, {"ok": True, "backup": kept,
                                    "mtime": os.path.getmtime(full),
                                    "content": content})

    def do_POST(self):
        route = urllib.parse.urlparse(self.path).path

        if route == "/unlock":
            try:
                form = urllib.parse.parse_qs(self.body_bytes(limit=4096).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return self.unlock_page("Malformed request.")
            given = (form.get("token") or [""])[0].strip()
            if secrets.compare_digest(given, TOKEN):
                self.log_message("unlocked")
                return self.redirect("/", self.set_session())
            time.sleep(0.7)                      # blunt the guessing rate
            self.log_message("FAILED unlock attempt")
            return self.unlock_page("That token doesn't match. Check the terminal.")

        if not self.authed():
            return self.fail(403, "not unlocked")

        if route == "/api/new":
            try:
                data = self.body_json()
                full = safe_path(data["path"])
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                return self.fail(400, str(e))
            if os.path.exists(full):
                return self.fail(409, "a note with that name already exists")
            title = data.get("title") or os.path.basename(full)[:-3]
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            body = ("---\ntitle: %s\ntags: []\nupdated: %s\n---\n\n# %s\n\n"
                    % (title, today, title))
            atomic_write(full, body)
            return self.send_json(200, {"ok": True, "path": os.path.relpath(full, VAULT),
                                        "content": body, "mtime": os.path.getmtime(full)})

        if route == "/api/trash":
            try:
                data = self.body_json()
                full = safe_path(data["path"], must_exist=True)
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                return self.fail(400, str(e))
            rel = os.path.relpath(full, VAULT)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            dest = os.path.join(VAULT, ".trash",
                                "%s.%s.md" % (os.path.basename(rel)[:-3], stamp))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.move(full, dest)
            return self.send_json(200, {"ok": True, "trashed": os.path.relpath(dest, VAULT)})

        return self.fail(404, "no such endpoint")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    tls = False
    exposed = False


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Local editor for the notes vault.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--lan", action="store_true",
                    help="accept connections from other devices on your network")
    ap.add_argument("--host", default=None,
                    help="bind a specific address (overrides --lan)")
    ap.add_argument("--tls", action="store_true",
                    help="encrypt with a self-signed certificate (recommended with --lan)")
    ap.add_argument("--vault", default=None,
                    help="path to the notes vault (default: $NOTES_VAULT, "
                         "else the folder containing this script's parent)")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    global VAULT, CERT_DIR
    if args.vault:
        VAULT = os.path.abspath(os.path.expanduser(args.vault))
    CERT_DIR = os.path.join(VAULT, ".certs")

    if not os.path.isdir(VAULT):
        sys.exit("vault not found at %s\n"
                 "Pass --vault /path/to/notes or set NOTES_VAULT." % VAULT)
    if not any(f.endswith(".md") for f in os.listdir(VAULT)) and \
       not any(any(f.endswith(".md") for f in fs) for _, _, fs in os.walk(VAULT)):
        sys.exit("no markdown files under %s — is that the right vault?" % VAULT)
    if not os.path.isfile(EDITOR_HTML):
        sys.exit("editor.html not found next to this script")

    host = args.host or ("0.0.0.0" if args.lan else "127.0.0.1")
    exposed = host not in ("127.0.0.1", "localhost")
    scheme = "https" if args.tls else "http"
    addrs = lan_ips() if exposed else []

    try:
        httpd = Server((host, args.port), Handler)
    except OSError as e:
        sys.exit("could not bind %s:%d — %s\nTry --port 8766" % (host, args.port, e))
    httpd.tls = args.tls
    httpd.exposed = exposed

    if args.tls:
        cert, key = ensure_cert(addrs)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    local = "%s://127.0.0.1:%d/?token=%s" % (scheme, args.port, TOKEN)

    print("\n  Notes editor")
    print("  vault : %s" % VAULT)
    print("  notes : %d" % len(list_notes()))
    print("  this machine : %s" % local)
    if exposed:
        for ip in addrs or ["<this machine's IP>"]:
            print("  other devices: %s://%s:%d/" % (scheme, ip, args.port))
        print("\n  Token (paste it on the other device):\n\n      %s\n" % TOKEN)
        if args.tls:
            print("  Certificate is self-signed, so the browser will warn once.")
            print("  Verify this SHA-256 fingerprint before accepting it:")
            print("      %s\n" % cert_fingerprint(os.path.join(CERT_DIR, "server.crt")))
        else:
            print("  !! PLAIN HTTP ON THE NETWORK !!")
            print("  Your notes and this token cross the wire unencrypted and are")
            print("  readable by anyone else on this network. Restart with --tls.\n")
    print("  Backups go to .backups/, deletes go to .trash/.")
    print("  Ctrl-C to stop.\n")

    if not args.no_browser:
        try:
            webbrowser.open(local)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped\n")


if __name__ == "__main__":
    main()
