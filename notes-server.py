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
A token is generated on first run, kept in the state directory and printed
in the terminal, so a device you pair once stays paired across restarts.
Opening the printed URL on this machine logs you in automatically.
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
* The previous version of every note you save is kept in backups/, and
  deleting moves the file to trash/ -- nothing is actually unlinked. Both
  live in a per-vault state directory OUTSIDE the vault (see --state-dir),
  so a vault in a sync folder doesn't upload every old version, and a
  delete actually leaves the cloud. The TLS key lives there too.
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
import shlex
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
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

# Where cairn keeps its own files: $XDG_STATE_HOME/cairn, i.e. ~/.local/state/cairn.
STATE_HOME = os.path.join(
    os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"),
                                                     ".local", "state"),
    "cairn")

# Backups, trash and the TLS key are deliberately NOT written into the vault.
# A vault in a sync folder (Proton Drive, iCloud, Dropbox) would otherwise
# upload a copy of every old version on every save, keep "deleted" notes
# synced forever, and — worst — mirror the TLS private key to the provider
# and every linked device. So they go to a per-vault directory under
# STATE_HOME, keyed on the vault's absolute path so two vaults can't collide.
# --state-dir overrides it; set properly in main().
STATE_DIR = None
BACKUP_DIR = TRASH_DIR = CERT_DIR = None

# The only non-hidden directory worth skipping. It is never notes, and a single
# node_modules holds thousands of package README.md files — /api/notes ships
# every note's full text in one payload, so walking it would bloat the response
# enormously and bury the real notes. bin/ was on this list once too, for no
# better reason than that this server used to live in the vault's bin/; that
# silently hid real notes and is why the list is this short. Keep it that way.
SKIP_DIRS = {"node_modules"}

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
}

# A fallback only: main() replaces this with the token persisted in the
# state directory. Generating it per process meant every restart logged
# out every device and the token had to be typed on the phone again.
TOKEN = secrets.token_urlsafe(24)
COOKIE = "notes_session"

# Optional sync command, enabled only by --sync-cmd. cairn neither knows nor
# cares what the script does — it is the user's own, and pointing at one is an
# explicit choice made at startup, the same shape as --vault.
#
# The reason this is safe to put behind a button: nothing from a request ever
# reaches it. No arguments, no shell, no note content, no path — the command is
# fixed when the server starts and run as a one-element argv list. A note is
# text an attacker could have written; it never gets a say in what runs here.
SYNC_CMD = None
SYNC_TIMER = None
SYNC_TIMEOUT = 900
SYNC_STATE = os.path.join(STATE_HOME, "sync.json")
# Two syncs writing the vault at once would fight over the same files, and the
# server is threaded, so concurrent presses are real.
SYNC_LOCK = threading.Lock()


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
        # Hidden directories cover .git/ and .obsidian/, plus a --state-dir
        # someone chose to put back inside the vault. Beyond those, only
        # SKIP_DIRS is hidden from the vault — see the note on it above.
        dirs[:] = [d for d in dirs
                   if not d.startswith(".") and d not in SKIP_DIRS]
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
        dirs[:] = [d for d in dirs
                   if not d.startswith(".") and d not in SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1].lower() in IMAGE_EXT:
                found.setdefault(f, os.path.relpath(os.path.join(root, f), VAULT))
    return found


def default_state_dir(vault):
    """~/.local/state/cairn/vaults/<name>-<hash>: readable, and unique per path."""
    key = hashlib.sha256(vault.encode("utf-8")).hexdigest()[:12]
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.basename(vault)) or "vault"
    return os.path.join(STATE_HOME, "vaults", "%s-%s" % (name, key))


def set_state_dir(path):
    global STATE_DIR, BACKUP_DIR, TRASH_DIR, CERT_DIR
    STATE_DIR = path
    BACKUP_DIR = os.path.join(path, "backups")
    TRASH_DIR = os.path.join(path, "trash")
    CERT_DIR = os.path.join(path, "certs")


def load_token(rotate=False):
    """The access token, kept in the state directory across restarts.

    A token that survives a restart is the difference between pairing a phone
    once and pairing it every single time the server comes back. The cost is
    that the token is now at rest on disk, so it is written 0600 inside a
    0700 directory -- the same posture as the TLS private key already sitting
    beside it, and anyone who can read either can read the vault anyway.
    """
    global TOKEN
    path = os.path.join(STATE_DIR, "token")
    if not rotate:
        try:
            saved = open(path).read().strip()
        except OSError:
            saved = ""
        if saved:
            TOKEN = saved
            return TOKEN
    TOKEN = secrets.token_urlsafe(24)
    # Created with the mode it needs rather than widened and then narrowed:
    # between an open() and a chmod() the token is readable by anyone. The
    # chmod after covers the other case, a file that already existed wider.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(TOKEN + "\n")
    os.chmod(path, 0o600)
    return TOKEN


def inside(path, root):
    return path == root or path.startswith(root + os.sep)


def stamped(base, full):
    """<base>/<vault-relative dir>/<name>.<timestamp>.md — the same shape for
    backups and trash, so two notes with one filename in different folders
    can't land on top of each other."""
    rel = os.path.relpath(full, VAULT)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(base, os.path.dirname(rel),
                        "%s.%s.md" % (os.path.basename(rel)[:-3], stamp))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    return dest


def backup(full):
    """Keep the version we are about to overwrite."""
    if not os.path.isfile(full):
        return None
    dest = stamped(BACKUP_DIR, full)
    shutil.copy2(full, dest)
    return dest


def migrate_state():
    """Vaults from before STATE_DIR existed have .backups/, .trash/ and
    .certs/ inside them. Leaving those behind would be the bad outcome — a
    .trash/ nobody looks at, still syncing, and a private key still in the
    cloud — so on start they are moved into STATE_DIR. Merge, never
    overwrite: anything already at the destination stays, and the old copy
    stays put and gets reported rather than lost."""
    if inside(STATE_DIR, VAULT):
        return []
    moved = []
    for old_name, new_dir in ((".backups", BACKUP_DIR), (".trash", TRASH_DIR),
                              (".certs", CERT_DIR)):
        old = os.path.join(VAULT, old_name)
        if not os.path.isdir(old):
            continue
        left = []
        for root, dirs, files in os.walk(old, topdown=False):
            for f in files:
                src = os.path.join(root, f)
                dst = os.path.join(new_dir, os.path.relpath(src, old))
                if os.path.exists(dst):
                    left.append(src)
                    continue
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(src, dst)
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except OSError:
                    pass
        try:
            os.rmdir(old)
        except OSError:
            pass
        moved.append((old, new_dir, left))
    return moved


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
# optional sync command
# --------------------------------------------------------------------------

def systemd_timer(unit):
    """Next and last firing of a systemd --user timer, in epoch seconds.

    Best effort on purpose: no systemd, no such unit, or a systemctl too old
    for --output=json all mean "unknown" rather than an error the UI has to
    render. list-timers is used rather than `show` because it reports raw
    microseconds, where `show` formats the timestamp in the server's locale.
    """
    try:
        out = subprocess.run(
            ["systemctl", "--user", "list-timers", unit, "--output=json", "--no-pager"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, text=True).stdout
        rows = json.loads(out or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}

    def seconds(v):
        # Microseconds, with a huge sentinel stashed in the field for "never".
        if isinstance(v, (int, float)) and 0 < v < 2 ** 62:
            return v / 1e6
        return None

    for row in rows if isinstance(rows, list) else []:
        if row.get("unit") == unit:
            return {"next": seconds(row.get("next")), "last": seconds(row.get("last"))}
    return {}


def sync_status():
    """Everything the sidebar shows: last run, next run, one in flight."""
    last = None
    try:
        with open(SYNC_STATE, encoding="utf-8") as fh:
            last = json.load(fh)
    except (OSError, ValueError):
        pass                                  # nothing has been recorded yet
    info = {"enabled": bool(SYNC_CMD), "running": SYNC_LOCK.locked(),
            "last": last, "next": None, "timer_last": None}
    if SYNC_TIMER:
        # A timer-driven run happens entirely outside cairn, so its time comes
        # from systemd; only button-driven runs land in SYNC_STATE.
        t = systemd_timer(SYNC_TIMER)
        info["next"] = t.get("next")
        info["timer_last"] = t.get("last")
    return info


def run_sync():
    """Run the configured command and record what happened."""
    started = time.time()
    try:
        proc = subprocess.run(
            [SYNC_CMD],                       # argv list: no shell, no splitting
            cwd=VAULT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=SYNC_TIMEOUT, text=True)
        code, output = proc.returncode, proc.stdout or ""
    except subprocess.TimeoutExpired:
        code, output = None, "timed out after %d seconds" % SYNC_TIMEOUT
    except OSError as e:
        code, output = None, str(e)
    record = {"at": started, "seconds": round(time.time() - started, 1),
              "ok": code == 0, "code": code,
              "output": output[-4000:]}       # a tail is all the UI shows
    try:
        atomic_write(SYNC_STATE, json.dumps(record))
    except OSError:
        pass                                  # a run that went unlogged still ran
    return record


# --------------------------------------------------------------------------
# open a terminal
# --------------------------------------------------------------------------
#
# "Open in terminal" hands a code block to a real terminal window on THIS
# machine with the command typed at the prompt but NOT executed -- the user
# still has to read it and press Enter. Nothing here ever runs the command.
#
# Two things keep that promise:
#   * the command is never handed to a shell for evaluation. It is written to
#     a file and read back with $(cat), and the text a command substitution
#     yields is never re-parsed as shell syntax.
#   * it is put into the line editor, not the shell. bash gets a readline macro
#     bound to the terminal's Device Status Report reply -- a macro types
#     characters and cannot press Return on the user's behalf -- and zsh gets
#     print -z, which pushes text onto the editing buffer stack for the next
#     prompt to pop. If neither lands, nothing is typed and the command is
#     still one Up-arrow away in history.
#
# Three shapes of machine to keep in mind here. Linux runs an emulator binary
# and hands it a command. macOS opens an application, which means a file it can
# be given, and means launchd in between -- so the environment does not carry
# across, which is why the command travels as a file. And $SHELL decides which
# rcfile is written, so a Mac gets zsh rather than a surprise bash prompt.

TERMINAL_CWD = os.path.expanduser("~/workspace")
TERMINAL_ENABLED = True
_TERMINAL = None                             # cached (name, flags), () for none

# Emulator, then the flags meaning "start here" and "run this next". The cwd is
# set on the spawned process too, but several emulators re-exec through a
# launcher that would otherwise land in $HOME, so the explicit flag matters.
# macOS is not in this table: there the terminal is an application, opened by
# `open -a`, and flags is None to say so.
TERMINALS = [
    ("ptyxis",              ["--working-directory={cwd}", "--"]),
    ("konsole",             ["--workdir", "{cwd}", "-e"]),
    ("gnome-terminal",      ["--working-directory={cwd}", "--"]),
    ("kgx",                 ["--working-directory={cwd}", "--"]),
    ("xfce4-terminal",      ["--working-directory={cwd}", "-x"]),
    ("kitty",               ["--directory", "{cwd}", "--"]),
    ("alacritty",           ["--working-directory", "{cwd}", "-e"]),
    ("foot",                ["--working-directory={cwd}", "--"]),
    ("wezterm",             ["start", "--cwd", "{cwd}", "--"]),
    ("tilix",               ["--working-directory={cwd}", "-e"]),
    ("terminator",          ["--working-directory={cwd}", "-x"]),
    ("x-terminal-emulator", ["-e"]),
    ("xterm",               ["-e"]),
]

# The script the emulator is actually given. It exists because macOS needs a
# file it can hand to an application, and because `cd` here means the window
# lands in the right place whatever the emulator does with its own flags. The
# clear is macOS again: Terminal runs this file from a login shell of its own,
# so the window opens on that shell's banner and on the echoed path of this
# script. Wiping it leaves a window that looks like any other new one.
LAUNCHER = """#!/bin/sh
cd __CWD__ 2>/dev/null || cd "$HOME"
clear 2>/dev/null
exec __SHELL__
"""

# Sourced by the throwaway shell. The command is read from a file rather than
# passed in the environment because macOS `open` hands the application to
# launchd, which does not carry the environment across -- and reading a file
# with $(cat) is the same guarantee anyway: command substitution yields text,
# and assigning that text to a variable never re-parses it as shell syntax.
#
# The bash version inserts the command with a readline macro bound to the
# terminal's reply to a Device Status Report: ask for one, and the answer types
# the command at the first prompt. The substitutions escape backslashes and
# quotes so the macro definition stays well formed whatever the note contains,
# and turn newlines into readline's "insert a literal newline", so a multi-line
# block arrives as one editable buffer instead of running a line at a time.
#
# Which startup files to load is a question about the terminal, not the shell,
# so it is asked of the machine rather than of $SHELL. Linux emulators open an
# interactive non-login shell, whose files are /etc/bash.bashrc and ~/.bashrc.
# Terminal.app opens a login shell, and a Mac has neither of those files: the
# system one is /etc/bashrc, reached through /etc/profile where path_helper
# builds PATH, and the user's is ~/.bash_profile. Read the wrong pair and the
# window comes up with a bare bash-3.2 prompt and none of their PATH.
BASH_RC = r"""# written by cairn, deleted as soon as it is read
CAIRN_CMD=$(cat __DIR__/cmd)
rm -rf __DIR__
if [ "$(uname)" = Darwin ]; then
    [ -f /etc/profile ] && . /etc/profile
    for __cairn_rc in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
        [ -f "$__cairn_rc" ] && { . "$__cairn_rc"; break; }
    done
else
    [ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
    [ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
fi
__cairn=${CAIRN_CMD//\\/\\\\}
__cairn=${__cairn//\"/\\\"}
__cairn=${__cairn//$'\n'/\\C-v\\C-j}
bind '"\e[0n": "'"$__cairn"'"' 2>/dev/null && printf '\e[5n'
history -s "$CAIRN_CMD"
unset __cairn __cairn_rc CAIRN_CMD
"""

# zsh needs no trick: print -z pushes text onto the line editor's buffer stack
# and the next prompt pops it in, ready to edit. -r stops print from reading
# backslashes as escapes. Reached when $SHELL is zsh, which on macOS is the
# default, so a Mac gets its own shell rather than a surprise bash prompt.
# ZDOTDIR points zsh at the file above instead of the user's own, so nothing
# they normally load happens by itself -- hence sourcing it here, in the order
# zsh would have. The login shell matters on macOS specifically: /etc/zprofile
# is where path_helper builds PATH, and a window without it would be missing
# every tool the user installed.
ZSH_RC = r"""# written by cairn, deleted as soon as it is read
CAIRN_CMD=$(cat __DIR__/cmd)
rm -rf __DIR__
ZDOTDIR=$HOME
[[ -f $HOME/.zshenv ]] && source $HOME/.zshenv
[[ -o login && -f $HOME/.zprofile ]] && source $HOME/.zprofile
[[ -f $HOME/.zshrc ]] && source $HOME/.zshrc
print -rs -- "$CAIRN_CMD"
print -rz -- "$CAIRN_CMD"
unset CAIRN_CMD
"""


def find_terminal():
    """(name, flags) for the terminal to use, or None. flags is None on macOS,
    where the terminal is an application rather than a binary taking a command.
    $CAIRN_TERMINAL overrides both: a name here, an app name on a Mac."""
    global _TERMINAL
    if _TERMINAL is None:
        _TERMINAL = ()
        override = os.environ.get("CAIRN_TERMINAL")
        if sys.platform == "darwin":
            _TERMINAL = (override or "Terminal", None)
        else:
            table = ([(override, ["-e"])] if override else []) + TERMINALS
            for name, flags in table:
                if shutil.which(name):
                    _TERMINAL = (name, flags)
                    break
    return _TERMINAL or None


def terminal_ready():
    return bool(TERMINAL_ENABLED and find_terminal())


def terminal_argv(name, flags, launcher, cwd):
    """The emulator's command line. Separate from open_terminal so the macOS
    shape can be checked on a machine that isn't one."""
    if flags is None:
        return ["open", "-a", name, launcher]
    return [name] + [f.format(cwd=cwd) for f in flags] + [launcher]


def shell_parts():
    """(rc filename, rc template, how to exec the shell). Follows $SHELL, so a
    Mac gets zsh and this machine gets bash, rather than either being told
    which shell it prefers."""
    if os.path.basename(os.environ.get("SHELL", "")) == "zsh" and shutil.which("zsh"):
        return ".zshrc", ZSH_RC, "env ZDOTDIR=%s zsh -il"
    return "rc.bash", BASH_RC, "bash --rcfile %s/rc.bash -i"


def sweep_stale():
    """A window closed before the shell read its rcfile leaves the directory
    behind. Clear out any old enough to be certainly dead."""
    tmp = tempfile.gettempdir()
    try:
        names = os.listdir(tmp)
    except OSError:
        return
    for name in names:
        stale = os.path.join(tmp, name)
        if not name.startswith("cairn-term-") or not os.path.isdir(stale):
            continue
        try:
            if time.time() - os.path.getmtime(stale) > 600:
                shutil.rmtree(stale, ignore_errors=True)
        except OSError:
            pass


def open_terminal(command):
    """Open a terminal at TERMINAL_CWD with `command` typed but not run."""
    found = find_terminal()
    if not found:
        raise RuntimeError("no terminal emulator found on this machine")
    name, flags = found
    cwd = TERMINAL_CWD if os.path.isdir(TERMINAL_CWD) else os.path.expanduser("~")
    sweep_stale()

    # None of this holds a secret, but the command is the user's business:
    # mkdtemp is 0700, and the rcfile deletes the whole directory -- itself,
    # the command, and the launcher -- the moment the shell reads it.
    rc_dir = tempfile.mkdtemp(prefix="cairn-term-")
    quoted = shlex.quote(rc_dir)
    rc_name, rc_body, shell = shell_parts()
    files = {
        "cmd": (command, 0o600),
        rc_name: (rc_body.replace("__DIR__", quoted), 0o600),
        "launch": (LAUNCHER.replace("__CWD__", shlex.quote(cwd))
                           .replace("__SHELL__", shell % quoted), 0o700),
    }
    for fname, (body, mode) in files.items():
        path = os.path.join(rc_dir, fname)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(path, mode)

    launcher = os.path.join(rc_dir, "launch")
    argv = terminal_argv(name, flags, launcher, cwd)
    try:
        if flags is None:
            # `open` hands the app to launchd and returns straight away, so its
            # exit status is the only chance to notice a missing application.
            done = subprocess.run(argv, cwd=cwd, timeout=15,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if done.returncode != 0:
                raise RuntimeError(done.stderr.decode("utf-8", "replace").strip()
                                   or "could not open %s" % name)
        else:
            subprocess.Popen(argv, cwd=cwd, start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        shutil.rmtree(rc_dir, ignore_errors=True)
        raise RuntimeError("could not start %s: %s" % (name, e))
    return name, cwd


# --------------------------------------------------------------------------
# network / tls
# --------------------------------------------------------------------------

# Interface names another device on the network can never reach us through:
# VPN tunnels, hypervisor and container bridges, virtual ethernet pairs.
# Matched as prefixes.
#
# This list exists because of a real failure, not tidiness. lan_ips() used to
# be a UDP connect() to a TEST-NET address, which reports whichever interface
# owns the default route -- and a VPN owns the default route by design. With
# ProtonVPN up, that returned the tunnel address, the certificate was pinned
# to it, and no other machine on the LAN could validate the result. A down
# libvirt bridge produces the same thing more quietly.
VIRTUAL_IFACE_PREFIXES = (
    "lo", "virbr", "vnet", "docker", "veth", "br-", "tun", "tap", "wg",
    "proton", "utun", "vmnet", "vboxnet", "zt", "tailscale",
)


def enumerate_ipv4():
    """[(interface, address)] for every configured IPv4 address on this box.

    Shells out because the standard library has no portable way to enumerate
    interfaces. getaddrinfo(gethostname()) is the usual stand-in and it is
    not good enough -- on a stock Debian it answers 127.0.1.1 and nothing
    else, which is exactly how the address list ended up empty and the
    default-route probe ended up being the only source. `ip` covers Linux,
    `ifconfig` covers macOS, and if neither answers the caller still has the
    probe to fall back on.
    """
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5, text=True).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    if out:
        # "3: wlan0    inet 10.0.0.87/24 brd 10.0.0.255 scope global ..."
        found = []
        for line in out.splitlines():
            f = line.split()
            if len(f) > 3 and "inet" in f:
                found.append((f[1], f[f.index("inet") + 1].split("/")[0]))
        return found

    try:
        out = subprocess.run(["ifconfig", "-a"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5, text=True).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    # "en0: flags=8863<UP,...>" then an indented "\tinet 192.168.1.5 netmask ..."
    found, iface = [], ""
    for line in out.splitlines():
        if line and not line[0].isspace():
            iface = line.split(":")[0].split()[0]
        f = line.split()
        if iface and "inet" in f:
            found.append((iface, f[f.index("inet") + 1]))
    return found


def lan_ips():
    """Every address another device on this network could reach us on.

    All of them, deliberately, not the single "primary" one: with a VPN up
    this machine has both a tunnel address and its real LAN address, and the
    certificate has to cover whichever one the other device actually dials.
    """
    ips = {ip for iface, ip in enumerate_ipv4()
           if not iface.startswith(VIRTUAL_IFACE_PREFIXES)
           and not ip.startswith("127.")}
    if not ips:
        # Neither tool answered. Ask the kernel which source address reaches
        # the internet: one address rather than all of them, and the VPN's
        # when a VPN is up, but better than pinning the cert to nothing.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))      # TEST-NET-1, never actually sent
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    return sorted(ips)


def lan_names():
    """Names the certificate should also answer to.

    An IP-only certificate has to be regenerated every time DHCP moves the
    machine, and every device that trusted it has to be told to trust it
    again. The mDNS name does not move with the lease, so a device that
    reaches cairn by name keeps working across one.
    """
    names = ["localhost"]
    host = socket.gethostname().split(".")[0]
    if host and host != "localhost":
        names += [host, host + ".local"]
    return names


def cert_alt_names(cert):
    """The subjectAltName entries already in a certificate, openssl-style."""
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, text=True).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    # The values follow a "X509v3 Subject Alternative Name:" header on the
    # line above them. Left in, that header fuses onto the first value and
    # the first name in every certificate reads as missing -- which means
    # regenerating on every single start, and telling the user to re-trust
    # the certificate on every device each time. There is a test for it.
    out = out.split("Name:", 1)[-1]
    got = set()
    for part in out.replace("\n", " ").split(","):
        part = part.strip()
        # openssl prints "IP Address:10.0.0.87" but only accepts "IP:10.0.0.87".
        if part.startswith("IP Address:"):
            got.add("IP:" + part.split(":", 1)[1].strip())
        elif part.startswith("DNS:"):
            got.add("DNS:" + part.split(":", 1)[1].strip())
    return got


def ensure_cert(hosts):
    """Self-signed cert in CERT_DIR, regenerated when it stops fitting.

    Needs openssl.
    """
    os.makedirs(CERT_DIR, exist_ok=True)
    cert = os.path.join(CERT_DIR, "server.crt")
    key = os.path.join(CERT_DIR, "server.key")

    alt = ["DNS:%s" % n for n in lan_names()] + ["IP:127.0.0.1"]
    for h in hosts:
        if h[0].isdigit() and "IP:%s" % h not in alt:
            alt.append("IP:%s" % h)

    if os.path.isfile(cert) and os.path.isfile(key):
        # Deliberately not just "does the file exist". A certificate pinned to
        # an address this machine no longer has is worse than none: the other
        # device rejects the name outright and the failure reads as a network
        # problem rather than a stale file. Missing names mean regenerate.
        # Extra ones -- a VPN that happens to be down right now -- are fine and
        # must not trigger a regeneration, or every connect/disconnect would
        # invalidate the trust the user established on their phone.
        missing = set(alt) - cert_alt_names(cert)
        if not missing:
            return cert, key
        print("  certificate is missing %s — regenerating it."
              % ", ".join(sorted(missing)))
        print("  Devices that trusted the old one will have to trust this one.")

    if not shutil.which("openssl"):
        sys.exit("--tls needs the `openssl` command, which isn't on your PATH.\n"
                 "Install it (sudo apt install openssl) or run without --tls.")

    print("  generating a self-signed certificate in %s …" % CERT_DIR)
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

    def is_local(self):
        """True when the request came from this machine, not the network."""
        host = self.client_address[0]
        return host.startswith("127.") or host in ("::1", "::ffff:127.0.0.1")

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
                                        "images": list_images(), "vault": VAULT,
                                        "terminal": terminal_ready() and self.is_local()})

        if path == "/api/sync/status":
            if not self.authed():
                return self.fail(403, "not unlocked")
            return self.send_json(200, {"ok": True, "sync": sync_status()})

        if path == "/cert":
            # Deliberately unauthenticated, and deliberately the .crt alone.
            # This is the very certificate the server already hands to anyone
            # who opens a TLS connection to it, so publishing it gives away
            # nothing that connecting does not. The private key beside it is
            # served by no route at all.
            #
            # The point of it is the phone. Installing the certificate is what
            # stops the browser warning for good, and a device with no shell
            # and no copy of the state directory has no other way to get the
            # file. Verify the printed fingerprint before trusting it.
            if not self.server.tls:
                return self.fail(404, "server is not running with --tls")
            try:
                with open(os.path.join(CERT_DIR, "server.crt"), "rb") as fh:
                    blob = fh.read()
            except OSError as e:
                return self.fail(500, "cannot read the certificate — %s" % e)
            return self.send(200, blob, "application/x-x509-ca-cert",
                             {"Content-Disposition":
                              'attachment; filename="cairn.crt"'})

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

        if route == "/api/sync":
            if not SYNC_CMD:
                return self.fail(404, "no sync command configured (see --sync-cmd)")
            # Refuse rather than queue: a second sync on top of a running one
            # would have two processes writing the same notes.
            if not SYNC_LOCK.acquire(blocking=False):
                return self.fail(409, "a sync is already running")
            try:
                record = run_sync()
            finally:
                SYNC_LOCK.release()
            # The request succeeded even when the script failed; the client
            # reads record["ok"] to tell those apart, so a failing sync gets a
            # real message instead of a generic transport error.
            return self.send_json(200, {"ok": True, "sync": record})

        if route == "/api/trash":
            try:
                data = self.body_json()
                full = safe_path(data["path"], must_exist=True)
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                return self.fail(400, str(e))
            dest = stamped(TRASH_DIR, full)
            shutil.move(full, dest)
            return self.send_json(200, {"ok": True, "trashed": dest})

        if route == "/api/terminal":
            # Opening a window is the one thing here that reaches outside the
            # vault, so it is deliberately the narrowest route in the file:
            # this machine only. A phone on the LAN is authenticated, but it
            # is not sitting in front of the screen a window would appear on.
            if not self.is_local():
                return self.fail(403, "terminal windows open only on this machine")
            if not TERMINAL_ENABLED:
                return self.fail(403, "terminal opening is off (--no-terminal)")
            try:
                data = self.body_json()
                command = data["command"]
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                return self.fail(400, str(e))
            if not isinstance(command, str) or not command.strip():
                return self.fail(400, "empty command")
            if len(command) > 8192 or "\x00" in command:
                return self.fail(400, "command is not something to type")
            try:
                name, cwd = open_terminal(command)
            except RuntimeError as e:
                return self.fail(503, str(e))
            self.log_message("opened %s in %s (not run)", name, cwd)
            return self.send_json(200, {"ok": True, "terminal": name, "cwd": cwd})

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
    ap.add_argument("--state-dir", default=None,
                    help="where backups/, trash/ and certs/ go (default: a "
                         "per-vault directory under $XDG_STATE_HOME/cairn, "
                         "i.e. ~/.local/state/cairn/vaults/<name>-<hash>)")
    ap.add_argument("--new-token", action="store_true",
                    help="discard the saved token and generate a fresh one, "
                         "logging out every device that had been paired")
    ap.add_argument("--sync-cmd", default=None,
                    help="script the Sync button runs, with no arguments and no "
                         "shell (default: no button, and /api/sync is a 404)")
    ap.add_argument("--sync-timer", default=None,
                    help="systemd --user timer unit to read the next scheduled "
                         "sync from, e.g. vault-sync.timer")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--terminal-cwd", default=None,
                    help="where 'open in terminal' starts (default: ~/workspace)")
    ap.add_argument("--no-terminal", action="store_true",
                    help="refuse to open terminal windows at all")
    args = ap.parse_args()

    global VAULT, SYNC_CMD, SYNC_TIMER, TERMINAL_CWD, TERMINAL_ENABLED
    if args.vault:
        VAULT = os.path.abspath(os.path.expanduser(args.vault))
    if args.terminal_cwd:
        TERMINAL_CWD = os.path.abspath(os.path.expanduser(args.terminal_cwd))
    TERMINAL_ENABLED = not args.no_terminal

    if args.sync_cmd:
        SYNC_CMD = os.path.abspath(os.path.expanduser(args.sync_cmd))
        # Fail here rather than on the first button press, where the only
        # symptom is a red toast in a browser.
        if not os.path.isfile(SYNC_CMD):
            sys.exit("--sync-cmd %s is not a file" % SYNC_CMD)
        if not os.access(SYNC_CMD, os.X_OK):
            sys.exit("--sync-cmd %s is not executable — chmod +x it" % SYNC_CMD)
    SYNC_TIMER = args.sync_timer

    if not os.path.isdir(VAULT):
        sys.exit("vault not found at %s\n"
                 "Pass --vault /path/to/notes or set NOTES_VAULT." % VAULT)
    if not any(f.endswith(".md") for f in os.listdir(VAULT)) and \
       not any(any(f.endswith(".md") for f in fs) for _, _, fs in os.walk(VAULT)):
        sys.exit("no markdown files under %s — is that the right vault?" % VAULT)
    if not os.path.isfile(EDITOR_HTML):
        sys.exit("editor.html not found next to this script")

    if args.state_dir:
        state = os.path.abspath(os.path.expanduser(args.state_dir))
        # Inside the vault is allowed (it is how you get the old behaviour
        # back) but only under a dot-directory, which the listing skips.
        # Anywhere else in the vault, every backup would show up as a note.
        if inside(state, VAULT):
            rel = os.path.relpath(state, VAULT)
            if rel == os.curdir or not rel.split(os.sep)[0].startswith("."):
                sys.exit("--state-dir %s is inside the vault but not hidden — "
                         "backups would be listed as notes.\n"
                         "Use a dot-directory (e.g. %s) or somewhere outside."
                         % (state, os.path.join(VAULT, ".cairn")))
        if inside(VAULT, state):
            sys.exit("--state-dir %s contains the vault" % state)
        set_state_dir(state)
    else:
        set_state_dir(default_state_dir(VAULT))
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    except OSError as e:
        sys.exit("could not create state directory %s — %s" % (STATE_DIR, e))
    migrated = migrate_state()
    load_token(rotate=args.new_token)

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
    print("  state : %s" % STATE_DIR)
    if inside(STATE_DIR, VAULT):
        print("  !! the state directory is inside the vault — the access token")
        print("     and the TLS private key are in a folder you may be syncing.")
    for old, new, left in migrated:
        print("  moved %s -> %s" % (old, new))
        for src in left:
            print("    left in place (already at destination): %s" % src)
    if SYNC_CMD:
        print("  sync  : %s" % SYNC_CMD)
    print("  this machine : %s" % local)
    if exposed:
        for ip in addrs or ["<this machine's IP>"]:
            print("  other devices: %s://%s:%d/" % (scheme, ip, args.port))
        # The mDNS name outlives the DHCP lease the addresses above don't, so
        # it is the one worth bookmarking on a phone. Offered rather than
        # promised: it needs an mDNS responder here (avahi, or Bonjour on a
        # Mac) that is publishing the real LAN interface.
        mdns = [n for n in lan_names() if n.endswith(".local")]
        for name in mdns:
            print("  or, if mDNS works: %s://%s:%d/" % (scheme, name, args.port))
        print("\n  Token (paste it on the other device):\n\n      %s\n" % TOKEN)
        print("  The same token comes back on the next start, so a device you")
        print("  pair once stays paired. --new-token replaces it.\n")
        if args.tls:
            print("  Certificate is self-signed. Install it once per device and")
            print("  the warning stops for good. On the device itself, open:")
            for h in (addrs or ["<this machine's IP>"])[:1] + mdns[:1]:
                print("      %s://%s:%d/cert" % (scheme, h, args.port))
            print("  and trust the file it downloads (iOS: Settings → General →")
            print("  VPN & Device Management, then Certificate Trust Settings).")
            print("  On this machine it is %s"
                  % os.path.join(CERT_DIR, "server.crt"))
            print("  Verify this SHA-256 fingerprint before trusting it:")
            print("      %s\n" % cert_fingerprint(os.path.join(CERT_DIR, "server.crt")))
        else:
            print("  !! PLAIN HTTP ON THE NETWORK !!")
            print("  Your notes and this token cross the wire unencrypted and are")
            print("  readable by anyone else on this network. Restart with --tls.\n")
    print("  Backups go to backups/ and deletes to trash/ under the state directory.")
    if terminal_ready():
        print("  Code blocks open in %s at %s — typed, never run."
              % (find_terminal()[0], TERMINAL_CWD))
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
