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

Python standard library and git: no pip install, no npm, no build step, no
internet.

How access works
----------------
A token is generated on first run, kept in the state directory and printed
in the terminal, so a device you pair once stays paired across restarts.
Opening the printed URL on this machine logs you in automatically.
On another device you open the plain URL and paste the token once; the server
sets a session cookie (HttpOnly, SameSite=Strict) and the token never appears
in a URL, browser history, or the page source.

A client that is not a browser -- a script, an agent with a file tool -- sends
the same token as `Authorization: Bearer <token>` and needs no cookie, and can
say what it is in `X-Cairn-Client: <name>` so the history says where an edit
came from instead of guessing "browser" from a User-Agent. Notes written
straight onto disk are committed one at a time, as soon as cairn next reads or
writes the vault, so they have a history too.

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
  leave a half-written note, and each one is committed to the vault's own git
  repository in the same breath: both, or neither. Every version of every
  note is in `git log`.
* Two browsers editing one note is a three-way merge, not a lost edit: each
  browser session has a branch of its own marking what it has seen, and a
  save that is behind is merged against what is on disk. A hunk both sides
  changed comes back to the browser to resolve.
* If the vault's repository has a pre-commit hook, it can refuse a save --
  paste an API key into a note and nothing reaches disk. cairn never passes
  --no-verify.
* Deleting moves the file to trash/ AND commits the removal. Trash is an
  undelete button; git is the record. trash/ and the TLS key live in a
  per-vault state directory OUTSIDE the vault (see --state-dir).
* Backups (--backup-dir) are a zip and a git bundle written somewhere else,
  usually a Proton Drive folder. The vault itself is local and must not live
  in a provider's folder: cairn says so loudly if it does.
* Paths are resolved and checked against the vault root, so a crafted request
  can't read or write outside it, and only .md files can be written.
"""

import argparse
import hashlib
import html
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
import zipfile
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

# Trash and the TLS key are deliberately NOT written into the vault. A vault
# in a sync folder (Proton Drive, iCloud, Dropbox) would otherwise keep
# "deleted" notes synced forever and — worst — mirror the TLS private key to
# the provider and every linked device. So they go to a per-vault directory
# under STATE_HOME, keyed on the vault's absolute path so two vaults can't
# collide. --state-dir overrides it; set properly in main().
#
# OLD_BACKUP_DIR is where a pre-git cairn kept the previous version of every
# note. Nothing writes there any more — history is `git log` now — but it is
# still the destination migrate_state() empties an old vault's .backups/ into,
# and anything already in it is left alone. It has nothing to do with
# --backup-dir, which is where archives of the whole vault go.
STATE_DIR = None
OLD_BACKUP_DIR = TRASH_DIR = CERT_DIR = None

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

# Not a release process, just a number that moves when the editor does, so a
# screenshot, a bug report and a running server can be talked about as the
# same thing. 0.1 was the three-pane editor; 0.2 drew its controls on canvas,
# put the vault in a tree, the note in an outline and sync in a footer, and
# added live mode. 0.3 made the vault a git repository cairn owns. 0.4 split
# the two jobs that were tangled together in it: git merges what the browsers
# editing this vault are doing, and backups are copies of the whole thing
# somewhere else. 0.5 stopped assuming an edit arrives through the browser:
# a note written straight onto disk is committed like any other, a client
# that is not a browser can say what it is, and a note can be renamed.
VERSION = "0.5.0"

# A fallback only: main() replaces this with the token persisted in the
# state directory. Generating it per process meant every restart logged
# out every device and the token had to be typed on the phone again.
TOKEN = secrets.token_urlsafe(24)
COOKIE = "notes_session"

# Backups are a copy of the vault put somewhere else — Proton Drive, an
# external disk — on a schedule. They are NOT where the vault lives and NOT
# how two devices share edits; git does that, in the vault, on this machine.
# Keeping those two jobs apart is the whole point: a vault living inside a
# provider's folder means a file-sync daemon and cairn writing the same bytes
# with no idea about each other, which is how a merge result gets overwritten
# by a stale copy from another device.
#
# Nothing from a request reaches a command here: every git call below is a
# fixed argv list with no shell, no note content and no path from a request
# body. A note is text an attacker could have written; it never gets a say in
# what runs.
BACKUP_DIR = None                            # --backup-dir, or $CAIRN_BACKUP_DIR
BACKUP_EVERY = 24 * 3600                     # --backup-every hours; 0 is off
BACKUP_STATE = None                          # per vault; set in set_state_dir
BACKUP_TIMEOUT = 900

# One lock over every git command that writes: a merge landing while a save
# stages its file would corrupt the index, and the server is threaded, so that
# collision is real. Re-entrant because a merge commits.
GIT_LOCK = threading.RLock()
# What the lock is being held for, when it is held for long enough to be worth
# saying: "backup" while an archive is being written. A lock held for the
# half-millisecond of a save's commit is not something the footer should show.
BUSY = ""

# The branch the vault's notes live on — what every client's edits are merged
# into, and the only branch ever checked out. Set in git_start().
TRUNK = None
# Client branches are refs/heads/client/<label>-<id>. One per browser session:
# it marks the trunk commit that client has seen, which is what lets cairn say
# "three notes changed on another device since you loaded this" and what a
# save's three-way merge measures against. Set in set_state_dir.
CLIENT_STATE = None
CLIENT_PREFIX = "client/"
CLIENT_COOKIE = "cairn_client"
# What a client that is not a browser calls itself. See clean_label().
CLIENT_HEADER = "X-Cairn-Client"
CLIENTS = {}                                 # id -> {label, branch, first, last}
CLIENTS_LOCK = threading.Lock()

# Everything cairn itself has run, newest last, for the activity panel in the
# footer. In memory only: it is a view of this process's own actions, not a
# record worth keeping across restarts, and the sync script's output can be
# large enough that writing it down would be its own problem.
RUN_LOG = []
RUN_LOG_MAX = 600
RUN_LOG_LOCK = threading.Lock()
_run_seq = 0


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
    global STATE_DIR, OLD_BACKUP_DIR, TRASH_DIR, CERT_DIR, BACKUP_STATE, CLIENT_STATE
    STATE_DIR = path
    OLD_BACKUP_DIR = os.path.join(path, "backups")
    TRASH_DIR = os.path.join(path, "trash")
    CERT_DIR = os.path.join(path, "certs")
    # Per vault, like everything else here. One shared file under STATE_HOME
    # would report one vault's failed backup in another vault's footer.
    BACKUP_STATE = os.path.join(path, "backup.json")
    CLIENT_STATE = os.path.join(path, "clients.json")


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
    """<base>/<vault-relative dir>/<name>.<timestamp>.md — trash keeps the
    note's folder, so two notes with one filename in different folders can't
    land on top of each other. (Migrated backups have the same shape.)"""
    rel = os.path.relpath(full, VAULT)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(base, os.path.dirname(rel),
                        "%s.%s.md" % (os.path.basename(rel)[:-3], stamp))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    return dest


def migrate_state():
    """Vaults from before STATE_DIR existed have .backups/, .trash/ and
    .certs/ inside them. Leaving those behind would be the bad outcome — a
    .trash/ nobody looks at, still syncing, and a private key still in the
    cloud — so on start they are moved into STATE_DIR. Merge, never
    overwrite: anything already at the destination stays, and the old copy
    stays put and gets reported rather than lost.

    .backups/ is on this list even though nothing writes backups any more.
    The vault is a git repository now, and the first thing cairn does with a
    dirty tree is commit it — which would swallow every old version of every
    note into the history it is meant to replace."""
    if inside(STATE_DIR, VAULT):
        return []
    moved = []
    for old_name, new_dir in ((".backups", OLD_BACKUP_DIR), (".trash", TRASH_DIR),
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
# what cairn has run
# --------------------------------------------------------------------------
#
# One append-only buffer of lines, each with a sequence number. The page polls
# with the highest number it has seen and gets only what is newer, so an open
# activity panel costs one small response per poll no matter how long the sync
# script has been talking.

def log_run(text, kind="out"):
    """Record one line for the activity panel. Returns its sequence number."""
    global _run_seq
    with RUN_LOG_LOCK:
        _run_seq += 1
        RUN_LOG.append({"n": _run_seq, "at": time.time(), "kind": kind,
                        "text": text[:2000]})
        del RUN_LOG[:-RUN_LOG_MAX]
        return _run_seq


def run_log_since(n):
    """Lines newer than sequence number n, and the newest number there is."""
    with RUN_LOG_LOCK:
        return [e for e in RUN_LOG if e["n"] > n], _run_seq


# --------------------------------------------------------------------------
# the vault's git repository
# --------------------------------------------------------------------------
#
# cairn owns this repository. Every save is a commit, on a branch named for
# this machine, and `git log` is where a note's history lives — there is no
# .backups/ any more. Two rules hold the whole design up:
#
#   * a save and its commit are atomic. Both or neither. A save whose commit
#     fails leaves the file exactly as it was and tells the user why.
#   * the repository's own hooks stay armed. The vault this was built for has
#     a pre-commit hook that refuses credential-shaped strings, because a live
#     GitHub token sat in a note for months once. cairn never passes
#     --no-verify: if the hook says no, the save is refused and the text stays
#     in the textarea where the user can fix it.
#
# Nothing a request carries ever becomes an argument to git. Paths go through
# safe_path() first and reach git only after `--`; commit messages are built
# here, never taken from the body; and every call is a fixed argv list run
# without a shell.

GIT_TTL = 4.0                                # a poll every few seconds is free
_git_cache = {"at": 0.0, "info": None}

# GIT_TERMINAL_PROMPT=0 so a remote that wants a password fails the sync
# instead of hanging a request forever on a prompt nobody can see.
GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0")


def git(*args, **kw):
    """One git command in the vault. Returns (exit code, output).

    stderr is folded into stdout because the interesting output here is the
    hook's complaint and git's merge chatter, and both should reach the user
    in the order git wrote them.
    """
    timeout = kw.pop("timeout", 120)
    try:
        p = subprocess.run(("git", "-C", VAULT) + args,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, text=True, env=GIT_ENV)
    except subprocess.TimeoutExpired:
        return 1, "git %s timed out after %ds" % (args[0], timeout)
    except OSError as e:
        return 1, str(e)
    return p.returncode, p.stdout.strip()


def _git(*args):
    """One read-only git command. None if git cannot answer.

    --no-optional-locks so that reading the status here can never collide with
    a git command the user is running in a terminal on the same repository.
    """
    code, out = git("--no-optional-locks", *args, timeout=10)
    return out if code == 0 else None


def _git_raw(*args):
    """One read-only git command, output exactly as git wrote it.

    git() strips, which is right for every other caller and wrong for
    `status --porcelain`: an unstaged change has a space in the first column,
    and stripping it turns " D note.md" into a status of "D " and a path with
    its first character eaten. show_at() runs its own git for the same kind
    of reason — the bytes matter there too.
    """
    try:
        p = subprocess.run(("git", "-C", VAULT, "--no-optional-locks") + args,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=10, text=True, env=GIT_ENV)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout if p.returncode == 0 else None


def git_fresh():
    """Forget the cached status — call after anything that writes."""
    _git_cache["info"] = None


def git_tracked(rel):
    return git("ls-files", "--error-unmatch", "--", rel)[0] == 0


def git_dirty():
    return bool(_git("status", "--porcelain"))


def ref_name(text, fallback="unknown"):
    """Sanitise a string into something git will accept as a ref component."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", text or "").strip("-._")
    while ".." in name:
        name = name.replace("..", ".")
    if name.endswith(".lock"):
        name = name[:-5]
    return name[:40] or fallback


def commit_message(verb, full, content=None, client=None, note=None):
    """Built here, never taken from a request. Subject is the note's title,
    which is what a `git log --oneline` is actually read for; the path goes
    in the body, where two notes with one title stay tellable apart, and the
    client that wrote it goes in a trailer so the history says which device
    an edit came from. `note` is one more body line for the cases where the
    path alone does not say what happened — a rename, which has two."""
    if content is None:
        try:
            content = open(full, encoding="utf-8").read()
        except OSError:
            content = ""
    meta, _ = parse_frontmatter(content)
    title = meta.get("title") or os.path.basename(full)[:-3]
    rel = os.path.relpath(full, VAULT)
    trailer = "\nClient: %s\n" % client["label"] if client else ""
    extra = "\n" + note if note else ""
    return "%s %s\n\n%s%s\n%s" % (verb, title.replace("\n", " ")[:60],
                                   rel, extra, trailer)


# --------------------------------------------------------------------------
# clients
# --------------------------------------------------------------------------
#
# One browser session is one client, and every client gets a branch of its
# own. The branch is a bookmark, not a workspace: there is one working tree
# and one checked-out branch (TRUNK), so a client branch records the trunk
# commit that client has seen. That is enough to do both jobs it exists for —
# to tell a client that other devices have moved the notes underneath it, and
# to give a save a base to three-way merge against when they have.
#
# The id is a random cookie value, so it survives a reload and does not
# survive a different device. The label is guessed from the User-Agent and is
# only ever shown, never run and never used as a path.

BROWSERS = [("Firefox", "Firefox"), ("Edg/", "Edge"), ("OPR/", "Opera"),
            ("Chrome", "Chrome"), ("Safari", "Safari")]
PLATFORMS = [("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"),
             ("Macintosh", "Mac"), ("Windows", "Windows"), ("Linux", "Linux")]


def client_label(agent):
    agent = agent or ""
    browser = next((n for k, n in BROWSERS if k in agent), "browser")
    platform = next((n for k, n in PLATFORMS if k in agent), None)
    return "%s on %s" % (browser, platform) if platform else browser


def clean_label(text):
    """A client's own name for itself, made fit to show.

    The User-Agent guess is right for browsers and wrong for everything else:
    a script, a shell one-liner, an agent with a file tool all come out as
    "browser", which makes the one line of history that says where an edit
    came from a lie. So a client may name itself. That name is only ever
    displayed and — at registration, through ref_name() — turned into a
    branch, so what it loses here is anything that is not plain printable
    text, and its length.
    """
    text = re.sub(r"\s+", " ", (text or "").replace("\n", " "))
    return re.sub(r"[^ \w.+@()/-]+", "", text).strip()[:40]


def load_clients():
    global CLIENTS
    try:
        with open(CLIENT_STATE, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            CLIENTS = {k: v for k, v in data.items() if isinstance(v, dict)}
    except (OSError, ValueError):
        CLIENTS = {}
    return CLIENTS


def save_clients():
    try:
        atomic_write(CLIENT_STATE, json.dumps(CLIENTS))
    except OSError:
        pass                                  # a client cairn forgets re-registers


def client_for(cid, agent, create=True, name=None):
    """The record for one client, registering it the first time.

    Returns None when there is no usable id — a request with no client cookie
    and no name of its own is served exactly as before, it just gets no branch
    and no "changed elsewhere" notice.
    """
    name = clean_label(name)
    if not cid and name:
        # A writer that is not a browser has no cookie to carry an id, and
        # asking a script to hold one would be asking it to be a browser. Its
        # name is its identity instead: the same agent gets the same record
        # and the same branch across runs, which is what makes "changed on
        # another device" true of it too. The digest is only to get a legal
        # id out of arbitrary text; nothing is hidden by it.
        cid = "agent-" + hashlib.sha1(name.encode("utf-8")).hexdigest()[:16]
    if not cid or not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", cid):
        return None
    with CLIENTS_LOCK:
        rec = CLIENTS.get(cid)
        if rec is None:
            if not create:
                return None
            label = name or client_label(agent)
            rec = {"label": label, "first": time.time(),
                   "branch": CLIENT_PREFIX + ref_name(label, "client") + "-" + cid[:8]}
            CLIENTS[cid] = rec
        elif name and rec.get("label") != name:
            # A renamed client keeps the branch it was given: the branch is a
            # bookmark with a name on it, not the name itself.
            rec["label"] = name
        rec["last"] = time.time()
        rec.setdefault("label", "browser")
        rec.setdefault("branch", CLIENT_PREFIX + "unknown-" + cid[:8])
        save_clients()
        return dict(rec, id=cid)


def client_mark(rec, sha=None):
    """Point a client's branch at the commit it has now seen.

    Called when a client reads the vault and when one of its saves lands: both
    mean "this session is up to date with trunk as of here". `git branch -f`
    on a branch that is not checked out touches no file in the working tree.
    """
    if not rec:
        return None
    sha = sha or _git("rev-parse", "HEAD")
    if not sha:
        return None
    git("branch", "-f", rec["branch"], sha)
    return sha


def client_base(rec):
    """The trunk commit a client last saw, or None if it has no branch yet."""
    if not rec:
        return None
    return _git("rev-parse", "--verify", "-q", "refs/heads/" + rec["branch"] + "^{commit}")


def client_branches():
    """Every client branch, newest-seen first: (branch, sha, when)."""
    out = _git("for-each-ref",
               "--format=%(refname:short)%09%(objectname)%09%(committerdate:unix)",
               "refs/heads/" + CLIENT_PREFIX.rstrip("/")) or ""
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].isdigit():
            rows.append((parts[0], parts[1], int(parts[2])))
    rows.sort(key=lambda r: -r[2])
    return rows


CLIENT_TTL = 30 * 86400


def prune_clients():
    """Forget browser sessions nobody has used in a month, and delete their
    branches. A branch per browser is fine; a branch per browser per month
    for years is a `git branch` listing nobody can read."""
    cutoff = time.time() - CLIENT_TTL
    with CLIENTS_LOCK:
        stale = [(k, v) for k, v in CLIENTS.items()
                 if (v.get("last") or 0) < cutoff]
        for key, rec in stale:
            CLIENTS.pop(key, None)
        if stale:
            save_clients()
    for _, rec in stale:
        if rec.get("branch", "").startswith(CLIENT_PREFIX):
            git("branch", "-D", rec["branch"])
    return len(stale)


def clients_info(me=None):
    """Who else is editing, and whether trunk has moved under this client."""
    now = time.time()
    others = []
    with CLIENTS_LOCK:
        records = [dict(v, id=k) for k, v in CLIENTS.items()]
    for rec in records:
        if me and rec["id"] == me.get("id"):
            continue
        others.append({"label": rec.get("label", "browser"),
                       "branch": rec.get("branch"),
                       "seen": rec.get("last"),
                       "active": bool(rec.get("last") and now - rec["last"] < 300)})
    others.sort(key=lambda c: -(c.get("seen") or 0))
    info = {"you": me["label"] if me else None,
            "branch": me["branch"] if me else None,
            "others": others[:12],
            "count": len(records)}
    base = client_base(me)
    info["base"] = base
    if base:
        # What has landed on trunk since this client last read the vault. This
        # is the "another device is editing" notice, and it is measured in
        # commits and note paths rather than guessed from a timer.
        count = _git("rev-list", "--count", base + "..HEAD")
        info["behind"] = int(count) if count and count.isdigit() else 0
        if info["behind"]:
            names = _git("diff", "--name-only", base + "..HEAD") or ""
            info["changed"] = [n for n in names.splitlines() if n.endswith(".md")][:50]
    return info


def git_commit(rel, message):
    """Stage one path — or a list of them — and commit only those. (ok, output).

    The pathspec is what keeps a save from sweeping up whatever else is dirty
    in the tree — a note the user is editing in another program, an image
    half-copied into attachments/. It also means the hook only ever sees the
    file this save is about.

    A list is for the one operation that is genuinely several paths at once:
    a rename, which is the note under its new name plus every note whose
    links were repointed at it, and which has to be one commit or none.
    """
    rels = [rel] if isinstance(rel, str) else list(rel)
    # -A so a path that is a deletion stages as one; `git add` without it
    # predates git 2.0 caring, and remove_note has always passed it.
    code, out = git("add", "-A", "--", *rels)
    if code:
        return False, out
    # Identical bytes: a save that changed nothing is a success with nothing
    # to record, not an empty commit and not an error.
    if git("diff", "--cached", "--quiet", "--", *rels)[0] == 0:
        return True, ""
    code, out = git("commit", "-q", "-m", message, "--", *rels)
    return code == 0, out


def git_commit_all(message):
    """Commit the whole tree — used at startup to adopt outside edits, and by
    a sync before it touches anyone else's branch."""
    code, out = git("add", "-A")
    if code:
        return False, out
    if git("diff", "--cached", "--quiet")[0] == 0:
        return True, ""
    code, out = git("commit", "-q", "-m", message)
    return code == 0, out


def git_restore(rel, tracked):
    """Put one path back the way HEAD has it, and unstage it.

    The rollback half of "both or neither": it runs when a commit was refused,
    and its job is to leave no trace of the write that was refused.
    """
    git("reset", "-q", "--", rel)
    if tracked:
        git("checkout", "-q", "HEAD", "--", rel)
    else:
        try:
            os.remove(os.path.join(VAULT, rel))
        except OSError:
            pass


# --------------------------------------------------------------------------
# what something other than cairn wrote
# --------------------------------------------------------------------------
#
# Not every edit arrives over HTTP. A note can be written straight onto disk
# by an editor, a script, or an agent with a file tool — and until that edit
# is committed it is invisible to everything cairn does with history. Worse
# than invisible: trunk has not moved, so a browser save carrying `base ==
# HEAD` skips the merge in save_note() and writes over it, and because the
# outside version was never committed there is nothing to recover it from.
#
# So an outside edit is adopted, one note at a time, and as soon as cairn
# notices it. Per-note because a commit called "Adopt changes made outside
# cairn" covering fourteen unrelated notes is not history — it is a lump with
# no title, no path, and nobody's name on it, and the history panel can say
# nothing useful about any note in it. Adopting it properly costs one commit
# each and makes the other four things true at once: `git log -- <note>` has
# the version in it, the panel names who wrote it, trunk moves, and the next
# browser save is a merge instead of an overwrite.

# The client label for an edit that did not come through the API. It is a
# client record in the sense commit_message() cares about — a thing with a
# label — and nothing else: no id, no branch, no session.
OUTSIDE = {"label": "outside cairn"}


def outside_paths():
    """Every path the working tree and HEAD disagree about: [(rel, verb)].

    `-z` because the alternative is git's quoted paths, and a note called
    `Ça va.md` is not an edge case in a vault of prose. `--untracked-files=all`
    so a whole new folder of notes lists as its notes rather than as the
    folder. A rename someone else staged carries its old name in a field of
    its own; that name is taken too, so nothing is left for the sweep.
    """
    out = _git_raw("status", "--porcelain", "-z", "--untracked-files=all")
    if not out:
        return []
    fields = out.split("\0")
    rows, i = [], 0
    while i < len(fields):
        entry, i = fields[i], i + 1
        if len(entry) < 4:
            continue
        code, rel = entry[:2], entry[3:]
        if code[0] in "RC":
            old = fields[i] if i < len(fields) else ""
            i += 1
            if old:
                rows.append((old, "Delete"))
        if "D" in code:
            verb = "Delete"
        elif code == "??" or code[0] == "A":
            verb = "Add"
        else:
            verb = "Update"
        rows.append((rel, verb))
    return rows


def adopt_outside(label=None):
    """Commit what arrived on disk, a note per commit. (adopted, refused).

    Each note gets the commit it would have got had it been saved through the
    browser: its title as the subject, its path in the body, and a Client
    trailer naming where the edit came from. Anything that is not a note — an
    image dropped into attachments/, a file the vault's own tooling wrote —
    is swept up at the end in one commit, because a title is not a thing it
    has.

    A note the repository refuses is left exactly as it is, on disk and out of
    the index, and the notes beside it still land. That is the difference
    between this and the single commit it replaces: one credential-shaped
    string in one note used to mean nothing at all could be adopted.

    The caller holds GIT_LOCK.
    """
    rows = outside_paths()
    if not rows:
        return [], []
    who = dict(OUTSIDE, label=label) if label else OUTSIDE
    adopted, refused, others = [], [], []
    for rel, verb in rows:
        if not rel.lower().endswith(".md"):
            others.append(rel)
            continue
        full = os.path.join(VAULT, rel)
        ok, out = git_commit(rel, commit_message(verb, full, None, who))
        if ok:
            adopted.append(rel)
        else:
            # Unstage, and nothing more. The bytes on disk are not cairn's to
            # roll back here — they are somebody's unsaved work, and the only
            # copy of it. write_note() restores a file because it wrote it;
            # this did not.
            git("reset", "-q", "--", rel)
            refused.append((rel, out))
    if others:
        ok, out = git_commit(others, "Adopt files that are not notes")
        if ok:
            adopted.extend(others)
        else:
            git("reset", "-q", "--", *others)
            refused.append((", ".join(others[:4]), out))
    if adopted or refused:
        git_fresh()
    return adopted, refused


def adopt_and_log(label=None):
    """adopt_outside(), with what it did written to the activity panel."""
    adopted, refused = adopt_outside(label)
    for rel in adopted:
        log_run("adopted %s — written outside cairn" % rel)
    for rel, why in refused:
        log_run("could not adopt %s — %s" % (rel, (why or "").splitlines()[0]
                                             if why else "the commit was refused"), "err")
    return adopted, refused


# --------------------------------------------------------------------------
# the three-way merge a save does
# --------------------------------------------------------------------------
#
# Two browsers editing one note used to be a 409 and a message telling you to
# reload and retype. It is a merge now: the client sends the trunk commit its
# copy came from, and a save that is not on top of trunk is merged against the
# version that is — the same three-way merge a pull request gets, done in the
# half-second of a save instead of in a branch someone has to remember to open.
#
# Only a hunk both sides touched stops it. Then nothing is written, the two
# versions and the conflicting hunks go back to the browser, and the user
# picks a side per hunk and saves the result — which is an ordinary save,
# because by then it is on top of trunk again.

MERGE_MARK = re.compile(r"^(<{7}|\|{7}|={7}|>{7}) ")


def merge3(base, mine, ondisk, nonce):
    """git merge-file, run on three temp files. (text, conflicted).

    A file rather than stdin because merge-file wants three paths, and in a
    temp directory rather than the vault so a merge never leaves anything
    behind for the next `git add` to sweep up. Labels carry a nonce so that a
    note which itself contains conflict markers cannot be misread as one.
    """
    tmp = tempfile.mkdtemp(prefix="cairn-merge-")
    try:
        paths = {}
        for name, text in (("mine", mine), ("base", base), ("ondisk", ondisk)):
            paths[name] = os.path.join(tmp, name)
            with open(paths[name], "w", encoding="utf-8") as fh:
                fh.write(text)
        p = subprocess.run(
            ["git", "merge-file", "-p", "--diff3",
             "-L", "yours " + nonce, "-L", "base " + nonce, "-L", "vault " + nonce,
             paths["mine"], paths["base"], paths["ondisk"]],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=30, env=GIT_ENV)
        # Exit status is the number of conflicts, and negative on a real
        # error — which the None return above is for.
        if p.returncode < 0:
            return None, True
        return p.stdout, p.returncode != 0
    except (OSError, subprocess.SubprocessError):
        return None, True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def split_conflicts(text, nonce):
    """Conflict-marked text -> a list of segments the browser can render.

    Each segment is either {"kind": "same", "text": …} or {"kind": "clash",
    "yours": …, "base": …, "vault": …}. Parsed rather than handed over raw so
    the editor can offer a choice per hunk instead of asking someone to edit
    around seven-angle-bracket lines by hand.
    """
    segments, same = [], []
    state = None
    yours = base = vault = []
    for line in text.splitlines(keepends=True):
        head = line.rstrip("\n")
        if head == "<<<<<<< yours " + nonce:
            if same:
                segments.append({"kind": "same", "text": "".join(same)})
                same = []
            state, yours, base, vault = "yours", [], [], []
            continue
        if state and head == "||||||| base " + nonce:
            state = "base"
            continue
        if state and head == "=======":
            state = "vault"
            continue
        if state and head == ">>>>>>> vault " + nonce:
            segments.append({"kind": "clash", "yours": "".join(yours),
                             "base": "".join(base), "vault": "".join(vault)})
            state = None
            continue
        if state == "yours":
            yours.append(line)
        elif state == "base":
            base.append(line)
        elif state == "vault":
            vault.append(line)
        else:
            same.append(line)
    if same:
        segments.append({"kind": "same", "text": "".join(same)})
    return segments


def show_at(sha, rel):
    """One note exactly as of one commit, or None if it wasn't there then.

    Not through git(), which strips: a note's trailing newline is part of the
    file, and a merge base one byte off from what was committed produces a
    conflict out of nothing.
    """
    try:
        p = subprocess.run(("git", "-C", VAULT, "--no-optional-locks", "show",
                            "%s:%s" % (sha, rel)),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=20, env=GIT_ENV)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    try:
        return p.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def save_note(full, content, client=None, base=None, auto=False):
    """Save one note onto trunk, merging first if trunk has moved.

    `auto` only picks the commit's verb. An autosave is an ordinary save in
    every other respect — same merge, same hooks, same one commit — but a
    history read with `git log --oneline` is worth being able to skim, and
    "the editor saved this because I stopped typing" and "I pressed Save"
    are different enough to be worth telling apart. It is a choice between
    two literals here, never a string from the request: see commit_message.

    Returns a dict the route hands back more or less as it stands:
      {"ok": True,  "commit": …, "content": …, "merged": bool}
      {"ok": False, "conflict": {...}}          nothing written
      {"ok": False, "refused": …}               the hook said no, nothing written
    """
    rel = os.path.relpath(full, VAULT)
    with GIT_LOCK:
        # Anything written to the vault from outside gets its history before
        # this save gets its own. Without that, an edit made on disk since
        # this browser last read leaves trunk where it was, `base == head`
        # skips the merge below, and the save replaces it with no trace of
        # what was there — which is the one outcome invariant 8 exists to
        # prevent. Committing it first turns that case back into a merge.
        if git_dirty():
            adopt_and_log()
        head = _git("rev-parse", "HEAD")
        merged = False
        if base and head and base != head and os.path.isfile(full):
            # The client is behind. Its edit is a patch against `base`, and
            # what is on disk is trunk's version — the ordinary pull-request
            # shape, and merge-file is the whole of it.
            was = show_at(base, rel)
            ondisk = open(full, encoding="utf-8").read()
            if was is not None and was != ondisk:
                nonce = secrets.token_hex(4)
                text, clashed = merge3(was, content, ondisk, nonce)
                if text is None:
                    return {"ok": False, "error": "the merge could not be run"}
                if clashed:
                    log_run("merge conflict in %s" % rel, "err")
                    return {"ok": False, "conflict": {
                        "path": rel, "base": base, "head": head,
                        "yours": content, "vault": ondisk,
                        "segments": split_conflicts(text, nonce)}}
                content, merged = text, True
                log_run("merged %s with the version on trunk" % rel)
        ok, detail, previous = write_note(full, content,
                                          "Autosave" if auto else "Update", client)
        if not ok:
            return {"ok": False, "refused": detail,
                    "content": previous if previous is not None else "",
                    "mtime": os.path.getmtime(full) if os.path.isfile(full) else None}
        client_mark(client)
        return {"ok": True, "commit": detail, "merged": merged, "content": content,
                "mtime": os.path.getmtime(full),
                "head": _git("rev-parse", "HEAD")}


def write_note(full, content, verb, client=None):
    """Write one note and commit it, or leave the vault exactly as it was.

    Returns (ok, detail, previous) — detail is the new commit's sha on
    success and git's own words on failure, and previous is the text that was
    there before, which the client needs to stay truthful about the file it
    thinks it has open.
    """
    rel = os.path.relpath(full, VAULT)
    with GIT_LOCK:
        existed = os.path.isfile(full)
        previous = None
        if existed:
            try:
                previous = open(full, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                previous = None
        tracked = git_tracked(rel)
        atomic_write(full, content)
        ok, out = git_commit(rel, commit_message(verb, full, content, client))
        if not ok:
            git_restore(rel, tracked)
            # A tracked file comes back from HEAD; an untracked one is gone.
            # Either way the bytes on disk are the ones `previous` describes,
            # so the client can be told the truth about what it has open.
            git_fresh()
            return False, out, previous
        git_fresh()
        return True, _git("rev-parse", "--short", "HEAD") or "", previous


def remove_note(full, client=None):
    """Move a note to the trash and commit the removal.

    Trash and history are different jobs: trash is an undelete button for
    someone who clicked the wrong note, history is the record of what the
    vault said. Both, therefore, not either.
    """
    rel = os.path.relpath(full, VAULT)
    with GIT_LOCK:
        # Same reason as save_note(): an edit made outside cairn and never
        # committed would go into the trash without ever having been in the
        # history, and trash and history are different jobs.
        if git_dirty():
            adopt_and_log()
        dest = stamped(TRASH_DIR, full)
        shutil.move(full, dest)
        message = commit_message("Delete", full, "", client)
        code, out = git("add", "-A", "--", rel)
        if code == 0:
            code, out = git("commit", "-q", "-m", message, "--", rel)
        git_fresh()
        if code:
            # The note is already in the trash, so there is nothing to undo —
            # but the removal is not in the history, and saying so is better
            # than a silent divergence between the two.
            return dest, out
        client_mark(client)
        return dest, None


# --------------------------------------------------------------------------
# renaming a note
# --------------------------------------------------------------------------
#
# A rename is a move and a link rewrite, and it is one commit or none. The
# link rewrite is the part that makes it worth doing in the app at all: `mv`
# is one command, but a vault where half the [[wikilinks]] point at a name
# nothing has any more is worse than one where the note kept its old title.
# git records the move itself — `git add -A -- <old> <new>` and git works out
# that it is a rename — so `git log --follow` walks a note's history straight
# through it.

WIKILINK = re.compile(r"(!?)\[\[([^\]\n|#]+)([^\]\n]*)\]\]")


def link_names(rel):
    """The two ways a wikilink can name one note: by its bare filename, and
    by its vault-relative path. Both without the extension, which links
    normally leave off."""
    return os.path.basename(rel)[:-3], rel[:-3]


def retarget(text, old_rel, new_rel):
    """Point every [[wikilink]] and ![[embed]] at a note's new name.

    A link that named the note by its filename keeps naming it that way; one
    that spelled out the folder keeps the folder. Rewriting one style into
    the other would churn every note in the vault the first time anybody
    renamed anything, and the diff is meant to be readable.
    """
    old_stem, old_path = link_names(old_rel)
    new_stem, new_path = link_names(new_rel)

    def one(m):
        bang, target, rest = m.group(1), m.group(2), m.group(3)
        name = target.strip()
        bare = name[:-3] if name.lower().endswith(".md") else name
        if bare.lower() == old_path.lower():
            now = new_path
        elif bare.lower() == old_stem.lower():
            now = new_stem
        else:
            return m.group(0)
        if name.lower().endswith(".md"):
            now += name[-3:]
        return "%s[[%s%s]]" % (bang, now, rest)

    return WIKILINK.sub(one, text)


def rename_note(full, dest, client=None):
    """Move one note, repoint the links that name it, commit all of it once.

    Both or neither, the same rule a save keeps: if the repository refuses
    the commit, the note goes back under its old name and every rewritten
    link goes back to the bytes it had.
    """
    old_rel = os.path.relpath(full, VAULT)
    new_rel = os.path.relpath(dest, VAULT)
    with GIT_LOCK:
        if os.path.exists(dest):
            return {"ok": False, "error": "a note with that name already exists"}
        # Whatever is on disk gets its own history before the move does, so a
        # rename cannot swallow an edit that was never committed.
        if git_dirty():
            adopt_and_log()
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.replace(full, dest)
        except OSError as e:
            return {"ok": False, "error": "could not move the note — %s" % e}

        # A note whose frontmatter title was its filename had the two in
        # step, and the sidebar shows the title — so renaming the file and
        # leaving the title behind would rename nothing the user can see. A
        # title that was already something else was chosen, and is left alone.
        retitled = None
        try:
            text = open(dest, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            text = None
        if text is not None:
            meta, _ = parse_frontmatter(text)
            old_stem, new_stem = link_names(old_rel)[0], link_names(new_rel)[0]
            if meta.get("title", "").strip() == old_stem:
                # Kept, because the rollback below has to put this back too:
                # a refused rename that left the note under its old name with
                # its new title in the frontmatter would be half a rename.
                retitled = text
                atomic_write(dest, re.sub(r"(?m)\A(---\n(?:.*\n)*?title:).*$",
                                          lambda m: m.group(1) + " " + new_stem,
                                          text, count=1))

        touched, originals = [old_rel, new_rel], {}
        for note in list_notes():
            if note["path"] == new_rel:
                continue
            fixed = retarget(note["raw"], old_rel, new_rel)
            if fixed != note["raw"]:
                originals[note["path"]] = note["raw"]
                atomic_write(os.path.join(VAULT, note["path"]), fixed)
                touched.append(note["path"])

        ok, out = git_commit(touched, commit_message(
            "Rename", dest, None, client, note="was " + old_rel))
        if not ok:
            for rel, was in originals.items():
                atomic_write(os.path.join(VAULT, rel), was)
            try:
                os.replace(dest, full)
                if retitled is not None:
                    atomic_write(full, retitled)
            except OSError:
                pass
            git("reset", "-q", "--", *touched)
            git_fresh()
            return {"ok": False, "refused": out}

        # The folder a note was the last thing in is not a folder any more.
        # git does not track directories, so nothing else would remove it.
        old_dir = os.path.dirname(full)
        if old_dir != VAULT:
            try:
                os.rmdir(old_dir)
            except OSError:
                pass
        client_mark(client)
        git_fresh()
        log_run("renamed %s to %s" % (old_rel, new_rel))
        return {"ok": True, "path": new_rel, "was": old_rel,
                "relinked": sorted(originals),
                "commit": _git("rev-parse", "--short", "HEAD") or "",
                "head": _git("rev-parse", "HEAD"),
                "mtime": os.path.getmtime(dest)}


LOG_FORMAT = "--format=%H%x1f%h%x1f%ct%x1f%s%x1f%b%x1e"
RENAMED_FROM = re.compile(r"(?m)^was (.+)$")


def parse_log(out):
    """git log, as written by LOG_FORMAT, into what the history panel draws."""
    versions = []
    for chunk in (out or "").split("\x1e"):
        bits = chunk.strip("\n").split("\x1f")
        if len(bits) >= 4 and bits[2].isdigit():
            body = bits[4] if len(bits) > 4 else ""
            who = re.search(r"(?m)^Client: (.+)$", body)
            versions.append({"sha": bits[0], "short": bits[1], "at": int(bits[2]),
                             "subject": bits[3], "body": body,
                             "client": who.group(1) if who else None})
    return versions


def note_history(rel, limit=40):
    """Every version of one note, back through the renames it has had.

    Not `git log --follow`: that asks git to guess from content similarity,
    and two notes made from the same frontmatter scaffold are similar enough
    for it to graft one note's history onto another that is still sitting
    there. cairn does not have to guess. It wrote `was <path>` into the body
    of every rename commit it made, so the chain is a fact recorded in the
    history rather than an inference drawn from it.
    """
    versions, seen, path = [], set(), rel
    since = []                               # the commit to walk back from
    while path and path not in seen and len(versions) < limit:
        seen.add(path)
        out = _git("log", "-%d" % (limit - len(versions)), LOG_FORMAT,
                   *(since + ["--", path]))
        batch = parse_log(out)
        versions += batch
        # A rename cairn made is the oldest thing this path can have: before
        # it, the note was somewhere else.
        was = RENAMED_FROM.search(batch[-1]["body"]) if batch else None
        if not was or not batch[-1]["subject"].startswith("Rename "):
            break
        path, since = was.group(1).strip(), [batch[-1]["sha"] + "^"]
    for v in versions:
        v.pop("body", None)
    return versions


def git_start():
    """Make the vault a repository cairn owns, checked out on trunk, with a
    tree that agrees with HEAD. Exits rather than starting in any state where
    "every save is a commit" would be a lie."""
    global TRUNK
    if not shutil.which("git"):
        sys.exit("git is not on PATH.\n"
                 "cairn keeps every version of every note in a git repository "
                 "in the vault, so it needs git installed.")

    top = _git("rev-parse", "--show-toplevel")
    if not top:
        code, out = git("init", "-b", "main")
        if code:
            sys.exit("could not create a git repository in %s — %s" % (VAULT, out))
        print("  git   : created a repository in the vault")
    elif os.path.realpath(top) != os.path.realpath(VAULT):
        sys.exit("the vault is inside the git repository at %s, not at its root.\n"
                 "cairn commits every save and moves branches of its own, which "
                 "would move that repository's branches too.\n"
                 "Serve the repository root with --vault, or give the vault its "
                 "own repository." % top)

    # Local only, and only when the machine has no identity of its own: a
    # commit with no author fails, and failing every save on a fresh machine
    # over a git config nobody has set yet would be a poor first impression.
    if not _git("config", "user.email"):
        git("config", "user.email", "cairn@" + socket.gethostname().split(".")[0])
    if not _git("config", "user.name"):
        git("config", "user.name", "cairn")

    if not _git("rev-parse", "--verify", "-q", "HEAD"):
        ok, out = git_commit_all("Adopt the vault as it stands")
        if not ok:
            sys.exit("the first commit was refused:\n\n%s\n\n"
                     "cairn keeps history in this repository, so it will not "
                     "start with a tree it cannot commit." % out)

    # Trunk is whatever the vault is already checked out on — cairn does not
    # get to rename someone's branch. The exception is a branch cairn itself
    # made under an older design: 0.3 put every machine on host/<hostname>,
    # which was a way of sharing a vault between machines through a remote.
    # There is one vault on one machine now, and its notes live on one branch.
    current = _git("rev-parse", "--abbrev-ref", "HEAD")
    TRUNK = current
    if not current or current == "HEAD" or current.startswith(("host/", CLIENT_PREFIX)):
        # A branch cairn itself made under an older design: 0.3 put every
        # machine on host/<hostname> and shared a vault between machines
        # through a remote. There is one vault on one machine now and its
        # notes live on one branch, so the machine branch is retired — but
        # only by fast-forwarding main onto the commits it holds. Moving to a
        # main that has diverged would take a working tree of notes back to
        # whatever it said, so that case keeps the branch it is on.
        want, head = "main", _git("rev-parse", "HEAD")
        exists = git("rev-parse", "--verify", "-q", "refs/heads/" + want)[0] == 0
        if exists and head and git("merge-base", "--is-ancestor", want, "HEAD")[0] != 0:
            print("  git   : staying on %s — %s has commits it does not"
                  % (current, want))
        else:
            if exists:
                git("branch", "-f", want, head)   # fast-forward, checked above
            else:
                code, out = git("branch", want)
                if code:
                    sys.exit("could not create the branch %s — %s" % (want, out))
            code, out = git("checkout", "-q", want)
            if code:
                sys.exit("could not check out %s — %s.\ncairn keeps the notes "
                         "on one branch; %s is where it wants them."
                         % (want, out, want))
            TRUNK = want
            if current and current != want:
                print("  git   : moved off %s onto %s — the old branch is "
                      "still there" % (current, want))

    # A tree that disagrees with HEAD at startup would make "every save is a
    # commit" false from the first request: the next save would carry along
    # whatever else was lying around. So it is adopted, or cairn does not run.
    if git_dirty():
        adopted, refused = adopt_outside()
        if refused:
            sys.exit("changes already in the vault could not be committed:\n\n"
                     "%s\n\nFix or remove what the hook objects to, then start "
                     "cairn again."
                     % "\n\n".join("%s:\n%s" % r for r in refused))
        print("  git   : committed %d change%s that were already in the vault"
              % (len(adopted), "" if len(adopted) == 1 else "s")
              if len(adopted) != 1 else
              "  git   : committed one change that was already in the vault")
    git_fresh()


def git_info():
    """Branch, working-tree counts, distance from upstream, last commit."""
    now = time.time()
    if _git_cache["info"] is not None and now - _git_cache["at"] < GIT_TTL:
        return _git_cache["info"]

    top = _git("rev-parse", "--show-toplevel")
    if not top:
        info = {"repo": False}
    else:
        branch = _git("rev-parse", "--abbrev-ref", "HEAD")
        porcelain = _git("status", "--porcelain") or ""
        changed = untracked = 0
        for line in porcelain.splitlines():
            if line.startswith("??"):
                untracked += 1
            elif line.strip():
                changed += 1

        upstream = _git("rev-parse", "--abbrev-ref", "--symbolic-full-name",
                        "@{upstream}")
        ahead = behind = None
        if upstream:
            counts = _git("rev-list", "--left-right", "--count",
                          "@{upstream}...HEAD")
            if counts:
                parts = counts.split()
                if len(parts) == 2 and all(p.isdigit() for p in parts):
                    behind, ahead = int(parts[0]), int(parts[1])

        last = None
        head = _git("log", "-1", "--format=%h%x1f%s%x1f%ct")   # empty repo: None
        if head:
            bits = head.split("\x1f")
            if len(bits) == 3 and bits[2].isdigit():
                last = {"short": bits[0], "subject": bits[1], "at": int(bits[2])}

        commits = _git("rev-list", "--count", "HEAD")
        info = {"repo": True, "root": top,
                "branch": None if branch in (None, "HEAD") else branch,
                "trunk": TRUNK, "detached": branch == "HEAD",
                "changed": changed, "untracked": untracked,
                "clean": changed == 0 and untracked == 0,
                "upstream": upstream, "ahead": ahead, "behind": behind,
                "commits": int(commits) if commits and commits.isdigit() else None,
                "last": last,
                "clients": len(client_branches())}

    _git_cache.update(at=now, info=info)
    return info


# Directory names a provider gives its sync folder. macOS File Provider names
# come first; the plain names cover Linux clients and anyone who made the
# folder themselves.
CLOUD_DIRS = [
    (re.compile(r"^ProtonDrive-(.+)-folder$"), "Proton Drive"),
    (re.compile(r"^Proton\s?Drive$", re.I),    "Proton Drive"),
    (re.compile(r"^com~apple~CloudDocs$"),     "iCloud Drive"),
    (re.compile(r"^iCloud\s?Drive$", re.I),    "iCloud Drive"),
    (re.compile(r"^Dropbox( .+)?$"),           "Dropbox"),
]


def provider_at(start):
    """Which provider's folder a path is inside, if any.

    Called about two paths that want opposite answers. A backup directory
    inside Proton Drive is the point. The *vault* inside Proton Drive is the
    thing this version of cairn exists to stop: a file-sync daemon and cairn
    writing the same notes with no idea about each other, where a merge cairn
    just made is overwritten by a stale copy from another device.

    Honest about its limits either way: this is path inspection and one stat.
    Proton Drive on macOS is a File Provider extension with no public
    interface to its upload queue, so cairn can say the folder is there and
    readable and cannot say whether the last write has reached the cloud.
    """
    path = os.path.abspath(start)
    while True:
        parent, name = os.path.split(path)
        if not name:                          # walked past the filesystem root
            return {"detected": False}
        for pattern, provider in CLOUD_DIRS:
            m = pattern.match(name)
            if m:
                account = m.group(1) if m.groups() else None
                return {"detected": True, "provider": provider,
                        "account": account, "root": path,
                        "present": os.path.isdir(path),
                        "inside": os.path.relpath(os.path.abspath(start), path)}
        if parent == path:                    # a relative path with no parent
            return {"detected": False}
        path = parent


def vault_info():
    """Where the notes actually are, and whether that is a place to keep them.

    The open vault is local, full stop. This is the chip that says so, and
    says loudly when it isn't.
    """
    cloud = provider_at(VAULT)
    return {"path": VAULT, "state": STATE_DIR,
            "in_provider": bool(cloud.get("detected")),
            "provider": cloud.get("provider"), "root": cloud.get("root")}


# --------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------
#
# A backup is a copy of the vault somewhere else — Proton Drive, an external
# disk, anywhere --backup-dir points. It is storage, not sharing: nothing is
# ever read back from it automatically, and the vault never lives inside it.
#
# Each run writes three files with one timestamp:
#
#   cairn-<vault>-<stamp>.zip     every note and attachment, openable by hand
#   cairn-<vault>-<stamp>.bundle  the whole git history, one file, restorable
#                                 with `git clone <file> notes`
#   cairn-<vault>-<stamp>.json    what commit it was taken at, and how big
#
# The zip is the copy a person can read without git; the bundle is the one
# that still has every version of every note in it. The manifest is what lets
# cairn say what has changed since — it names a commit, so "3 notes changed
# since your last backup" is `git diff --name-only <that commit>..HEAD`
# rather than a guess from timestamps.
#
# Nothing from a request reaches any of this. There is no path in a body, no
# name from a note, and no shell: the only argument cairn did not write is
# --backup-dir, which came from the command line.

ARCHIVE = re.compile(r"^cairn-(.+)-(\d{8}-\d{6})\.json$")


def backup_name():
    return "cairn-%s-%s" % (ref_name(os.path.basename(VAULT), "vault"),
                            datetime.now().strftime("%Y%m%d-%H%M%S"))


def backup_files():
    """Every file a backup should contain, vault-relative.

    The same filter the note listing uses, plus attachments: hidden
    directories are out (that is .git, whose history the bundle carries
    properly) and so is node_modules.
    """
    found = []
    for root, dirs, files in os.walk(VAULT):
        dirs[:] = [d for d in dirs
                   if not d.startswith(".") and d not in SKIP_DIRS]
        for f in sorted(files):
            if f.startswith("."):
                continue
            full = os.path.join(root, f)
            if os.path.isfile(full) and not os.path.islink(full):
                found.append(os.path.relpath(full, VAULT))
    return found


def newest_archive():
    """The most recent manifest actually sitting in the backup directory.

    Read rather than trusted from cairn's own state file, because the state
    file only knows about backups this machine made and the directory is the
    thing the user actually has. A backup deleted to save space stops being
    reported as the last one, which is the truthful answer.
    """
    if not BACKUP_DIR or not os.path.isdir(BACKUP_DIR):
        return None
    best = None
    try:
        names = os.listdir(BACKUP_DIR)
    except OSError:
        return None
    for name in sorted(names, reverse=True):
        if not ARCHIVE.match(name):
            continue
        try:
            with open(os.path.join(BACKUP_DIR, name), encoding="utf-8") as fh:
                rec = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict) and rec.get("at"):
            if best is None or rec["at"] > best["at"]:
                best = rec
    return best


def since_backup(sha):
    """What has changed since the commit a backup was taken at."""
    out = {"commits": None, "notes": None, "unknown": False}
    if not sha or git("cat-file", "-e", sha + "^{commit}", timeout=10)[0] != 0:
        # The bundle is from a history this repository does not have — a
        # vault that was re-initialised, or someone else's backup in the
        # folder. Saying "unknown" beats printing a number that means nothing.
        out["unknown"] = bool(sha)
        return out
    count = _git("rev-list", "--count", sha + "..HEAD")
    out["commits"] = int(count) if count and count.isdigit() else 0
    names = _git("diff", "--name-only", sha + "..HEAD") or ""
    out["notes"] = len([n for n in names.splitlines() if n.endswith(".md")])
    return out


def backup_status():
    """Everything the footer's backup chip draws."""
    info = {"enabled": bool(BACKUP_DIR), "dir": BACKUP_DIR,
            "every": BACKUP_EVERY, "running": BUSY == "backup",
            "provider": None, "present": False, "writable": False,
            "last": None, "since": None, "next": None, "error": None}
    if not BACKUP_DIR:
        return info
    prov = provider_at(BACKUP_DIR)
    info["provider"] = prov.get("provider")
    info["present"] = os.path.isdir(BACKUP_DIR)
    info["writable"] = info["present"] and os.access(BACKUP_DIR, os.W_OK)
    try:
        with open(BACKUP_STATE, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = None
    # The directory wins over cairn's own record of what it did: a backup that
    # someone deleted to save space is not a backup any more, and a backup
    # another machine left there is.
    info["last"] = newest_archive()
    if state and not state.get("ok"):
        info["error"] = (state.get("error") or "").strip()[:400] or "the last backup failed"
        info["failed_at"] = state.get("at")
    info["since"] = since_backup((info["last"] or {}).get("commit"))
    if BACKUP_EVERY and info["last"]:
        info["next"] = info["last"]["at"] + BACKUP_EVERY
    elif BACKUP_EVERY:
        info["next"] = time.time()            # never backed up: it is due now
    return info


def run_backup():
    """Write one zip, one bundle and one manifest. Assumes GIT_LOCK is held.

    The lock is not about the zip — it is the bundle: `git bundle create`
    reads refs and objects, and a commit landing halfway through would be a
    bundle of a history that never existed.
    """
    started = time.time()

    def say(text, kind="out"):
        for line in str(text).splitlines() or [""]:
            log_run(line, kind)

    log_run("backup to %s" % BACKUP_DIR, "start")
    stem = backup_name()
    dirty = None
    # The zip is the working tree and the bundle is the history: if the tree
    # has uncommitted changes in it those two disagree, and a restore from
    # one would not match a restore from the other. So anything outstanding
    # is committed first — the same thing startup does, for the same reason.
    # A hook that refuses does not cancel the backup: a copy of the notes as
    # they are is worth more than a clean pair of files, and the record says
    # which it got.
    if git_dirty():
        adopted, refused = adopt_outside()
        for rel in adopted:
            say("committed %s, which was already in the vault" % rel)
        for rel, why in refused:
            say("%s could not be committed — %s" % (rel, why), "err")
        dirty = ", ".join(r for r, _ in refused) or None
    record = {"at": started, "ok": False, "vault": VAULT,
              "commit": _git("rev-parse", "HEAD"), "uncommitted": dirty,
              "branch": TRUNK, "name": stem}
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
    except OSError as e:
        record["error"] = "cannot write to %s — %s" % (BACKUP_DIR, e)
        say(record["error"], "err")
        return finish_backup(record, started)

    # Written beside the destination and moved into place, so a backup
    # interrupted halfway leaves no half-file for the next run to count as
    # the newest one.
    tmp = tempfile.mkdtemp(prefix="cairn-backup-", dir=BACKUP_DIR)
    try:
        files = backup_files()
        zip_tmp = os.path.join(tmp, stem + ".zip")
        say("zipping %d file%s" % (len(files), "" if len(files) == 1 else "s"), "cmd")
        with zipfile.ZipFile(zip_tmp, "w", zipfile.ZIP_DEFLATED) as z:
            for rel in files:
                z.write(os.path.join(VAULT, rel), os.path.join(stem, rel))
        record["files"] = len(files)
        record["zip_bytes"] = os.path.getsize(zip_tmp)

        bundle_tmp = os.path.join(tmp, stem + ".bundle")
        say("git bundle create <backup>.bundle --all", "cmd")
        code, out = git("bundle", "create", bundle_tmp, "--all",
                        timeout=BACKUP_TIMEOUT)
        if code:
            raise OSError(out or "git bundle failed")
        record["bundle_bytes"] = os.path.getsize(bundle_tmp)
        record["ok"] = True
        record["zip"] = stem + ".zip"
        record["bundle"] = stem + ".bundle"

        manifest = os.path.join(tmp, stem + ".json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        for name in (stem + ".zip", stem + ".bundle", stem + ".json"):
            os.replace(os.path.join(tmp, name), os.path.join(BACKUP_DIR, name))
        say("wrote %s.zip (%s) and %s.bundle (%s)"
            % (stem, human(record["zip_bytes"]), stem, human(record["bundle_bytes"])))
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        record["ok"] = False
        record["error"] = str(e)
        say(str(e), "err")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return finish_backup(record, started)


def finish_backup(record, started):
    record["seconds"] = round(time.time() - started, 1)
    log_run("backup %s in %ss" % ("finished" if record["ok"] else "failed",
                                  record["seconds"]),
            "end" if record["ok"] else "err")
    try:
        atomic_write(BACKUP_STATE, json.dumps(record))
    except OSError:
        pass                                  # a run that went unlogged still ran
    return record


def human(n):
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def backup_now(force=False):
    """Take the lock and run a backup, or say why not. (record or None, error)."""
    if not BACKUP_DIR:
        return None, "no backup directory — start cairn with --backup-dir"
    if not GIT_LOCK.acquire(blocking=False):
        return None, "the repository is busy — try again in a moment"
    global BUSY
    BUSY = "backup"
    try:
        return run_backup(), None
    finally:
        BUSY = ""
        GIT_LOCK.release()


def backup_loop():
    """Take a backup when one is due. A thread, checking every few minutes.

    Deliberately dumb: it asks the same question the footer does — is the next
    backup time in the past — so what the user is shown and what the timer
    does can never disagree. A missed window because the machine was asleep
    just makes the next check overdue, which is what the user wanted anyway.
    """
    while True:
        time.sleep(300)
        try:
            if not BACKUP_DIR or not BACKUP_EVERY:
                continue
            status = backup_status()
            if status["next"] and status["next"] <= time.time():
                record, why = backup_now()
                if why:
                    log_run("scheduled backup skipped — %s" % why, "err")
        except Exception as e:                # a backup must never kill the server
            log_run("scheduled backup failed — %s" % e, "err")


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

def note_route(raw):
    """The route to send a browser back to, or "/" if it isn't one of ours.

    Only "/" and /n/<note path> are pages, so anything else — an absolute URL,
    a protocol-relative "//host", an API path — collapses to the root rather
    than becoming a redirect to somewhere we didn't mean to send anyone."""
    raw = (raw or "/").split("#")[0].split("?")[0]
    if raw == "/n/" or not raw.startswith("/n/") or raw.startswith("/n//"):
        return "/"
    return "/" if "\\" in raw else raw


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
  <input type="hidden" name="next" value="__NEXT__">
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
    server_version = "cairn/" + VERSION
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
        # A list of pairs, not just a dict: a response that both unlocks the
        # session and hands out a client id sends two Set-Cookie headers, and
        # a dict cannot hold two of those.
        pairs = extra.items() if isinstance(extra, dict) else (extra or [])
        for k, v in pairs:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, code, obj):
        self.send(code, json.dumps(obj, ensure_ascii=False))

    def fail(self, code, msg):
        self.send_json(code, {"ok": False, "error": msg})

    def redirect(self, to, extra=None):
        pairs = list(extra.items() if isinstance(extra, dict) else (extra or []))
        self.send(303, b"", "text/plain", [("Location", to)] + pairs)

    def cookie(self, name):
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        try:
            jar = http.cookies.SimpleCookie()
            jar.load(raw)
            return jar[name].value if name in jar else ""
        except Exception:
            return ""

    def cookie_token(self):
        return self.cookie(COOKIE)

    def client(self, create=True):
        """The session behind this request, or None if it has no id.

        Everything works without one — the id only buys a branch and the
        notice that another device has moved the notes. A client that is not
        a browser names itself in X-Cairn-Client; a page in another tab could
        not send that header without a preflight this server refuses, so it
        is no more forgeable than the token already is.
        """
        return client_for(self.cookie(CLIENT_COOKIE),
                          self.headers.get("User-Agent"), create=create,
                          name=self.headers.get(CLIENT_HEADER))

    def query_token(self):
        return urllib.parse.parse_qs(
            urllib.parse.urlparse(self.path).query).get("token", [""])[0]

    def is_local(self):
        """True when the request came from this machine, not the network."""
        host = self.client_address[0]
        return host.startswith("127.") or host in ("::1", "::ffff:127.0.0.1")

    def bearer_token(self):
        """`Authorization: Bearer <token>`, for callers that are not browsers.

        The same token, presented the way every HTTP client already knows how
        to present one — which is the difference between a script that can
        write a note in one call and one that has to POST the unlock form and
        keep a cookie jar. It is not a second way in: no header, no token, no
        entry, and the cross-origin refusal above still runs first.
        """
        scheme, _, value = (self.headers.get("Authorization") or "").partition(" ")
        return value.strip() if scheme.lower() == "bearer" else ""

    def authed(self):
        """Token gate. Also refuses cross-origin requests outright."""
        origin = self.headers.get("Origin")
        if origin:
            host = self.headers.get("Host", "")
            if urllib.parse.urlparse(origin).netloc != host:
                return False
        for given in (self.headers.get("X-Notes-Token"), self.bearer_token(),
                      self.cookie_token(), self.query_token()):
            if given and secrets.compare_digest(given, TOKEN):
                return True
        return False

    def set_session(self, client=True):
        """The session cookie, and a client id if this browser has none.

        Same posture as the session cookie — HttpOnly and SameSite=Strict —
        because it names a branch in the user's repository. It is a random
        value and nothing else: no device fingerprint, no account, and it
        never leaves this server.
        """
        secure = "; Secure" if self.server.tls else ""
        out = [("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Strict%s"
                              % (COOKIE, TOKEN, secure))]
        if client and not self.cookie(CLIENT_COOKIE):
            out.append(("Set-Cookie",
                        "%s=%s; Path=/; Max-Age=31536000; HttpOnly; "
                        "SameSite=Strict%s"
                        % (CLIENT_COOKIE, secrets.token_urlsafe(12), secure)))
        return out

    def unlock_page(self, err="", nxt="/"):
        page = UNLOCK.replace("__ERR__", err).replace("__NEXT__",
                                                      html.escape(nxt, quote=True))
        risky = self.server.exposed and not self.server.tls
        page = page.replace("__WARN__", INSECURE_WARN if risky else "")
        self.send(200, page, "text/html; charset=utf-8")

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

        # "/" and every /n/<note path> are the same page: the editor decides
        # which note to open from the address, so a note can be linked to,
        # bookmarked, and reached with the back button.
        if path == "/" or path.startswith("/n/"):
            if not self.authed():
                return self.unlock_page(nxt=note_route(url.path))
            # Token arrived in the URL: convert it to a cookie and drop it from
            # the address bar so it never lands in history.
            if self.query_token():
                return self.redirect(note_route(url.path), self.set_session())
            try:
                html = open(EDITOR_HTML, encoding="utf-8").read()
            except OSError:
                return self.send(500, "editor.html is missing from bin/",
                                 "text/plain; charset=utf-8")
            return self.send(200, html, "text/html; charset=utf-8", self.set_session())

        if path == "/unlock":
            return self.unlock_page(nxt=note_route(
                urllib.parse.parse_qs(url.query).get("next", ["/"])[0]))

        if path == "/api/notes":
            if not self.authed():
                return self.fail(403, "not unlocked")
            # Anything written to the vault while cairn was running is
            # committed here, before the vault is read, so that what this
            # response carries and the commit it names are the same thing.
            # Startup is too late for it: a note an agent or an editor wrote
            # an hour ago would have no history until the next restart, and
            # the first browser save on top of it would silently replace it.
            #
            # Non-blocking, and all three steps under the one lock: a backup
            # can hold it for a while, and a page load waiting on one would
            # look like a hung server. Skipping the whole block costs this
            # client one stale "changed elsewhere" line and one late
            # adoption, which are much smaller things to be wrong about.
            notes, head = None, None
            if GIT_LOCK.acquire(blocking=False):
                try:
                    if git_dirty():
                        adopt_and_log()
                    notes = list_notes()
                    # This client has now read the whole vault, so its branch
                    # moves to the commit it read — which is what the next
                    # save merges against and what "changed on another
                    # device" is counted from.
                    head = client_mark(self.client())
                finally:
                    GIT_LOCK.release()
                git_fresh()
            if notes is None:
                notes = list_notes()
            if head is None:
                head = _git("rev-parse", "HEAD")
            return self.send_json(200, {"ok": True, "notes": notes,
                                        "images": list_images(), "vault": VAULT,
                                        "head": head,
                                        "terminal": terminal_ready() and self.is_local()})

        if path == "/api/status":
            # Everything the footer draws, in one request: where the notes
            # are, the repository they live in, the other browsers editing
            # them, and the state of the backups.
            if not self.authed():
                return self.fail(403, "not unlocked")
            return self.send_json(200, {"ok": True, "version": VERSION,
                                        "git": git_info(), "vault": vault_info(),
                                        "backup": backup_status(),
                                        "clients": clients_info(self.client())})

        if path == "/api/history":
            # Every version of one note, or of the whole vault. Read-only, and
            # the only thing from the request that reaches git is a path that
            # went through safe_path() and lands after `--`.
            if not self.authed():
                return self.fail(403, "not unlocked")
            q = urllib.parse.parse_qs(url.query)
            rel = (q.get("path") or [""])[0]
            if rel:
                try:
                    safe_path(rel)
                except ValueError as e:
                    return self.fail(400, str(e))
                versions = note_history(rel)
            else:
                versions = parse_log(_git("log", "-40", LOG_FORMAT))
                for v in versions:
                    v.pop("body", None)
            return self.send_json(200, {"ok": True, "path": rel,
                                        "versions": versions})

        if path == "/api/history/show":
            if not self.authed():
                return self.fail(403, "not unlocked")
            q = urllib.parse.parse_qs(url.query)
            sha = (q.get("sha") or [""])[0]
            rel = (q.get("path") or [""])[0]
            # Hex only. A sha is the one thing here that is not a path, so it
            # gets its own check rather than being trusted for looking short.
            if not re.fullmatch(r"[0-9a-fA-F]{7,64}", sha or ""):
                return self.fail(400, "not a commit id")
            try:
                safe_path(rel)
            except ValueError as e:
                return self.fail(400, str(e))
            text = show_at(sha, rel)
            if text is None:
                return self.fail(404, "that note is not in that commit")
            return self.send_json(200, {"ok": True, "sha": sha, "path": rel,
                                        "content": text})

        if path == "/api/run/log":
            if not self.authed():
                return self.fail(403, "not unlocked")
            try:
                since = int((urllib.parse.parse_qs(url.query).get("since")
                             or ["0"])[0])
            except ValueError:
                since = 0
            lines, seq = run_log_since(since)
            return self.send_json(200, {"ok": True, "lines": lines, "seq": seq,
                                        "running": bool(BUSY), "busy": BUSY})

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

        if data.get("stamp", True):
            content = touch_updated(content)

        # `base` is the commit the browser's copy came from. It replaces the
        # mtime check that used to refuse a save outright: knowing the base
        # means a save that is behind can be merged instead of rejected. An
        # older client that sends only an mtime still gets the old behaviour.
        base = data.get("base")
        if not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{7,64}", base or ""):
            base = None
        seen = data.get("mtime")
        if base is None and seen is not None and os.path.isfile(full):
            if abs(os.path.getmtime(full) - float(seen)) > 0.001:
                return self.fail(409, "changed on disk since you opened it")

        result = save_note(full, content, self.client(), base,
                           auto=data.get("auto") is True)
        if result.get("conflict"):
            # 409 with both versions and the hunks that clash. Nothing was
            # written: the browser shows the two sides, the user picks one per
            # hunk, and what comes back is an ordinary save on top of trunk.
            return self.send_json(409, {"ok": False,
                                        "error": "this note changed on another device "
                                                 "while you were editing it",
                                        "conflict": result["conflict"]})
        if not result["ok"] and result.get("refused") is not None:
            # 422: the request was fine, the repository refused it — a
            # pre-commit hook finding a credential-shaped string is why this
            # normally happens. Nothing was written, so the client is handed
            # the file as it still is, and the user still has their text in
            # the textarea to fix.
            return self.send_json(422, {
                "ok": False,
                "error": "the vault's git hook refused this save",
                "refused": result["refused"],
                "content": result.get("content") or "",
                "mtime": result.get("mtime")})
        if not result["ok"]:
            return self.fail(500, result.get("error") or "the save did not happen")
        return self.send_json(200, result)

    def do_POST(self):
        route = urllib.parse.urlparse(self.path).path

        if route == "/unlock":
            try:
                form = urllib.parse.parse_qs(self.body_bytes(limit=4096).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return self.unlock_page("Malformed request.")
            given = (form.get("token") or [""])[0].strip()
            nxt = note_route((form.get("next") or ["/"])[0])
            if secrets.compare_digest(given, TOKEN):
                self.log_message("unlocked")
                return self.redirect(nxt, self.set_session())
            time.sleep(0.7)                      # blunt the guessing rate
            self.log_message("FAILED unlock attempt")
            return self.unlock_page("That token doesn't match. Check the terminal.",
                                    nxt)

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
            ok, detail, _ = write_note(full, body, "Add", self.client())
            if not ok:
                return self.send_json(422, {"ok": False, "refused": detail,
                                            "error": "the vault's git hook refused this note"})
            client_mark(self.client())
            return self.send_json(200, {"ok": True, "path": os.path.relpath(full, VAULT),
                                        "commit": detail, "content": body,
                                        "head": _git("rev-parse", "HEAD"),
                                        "mtime": os.path.getmtime(full)})

        if route == "/api/rename":
            # Two paths from the request, both through safe_path(), which is
            # what keeps a rename inside the vault and on a .md file. Neither
            # ever reaches git as anything but a pathspec after `--`.
            try:
                data = self.body_json()
                full = safe_path(data["path"], must_exist=True)
                dest = safe_path(data["to"])
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                return self.fail(400, str(e))
            if os.path.normcase(dest) == os.path.normcase(full):
                return self.fail(400, "that is the name it already has")
            result = rename_note(full, dest, self.client())
            if result.get("refused") is not None:
                return self.send_json(422, {
                    "ok": False, "refused": result["refused"],
                    "error": "the vault's git hook refused this rename"})
            if not result["ok"]:
                return self.fail(409, result["error"])
            return self.send_json(200, result)

        if route == "/api/backup":
            # Nothing in the body is read. Where a backup goes was decided on
            # the command line, and a request does not get to name a path to
            # write a copy of the whole vault into.
            if not BACKUP_DIR:
                return self.fail(404, "this cairn has no backup directory — "
                                      "start it with --backup-dir")
            record, why = backup_now()
            if why:
                return self.fail(409, why)
            # The request succeeded even when the backup failed; the client
            # reads record["ok"] to tell those apart, so a failed backup gets
            # a real message instead of a generic transport error.
            return self.send_json(200, {"ok": True, "backup": record,
                                        "status": backup_status()})

        if route == "/api/trash":
            try:
                data = self.body_json()
                full = safe_path(data["path"], must_exist=True)
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                return self.fail(400, str(e))
            dest, why = remove_note(full, self.client())
            # The note is in the trash either way; `why` says the removal did
            # not make it into the history, which is worth telling the user.
            return self.send_json(200, {"ok": True, "trashed": dest,
                                        "uncommitted": why})

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
            # Worth a line in the activity panel: it is the other thing cairn
            # does to the machine. Only the first line, and only as far as the
            # first newline -- the panel is a record that it happened, not a
            # second copy of the code block.
            first = command.strip().splitlines()[0]
            log_run("%s: %s%s" % (name, first[:120],
                                  " …" if len(command.strip()) > len(first[:120]) else ""),
                    "term")
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
                    help="where trash/ and certs/ go (default: a per-vault "
                         "directory under $XDG_STATE_HOME/cairn, i.e. "
                         "~/.local/state/cairn/vaults/<name>-<hash>)")
    ap.add_argument("--version", action="version", version="cairn " + VERSION)
    ap.add_argument("--new-token", action="store_true",
                    help="discard the saved token and generate a fresh one, "
                         "logging out every device that had been paired")
    ap.add_argument("--backup-dir", default=None,
                    help="where backups of the whole vault go — a Proton Drive "
                         "folder, an external disk. Also read from "
                         "$CAIRN_BACKUP_DIR. The vault itself must not be in "
                         "there.")
    ap.add_argument("--backup-every", type=float, default=24,
                    help="hours between automatic backups (default 24; 0 for "
                         "manual only)")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--terminal-cwd", default=None,
                    help="where 'open in terminal' starts (default: ~/workspace)")
    ap.add_argument("--no-terminal", action="store_true",
                    help="refuse to open terminal windows at all")
    args = ap.parse_args()

    global VAULT, BACKUP_DIR, BACKUP_EVERY, TERMINAL_CWD, TERMINAL_ENABLED
    if args.vault:
        VAULT = os.path.abspath(os.path.expanduser(args.vault))
    if args.terminal_cwd:
        TERMINAL_CWD = os.path.abspath(os.path.expanduser(args.terminal_cwd))
    TERMINAL_ENABLED = not args.no_terminal


    backup_dir = args.backup_dir or os.environ.get("CAIRN_BACKUP_DIR")
    if backup_dir:
        BACKUP_DIR = os.path.abspath(os.path.expanduser(backup_dir))
    BACKUP_EVERY = int(max(0.0, args.backup_every) * 3600)

    if not os.path.isdir(VAULT):
        sys.exit("vault not found at %s\n"
                 "Pass --vault /path/to/notes or set NOTES_VAULT." % VAULT)
    if not any(f.endswith(".md") for f in os.listdir(VAULT)) and \
       not any(any(f.endswith(".md") for f in fs) for _, _, fs in os.walk(VAULT)):
        sys.exit("no markdown files under %s — is that the right vault?" % VAULT)
    if not os.path.isfile(EDITOR_HTML):
        sys.exit("editor.html not found next to this script")
    if BACKUP_DIR and (inside(VAULT, BACKUP_DIR) or inside(BACKUP_DIR, VAULT)):
        # Backups are a copy somewhere else. A backup directory inside the
        # vault would be committed, zipped into the next backup, and grow by
        # its own size every run; a vault inside the backup directory would
        # have cairn writing into the folder a sync daemon owns.
        sys.exit("--backup-dir %s and the vault %s are inside one another.\n"
                 "Backups are a copy of the vault somewhere else — point "
                 "--backup-dir at a folder outside it." % (BACKUP_DIR, VAULT))

    if args.state_dir:
        state = os.path.abspath(os.path.expanduser(args.state_dir))
        # Inside the vault is allowed (it is how you get the old behaviour
        # back) but only under a dot-directory, which the listing skips.
        # Anywhere else in the vault, every trashed note would come back as
        # one — and, worse, be committed.
        if inside(state, VAULT):
            rel = os.path.relpath(state, VAULT)
            if rel == os.curdir or not rel.split(os.sep)[0].startswith("."):
                sys.exit("--state-dir %s is inside the vault but not hidden — "
                         "trashed notes would be listed as notes.\n"
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
    load_clients()

    print("\n  cairn %s" % VERSION)
    print("  vault : %s" % VAULT)
    # Before the port is bound and before the banner's remaining lines: this
    # can exit, and it can print, and a half-started server is worse than one
    # that never came up.
    git_start()
    prune_clients()

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

    print("  notes : %d" % len(list_notes()))
    print("  branch: %s" % TRUNK)
    print("  state : %s" % STATE_DIR)
    if inside(STATE_DIR, VAULT):
        print("  !! the state directory is inside the vault — the access token")
        print("     and the TLS private key are in a folder you may be syncing.")
    for old, new, left in migrated:
        print("  moved %s -> %s" % (old, new))
        for src in left:
            print("    left in place (already at destination): %s" % src)
    if BACKUP_DIR:
        every = ("every %g hours" % (BACKUP_EVERY / 3600.0)) if BACKUP_EVERY \
                else "on request only"
        print("  backup: %s, %s" % (BACKUP_DIR, every))
        prov = provider_at(BACKUP_DIR)
        if prov.get("detected"):
            print("          in %s%s" % (prov["provider"],
                                         " — " + prov["account"] if prov.get("account") else ""))
        if not os.path.isdir(BACKUP_DIR):
            print("          !! that folder is not there right now")
    else:
        print("  backup: off — pass --backup-dir to keep copies somewhere else")
    here = provider_at(VAULT)
    if here.get("detected"):
        # The mistake this version exists to stop. Not fatal — it is the
        # user's vault — but it is the first thing the banner should say.
        print("  !! the vault is inside %s (%s)." % (here["provider"], here["root"]))
        print("     %s's client and cairn will both write these files, and the"
              % here["provider"])
        print("     one that finishes last wins — including over a merge cairn")
        print("     just made. Move the vault out and back it up there instead.")
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
    print("  Every save is a commit on %s, merged from the branch of the" % TRUNK)
    print("  browser that made it. Deletes also go to trash/ under the state")
    print("  directory, so a wrong click is one file move to undo.")
    if terminal_ready():
        print("  Code blocks open in %s at %s — typed, never run."
              % (find_terminal()[0], TERMINAL_CWD))
    print("  Ctrl-C to stop.\n")

    if BACKUP_DIR and BACKUP_EVERY:
        threading.Thread(target=backup_loop, daemon=True).start()

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
