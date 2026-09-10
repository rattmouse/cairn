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
  note is in `git log`, on a branch named for this machine.
* If the vault's repository has a pre-commit hook, it can refuse a save --
  paste an API key into a note and nothing reaches disk. cairn never passes
  --no-verify.
* Deleting moves the file to trash/ AND commits the removal. Trash is an
  undelete button; git is the record. trash/ and the TLS key live in a
  per-vault state directory OUTSIDE the vault (see --state-dir), so a vault
  in a sync folder doesn't keep "deleted" notes synced forever and doesn't
  mirror the private key to the provider.
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

# Trash and the TLS key are deliberately NOT written into the vault. A vault
# in a sync folder (Proton Drive, iCloud, Dropbox) would otherwise keep
# "deleted" notes synced forever and — worst — mirror the TLS private key to
# the provider and every linked device. So they go to a per-vault directory
# under STATE_HOME, keyed on the vault's absolute path so two vaults can't
# collide. --state-dir overrides it; set properly in main().
#
# BACKUP_DIR is where a pre-git cairn kept the previous version of every note.
# Nothing writes there any more — history is `git log` now — but it is still
# the destination migrate_state() empties an old vault's .backups/ into, and
# anything already in it is left alone.
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

# Not a release process, just a number that moves when the editor does, so a
# screenshot, a bug report and a running server can be talked about as the
# same thing. 0.1 was the three-pane editor; 0.2 drew its controls on canvas,
# put the vault in a tree, the note in an outline and sync in a footer, and
# added live mode. 0.3 made the vault a git repository cairn owns.
VERSION = "0.3.0"

# A fallback only: main() replaces this with the token persisted in the
# state directory. Generating it per process meant every restart logged
# out every device and the token had to be typed on the phone again.
TOKEN = secrets.token_urlsafe(24)
COOKIE = "notes_session"

# Sync is built in rather than configured: it moves this machine's branch
# through the repository's `origin` and merges the other machines' branches
# back. It used to be --sync-cmd, an arbitrary script; what made that safe
# survives the change unaltered. Nothing from a request ever reaches a
# command: every git call below is a fixed argv list with no shell, no note
# content and no path from a request body. A note is text an attacker could
# have written; it never gets a say in what runs here. The remote is whatever
# `origin` is in the vault, set once by the user with git.
SYNC_TIMER = None
SYNC_TIMEOUT = 900
SYNC_STATE = None                            # per vault; set in set_state_dir
# One lock over every git command that writes. It was SYNC_LOCK and covered
# only the sync script; cairn commits on every save now, and a merge landing
# while a save stages its file would corrupt the index. The server is
# threaded, so that collision is real. Re-entrant because a sync commits.
GIT_LOCK = threading.RLock()
# Whether the lock is held by a sync in particular. The footer asks "is a sync
# running", and a lock held for the half-millisecond of a save's commit is not
# an answer to that question.
SYNCING = False

# The branch this machine writes, host/<hostname>. Set in git_start().
BRANCH = None

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
    global STATE_DIR, BACKUP_DIR, TRASH_DIR, CERT_DIR, SYNC_STATE
    STATE_DIR = path
    BACKUP_DIR = os.path.join(path, "backups")
    TRASH_DIR = os.path.join(path, "trash")
    CERT_DIR = os.path.join(path, "certs")
    # Per vault, like everything else here. It was one shared file under
    # STATE_HOME, which meant a failed sync of one vault was reported in the
    # footer of another — invisible when this was a line of text in a sidebar,
    # and a red dot now that it is not.
    SYNC_STATE = os.path.join(path, "sync.json")


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


def git_fresh():
    """Forget the cached status — call after anything that writes."""
    _git_cache["info"] = None


def git_tracked(rel):
    return git("ls-files", "--error-unmatch", "--", rel)[0] == 0


def git_dirty():
    return bool(_git("status", "--porcelain"))


def host_branch():
    """host/<this machine>. Sanitised because it becomes a ref name."""
    name = socket.gethostname().split(".")[0]
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-._")
    while ".." in name:
        name = name.replace("..", ".")
    if name.endswith(".lock"):
        name = name[:-5]
    return "host/" + (name or "unknown")


def commit_message(verb, full, content=None):
    """Built here, never taken from a request. Subject is the note's title,
    which is what a `git log --oneline` is actually read for; the path goes
    in the body, where two notes with one title stay tellable apart."""
    if content is None:
        try:
            content = open(full, encoding="utf-8").read()
        except OSError:
            content = ""
    meta, _ = parse_frontmatter(content)
    title = meta.get("title") or os.path.basename(full)[:-3]
    rel = os.path.relpath(full, VAULT)
    return "%s %s\n\n%s\n" % (verb, title.replace("\n", " ")[:60], rel)


def git_commit(rel, message):
    """Stage one path and commit only that path. (ok, output).

    The pathspec is what keeps a save from sweeping up whatever else is dirty
    in the tree — a note the user is editing in another program, an image
    half-copied into attachments/. It also means the hook only ever sees the
    file this save is about.
    """
    code, out = git("add", "--", rel)
    if code:
        return False, out
    # Identical bytes: a save that changed nothing is a success with nothing
    # to record, not an empty commit and not an error.
    if git("diff", "--cached", "--quiet", "--", rel)[0] == 0:
        return True, ""
    code, out = git("commit", "-q", "-m", message, "--", rel)
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


def write_note(full, content, verb):
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
        ok, out = git_commit(rel, commit_message(verb, full, content))
        if not ok:
            git_restore(rel, tracked)
            # A tracked file comes back from HEAD; an untracked one is gone.
            # Either way the bytes on disk are the ones `previous` describes,
            # so the client can be told the truth about what it has open.
            git_fresh()
            return False, out, previous
        git_fresh()
        return True, _git("rev-parse", "--short", "HEAD") or "", previous


def remove_note(full):
    """Move a note to the trash and commit the removal.

    Trash and history are different jobs: trash is an undelete button for
    someone who clicked the wrong note, history is the record of what the
    vault said. Both, therefore, not either.
    """
    rel = os.path.relpath(full, VAULT)
    with GIT_LOCK:
        dest = stamped(TRASH_DIR, full)
        shutil.move(full, dest)
        message = commit_message("Delete", full, "")
        code, out = git("add", "-A", "--", rel)
        if code == 0:
            code, out = git("commit", "-q", "-m", message, "--", rel)
        git_fresh()
        if code:
            # The note is already in the trash, so there is nothing to undo —
            # but the removal is not in the history, and saying so is better
            # than a silent divergence between the two.
            return dest, out
        return dest, None


def git_start():
    """Make the vault a repository cairn owns, checked out on this machine's
    branch, with a tree that agrees with HEAD. Exits rather than starting in
    any state where "every save is a commit" would be a lie."""
    global BRANCH
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
                 "cairn commits on a branch of its own per machine, which would "
                 "move that repository's branch too.\n"
                 "Serve the repository root with --vault, or give the vault its "
                 "own repository." % top)

    # Local only, and only when the machine has no identity of its own: a
    # commit with no author fails, and failing every save on a fresh machine
    # over a git config nobody has set yet would be a poor first impression.
    if not _git("config", "user.email"):
        git("config", "user.email", "cairn@" + socket.gethostname().split(".")[0])
    if not _git("config", "user.name"):
        git("config", "user.name", "cairn")

    BRANCH = host_branch()

    if not _git("rev-parse", "--verify", "-q", "HEAD"):
        ok, out = git_commit_all("Adopt the vault as it stands")
        if not ok:
            sys.exit("the first commit was refused:\n\n%s\n\n"
                     "cairn keeps history in this repository, so it will not "
                     "start with a tree it cannot commit." % out)

    if _git("rev-parse", "--abbrev-ref", "HEAD") != BRANCH:
        if git("rev-parse", "--verify", "-q", "refs/heads/" + BRANCH)[0] != 0:
            code, out = git("branch", BRANCH)
            if code:
                sys.exit("could not create the branch %s — %s" % (BRANCH, out))
        code, out = git("checkout", "-q", BRANCH)
        if code:
            sys.exit("could not check out %s — %s" % (BRANCH, out))

    # A tree that disagrees with HEAD at startup would make "every save is a
    # commit" false from the first request: the next save would carry along
    # whatever else was lying around. So it is adopted, or cairn does not run.
    if git_dirty():
        ok, out = git_commit_all("Adopt changes made outside cairn")
        if not ok:
            sys.exit("changes already in the vault could not be committed:\n\n%s\n\n"
                     "Fix or remove what the hook objects to, then start cairn "
                     "again." % out)
        print("  git   : committed changes that were already in the vault")
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

        info = {"repo": True, "root": top,
                "branch": None if branch in (None, "HEAD") else branch,
                "detached": branch == "HEAD",
                "changed": changed, "untracked": untracked,
                "clean": changed == 0 and untracked == 0,
                "upstream": upstream, "ahead": ahead, "behind": behind,
                "last": last,
                # Where a sync would push. No origin means no sync button:
                # there is nowhere for this machine's branch to go.
                "remote": _git("remote", "get-url", "origin"),
                "peers": peer_count()}

    _git_cache.update(at=now, info=info)
    return info


def peer_branches():
    """The other machines' branches, oldest commit first.

    Ordering is not decoration. Merging with -X theirs means the branch coming
    in wins the conflicting hunks, so the order the merges happen in decides
    which machine's version of a line survives — see run_sync().
    """
    out = _git("for-each-ref", "--format=%(refname:short)%09%(committerdate:unix)",
               "refs/remotes/origin/host") or ""
    rows = []
    for line in out.splitlines():
        ref, _, when = line.partition("\t")
        if ref and ref != "origin/" + (BRANCH or "") and when.isdigit():
            rows.append((int(when), ref))
    rows.sort()
    return rows


def peer_count():
    return len(peer_branches())


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


def cloud_info():
    """Which provider's folder the vault is inside, if any.

    Honest about its limits: this is path inspection and one stat. Proton
    Drive on macOS is a File Provider extension with no public interface to
    its upload queue, so cairn can say the folder is there and readable and
    cannot say whether the last save has reached the cloud. The page says so
    rather than implying a green light means uploaded.
    """
    path = VAULT
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
                        "inside": os.path.relpath(VAULT, path)}
        path = parent


# --------------------------------------------------------------------------
# sync
# --------------------------------------------------------------------------
#
# One machine's branch out, every other machine's branch in. Nothing else:
# no working-tree copying, no rsync, no file the request gets to name.
#
# Conflicts resolve last-writer-wins, which takes a little care to actually
# mean that. `-X theirs` resolves conflicting hunks in favour of the branch
# being merged, which is "last fetched wins" unless the order is chosen: so
# the peers are merged oldest first, and a peer whose tip is older than this
# machine's own last commit is merged with `-X ours` instead. The branch that
# was written most recently is the one left standing either way.
#
# The version that loses needs no special logging. It is a permanent commit
# on the machine that wrote it, and after the merge it is a permanent commit
# here too.

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


TIMER_TTL = 30.0
_timer_cache = {"at": 0.0, "info": None}


def sync_status():
    """Everything the footer shows: last run, next run, one in flight."""
    last = None
    try:
        with open(SYNC_STATE, encoding="utf-8") as fh:
            last = json.load(fh)
    except (OSError, ValueError):
        pass                                  # nothing has been recorded yet
    git = git_info()
    # No origin, no sync: there is nowhere for this machine's branch to go and
    # nobody else's to merge. The button hides rather than failing on a press.
    info = {"enabled": bool(git.get("remote")), "running": SYNCING,
            "remote": git.get("remote"), "branch": git.get("branch"),
            "peers": git.get("peers", 0),
            "last": last, "next": None, "timer_last": None}
    if SYNC_TIMER:
        # A timer-driven run happens entirely outside cairn, so its time comes
        # from systemd; only button-driven runs land in SYNC_STATE. Cached
        # because every miss spawns a systemctl, and the footer asks for this
        # far more often than a timer's schedule can change.
        now = time.time()
        if _timer_cache["info"] is None or now - _timer_cache["at"] >= TIMER_TTL:
            _timer_cache.update(at=now, info=systemd_timer(SYNC_TIMER))
        t = _timer_cache["info"]
        info["next"] = t.get("next")
        info["timer_last"] = t.get("last")
    return info


def run_sync():
    """Push this machine's branch, merge every other machine's, push again.

    Assumes GIT_LOCK is held: a merge rewriting the working tree while a save
    is staging a file is the collision the single lock exists to stop.

    Every step is logged as it happens rather than collected at the end, so
    the activity panel fills while a slow push is still going.
    """
    started = time.time()
    lines = []
    failed = []

    def say(text, kind="out"):
        for line in str(text).splitlines() or [""]:
            lines.append(line)
            log_run(line, kind)

    def step(*args):
        say("git " + " ".join(args), "cmd")
        code, out = git(*args, timeout=SYNC_TIMEOUT)
        if out:
            say(out, "err" if code else "out")
        if code:
            failed.append(" ".join(args))
        return code == 0

    log_run("sync on %s" % (BRANCH or "?"), "start")
    lines.append("sync on %s" % (BRANCH or "?"))

    # 1. Anything outstanding is committed first. A merge refuses to run over
    #    a dirty tree, and a note the user edited in another program is part
    #    of what a sync is for.
    if git_dirty():
        ok, out = git_commit_all("Adopt changes made outside cairn")
        say("committed changes that were already in the vault"
            if ok else out, "out" if ok else "err")
        if not ok:
            failed.append("commit")

    mine = _git("log", "-1", "--format=%ct") or "0"
    mine = int(mine) if mine.isdigit() else 0

    # 2. Out, then in, then out again — the last push carries the merges.
    #    -u on the first one so the footer can say ahead/behind afterwards.
    if not failed and step("push", "-u", "origin", BRANCH):
        if step("fetch", "--prune", "origin"):
            merged = 0
            for when, ref in peer_branches():
                # Older than this machine's newest commit: this machine is the
                # later writer, so it keeps its lines. Newer: it does not.
                strategy = "theirs" if when > mine else "ours"
                if not step("merge", "--no-edit", "-X", strategy, ref):
                    # An -X merge only fails on something a strategy cannot
                    # decide, like the same file added and deleted. Put the
                    # tree back and let the user look. Not through step(): the
                    # merge is the failure, and an abort with nothing to abort
                    # would report a second one on top of it.
                    say("git merge --abort", "cmd")
                    git("merge", "--abort")
                    break
                merged += 1
            if not failed:
                say("merged %d branch%s" % (merged, "" if merged == 1 else "es"))
                if merged:
                    step("push", "origin", BRANCH)

    git_fresh()
    record = {"at": started, "seconds": round(time.time() - started, 1),
              "ok": not failed, "code": 1 if failed else 0,
              "output": "\n".join(lines)[-4000:]}
    log_run("finished in %ss%s" % (record["seconds"],
                                   "" if record["ok"] else
                                   " — %s failed" % failed[0]),
            "end" if record["ok"] else "err")
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

        if path == "/api/status":
            # Everything the footer draws, in one request: the sync command,
            # the git repository, and the provider folder the vault is in.
            if not self.authed():
                return self.fail(403, "not unlocked")
            return self.send_json(200, {"ok": True, "version": VERSION,
                                        "sync": sync_status(),
                                        "git": git_info(), "cloud": cloud_info()})

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
                                        "running": SYNCING})

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

        ok, detail, previous = write_note(full, content, "Update")
        if not ok:
            # 422: the request was fine, the repository refused it — a
            # pre-commit hook finding a credential-shaped string is why this
            # normally happens. Nothing was written, so the client is handed
            # the file as it still is, and the user still has their text in
            # the textarea to fix.
            return self.send_json(422, {
                "ok": False,
                "error": "the vault's git hook refused this save",
                "refused": detail,
                "content": previous if previous is not None else "",
                "mtime": os.path.getmtime(full) if os.path.isfile(full) else None})
        return self.send_json(200, {"ok": True, "commit": detail,
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
            ok, detail, _ = write_note(full, body, "Add")
            if not ok:
                return self.send_json(422, {"ok": False, "refused": detail,
                                            "error": "the vault's git hook refused this note"})
            return self.send_json(200, {"ok": True, "path": os.path.relpath(full, VAULT),
                                        "commit": detail, "content": body,
                                        "mtime": os.path.getmtime(full)})

        if route == "/api/sync":
            if not git_info().get("remote"):
                return self.fail(404, "this vault has no 'origin' remote, so there "
                                      "is nowhere to sync to")
            # Refuse rather than queue: a second sync on top of a running one
            # would be two merges racing over one index. Non-blocking so a
            # press during a save waits for nothing — it is told to try again.
            if not GIT_LOCK.acquire(blocking=False):
                return self.fail(409, "the repository is busy — try again in a moment")
            global SYNCING
            SYNCING = True
            try:
                record = run_sync()
            finally:
                SYNCING = False
                GIT_LOCK.release()
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
            dest, why = remove_note(full)
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
    ap.add_argument("--sync-timer", default=None,
                    help="systemd --user timer unit to read the next scheduled "
                         "sync from, e.g. vault-sync.timer")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--terminal-cwd", default=None,
                    help="where 'open in terminal' starts (default: ~/workspace)")
    ap.add_argument("--no-terminal", action="store_true",
                    help="refuse to open terminal windows at all")
    args = ap.parse_args()

    global VAULT, SYNC_TIMER, TERMINAL_CWD, TERMINAL_ENABLED
    if args.vault:
        VAULT = os.path.abspath(os.path.expanduser(args.vault))
    if args.terminal_cwd:
        TERMINAL_CWD = os.path.abspath(os.path.expanduser(args.terminal_cwd))
    TERMINAL_ENABLED = not args.no_terminal

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

    print("\n  cairn %s" % VERSION)
    print("  vault : %s" % VAULT)
    # Before the port is bound and before the banner's remaining lines: this
    # can exit, and it can print, and a half-started server is worse than one
    # that never came up.
    git_start()

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
    print("  branch: %s" % BRANCH)
    print("  state : %s" % STATE_DIR)
    if inside(STATE_DIR, VAULT):
        print("  !! the state directory is inside the vault — the access token")
        print("     and the TLS private key are in a folder you may be syncing.")
    for old, new, left in migrated:
        print("  moved %s -> %s" % (old, new))
        for src in left:
            print("    left in place (already at destination): %s" % src)
    remote = git_info().get("remote")
    print("  sync  : %s" % (remote or "off — no 'origin' remote in the vault"))
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
    print("  Every save is a commit on %s. Deletes also go to trash/ under" % BRANCH)
    print("  the state directory, so a wrong click is one file move to undo.")
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
