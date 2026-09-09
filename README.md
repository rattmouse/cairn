# cairn

A small browser editor for a folder of markdown notes. Two files, Python
standard library only: no dependencies, no build step, no internet.

![The cairn editor: the vault as a tree on the left, markdown source and live preview in the middle, an outline of the note on the right, and a sync footer along the bottom](docs/screenshot.png)

The screenshot is the demo vault in `docs/demo-vault/` — nine invented notes,
not anyone's real ones. You can run the editor against it yourself:

```bash
python3 notes-server.py --vault docs/demo-vault
```

It follows the system theme. Here it is in dark, in **live** mode — the note
is rendered except for the block the caret is in, which shows its markdown:

![The same editor in dark mode, in live mode: the note reads as the preview does, except for one callout block showing its raw markdown](docs/screenshot-dark.png)

## Run

```bash
python3 notes-server.py --vault ~/Documents/notes
```

Opens on `127.0.0.1:8765`. Markdown source on the left, rendered on the
right, `Ctrl-S` saves straight to the `.md` file on disk.

## The window

Four parts, three of which you can put away:

| Part | What's in it | Toggle |
| --- | --- | --- |
| Left | The vault as a tree. Folders come from the note paths, remember whether they were shut, and open themselves when you follow a link into one. Search flattens nothing — it filters and opens everything that matched. | `Ctrl/⌘-B` |
| Middle | Source, preview, both, or **live** — see below. | — |
| Right | An outline of the open note: its headings, one entry per fenced code block, and every link it contains at the bottom. Built from the text as you type. Clicking an entry moves the preview *and* the caret to that line; scrolling the preview moves the highlight. | `Ctrl/⌘-E` |
| Bottom | Sync status, always on. Left to right: the provider folder the vault is in, the git repository, and the sync command. | — |
| Activity | Inside the footer: every line of every command cairn has run, as it runs. | `Ctrl/⌘-J` |

## Live mode

The fourth button in the middle. The note reads exactly as the preview does,
one rendered block at a time, until the caret lands in a block — that one
shows its markdown instead, tinted, with a bar in the margin. So the raw text
is only ever where you are working, and the rest of the note stays readable
while you work on it.

Click anywhere in the note to edit there; the caret lands roughly where you
clicked, not at the start of the block. `Escape` closes the block back to
rendered. Arrow off the top or the bottom of a block and the next one opens,
so the caret walks the note the way it would in a plain editor. The outline on
the right opens blocks too.

Block, not line: a paragraph is three lines that render as one thing, and
there is no half-rendered paragraph to put a raw line inside. List items are
cut one per block though, so fixing one bullet does not turn the whole list
into source.

There is still only one copy of the text. The block being edited splices its
own lines back into the same textarea the other modes use, so saving, the
conflict check, the outline and `Ctrl-S` all carry on reading the note they
always did — and switching modes mid-edit keeps everything you typed.

## The footer

Three ways these notes leave this machine, and cairn watching all three.

**The sync folder.** cairn looks at the vault's own path for a provider's
folder — Proton Drive, iCloud, Dropbox — and names what it finds, along with
the account the folder is signed in as and when a note last changed on disk.
It stops there, deliberately: Proton Drive on macOS is a File Provider
extension with no public interface to its upload queue, so a green dot here
means *the folder is there and readable*, not *your last save is in the
cloud*. The chip's tooltip says as much rather than implying otherwise.

**Git.** If the vault is in a repository — at any level above it — the footer
shows the branch, how many files are modified and how many are new, how far
ahead or behind its upstream it is, and when the last commit landed. Amber
means something exists only on this machine: uncommitted work, or commits
that have not been pushed.

This is read-only, and stays read-only. cairn never stages, commits or pushes,
and every git command it runs carries `--no-optional-locks` so that looking at
the repository cannot collide with a git command you are running in a terminal
on the same one.

**The sync command.** Whatever `--sync-cmd` points at: your script, run with
no arguments, no shell and nothing from the request. The footer shows when it
last ran, whether it worked, and — with `--sync-timer` — when it next will. A
run started by the timer rather than by the button still shows up here.

## Activity

Everything cairn runs, in the panel above the footer. The sync script's output
arrives line by line while it is still running rather than in one lump when it
finishes, so a slow sync shows you where it has got to. Opening a terminal
from a code block leaves a line here too. It is this process's own record and
lives in memory: restarting the server empties it.

Reachable from another machine on the same network:

```bash
python3 notes-server.py --vault ~/Documents/notes --lan --tls
```

`--lan` accepts outside connections; `--tls` encrypts them with a
self-signed certificate. Use them together — without `--tls` the notes and
the login token cross the network in the clear.

| Flag | Meaning |
| --- | --- |
| `--vault PATH` | Which notes folder to serve. Also read from `$NOTES_VAULT`. |
| `--lan` | Accept connections from other devices. Off by default. |
| `--tls` | Encrypt with a self-signed cert, kept in the state directory. |
| `--host ADDR` | Bind a specific address instead of `--lan`'s `0.0.0.0`. |
| `--port N` | Default 8765. |
| `--state-dir PATH` | Where backups, trash and the TLS cert go. Default: a per-vault folder under `~/.local/state/cairn/vaults/`. |
| `--no-browser` | Don't open a browser on start. |
| `--terminal-cwd PATH` | Where "open in terminal" starts. Default `~/workspace`. |
| `--no-terminal` | Never open a terminal window. |
| `--sync-cmd PATH` | An executable to run when you press Sync now. Without it there is no button and `/api/sync` is a 404. |
| `--sync-timer UNIT` | A systemd `--user` timer to read the next scheduled sync from, e.g. `vault-sync.timer`. |

## Code blocks

Hovering a fenced code block shows two buttons. **copy** puts it on the
clipboard. **terminal** opens a real terminal window on the machine running
the server, at `~/workspace`, with the command typed at the prompt and *not
executed* — you still read it and press Enter yourself. Change where it opens
with `--terminal-cwd`, or turn it off with `--no-terminal`.

The command is never handed to a shell for evaluation. It is written to a file
and read back with `$(cat)`, and the text a command substitution yields is
never re-parsed as shell syntax. It then goes into the *line editor* rather
than the shell: under bash by a readline macro, which types characters and
cannot press Return for you, and under zsh by `print -z`. So a code block full
of quotes and semicolons arrives as text rather than as instructions.
Multi-line blocks land as one editable buffer.

`$SHELL` decides which — a Mac on the stock shell gets zsh, not a surprise
bash prompt. Either way the window is yours: it reads the startup files your
terminal would have read, so your prompt, your `PATH` and your aliases are
all there. (Which files those are is a question about the terminal, not the
shell: Terminal.app opens a login shell, Linux emulators do not.)

On Linux the first installed emulator wins, in roughly desktop-native order
(`konsole`, `gnome-terminal`, `kitty`, `alacritty`, … down to `xterm`). On
macOS it opens Terminal.app. `$CAIRN_TERMINAL` overrides both — a binary name
on Linux, an application name on macOS:

```bash
CAIRN_TERMINAL=iTerm python3 notes-server.py --vault ~/Documents/notes
```

The button only appears for shell-ish blocks (` ```bash `, ` ```sh `, or no
language at all), only when the browser is on the same machine as the server —
a phone on the LAN is still authenticated, but it isn't sitting in front of
the screen the window would open on — and only if a terminal was found. The
startup banner names the one it will use.

## Access

A token is generated fresh at every start and printed in the terminal.
Opening the printed URL on the same machine logs you in. From another device
you open the plain URL and paste the token once; the server sets an
`HttpOnly; SameSite=Strict` session cookie and the token never appears in a
URL, in history, or in the page source. Restarting the server invalidates
every session.

With `--tls` the certificate is self-signed, so a browser warns the first
time. Rather than checking the printed fingerprint at every visit, install
`certs/server.crt` from the state directory (the banner prints where that
is) once as a trusted certificate on each device — macOS
Keychain Access, or iOS Settings → General → VPN & Device Management,
followed by Certificate Trust Settings. After that the device connects
cleanly and you type nothing.

The certificate covers `localhost`, `127.0.0.1`, this machine's mDNS name
(`<hostname>.local`) and every non-virtual LAN address it has. VPN tunnels,
libvirt bridges and container interfaces are deliberately excluded — an
address only this machine can reach is worse than useless in a certificate.
On start the server checks the existing certificate still covers all of
those and regenerates it if not, so a new DHCP lease fixes itself. A
regenerated certificate has to be trusted again on each device, which is
why the mDNS name is in there: reach cairn by name and the lease can move
without invalidating anything.

## What protects your files

- Binds `127.0.0.1` unless `--lan` is passed explicitly.
- Every request needs the token; cross-origin requests are refused outright.
- Writes are atomic (temp file, then `os.replace`).
- The previous version of every saved note is kept in `backups/`, and
  deleting moves the file to `trash/`; nothing is unlinked. Both live in the
  state directory, *outside* the vault, so a vault in a sync folder (Proton
  Drive, iCloud, Dropbox) doesn't upload every old version or keep deleted
  notes forever — and the `--tls` private key never reaches the cloud.
  Older vaults with `.backups/`, `.trash/` or `.certs/` inside them are moved
  out on the next start; the banner says where.
- Reading git and the sync folder is read-only and takes no arguments from a
  request: fixed argv, no shell, and nothing that writes.
- A save is refused if the file changed on disk since the browser loaded it.
- Paths are resolved against the vault root; only `.md` files can be written.
- Opening a terminal is refused for anything but a browser on this machine,
  and it types the command rather than running it.

## Versions

`python3 notes-server.py --version`, and the footer's left-hand corner says
the same thing. Not a release process — a number that moves when the editor
does, so a screenshot, a bug report and a running server can be talked about
as the same thing.

- **0.2** — the tree, the outline, the footer, live mode.
- **0.1** — the three-pane editor.

## What it is not

Single-user, single-vault, for a network you control. No accounts, no real
rate limiting, no audit trail beyond the terminal. Don't port-forward it.

## Markdown support

The renderer in `editor.html` is deliberately small and covers what these
notes use: headings, fenced code, inline code, bold/italic/strikethrough,
links and bare URLs, `[[wikilinks]]` and `![[embeds]]`, bullet, numbered and
task lists, tables, blockquotes, `> [!NOTE]` callouts, horizontal rules, and
YAML frontmatter. Footnotes and nested blockquotes are not handled.

`docs/demo-vault/2 - Resources/Markdown Reference.md` exercises most of it.

## Tests

```bash
python3 tests/test_server.py
```

Checks over auth, reading, writing, path safety, TLS, opening a terminal, and
the footer's own endpoints — including a throwaway repository inside a
folder named the way Proton Drive names its own.
Standard library only. It builds a throwaway vault in `/tmp` and never touches
a real one. No terminal window is opened during the tests: a shim records what
the server tried to launch, and the shell part is driven under a pty, which is
where a hostile code block is proved to be typed rather than run.
