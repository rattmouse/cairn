# cairn

A small browser editor for a folder of markdown notes. Two files, Python
standard library only: no dependencies, no build step, no internet.

![The cairn editor: note list on the left, markdown source in the middle, live preview on the right](docs/screenshot.png)

The screenshot is the demo vault in `docs/demo-vault/` — nine invented notes,
not anyone's real ones. You can run the editor against it yourself:

```bash
python3 notes-server.py --vault docs/demo-vault
```

It follows the system theme:

![The same editor in dark mode, showing a weekly review note](docs/screenshot-dark.png)

## Run

```bash
python3 notes-server.py --vault ~/Documents/notes
```

Opens on `127.0.0.1:8765`. Edit on the left, live preview on the right,
`Ctrl-S` saves straight to the `.md` file on disk.

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
| `--tls` | Encrypt with a self-signed cert in the vault's `.certs/`. |
| `--host ADDR` | Bind a specific address instead of `--lan`'s `0.0.0.0`. |
| `--port N` | Default 8765. |
| `--no-browser` | Don't open a browser on start. |
| `--terminal-cwd PATH` | Where "open in terminal" starts. Default `~/workspace`. |
| `--no-terminal` | Never open a terminal window. |

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

## What protects your files

- Binds `127.0.0.1` unless `--lan` is passed explicitly.
- Every request needs the token; cross-origin requests are refused outright.
- Writes are atomic (temp file, then `os.replace`).
- The previous version of every saved note is kept in the vault's `.backups/`.
- Deleting moves the file to `.trash/`; nothing is unlinked.
- A save is refused if the file changed on disk since the browser loaded it.
- Paths are resolved against the vault root; only `.md` files can be written.
- Opening a terminal is refused for anything but a browser on this machine,
  and it types the command rather than running it.

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

Checks over auth, reading, writing, path safety, TLS, and opening a terminal.
Standard library only. It builds a throwaway vault in `/tmp` and never touches
a real one. No terminal window is opened during the tests: a shim records what
the server tried to launch, and the shell part is driven under a pty, which is
where a hostile code block is proved to be typed rather than run.
