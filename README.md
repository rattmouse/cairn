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

Checks over auth, reading, writing, path safety and TLS. Standard library
only. It builds a throwaway vault in `/tmp` and never touches a real one.
