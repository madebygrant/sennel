# Sennel

A KeePass-style password manager for the terminal, built with [ratatui](https://github.com/ratatui/ratatui).
Reads and writes real KDBX4 databases (KeePass compatible), gives every secret one-key clipboard
copy, organises entries into a folder tree, and finds anything with fuzzy search.

macOS and Linux only.

## Quick start

```sh
sennel                     # opens ~/.config/sennel/config.toml's db, or asks for one
sennel --db vault.kdbx     # open a specific vault (created on first unlock)
sennel --check             # print what the app sees: config, paths, clipboard backend
sennel --list --db v.kdbx  # group and entry inventory (titles only, no secrets)
```

Run without installing: `cargo run --release -- --db vault.kdbx`.
Install onto your PATH: `cargo install --path .`, then just `sennel`.

## The unlock screen

The first box is the vault file, so one session can point at any vault: type (or accept the
prefilled from config) a path, `tab` to the password box, `enter` to unlock. The path field is
editable every time the app locks — idle auto-lock drops the secrets and the editor state, not the
vault path, so switching vaults after a lock is `esc`, edit the file box, `enter`. A path that
doesn't exist yet is a new database: confirm, then set the password twice.

## Keys

| Key             | Action                                        |
| --------------- | --------------------------------------------- |
| `tab ↑ ↓`       | move between boxes on prompt screens (unlock, forms) |
| `enter`         | unlock / save the form                        |
| `j k ↑ ↓`       | move within the pane                          |
| `Tab`           | groups pane ↔ entries pane                    |
| `enter`         | open group / focus detail                     |
| `y` `p` `U`     | copy username / password / URL                |
| `*`             | show/hide the password in the detail pane     |
| `/`             | fuzzy search (`enter` keeps, `esc` clears)    |
| `n` `N`         | next / previous match                         |
| `a` `e` `D`     | add / edit / delete entry                     |
| `A` `E`         | add / rename group                            |
| `D` (on groups) | delete group (refused while not empty)        |
| `X` `V`         | cut / paste entry or group                    |
| `←` `→`         | collapse / expand group (entries pane: hop)   |
| `o`             | entries order: stored, name, recent, updated  |
| `u`             | undo the last change (one level)              |
| `^s`            | generate a password into the edit form        |
| `h` `?`         | keys overlay                                  |
| `esc`           | unwind: drop cut, clear filter, then report   |
| `q` `^c`        | quit (asks when unsaved changes; `qq` answers) |

Platform note: some terminals bind `tab`–`backtab` and arrow chords themselves; every key here also
has a visible home in the `h` overlay.

## Security notes

- **KDBX4 end to end.** The vault is a real KeePass database. No plugins, no homebrew format; the
  file is never modified without your password being re-keyed.
- **Owner-only files.** Saves are atomic (write to a sibling temp file, then rename) and
  `chmod 0600`, so the vault is readable only by your user.
- **Clipboard auto-clear.** Copies are wiped after a configurable interval (default 15s). A second
  copy re-arms the timer instead of being wiped early; overwriting happens even if Sennel exits.
- **Idle auto-lock.** After the idle timeout (default 300s, `0` disables) the vault is locked and
  the in-memory secrets are zeroized.
- **Zeroized in memory.** Password fields, retained database keys, and undo snapshots all wipe on
  drop. The status bar names what was copied, never the secret.
- **No recycle bin.** Deletes are confirmed, then permanent. `u` undoes the most recent change.
- **Search and `--list` stay clean.** The fuzzy index covers titles, usernames, URLs and group
  paths — never notes — and printed inventories carry titles only.

## Configuration

`~/.config/sennel/config.toml`, all keys optional:

```toml
db = "~/vaults/main.kdbx"      # default database
clipboard_timeout = 15         # seconds before the clipboard clears (0 = leave it)
lock_timeout = 300             # seconds idle before auto-lock (0 = never)
```

## Building

```sh
cargo build --release
cargo test
cargo clippy -- -D warnings
```

Rust 1.85+ (2024 edition). `--check` runs headless with no TTY required.

## License

MIT OR Apache-2.0 — see LICENSE-MIT and LICENSE-APACHE.
