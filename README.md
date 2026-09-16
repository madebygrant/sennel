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

The first box is the vault file, so one session can point at any vault. Type a path (or accept the
one from your config), or press `^o` to pick one from a list: folders and `.kdbx` files only, `enter`
steps into a folder or takes a vault, `←` goes back up, and typing narrows the list. Then `tab` to
the password box and `enter` to unlock.

A vault that opens is remembered — its path is written into `config.toml` as `db`, so the next launch
opens it without arguments. Sennel says so when it does; `--no-config` has nowhere to write and so
does not. The path field is editable every time the app locks — idle auto-lock drops the secrets and
the editor state, not the vault path, so switching vaults after a lock is `esc`, edit the file box,
`enter`. A path that doesn't exist yet is a new database: confirm, then set the password twice. Every
printable key on this screen is text — a `*` in a password types as `*` — so the reveal is `^r`, not
the browser's `*`.

## Keys

| Key             | Action                                        |
| --------------- | --------------------------------------------- |
| `tab ↑ ↓`       | move between boxes on prompt screens (unlock, forms) |
| `^o`            | pick the vault file from a list (unlock screen) |
| `enter`         | unlock / save the form                        |
| `j k ↑ ↓`       | move within the pane                          |
| `^d ^u` `PgUp PgDn` | move a screen at a time                   |
| `g` `G`         | top / bottom of the pane                      |
| `Tab`           | groups pane ↔ entries pane                    |
| `enter`         | open group / open entry (detail popup)        |
| `j k` (in the popup) | read the next / previous entry without closing it |
| `y` `p` `U` `t` | copy username / password / URL / one-time code |
| `*`             | show/hide the password (needs the detail pane or popup) |
| `/`             | fuzzy search (`enter` keeps, `esc` clears)    |
| `^g` (in search) | narrow the needle to this group, or widen it again |
| `n` `N`         | next / previous match                         |
| `↑ ↓` (in search) | move through the results while still typing |
| `a` `e` `D`     | add / edit / delete entry (the form has an `otp` box) |
| `A` `E`         | add / rename group                            |
| `D` (on groups) | delete group (refused while not empty)        |
| `X` `V`         | cut / paste entry or group                    |
| `←` `→`         | collapse / expand group (entries pane: hop)   |
| `o`             | entries order: stored, name, recent, updated  |
| `u`             | undo the last change (one level)              |
| `^l`            | lock now (same wipe as the idle auto-lock)    |
| `^s`            | save now (every change already autosaves)     |
| `^r`            | reload from disk (offered when the file changed under you) |
| `^s` (in a form) | generate a password into the edit form       |
| `^r` (in a form) | show what is in the password box             |
| `alt+enter`     | new line in the notes box (`enter` saves)     |
| `h` `?` `F1`    | keys overlay (`F1` on the lock screen, where letters are text) |
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
  copy re-arms the timer instead of being wiped early; overwriting happens even if Sennel exits. The
  status bar counts the wipe down, so the screen says when a secret is still sitting on the clipboard.
- **Idle auto-lock.** After the idle timeout (default 300s, `0` disables) the vault is locked and
  the in-memory secrets are zeroized. `^l` does the same thing on demand.
- **Zeroized in memory.** Password fields, retained database keys, and undo snapshots all wipe on
  drop. The status bar names what was copied, never the secret.
- **No recycle bin.** Deletes are confirmed; `u` restores the entry you just deleted (one level).
  Group deletes are refused while the group holds anything, and are not undoable.
- **Never overwrites somebody else's write.** Sennel remembers what the file looked like when it
  opened it. If KeePassXC, a sync client or a second Sennel writes the vault in the meantime, the
  next autosave is refused rather than silently winning: `^s` overwrites theirs, `^r` takes theirs.
- **One-time codes, not their seeds.** An entry with a code is marked `⊙` in the list and shows the
  current digits and the seconds left; `t` copies them. The seed behind them is never copied — that
  would put a permanent credential on the clipboard to save typing six digits. The `otp` box in the
  entry form takes either the `otpauth://` url behind a QR code or the secret a site prints beside
  it (spaces, hyphens and lower case are all fine), stores it protected, and shows the code it
  produces while you type so it can be checked before it is saved. Codes are six digits unless the
  url says otherwise — the rule every authenticator app follows.
- **Search and `--list` stay clean.** The fuzzy index covers titles, usernames, URLs and group
  paths — never notes — and printed inventories carry titles only.

## Configuration

`~/.config/sennel/config.toml`, all keys optional:

```toml
db = "~/vaults/main.kdbx"      # default database · rewritten when you open another
clipboard_timeout = 15         # seconds before the clipboard clears (0 = leave it)
lock_timeout = 300             # seconds idle before auto-lock (0 = never)
sort = "name"                  # entries order at startup: stored, name, recent, updated

[generator]                    # what ^s makes in the entry form
length = 20                    # 4–256
upper = true                   # A–Z
digits = true                  # 0–9
symbols = false                # !@#$… — on for sites that demand one
ambiguous = false              # true allows l 1 I O 0, which read alike
```

```toml
mouse = true                   # wheel scrolls, click selects; false gives the
                               # terminal its own text selection back
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
