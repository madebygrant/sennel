# Keys and the unlock screen

[Back to the README](../README.md)

## The unlock screen

The first box is the vault file, so one session can point at any vault. Type a path, accept the one
from your config, or press `^o` to pick from a list of folders and `.kdbx` files. `enter` steps into
a folder or takes a vault, `←` goes back up, and typing narrows the list. Then `tab` to the password
box and `enter` to unlock.

A vault that opens is remembered. Its path goes into `config.toml` as `db`, and Sennel says so when
it writes it. Under `--no-config` there is nowhere to write, so nothing is written.

The path field is editable every time the app locks. An idle auto-lock drops the secrets and the
editor state, not the vault path, so switching vaults after a lock is `esc`, edit the file box,
`enter`. A path that does not exist yet is a new database. Confirm, then set the password twice.

Every printable key on this screen is text, so a `*` in a password types as `*`. The reveal is `^r`,
not the browser's `*`.

## Every key

| Key                 | Action                                                        |
| ------------------- | ------------------------------------------------------------- |
| `tab ↑ ↓`           | move between boxes on prompt screens (unlock, forms)          |
| `^o`                | pick the vault file from a list (unlock screen)               |
| `enter`             | unlock, or save the form                                      |
| `j k ↑ ↓`           | move within the pane                                          |
| `^d ^u` `PgUp PgDn` | move a screen at a time                                       |
| `g` `G`             | top, bottom of the pane                                       |
| `Tab`               | groups pane, entries pane                                     |
| `enter`             | open group, open entry (detail popup)                         |
| `j k` (in the popup)| read the next or previous entry without closing it            |
| `y` `p` `U` `t`     | copy username, password, url, one-time code                   |
| `*`                 | show or hide the password (needs the detail pane or popup)    |
| `/`                 | fuzzy search (`enter` keeps, `esc` clears)                    |
| `^g` (in search)    | narrow the needle to this group, or widen it again            |
| `#tag` (in search)  | filter by tag instead of fuzzy-matching · `#` alone lists them|
| `n` `N`             | next, previous match                                          |
| `↑ ↓` (in search)   | move through the results while still typing                   |
| `a` `e` `D`         | add, edit, delete entry to the bin (`otp` and `tags` boxes)   |
| `A` `E`             | add, rename group                                             |
| `D` (on groups)     | group to the recycle bin, contents and all                    |
| `X` `V`             | cut, paste entry or group                                     |
| `>` `<`             | move a group in or out of the tree (groups pane)              |
| `←` `→`             | collapse, expand group (in the entries pane, hop)             |
| `o`                 | entries order: stored, name, recent, updated                  |
| `u`                 | undo, step by step back through the session                   |
| `^l`                | lock now (same wipe as the idle auto-lock)                    |
| `^p`                | change the master password (typed twice, `^r` reveals)        |
| `!`                 | reused, weak and empty passwords · `enter` goes to one        |
| `F`                 | custom fields and attachments                                 |
| `H`                 | old versions of the entry · `D` clears them                   |
| `^t`                | next palette, remembered for next launch                      |
| `^s`                | save now (every change already autosaves)                     |
| `^r`                | reload from disk (offered when the file changed under you)    |
| `^s` (in a form)    | generate a password into the edit form                        |
| `^r` (in a form)    | show what is in the password box                              |
| `alt+enter`         | new line in the notes box (`enter` saves)                     |
| `h` `?` `F1`        | keys overlay (`F1` on the lock screen, where letters are text)|
| `esc`               | unwind: drop cut, clear filter, then report                   |
| `q` `^c`            | quit (asks when there are unsaved changes; `qq` answers)      |

## The fields screen (`F`)

Everything on an entry the five fixed rows cannot show: KeePassXC custom string fields, and
attachments.

| Key   | Action                                                              |
| ----- | ------------------------------------------------------------------- |
| `j k` | move                                                                |
| `y`   | copy a field's value, through the same clipboard wipe as a password |
| `s`   | write an attachment out beside the vault, owner-only                |
| `*`   | reveal the protected fields                                         |
| `a`   | add a custom field (name, then value)                               |
| `f`   | attach a file (name, then the path to read)                         |
| `D`   | remove the field or attachment under the cursor                     |
| `esc` | close                                                               |

Fields you add go in protected, because a field somebody adds by hand to a password manager is more
likely to be a secret than not. An extracted attachment is written beside the vault file rather than
into the working directory, and loses the vault's protection the moment it lands.

Some terminals bind `tab`, `backtab` and the arrow chords themselves. Every key here also has a
visible home in the `h` overlay.
