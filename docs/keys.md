# Keys and the unlock screen

[Back to the README](../README.md)

## The unlock screen

The first box is the vault file, so one session can point at any vault. Type a path, accept the one
from your config, or press `^o` to pick from a list of folders and `.kdbx` files. `enter` steps into
a folder or takes a vault, `←` goes back up, and typing narrows the list. Then `tab` to the password
box and `enter` to unlock.

A vault that opens is remembered. Its path goes into `config.toml` as `db` and joins the vault
library that `^v` opens: every vault this machine has unlocked, newest first, the current one marked
and any that have moved marked `missing`. `enter` points the session at one and `^d` forgets a row,
never the file. Typing narrows the list over the whole path, so `work` finds a vault by its folder
as well as by its name. Forget the vault `db` names and that setting goes too, so the next launch
asks instead of bringing it back. Under `--no-config` there is nowhere to write, and nothing is
remembered.

Picking a vault whose file is gone is allowed. The screen then reads `new database`, because that is
what a path with nothing behind it is, and `enter` would create one. Confirm, then set the password
twice.

The path field is editable every time the app locks. An idle auto-lock drops the secrets and the
editor state but not the vault path or the key-file path, so switching vaults after a lock is `esc`, edit the file box,
`enter`.

Every printable key on this screen is text, so a `*` in a password types as `*`. The reveal is `^r`,
not the browser's `*`.

## Every key

| Key                 | Action                                                        |
| ------------------- | ------------------------------------------------------------- |
| `tab ↑ ↓`           | move between boxes on prompt screens (unlock, forms)          |
| `^o`                | pick the vault file from a list (unlock screen)               |
| `^v`                | the vault library · `^d` forgets a row (unlock screen)        |
| `^y`                | use the configured YubiKey for this unlock, or not            |
| paste               | into the focused box, minus its final newline (nowhere else)  |
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
| `:`                 | the command palette: every action, found by name              |
| `a` `e` `D`         | add, edit, delete entry to the bin (`otp`, `tags`, `expires`) |
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
| `^f`                | merge the file on disk into your changes (when it changed)    |
| `^r`                | reload from disk (offered when the file changed under you)    |
| `P`                 | generate a password with no entry to put it in                |
| `^s` (in a form)    | generate a password into the edit form                       |
| `^y` (in a form)    | copy the password box before the entry is saved               |
| `^r` (in a form)    | show what is in the password box                              |
| `alt+enter`         | new line in the notes box (`enter` saves)                     |
| `h` `?` `F1`        | keys overlay (`F1` on the lock screen, where letters are text)|
| `esc`               | unwind: drop cut, clear filter, then report                   |
| `q` `^c`            | quit (asks when there are unsaved changes; `qq` answers)      |

## The command palette (`:`)

Every row of the header menus in one list, found by typing part of its name: `:` then `lock`, or
`cp pass` for Entry › Copy password. `↑ ↓` or `^n ^p` choose, `enter` runs it, `^u` clears the
query and `esc` closes. Each row shows its key on the right, as the menus do, so the palette is also
the way to learn a key you have forgotten. It runs exactly what the menu row would, and works with
`mouse = false`.

## The generator (`P`)

A password with no entry to store it in. `r` rolls another, `y` copies it, `t` walks complex,
passphrase and pin, `-` and `+` change the length (words, for a passphrase), and `u` `d` `s` `a`
turn capitals, digits, punctuation and the `l 1 I O 0` lookalikes on and
off (complex only). The toggles last the session only. [More](generate.md).

## The fields screen (`F`)

Everything on an entry the five fixed rows cannot show: KeePassXC custom string fields, and
attachments.

| Key   | Action                                                              |
| ----- | ------------------------------------------------------------------- |
| `j k` | move                                                                |
| `y`   | copy a field's value, through the same clipboard wipe as a password |
| `s`   | write an attachment out beside the vault, owner-only                |
| `g`   | give an attachment to ssh-agent as a key, for `ssh_agent_lifetime`  |
| `*`   | reveal the protected fields                                         |
| `a`   | add a custom field (name, then value)                               |
| `f`   | attach a file (name, then the path to read)                         |
| `D`   | remove the field or attachment under the cursor                     |
| `esc` | close                                                               |

Fields you add go in protected, because a field somebody adds by hand to a password manager is more
likely to be a secret than not. An extracted attachment is written beside the vault file rather than
into the working directory, and loses the vault's protection the moment it lands.

## The marks in the list

| Glyph | Means                                                    |
| ----- | -------------------------------------------------------- |
| `▌`   | the cursor, in the pane that has the keys                |
| `│`   | the cursor, in the pane that does not                    |
| `⊙`   | the entry has a one-time code                            |
| `⧖`   | the entry is past its expiry date                        |
| `⌦`   | the recycle bin, and anything inside it                  |

Every one is a glyph rather than a colour, so they still say what they say under `NO_COLOR`. Every
one is also a single cell, checked by a test that reads the UI's own source, because a two-cell
glyph in a one-cell budget wraps rows on somebody else's terminal.

## The mouse

Off with `mouse = false`, which gives the terminal its own text selection back. Otherwise the wheel
scrolls the pane under the pointer, and a click selects a row and hands that pane the keys. A click
on the `user`, `pass`, `url` or `totp` row of the detail view copies that field, the same copy
`y p U t` do and the same wipe. The row shows `✓ copied` for a moment afterwards, because a copy is
otherwise invisible: the clipboard is somewhere else, and the status line is at the far end of the
screen from the hand that just moved.

The header holds a menu bar, `Vault  Entry  Group  View  Help`. A click opens a menu under its
label, and most rows show their key on the right, so the menus teach the key table as they go.
Delete, Cut and Paste show none, because `D`, `X` and `V` follow the pane or the cut rather than
the menu. A click on a row runs it, and a click on a label switches to that menu. A click outside
the menu closes it and goes no further, so it cannot select a row or copy a field behind it. While
a menu is open the wheel moves through its rows instead of scrolling a pane, `↑ ↓` or `j k` move,
`← →` step to the next menu, `enter` runs the row and `esc` closes it. Any other key closes the
menu and then does what it always does, so `^l` still locks.

A right-click on a group or entry selects it and opens its menu at the pointer. On empty space it
opens no menu, though the pane under it takes the keys, as a click there would. On an open menu it
does nothing. A click on the open menu's own label moves it up under the label.

A menu row runs the same action as its key, but where a key depends on the pane, the menu names
the row instead: Entry › Delete deletes the entry and Group › Delete the group, whichever pane has
the keys, and each Paste moves only its own kind of cut. The labels only take room the header has
spare, so on a narrow terminal or under a long status message they give way. While a menu hangs
from one they hold their place and the message is cut short instead. With `mouse = false` there
are no labels, since nothing could open them.

Nothing here is the only way to do anything, and the mouse and the menus stay out of the popups
that ask a question, so a stray click cannot answer one.

Some terminals bind `tab`, `backtab` and the arrow chords themselves. Every key here also has a
visible home in the `h` overlay, apart from the keys inside a menu, which are listed above.
