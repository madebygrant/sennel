# Sennel

A KeePass password manager that lives in your terminal. Real KDBX4 files, one key per secret,
fuzzy search over the whole vault, and a clipboard that wipes itself.

macOS and Linux.

```sh
cargo install --path .
sennel --db vault.kdbx      # created on first unlock
sennel get github -p        # or copy one secret and exit
sennel gen --stdout         # or just a password, stored nowhere
```

Open a vault once and Sennel remembers the path, so the next launch is just `sennel`. Open a second
and `^v` keeps them both.

## What it does

**Comes with a way in.** `sennel import export.csv` reads what KeePassXC, Bitwarden and 1Password
hand you, into a group of its own so a regretted import is one delete. `--dry-run` shows what would
land without asking for your password. [More](docs/import.md).

**Scriptable.** `sennel get github -p` copies a password without opening the TUI, wipes it on the
same timer, and exits with a code a script can branch on. `--stdout` pipes it instead, and refuses
to print into a terminal where it would sit in your scrollback. [More](docs/get.md).

**Real KeePass files.** KDBX4 in, KDBX4 out. KeePassXC opens what Sennel writes and Sennel opens
what KeePassXC writes. No plugins, no homebrew format, no lock-in. Older KDBX 3.1 vaults open
read-only; `sennel convert` writes a verified KDBX 4 copy beside the original.
[More](docs/kdbx3.md).

**One key per secret, or one click.** `y` copies the username, `p` the password, `U` the url, `t`
the one-time code — and clicking that row in the detail view does the same, lighting up `✓ copied`
so you can see it worked. Every copy wipes after 15 seconds, and the status bar counts it down, so you always know
when a password is still sitting on the pasteboard. Quitting wipes it immediately.

**A vault library, not one favourite.** Work and personal are two vaults, and `db` in a config file
only ever held one of them. `^v` lists every vault this machine has opened, newest first, marks the
one that is open and the ones that have moved, and `enter` points the session at another without a
restart. [More](docs/keys.md).

**A generator you can reach without an entry.** `P` opens it on its own: the password on screen,
what it is worth in bits, and one key per class so you can meet whatever rule the site has this
week. `y` copies it, `esc` closes it, and nothing is stored. Outside the TUI, `sennel gen` does the
same in one line. [More](docs/generate.md).

**It will not clobber another writer.** If KeePassXC or a sync client writes the vault while you
have it open, the next autosave refuses rather than quietly winning. `^s` keeps yours, `^r` takes
theirs.

**Fuzzy search that shows its work.** `/` searches titles, usernames, urls and group paths. Never
notes. The characters that matched light up in each row, so you can see why a row is there. A needle
starting with `#` filters by tag instead, and lists the tags you have while you type it.

**Expiry dates it actually reads.** KDBX has carried an expiry on every entry all along. Expired
rows are marked `⌛` in the list and named in the pane, `--list` says `(expired)`, and `!` puts them
above the merely-weak ones — an expiry is a decision its owner already made.

**One-time codes without handing over the seed.** Entries with a code are marked `⊙` and show the
digits with a countdown. `t` copies them. The seed stays in the vault, because putting a permanent
credential on the clipboard to save typing six digits is a bad trade.

**Themes you pick by looking at them.** `^t` walks four palettes with the screen in front of you
and remembers the one you stop on. Every colour is measured against WCAG 4.5:1 before it ships,
and `NO_COLOR` still gives you a usable app.

**Custom fields and attachments, not just a count of them.** `F` opens what the five fixed rows
cannot show: KeePassXC's custom string fields with their values, and the files on an entry. `y`
copies a field, `s` writes an attachment out, `a` and `f` add them.

**It can forget, too.** Sennel's own edits write no history, so an old password is never kept
behind your back. Entries that arrive from KeePassXC often carry one anyway, and `H` shows every old
version it holds and clears them for good.

**It tells you which passwords to change.** `!` lists every reused, weak, expired or empty password
in the vault, worst first, and `enter` puts the cursor on the entry so the fix is two keys from the
finding. Reuse is the one nobody can spot themselves, and the one that costs more than one account.
`sennel audit --pwned` adds a breach check that never sends your password anywhere.
[More](docs/audit.md).

**Deletes are recoverable.** `D` moves an entry or a whole group into the same recycle bin
KeePassXC uses, so a mistake costs one `u` rather than a restore from backup. Binned rows stay out
of counts, search and `--list`. Inside the bin, `D` means it.

**Change the master password without leaving.** `^p` re-keys the vault in place, writing the file
under the new password before the session swaps to it. A failed write leaves the old password
working rather than a vault nobody can open.

**It locks itself.** Five idle minutes and the vault closes, with every secret in memory
overwritten rather than dropped. `^l` does it now.

## The keys you need on day one

| Key         | Action                                          |
| ----------- | ----------------------------------------------- |
| `j k` `Tab` | move in a pane, switch panes                    |
| `enter`     | open the entry                                  |
| `y p U t`   | copy username, password, url, one-time code     |
| `^v`        | the vaults you have opened (unlock screen)      |
| `/`         | search                                          |
| `a e D`     | add, edit, delete an entry (to the bin)         |
| `P`         | generate a password, no entry needed            |
| `!`         | passwords worth changing                        |
| `F`         | custom fields and attachments                   |
| `u`         | undo, as many steps as you made                 |
| `h`         | every other key                                 |

[The full key map](docs/keys.md) covers the unlock screen, groups, cut and paste, and the ordering
keys.

## More

- [`sennel get`](docs/get.md), the non-interactive path
- [Generating passwords](docs/generate.md), in the TUI and from a script
- [Importing](docs/import.md) from KeePassXC, Bitwarden or 1Password
- [Auditing](docs/audit.md), including the breach check
- [Older KDBX files](docs/kdbx3.md) and `sennel convert`
- [Keys and the unlock screen](docs/keys.md)
- [Security](docs/security.md), which is the interesting one: what is wiped, when, and why
- [Themes](docs/themes.md) and how the colours are measured
- [Configuration](docs/configuration.md)

## Building

```sh
cargo build --release
cargo test
cargo clippy -- -D warnings
```

Rust 1.85+, 2024 edition. `sennel --check` prints what the app sees and needs no TTY.

```sh
sennel completions zsh > ~/.zfunc/_sennel    # bash, zsh, fish, elvish
sennel man > /usr/local/share/man/man1/sennel.1
```

## License

MIT OR Apache-2.0. See LICENSE-MIT and LICENSE-APACHE.
