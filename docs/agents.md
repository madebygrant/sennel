# Sennel CLI reference for AI agents

Sennel is a terminal KeePass (KDBX4) password manager. Bare `sennel` opens an interactive TUI. An
agent can't drive it, and it exits 1 with `Sennel needs a terminal` when stdin or stdout is not a
TTY. Use the subcommands below instead. Each one runs, prints and exits.

## Rules for agents

- Pass `--stdout` to get a value back. Without it the value goes to the OS clipboard, and the
  process sleeps for the clipboard timeout (default 30 s) before it exits.
- `--stdout` is refused when stdout is a terminal, unless you add `--force`. Captured output, a
  pipe or `$(...)` is not a terminal, so `--force` is normally not needed.
- Supply the master password as the first line of stdin. Sennel only prompts when stdin is a TTY.
- Secrets printed with `--stdout` end up in your context and any logs of it. Prefer piping a
  secret straight into the command that needs it over echoing or storing it.
- Every subcommand except `gen`, `completions` and `man` needs a vault, from `--db` or the config.
- `get` exit codes 2 and 3 are not failures to retry blindly. See [get](#sennel-get).

## Vault and config resolution

| Source                   | Used for                                                       |
| ------------------------ | -------------------------------------------------------------- |
| `--db PATH`              | the vault. Wins over the config                                |
| `db = "..."` in config   | the vault when `--db` is absent                                |
| `--key-file PATH`        | key file, when the vault needs one                             |
| `--config PATH`          | config file. Default `$XDG_CONFIG_HOME/sennel/config.toml`, else `~/.config/sennel/config.toml` |
| `--no-config`            | ignore the config file. Use for reproducible runs              |

`--db`, `--key-file`, `--config` and `--no-config` are global: they work before or after the
subcommand. All other top-level flags (`--clipboard-timeout`, `--lock-timeout`, `--sort`,
`--theme`, `--check`, `--list`) must come before it.

No vault configured: exit 1, `no database given · pass --db <file>`.

## Output and errors

- stdout carries the result only. Messages, warnings and candidate lists go to stderr.
- Errors print `Error: <message>` on stderr and exit 1, unless a command lists other codes.
- Entry titles are printed with control characters stripped.

## Commands

### `sennel get`

Fetch one field of one entry.

```sh
printf '%s\n' "$MASTER" | sennel get NEEDLE [FIELD] --stdout --db VAULT
```

| Flag             | Field                                     |
| ---------------- | ----------------------------------------- |
| `-p`, `--password` | password (default when no field is named) |
| `-u`, `--user`   | username                                  |
| `--url`          | url                                       |
| `--otp`          | current TOTP code. The seed is never output |
| `--stdout`       | print instead of copy                     |
| `--force`        | allow `--stdout` into a terminal (needs `--stdout`) |

Name at most one field. Two or more: exit 1, `name one field · -u, -p, --url or --otp`.

How the needle is matched, in order:

1. An exact title match, ignoring case, wins outright.
2. Otherwise fuzzy matching over title, username, url and group path. Notes are never searched.
   A single hit wins.
3. More than one hit: exit 2. Fewer than one: exit 3.

Entries in the recycle bin never match.

| Exit | Meaning                                                    | stderr                          |
| ---- | ---------------------------------------------------------- | ------------------------------- |
| 0    | printed (`--stdout`) or copied                             | copy confirmation               |
| 1    | wrong password, no vault, empty field, bad flags           | `Error: ...`                    |
| 2    | ambiguous needle                                           | `"x" matches N entries:` then up to 10 titles, one per line, indented two spaces |
| 3    | no match                                                   | `nothing matches "x"`           |

On exit 2, pick an exact title from the stderr list and retry with it, since an exact title wins.
If two entries share that title, it stays ambiguous: ask the user.

An empty field exits 1 with `<title> has no <field>`.

### `sennel gen`

Generate a secret. Opens no vault and needs no password.

```sh
sennel gen --stdout [--kind complex|passphrase|pin] [options]
```

| Flag                 | Effect                                                     | Default            |
| -------------------- | ---------------------------------------------------------- | ------------------ |
| `--kind KIND`        | `complex`, `passphrase` or `pin` (any case)                | config, else `complex` |
| `-n`, `--length N`   | characters for complex (4–256), digits for pin (4–12)      | 20 / 6             |
| `--words N`          | passphrase words (1–64)                                    | 6                  |
| `--symbols` / `--no-symbols` | punctuation in or out. The last one given wins     | off                |
| `--no-digits`        | drop 0–9                                                   | digits on          |
| `--no-upper`         | drop A–Z                                                   | upper on           |
| `--ambiguous`        | allow `l 1 I O 0`                                          | excluded           |
| `--count N`          | N secrets, one per line (needs `--stdout`)                 | 1                  |
| `--stdout`           | print instead of copy                                      |                    |
| `--force`            | allow `--stdout` into a terminal                           |                    |

- complex: every enabled class appears at least once. Lowercase is always included.
- passphrase: words from the EFF large wordlist (7772 words), joined with `-`. About 12.9 bits per
  word.
- pin: digits only, about 3.3 bits per digit. Class flags are ignored.
- Flags that don't apply to the chosen kind are ignored, with a warning on stderr. Exit code stays 0.
- A length or word count out of range exits 1 with `... is outside MIN–MAX`. An unknown kind exits
  1 with `kind "x" is none of complex, passphrase, pin`.

### `sennel audit`

List weak, reused, expired and empty passwords. Exit 0 whether or not anything is found.

```sh
printf '%s\n' "$MASTER" | sennel audit --db VAULT [--pwned]
```

stdout is one line per finding, worst first: the title padded to 40 columns, two spaces, then one
of these:

- `no password`
- `reused across N entries`
- `expired`
- `~B bits · weak|fair|good|strong` (weak means under 60 bits)

No findings prints `nothing reused, weak, expired or empty`.

`--pwned` also checks each password against Have I Been Pwned through `curl`, sending only the first
five hex characters of its SHA-1. Each hit is a line `<title padded to 40>  in N known breaches`,
followed by a summary line. It needs network access and `curl`. Don't add it unless the user asks.

### `sennel --list`

Print the group tree and entry titles, no secrets. Needs the password.

```sh
printf '%s\n' "$MASTER" | sennel --list --db VAULT
```

The first line is `G groups · E entries`. Then groups appear as `[name]`, indented two spaces per
depth level. Each entry title sits two spaces deeper than its group, with `  (expired)` appended
when the entry has expired. Use this to find exact titles before calling `get`.

### `sennel --check`

Reports what Sennel sees: config file, vault path, generator defaults, timeouts and clipboard. Needs
no password and no TTY. Exit 1 when no clipboard backend is available, otherwise 0. Run it first
when diagnosing setup problems.

### `sennel import FILE`

Import a CSV export from KeePassXC, Bitwarden or 1Password (or any CSV with matching headers) into a
new group. Writes to the vault.

```sh
sennel import export.csv --dry-run --db VAULT                  # no password needed, writes nothing
printf '%s\n' "$MASTER" | sennel import export.csv --db VAULT  # imports for real
```

- `--group NAME` sets the target group. The default is `Imported <date>`.
- Unused columns are named on stderr.
- A KDBX 3.1 vault is refused. Convert it first.
- Always run `--dry-run` first and confirm with the user before the real import. The CSV holds
  plaintext passwords: suggest deleting it afterwards.

### `sennel convert`

Write a KDBX 4 copy of a KDBX 3.1 vault. The original is never modified.

```sh
printf '%s\n' "$MASTER" | sennel convert --db OLD.kdbx [--to NEW.kdbx]
```

- The output defaults to `<name>-kdbx4.kdbx` next to the original.
- It refuses to overwrite an existing file, and refuses a vault that is already KDBX 4.1.
- The copy is reopened and compared before success is reported. On a mismatch the copy is deleted
  and the command exits 1.

### Other subcommands

- `sennel completions bash|zsh|fish|elvish` prints a completion script.
- `sennel man` prints a man page.

## Recipes

```sh
# Password into another command without it touching the clipboard or a variable
printf '%s\n' "$MASTER" | sennel get github --stdout --db ~/vault.kdbx | some-tool --password-stdin

# Resolve an ambiguous needle
printf '%s\n' "$MASTER" | sennel get mail --stdout --db v.kdbx
case $? in
  0) ;;                                   # value on stdout
  2) echo "ambiguous; candidates on stderr" ;;
  3) echo "no entry matches" ;;
  *) echo "error; see stderr" ;;
esac

# Find exact titles first
printf '%s\n' "$MASTER" | sennel --list --db v.kdbx

# Secrets with no vault
sennel gen --stdout                                   # 20 chars, a–z A–Z 0–9
sennel gen --stdout -n 32 --symbols
sennel gen --stdout --kind passphrase --words 5
sennel gen --stdout --kind pin -n 6
sennel gen --stdout --count 10 --no-config           # ten, ignoring user defaults
```

## What the CLI cannot do

The CLI can't create, edit or delete entries, move them, set custom fields or change the master
password. Those are TUI-only. When a user asks for one of them, tell them the key: `a` add, `e`
edit, `D` delete, `F` fields, `^p` change master password. Run `h` inside the TUI for the full key
map. There is no JSON output mode, so parse the line formats above.
