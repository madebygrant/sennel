<div align="center">
  <img src="docs/images/logo.svg" alt="" width="112">
  <h1>Sennel</h1>
  <p>
    <strong>Find it with <code>/</code>. Copy it with <code>p</code>. Gone from the clipboard in 30 seconds.</strong><br>
    A fast terminal app and a native desktop app for the <code>.kdbx</code> file you already have.
  </p>
  <p>
    <a href="https://github.com/madebygrant/sennel/actions/workflows/ci.yml"><img src="https://github.com/madebygrant/sennel/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/madebygrant/sennel/releases/latest"><img src="https://img.shields.io/github/v/release/madebygrant/sennel?color=555" alt="Latest release"></a>
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-555" alt="macOS and Linux">
    <img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-555" alt="MIT or Apache-2.0">
  </p>
  <p>
    <a href="#install">Install</a> ·
    <a href="#quick-start">Quick start</a> ·
    <a href="#documentation">Documentation</a>
  </p>
  <img src="docs/images/sennel.gif" alt="The terminal app: unlocking a vault, searching, copying a password and generating one" width="760">
</div>

## Why Sennel

- **Search that shows its work.** Fuzzy matching lights up the letters that matched, across titles,
  usernames, websites and groups, never your notes.
- **Your file, your sync.** No account and no server. The vault is a KDBX 4 file that KeePassXC
  opens too, so Dropbox, Syncthing or a USB stick all work.
- **Hard to lose a password.** Undo, a recycle bin, three local backups, and a merge when another
  app changed the file while you had it open.
- **Locks itself.** Five idle minutes, or however long you choose, and every secret in memory is
  overwritten.

## Two apps, one vault

<img src="docs/images/desktop.png" alt="The desktop app: groups, entries and an entry with its password hidden, a one-time code counting down and the clipboard countdown at the top" width="760">

The terminal app and the desktop app share one Rust core, the same keys, settings and list of
recent vaults. Run both at once if you like. [The desktop app](docs/desktop.md)

## What's inside

- **One key per field.** `y` `p` `U` `t` copy the username, password, website or one-time code. [Keys](docs/keys.md)
- **Two-factor codes.** `t` copies the current code, never the seed. The desktop app reads a QR screenshot. [One-time codes](docs/one-time-codes.md)
- **A generator on call.** Passwords, passphrases and PINs, with their strength in bits. [Generating](docs/generate.md)
- **A built-in audit.** Reused, weak, expired and old passwords, worst first, plus an optional breach check. [Auditing](docs/audit.md)
- **Many vaults.** Work and personal side by side. `^v` switches. [Vaults](docs/vaults.md)
- **Hardware keys.** YubiKey challenge-response, key files and Touch ID. [Security](docs/security.md)
- **SSH keys for your agent.** Unlocking hands `ssh-agent` the keys in your vault, and locking takes them back. [Security](docs/security.md)
- **Bring your passwords.** Import from KeePassXC, Bitwarden or 1Password. Export to CSV or JSON. [Importing](docs/import.md)
- **Settings in the window.** The desktop app's ⌘, sets the idle lock, clipboard clearing, list order,
  single-letter keys, backups and Touch ID, and saves them to the config file both apps read. [The desktop app](docs/desktop.md#using-it)
- **Scriptable.** `sennel get`, `gen`, `audit` and `run`, with exit codes a script can branch on. [sennel get](docs/get.md)

## Secrets for your projects

Stop keeping a `.env` full of real keys where a stray commit or an AI agent can read it. Paste the
whole file into one entry, comments and all, then delete it:

<img src="docs/images/env-entry.png" alt="The desktop app showing an env entry: variables grouped under Database, Payments and Monitoring, each with its label and hidden value" width="760">

```sh
sennel env import "myapp dev" .env --group Projects/myapp
rm .env
sennel run --entry "myapp dev" -- npm run dev
```

`sennel run` hands the variables to the program and nothing else. They never touch the clipboard, a
shell variable or your history. A project can also commit a `sennel.env` that names entries and
holds no secrets. [sennel run](docs/run.md)

## Install

Download a build from the [latest release](https://github.com/madebygrant/sennel/releases/latest),
or build from a clone:

```sh
git clone https://github.com/madebygrant/sennel.git && cd sennel
scripts/install.sh            # asks: terminal app, desktop app, or both
```

Checksums, Linux packages and every other way to install: [Installing](docs/install.md)

## Quick start

```sh
sennel --db ~/vault.kdbx      # opens a vault, or creates it on first unlock
```

Sennel remembers the vault, so next time it is just `sennel`. In the desktop app, pick
**New vault** on the unlock screen instead. The keys for day one:

| Key       | Does                                 |
| --------- | ------------------------------------ |
| `/`       | search                               |
| `j` `k`   | move up and down                     |
| `p`       | copy the password                    |
| `y` `t`   | copy the username, the one-time code |
| `a` `e`   | add, edit an entry                   |
| `P`       | generate a password                  |
| `u`       | undo                                 |
| `h`       | every other key                      |

## Documentation

| Guide                                                     | What it covers                                                  |
| --------------------------------------------------------- | --------------------------------------------------------------- |
| [Installing](docs/install.md)                             | releases, checksums, building from source                       |
| [Keys](docs/keys.md)                                      | every key, the unlock screen, the mouse and the menus           |
| [The desktop app](docs/desktop.md)                        | building, installing and using the window                       |
| [Finding entries](docs/search.md)                         | fuzzy search, tags, expiry dates and sort order                 |
| [One-time codes](docs/one-time-codes.md)                  | adding codes, including from a QR screenshot                    |
| [Vaults, sync and safety nets](docs/vaults.md)            | several vaults, merging, backups, undo and history              |
| [Generating passwords](docs/generate.md)                  | passwords, passphrases and PINs, in the app and from a script   |
| [Auditing](docs/audit.md)                                 | what gets flagged, and the breach check                         |
| [Importing](docs/import.md) · [Exporting](docs/export.md) | moving between password managers                                |
| [Older KDBX files](docs/kdbx3.md)                         | KDBX 3.1 and `sennel convert`                                   |
| [sennel get](docs/get.md)                                 | secrets from the command line                                   |
| [sennel run](docs/run.md)                                 | a program with secrets in its environment, and `sennel env`     |
| [The system keychain](docs/keychain.md)                   | unlocking scripts without typing the master password            |
| [Themes](docs/themes.md)                                  | six palettes, and how their contrast is measured                |
| [Configuration](docs/configuration.md)                    | every setting in the config file                                |
| [Security](docs/security.md)                              | what is wiped, when, and why                                    |
| [Reference for AI agents](docs/agents.md)                 | every scriptable command, also indexed in [`llms.txt`](llms.txt) |

## Development

```sh
cargo build --release
cargo test
cargo clippy -- -D warnings
```

The desktop app also needs Node.js. See [the desktop app](docs/desktop.md#building).

## License

MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

The passphrase wordlist is the [EFF large wordlist](https://www.eff.org/dice), CC-BY 3.0, minus four
hyphenated entries.
