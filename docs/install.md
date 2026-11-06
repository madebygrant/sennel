# Installing Sennel

[Back to the README](../README.md)

Sennel runs on macOS and Linux. There are two apps, and you can install either or both:

- **The terminal app and CLI**, a single binary called `sennel`. It includes `sennel get`,
  `sennel run`, `sennel env` and the other subcommands.
- **The desktop app**, a native window over the same vaults. [The desktop app](desktop.md)

## Download a release

The [latest release](https://github.com/madebygrant/sennel/releases/latest) has ready-built files:

| File                                               | What it is                                                    |
| -------------------------------------------------- | ------------------------------------------------------------- |
| `sennel-<version>-aarch64-apple-darwin.tar.gz`     | terminal app and CLI, Apple silicon Mac                       |
| `sennel-<version>-x86_64-apple-darwin.tar.gz`      | terminal app and CLI, Intel Mac                               |
| `sennel-<version>-x86_64-unknown-linux-gnu.tar.gz` | terminal app and CLI, Linux x86_64, glibc 2.35 or later       |
| `sennel-<version>-aarch64-unknown-linux-gnu.tar.gz` | terminal app and CLI, Linux arm64, glibc 2.35 or later       |
| `.dmg`                                             | desktop app, Apple silicon Mac                                |
| `.AppImage` and `.deb`                             | desktop app, Linux x86_64, glibc 2.39 or later, such as Ubuntu 24.04 |
| `SHA256SUMS`                                       | a checksum for every file above                               |

### The terminal app

Set `v` to the release's version and `t` to your platform from the table. This downloads the
tarball, checks it against `SHA256SUMS` and installs `sennel` into `~/.local/bin`:

```sh
v=0.4.0 t=aarch64-apple-darwin
base=https://github.com/madebygrant/sennel/releases/download/v$v
curl -LO "$base/sennel-$v-$t.tar.gz" -LO "$base/SHA256SUMS"
grep " sennel-$v-$t.tar.gz\$" SHA256SUMS | shasum -a 256 -c
tar -xzf "sennel-$v-$t.tar.gz"
install -m 755 "sennel-$v-$t/sennel" ~/.local/bin/
```

On Linux, use `sha256sum -c` in place of `shasum -a 256 -c`. Any folder on your `PATH` works in
place of `~/.local/bin`.

### The desktop app

- **Mac:** open the `.dmg` and drag Sennel to Applications. The builds have no Apple developer
  signature, so macOS quarantines a `.dmg` downloaded in a browser. Open it once, then allow it under
  System Settings › Privacy & Security.
- **Linux:** make the `.AppImage` executable and run it, or install the `.deb` with
  `sudo apt install ./Sennel_<version>_amd64.deb`.

## Build from source

You need [Rust](https://rustup.rs) 1.88 or later. The desktop app needs Rust 1.90 and
[Node.js](https://nodejs.org) as well.

```sh
git clone https://github.com/madebygrant/sennel.git && cd sennel
scripts/install.sh
```

The script asks whether to install the terminal app and CLI, the desktop app, or both. `--cli`,
`--desktop` or `--both` skips the question. A script or CI job has to pass one, since there is
nobody to answer.

- The terminal app and CLI install as `sennel` in `~/.cargo/bin`, built from the clone's lockfile.
- The desktop app goes in `/Applications` as `Sennel.app` on a Mac. On Linux the AppImage installs
  as `~/.local/bin/sennel-desktop`, with a menu entry. On Linux, install WebKitGTK first, as listed
  in [the desktop app](desktop.md#building).

To install only the terminal app without a clone:

```sh
cargo install --git https://github.com/madebygrant/sennel.git sennel-tui --locked
```

## After installing

`sennel --check` prints what Sennel can see: the config file, the vault, the clipboard and an SSH
agent. It needs no vault password, so it is the first thing to run when something seems off.

Shell completions and a man page come from the binary:

```sh
sennel completions zsh > ~/.zfunc/_sennel    # bash, zsh, fish, elvish
sennel man > /usr/local/share/man/man1/sennel.1
```
