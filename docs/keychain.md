# Unlocking from the system keychain

[Back to the README](../README.md)

Keep the master password in the system keychain, and let the shell hand it to `sennel get` so a
script, an alias or a database login never asks you to type it. Sennel has no keychain code of its
own. It reads the master password from the first line of stdin whenever stdin is a pipe, and both
macOS and Linux ship a command that prints a keychain item to stdout. The two join with one pipe.

This is for the subcommands: `get`, `--list`, `audit`, `export` and `import`. The TUI and the
desktop app still prompt, and after a lock use [Touch ID](security.md) instead, which keeps nothing
outside the running process.

## macOS

### Store it once

```sh
security add-generic-password -a "$USER" -s sennel-master -T "" -w
```

`-w` with no value prompts for the password twice, so it stays out of your shell history. `-T ""`
trusts no application, so every read asks before handing it over. The item lands in the login
keychain, encrypted with your login password and unlocked while you are logged in.

To change it later, add `-U`. To remove it:

```sh
security delete-generic-password -a "$USER" -s sennel-master
```

### Use it

```sh
security find-generic-password -a "$USER" -s sennel-master -w | sennel get prod-postgres --stdout
```

`find-generic-password -w` prints the password alone with a trailing newline, which is the one line
Sennel reads. The same pipe works in front of any subcommand that needs the vault. A key file or
YubiKey is still passed as usual:

```sh
security find-generic-password -a "$USER" -s sennel-master -w | sennel get prod-postgres --stdout --key-file ~/.sennel.key
```

A function in `~/.zshrc` turns it into one word:

```sh
sennel-pw() {
  security find-generic-password -a "$USER" -s sennel-master -w | sennel get "$@" --stdout
}
```

```sh
PGPASSWORD="$(sennel-pw prod-postgres)" psql -h db.example.com -U app mydb
MYSQL_PWD="$(sennel-pw prod-mysql)" mysql -h db.example.com -u app mydb
```

`$(...)` is not a terminal, so `--stdout` needs no `--force`, and the secret goes into an
environment variable rather than an argument, so `ps` and your history never see it. Exit 2 means
the needle matched more than one entry and 3 means it matched none, so a script can tell the two
apart. [sennel get](get.md).

For a program that takes its secret from an environment variable, `sennel run` skips the shell
step, so the secret never sits in a `$(...)` result:

```sh
sennel-run() {
  security find-generic-password -a "$USER" -s sennel-master -w | sennel run "$@"
}
sennel-run -e PGPASSWORD=prod-postgres -- psql -h db.example.com -U app mydb
```

[sennel run](run.md).

### Make every read ask

With `-T ""` the first read opens a dialog: Deny, Allow Once or Always Allow. Always Allow adds
`security` to the item's trusted list and the question never comes back, which is the convenient
setting and the weak one, because anything running as you can then run the same command in silence.

To keep the question, open Keychain Access, find `sennel-master` in the login keychain, open it and
go to Access Control. Choose "Confirm before allowing access" and tick "Ask for keychain password".
Every read now needs your login password, with no Always Allow to click through. The confirmation is
the keychain's own dialog, so a script that runs with no display, over SSH or from cron, fails with
`User interaction is not allowed` instead of reading the password. Touch ID is not offered here:
macOS reserves it for items apps create through the data-protection keychain, which the `security`
command cannot read.

## Linux

GNOME Keyring and KDE Wallet both answer the Secret Service D-Bus API, and `secret-tool` from
libsecret talks to whichever is running. It is in `libsecret-tools` on Debian and Ubuntu, `libsecret`
on Fedora and Arch. Everything below needs a running desktop session, since the keyring is unlocked
by your login and the prompts are drawn by it.

Omarchy installs `gnome-keyring` and `libsecret` in its base, so `secret-tool` is already there.
Seahorse is not: `sudo pacman -S seahorse` before the separate-keyring step below. If the first
`lookup` opens a window asking to unlock the login keyring, that is GNOME Keyring's own prompt,
drawn in Hyprland like any other, and it means your keyring password is not the one PAM saw at
login. Unlock it once per session, or set the keyring password to match in Seahorse.

### Store it once

```sh
secret-tool store --label='Sennel master password' service sennel-master
```

It prompts for the password on the terminal. `service sennel-master` is an attribute pair the lookup
matches on, and the label is what the keyring's own app, Seahorse or KWalletManager, shows.

To change it, run the same command again with the same attributes: it replaces the item. To remove
it:

```sh
secret-tool clear service sennel-master
```

### Use it

```sh
secret-tool lookup service sennel-master | sennel get prod-postgres --stdout
```

`lookup` prints the password with no trailing newline. Sennel accepts that, because it reads up to
the end of the first line or the end of input, whichever comes first. The shell function and the
database examples from the macOS section work unchanged with this one line swapped in:

```sh
sennel-pw() {
  secret-tool lookup service sennel-master | sennel get "$@" --stdout
}
```

### Make every read ask

The Secret Service API has no per-item access control. Once the keyring is unlocked, any process in
your session reads any item without a prompt, and `secret-tool` cannot change that. There are two
ways to get a question back:

- **A separate keyring that locks.** In Seahorse, create a keyring named `sennel` with its own
  password, move the item into it, and lock it, from the keyring's right-click menu, after each use.
  The next `lookup` makes GNOME Keyring prompt for that keyring's password. KWallet does the same
  with a second wallet and a close-after timeout in its settings. A locked keyring over SSH or from
  cron cannot prompt, so `lookup` prints nothing and Sennel exits 1 on the empty password.
- **`pass` with a GPG key on a smart card or YubiKey.** `pass sennel-master | sennel get ...` asks
  for the card's PIN or a touch through `gpg-agent`, and the agent's cache timeout decides how long
  one answer lasts. The password is encrypted at rest with a key that never leaves the card.

Of the two, the locked keyring is the simpler one and the smart card is the stronger.

## What this does and does not protect

The keychain is unlocked for as long as you are logged in. With Always Allow on macOS, or with the
default keyring on Linux, the master password is one command away for any process running as you,
which is the same exposure as a plaintext file with mode 600, except that the file would also
survive in a backup and the keychain does not leave the machine unencrypted. With "Ask for keychain
password" or a separate locked keyring, a process needs you at the keyboard. A locked screen, a
sleeping laptop or a stolen one that was powered off holds the item encrypted with your login
password.

A vault that leaves the machine, through iCloud, Dropbox or a backup, is better off also needing a
[key file or YubiKey](security.md). The keychain then holds one factor and the disk or key holds
the other, so neither alone opens the vault.

Do not put the master password in `.zshrc`, an environment variable or a dotfile repository. Those
are readable by anything, are not encrypted at rest, and travel with your backups.
