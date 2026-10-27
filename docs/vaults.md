# Vaults, sync and safety nets

[Back to the README](../README.md)

A Sennel vault is a KeePass `.kdbx` file you own. Keep it anywhere, sync it with anything, and open
it in KeePassXC too.

## More than one vault

Open a vault once and Sennel remembers it. The next launch opens it again, and `^v` on the unlock
screen lists every vault this machine has unlocked, newest first, with any that have moved marked
`missing`. `enter` switches to one without a restart, and `^d` forgets a row, never the file. Typing
narrows the list over the whole path, so `work` finds a vault by its folder as well as its name.

The desktop app reads the same list, shown as **Library** under the unlock form, so a vault opened
in one app is a click away in the other. [More on the unlock screen](keys.md#the-unlock-screen).

## Sharing a file with other apps

Every change saves at once. Before each save Sennel checks the file is still the one it opened. If
KeePassXC, a sync client or the other Sennel app wrote it in the meantime, Sennel refuses to save
rather than quietly winning, and you choose:

| Terminal | Desktop          | Does                                                   |
| -------- | ---------------- | ------------------------------------------------------ |
| `^f`     | **Merge both**   | fold their changes into yours, entry by entry          |
| `^s`     | **Overwrite theirs** | keep yours. Sennel backs theirs up first           |
| `^r`     | **Reload theirs**| drop your unsaved changes and take theirs              |

A merge matches entries by id and keeps the newer edit of each, with adds, moves and deletes from
both sides. [The details, including when a merge is refused](security.md).

## Backups

The first save of each session keeps a copy of the file as it was, three of them by default. They
go in `~/.local/state/sennel/backups`, never beside the vault, because that folder is usually the
one Dropbox, Drive or iCloud uploads. Changing the master password deletes them, since they still
open with the old one. `backups` and `backup_dir` in the [config file](configuration.md) change the
count and the place, and `sennel --check` lists them. [More](security.md).

## Undo and the recycle bin

`D` moves an entry or a group into the same Recycle Bin KeePassXC uses, and `u` brings it back. Undo
goes back step by step through the session's edits, moves and deletes, up to 32 of them. Entries in
the bin stay out of search and counts, so a deleted password cannot be copied by accident. Deleting
from inside the bin is permanent.

## History

KeePassXC keeps old versions of an entry when you edit it, and those versions hold old passwords.
Sennel's own edits write no history, so nothing is kept behind your back. `H` shows the versions an
entry arrived with, and clears them for good.

## Fields and attachments

`F` opens what an entry's fixed rows cannot show: custom fields, such as recovery codes, and attached
files. Sennel stores the fields you add as protected. An attachment can go out beside the vault,
or to `ssh-agent` as a key. [The keys](keys.md#the-fields-screen-f).

## Changing the master password

`^p` in the terminal app, or `⌘P` and the key button in the desktop app, re-keys the vault in
place. Sennel writes the file under the new password before switching to it, so a failed write
leaves a vault that still opens with the old one. A key file you unlocked with stays part of the
key. Nothing can recover the new password if you forget it.

## Unlocking with more than a password

- **Key files** are a second box on the unlock screen.
- **YubiKey** challenge-response slots work as in KeePassXC. Set `yubikey = "2"`, and touch the key
  when Sennel asks.
- **Touch ID** on a Mac reopens a vault after a lock with a fingerprint, once you have typed the
  password that session. Set `touch_id = true`.

[How each one works](security.md).

## Older files

KDBX 3.1 vaults open read-only. `sennel convert` writes a verified KDBX 4 copy beside the original.
[More](kdbx3.md).
