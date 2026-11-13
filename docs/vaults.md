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
files. The terminal app stores the fields you add as protected. In the desktop app only a Password
field is, and Text, Textarea and Number fields are stored unprotected. An attachment can go out to Sennel's own
files folder, or to `ssh-agent` as a key. [The keys](keys.md#the-fields-screen-f).

## Field references

KeePass and KeePassXC let one entry borrow another's field, so a shared password lives in one place.
KeePassXC writes references when you clone an entry and choose to reference its username and
password rather than copy them. The field then holds a placeholder such as `{REF:P@I:46C9B1FFBD4ABC4BBB260C6190BAD20C}`, meaning "the
password of the entry with this ID".

Sennel resolves them wherever it hands out or shows a value: copying, `sennel get`, `sennel run`, the
detail pane and the fields screen, the desktop app, and export. Editing shows the placeholder itself, so saving an
entry keeps the reference instead of replacing it with a copy.

| Code | Field     |
| ---- | --------- |
| `T`  | title     |
| `U`  | username  |
| `P`  | password  |
| `A`  | url       |
| `N`  | notes     |
| `I`  | the entry's ID. Wanted: gives the ID. Searched: names one entry exactly |
| `O`  | other fields, searched only                                             |

- **One match or none.** KeePass takes the first entry when a search such as `{REF:P@T:mail}` matches
  several. Sennel refuses instead and says so, the same rule `get` follows, so a guess never picks a
  password. A reference by `I`, which KeePassXC writes, always names one entry.
- **Inside other text.** A reference can sit inside a field, such as
  `https://forum.example.com/?user={REF:U@T:Example}`, and can point at a field that holds a
  reference of its own. A loop is refused rather than followed forever.
- **Broken references.** A reference to an entry that is gone, or one Sennel cannot read, is an error
  when copying, `get` or `run` asks for it, never its raw text passed off as the value. The detail
  pane shows the raw text, so you can see what is stored. Export writes it as stored.
- **Passwords stay masked in views.** A reference to a password inside a field Sennel shows openly,
  such as `https://ada:{REF:P@I:...}@bank.example` in the url, shows the password as `••••••`. It
  resolves in full only when you copy the field, reveal it, or ask `get`, `run` or export for it.
  In the desktop app the password does not reach the window until then.
- **Limits.** A chain stops after ten steps, and one value follows at most 64 references in all, so
  an entry built to fan out cannot freeze the screen. Past either limit it is an error.
- **The recycle bin.** A reference by ID still reaches an entry in the bin. A search never does.
- **The audit.** An entry whose password is a reference is skipped. Its target is checked in its own
  right, and sharing on purpose is not reuse.

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
