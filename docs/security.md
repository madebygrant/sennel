# Security

[Back to the README](../README.md)

What Sennel protects, and what it does not.

**KDBX4 end to end.** The vault is a real KeePass database. The file is never modified without your
password being re-keyed.

**Owner-only files.** Saves are atomic. Sennel writes a sibling temp file and renames it over the
vault, `chmod 0600` from the first byte. The temp file is created exclusively, so a symlink planted
in the vault's directory cannot redirect the write. The config file is `0600` too. It holds no
secret, but it names where the vault lives.

**No crash dumps, no ptrace.** Core dumps are off at startup and, on Linux, the process is marked
undumpable. A dump of Sennel holds every secret at once, and anything running as the same user can
attach to a dumpable process.

**Clipboard auto-clear.** Copies are wiped after a configurable interval, 15 seconds by default. A
second copy re-arms the timer rather than being wiped early by the first one. Quitting wipes
immediately, because the timer is a thread inside the process and cannot outlive it. The status bar
counts the wipe down, so the screen tells you when a secret is still on the clipboard.
`clipboard_timeout = 0` means leave it there, and that is honoured on the way out too.

**Changing the master password.** `^p` re-keys the vault in place: the database is written again
under the new password before the session swaps to it, so a refused or failed write leaves a file
that still opens with the password you already had. The write is guarded like any other, so it
cannot land on top of somebody else's. A key file stays part of the key and is re-read from the
path you unlocked with, because a re-key that forgot it would write a vault you could not open.
Sennel records the change in the file's metadata the way KeePassXC does. Nothing can recover the
new password if you forget it, and the prompt says so.

**Idle auto-lock.** After the idle timeout, 300 seconds by default and `0` to disable, the vault
locks and the in-memory secrets are zeroized. `^l` does the same on demand.

**Zeroized in memory.** The typed password, key-file and one-time-seed boxes are overwritten, not
merely emptied, whenever they are cleared, locked or thrown away. The retained database key and the
undo snapshots wipe on drop. The status bar names what was copied, never the secret itself.

**Deletes go to the recycle bin.** `D` moves an entry or a group, subtree and all, into the same
`Recycle Bin` group KeePassXC uses, recorded in the file's own metadata. Nothing is destroyed, the
entry keeps its id and history, and `u` moves it home. Binned rows draw back in the tree and are
left out of counts, search and `--list`, so a deleted password cannot be copied by accident. Inside
the bin, `D` is the real delete: the confirm says so, and there is no undo for it.

**It will not overwrite somebody else's write.** Sennel remembers the modification time and length
of the file it opened. If KeePassXC, a sync client or a second Sennel writes the vault meanwhile,
the next autosave refuses rather than silently winning. `^s` overwrites theirs, `^r` takes theirs.
Two writes inside one filesystem timestamp tick that leave the file exactly the same length would
slip past, but every real edit changes one or the other.

**One-time codes, not their seeds.** An entry with a code is marked `⊙` in the list and shows the
current digits with the seconds left. `t` copies them. The seed is never copied, because that would
put a permanent credential on the clipboard to save typing six digits. The `otp` box in the entry
form takes either the `otpauth://` url behind a QR code or the secret a site prints beside it.
Spaces, hyphens and lower case are all fine. Sennel stores it protected and shows the code it
produces while you type, so you can check it before saving. Codes are six digits unless the url says
otherwise, which is the rule every authenticator app follows.

**Vault text cannot drive your terminal.** Entry titles and group names come out of a file anyone
may have written, so Sennel strips control characters everywhere text leaves the TUI, meaning
`--list` output and the window title. Inside the browser, ratatui's cell buffer drops them.

**Entry history is not Sennel's.** Editing an entry here writes no history record, so an old
password is not kept behind your back. Entries imported from KeePassXC may already carry history
from that client. Sennel preserves it untouched but neither displays nor clears it. Use KeePassXC if
you need to purge it.

**`get` keeps the clipboard rules.** The non-interactive path copies through the same board as the
TUI, waits out the wipe rather than abandoning a secret on the clipboard, and gives the current
one-time code rather than the seed. `--stdout` is the one way a secret leaves that path, and it
refuses a terminal unless forced, because scrollback is exactly where a password should not be.
Entries in the recycle bin are not candidates for any needle.

**Search and `--list` stay clean.** The fuzzy index covers titles, usernames, urls and group paths,
never notes. Printed inventories carry titles only.
