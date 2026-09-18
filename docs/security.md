# Security

[Back to the README](../README.md)

What Sennel protects, and what it does not.

**KDBX4 end to end.** The vault is a real KeePass database, and the file is never modified without
your password being re-keyed. Older files (3.1 and below) open read-only, and Sennel says so at
unlock rather than at the first failed save. `sennel convert` writes a verified KDBX 4 copy beside
the original, never in place and never over an existing file. See [docs/kdbx3.md](kdbx3.md).

**An import leaves a plaintext file behind.** Every export from every password manager is every
password you own, in the clear, on disk. `sennel import` says so when it finishes. Delete it.

**Owner-only files.** Sennel writes a sibling temp file, flushes it to the disk, then renames it
over the vault, `chmod 0600` from the first byte. The flush is what makes the rename mean anything.
A rename is atomic about the *name* only, so without it a power cut moments after a save could leave
the vault's path pointing at blocks that never landed. The temp file is created exclusively, so a
symlink planted in the vault's directory cannot redirect the write. The config file is `0600` too.
It holds no secret, but it names where the vault lives.

**No crash dumps, no ptrace.** Core dumps are off and, on Linux, the process is marked undumpable.
That happens before the config is read or a vault is opened, on every path including `get`, `audit`
and `import`. A dump of Sennel holds every secret at once, and anything running as the same user can
attach to a dumpable process. `sennel --check` reads the limit back rather than assuming it took.

**Clipboard auto-clear.** Copies are wiped after a configurable interval, 15 seconds by default,
counted on the wall clock as well as the monotonic one. A sleeping thread does not run while the
machine is suspended, so the wipe waits out the interval rather than that many seconds of uptime. A
second copy re-arms the timer instead of being wiped early by the first one. Quitting wipes
immediately, because the timer is a thread inside the process and cannot outlive it. The status bar
counts the wipe down. `clipboard_timeout = 0` means leave it there, on the way out too.

**Changing the master password.** `^p` re-keys the vault in place. The database is written again
under the new password before the session swaps to it, so a refused or failed write leaves a file
that still opens with the password you already had. The write is guarded like any other, so it
cannot land on top of somebody else's. A key file stays part of the key and is re-read from the path
you unlocked with, because a re-key that forgot it would write a vault you could not open. Nothing
can recover the new password if you forget it, and the prompt says so.

**Idle auto-lock.** After the idle timeout, 300 seconds by default and `0` to disable, the vault
locks and the in-memory secrets are zeroized. `^l` does the same on demand. Time the machine spent
suspended counts: neither platform's monotonic clock advances across a suspend, so the wall clock is
read alongside it and the longer answer wins. A vault unlocked before the lid closed is locked when
it opens. Keeping both clocks is also what stops one set backwards from holding a vault open.

**Zeroized in memory.** The typed password, key-file and one-time-seed boxes are overwritten, not
merely emptied, whenever they are cleared, locked or thrown away. So are the decrypted values the
`F` and `H` screens hold, since a custom field is a recovery code as often as not and every row of
the history screen is a password somebody used to have. So are the rows an import parses out of a
CSV. The retained database key and the undo snapshots wipe on drop, and so does a field on its way
to the clipboard: `p` and `sennel get -p` wipe their copy rather than leaving it for the allocator.
The boxes you type into are given room for a password up front, because a `String` that grows
reallocates, and the block it leaves behind is freed with your keystrokes still in it. The status
bar names what was copied, never the secret itself.

**Deletes go to the recycle bin.** `D` moves an entry or a group, subtree and all, into the same
`Recycle Bin` group KeePassXC uses, recorded in the file's own metadata. Nothing is destroyed, the
entry keeps its id and history, and `u` moves it home. The undo stack stops at 32 steps on purpose:
each snapshot holds a whole entry, secrets included, and dropping the oldest is what zeroizes it. A
lock or a reload empties it. Binned rows stay out of counts, search and `--list`, so a deleted
password cannot be copied by accident. Inside the bin, `D` is the real delete, and there is no undo
for it.

**It will not overwrite somebody else's write.** Sennel remembers the modification time and length
of the file it opened. If KeePassXC, a sync client or a second Sennel writes the vault meanwhile,
the next autosave refuses rather than silently winning. `^s` overwrites theirs, `^r` takes theirs.
Two writes inside one filesystem timestamp tick that leave the file exactly the same length would
slip past, but every real edit changes one or the other.

**One-time codes, not their seeds.** `t` copies the six digits an entry's code is showing. The seed
is never copied, because that would put a permanent credential on the clipboard to save typing six
digits. It is stored protected, and the entry form shows the code it produces while you type, so you
can check a seed before saving it.

**Vault text cannot drive your terminal.** Entry titles and group names come out of a file anyone
may have written, so Sennel strips control characters everywhere text leaves the TUI, meaning
`--list` output and the window title. Inside the browser, ratatui's cell buffer drops them.

**Entry history is not Sennel's, but you can see and clear it.** Editing an entry here writes no
history record, so an old password is never kept behind your back. Entries imported from KeePassXC
may already carry history from that client, and `H` shows every version it holds. `D` throws the lot
away and writes the file out, so those passwords are gone from it rather than merely hidden. That
has no undo, and the message says so.

**`get` keeps the clipboard rules.** It copies through the same board as the TUI and waits out the
wipe rather than abandoning a secret on the clipboard. `--stdout` is the one way a secret leaves that
path, and it refuses a terminal unless forced, because scrollback is exactly where a password should
not be. Entries in the recycle bin are not candidates for any needle.

**Custom fields and attachments.** Fields you add are stored protected and masked until `*`, the
same rule the password follows, and `y` copies one through the same board and auto-clear. An
attachment written out with `s` is created exclusively and `0600` from the first byte, so a symlink
planted at the path cannot redirect it. It has still left the vault, and the message says so. The
name is reduced to its last path component first, so an attachment called `../../.ssh/authorized_keys`
lands as a file rather than a write somewhere else entirely.

**The breach check never sends a password.** `sennel audit --pwned` is the only feature that touches
the network. It is opt-in per run and unreachable from any keystroke in the TUI. It sends the first
five hex characters of a password's SHA-1 and matches the answer locally, so the service learns that
somebody asked about one of roughly half a million hashes. [The audit page](audit.md) explains the
hand-written SHA-1 and the `curl` call.

**The audit runs offline.** `!` compares passwords inside the process and sends nothing anywhere. It
groups them by hash rather than building a table of every password in the vault, then compares the
ones that land together before calling either reused. A false "reused" is the one finding you cannot
check without putting two passwords side by side. It names the finding without printing the
password, and skips the recycle bin, because telling somebody to go fix an entry they deleted is how
an audit loses their trust. "Weak" is the same 60-bit line the entry form draws in amber, not a
second opinion.

**Search and `--list` stay clean.** The fuzzy index covers titles, usernames, urls and group paths,
never notes. Printed inventories carry titles only.
