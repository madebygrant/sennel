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

**Clipboard auto-clear.** Copies are wiped after a configurable interval, 30 seconds by default,
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

**Backups.** The first save of a session keeps the file as it was opened, and older copies shift up,
`backups` of them in all (3 by default, 0 for none). They live in `~/.local/state/sennel/backups`
(`XDG_STATE_HOME`, or `backup_dir`), named for the vault's full path so two `vault.kdbx` files do not
share them. Never beside the vault: that folder is usually the one Dropbox, Drive or iCloud watches,
and a backup there would be uploaded, old passwords and all. One per session, not one per save,
because autosave writes after every edit and a copy per save would only ever hold the last few
keystrokes. A session that starts within six hours of the newest backup takes none, because every
unlock is a session and a day of locking would otherwise replace every copy with one from today. Each
is a real copy of the whole vault, secrets included, `0600` in a `0700` folder, so a program that
rewrites the vault in place cannot change it. The `^s` overwrite and a merge always keep the file
they replace, since that is somebody else's work. A rekey deletes every backup and says how many,
because they still open with the old password. If a backup cannot be written the save is refused
rather than going ahead without one. Nothing else deletes them: they outlive a quit, a deleted entry
and a cleared history, and `sennel --check` lists them.

**A YubiKey as part of the key.** `yubikey = "2"` (or `--yubikey 2`, or `"2:<serial>"` to name one of
several) opens vaults that KeePassXC protects with a YubiKey's HMAC-SHA1 challenge-response slot. The
challenge is the file's own fresh KDF seed, which changes on every write, so **every save asks the
key again**, and a key that needs a touch needs one per save. Sennel draws "touch your key to save…"
first, then writes, and edits made before that frame share the one write. An unplugged key is
reported as a missing key and the edit stays in memory, never as a wrong password. Nothing in the
file says a vault uses a key, so the setting is a default and `^y` on the lock screen turns it off for
a vault that has none. A new vault made while it is on is keyed to the slot. Adding a key to an
existing vault is not done here: do it in KeePassXC. The hardware path is untested against a real key
by this project's suite, which covers the same code with a software HMAC secret. On Linux the
udev rules for the key (`yubikey-personalization` ships them) must let your user open it.

**Paste and export.** A paste is bracketed by the terminal and fed to the focused box only: in the
entry list it does nothing, because each character there is a command. It is dropped past 16 KiB, its
line breaks are dropped except in notes, and the pasted string is wiped after use. An authenticator
export link in the seed box is decoded by hand, its buffers wiped, and refused when it holds more
than one account, a counter-based code or an MD5 code. `sennel export` writes every password in the
clear: it refuses a terminal, refuses to overwrite, creates the file `0600`, and builds the text in
one buffer that is wiped when it drops. The file it leaves is yours to delete, and `docs/export.md`
says what is left out.

**SSH keys for the agent.** With `ssh_agent = true`, unlocking a vault gives `ssh-agent` the keys that
KeePassXC's KeeAgent settings mark "add at database open": an entry with a `KeeAgent.settings`
attachment naming the key attachment, whose password is the key's passphrase. It is off by default
because it hands keys to a process outside Sennel. The key goes from the vault's memory to the agent's
socket and is never written to disk. Every key is sent with a lifetime (`ssh_agent_lifetime`, 3600
seconds, or the entry's own if shorter), so a crash or a kill cannot leave it there for good: the agent
forgets it by itself. A clean lock, idle lock or quit takes the keys back out, except any whose
settings say not to remove them at close, and those still expire. The entry's "confirm" setting is
passed on. Only OpenSSH-format keys in an attachment are read: not PuTTY `.ppk`, not old PEM, not a
file path. ed25519 and RSA are reliable. The key library cannot read about one valid ECDSA key in
twenty (P-521 more often), and says so instead of calling it a wrong passphrase. `g` on an attachment in the `F` screen gives that one key to the agent even with
`ssh_agent` off, and it is taken back out on lock like the others. A forwarded agent
(`ssh -A`) is whatever `SSH_AUTH_SOCK` points at, so it receives the keys too. `sennel --check` says
whether the agent answers.

**Idle auto-lock.** After the idle timeout, 300 seconds by default and `0` to disable, the vault
locks and the in-memory secrets are zeroized, apart from the sealed password `touch_id` keeps. `^l` does the same on demand. Time the machine spent
suspended counts: neither platform's monotonic clock advances across a suspend, so the wall clock is
read alongside it and the longer answer wins. A vault unlocked before the lid closed is locked when
it opens. Keeping both clocks is also what stops one set backwards from holding a vault open.

**Touch ID after a lock (macOS, opt-in).** With `touch_id = true`, a typed unlock also seals the
master password to a new Secure Enclave key, and `enter` on an empty password box after a lock asks
for a fingerprint instead. The key is made inside the Enclave and cannot leave it. Using it takes a
fingerprint, and adding or removing any finger voids it, so after that the password is typed again.
It is never written to a keychain, so it dies with the process: a quit, a crash or a reboot means
typing the password again. What survives a lock is the password encrypted to that key, so a dump of
the process does not give the password, but a person at the unlocked machine with your finger does.
The system's own copy of the password as it comes out of the Enclave is freed, not wiped, which is
the one exception to the rule below. A key file is read again and a YubiKey is touched again, as for
a typed unlock. A dismissed prompt asks again on the next `enter`. A password the vault refuses,
because it changed somewhere else, is dropped, and `^p` seals the new one. On a Mac with no sensor
it says so once and stays off for the session. Off by default, because it keeps something on the far
side of a lock that the lock used to wipe.

**Zeroized in memory.** The typed password, confirmation and one-time-seed boxes are overwritten, not
merely emptied, whenever they are cleared, locked or thrown away. So are the decrypted values the
`F` and `H` screens hold, since a custom field is a recovery code as often as not and every row of
the history screen is a password somebody used to have. So are the rows an import parses out of a
CSV. The retained database key and the undo snapshots wipe on drop, and so does a field on its way
to the clipboard: `p` and `sennel get -p` wipe their copy rather than leaving it for the allocator.
The boxes you type into are given room for a password up front, because a `String` that grows
reallocates, and the block it leaves behind is freed with your keystrokes still in it. The key-file
box holds a path, not the file's contents, so a lock keeps it. The status bar names what was copied,
never the secret itself.

**Deletes go to the recycle bin.** `D` moves an entry or a group, subtree and all, into the same
`Recycle Bin` group KeePassXC uses, recorded in the file's own metadata. Nothing is destroyed, the
entry keeps its id and history, and `u` moves it home. The undo stack stops at 32 steps on purpose:
each snapshot holds a whole entry, secrets included, and dropping the oldest is what zeroizes it. A
lock or a reload empties it. Binned rows stay out of counts, search and `--list`, so a deleted
password cannot be copied by accident. Inside the bin, `D` is the real delete, and there is no undo
for it.

**It will not overwrite somebody else's write.** Sennel remembers the modification time and length
of the file it opened. If KeePassXC, a sync client or a second Sennel writes the vault meanwhile,
the next autosave refuses rather than silently winning. `^f` merges, `^s` overwrites theirs, `^r`
takes theirs. Two writes inside one filesystem timestamp tick that leave the file exactly the same
length would slip past, but every real edit changes one or the other.

**Merging.** `^f` reads the file on disk with the key already held, folds it into this session entry
by entry (matched by id, the newer edit wins, adds, moves and deletes from both sides are kept), and
writes the result. The file it replaces is backed up first. It goes into a copy and replaces the
session's vault only when it succeeds, and the file is checked again just before the write, so a
third writer in between is a conflict again. It is refused, changing nothing, when two different
edits to one entry carry the same timestamp (they are whole seconds) and nothing can order them.
It is also refused when it would have to carry an attachment across: an entry the other side
created with files, or whose files they changed after you. The merge code it uses copies entries
between the two files as whole records, and an attachment in one file is a number into that file's
own table, so carried over it would open as the wrong file. `^s` and `^r` are still there. Deletes
only survive a merge because Sennel now records them in the file's deleted-objects list, so a vault
last written by an older Sennel may bring back an entry deleted there. The merge is the `keepass`
crate's, whose `_merge` feature is marked unstable, so that version is pinned.

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

## The desktop app

Everything above holds for [the desktop app](desktop.md) too, because the vault, saving, backups,
the clipboard and Touch ID are the same Rust code. The window adds one more place a secret can be:
the webview, which runs JavaScript.

**A secret in the webview is not wiped.** JavaScript strings cannot be overwritten, only dropped,
so a secret that reaches the page stays in the webview's memory until its garbage collector frees
it, possibly long after. These put one there: the password typed on the unlock screen, a password
revealed with Show, the password and one-time-code seed typed or generated in the entry form, the
generator's result, and the value of a custom field added on the Fields screen. The page clears its
boxes after use, which is as far as a webview goes. On the way across, each one also passes through
Tauri's IPC as JSON text, and those buffers are freed, not wiped. Rust wipes the copies it holds
itself: a revealed or generated password once it is sent, and a typed one once it is used. So the
main process can briefly hold an unwiped copy too, and a dump of the webview process could hold
any of them for longer.

**Copying stays in Rust.** Copy reads the value inside the Rust process and hands it to the same
board as the terminal app, with the same auto-clear. The value never reaches the page. A password
revealed in the entry pane cannot be selected. In a box that holds a secret, on the unlock screen,
in the entry form or in a new custom field, ⌘C and ⌘X send the selection to Rust instead of the
system's own copy, so it clears like any other copy. The generator's Copy does the same.

**What the page is given.** Lists carry titles, usernames and urls. The entry pane gets everything
else except the password. Protected custom fields are left out, and the copy button reads them in
Rust. A stored one-time-code seed is never sent: Copy puts the current code on the clipboard.
The audit names a finding without the password behind it, and history shows titles, usernames and
dates.

**No server, and a locked-down page.** The page is bundled into the binary and talks to Rust over
Tauri's in-process IPC, so there is no port for anything on the machine or the web to reach. The
content security policy allows only the bundled files and that IPC. The page may call Sennel's own
commands, each granted by name, and listen for events. Rust emits three: `locked`, `prompt` (touch
your key) and `quit-asked`. Tauri's listen permission is not limited by event name. There are no file, shell or network
plugins: a key file or an attachment is read by Rust from a typed path. Devtools exist only in debug
builds.

**The idle lock does not trust the page.** It runs on a Rust thread, so a frozen or hidden window
cannot hold the vault open. Only keys and clicks in the window count as activity. Switching to it or
away does not, so a window left in the background locks on time.
