# Security

[Back to the README](../README.md)

What Sennel protects, and what it does not.

**KDBX4 end to end.** The vault is a real KeePass database, and the file is never modified without
your password being re-keyed. Older files (3.1 and below) open read-only, and Sennel says so at
unlock rather than at the first failed save. `sennel convert` writes a verified KDBX 4 copy beside
the original, never in place and never over an existing file. See [docs/kdbx3.md](kdbx3.md).

**New vaults get strong key derivation.** A vault Sennel creates uses Argon2id with 64 MiB of
memory, 3 passes and 4 lanes, the second setting RFC 9106 recommends. Every unlock and every save
runs it once. A vault whose Argon2 memory is under 16 MiB is raised to the same setting on its next
save, and the unlock message says so. Anything at or above that, and a vault using AES-KDF, is left
as it was set.

**A vault file cannot ask for unlimited work.** The `keepass` crate runs the key derivation a file's
header asks for before it can check the file was written with your key, so whoever can write the
file chooses how long an unlock takes and how much memory it uses. Sennel reads the header first and
refuses more than a billion AES rounds, more than 2 GiB of Argon2 memory, more than 10,000 passes,
more than 64 lanes, or memory times passes above 256 GiB. Key files, attachments and CSV imports
over 64 MiB are refused too, and a one-time code whose period is outside 1 second to a day, or whose
digits are outside 6 to 10, is treated as no code.

**Groups nest at most 64 deep.** The file format's parser refuses XML nested past 128 elements, so a
vault with deeper groups would save but never open again. A move or an import that would go past 64
is refused before anything changes.

**An import leaves a plaintext file behind.** Every export from every password manager is every
password you own, in the clear, on disk. `sennel import` says so when it finishes. Delete it.

**Owner-only files.** Sennel writes a sibling temp file, flushes it to the disk, then renames it
over the vault, `chmod 0600` from the first byte. The flush is what makes the rename mean anything.
A rename is atomic about the *name* only, so without it a power cut moments after a save could leave
the vault's path pointing at blocks that never landed. The temp file is created exclusively, so a
symlink planted in the vault's directory cannot redirect the write. A vault path that is itself a
symlink is followed: the save lands on the file it points at, and the link stays a link. The config
file is `0600` too. It holds no secret, but it names where the vault lives.

**No crash dumps, no ptrace.** Core dumps are off, and other processes of the same user cannot
attach to Sennel: on Linux the process is marked undumpable, and on macOS release builds deny
debugger attach. Both happen before the config is read or a vault is opened, on every path including
`get`, `audit` and `import`. A dump of Sennel holds every secret at once. If the system refuses either
call, the terminal app says so on stderr and the desktop app in a dialog, and `sennel --check` reads
both back rather than assuming they took. macOS cannot be asked whether attach is denied, so there
`--check` reports whether the call worked.

**Clipboard auto-clear.** Copies are wiped after a configurable interval, 30 seconds by default,
counted on the wall clock as well as the monotonic one. A sleeping thread does not run while the
machine is suspended, so the wipe waits out the interval rather than that many seconds of uptime. A
second copy re-arms the timer instead of being wiped early by the first one. The wipe clears whatever
is on the clipboard when it fires, so something you copied from another app in the meantime goes
too. Quitting wipes immediately, because the timer is a thread inside the process and cannot outlive
it, and so do `^C`, closing the terminal, a `kill` and a panic. The status bar counts the wipe down.
`clipboard_timeout = 0` means leave it there, on the way out too.

**Kept out of clipboard history.** The wipe clears the clipboard, not a clipboard manager's copy of
it, so every copy carries the marker those managers skip. On macOS that is
`org.nspasteboard.ConcealedType`, the convention described at nspasteboard.org. On Linux it is
`x-kde-passwordManagerHint`, on X11 and Wayland. On Windows it is the
flag that keeps a copy out of both clipboard history and cloud sync. A manager that ignores its
platform's marker still keeps the copy, and Sennel cannot tell.

**Changing the master password.** `^p` re-keys the vault in place, and asks for the current password
first, so somebody at an unlocked, unattended session cannot change it. The database is written again
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
line breaks are dropped except in notes, and the pasted string is wiped after use. This depends on
the terminal supporting bracketed paste. One that does not delivers a paste as keystrokes, and in the
entry list those are commands. An authenticator
export link in the seed box is decoded by hand, its buffers wiped, and refused when it holds more
than one account, a counter-based code or an MD5 code. `sennel export` writes every password in the
clear: it refuses a terminal, refuses to overwrite, creates the file `0600`, and builds the text in
one buffer that is wiped when it drops. The file it leaves is yours to delete, and `docs/export.md`
says what is left out.

**SSH keys for the agent.** With `ssh_agent = true`, unlocking a vault gives `ssh-agent` the keys that
KeePassXC's KeeAgent settings mark "add at database open": an entry with a `KeeAgent.settings`
attachment naming the key attachment, whose password is the key's passphrase. It is off by default
because it hands keys to a process outside Sennel. The key goes from the vault's memory to the agent's
socket, and Sennel never writes it to disk. What the agent does with it is up to the agent: one that
saves added keys to disk is outside Sennel's control. Every key is sent with a lifetime (`ssh_agent_lifetime`, 3600
seconds, or the entry's own if shorter), so a crash or a kill cannot leave it there for good: the agent
forgets it by itself. A clean lock, idle lock or quit takes the keys back out, except any whose
settings say not to remove them at close, and those still expire. The entry's "confirm" setting is
passed on. Only OpenSSH-format keys in an attachment are read: not PuTTY `.ppk`, not old PEM, not a
file path. ed25519 and RSA are reliable. The key library cannot read about one valid ECDSA key in
twenty (P-521 more often), and says so instead of calling it a wrong passphrase. `g` on an attachment in the `F` screen, or the desktop app's button, gives that one key to the agent even with
`ssh_agent` off, and it is taken back out on lock like the others. A forwarded agent
(`ssh -A`) is whatever `SSH_AUTH_SOCK` points at, so it receives the keys too. `sennel --check` says
whether the agent answers.

**Idle auto-lock.** After the idle timeout, 300 seconds by default and `0` to disable, the vault
locks and the in-memory secrets are zeroized, apart from the sealed password `touch_id` keeps. `^l`
does the same on demand. Only key presses, mouse clicks and scrolls count as activity. A pointer
passing over the window does not. Time the machine spent
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

**Zeroized in memory, and where that stops.** These are overwritten, not merely freed, when they
are cleared, locked or thrown away:

- the boxes you type a password, a seed or notes into, which are given room up front because a
  `String` that grows reallocates and frees the old block with your keystrokes still in it
- the decrypted values the `F` and `H` screens hold, the undo snapshots and the retained database key
- every cell an import parses out of a CSV, including columns Sennel ignores
- a field on its way to the clipboard, so `p` and `sennel get -p` wipe their copy
- an export or `env export`, built in a buffer that wipes each block it outgrows
- the message that hands a key to `ssh-agent`, the breach check's hash, and a QR code's text, plus
  the image's pixels once it proves to hold a one-time code
- the vault itself on lock: protected values, and, through a patch to the `keepass` crate that ships
  with Sennel, the unprotected ones too (titles, usernames, URLs, and notes other programs store
  unprotected), along with the keys and the decrypted file used during the unlock

Some copies are out of reach. The terminal app draws a revealed value into ratatui's screen buffer
and builds plain text for it on every frame, so while a secret is on screen, unwiped copies of it
are made and freed. Buffers inside the decryption, decompression and QR-decoding libraries, and the
`keepass` crate's one-time-code type, are not Sennel's to wipe. Terminal scrollback and a clipboard
manager's history are outside the process altogether. The key-file box holds a path, not the file's
contents, so a lock keeps it. The status bar names what was copied, never the secret itself.

**Deletes go to the recycle bin.** `D` moves an entry or a group, subtree and all, into the same
`Recycle Bin` group KeePassXC uses, recorded in the file's own metadata. Nothing is destroyed, the
entry keeps its id and history, and `u` moves it home. The undo stack stops at 32 steps on purpose:
each snapshot holds a whole entry, secrets included, and dropping the oldest is what zeroizes it. A
lock or a reload empties it. Binned rows stay out of counts, search and `--list`, so a deleted
password cannot be copied by accident. Inside the bin, `D` is the real delete, and there is no undo
for it: it also drops every undo step that held a copy of what it deleted.

**It will not overwrite somebody else's write.** Sennel remembers the modification time, length and
inode of the file it opened. If KeePassXC, a sync client or a second Sennel writes the vault meanwhile,
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

**Vault text cannot drive your terminal or disguise itself.** Entry text comes out of a file anyone
may have written. Control characters, and the invisible ones that reverse or hide text (bidi
overrides and isolates, zero-width spaces), show as `·` in both apps, in `--list`, in the window
title and in the paths `--check` prints. A reference in an error is named by its kind, never its text. `sennel env
export` writes only blank lines, comments and valid variable names from the stored layout, so a
vault cannot put a command into a file you source.

**Entry history is not Sennel's, but you can see and clear it.** Editing an entry here writes no
history record, so an old password is never kept behind your back. Entries imported from KeePassXC
may already carry history from that client, and `H` shows every version it holds. `D` throws the lot
away and writes the file out, so those passwords are gone from it rather than merely hidden. That
has no undo, and the message says so.

**`get` keeps the clipboard rules.** It copies through the same board as the TUI and waits out the
wipe rather than abandoning a secret on the clipboard. `--stdout` is the one way a secret leaves that
path, and it refuses a terminal unless forced, because scrollback is exactly where a password should
not be. Entries in the recycle bin are not candidates for any needle.

**Custom fields and attachments.** A field added in the terminal app is stored protected and masked
until `*`, the same rule the password follows. The desktop app asks for a type, and only Password is
stored protected. Text, Textarea and Number fields are stored unprotected, so KeePassXC shows them
plainly: put secrets in a Password field. `y` copies any of them through the
same board and auto-clear. An attachment written out with `s` goes to a folder named for the vault in
`~/.local/state/sennel/files` (`XDG_STATE_HOME`), never beside the vault, where a sync client would
upload it. The folder is `0700` and the file is created exclusively and `0600` from the first byte,
so a symlink planted at the path cannot redirect it. It has still left the vault, and the message
says so. The name is reduced to a plain file name first, so an attachment called
`../../.ssh/authorized_keys` lands as a file rather than a write somewhere else entirely.

**The breach check never sends a password.** `sennel audit --pwned` is the only feature that touches
the network. It is opt-in per run and unreachable from any keystroke in the TUI. It sends the first
five hex characters of a password's SHA-1 and matches the answer locally, so the service learns that
somebody asked about one of roughly half a million hashes. The prefix is on `curl`'s command line,
so other users of the machine can see it in the process list while the check runs. [The audit
page](audit.md) explains the hand-written SHA-1 and the `curl` call.

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
it, possibly long after. These put one there: the password typed on the unlock screen, the current
and new master passwords during a rekey, a password revealed with Show, a protected custom field
revealed on the Fields screen, the password and one-time-code seed typed, generated or scanned from
a QR code in the entry form, `.env` text pasted into the env screen, the generator's result, and the
value of a custom field added on the Fields screen. The page clears its boxes after use, which is as
far as a webview goes. On the way across, each one also passes through Tauri's IPC as JSON text, and
those buffers are freed, not wiped. Rust wipes the copies it holds itself: a revealed or generated
password once it is sent, and a typed one once it is used. So the main process can briefly hold an
unwiped copy too, and a dump of the webview process could hold any of them for longer. Show has no
rate limit, so a script running in the page could reveal every password. Nothing found so far lets
a script into the page, and the native confirms below are what stand between it and the rest.

**Copying stays in Rust.** Copy reads the value inside the Rust process and hands it to the same
board as the terminal app, with the same auto-clear. The value never reaches the page. A password
revealed in the entry pane cannot be selected. In a box that holds a secret, on the unlock screen,
in the entry form or in a new custom field, ⌘C and ⌘X send the selection to Rust instead of the
system's own copy, so it clears like any other copy. The generator's Copy does the same.

**What the page is given.** Lists carry titles, usernames and urls. The entry pane gets everything
else except the password, though it does get the password's length. Protected custom fields are left
out, and the copy button reads them in Rust. A stored one-time-code seed is never sent: Copy puts
the current code on the clipboard. The audit names a finding without the password behind it, but a
"reused" finding says how many entries share it. History shows titles, usernames and dates.

**No server, and a locked-down page.** The page is bundled into the binary and talks to Rust over
Tauri's in-process IPC, so there is no port for anything on the machine or the web to reach. The
content security policy allows only the bundled files and that IPC, and the window cannot navigate
anywhere but its own page. The page may call Sennel's own commands, each granted by name, and listen
for events. Rust emits three: `locked`, `prompt` (touch your key) and `quit-asked`. Tauri's listen
permission is not limited by event name. The only plugin is the file dialog, and the page may only
show its open and save pickers, which hand back a path. There are no shell or network plugins.
Devtools exist only in debug builds.

**The page cannot approve its own requests.** Lengthening the idle lock or the clipboard wipe,
keeping fewer backups and turning on Touch ID each ask in a native dialog raised by Rust, and are
refused while the vault is locked. Giving a key to `ssh-agent` asks the same way, once per unlock.
Attaching a file opens Rust's own file picker, so the page never names a path to read. Unlocking or
switching vaults is refused while one is open, and a rekey needs the current password. A script in
the page cannot click a native dialog.

**The idle lock runs in Rust, but the page reports activity.** The timer is a Rust thread, so a
frozen or hidden window cannot hold the vault open by stalling it. Only keys, clicks and scrolls in
the window count, and a scroll only while the window has focus. The page is what reports them,
though, so a script running in it could keep the vault open.

**The Mac app is ad hoc signed and not sandboxed.** It has no Apple Developer ID signature or
notarisation, and runs without the App Sandbox, so it can read any file your user can. Release files
carry GitHub build attestations, which show which workflow run built them. [Installing](install.md)
shows how to check one.
