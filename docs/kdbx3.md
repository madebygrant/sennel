# Older KDBX files

[Back to the README](../README.md)

Sennel **reads** KDBX 3.1 and older. It **writes** KDBX 4 only, so an older vault opens read-only,
and says so at unlock rather than at the first failed save.

```sh
sennel convert --db old.kdbx        # writes old-kdbx4.kdbx beside it
```

## Why not just write 3.1

The writer does not exist. The `keepass` crate's KDBX3 module is parse-only, and `save` refuses
anything below KDBX 4 — still true in the latest release. Writing the format would mean a
hashed-block-stream framer, a Salsa20 inner stream, a different outer header and a second XML shape
for attachments: crypto-adjacent work that belongs upstream in the library, with round-trip fixtures
against KeePassXC, rather than in a password manager's own source.

Converting costs nothing, because KeePassXC has read and written KDBX 4 since 2.0 in 2016. The file
you get back opens in the client the old one almost certainly came from.

## What `convert` does, and refuses to do

It never touches the original. It opens it, swaps the whole format config for the one every vault
Sennel creates already uses, and writes a **new** file — created exclusively, `0600`, defaulting to
`<name>-kdbx4.kdbx` in the same directory. `--to` names another path.

Then it reads that file back from disk, with the same key, and compares every entry field by field
against the original. Only then does it say it worked. If the copy will not reopen, or anything
differs, the copy is deleted and you are told — a half-converted vault sitting beside a good one is
the worst of both.

It refuses to write over the original, to write over any existing file, and to convert a vault that
is already KDBX 4.

**No second password.** The copy is written with the key the vault was opened with, so it keeps the
original's password and key file exactly. Asking for the same secret twice is how people end up
typing a different one by accident. Use `^p` in the TUI afterwards if you want to change it.

## Afterwards

Open the new file in KeePassXC before you replace the old one. Sennel verifies the copy against
itself, which is not the same as another client agreeing — and the original is still there precisely
so that check costs you nothing.
