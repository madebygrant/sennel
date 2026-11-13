# Sennel's patches to keepass 0.14.0

This is keepass 0.14.0 from crates.io (upstream commit `5fb4f30bbe1403b0bc4218d91dab3bc90216615d`),
used through `[patch.crates-io]` in the root `Cargo.toml` and in `fuzz/Cargo.toml`. Every change is
marked `SENNEL PATCH` in the source. `.cargo_vcs_info.json`, `Cargo.toml.orig`, `Cargo.lock` and
`.cargo-ok` from the published package were left out.

## Attachment references are written by position

`src/format/xml_db/entry.rs`, `Entry::db_to_xml`, with the positions computed once in
`src/format/xml_db/mod.rs`, `KeePassFile::db_to_xml`, and passed down through
`src/format/xml_db/group.rs`, `Group::db_to_xml`.

The binary pool is written densely in id order (`src/format/xml_db/mod.rs`, `to_xml`), and a load
gives pool item `i` the id `i`. Each entry's reference was written as the attachment's id. Once an
attachment below the highest id was removed, every later reference pointed at its neighbour's bytes
in the saved file, and the last one at nothing. References are now the attachment's position in the
pool, and a reference to an attachment no longer in the pool is not written.

## Attachment back-references are rebuilt on load

`src/format/xml_db/mod.rs`, `KeePassFile::xml_to_db`.

The parser left every `Attachment.entries` set empty, the same way it once did for custom icons.
`remove_attachment_by_name` drops a blob when that set is empty, so removing one entry's name for a
blob dropped it while other entries, or history versions, still pointed at it. The sets are now
filled in the same pass that fills the custom icons' sets.

## Removing an attachment touches only that version's reference

`src/db/types/entry.rs`, `EntryMut::remove_attachment_by_name` and `remove_attachment_by_id`.

Both cleared every reference with the entry's id, including the ones its own history versions hold.
They now clear only the reference of the version they were called on.

`remove_attachment_by_name` also keeps the reference while another name in the same version still
points at the blob. KeePassXC stores identical files once, so two names for one blob are normal, and
removing one used to drop the bytes the other still needed.

## Three helpers for putting a whole entry back

`src/db/types/entry.rs`, `EntryMut::restore_keeping_attachments` and
`EntryMut::forget_attachments`, and `src/db/types/mod.rs`, `Database::collect_attachments`. All three
are new public methods.

Sennel's undo puts back a cloned `Entry`. Its attachment ids can name a blob that has since been
removed, or one whose id was handed to another entry's file.

- `restore_keeping_attachments` puts the clone in place but keeps the entry's current names and ids,
  for an undo step that did not change the entry's files.
- `forget_attachments` empties an entry's names without touching any blob, for a step that did.
  Sennel then adds the files back from bytes it kept with the step.
- `collect_attachments` rebuilds every back-reference from the entries, drops references to blobs
  that are gone and removes blobs nothing uses. Sennel also calls it after clearing an entry's
  history, so a file only the old versions used does not stay in the vault.

## Reading a header's key derivation without running it

`src/db/open.rs`, `Database::kdf_config_of`, with a `kdf_config_of` beside each format's parser in
`src/format/kdb.rs`, `src/format/kdbx3.rs` and `src/format/kdbx4/parse.rs`.

The crate runs the key derivation a header asks for before it checks the header's HMAC, so anyone
who can write the file chooses how much work and memory an unlock takes. This returns the settings
from the crate's own header parser without deriving anything, and Sennel refuses unreasonable ones
first (`crates/sennel-core/src/kdfcap.rs`). Using the crate's parser, not a second one, means the
settings checked are the ones that would run.

## Unprotected values are wiped on drop

`src/db/types/value.rs`, `impl Drop for Value`.

`Value::Protected` wipes itself through `SecretBox`, but `Value::Unprotected` was freed as it was.
Titles, usernames, URLs, and notes written by programs that store them unprotected stayed in freed
memory after a lock. The unprotected variant is now zeroized when the value drops. The impl means
code can no longer move the contents out of a `Value` by pattern; nothing in the crate or in Sennel
did.

## The KDBX 3 and 4 parsers wipe their keys and the decrypted payload

`src/format/kdbx4/parse.rs`, `decrypt_kdbx4`, and `src/format/kdbx3.rs`, `decrypt_kdbx3`, which now
return the XML as `Zeroizing<Vec<u8>>`, and `src/db/open.rs`, `Database::get_xml`, which moves it
out. The inner stream key is `Zeroizing` in both formats' headers (`src/format/kdbx4/mod.rs`,
`KDBX4InnerHeader`, and `src/format/kdbx3.rs`, `KDBX3Header`), including the one `dump.rs` makes for
a save. `Cargo.toml` turns on `hybrid-array`'s `zeroize` feature so the key arrays can be wrapped.

The key elements, the composite, transformed and master keys, the HMAC keys (KDBX 4), the decrypted
and decompressed payload, and the XML are wrapped in `Zeroizing`. KDBX 3's block buffer is sized to
the payload up front instead of growing. Buffers inside the cipher and the decompressor are not
reachable from here.

## The `aes` range is narrowed

`Cargo.toml`, `[dependencies.aes]`: `"<0.9.3"` became `">=0.9, <0.9.3"`. As a path dependency the
crate is resolved afresh, and Cargo satisfied `<0.9.3` with the `aes 0.8` the rest of the tree uses.
keepass 0.14 does not build against 0.8.

## Known and not fixed

- KDBX 3 files: `xml_to_db` gives each XML `Binary` an id from `AttachmentId::next_free(&db)` while
  `db.attachments` is still empty, so every one gets id 0. Sennel opens KDBX 3 read-only.
- An attachment referenced only by history versions is not removed with its entry, because
  `EntryMut::remove` walks the current version's attachments only. It stays in the pool and is
  written with every save.

## Upgrading keepass

Check each section above against the new release. Drop a patch the release fixes, carry the rest,
then rerun the attachment and merge tests in `crates/sennel-core/src/vault.rs`.
