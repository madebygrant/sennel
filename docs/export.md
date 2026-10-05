# Exporting

[Back to the README](../README.md)

```sh
sennel export --out vault.csv --db vault.kdbx             # a file, owner-only
sennel export --format json --stdout --db vault.kdbx      # to a pipe
sennel export --out banks.csv --group Banks/Savings       # one group and what is under it
```

The way out, for when you are moving to another manager or want a copy that does not need Sennel.
**The file holds every password in the clear.** Delete it when you are done, and do not leave it in
a folder that syncs.

## Where it goes

`--out FILE` creates the file owner-only (`0600`) and refuses to write over one that exists.
`--stdout` prints instead, and refuses a terminal unless you add `--force`, because scrollback is
where a password should not be. One of the two is required, and both refusals come before the
password prompt.

## Formats

**CSV** has the columns `Group,Title,Username,Password,URL,Notes,TOTP`, quoted only where it has to
be. It is what [`sennel import`](import.md) reads, and what other managers' importers expect. The
group is a `/` path with the vault's own root name left off, so `Banks/Savings`, and an entry at the
top has an empty group. `TOTP` is the full `otpauth://` URL, seed included.

**JSON** is an object with `format`, `version` and an `entries` array. Each entry has the same
fields plus `tags`, `expires` (UTC, or `null`), `fields` (your custom fields as name and value) and
`files` (attachment names). Nothing reads it back yet. It is there for scripts and for the fields
CSV has no column for.

## What is left out

Entries in the recycle bin. Custom fields in CSV, and attachment contents in both: a file is named
in JSON and counted on stderr, never written out. Sennel tells you how many it left out each time.
History is not exported.

CSV is opened by spreadsheets, and a spreadsheet treats a cell that starts with `=`, `+`, `-` or `@`
as a formula. The file is not altered to prevent that, because it would no longer be your password.
Do not open it in one.
