# Importing from another password manager

[Back to the README](../README.md)

```sh
sennel import export.csv --dry-run --db vault.kdbx   # see what would land
sennel import export.csv --db vault.kdbx             # do it
```

Takes the CSV that KeePassXC, Bitwarden and 1Password export. One reader rather than three: they
all write a header row and different names for the same six things, so the columns are matched by
name. A tool nobody here has heard of works too if it names its columns like everyone else.

| Sennel field | Header names it answers to                            |
| ------------ | ----------------------------------------------------- |
| group        | `group`, `folder`, `grouping`, `category`             |
| title        | `title`, `name`, `account`, `item name`               |
| username     | `username`, `login_username`, `user`, `login name`, `email` |
| password     | `password`, `login_password`                          |
| url          | `url`, `login_uri`, `website`, `login url`            |
| notes        | `notes`, `note`, `comments`                           |
| one-time seed| `totp`, `login_totp`, `otpauth`, `otp`                |

Case, spaces, underscores and hyphens are all ignored when matching, so `Login Name` and
`login_name` are the same column. Columns nothing is done with are named on stderr rather than
dropped in silence. A file with no title column is refused, and the message lists the header it
found instead.

## Where it lands

Everything goes under one new group, `Imported <date>` unless `--group` names another. The file's
own group column becomes a subgroup of that.

One group, rather than merging into the tree the file describes, because an import is the operation
most likely to be regretted, and one group is one thing to delete when it is.

## Two things worth knowing

**`--dry-run` needs no password.** It reads the CSV and prints what would land. Nothing should have
to unlock a vault to tell you what is in somebody else's file.

**A seed that will not parse costs its own entry a code and nothing else.** The entry still lands,
and the line names it. Failing a whole import over one bad column would strand you mid-migration.

**Afterwards, delete the export.** It is a plaintext file holding every password you own, and
`import` says so on the way out.

## KDBX 3.1

Sennel reads older KDBX files but writes KDBX 4 only, so importing into a 3.1 vault is refused
before anything is read. Open it in KeePassXC and save a copy as KDBX 4 first. The TUI says the same
thing at unlock rather than at the first failed save.
