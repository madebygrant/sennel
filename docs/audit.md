# Auditing a vault

[Back to the README](../README.md)

`!` in the TUI, or `sennel audit` for the same findings printed.

```sh
sennel audit --db vault.kdbx           # offline, instant
sennel audit --pwned --db vault.kdbx   # also check for known breaches
```

## What it looks for

**Reused.** The same password on more than one entry. This is the finding nobody can spot for
themselves, and the one that costs more than one account when it bites.

**Expired.** Past the date on the entry. Not a weakness in the password, which may be a fine one,
but a credential whose owner already decided it had a shelf life — which is why it sits above weak,
where the audit is only an estimate disagreeing with them.

**Weak.** Under 60 bits by the same estimate the entry form draws in amber while you type. The same
line, not a second opinion.

**Empty.** No password at all.

Findings are worst-first and stable between runs, so the list works as a to-do list. Entries in the
recycle bin are skipped: telling somebody to go fix an entry they deleted is how an audit loses
their trust. Passwords are compared by hash inside the process; nothing is printed but the finding.

In the TUI, `enter` on a finding puts the cursor on that entry, in the group holding it, so the fix
is two keys from the finding.

## `--pwned`

Asks [Have I Been Pwned](https://haveibeenpwned.com/Passwords) whether each password appears in a
known breach, using their k-anonymity range API.

**Your password never leaves the machine.** Sennel takes its SHA-1, sends the first five hex
characters, and gets back every suffix the service knows beginning with those five — around 800 of
them. The match happens locally. The service learns that somebody asked about one of roughly half a
million hashes, and nothing else.

One request per prefix, not per entry, so a vault where six entries share a password asks once.

Two implementation choices worth knowing, because both are unusual:

- **SHA-1 is written into Sennel** rather than pulled from a crate. It is fixed, short, used for
  exactly one thing, and a hash of your passwords is not somewhere to inherit a dependency's
  release schedule. It is not doing security work here — HIBP chose the algorithm, and a prefix
  lookup does not care that SHA-1 is broken.
- **The request goes through `curl`.** A TLS stack and an HTTP parser are a lot of code to add to a
  password manager for one optional GET. This way the exact command is something you can read, run
  yourself and see in `ps`. If curl is not installed, `--pwned` says so and nothing else changes.

This is the only feature in Sennel that touches the network, it is opt-in per run, and it is never
reachable from a keystroke inside the TUI.
