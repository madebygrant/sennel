# Auditing a vault

[Back to the README](../README.md)

`!` in the TUI, or `sennel audit` for the same findings printed.

```sh
sennel audit --db vault.kdbx           # offline, instant
sennel audit --pwned --db vault.kdbx   # also check for known breaches
```

## What it looks for

**Reused.** The same password on more than one entry. Nobody can spot this one for themselves, and
it costs more than one account when it bites.

**Expired.** Past the date on the entry. The password may be a fine one. This is a credential whose
owner already decided it had a shelf life, which is why it sits above weak, where the audit is only
an estimate disagreeing with them.

**Weak.** Under 60 bits by the same estimate the entry form draws in amber while you type. The same
line, not a second opinion.

**Empty.** No password at all.

Findings are worst-first and stable between runs, so the list works as a to-do list. Entries in the
recycle bin are skipped, because telling somebody to go fix an entry they deleted is how an audit
loses their trust. Passwords are compared inside the process, and nothing is printed but the
finding.

In the TUI, `enter` on a finding puts the cursor on that entry, so the fix is two keys away.

## `--pwned`

Asks [Have I Been Pwned](https://haveibeenpwned.com/Passwords) whether each password appears in a
known breach, using their k-anonymity range API.

**Your password never leaves the machine.** Sennel takes its SHA-1 and sends the first five hex
characters. Back come every suffix the service knows beginning with those five, around 800 of them,
and the match happens here. The service learns that somebody asked about one of roughly half a
million hashes, and nothing else.

One request per prefix, not per entry, so a vault where six entries share a password asks once.

Two implementation choices worth knowing, because both are unusual:

- **SHA-1 is written into Sennel** rather than pulled from a crate. It is fixed, short, used for
  exactly one thing, and a hash of your passwords is not somewhere to inherit a dependency's release
  schedule. It is doing no security work here. HIBP chose the algorithm, and a prefix lookup does
  not care that SHA-1 is broken.
- **The request goes through `curl`.** A TLS stack and an HTTP parser are a lot of code to add to a
  password manager for one optional GET. This way the exact command is something you can read, run
  yourself and see in `ps`. If curl is missing, `--pwned` says so and nothing else changes.

This is the only feature that touches the network. It is opt-in per run, and never reachable from a
keystroke inside the TUI.
