# sennel get

[Back to the README](../README.md)

Copy one field of one entry without opening the TUI.

```sh
sennel get github                  # copies the password, wipes it after 15s
sennel get github -u               # the username
sennel get github --otp            # the current one-time code
sennel get github --stdout | pbcopy
```

| Flag       | What it copies                                   |
| ---------- | ------------------------------------------------ |
| `-p`       | the password. The default when nothing is named  |
| `-u`       | the username                                     |
| `--url`    | the url                                          |
| `--otp`    | the current one-time code, never the seed        |
| `--stdout` | print the value instead of copying it            |
| `--force`  | allow `--stdout` into a terminal                 |

Name one field. Two would mean one clipboard silently winning, and no way to tell which.

## Finding the entry

The needle is fuzzy and covers titles, usernames, urls and group paths, the same index the TUI's `/`
uses. There is no list to pick from here, so the rules are ones you can predict:

1. An exact title, ignoring case, wins outright. `mail` finds the entry called `mail` even when
   `mailchimp-api-key` also matches.
2. Otherwise a single fuzzy match wins.
3. Anything else prints the candidates and exits 2. Two entries with the same title stay ambiguous,
   because the score that separates them is not something you can see, so it does not get to pick.

Entries in the recycle bin are never candidates, by any needle, including their exact name.

## The password

From a terminal, `get` prompts. From a pipe it reads the first line of stdin:

```sh
pass sennel-master | sennel get github --stdout
```

## Exit codes

| Code | Meaning                               |
| ---- | ------------------------------------- |
| 0    | copied or printed                     |
| 1    | anything else: bad password, no vault, empty field, two fields named |
| 2    | the needle matched more than one entry |
| 3    | the needle matched nothing             |

2 and 3 are separate so a script retrying with a longer needle knows which happened.

## Two things it will not do

**`--stdout` into a terminal** puts the secret in your scrollback, which is what the TUI exists to
avoid. Refused unless you pass `--force`, and refused before the password prompt, not after.

**Hand over a TOTP seed.** `--otp` gives the six digits the seed produces right now. The seed mints
codes forever, so it stays in the vault.

## Why it waits

A copy is wiped by a timer thread inside the process, so a `get` that exited immediately would
abandon the password on the clipboard. It stays alive for the timeout, says how long, and wipes
before returning. Under `clipboard_timeout = 0` there is nothing to wait for, and it exits at
once.
