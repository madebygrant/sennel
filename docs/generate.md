# Generating a password

[Back to the README](../README.md)

Three ways in, all drawing from the OS (`getrandom`), all refusing to produce something the settings
could not honour. Three shapes: `complex` (characters from classes, the default), `passphrase`
(words off an embedded list) and `pin` (digits, for the screens that take nothing else).

- `P` in the browser opens the generator on its own, with no entry to store the result in.
  `t` walks the three kinds.

- `^s` inside the add or edit form writes one straight into the password box.
  `^y` copies the password box, on the same wipe timer as every other copy, so it can go into
  the site first.
- `sennel gen` does it without the TUI at all, and opens no vault to do it.

## `P`, the standalone generator

```
┌ ♜ generate ─────────────────────────────────┐
│                                             │
│  x7RqW4mHvaZ3ktPuEn2d                       │
│                                             │
│  20 chars  ·  ~117 bits  ·  strong          │
│                                             │
│  t complex  u A–Z  d 0–9  s !@#  a l1IO0    │
│  - +  shorter, longer                       │
│                                             │
│  y copy · r again · t kind · esc close      │
└─────────────────────────────────────────────┘
```

| Key         | Action                                                      |
| ----------- | ----------------------------------------------------------- |
| `r` `space` | a new one                                                   |
| `y` `enter` | copy it, on the same wipe timer as every other copy         |
| `t`         | complex, passphrase, pin, and back round — rolls at each stop |
| `-` `+`     | one character shorter or longer, between 4 and 256 (words, for a passphrase, between 1 and 64) |
| `u`         | capitals (complex only)                                     |
| `d`         | digits (complex only)                                       |
| `s`         | punctuation (complex only)                                  |
| `a`         | allow `l 1 I O 0`, which are left out by default (complex only) |
| `esc` `q`   | close                                                       |

The password is shown plainly, never masked. One you cannot read is one you cannot check against
whatever rule the site has this week. Every key rolls a fresh password, so the numbers under it
always describe what is on screen. Lower case is always on, which is why it has no key.

The toggles last the session and are never written back, so [the config file](configuration.md)
stays the one place the default is set. Nothing here touches the vault, and `^l` or the idle lock
takes the popup with it.

## `sennel gen`

```sh
sennel gen                          # copies it, wipes it after 30s
sennel gen --stdout | pbcopy        # or hand it to something else
pw=$(sennel gen --stdout)
sennel gen -n 32 --symbols --stdout --force
sennel gen --kind passphrase --words 6 --stdout --force
sennel gen --kind pin -n 6 --stdout --force
```

| Flag           | What it does                                              |
| -------------- | --------------------------------------------------------- |
| `--kind`       | complex, passphrase or pin. Defaults to the config        |
| `-n`, `--length` | how many characters (4–256), or digits for a pin (4–12). Defaults to the config |
| `--words`      | how many words, for a passphrase (1–64)                   |
| `--symbols` / `--no-symbols` | punctuation in or out; the last one wins    |
| `--no-digits`  | leave digits out                                          |
| `--no-upper`   | leave capitals out                                        |
| `--ambiguous`  | allow `l 1 I O 0`                                         |
| `--count N`    | print N of them (needs `--stdout`)                        |
| `--stdout`     | print it instead of copying it                            |
| `--force`      | allow `--stdout` into a terminal                          |

No vault is opened and no password is asked for, so this works on a machine with no database at all.
The defaults come from the `[generator]` table, and the flags override them for one run.

Without `--stdout` the password goes to the clipboard and the process waits out the wipe before
exiting, the same as `sennel get`. With it, stdout is the password and nothing else. Everything the
run has to say goes to stderr instead, and printing into a terminal is refused unless you add
`--force`, because scrollback keeps what the clipboard would not.

## What it makes

Every class you ask for appears at least once. The rest is drawn from the combined pool, then the
whole thing is shuffled so the forced characters are not sitting at the front in class order.
Indices are rejection-sampled rather than taken modulo, so no character is likelier than another.

A passphrase is words off an embedded list (the EFF large wordlist, minus four hyphenated entries
that would read as separators), joined with dashes: six words hold ~78 bits and read as words, not
noise. A PIN is digits only — six hold ~20 bits, which is fine for a screen that locks after three
tries and nothing more.

The bit count is `length × log2(alphabet)`, priced against the pool actually drawn from. Excluding
the lookalikes shrinks the alphabet, and quoting the wider one would overstate the secret in the one
direction that matters. Under 40 bits reads as `weak`, 60 `fair`, 80 `good`, above that `strong`.
