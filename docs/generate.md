# Generating a password

[Back to the README](../README.md)

Two ways in, both drawing from the OS (`getrandom`) and both refusing to produce something the
settings could not honour.

- `P` in the browser opens the generator on its own, with no entry to store the result in.
- `^s` inside the add or edit form writes one straight into the password box.
- `sennel gen` does it without the TUI at all, and is the only subcommand that opens no vault.

## `P`, the standalone generator

```
┌ ♜ generate ─────────────────────────────────┐
│                                             │
│  x7RqW4mHvaZ3ktPuEn2d                       │
│                                             │
│  20 chars  ·  ~117 bits  ·  strong          │
│                                             │
│  u A–Z  d 0–9  s !@#  a l1IO0               │
│  - +  shorter, longer                       │
│                                             │
│  y copy · r again · esc close               │
└─────────────────────────────────────────────┘
```

| Key         | Action                                                      |
| ----------- | ----------------------------------------------------------- |
| `r` `space` | a new one                                                   |
| `y` `enter` | copy it, on the same wipe timer as every other copy         |
| `-` `+`     | one character shorter or longer, between 4 and 256          |
| `u`         | capitals                                                    |
| `d`         | digits                                                      |
| `s`         | punctuation                                                 |
| `a`         | allow `l 1 I O 0`, which are left out by default            |
| `esc` `q`   | close                                                       |

The password is shown plainly, never masked: one you cannot read is one you cannot check against
whatever rule the site has. Every key rolls a fresh password, so the numbers under it always
describe what is on screen. Lower case is always on, which is why it has no key.

The toggles last the session and are never written back — [the config file](configuration.md) stays
the one place the default is set. Nothing here touches the vault, and `^l` or the idle lock takes
the popup with it.

## `sennel gen`

```sh
sennel gen                          # copies it, wipes it after 15s
sennel gen --stdout | pbcopy        # or hand it to something else
pw=$(sennel gen --stdout)
sennel gen -n 32 --symbols --stdout --force
```

| Flag           | What it does                                              |
| -------------- | --------------------------------------------------------- |
| `-n`, `--length` | how many characters (4–256). Defaults to the config     |
| `--symbols` / `--no-symbols` | punctuation in or out; the last one wins    |
| `--no-digits`  | leave digits out                                          |
| `--no-upper`   | leave capitals out                                        |
| `--ambiguous`  | allow `l 1 I O 0`                                         |
| `--count N`    | print N of them (needs `--stdout`)                        |
| `--stdout`     | print it instead of copying it                            |
| `--force`      | allow `--stdout` into a terminal                          |

No vault is opened and no password is asked for, so this works on a machine with no database at
all. The defaults come from the `[generator]` table; the flags override them for one run.

Without `--stdout` the password goes to the clipboard and the process waits out the wipe before
exiting, the same as `sennel get`. With it, stdout is the password and nothing else — everything
the run has to say goes to stderr — and printing into a terminal is refused unless you add
`--force`, because scrollback keeps what the clipboard would not.

## What it makes

Every class you ask for is guaranteed to appear at least once, then the rest is drawn from the
combined pool and the whole thing is shuffled, so the forced characters are not sitting at the
front in class order. Indices are rejection-sampled rather than taken modulo, so no character is
slightly likelier than another.

The bit count is `length × log2(alphabet)`, priced against the pool actually drawn from: excluding
the lookalikes shrinks the alphabet, and quoting the wider one would overstate the secret in the
one direction that matters. Under 40 bits reads as `weak`, 60 `fair`, 80 `good`, above that
`strong`.
