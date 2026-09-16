# Configuration

[Back to the README](../README.md)

`~/.config/sennel/config.toml`. Every key is optional, and Sennel writes the file `0600`.

```toml
db = "~/vaults/main.kdbx"      # default database · rewritten when you open another
recent = ["~/vaults/main.kdbx", "~/vaults/work.kdbx"]
                               # the vault library behind ^v · written by the app,
                               # newest first, ten at most
clipboard_timeout = 15         # seconds before the clipboard clears (0 = leave it)
lock_timeout = 300             # seconds idle before auto-lock (0 = never)
sort = "name"                  # entries order at startup: stored, name, recent, updated
theme = "warm"                 # warm (default), light, cool, neon · rewritten by ^t
mouse = true                   # wheel scrolls, click selects; false gives the
                               # terminal its own text selection back

[generator]                    # the default for ^s in a form, P on its own,
                               # and sennel gen
length = 20                    # 4–256
upper = true                   # A–Z
digits = true                  # 0–9
symbols = false                # !@#$… · on for sites that demand one
ambiguous = false              # true allows l 1 I O 0, which read alike
                               # P and sennel gen override these per run and
                               # never write back · see docs/generate.md

[colors]                       # see docs/themes.md
cursor = "#00ff88"
```

Sennel rewrites `db`, `recent` and `theme` in place when you open another vault or press `^t`. It
replaces the one key and leaves your comments, ordering and unknown keys alone. A value written
across several lines is replaced whole, so an array you have reformatted by hand survives.

`recent` holds paths and nothing else, but a list of where your vaults live is still worth keeping
to yourself, which is why the file is `0600`. Trim it by hand, or press `^d` on a row in `^v`.
Forgetting the vault named by `db` removes that key too, so the next launch asks rather than
reopening what you just forgot. `--check` prints the library.

Paths are stored absolute, resolved through the folder they are in. `sennel --db vault.kdbx` names
a different file from every other directory, and a library row has to mean the same thing tomorrow.

## Command line

```sh
sennel                     # opens the config's db, or asks for one
sennel --db vault.kdbx     # open a specific vault, created on first unlock
sennel --theme light       # draw in another palette
sennel --lock-timeout 60   # override lock_timeout · --clipboard-timeout does the same
sennel --check             # print what the app sees: config, paths, clipboard backend
sennel --list --db v.kdbx  # group and entry inventory, titles only, no secrets
sennel get <needle> -p     # copy one field and exit · see docs/get.md
sennel import e.csv        # read another manager's export · see docs/import.md
sennel audit               # reused, weak and empty passwords · see docs/audit.md
sennel convert             # rewrite an older KDBX 3.1 vault as KDBX 4 · see docs/kdbx3.md
sennel get x --key-file k  # every subcommand takes --key-file when the vault has one
sennel completions zsh     # completion script · bash, zsh, fish, elvish
sennel man                 # the man page, as roff
sennel --no-config         # ignore the config file and write nothing back
sennel --config path.toml  # read this file instead of the one in ~/.config/sennel
```

A path on the command line is visible to `ps`, which is worth knowing on a shared machine.
`--check`, `--list` and `get` run headless and need no TTY. Without one, `--list` and `get` read the
master password from the first line of stdin.
