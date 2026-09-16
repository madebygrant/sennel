# Configuration

[Back to the README](../README.md)

`~/.config/sennel/config.toml`. Every key is optional, and Sennel writes the file `0600`.

```toml
db = "~/vaults/main.kdbx"      # default database · rewritten when you open another
clipboard_timeout = 15         # seconds before the clipboard clears (0 = leave it)
lock_timeout = 300             # seconds idle before auto-lock (0 = never)
sort = "name"                  # entries order at startup: stored, name, recent, updated
theme = "warm"                 # warm (default), light, cool, neon · rewritten by ^t
mouse = true                   # wheel scrolls, click selects; false gives the
                               # terminal its own text selection back

[generator]                    # what ^s makes in the entry form
length = 20                    # 4–256
upper = true                   # A–Z
digits = true                  # 0–9
symbols = false                # !@#$… · on for sites that demand one
ambiguous = false              # true allows l 1 I O 0, which read alike

[colors]                       # see docs/themes.md
cursor = "#00ff88"
```

Sennel rewrites `db` and `theme` in place when you open another vault or press `^t`. It edits the
one line and leaves your comments, ordering and unknown keys alone.

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
sennel completions zsh     # completion script · bash, zsh, fish, elvish
sennel man                 # the man page, as roff
sennel --no-config         # ignore the config file and write nothing back
sennel --config path.toml  # read this file instead of the one in ~/.config/sennel
```

A path on the command line is visible to `ps`, which is worth knowing on a shared machine.
`--check`, `--list` and `get` run headless and need no TTY. Without one, `--list` and `get` read the
master password from the first line of stdin.
