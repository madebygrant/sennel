# Finding entries

[Back to the README](../README.md)

## Fuzzy search

`/` searches the whole vault as you type: titles, usernames, urls and group paths. Never notes, so
a note's contents cannot leak into a list of results. Letters can be skipped, so `ghb` finds
GitHub, and the letters that matched light up in each row, so you can see why it is there.

| Key        | In search                                     |
| ---------- | --------------------------------------------- |
| `↑ ↓`      | move through the results while still typing   |
| `enter`    | keep the results and go back to the list      |
| `esc`      | clear the search                              |
| `n N`      | next, previous match                          |
| `^g`       | search only the current group, or widen again |

In the desktop app, `/` or `⌘F` opens the search box, `↑ ↓` pick a result and `enter` copies its
password, so `/`, a few letters and `enter` is the whole trip.

## Tags

A search starting with `#` filters by tag instead. `#wo` lists entries with a tag starting `wo`, so
`#work` finds what is tagged work and not "homework". `#` on its own lists every tag the vault has.
You set tags in the entry form, separated by commas.

## Expiry dates

A KeePass entry can carry an expiry date. Sennel marks expired entries `⧖` in the list, and
[the audit](audit.md) puts them above the merely weak ones, because an expiry is a decision its
owner already made.

## Order

`o` cycles the entries list through four orders: as stored in the file, by name, newest added
first, and most recently changed first. `sort = "name"` in the [config file](configuration.md)
sets the order the list opens in.

## From a script

`sennel get NEEDLE` uses the same matching: an exact title wins outright, otherwise a single fuzzy
match wins, and more than one is an error that lists the candidates. [More](get.md).
