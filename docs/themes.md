# Themes

[Back to the README](../README.md)

Four palettes ship. `^t` walks them with the screen in front of you, which is how anyone picks a
theme, and writes the one you stop on back to the config. `theme` in the config and `--theme` on the
command line name one directly.

| Theme   | For                                                                     |
| ------- | ----------------------------------------------------------------------- |
| `warm`  | the default. Cream and gold on a warm near-black gradient               |
| `light` | terminals with a light background, where the other three are unreadable |
| `cool`  | slate and steel. Warm's structure with the warmth taken out             |
| `neon`  | magenta and cyan over violet-to-black                                   |

## Repainting one colour

Any slot can be repainted on top of whichever theme is named, so changing one colour does not mean
restating eight.

```toml
theme = "neon"

[colors]
cursor = "#00ff88"             # text · accent · cursor · warn · error · muted · rule · surface
```

`text` is titles and anything the eye lands on first. `accent` is chrome: borders, bars and key
names. `cursor` marks where you are. `warn` and `error` carry the flashes. `muted` is usernames, urls
and hints. `rule` is the lines between panes. `surface` is the flat tone popups are raised with.

A value that is not `#rrggbb`, or a slot nobody draws in, stops startup and names what it should
have been. A colour that merely measures badly starts anyway and says so once, because it is your
screen.

`^t` walks the base palette only. The `[colors]` table stays in the file and goes on repainting
whatever `^t` lands on, which is why the flash says so while a table is there.

## Measured, not eyeballed

Every readable colour clears WCAG 4.5:1 against both ends of its own gradient and against the tone
popups are raised with, and still clears 3:1 after a 256-colour terminal has quantised it. The tests
run those numbers on every palette, so a theme cannot ship unmeasured. Two of the three new palettes
failed on the first attempt and went back for another shade.

Under `NO_COLOR` every colour collapses to the terminal's own and the app stays usable: the pane
marker (`▌` against `│`) and the `!` and `×` flash glyphs carry what colour was saying.

A theme changes colour, never layout. The tests assert the frame is identical cell for cell across
all four.
