# Theme selection — wave plan

**Date:** 2026-09-16
**Branch:** `feat/theme-selection`, planned against `44d1f47`. Line numbers are hints; re-check
before acting.
**Scope:** keep the current warm theme, add light, cool and a cyberpunk/hacker dark one; built-in
palettes, live switching, and user-defined colours.

**Already in place, so no wave spends effort on it:** 256-colour quantisation and the `NO_COLOR` →
`Color::Reset` collapse (`theme.rs:144-180`) work on any palette and need no change; the diagonal
gradient painter (`theme.rs:54`) already takes its stops from constants; config write-back exists
(`config.rs remember_db`), so "remember the theme I picked" is a caller away; the flash machinery can
name a switch.

**Flagged as the planner's, not the requester's:** "cool" may be an echo of the word used when
offering options rather than a fourth theme that was asked for. Four palettes are planned (warm,
light, cool, neon); cutting `cool` from Wave 3 changes nothing else.

---

## Wave 1 — Palette as data, with names that survive a light theme

**Why here:** everything else needs a palette *value* to exist. Today the colours are nine
`pub const`s read directly by 83 sites in `ui.rs`, so no selection of any kind is possible without
this. The names are the reason it has to be this wave and not later: `CREAM` and `GOLD` describe a
warm dark theme's pigments, not roles. On a light theme `CREAM` would be near-black ink — a name that
lies at every one of those 83 sites. Renaming while the plumbing already touches them costs nothing;
doing it later means editing them twice.

- Introduce `struct Palette` holding the nine slots plus the gradient stops (`NEAR`, `FAR`, `STOP`,
  `theme.rs:36-39`) and the popup `SURFACE` tone (`theme.rs:52`). `Copy`, so it travels by value.
- Rename the slots to roles as they move: `CREAM→text`, `GOLD→accent`, `TEAL→cursor`, `AMBER→warn`,
  `RED→error`, `DIM→muted`, `RULE→rule`, `SURFACE→surface`, `SAND→masked`, `INK→ink`.
- **The decision this wave exists to make:** where the palette lives. Recommendation is on `App`
  (`app.theme`), read by `ui.rs` as `app.theme.text`, with the ~10 free helpers that have no `app`
  (`dim()`, `teal()`, `mark()`, `row_style()`, `highlight()`, `popup()`, `draw_rule()`) becoming
  methods on `Palette` or taking one. A global `RwLock<Palette>` would be a smaller diff and keep the
  `theme::` API, but tests run in parallel and a mutable global makes per-theme assertions race each
  other — `depth()` gets away with `OnceLock` (`theme.rs:112`) only because it never changes after
  startup, which is exactly what a switchable theme is not.
- `warm` is the only built-in, byte-identical to today's values.

**Exit:** `cargo test` and `clippy -D warnings` pass untouched, and a rendered frame is identical to
`main`'s — this wave must be invisible.
**Risk:** large mechanical diff (83 sites). Low individually, but it is where a wrong-slot typo
hides, which is what Wave 2 exists to catch.

## Wave 2 — Guardrails: contrast and a frame that cannot drift

**Why here:** before three new palettes land, not after. `theme.rs:5-9` already claims *"every colour
clears 4.5:1 over the lightest corner of the gradient except RULE"* — a claim currently enforced by
nobody. A light theme inverts which corner is lightest, so the first palette to break it breaks it
silently, and by then there are three candidates to bisect.

- A WCAG contrast helper, and a test asserting every slot of every built-in clears 4.5:1 against
  **both** gradient extremes, with `rule` and `masked` as named exemptions rather than silent ones.
- The same palette quantised to 256 colours (`quantise`, `theme.rs:144`) still clears 3:1 — the cube
  is coarse and the light themes sit nearest the greys.
- A `NO_COLOR` test per palette: every slot collapses to `Reset`, so no theme smuggles colour past it.
- One frame test per palette asserting the symbols are identical across themes — a theme may change
  colour, never layout.

**Exit:** the contrast test fails when a slot's luminance is nudged the wrong way (verified by
nudging one, the way the zeroize tests were checked).
**Risk:** none to the product; this wave ships no user-visible change.

## Wave 3 — The palettes

**Why here:** the enablement is done, so each palette is a data change that a test grades. Cheapest
first: `cool` is a hue rotation of the existing structure, `neon` needs new gradient stops, `light`
needs the most thought because it inverts the ground.

- **`cool`** — slate and steel: desaturated blue-greys, colder cyan cursor, same structural logic as
  warm. *(Cut if it was the planner's word.)*
- **`neon`** — the cyberpunk/hacker one: near-black ground with a deep indigo-to-black gradient,
  magenta accent, cyan cursor, acid yellow warn, hot pink error. The risk is legibility, and it fails
  first on `muted`, which is what usernames and hints draw in.
- **`light`** — ink on parchment. The inversion the whole plan is priced around: gradient stops become
  light, `surface` must be *darker* than the page or popups read as holes (`theme.rs:49-52` assumes
  the opposite), and `rule`/`muted` darken rather than lighten. Check the bold-on-selected row
  (`row_style`), which reads heavier on a light ground.

**Exit:** all four palettes pass Wave 2's contrast, quantise and `NO_COLOR` tests, and frames rendered
in each are symbol-identical.
**Risk flag:** `light` wants eyeballing in a real terminal — contrast maths says legible, not
comfortable.

## Wave 4 — Choosing one

**Why here:** a palette nobody can select is dead code, but selection is only meaningful once there
is more than one. Config before live switching, because the flag and the key resolve through the same
lookup and a misspelt name should fail the same way in both.

- `theme = "warm"` in `config.toml` and a `--theme` flag through the existing precedence
  (`config.rs Config::build`: flag beats file beats default), with an unknown name stopping startup
  and naming the valid ones — the pattern `sort` and the generator already use.
- `--check` reports the active theme beside `sort`, `generate` and `mouse`.

**Exit:** `sennel --theme neon` starts neon; `--theme nope` exits naming the four; `--check` says
which is live.

## Wave 5 — Switching it live, and keeping the choice

**Why here:** needs Wave 4's lookup and the built-ins, and it is the first wave to change the keymap,
so it lands after the parts that cannot break a key.

- `^t` cycles the palettes, the flash naming each (`^t` is free; `t` is the one-time code).
- Remember the choice the way an opened vault is remembered (`config.rs remember_db`,
  `app.rs remember_vault`): write `theme` back, say so out loud, honour `--no-config` by not writing.
- Help overlay row and README key-table row.

**Exit:** cycle to `light`, quit, relaunch, still `light`; under `--no-config` the cycle works and
writes nothing.
**Risk flag:** a second config write-back path. The rule that the tool announces what it edits in
your dotfiles holds here too.

## Wave 6 — Colours of your own, and the reference

**Why here:** last of the functional waves because it generates work — every override is a new way to
produce an unreadable screen — and it needs Wave 2's contrast helper to warn rather than silently
allow. Docs sit here because this is the wave that fixes the vocabulary users write against.

- `[theme.colors]` overrides keyed by the Wave 1 role names, taking `#rrggbb`, applied on top of a
  named base so an override is a diff rather than a whole palette.
- Bad hex stops startup with the offending key named. An override failing 4.5:1 warns at startup and
  renders anyway — it is the user's screen, and a warning that blocks is one people work around.
- Decide whether overrides may reach the two gradient stops, which is where a light/dark mismatch is
  easiest to create by accident.
- README `[theme]` section naming each role and what it paints, plus a line in the security notes
  that themes never affect what is masked.

**Exit:** a config overriding two roles on top of `neon` starts, renders, and warns about the one that
fails contrast.

---

## Why this order

One decision drives the sequence: whether the palette is a global or an `App` field (Wave 1).
Everything downstream — live switching, per-theme tests, parallel test safety — is easy on one side
of that choice and awkward on the other, so it goes first and alone. Then guardrails before palettes,
because the contrast claim in `theme.rs` is exactly the kind of invariant three new colour sets break
quietly. Palettes before selection, because selecting between one thing is not a feature. Config
before the key, since both resolve the same name. User-defined colours last, because they are the only
part that can produce an unreadable screen and they should lean on a checker that already exists.

## What can slip

Waves 1–3 are the deliverable: they are what "a light theme and a cyberpunk one" actually means, and
Wave 4 is the thinnest way to reach them. Wave 5 is convenience — it is how anyone will actually *try*
four palettes, but a config key plus a restart gets the same result. Wave 6 is genuinely optional and
the most likely to generate support questions, so if the plan is cut, cut there. Wave 2 is the one
that looks skippable and is not: drop it and the light theme's legibility becomes an opinion rather
than a check.
