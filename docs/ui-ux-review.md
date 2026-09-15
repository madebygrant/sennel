# Sennel — UI/UX Review

**Date:** 2026-09-15
**Scope:** The interactive TUI (unlock screen, browser, popups, search band, status/header chrome), reviewed from source and from frames rendered off-screen at 80, 90, 100 and 120 columns.
**Focus:** Small design tweaks and updates that make the app feel finished — not new features.

## Overall

Sennel is already an unusually polished TUI. The colour system is designed as a system (contrast ratios, 256-colour quantisation, `NO_COLOR` degradation in `src/theme.rs`), every key that can't act says why, empty states name the way out, and the status bar honestly reports cut/undo/search state. The findings below are nits in that context: five real defects, ten small polish tweaks, and a short list of things worth considering later.

---

## A. Defects (small fixes, real user impact)

### A1. The header says `ready` while the vault is locked

After an idle auto-lock, `check_idle` (`src/app.rs:528-545`) drops the vault and flashes "locked after N seconds idle", but never resets `resting`. `try_unlock` set `resting = "ready"` on the way in (`src/app.rs:643`), so when the flash expires the **lock screen's header reads `Sennel · ready`**.

**Fix:** set `resting = "locked"` in `check_idle`, next to `self.view = View::Unlock`.

### A2. `Enter` on the browser is silent, but the README promises it acts

`handle_browser_key` (`src/main.rs:206-260`) has no `Enter` arm, so it falls through to `_ => {}` — dead silence. README.md:39 promises `enter` = "open group / focus detail". This also violates the project's own stated principle ("a key that goes silent reads as a broken key").

**Fix (pick one):**
- Wire it up: `Enter` on groups opens the group (steps in / expands), `Enter` on entries opens a detail popup (see C1) — making the README true.
- Or change the README and make `Enter` say so ("enter does nothing here yet").

### A3. A kept search filter still shows a text caret

`draw_search` (`src/ui.rs:549-561`) always draws the `█` caret and the hint `enter keep · esc clear`, but it renders whenever `search.is_some()` — including after `Enter` keeps the filter and hands the keys back to the browser (`keep_search` sets `band = false`). The band row then shows **an input caret on a box that doesn't take typing**.

**Fix:** draw the caret only when `app.band`; when the filter is merely kept, draw it as a passive chip, e.g. `/bank · esc clears` in DIM.

### A4. `*` claims to reveal a password that has nowhere to appear

`draw_browser` only draws the detail pane at `width >= PREVIEW_FROM` (100 cols, `src/ui.rs:143`). Below that, `toggle_password` (`src/app.rs:432-437`) still flashes "password shown · * hides it" — a lie on the default 80-column terminal.

**Fix:** refuse with a real message below 100 columns ("no detail pane at this width"), or (better) give the reveal a narrow-width home — see C1.

### A5. `q` and `^c` mean *yes* on delete confirms

`handle_confirm_key` (`src/main.rs:420-424`) treats `y`, `Y`, `q`, `Enter` **and `^c`** as yes — for every confirm, including `delete entry …?`. Two habitual keypresses become destructive:

- `q` means "quit" everywhere else in the app; on a delete confirm it **deletes**.
- `^c` means cancel in almost every terminal app; here it confirms the delete.

The popup only advertises `y` and `esc`, so these are hidden accelerators with a bite.

**Fix:** yes = `y`/`Enter` on all confirms; `q` and `^c` = yes **only** on the quit confirm (where they already mean quit); anything else dismisses. The `qq` flow in the README still works.

---

## B. Small design tweaks

### B1. Unlock labels run into their values

The unlock field row pads labels with `{label:<8}` (`src/ui.rs:465`), but "password" and "key file" are exactly 8 chars, so a filled box renders as `password••••••••` — no gap. The entry form uses `{:<9}` (`src/ui.rs:647`), the group prompt a hand-padded `" name     "` (`src/ui.rs:745`).

**Fix:** use one label width everywhere (10 reads best), e.g. `format!(" {label:<10}")` in unlock, form, and group prompt. One constant, three screens, identical rhythm.

### B2. Truncation is invisible

`truncate` (`src/ui.rs:171-186`) cuts mid-word with no marker. In the rendered frames a group path shows as `Root/Bankin` — indistinguishable from a group actually named "Bankin". Titles, usernames, URLs and notes all truncate the same way.

**Fix:** when anything is cut, end the string with `…` (reserve one column). Applies to the entries pane, groups pane, and the detail pane.

### B3. Message key-case doesn't match the real keys

The keys are uppercase `X`/`V`, but the messages say lowercase: "nothing cut · **x** arms the shelf" (`src/app.rs:1888`), "entry cut · **v** pastes it…" (`src/app.rs:1878-1879`), "cut: … · **v** pastes" (`src/ui.rs:532`). Case is the difference between cut and nothing in this keymap, so the copy should teach it.

**Fix:** say `X` and `V` in all three places (plus the matching test expectations).

### B4. The help overlay and README have both drifted

The overlay (`src/ui.rs:683-729`) omits live keys: `*` (reveal), `n`/`N` (match walk), `g`/`G` (pane ends), `PgUp`/`PgDn` and `^d`/`^u` (paging). Its "fold ← →" row doesn't mention the entries-pane hop, and "undo u one level · ^s generates" implies `^s` works from the browser — it's form-only. The README table is missing `g`/`G` and paging entirely.

**Fix:** add the missing rows to the overlay (it's a vec push), split the undo row's `^s` note into the form hint where it already lives, and add `g`/`G` + paging rows to the README table. The overlay's own rule — "a row naming a key that does nothing is documentation for a bug" — cuts both ways.

### B5. The unlock hint says `enter unlock` in create mode

`ui.rs:499` is static text. When the popup's own title is "new database" and a confirm box is on screen, the hint should say `enter create` (and the file box's Enter means "apply path", which the hint could also name when focus is on it).

**Fix:** two or three hint variants selected on `unlock_new` / focused field.

### B6. `h keys` can be pushed off the status bar

Status spans are appended left-to-right with no budget (`src/ui.rs:504-544`). On an 80-column terminal with cut + undo + search counts live, the line clips — and the first thing to vanish is `h keys`, the one hint that always matters. The flashed errors living in the header can likewise overflow.

**Fix:** right-align `h keys` in whatever width remains (measure the line, pad between), and drop the cut/undo notes before the copy keys when space runs out.

### B7. Every flash is the same colour

Header flashes render CREAM whether they're "unlocked 42 entries" or "save failed · kept in memory" (`draw_header`, `src/ui.rs:114-121`). Errors and confirmations of error look identical to success at a glance.

**Fix:** give `say` a severity (or add `App::warn`/`App::error`), render error flashes RED and warnings AMBER. The palette already has both slots.

### B8. Unsaved state is invisible after the flash expires

Autosave failures set `dirty` and flash once (`persist`, `src/app.rs:1307-1322`); the flash is gone in ≤8s but the quit guard stays armed. A user who misses the flash meets "unsaved changes would be lost" later with no persistent hint of what or why.

**Fix:** a small persistent chip in the status bar while `dirty` (e.g. `unsaved` in AMBER next to the counts).

### B9. The detail pane is 40% of the screen and 80% empty

At 120 cols the detail pane (`src/ui.rs:345-407`) shows 5-6 lines in a 46×30 area. The data to fill it exists: `created`/`updated` timestamps are already read for the sort orders, and a "y copy · * reveal" hint would make the pane self-documenting.

**Fix:** add `updated` (and `created` if it fits) rows under notes, and a dim key hint in the empty space below. Cheap, high perceived-polish.

### B10. No vault identity on screen, and no terminal title

While unlocked, nothing on screen says **which** vault is open — the resting header stage is just "ready" (`src/app.rs:643`). The app's own headline feature is pointing one session at any vault, but after unlocking, vault A and vault B look identical.

**Fix:** make the resting stage the vault filename (`personal.kdbx`), and set the terminal window title to `Sennel — personal.kdbx` on unlock (and back on lock). ratatui's crossterm backend supports `SetTitle`.

---

## C. Worth considering (bigger than a tweak)

1. **A detail view for narrow terminals.** Below 100 columns there is no way to see any entry detail — and 80 columns is the default terminal size. An `Enter`-driven full-width detail popup would fix A2 and A4 in one move and match the README's promise.
2. **A lock-now key.** Locking on demand currently means quitting. `^l` (or `L`) reusing `check_idle`'s wipe path would close the gap; the README's lock story is otherwise passive-only.
3. **Search match highlighting.** `nucleo-matcher` can return match indices; highlighting the matched characters in the entries pane (bold or TEAL) would make fuzzy hits scannable instead of merely sorted.
4. **Mouse wheel scrolling** for the panes — ratatui 0.30 handles mouse events; wheel = step, click = select would round out the pane UX for trackpad users.
5. **A busy state for slow unlocks.** KDBX4/Argon2 unlocks are synchronous in the key handler — the frame freezes for the whole derivation. `theme.rs` already reserves GOLD for "the spinner"; it doesn't exist yet. Even one redraw with an "unlocking…" stage before `try_unlock` would help.
6. **Persist the sort order.** `o` is session-only (noted in `SortOrder`'s comment); a `sort = "name"` config key would stop the surprise after restart.

---

## Priority summary

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| A1 | header says `ready` while locked | 1 line | correctness |
| A5 | `q`/`^c` confirm deletes | few lines | safety |
| A3 | phantom caret on kept filter | few lines | correctness |
| A4 | `*` lies below 100 cols | few lines | correctness |
| A2 | `Enter` dead vs README | small | trust |
| B2 | ellipsis on truncation | small | everyday readability |
| B4 | help overlay / README drift | small | discoverability |
| B1 | label gap on unlock | 1 line | everyday readability |
| B3 | `x`/`v` case in messages | 3 lines | teaches the keymap |
| B7 | flash severity colour | small | glanceability |
| B6 | status bar overflow | small | small screens |
| B8 | unsaved chip | small | trust |
| B9 | detail pane timestamps | small | perceived polish |
| B5 | create-mode hint text | trivial | correctness |
| B10 | vault name + terminal title | small | identity |
| C1 | detail popup on `Enter` | medium | closes A2/A4 properly |
| C2 | lock-now key | small-medium | security habit |
| C3 | match highlighting | medium | search UX |
| C4 | mouse wheel | medium | comfort |
| C5 | unlock busy state | medium | perceived speed |
| C6 | persist sort order | small | continuity |

Everything in A and B is achievable as isolated, testable tweaks in the existing style; nothing here asks the architecture for anything new.
