# Sennel — UI/UX Review, second pass

**Date:** 2026-09-16
**Scope:** The whole interactive surface — unlock, browser, detail pane and popup, search band, entry
form, group prompt, confirms, keys overlay, status chrome — plus the key routing behind them and the
save path underneath.
**Method:** Source read end to end, frames rendered off-screen at 24×8, 46×18, 80×14, 80×24, 100×24
and 120×30, and the key handler probed directly for the paths a frame cannot show.
**Focus:** Everything, from a one-line fix to a feature worth arguing about.

## Overall

The first review's findings are fixed and the app is better for them. What follows is a fresh pass
with no regard for that one: it goes wider (routing, the save path, non-colour terminals, short
terminals) and it found more, including one thing that can lose a user's data and several keys that
do the opposite of what the screen says. The good news is that almost all of it is small.

The strongest thing about Sennel is its stated principle — *a key that goes silent reads as a broken
key* — and the most productive way to review it is to hold it to that principle everywhere. Section A
is mostly places where the app breaks its own rule.

---

## A. Defects

### A1. An autosave can silently overwrite another program's changes

`Vault::save` (`src/vault.rs:192`) writes through `write_file` (`src/vault.rs:221`) with no idea
whether the file on disk is still the one that was opened. Sennel autosaves after *every* mutation.
So: open the vault in Sennel, edit an entry in KeePassXC (or let a sync client pull a newer copy, or
run a second Sennel), then change anything here — and the other program's work is gone, atomically
and without a word. The README sells KeePassXC compatibility, which makes this a normal Tuesday, not
an edge case.

**Fix:** record `(mtime, len)` at open and after each successful save; re-stat immediately before
writing. On a mismatch, refuse the write, set `dirty`, and say so in RED — "vault changed on disk ·
your changes are unsaved · `^s` overwrites, `r` reloads". This is the one finding in this document
that can destroy something the user cannot get back.

### A2. `q` with the keys overlay open quits the app — or types into the master password

`handle_key` (`src/main.rs:193`) dismisses the overlay on any key *except* `q`, which falls through
to the screen behind it. Probed:

- On the browser: `q` quits. The overlay is still on screen as the app exits.
- On the lock screen: `q` is typed into the password box, **the overlay stays open**, and the
  character lands in the field nobody can see behind the popup.

The second one is a keystroke silently added to a master password. Whatever the intent (the overlay
lists `quit q ^c`), a help popup that eats a key into the password box is the wrong outcome.

**Fix:** `q`, `esc`, `h` and `?` close the overlay and nothing else. Quitting is then one more press —
which is right, because quitting should not be something a help screen does for you.

### A3. The lock screen advertises `h keys`, where `h` is a letter

The status bar prints `h keys` on every screen (`draw_status`, `src/ui.rs`), but `handle_unlock_key`
treats every printable key as text — deliberately, and correctly. The repo's own test
`plain_keys_type_on_the_lock_screen` asserts it. So the one hint the bar promises always works is, on
the first screen a user ever sees, a hint for a key that types `h` into their password.

**Fix:** bind the overlay to `F1` on the unlock screen (no password contains F1) and make the bar
name the keys that are actually live there: `enter unlock · ^r reveal · F1 keys · ^c quit`.

### A4. The delete confirm cuts off the sentence that carries the warning

`popup` sizes to the longest line and clamps to the terminal (`src/ui.rs:736`), and the question is
one long line (`src/ui.rs:771`). At 80 columns with a real-world title:

```
│ delete entry “Commonwealth Bank — personal everyday account”?  this cannot be│
```

The words "undone" never render. The one sentence whose job is to slow the user down is the one the
layout amputates — and there is no `…` to say it happened.

**Fix:** truncate the *title* to the room available, never the sentence; or wrap the question over
two lines. The verb must always be on screen.

### A5. …and that sentence is not true for entries

`confirm_delete_entry` (`src/app.rs`) stores `Undo::Delete { id, parent, before }` and `undo_last`
restores the entry wholesale. Deleting an entry is *undoable*, but the popup says "this cannot be
undone", so the app frightens the user and hides its own safety net in the same breath. (For groups
it is accurate — there is no `Undo` variant for them.)

**Fix:** entries: "y delete · esc keep · `u` restores it afterwards". Groups: keep the current
wording, it is honest. And the post-delete flash should say `u` restores it too.

### A6. The keys overlay silently loses rows on a short terminal

At 80×14 the overlay renders 12 of its 17 rows; `find`, `match`, `undo`, `lock` and `quit` are simply
absent, and the popup's bottom border sits on top of the status bar. `Paragraph` drops what does not
fit and says nothing. A help screen that hides half the keys — with no scrollbar, no "more", no
marker — is worse than a short help screen.

**Fix:** when the rows do not fit, drop to two columns (this table fits 80×10 in two columns), and
failing that page it with `j/k` and a `1/2` marker. Same rule for the detail popup, whose notes block
can outgrow a short window.

### A7. Entry rows run past the edge of their pane

`draw_entries` truncates the *title* to the pane width (`src/ui.rs:295`) and then appends the username
and, while searching, the group path. The total is never measured, so ratatui hard-clips it:

```
▌ Commonwealth Bank — personal everyday account  gra
```

`gra` is a username cut with no marker — precisely the defect the first review fixed for titles, one
span to the right. It also runs under the scrollbar (A14 below).

**Fix:** budget the row: reserve the username column (and the group column while searching), give the
title the remainder, and truncate each span to its own width.

### A8. Multi-line notes are mangled in the form and cannot be edited

`draw_form` renders `form.notes` as one `Line` (`src/ui.rs:833`), so a note with a newline in it
renders as `card ending 4417second line of notes` — two lines welded together with no separator.
Meanwhile `Enter` submits the form, so there is no way to type a newline either. Any entry with
multi-line notes (KeePassXC writes these constantly) is displayed wrongly, and a user who "fixes"
what they see destroys the line break.

**Fix:** render the notes box as a multi-row field with a visible `⏎` glyph at each break, and bind
`alt+enter` (or `^j`) to insert one. At minimum, show the glyph so the text is not a lie.

### A9. The search band swallows the arrow keys

While the band has the keys, `handle_search_key` (`src/main.rs:313`) binds `Left`/`Right` to caret
movement and nothing to `Up`/`Down` — probed: `Down` moves nothing. Everyone who has used a fuzzy
finder types a few characters and reaches for `↓`. Here it is a dead key, and the only way to touch
the results is to press Enter first.

**Fix:** `↑`/`↓` (and `^n`/`^p`) step the entry cursor while the band is live. The band keeps the
text keys; movement belongs to the list it is filtering.

### A10. After a search is kept, the keys drive the wrong pane

`keep_search` (`src/app.rs:1135`) clears `band` and snaps, but leaves `active_pane` where it was —
which is almost always `Groups`, since that is where `/` is usually pressed. Probed: after typing a
needle and pressing Enter, `j` moves the *group* cursor while the entries pane is showing whole-vault
matches. The user is looking at their search results and driving something else.

**Fix:** `keep_search` moves focus to the entries pane. That is the pane the search was about.

### A11. Silent keys — the rule the app sets for itself

Probed on the browser, all doing nothing at all: lowercase **`x`**, lowercase **`v`**, lowercase
**`d`**, **`^s`**, and **`Right` on the entries pane**.

- `x`/`v` are the single most likely mistake in this keymap, because the real keys are `X`/`V` and the
  app is at pains to teach the case. The key that teaches it should be the key itself.
- `d` is the obvious guess for delete (the real key is `D`).
- `^s` is what every human presses to save. Sennel autosaves, so it has a *nice* answer available.
- `Right` on entries is silent while `Left` hops to the groups pane — asymmetry with no message.

**Fix:** `x`/`v`/`d` → "cut is `X` · shift matters here" (and the equivalents); `^s` → save now,
which doubles as the retry after a failed autosave (see A1); `Right` on entries → open the detail
popup, mirroring `Left`.

### A12. The generated password's entropy is overstated

`form_generate` (`src/app.rs:2178`) generates with `exclude_ambiguous = true` but computes the
estimate with `alphabet_len(false)`. The pool is 57 characters; the flash prices it at 62. "~119
bits" where the truth is ~117. Small, but it is a security number quoted to the user, and quoting the
alphabet you did not draw from is the one direction an estimate must not err in.

**Fix:** pass `true`, matching the draw. One character.

### A13. `NO_COLOR` erases signals that exist only as colour

`shade_at` maps every colour to `Color::Reset` under `NO_COLOR` (`src/theme.rs`), which is the right
call — but three things are then indistinguishable:

- **Which pane has focus.** Both panes draw `▌` on their selected row; only the colour (TEAL vs DIM)
  differs. With colour off, focus is invisible.
- **Flash severity** (added in the last pass): red, amber and cream all render identical.
- **The `unsaved` chip**, which is amber and otherwise unremarkable text.

**Fix:** give each one a second channel. Focus: `▌` on the live pane, `│` on the other. Severity: a
leading glyph — `×` for errors, `!` for warnings, nothing for info. Unsaved: `•unsaved`. Colour then
reinforces rather than carries.

---

## B. Design tweaks

### B1. The panes have no names, and nothing says where you are

Three columns, no headers, no breadcrumb. The group path only ever appears as a dim suffix on search
results. On a deep tree with the pane truncating names to `Clients and contrac…`, the screen cannot
answer "which folder am I in".

**Fix:** one dim header row per pane — `groups`, `Banking · 2 entries`, `detail` — with the live one
in CREAM. It names the panes, shows the breadcrumb and marks focus in the same row.

### B2. The detail pane is still 80% empty, and the hint is at the very bottom

At 120×30 the pane draws 8 rows of content, 20 blank, then the key hint on the last line — as far
from the content as the layout allows. The eye never travels there.

**Fix:** move the hint directly under the fields, separated by a rule. Then use the space: group
path, entry age ("updated 3 days ago" beside the stamp), and a strength read-out for the password.

### B3. The sort order is invisible the moment its flash expires

`o` cycles four orders and says so once. Nothing on screen names the current one afterwards — and now
that `sort` persists in the config, a session can *start* in an order the user set weeks ago and has
no way to see.

**Fix:** a dim `order: name` in the entries-pane header (B1) or as a droppable status segment.

### B4. The empty states do not teach the way out

` no entries here` (`src/ui.rs:307`) and ` no groups` (`src/ui.rs:237`). The search empty state does
this properly — "nothing matches zzz · esc clears it" — and these two should match it. This is the
first screen after creating a vault, so it is also the onboarding moment.

**Fix:** "no entries here · `a` adds one" and "no groups · `A` adds one".

### B5. The form never says where the entry is going

The popup is titled `new entry`. Entries land in the cursor group, which may be scrolled out of view,
and there is no group field in the form.

**Fix:** title it `new entry in Banking`. (And on edit, `edit entry · Banking`.)

### B6. You cannot see the password you just generated

`^s` fills the box, the box masks, and the form has no reveal. The only way to read a generated
password is to save the entry and press `*` somewhere else. The lock screen has `^r`; the form should
have the same key for the same job.

### B7. The delete flash does not mention the undo that exists

"entry deleted" — and `u` sits right there able to bring it back. Pair it with A5.

### B8. The clipboard countdown is a promise, not a display

"copied password · clears in 15s" is shown for a few seconds, then the header moves on while the
secret is still on the clipboard. The frame loop already redraws every 120ms.

**Fix:** a status chip counting down — `clipboard 12s` — that disappears when the wipe lands. It is
also the honest place to show that a second copy re-armed the timer.

### B9. The detail popup omits a key that works, and the group it belongs to

The hint row names `y p U`, `*` and `esc`. `e` opens the editor from inside the popup and is not
advertised. The popup also never says which group the entry lives in — the one bit of context the
side pane gets from being next to the tree.

### B10. The flash queue can run three messages behind

Up to 3 queued, each up to 8 seconds (`QUEUE`, `FLASH_MAX` in `src/app.rs`). Copy three fields
quickly and the header narrates the first one while you are already on the third; a later error
queues behind two stale confirmations.

**Fix:** let a new message of the same kind replace a queued one of that kind (copies replace copies),
and let an `error` jump the queue. Nobody needs to read "copied username" twice.

### B11. The status bar offers copy keys when there is nothing to copy

`y user  p pass  U url` renders whenever the browser is up, including on an empty group where all
three answer "no entry here to copy from".

**Fix:** dim them (or drop them, they are already droppable) when `selected_entry()` is `None`.

### B12. Small movement conventions are missing

`g` jumps on a single press where vim users expect `gg` (and `g` alone is a prefix); `Home`/`End` are
unbound in the panes; `Space` does nothing where a pager would page.

**Fix:** accept `Home`/`End` as `g`/`G`, and either take `gg` or leave `g` as is — but say so in the
overlay.

### B13. Very small terminals lose the one always-true hint

At 24×8 the bar renders `y user   p pass   U url` and `h keys` is pushed off the row entirely. Below a
certain width the copy keys are the thing to drop, not the hint.

**Fix:** under ~40 columns show `h keys` alone. Under ~30×8, one dim line — "terminal too small" —
beats a broken layout.

### B14. The scrollbar draws on top of the list text

`draw_scrollbar` (`src/ui.rs:215`) renders into the pane's own last column. The lists truncate to
`width - 2`, which usually saves them, but the entries row appends spans past that budget (A7), so the
thumb lands on characters. Visible at 24 columns, possible at any width with a long username.

**Fix:** reserve the column when the scrollbar is live: the list's budget is `width - 1` when
`len > height`.

### B15. The generator cannot be configured

Hard-coded: 20 characters, lower + upper + digits, no symbols, ambiguous excluded
(`src/app.rs:2178`). Some sites demand a symbol; some forbid them; some cap the length. There is no
config key and no way to ask for anything else, so the answer is "generate, then edit by hand".

**Fix:** `generator = { length = 20, symbols = false, ambiguous = false }` in `config.toml`, and
`^s` repeated cycles a couple of presets with the flash naming each.

### B16. The tree does not say how much is in each group

Every group looks equally full. A dim count — `Banking 2` — turns the tree into a map. It is the same
information the status bar already computes for the whole vault.

### B17. The vault's name disappears whenever anything is flashed

The header is one slot: `Sennel · <flash or vault name>`. While any message is up, nothing on screen
says which vault is open — which is the thing the last review added it for.

**Fix:** vault name right-aligned in the header, flash on the left. They stop competing.

---

## C. Worth building

1. **Walk entries from inside the detail popup.** `j`/`k` (and `n`/`N` while a filter is live) move to
   the next entry and redraw the popup. At 80 columns the popup *is* the detail view, and closing it
   to move and reopening it is the whole interaction cost of a narrow terminal.
2. **TOTP.** KDBX stores `otp` as an entry attribute and KeePassXC writes it. Sennel currently shows
   nothing and copies nothing. Even read-only support — a `totp` row with the current code and
   seconds remaining, `t` to copy — would put it alongside the manager people are migrating from.
3. **Say that hidden fields exist.** Custom string fields and attachments are invisible: an entry with
   five extra fields and a recovery-codes file looks identical to an empty one, and a save writes them
   back untouched (good) while the UI denies they exist. One dim row — `3 more fields · 1 attachment`
   — is enough to stop a user believing the data is gone.
4. **Search match highlighting.** `nucleo-matcher` returns indices; bolding the matched characters
   turns a sorted list into a scannable one. (Carried from the first review.)
5. **Mouse.** Wheel to scroll, click to select, click a pane to focus it. (Carried.)
6. **A busy state for slow unlocks.** Argon2 runs synchronously in the key handler and the frame
   freezes; `theme.rs` still reserves GOLD for a spinner that does not exist. (Carried.)
7. **`^s` as save-now.** Answers the silent key (A11), gives the retry path A1 needs, and gives anyone
   who does not trust autosave something to press.
8. **Strength read-out in the form.** The generator already computes entropy; scoring what is *typed*
   with the same function and showing `~48 bits` under the box costs almost nothing.
9. **A search scope toggle.** A live needle silently widens to the whole vault. That is usually right,
   but `^g` to pin it back to the current group (with the band saying which) would make the widening
   a choice rather than a surprise.
10. **`--check` should check the vault, not just the config.** Whether the file exists, is readable,
    is writable, and when it last changed. That is what a bug report needs and what a first run wants.
11. **First-run scaffolding.** After creating a database, the browser shows an empty tree. Offer to
    create `Personal` / `Work` / `Email`, or at minimum land the cursor with "a adds your first entry"
    up (B4).

---

## Priority

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| A1 | autosave overwrites external changes | medium | **data loss** |
| A2 | `q` on the overlay quits / types into the password | few lines | safety, trust |
| A5 | "cannot be undone" is false for entries | 2 lines | trust, fear |
| A4 | confirm truncates its own warning | small | safety |
| A3 | `h keys` is a lie on the lock screen | small | first-run trust |
| A8 | multi-line notes mangled and uneditable | medium | correctness |
| A9 | arrows dead in the search band | small | everyday flow |
| A10 | kept filter drives the wrong pane | 1 line | everyday flow |
| A7 | entry rows overflow the pane | small | everyday readability |
| A11 | silent `x` `v` `d` `^s` `→` | small | the app's own rule |
| A6 | overlay loses rows when short | small | discoverability |
| A13 | `NO_COLOR` loses focus and severity | small | accessibility |
| A12 | entropy quoted against the wrong alphabet | 1 char | honesty |
| B1 | pane headers and breadcrumb | small | orientation |
| B4 | empty states that teach | 2 lines | onboarding |
| B6 | reveal in the form | small | generator usability |
| B3 | sort order visible | small | continuity |
| B8 | clipboard countdown | small | trust |
| B5 | form names its group | 1 line | correctness |
| B7 | delete flash names `u` | 1 line | recovery |
| B9 | popup names `e` and the group | 1 line | discoverability |
| B14 | scrollbar overdraw | small | polish |
| B2 | detail pane layout | small | perceived polish |
| B11 | copy keys when nothing is selected | small | honesty |
| B13 | tiny-terminal bar | small | small screens |
| B10 | flash queue backlog | small | responsiveness |
| B16 | counts in the tree | small | orientation |
| B17 | vault name vs flash in the header | small | identity |
| B12 | `Home`/`End`, `gg` | small | convention |
| B15 | configurable generator | medium | real-world use |
| C1 | walk entries inside the popup | small-medium | narrow-terminal UX |
| C2 | TOTP | medium-large | parity with KeePassXC |
| C3 | name hidden fields and attachments | small | honesty about data |
| C7 | `^s` saves now | small | habit + A1 retry |
| C4–C6, C8–C11 | see above | mixed | mixed |

Nothing in A or B needs a new architecture. A1 wants a stat before a write; A8 and C2 are the only
items that touch the vault layer at all.
