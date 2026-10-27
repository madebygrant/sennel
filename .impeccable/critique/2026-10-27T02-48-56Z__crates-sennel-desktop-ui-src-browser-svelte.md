---
target: the app
total_score: 25
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/Users/grant/Projects/_misc/sennel/crates/sennel-desktop/ui/src/Browser.svelte"
target_fingerprint: "sha256:2a424c6e2ac8cf92136c6ca0a80f54c95aa0c3b465e6c8711449b9ef258ce723"
target_path: /Users/grant/Projects/_misc/sennel/crates/sennel-desktop/ui/src/Browser.svelte
timestamp: 2026-10-27T02-48-56Z
slug: crates-sennel-desktop-ui-src-browser-svelte
---
Method: dual-agent (A: design review · B: detector + browser)

## Design health score

| # | Heuristic | Score | Key issue |
|---|-----------|-------|-----------|
| 1 | Visibility of system status | 3 | The countdown and inline "Copied" are good. Footer notes go stale, and the clipboard clearing has no end state. |
| 2 | Match system / real world | 3 | Mostly plain language. "Copied, never shown" reads as already copied, and the → / ← reparent buttons are cryptic. |
| 3 | User control and freedom | 3 | ⌘Z and the recycle bin are good. The delete prompt ignores Esc, and Esc in Edit discards changes without asking. |
| 4 | Consistency and standards | 2 | "Needs attention" opens a sheet titled "Audit". Copy feedback differs in each of three places. Show/Hide is a button in one place and a link in another. |
| 5 | Error prevention | 3 | Deletes are confirmed and go to the bin. Expiry dates are free text. |
| 6 | Recognition rather than recall | 2 | The toolbar is six icon-only buttons. Copy hints stay hidden until hover. The reason for a flag is only in a tooltip. |
| 7 | Flexibility and efficiency | 2 | Inside the search box, Enter, ↓ and ⌘C do nothing. There is no shortcut for the one-time code or Show, and Esc does not clear search. |
| 8 | Aesthetic and minimalist design | 3 | The detail-pane hierarchy is strong. The bottom of the sidebar has dim disabled buttons over the hex grid. |
| 9 | Error recovery | 2 | Errors are raw strings in a small footer, far from where they happened. A failed unlock gives feedback only in the footer. |
| 10 | Help and documentation | 2 | Tooltips and a few key hints. There is no in-app shortcut list. |
| **Total** | | **25/40** | **Acceptable** |

## Design specificity verdict

**LLM assessment:**
- **Specific, not template.** The numbered decoding cells, the segmented clipboard countdown and the strict roles (mono for data, verdigris for labels, Chakra for actions) belong to this product only. Show is the best moment in the app.
- **Weak spots:**
  - The unlock screen is a plain centred form with none of this character.
  - All four dialogs share one generic panel with a gold left rail.
  - The hex canvas is decorative only and carries no meaning.

**Deterministic scan:** `impeccable detect` found 5 side-tab warnings:
- `App.svelte:99` (`.ask`)
- `Browser.svelte:954` (`.prompt`)
- `Browser.svelte:772` (the `.password` inset stripe)
- `EntryForm.svelte:144` (`form`)
- `Sheet.svelte:137` (`section`)

These agree with the review's point about generic dialog panels. The browser overlay found 6 issues on the main view and 1 on the unlock view. All are contrast failures plus the password stripe:
- The muted `--faint` text is #7d705f, which measures 3.8–4.0:1 against the dark backgrounds.
- The input placeholders fall back to the browser's default #757575 (4.0–4.2:1), because no `::placeholder` rule exists.
- Dimmed text on the gold fill measures 4.1:1.

The review measured light-mode `--faint` at 2.7–3.0:1, which is worse. It also measured the red flag on the selected gold row at 1.4:1. There are no false positives. The password stripe is the weakest of the side-tab hits, because it marks the secret rather than decorating a card.

## Priority issues

1. **[P1] Search is a dead end for the keyboard.**
   - The core loop is ⌘F, type, copy. It breaks because the search box swallows Enter, ↓/↑ and ⌘C (`Browser.svelte:165`).
   - Fix:
     - In the search box, ↓/↑ move the selection and Enter copies the password.
     - ⌘C copies the password when no text is selected.
     - Esc clears the search, then leaves the box.
   - Command: `/impeccable harden`
2. **[P1] Dialogs are not real dialogs.**
   - There is no `role="dialog"` or focus management. Focus stays behind the dim backdrop, and Tab walks through the background. The delete prompt has no Esc. Esc in Edit throws away changes without asking.
   - Fix:
     - Use `<dialog>` with `showModal()`, so the background is inert.
     - Focus the safe button and give focus back on close.
     - Make Esc work everywhere, but have it confirm before discarding edits.
   - Command: `/impeccable harden`
3. **[P1] The muted text fails contrast in both themes.**
   - `--faint` is used for usernames, counts, cell numbers and hints. It measures 3.8–4.0:1 in dark and 2.7–3.0:1 in light. Placeholders use the browser default, and the red flag on the selected row is 1.4:1.
   - Fix:
     - Set dark `--faint` to about #8f8270 and light to about #7a6a55.
     - Add a `::placeholder` colour.
     - Draw the flag in `--accent-ink` on the active row.
   - Command: `/impeccable audit`, then `/impeccable polish`
4. **[P2] Feedback sits in a stale footer that screen readers miss.**
   - The footer has no `aria-live`, and notes never expire. Errors appear far from where they happened, and the clipboard clearing has no closing moment.
   - Fix:
     - Give the footer `role="status"`, and fade each note after about 4 seconds.
     - Show unlock errors under the password field.
     - Add a brief "Clipboard cleared" end state to the countdown.
   - Command: `/impeccable clarify`
5. **[P2] Copy and wording are inconsistent across surfaces.**
   - The detail pane, Generate, Fields and the form's "copy" link each give different feedback. Generated passwords skip the cells, and the "Audit" title doesn't match the sidebar.
   - Fix:
     - Use one copy treatment everywhere.
     - Show generated passwords in cells.
     - Rename the sheet "Needs attention".
     - Give the unlock screen and the dialogs the app's own character instead of the gold left rail.
   - Command: `/impeccable polish`

## Persona red flags

**Alex (power user)**
- ⌘F, type, Enter does nothing.
- There is no key for the one-time code (a core job) or for Show.
- Esc does not clear search.
- The group list cannot be reached by keyboard.
- Moving an entry to the bin asks for confirmation even though ⌘Z already undoes it.
- The decode animation (about 0.85s for 15 characters) cannot be skipped.

**Sam (accessibility)**
- No dialog moves or traps focus.
- Copy results, errors and the countdown are never announced.
- The masked password reads as twelve separate "•".
- Selection is shown by colour only, with no `aria-current`.
- The reason for a flag is in a tooltip only.
- The 20-second clipboard timer cannot be extended.
- The contrast failures above.

## Minor observations

- The masked state shows 12 dots grouped 5/5/2. That looks like a real length and shifts when revealed.
- While searching, the "Personal" group stays highlighted, so it's unclear what the search covers.
- Group counts are direct entries only, but the list shows entries from subgroups too.
- The one-time code field offers two ways to remove a code: "clear it to remove" in the placeholder and a "Remove code" button.
- Footer notes are lowercase ("copied the username"), unlike the sentence case elsewhere.
- On unlock, Library sits below the Unlock button, though people with several vaults pick a vault first.
- The disabled group actions at 0.45 opacity are barely readable over the hex grid.
- Chrome reports form fields without an `id` or `name`.

## Questions to consider

- The product promises that the clipboard clears itself. Why does that moment have no visual?
- Should the hex field carry meaning, such as a pulse on copy, a lit cell per flagged entry, or stillness when locked? Or should it go?
- For a keyboard-first user, should ⌘F, type, Enter be the primary path, with the three columns secondary?
