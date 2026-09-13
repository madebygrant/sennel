# sennel-tui Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sennel-tui, a KeePass-style ratatui password manager with one-key clipboard copy, folder/category organisation, and fuzzy search.

**Architecture:** Single-threaded TUI (no worker thread — vault ops are instant, unlike earworm's subprocess work). `main.rs` event loop + per-screen key dispatch; `app.rs` single `App` state with `View` enum; `vault.rs` in-memory model ↔ KDBX4 via `keepass-rs`; `ui.rs` draw functions; `theme.rs`/`config.rs` ported from earworm.

**Tech Stack:** Rust 2024, ratatui 0.30, keepass-rs (KDBX4), arboard (clipboard), nucleo-matcher (fuzzy), zeroize/secrecy, clap 4 derive, anyhow, serde/toml, unicode-width.

## Global Constraints

- macOS and Linux only. `build.rs` refuses any other target OS; Windows-only crates in the lockfile (via `arboard`'s backend graph) are never compiled.
- Storage format is KDBX4 via `keepass-rs` (real KeePass compat), not a homebrew format.
- Clipboard via `arboard`, auto-clear after 15s default (configurable).
- Fuzzy search via `nucleo-matcher`.
- Style/reference project: `/home/ronin/Projects/earworm` (module layout, theme depth handling, filter-as-predicate, TestBackend tests, why-comments).
- Comments explain why, not what. Multi-line `/* */`, doc `///` with reasoning.
- `Esc` never quits; `q`/`^c` quit (dirty guard asks first, `qq` fast-path).
- Secrets never touch logs, status tally, or search-note highlights.
- Test with `TestBackend`, assert cell-by-cell (double-width glyphs); `cargo clippy -- -D warnings` clean.

---

## Wave 0 — Scaffold + earworm style foundation

### Task 0.1: Crate + dependencies

**Files:**
- Create: `Cargo.toml`, `src/main.rs` (hello stub via `cargo init --bin`)

**Interfaces:**
- Consumes: nothing
- Produces: buildable crate; locked dep set for all later waves

- [ ] **Step 1: Init crate**

Run: `cargo init --bin --name sennel-tui .` in `/home/ronin/Projects/sennel-tui`
Expected: `src/main.rs` created

- [ ] **Step 2: Set Cargo.toml deps**

```toml
[package]
name = "sennel-tui"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
ratatui = "0.30"
serde = { version = "1", features = ["derive"] }
toml = "1"
unicode-normalization = "0.1"
unicode-width = "0.2"
keepass-rs = "0.8"
arboard = "3"
nucleo-matcher = "0.3"
zeroize = "1"
secrecy = "0.8"
```

- [ ] **Step 3: Verify build**

Run: `cargo build`
Expected: compiles (warnings ok at this stage)

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml src/main.rs
git commit -m "chore: scaffold sennel-tui crate with dep set"
```

### Task 0.2: Port theme.rs + config.rs

**Files:**
- Create: `src/theme.rs`, `src/config.rs`
- Test: `cargo test config:: theme::`

**Interfaces:**
- Consumes: dep set from 0.1
- Produces: `theme::{depth_from, shade, background, plain, CREAM/GOLD/TEAL/AMBER/RED/DIM/RULE/SAND/SURFACE/INK}`; `config::{Cli, FileConfig, Config::build, config_path}`

- [ ] **Step 1: Write theme.rs** — port earworm's `src/theme.rs` verbatim (palette, `background()`, `Depth`, `depth_from`, `quantise`, `shade_at`, `plain`), retint only if desired. Keep its tests.
- [ ] **Step 2: Write config.rs** — `Cli { db: Option<String>, config, no_config, check, clipboard_timeout, lock_timeout }`, `FileConfig` all-optional + `deny_unknown_fields`, `Config::build(cli, &matches)` with the negation rule, `config_path() -> ~/.config/sennel/config.toml`, atomic comment-preserving save (copy earworm `write_atomically`).
- [ ] **Step 3: Run tests** — `cargo test` — Expected: PASS (theme + config unit tests).
- [ ] **Step 4: Commit** — `git commit -m "feat: port theme and config from earworm patterns"`

### Task 0.3: main/app/ui skeleton

**Files:**
- Create: `src/app.rs`, `src/ui.rs`; Modify: `src/main.rs`
- Test: `cargo test`

**Interfaces:**
- Consumes: theme + config from 0.2
- Produces: `App { view: View::Unlock, ... }`, `ui::draw`, event loop with `handle_key`, `sennel --check` working

- [ ] **Step 1: app.rs skeleton** — `View::{Unlock, Browser}`, `App::new`, `say()` flash queue (`FLASH`+`PER_CHAR`, `QUEUE=3`), `expire_flash()`, `ask_quit()`, `scroll_to()`+`SCROLLOFF`.
- [ ] **Step 2: ui.rs frame** — `draw()` order (background → header → band → body → status → popups → `recolour()`), placeholder body text, `h/?` help overlay, `cols()` via unicode-width.
- [ ] **Step 3: main.rs loop** — terminal setup, `handle_key` dispatch, `Esc`-never-quits, `q`/`^c` quit, `--check` prints clipboard backend + config path + db path.
- [ ] **Step 4: One TestBackend test** — header renders; help opens on `h`.
- [ ] **Step 5: Commit** — `git commit -m "feat: tui shell with help overlay and check"`

---

## Wave 1 — Domain model (in-memory vault)

### Task 1.1: vault.rs groups + entries

**Files:** Create `src/vault.rs`. Test: `cargo test vault::`

**Interfaces:**
- Consumes: nothing (pure model)
- Produces: `Group{id,name,parent}`, `Entry{id,group,title,username,password:SecretString,url,notes,updated}`, `Vault::add/rename/delete/move_group`, `add/edit/delete/move_entry` (stable ids, never key on names)

- [ ] Steps: failing test → impl → pass → commit (`feat: in-memory vault model with stable ids`).
- [ ] Rule: deleting a non-empty group is blocked (UI confirms); document why in a comment.

### Task 1.2: App selection state

**Files:** Modify `src/app.rs`. Test: `cargo test app::`

- [ ] `group_cursor`, `entry_cursor`, per-pane scroll, `rows()` views, `snap()` after every mutation.
- [ ] Commit: `feat: vault selection state with snap`

---

## Wave 2 — Encrypted storage + lock screen

### Task 2.1: KDBX open/save

**Files:** Modify `src/vault.rs`. Test: `cargo test vault::kdbx` (temp fixtures only, never commit real dbs).

- [ ] `open(path, password, keyfile)`, `save()` atomic (tmp+rename, `0600`), `change_password`. Model↔keepass tree mapping lives in this one module.
- [ ] Commit: `feat: kdbx4 open and atomic save`

### Task 2.2: Unlock view + dirty tracking

**Files:** Modify `src/app.rs`, `src/ui.rs`, `src/main.rs`.

- [ ] Password prompt (no echo, `SecretString`, zeroize on drop); wrong password names next step; `modified` flag → header dot + quit-confirm (`Confirm::Quit`, `qq` fast-path). Direct calls, no thread — comment why (divergence from earworm).
- [ ] Commit: `feat: unlock screen with dirty guard`

### Task 2.3: Auto-lock

- [ ] `lock_timeout` (default 300s, 0=off); expiry zeroizes secrets → Unlock view; any key resets timer. Test with injected clock.
- [ ] Commit: `feat: idle auto-lock with secret wipe`

---

## Wave 3 — Browser UI (three-pane layout)

### Task 3.1: groups | entries | detail

**Files:** Modify `src/ui.rs`, `src/app.rs`. Test: `cargo test ui::` (TestBackend).

- [ ] `<100 cols`: groups+entries; `>=100`: + detail pane. `▌` from `pos == cursor`, masked password default.
- [ ] Status: `N groups · M entries`, no secrets in tally.
- [ ] Commit: `feat: three-pane browser layout`

### Task 3.2: Keymap + help

- [ ] `j/k/↑/↓ ^d/^u g/G Tab enter e D h/? Esc q` per plan table; README table + overlay; overlay yields legend-then-settings.
- [ ] Commit: `feat: browser keymap and help`

### Task 3.3: Detail + show/hide

- [ ] `*` toggles mask with warning flash; `detail_rows` wrapped fields. Commit: `feat: detail pane with masked secrets`

---

## Wave 4 — Clipboard (one-key copy)

### Task 4.1: clipboard.rs copy

**Files:** Create `src/clipboard.rs`. Modify `app.rs` (hints), `main.rs` (`y`/`p`/`U`).

- [ ] `arboard` copy; headless error names the fix, never the secret. Flash `copied password · clears in 15s`.
- [ ] Commit: `feat: one-key username password url copy`

### Task 4.2: Auto-clear with epoch

- [ ] Clearer thread + epoch counter (second copy re-arms); overwrite with empty at deadline; `clipboard_timeout` config. Unit-test epoch; real-clipboard test `#[ignore]`.
- [ ] Commit: `feat: clipboard auto-clear`

---

## Wave 5 — Folders/categories

### Task 5.1: Group CRUD keys

**Files:** Modify `app.rs`, `ui.rs`, `main.rs`, `vault.rs`.

- [ ] `A` new group, `E` rename group (`e` stays entry — comment the `O`/`o` rationale), `D` on group asks move-out-vs-delete-all, `X`/`V` cut-paste entry-or-group. Status names armed clipboard.
- [ ] Commit: `feat: group crud and cut paste`

### Task 5.2: Entry order (view, never re-sort)

- [ ] `o` cycles `name | recent | updated` via `entry_rows()`; cursor stays a position in the underlying vec. Persist choice via atomic config save.
- [ ] Commit: `feat: entry sort orders as views`

### Task 5.3: Tree rendering + collapse

- [ ] Indent by depth, `▸/▾`, `Tab` collapse; per-group counts; empty placeholder. Tests: collapsed descendants hidden from `rows()`, cursors stay valid.
- [ ] Commit: `feat: collapsible group tree`

---

## Wave 6 — Fuzzy search

### Task 6.1: search.rs on nucleo-matcher

**Files:** Create `src/search.rs`. Test: `cargo test search::`.

- [ ] Haystack `title+username+url+group path` (+notes opt-in — comment why); scored, case-insensitive, normalized (chars not bytes).
- [ ] Commit: `feat: fuzzy matcher over entry haystacks`

### Task 6.2: Search band UI

**Files:** Modify `ui.rs`, `app.rs`, `main.rs`.

- [ ] `FILTER /gith█ 3 of 40 shown · esc clears` band (earworm pattern); live narrowing, `^w/^u`, `Enter` keeps + returns keys, `Esc` clears first. Predicate-only filter; `selected()` None off-screen + `snap()`.
- [ ] Commit: `feat: live fuzzy search band`

### Task 6.3: Scope + empty states + n/N

- [ ] All-groups flattened with dim group path; `nothing matches X · esc clears it`; `n/N` no-wrap with end notice.
- [ ] Commit: `feat: global search scope and match jumps`

---

## Wave 7 — Editor, generator, hardening, ship

### Task 7.1: Entry form

**Files:** Modify `app.rs`, `ui.rs`, `main.rs`. Pattern: earworm `Prompt::Form`.

- [ ] All fields at once, `Tab` boxes, `^s` generate-into-box, validation names next step, one-level `u` undo with status naming what it holds.
- [ ] Commit: `feat: entry editor form with undo`

### Task 7.2: Generator

**Files:** Create `src/gen.rs`.

- [ ] Length + classes + unambiguous-exclusion, entropy estimate, OS RNG. Test sanity not exact strings.
- [ ] Commit: `feat: password generator`

### Task 7.3: Ship

- [ ] `clippy -D warnings` clean, `0600` enforcement, `--check` + `--list` (counts, no secrets), README key tables + security notes, MIT/Apache licenses, pty smoke test.
- [ ] Commit: `chore: release hardening`

---

## Keymap v1 (ships in README + `h` overlay)

| Key | Action |
|---|---|
| `j/k ↑/↓ ^d/^u g/G` | move |
| `Tab` | groups ↔ entries pane |
| `enter` | open group / focus detail |
| `y / p / U` | copy username / password / URL |
| `*` | show/hide password |
| `/` | fuzzy search (`Enter` keep, `Esc` clear) |
| `a / e / D` | add / edit / delete entry |
| `A / E` | add / rename group; `X/V` cut-paste |
| `o` | entry order: name, recent, updated |
| `u` | undo last edit |
| `h/?` | keys; `Esc` unwind; `q/^c` quit (dirty asks) |
