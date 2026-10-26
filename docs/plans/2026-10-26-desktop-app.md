# Sennel desktop app (Tauri) plan

## Context

Sennel is a terminal app. The user asked what it would take to give it a native or local web front end, and chose a Tauri desktop app: the Rust code and a web UI in a native window, with no HTTP server and no local port. Another reason to choose Tauri is that it reuses the Rust vault code directly.

The result is two apps in one repository that share a core. `sennel`, the terminal app with its scripting commands, stays as it is. `sennel-desktop` is added beside it. Both open the same `.kdbx` files, and the existing conflict check keeps them from overwriting each other.

The vault layer is already independent of the terminal. `vault.rs`, `generator.rs`, `search.rs`, `clipboard.rs`, `agent.rs`, `touchid.rs`, `import.rs`, `export.rs`, `pwned.rs` and `migration.rs` have no ratatui dependency, about 6.5k lines.

The blocker is `src/app.rs` (about 8.1k lines). Every action follows the same pattern: a guard, a `Vault` call, `push_undo`, `snap()` (a cursor fix-up), `persist()`, then a `say`/`warn`/`error` flash. So the session behaviour is real core logic that is woven into TUI state. A second front end can't reuse it until that logic returns outcomes instead of writing messages.


## Wave 1: Workspace and core crate, moved without changing behaviour [done 2026-10-26]
- Convert to a Cargo workspace with `crates/sennel-core` (lib) and `crates/sennel-tui` (the current binary, still named `sennel`).
- Move the ratatui-free modules into core as they are.
- Split config:
  - The file side moves to core: `FileConfig::load` (config.rs:417), `config_path`, `remember_*` and `forget_db` (705–730), `absolute` (887) and `expand` (913).
  - `Config::build` (484) stays in the TUI, because it depends on clap and `theme::Palette`.
  - Core stores colours as strings or RGB tuples. The TUI turns them into `ratatui::Color` (`hex()`, config.rs:639).
- Move `SortOrder` (app.rs:501) into core.
- Make the test-only items public behind a `test-support` feature so the TUI crate's tests can still reach them:
  - helpers: `temp_path`, `TempPath`, `locked_app_with_db` (app.rs:5514–5532)
  - vault test APIs: `Vault::open` (vault.rs:867), `save_as` (1128), `all_entry_ids` (1356)
  - the Touch ID fake: `touchid::REFUSE`, and the `imp` swap from `cfg(test)` to `cfg(any(test, feature = "test-support"))`
- **Exit criterion:** `cargo test --workspace` and `cargo clippy --workspace --all-targets` both pass with the same test count. `tests/get.rs` still runs the `sennel` binary.

## Wave 2: A `Session` in core that returns outcomes
- Add `sennel_core::session::Session` holding:
  - the vault
  - save state: `dirty`, `overwrite_armed`, `pending`, `revision`
  - the undo stack (`Undo` at app.rs:472, `push_undo` at 5033 and `undo_last` at 5040)
  - the cut
  - Touch ID state: `quick` and `quick_here`
  - the SSH keys handed to the agent (`agent_keys`)
  - the idle clocks: `touch` (1432) and `idle_expired` (1445, without its `View` check)
- Methods return `Result<Outcome, SessionError>` instead of flashing. `App` holds a `Session`, turns outcomes into its existing messages, and keeps the cursors and `snap()`.
- Move one area at a time. The TUI tests stay green after each step:
  1. unlock and create (`unlock_with` 1754): the boxes go in as arguments, so the core no longer reads `unlock_confirm` or the file box
  2. lock (1487): the wipe moves; the reset of about 20 UI fields stays in the TUI
  3. persist, save, merge and reload (3462–3569)
  4. delete (`confirm_delete_entry` 3675, `confirm_delete_group` 4864)
  5. paste and `reparent_group` (4959, 4569)
  6. form validation (`parse_expiry` 276, `split_tags` 292, and the touched-field rules in `submit_form` 3862)
  7. rekey (4174)
  8. fields and attachments (`fields_save` 4373, `fields_add_submit` 4482)
  9. the agent (1318 and 1346)
  10. Touch ID (1390 and 1395)
- **Exit criterion:**
  - every existing test passes
  - new core tests drive `Session` with no TUI
  - `app.rs` keeps only view state, input routing and message wording

## Wave 3: The Tauri app
- Add `crates/sennel-desktop`, a Tauri 2 app with a TypeScript frontend (Svelte or plain TS with Vite), bundled locally with no remote content.
- The Rust side holds one `Mutex<Session>` in Tauri state. Commands:
  - unlock, lock, Touch ID unlock
  - the group tree, and entry rows with titles, usernames and urls only
  - entry detail, with the password masked unless revealed
  - copy a field; this runs in Rust through the existing `Board`, so a copied secret never enters JavaScript
  - add, edit, delete, move, undo
  - save, merge, reload
  - generate, audit, history, fields
- Blocking work runs in `spawn_blocking`: Argon2, YubiKey touches, Touch ID, and saves on a keyed vault. Check early that `Vault` is `Send`.
- The idle lock runs on a Rust timer and sends a `locked` event to the window, so a hung or hidden UI cannot hold the vault open. Window blur or minimise counts as idle time, not activity.
- Hardening:
  - Lock the content security policy to the bundled assets only.
  - Disable remote URLs and devtools in release builds.
  - Enable only the Tauri capabilities the commands need. No fs or shell plugins.
- **Exit criterion:** the app can unlock the fixture vault, copy a password that auto-clears, add and edit an entry, auto-lock and Touch ID unlock, and KeePassXC still opens the file afterwards.

## Wave 4: Unsigned builds and docs
- `cargo tauri build` produces a `.app` and `.dmg` on macOS, an AppImage or `.deb` on Linux, and an MSI on Windows, all unsigned. A build runs on the Mac that made it. A copy on another Mac must be allowed once in System Settings › Privacy & Security, and Windows shows a SmartScreen warning.
- Add a `docs/desktop.md`. Add a section to `docs/security.md` covering two things:
  - JavaScript strings cannot be zeroized, so a revealed or edited password lives in the webview until it is garbage-collected.
  - Copying stays in Rust.
- **Exit criterion:** the `.app` from `cargo tauri build` opens on this Mac, unlocks the fixture vault, and Touch ID works.

## Roadmap (not scheduled)
- **Signing and notarisation.** An Apple Developer ID ($99 a year) so the app opens on other Macs without the Open Anyway step, and an Authenticode certificate for Windows. Needed only to share the app.
- **Touch ID that survives a quit.** Needs a signed app with a keychain entitlement, so it waits on signing. Today the sealed password dies with the process by design.

## Security notes that shape the design
- There is no localhost server. Tauri talks to the frontend over in-process IPC, so other software on the machine and web pages have no port to reach.
- Secrets reach JavaScript only on reveal or edit. Copy, audit, Touch ID and the agent never send them there.
- Core keeps every guarantee from the TUI:
  - zeroized buffers
  - backups outside the synced folder
  - conflict refusal
  - recycle bin
  - core dumps off; `main.rs` already does this, and the desktop binary needs the same call

## Critical files
- `src/app.rs`: source for the `Session` extraction
- `src/config.rs` and `src/theme.rs`: the config split
- `src/main.rs`: module declarations, the unlock and save frame pattern (893–915) and the hardening calls
- `Cargo.toml`: becomes a workspace
- `tests/get.rs`: unchanged, as the regression check

## Verification
- After waves 1 and 2: `cargo test --workspace` gives the same pass count as now (438 + 20, 4 ignored), and clippy is clean.
- Run the TUI by hand against `tests/fixtures/keepassxc4.kdbx` (password `sennel-fixture`).
- After wave 3: `cargo tauri dev`, then run the exit checklist above.
- Check the CSP and that no network requests are made, using the webview inspector in a debug build.
- Open the saved vault in KeePassXC to confirm it still reads.

## What can slip
Waves 1 and 2 are required, because without them the desktop app would copy `app.rs` logic and the two front ends would drift. They also make the TUI easier to test on its own. Signing is on the roadmap, not in a wave, so nothing here depends on it.
