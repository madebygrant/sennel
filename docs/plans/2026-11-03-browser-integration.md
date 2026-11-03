# Browser integration plan

## Context

Sennel has no browser autofill, so every login is a copy and a paste. The user chose to ship a Sennel browser extension that speaks KeePassXC's browser protocol, and to have the desktop app serve the stock KeePassXC-Browser extension as well.

One protocol serves both extensions. KeePassXC-Browser's protocol is documented in its repository (`keepassxc-protocol.md`). The extension starts a small proxy through the browser's native messaging. The proxy relays JSON to the running password manager over a local socket. After a key exchange, every message is a NaCl `box` with a 24-byte nonce that the reply increments. A browser pairs once with `associate`, and the public half of its identification key is stored in the vault.

That gives three combinations, and all of them should work:
- KeePassXC-Browser talking to Sennel
- the Sennel extension talking to Sennel
- the Sennel extension talking to KeePassXC, because it speaks the same protocol

KeeWeb did the same thing before: its own extension, plus support for KeePassXC-Browser. That is the precedent to study, not to copy.

Two constraints shape the design:
- **Licence.** KeePassXC and KeePassXC-Browser are GPL-3, and Sennel is MIT or Apache-2.0. The Sennel side of the protocol is written from the protocol document alone, without reading KeePassXC's source. The extension is a separate program that talks over IPC, so its licence does not bind the app. See decision 1.
- **The native messaging host name.** KeePassXC-Browser only ever looks for `org.keepassxc.keepassxc_browser`. KeePassXC rewrites that registration on every start by default, through its "Update native messaging manifest files at startup" setting. So Sennel can serve the stock extension only while it holds that registration, and KeePassXC takes it back each time it starts. The Sennel extension uses a host name of its own and never conflicts.

## Decisions for the user

1. **Fork KeePassXC-Browser, or write the extension from scratch.**
   - **Fork (recommended).** It starts from years of autofill fixes: invisible frames, cross-origin forms, look-alike subdomains and timing. It must be rebranded, since "KeePassXC" is the project's name, and it stays GPL-3. It lives in its own repository, so this repository stays MIT or Apache-2.0. The cost is merging upstream fixes by hand.
   - **From scratch.** The licence is free, but it takes much longer, and every autofill attack KeePassXC-Browser has already fixed has to be found again.
2. **The Sennel host name.** This is a reverse domain the project controls, such as `dev.sennel.browser`. It is fixed once the extension ships, because it is written into every user's browser registration.
3. **Taking over KeePassXC-Browser's registration.** The recommended default is off, behind a setting that explains KeePassXC will take it back on its next start unless its own setting is turned off.
4. **Whether the terminal app can host the server.** The recommendation is desktop only at first. A browser request needs somewhere to show an approval dialog and to unlock the vault, and the terminal app is often not running.

## Wave 1: The protocol in core, with no transport
- Add `crates/sennel-browser`, a library with no Tauri or socket code. It holds:
  - the message types and their JSON shapes, as the protocol document lists them
  - the session crypto, using the `crypto_box` crate (X25519, XSalsa20-Poly1305), with nonce increment and a check that rejects a reused nonce
  - a `Server` that takes one decrypted request and returns one reply, against a `&mut Session`
- Actions: `change-public-keys`, `associate`, `test-associate`, `get-databasehash`, `get-logins`, `get-totp`, `generate-password`, `lock-database`, and the `database-locked` and `database-unlocked` notices.
- Association storage. Verify first how KeePassXC writes paired browsers into the vault, believed to be meta custom data under a `KPXC_BROWSER_` prefix. Do this by inspecting a vault KeePassXC has paired, not its source. Matching that format means a browser paired with KeePassXC on the same vault works with Sennel unchanged.
- URL matching for `get-logins`:
  - exact host by default
  - the entry's extra URLs, KeePassXC's `KP2A_URL` fields
  - never an https entry's password for an http page
  - honour KeePassXC's per-entry "KeePassXC-Browser Settings" allow and deny lists, read as data from the vault
- **Exit criterion:** core tests drive a full exchange, from key exchange through pairing to a lookup. The pairing test runs against the KeePassXC-paired fixture vault and finds the existing association. A replayed nonce is refused.

## Wave 2: Transport and the desktop side
- Add a `sennel-proxy` binary. It relays the browser's length-prefixed stdio messages to the desktop app's socket, byte for byte, and holds no keys.
- The desktop app listens while it runs:
  - on Unix, a socket in a per-user directory with mode 0700
  - on Windows, a named pipe limited to the current user
- Install the native messaging registration for Chrome, Chromium, Edge, Brave and Firefox on macOS, Linux and Windows. Chrome-family browsers use `allowed_origins` and Firefox uses `allowed_extensions`. Verify the current store extension IDs, because two different Chrome IDs for KeePassXC-Browser appear in the wild.
- Desktop UI:
  - an approval dialog for each new pairing, naming the browser and showing a key fingerprint
  - a per-site prompt the first time a site asks for a login: allow once, always, or deny
  - a "Connected browsers" list with revoke
  - the takeover setting from decision 3
- A locked vault answers `database-locked` and brings the window forward to unlock. No request waits on a hidden prompt.
- **Exit criterion:** stock KeePassXC-Browser in Chrome and Firefox on macOS pairs with Sennel, fills a login and a one-time code, and sees lock and unlock. KeePassXC then reclaims the registration on its next start, as documented.

## Wave 3: Saving logins
- `set-login`, `get-database-groups` and `create-new-group`. These go through `Session` like any other edit, so they get undo, conflict refusal and backups.
- Updating an existing login asks first and names the entry.
- **Exit criterion:** a new login saved from a browser form opens in KeePassXC with the right group, URL and password.

## Wave 4: The Sennel extension
- Start the extension under decision 1, in its own repository.
- Manifest V3 for Chrome-family browsers, plus a Firefox build, both talking to the Sennel host name.
- Feature check: on connect, the extension sends a Sennel-only action. KeePassXC answers it with an error, and the extension then falls back to plain protocol behaviour. Sennel-only features, such as fuzzy search and single-key copy in the popup, stay behind that check.
- Publish to the Chrome Web Store and Firefox Add-ons.
- **Exit criterion:** the Sennel extension fills from Sennel and from KeePassXC. KeePassXC-Browser still fills from Sennel when Sennel holds the registration.

## Wave 5: Passkeys
- `passkeys-get` and `passkeys-register`, storing credentials in KeePassXC's passkey format so the same passkey works from both apps.
- Show passkey entries as passkeys in the desktop and terminal apps, read-only, so an edit cannot break one.
- **Exit criterion:** a passkey registered on a test site through Sennel signs in through KeePassXC, and the other way round.

## Roadmap (not scheduled)
- **Safari.** A Safari web extension has to ship inside a signed macOS app, so this waits on signing from the desktop plan's roadmap.
- **macOS AutoFill.** A credential provider extension covers Safari and native apps, with passkeys included. It also needs signing.
- **Hosting in the terminal app.** Reconsider after wave 2, if there is a way to approve pairings and site access from the terminal.

## Security notes that shape the design
- The proxy and socket carry only ciphertext after the key exchange. Only the current user can open the socket.
- A pairing always needs a click in the app. Pairings live in the vault, so they travel with it to other machines, as they do with KeePassXC. Revoking one removes it from the vault.
- Credentials go only to an origin that matches the entry. The first request from a site needs approval unless the entry's allow list already covers it.
- Nothing reaches the browser while the vault is locked, and locking sends `database-locked` to every connected browser.
- The protocol document itself notes a minor weakness: only the public half of the identification key is used. Record that in `docs/security.md` rather than inventing a fix that would break compatibility.

## Critical files
- `crates/sennel-core/src/session.rs`: every browser edit goes through it, for undo and conflict refusal
- `crates/sennel-core/src/vault.rs`: custom data reads and writes, and URL fields
- `crates/sennel-desktop/src/lib.rs` and `desk.rs`: the socket listener and the approval dialogs
- `crates/sennel-desktop/capabilities/default.json`: any new commands
- `Cargo.toml`: the new `sennel-browser` crate and `sennel-proxy` binary

## Verification
- Waves 1 to 3: `cargo test --workspace` and clippy stay clean, and new protocol tests run with no browser.
- By hand after wave 2: KeePassXC-Browser in Chrome and Firefox against `tests/fixtures/keepassxc4.kdbx` (password `sennel-fixture`).
- After every wave that writes, open the vault in KeePassXC and check that pairings, saved logins and passkeys still work there.

## What can slip
Waves 1 and 2 are the product: they get KeePassXC-Browser filling from Sennel with no extension of our own. Wave 3 is what users expect next. Wave 4 is the brand and the Sennel-only features, and nothing before it depends on it. Passkeys can wait until the KeePassXC passkey format has been checked against real vaults.
