# Browser integration plan

## Context

Sennel has no browser autofill, so every login is a copy and a paste. The user chose to ship a Sennel browser extension that speaks KeePassXC's browser protocol, and to have the desktop app serve the stock KeePassXC-Browser extension as well.

One protocol serves both extensions. KeePassXC-Browser's protocol is documented in its repository (`keepassxc-protocol.md`). The extension starts a small proxy through the browser's native messaging. The proxy relays JSON to the running password manager over a local socket. After a key exchange, every message is a NaCl `box` with a 24-byte nonce that the reply increments. A browser pairs once with `associate`, and the public half of its identification key is stored in the vault.

That gives three combinations, and all of them should work:
- KeePassXC-Browser talking to Sennel
- the Sennel extension talking to Sennel
- the Sennel extension talking to KeePassXC, because it speaks the same protocol

KeeWeb did the same thing before: its own extension, plus support for KeePassXC-Browser. That is the precedent to study, not to copy.

**The first release is read-only.** It fills logins and one-time codes into forms and never changes a login, a group or a passkey. The one write it keeps is pairing, because the protocol stores each paired browser's key in the vault. Saving logins and passkeys come after the first release.

Two constraints shape the design:
- **Licence.** KeePassXC and KeePassXC-Browser are GPL-3, and Sennel is MIT or Apache-2.0. Copyright covers their code, not the protocol or the lessons in their issue history. So the app's side of the protocol and the extension are both written without reading either project's source. They come from the protocol document, the changelog, the issues and the pull request descriptions, turned into written rules first. See decision 1.
- **The native messaging host name.** KeePassXC-Browser only ever looks for `org.keepassxc.keepassxc_browser`. KeePassXC rewrites that registration on every start by default, through its "Update native messaging manifest files at startup" setting. So Sennel can serve the stock extension only while it holds that registration, and KeePassXC takes it back each time it starts. The Sennel extension uses a host name of its own and never conflicts.

## Decisions for the user

1. **The extension is written from scratch** [decided 2026-11-03]. It is MIT or Apache-2.0 like the app, so it lives in this repository under `extension/`. It learns from KeePassXC-Browser's public record, not its code:
   - Nobody working on Sennel reads KeePassXC or KeePassXC-Browser source. If one behaviour can only be understood from the source, one person reads it and writes a description in their own words, and someone else implements it.
   - Libraries are permissive only: TweetNaCl-js (public domain) for the encryption, and Mozilla's `webextension-polyfill` (MPL-2.0) for the browser API differences. No code comes from Bitwarden's extension either, which is also GPL-3.
2. **The first release is read-only** [decided 2026-11-03]. It fills forms and writes nothing to the vault except pairings.
3. **The Sennel host name.** This is a reverse domain the project controls, such as `dev.sennel.browser`. It is fixed once the extension ships, because it is written into every user's browser registration.
4. **Taking over KeePassXC-Browser's registration.** The recommended default is off, behind a setting that explains KeePassXC will take it back on its next start unless its own setting is turned off.
5. **Whether the terminal app can host the server.** The recommendation is desktop only at first. A browser request needs somewhere to show an approval dialog and to unlock the vault, and the terminal app is often not running.

## First release: read-only fill

### Wave 1: The protocol in core, with no transport
- Add `crates/sennel-browser`, a library with no Tauri or socket code. It holds:
  - the message types and their JSON shapes, as the protocol document lists them
  - the session crypto, using the `crypto_box` crate (X25519, XSalsa20-Poly1305), with nonce increment and a check that rejects a reused nonce
  - a `Server` that takes one decrypted request and returns one reply, against a `&mut Session`
- Answered actions: `change-public-keys`, `associate`, `test-associate`, `get-databasehash`, `get-logins`, `get-totp`, `lock-database`, and the `database-locked` and `database-unlocked` notices.
- Refused actions: `set-login`, `create-new-group`, `get-database-groups`, `generate-password`, `passkeys-register`, `passkeys-get` and `request-autotype`. Each gets the protocol's error reply naming the feature as not available yet, so the stock extension shows a message instead of waiting. Check by hand that KeePassXC-Browser handles each error without breaking.
  - `generate-password` is refused too, although it writes nothing. A generated password filled into a sign-up form, with no way to save it, is a password nobody can recover.
- Association storage. Verify first how KeePassXC writes paired browsers into the vault, believed to be meta custom data under a `KPXC_BROWSER_` prefix. Do this by inspecting a vault KeePassXC has paired, not its source. Matching that format means a browser paired with KeePassXC on the same vault works with Sennel unchanged.
- URL matching for `get-logins`:
  - exact host by default
  - the entry's extra URLs, KeePassXC's `KP2A_URL` fields
  - never an https entry's password for an http page
  - honour KeePassXC's per-entry "KeePassXC-Browser Settings" allow and deny lists, read as data from the vault
- **Exit criterion:** core tests drive a full exchange, from key exchange through pairing to a lookup. The pairing test runs against the KeePassXC-paired fixture vault and finds the existing association. A replayed nonce is refused. Every refused action gets its error reply, and a test checks that none of them changes the vault.

### Wave 2: Transport and the desktop side
- Add a `sennel-proxy` binary. It relays the browser's length-prefixed stdio messages to the desktop app's socket, byte for byte, and holds no keys.
- The desktop app listens while it runs:
  - on Unix, a socket in a per-user directory with mode 0700
  - on Windows, a named pipe limited to the current user
- Install the native messaging registration for Chrome, Chromium, Edge, Brave and Firefox on macOS, Linux and Windows. Chrome-family browsers use `allowed_origins` and Firefox uses `allowed_extensions`. Verify the current store extension IDs, because two different Chrome IDs for KeePassXC-Browser appear in the wild.
- Desktop UI:
  - an approval dialog for each new pairing, naming the browser and showing a key fingerprint
  - a per-site prompt the first time a site asks for a login: allow once, always, or deny. "Always" is remembered by Sennel, not written into the entry, so filling stays read-only.
  - a "Connected browsers" list with revoke
  - the takeover setting from decision 4
- A locked vault answers `database-locked` and brings the window forward to unlock. No request waits on a hidden prompt.
- **Exit criterion:** stock KeePassXC-Browser in Chrome and Firefox on macOS pairs with Sennel, fills a login and a one-time code, and sees lock and unlock. Its save and generate buttons show the "not available yet" message. KeePassXC then reclaims the registration on its next start, as documented.

### Wave 3: The rules, then an extension that talks
- Write `docs/extension-rules.md` before any extension code. Each rule states what to do, why, and the public issue or changelog entry it came from. It starts from these:
  - Fill only after a user action. Filling on page load lets an invisible form on a compromised page collect credentials.
  - Match scheme, host and port. Never send an https entry's password to an http page. Subdomain matching is a stated choice, not an accident.
  - Fill the top page and same-origin frames on a click. A cross-origin frame needs a click on a prompt that names the frame's origin.
  - Skip fields the user cannot see: zero size, off screen, transparent, or covered.
  - Treat a dropped connection to the app as routine, because Chrome stops an idle extension's background worker.
  - Keep Sennel's own in-page UI where the page cannot style or overlay it.
- Then the extension's skeleton in `extension/`, built with Vite and Svelte like the desktop page:
  - the protocol client: key exchange, pairing, nonces, and the Sennel-only feature check, which falls back to plain protocol behaviour against KeePassXC
  - a toolbar popup that lists the logins for the current site, fills on a click, and copies the one-time code. It has no save or generate buttons.
  - Chrome-family and Firefox builds, loaded unpacked for now
- **Exit criterion:** the unpacked extension pairs with Sennel and with KeePassXC. On a plain login page, a click in the popup fills the form. Every rule in the document has a test or a written manual check.

### Wave 4: Autofill on the page, and the stores
- Field detection: usernames, passwords, one-time code fields, forms added after the page loads, and logins split across two pages.
- Shadow DOM, and frames under the rules from wave 3.
- An in-page prompt on a focused field, drawn where the page cannot reach it. It offers to fill, never to save.
- A test page set in the repository: plain, two-step, iframe, cross-origin iframe, invisible fields, a dynamic form and shadow DOM. The extension's tests run against it in a headless browser.
- Publish to the Chrome Web Store and Firefox Add-ons. The listing says the release fills and does not save. It names KeePassXC compatibility without using its name or look as Sennel's.
- **Exit criterion:** every page in the test set behaves as the rules say, in Chrome and Firefox. After a session of fills, the vault file has changed only by its pairing records. The published builds install from both stores and pair with Sennel.

## After the first release

### Wave 5: Saving logins
- In the app: `set-login`, `get-database-groups`, `create-new-group` and `generate-password`. These go through `Session` like any other edit, so they get undo, conflict refusal and backups. Updating an existing login asks first and names the entry.
- In the extension: offer to save or update a login after a submit that looks successful, so a mistyped password is not stored. Add the generate button to the popup.
- **Exit criterion:** a login saved from a real site opens in KeePassXC with the right group, URL and password.

### Wave 6: Passkeys
- `passkeys-get` and `passkeys-register` in the app and the extension, storing credentials in KeePassXC's passkey format so the same passkey works from both apps.
- Show passkey entries as passkeys in the desktop and terminal apps, read-only, so an edit cannot break one.
- **Exit criterion:** a passkey registered on a test site through Sennel signs in through KeePassXC, and the other way round.

## Roadmap (not scheduled)
- **Safari.** A Safari web extension has to ship inside a signed macOS app, so this waits on signing from the desktop plan's roadmap.
- **macOS AutoFill.** A credential provider extension covers Safari and native apps, with passkeys included. It also needs signing.
- **Hosting in the terminal app.** Reconsider after wave 2, if there is a way to approve pairings and site access from the terminal.
- **Sennel-only features in the popup.** Fuzzy search and single-key copy, behind the feature check from wave 3.

## Security notes that shape the design
- The proxy and socket carry only ciphertext after the key exchange. Only the current user can open the socket.
- A pairing always needs a click in the app. Pairings live in the vault, so they travel with it to other machines, as they do with KeePassXC. Revoking one removes it from the vault.
- In the first release the server refuses every write except pairing, and a test holds it to that.
- Credentials go only to an origin that matches the entry. The first request from a site needs approval unless the entry's allow list already covers it.
- Nothing reaches the browser while the vault is locked, and locking sends `database-locked` to every connected browser.
- The extension follows `docs/extension-rules.md`. A change that breaks a rule changes the rule first, with its reason.
- The protocol document itself notes a minor weakness: only the public half of the identification key is used. Record that in `docs/security.md` rather than inventing a fix that would break compatibility.

## Critical files
- `crates/sennel-core/src/session.rs`: pairings go through it now, and every browser edit after the first release
- `crates/sennel-core/src/vault.rs`: custom data reads and writes, and URL fields
- `crates/sennel-desktop/src/lib.rs` and `desk.rs`: the socket listener and the approval dialogs
- `crates/sennel-desktop/capabilities/default.json`: any new commands
- `Cargo.toml`: the new `sennel-browser` crate and `sennel-proxy` binary
- `extension/`: the extension, with its own `package.json`
- `docs/extension-rules.md`: the autofill rules, written before the extension code

## Verification
- Waves 1 and 2: `cargo test --workspace` and clippy stay clean, and new protocol tests run with no browser.
- By hand after wave 2: KeePassXC-Browser in Chrome and Firefox against `tests/fixtures/keepassxc4.kdbx` (password `sennel-fixture`).
- After the first release's waves, open the vault in KeePassXC and check that pairings still work there and nothing else changed. After waves 5 and 6, check saved logins and passkeys the same way.
- From wave 3: the extension's own tests, and the test page set in Chrome and Firefox.

## What can slip
Waves 1 and 2 are the core of the first release: they get KeePassXC-Browser filling from Sennel with no extension of our own. Waves 3 and 4 build the Sennel extension from scratch, which is the slow part, and nothing before them depends on them, so they can take the time the rules need. Saving and passkeys wait until after the first release, and passkeys also wait until the KeePassXC passkey format has been checked against real vaults.
