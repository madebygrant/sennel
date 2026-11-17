# Where the protocol details come from

Sennel's side of the protocol is written without reading KeePassXC or KeePassXC-Browser source (see decision 1 in `docs/plans/2026-11-03-browser-integration.md`). Every detail the code depends on came from one of these:

- **The protocol document**, `keepassxc-protocol.md` in the KeePassXC-Browser repository. It gives the action names, the request and reply fields, the three key pairs, and that a reply's nonce is the request's plus one.
- **Asking KeePassXC 2.8.0** (macOS build, `keepassxc-proxy` from the app bundle) with a probe written for Sennel, on 2026-11-17, against a copy of `tests/fixtures/keepassxc4.kdbx`. It showed:
  - the nonce is incremented as a little-endian number
  - `change-public-keys` and error replies are sent unencrypted. An error is `{"action", "error", "errorCode"}` with the code as a string.
  - codes and wording: 4 "Cannot decrypt message", 8 "KeePassXC association failed, try again", 12 "Incorrect action", 15 "No logins found", 18 "No valid UUID provided"
  - `get-databasehash` is SHA-256 of the root group's uuid in lowercase hex, checked against KeePassXC's answer for the fixture
  - the encrypted reply body carries `nonce`, `success: "true"` and `version`, and `get-logins` entries carry `group`, `login`, `name`, `password`, `stringFields` and `uuid` (32 hex digits)
  - `lock-database` is answered with `{"action": "database-locked"}` in the clear, then the encrypted reply
  - KeePassXC accepts a replayed nonce and matches subdomains and other ports. Sennel refuses all three on purpose, remembering the last 4096 nonces of each connection.
- **The vault KeePassXC paired**, `tests/fixtures/keepassxc4-paired.kdbx`, inspected with `keepassxc-cli export`:
  - a pairing is vault custom data `KPXC_BROWSER_<name>` holding the base64 identification key, with `_CREATED_<name>` beside it
  - remembered site answers are entry custom data `KeePassXC-Browser Settings`, JSON with `Allow` and `Deny` host lists
- **A copy of that vault with "Hide this entry from the browser extension" ticked**, `tests/fixtures/keepassxc4-hidden.kdbx`: the box is entry custom data `BrowserHideEntry` holding `true`.
- **Code 1, "Database not opened"**, is from the protocol document's `lock-database` example.

Not yet checked against KeePassXC, so to verify by hand in wave 2:
- how the stock extension shows the code 12 "not available in Sennel yet" replies
- `database-unlocked` as the clear `{"action": "database-unlocked"}`, by analogy with `database-locked`
- whether the extension needs anything else in a `get-totp` reply
