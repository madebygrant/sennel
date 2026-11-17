# Extension rules

These are the rules the Sennel browser extension follows. They come from KeePassXC-Browser's public issue history and the research it links to, read for the lesson and never for the code. Each rule says what to do, why, where the lesson came from, and how it is checked.

A change that breaks a rule changes the rule first, with its reason.

## R1. Fill only after the user acts

Nothing is filled when a page loads, when a field gets focus, or when a script dispatches an event. A fill starts from a click in the extension's own popup, or later from a key or click on Sennel's own in-page UI that the browser marks as trusted.

**Why.** An attacker who can run script on a page through cross-site scripting or a bad advert can draw an invisible form and collect whatever is filled into it. If a fill needs a real user action on UI the page cannot reach, the script cannot start one.

**Source.** [#437 Raising awareness around the security concerns of auto-fill](https://github.com/keepassxreboot/keepassxc-browser/issues/437): a dropdown the page could "click" with script, and the suggestion to require `Event.isTrusted`.

**Checked by.** The popup is the only place a fill starts in this release. A code review check: `fill` in `extension/src/session.js` is reached only through the background worker's `fill` message, which `extension/src/background.js` accepts only from the extension's own pages, and the popup sends it only from a row's click handler. The injected `extension/public/fill.js` runs nothing until called. Manual check M1.

## R2. Match scheme, host and port

The app decides which logins a page gets: the same host and port, and never an https entry's password on an http page. Subdomains do not match unless the entry lists them. The extension sends the page's full address and fills only into the tab and page it asked about: the same origin and path. A new query or fragment on that page, as single-page logins add, does not count as moving. If the tab has gone to another page since the list was fetched, it refuses to fill.

**Why.** A password saved for `https://bank.example` must not reach `http://bank.example`, where anyone on the network can read it, or `bank.example.evil.test`. A port is a different service on the same host. A popup kept open while the tab navigates must not fill the new page with the old page's login.

**Source.** [#686 Subdomains are ignored](https://github.com/keepassxreboot/keepassxc-browser/issues/686) and [#2334](https://github.com/keepassxreboot/keepassxc-browser/issues/2334) show subdomain matching as a long-running source of surprise. [#1587 Ports are not stored in allow/deny](https://github.com/keepassxreboot/keepassxc-browser/issues/1587) shows the cost of ignoring ports. [#2401](https://github.com/keepassxreboot/keepassxc-browser/issues/2401) covers bare domains and http.

**Checked by.** `crates/sennel-browser/src/matching.rs` tests for the app's side. `extension/src/page.test.js` and `extension/src/visible.test.js` for refusing a page that moved.

## R3. Fill the top page only, until frames have their own prompt

This release fills only the tab's top frame. Same-origin frames, and cross-origin frames behind a prompt that names the frame's origin, come with on-page filling in wave 4.

**Why.** A login form in a cross-origin frame belongs to whoever serves that frame, which may not be the site the user sees in the address bar. An attacker can also load the real site in a transparent frame and steer clicks onto it.

**Source.** [#1367 Clickjacking vulnerability](https://github.com/keepassxreboot/keepassxc-browser/issues/1367) (the real site loaded in an invisible frame), [#3097](https://github.com/keepassxreboot/keepassxc-browser/issues/3097) (a site-wide cross-origin switch is too broad) and [#2937](https://github.com/keepassxreboot/keepassxc-browser/issues/2937) (fills bubbling into other frames).

**Checked by.** The fill is injected with `allFrames: false` (`fill` in `extension/src/session.js`). Manual check M3.

## R4. Skip fields the user cannot see

A field is filled only if it has a size, sits at least partly in the viewport, is not hidden by `display`, `visibility` or near-zero `opacity` on itself or any ancestor, and is the element actually under at least one of five points across it, so nothing covers it whole. A field below the fold is scrolled to before it is judged; one hidden any other way is not.

**Why.** A hidden or covered field is how a page collects a password the user never saw being entered.

**Source.** [#2184 Suggestions for Improvement in Detecting Hidden Form Elements](https://github.com/keepassxreboot/keepassxc-browser/issues/2184): concrete hiding tricks the size and opacity checks alone missed, and the cost of checking every ancestor.

**Checked by.** `extension/src/visible.test.js` covers each way of hiding. Manual check M4.

## R5. A dropped connection to the app is routine

The extension opens the native messaging connection when it needs one and expects it to drop at any moment. In Chrome the service worker stops when idle, and the app quits or locks. The connection lives in the background worker, not the popup, because Sennel's dialogs take focus and the browser closes the popup when they do. It never reconnects in a loop on a timer, and it makes one key pair per connection, not one per attempt.

**Why.** An extension that assumes a long-lived connection breaks after the browser stops its worker. A reconnect loop that makes a new key pair on every tick, while the app is not running, grows memory without bound.

**Source.** [#3072](https://github.com/keepassxreboot/keepassxc-browser/issues/3072) (Manifest V3 reconnects, and the key pair per reconnect tick named as the cause of the leak) and [#1113 Memory leaks on firefox](https://github.com/keepassxreboot/keepassxc-browser/issues/1113).

**Checked by.** `extension/src/client.test.js`: one connection makes one key pair, and a closed port rejects pending requests instead of retrying. Manual check M5.

## R6. Sennel's UI on a page is out of the page's reach

Any UI the extension draws on a page sits in a closed shadow root with its own styles, positioned on top, and refuses clicks while the page has made it or its frame transparent. This release draws nothing on pages; the rule binds wave 4.

**Why.** A page can restyle, cover or fade an extension's in-page UI to steer the user's click onto it, which is DOM-based clickjacking. It can also break the UI by accident, as `font-size: 0` on `<body>` did.

**Source.** [#1367](https://github.com/keepassxreboot/keepassxc-browser/issues/1367), [#2645 Potential Clickjacking](https://github.com/keepassxreboot/keepassxc-browser/issues/2645) and the research it links, [DOM-based extension clickjacking](https://marektoth.com/blog/dom-based-extension-clickjacking/), and [#3035](https://github.com/keepassxreboot/keepassxc-browser/issues/3035) (page CSS hiding the extension's banner).

**Checked by.** Nothing yet: no in-page UI exists. Wave 4's test pages carry the check.

## R7. A one-time code goes with the login it belongs to

The code copied or filled is the code of the entry the user picked, never the first entry that has one.

**Why.** With several accounts on one site, the wrong code fails the login at best and locks the account at worst.

**Source.** [#1852 Wrong account's TOTP filled during authentication](https://github.com/keepassxreboot/keepassxc-browser/issues/1852).

**Checked by.** The popup asks for the code by the chosen row's uuid, on the connection that listed it (`code` in `extension/src/session.js`), and the app serves a code only for an entry that connection was given (`crates/sennel-browser` test `a_one_time_code_needs_its_own_yes_and_a_login_given_first`).

## R8. The extension checks the app's replies too

Every encrypted reply must carry the request's nonce plus one, both inside and outside the encryption. A reply that does not is dropped, and so is one that fails to decrypt.

**Why.** The nonce ties a reply to its request. Without the check, a replayed or reordered reply could answer a different question.

**Source.** The protocol document, `keepassxc-protocol.md`, which says the response nonce is the request's incremented. Sennel's app already refuses replayed requests; this is the same rule on the other side.

**Checked by.** `extension/src/client.test.js`.

## Manual checks

Run in Chrome and Firefox against Sennel with the unpacked extension.

- **M1.** Open a login page that has a matching entry. Nothing fills until a row in the popup is clicked.
- **M2.** Open the popup on a login page, then navigate the tab to another site with the popup still open, and click a row. Nothing fills, and the popup says the page changed.
- **M3.** On a page with a login form inside a cross-origin iframe, clicking a row fills nothing in the frame.
- **M4.** On the repository's test page `extension/test/hidden.html`, the hidden and covered fields stay empty after a fill, and the visible pair is filled.
- **M5.** Quit Sennel, then open the popup. It says the app is not reachable and does not retry on its own. Open Sennel and reopen the popup, and it works.
- **M6.** On a site with no remembered answer, choose a login. Sennel's dialog closes the popup; answer "Allow once", reopen the popup, and the list is there without a second question. Pairing works the same way: click Connect, answer in Sennel, and reopen the popup.
