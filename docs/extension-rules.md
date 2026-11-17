# Extension rules

These are the rules the Sennel browser extension follows. They come from KeePassXC-Browser's public issue history and the research it links to, read for the lesson and never for the code. Each rule says what to do, why, where the lesson came from, and how it is checked.

A change that breaks a rule changes the rule first, with its reason.

## R1. Fill only after the user acts

Nothing is filled when a page loads, when a field gets focus, or when a script dispatches an event. A fill starts from a click in the extension's own popup, or from a click on a row of Sennel's in-page list, an event the browser marks as trusted (`isTrusted`). The list opens on a trusted click on a login field or on Sennel's button, but opening it fills nothing.

**Why.** An attacker who can run script on a page through cross-site scripting or a bad advert can draw an invisible form and collect whatever is filled into it. If a fill needs a real user action on UI the page cannot reach, the script cannot start one.

**Source.** [#437 Raising awareness around the security concerns of auto-fill](https://github.com/keepassxreboot/keepassxc-browser/issues/437): a dropdown the page could "click" with script, and the suggestion to require `Event.isTrusted`.

**Checked by.** `extension/e2e/pages.test.js`: nothing fills on load or on focus, and a script's click on the button opens nothing. In the code, the content script's click handlers go through `trusted()` in `extension/public/content.js`, and the popup's fill is reached only through the background worker's `fill` message, which `extension/src/background.js` accepts only from the extension's own pages. Manual check M1.

## R2. Match scheme, host and port

The app decides which logins a page gets: the same host and port, and never an https entry's password on an http page. Subdomains do not match unless the entry lists them. The extension sends the page's full address and fills only into the tab and page it asked about: the same origin and path. A new query or fragment on that page, as single-page logins add, does not count as moving. If the tab has gone to another page since the list was fetched, it refuses to fill.

**Why.** A password saved for `https://bank.example` must not reach `http://bank.example`, where anyone on the network can read it, or `bank.example.evil.test`. A port is a different service on the same host. A popup kept open while the tab navigates must not fill the new page with the old page's login.

**Source.** [#686 Subdomains are ignored](https://github.com/keepassxreboot/keepassxc-browser/issues/686) and [#2334](https://github.com/keepassxreboot/keepassxc-browser/issues/2334) show subdomain matching as a long-running source of surprise. [#1587 Ports are not stored in allow/deny](https://github.com/keepassxreboot/keepassxc-browser/issues/1587) shows the cost of ignoring ports. [#2401](https://github.com/keepassxreboot/keepassxc-browser/issues/2401) covers bare domains and http.

**Checked by.** `crates/sennel-browser/src/matching.rs` tests for the app's side. `extension/src/page.test.js` and `extension/src/visible.test.js` for refusing a page that moved.

## R3. Frames: the same origin on a click, another origin only when named

The in-page button appears in the top frame and in frames of the same origin, and only while no frame around it is faded or filtered. It never appears in a cross-origin frame, where the parent page could make the whole frame transparent without the frame being able to tell. A login form in a cross-origin frame is offered by the toolbar popup instead, on a button that names the frame's origin, and its logins are fetched for that frame's address and filled into that frame alone.

**Why.** A login form in a cross-origin frame belongs to whoever serves that frame, which may not be the site the user sees in the address bar. An attacker can also load the real site in a transparent frame and steer clicks onto it.

**Source.** [#1367 Clickjacking vulnerability](https://github.com/keepassxreboot/keepassxc-browser/issues/1367) (the real site loaded in an invisible frame), [#3097](https://github.com/keepassxreboot/keepassxc-browser/issues/3097) (a site-wide cross-origin switch is too broad) and [#2937](https://github.com/keepassxreboot/keepassxc-browser/issues/2937) (fills bubbling into other frames).

**Checked by.** `extension/e2e/pages.test.js`: a same-origin frame fills and a cross-origin frame gets no button. `frameIsSafe` in `extension/public/content.js`; the popup's fill targets one `frameId` (`fill` in `extension/src/session.js`). Manual check M3.

## R4. Skip fields the user cannot see

A field is filled only if it has a size, sits at least partly in the viewport, is not hidden by `display`, `visibility` or near-zero `opacity` on itself or any ancestor, and is the element actually under at least one of five points across it, so nothing covers it whole. A field below the fold is scrolled to before it is judged; one hidden any other way is not.

**Why.** A hidden or covered field is how a page collects a password the user never saw being entered.

**Source.** [#2184 Suggestions for Improvement in Detecting Hidden Form Elements](https://github.com/keepassxreboot/keepassxc-browser/issues/2184): concrete hiding tricks the size and opacity checks alone missed, and the cost of checking every ancestor.

**Checked by.** `extension/src/visible.test.js` covers each way of hiding, and `extension/e2e/pages.test.js` fills `hidden.html` in Chrome. Manual check M4.

## R5. A dropped connection to the app is routine

The extension opens the native messaging connection when it needs one and expects it to drop at any moment. In Chrome the service worker stops when idle, and the app quits or locks. The connection lives in the background worker, not the popup, because Sennel's dialogs take focus and the browser closes the popup when they do. It never reconnects in a loop on a timer, and it makes one key pair per connection, not one per attempt.

**Why.** An extension that assumes a long-lived connection breaks after the browser stops its worker. A reconnect loop that makes a new key pair on every tick, while the app is not running, grows memory without bound.

**Source.** [#3072](https://github.com/keepassxreboot/keepassxc-browser/issues/3072) (Manifest V3 reconnects, and the key pair per reconnect tick named as the cause of the leak) and [#1113 Memory leaks on firefox](https://github.com/keepassxreboot/keepassxc-browser/issues/1113).

**Checked by.** `extension/src/client.test.js`: one connection makes one key pair, and a closed port rejects pending requests instead of retrying. Manual check M5.

## R6. Sennel's UI on a page is out of the page's reach

Sennel's in-page button and list sit in a closed shadow root with their own styles, in the browser's top layer (a popover) above anything the page stacks. A click on them counts only if it is trusted, the button or list has been on screen and still for half a second (moving it, by scrolling or resizing, starts the wait again), nothing of the page's is open in the top layer or full screen, and at that moment the button, the page's `<html>` and `<body>`, and every frame around it are fully opaque, visible and unfiltered.

A known gap: a popover the page opens inside a closed shadow root of its own cannot be seen, so it could still sit above Sennel's button.

**Why.** A page can restyle, cover or fade an extension's in-page UI to steer the user's click onto it, which is DOM-based clickjacking. It can also break the UI by accident, as `font-size: 0` on `<body>` did.

**Source.** [#1367](https://github.com/keepassxreboot/keepassxc-browser/issues/1367), [#2645 Potential Clickjacking](https://github.com/keepassxreboot/keepassxc-browser/issues/2645) and the research it links, [DOM-based extension clickjacking](https://marektoth.com/blog/dom-based-extension-clickjacking/), and [#3035](https://github.com/keepassxreboot/keepassxc-browser/issues/3035) (page CSS hiding the extension's banner).

**Checked by.** `extension/e2e/pages.test.js`: a click before the button settles, after the page scrolls it, after the page opens its own popover over it, and after the page fades itself, its body or the button, opens nothing.

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

## R9. Nothing reaches Sennel until the user clicks

The content script runs on every page. Focus on a login field, by Tab or by a page's own script, shows Sennel's button and nothing more. Only a click the browser marks as trusted, on a login field or on the button, asks Sennel for the site's logins. Pairing is never started from a page, only from the toolbar popup.

**Why.** Every message to Sennel can raise a dialog in the app, and a lookup tells the app which sites the user visits. A page should not be able to cause either by drawing a login form or by focusing one. A page can still steer a real click onto a field it controls, which is why opening the list fills nothing (R1).

**Source.** [#3043](https://github.com/keepassxreboot/keepassxc-browser/issues/3043): a site whose page alone made the extension prompt to unlock the database.

**Checked by.** `extension/e2e/pages.test.js`: focus shows the button with no list, a script's click on the field opens nothing, and a real click opens the list. In `extension/public/content.js` every `sendMessage` follows a trusted click, and `extension/src/background.js` offers content scripts no pairing operation. Manual check M7.

## Manual checks

Run in Chrome and Firefox against Sennel with the unpacked extension.

- **M1.** Open a login page that has a matching entry. Nothing fills until a row is clicked, in the popup or in the in-page list.
- **M2.** Open the popup on a login page, then navigate the tab to another site with the popup still open, and click a row. Nothing fills, and the popup says the page changed.
- **M3.** On `test/iframe-cross.html`, focusing the frame's field shows no button. The toolbar popup offers "Login form in a frame from http://127.0.0.1:…", and choosing it lists and fills that frame.
- **M4.** On `test/hidden.html`, the hidden and covered fields stay empty after a fill, and the visible pair is filled.
- **M5.** Quit Sennel, then open the popup. It says the app is not reachable and does not retry on its own. Open Sennel and reopen the popup, and it works.
- **M6.** On a site with no remembered answer, choose a login. Sennel's dialog closes the popup; answer "Allow once", reopen the popup, and the list is there without a second question. Pairing works the same way: click Connect, answer in Sennel, and reopen the popup.
- **M7.** With the Sennel window in view, open a login page and Tab into its fields. Sennel shows no dialog and its status line stays quiet. Click a field, and Sennel's list opens (with Sennel's site question the first time).
- **M8.** In Firefox, repeat the browser tests' pages by hand: `login.html`, `two-step.html`, `dynamic.html`, `shadow.html`, `iframe-same.html`, `iframe-cross.html`, `hidden.html` and `otp.html`. Firefox runs no automated browser test.
