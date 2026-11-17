# Sennel browser extension

Fills logins from the Sennel desktop app, from its toolbar popup or from a button that appears in a login field when it gets focus. It follows the rules in `../docs/extension-rules.md`.

## Build

```sh
npm ci
npm run build        # dist/chrome and dist/firefox
npm test             # unit tests
npm run test:pages   # the test pages in headless Chrome
```

`npm run test:pages` builds a test copy of the extension into `dist/test-chrome` that talks to a stand-in for the Sennel app (`src/fake-app.js`) instead of the real one, then drives it through Puppeteer. The release build contains none of the stand-in.

## Load it unpacked

- **Chrome, Edge, Brave:** open the extensions page, turn on developer mode, choose "Load unpacked" and pick `dist/chrome`. The manifest's `key` fixes the id to `naibgmdhaebnonifkllpaiaflpnggnfa`, which the desktop app's registration allows.
- **Firefox:** open `about:debugging#/runtime/this-firefox`, choose "Load Temporary Add-on" and pick `dist/firefox/manifest.json`. It stays until Firefox restarts. Firefox asks for site access separately: allow it for all sites in the add-on's permissions, or the in-page button never appears.

After each build, click the extension's reload arrow (or reload it in `about:debugging`): the browser keeps running the build it loaded until then.

The Sennel desktop app registers itself for this extension every time it starts, so open Sennel once after installing it.

## Test pages

Serve `test/` over http, since the extension does not fill `file://` pages:

```sh
python3 -m http.server -d test 8000
```

Then add an entry with URL `http://localhost:8000` to the vault. The pages are `login.html`, `two-step.html`, `dynamic.html`, `shadow.html`, `iframe-same.html`, `iframe-cross.html`, `hidden.html` and `otp.html`; the manual checks in the rules document use them.
