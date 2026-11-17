# Sennel browser extension

Fills logins from the Sennel desktop app. It follows the rules in `../docs/extension-rules.md`.

## Build

```sh
npm ci
npm run build   # dist/chrome and dist/firefox
npm test
```

## Load it unpacked

- **Chrome, Edge, Brave:** open the extensions page, turn on developer mode, choose "Load unpacked" and pick `dist/chrome`. The manifest's `key` fixes the id to `naibgmdhaebnonifkllpaiaflpnggnfa`, which the desktop app's registration allows.
- **Firefox:** open `about:debugging#/runtime/this-firefox`, choose "Load Temporary Add-on" and pick `dist/firefox/manifest.json`. It stays until Firefox restarts.

After each build, click the extension's reload arrow (or reload it in `about:debugging`): the browser keeps running the build it loaded until then.

The Sennel desktop app registers itself for this extension every time it starts, so open Sennel once after installing it.

## Test pages

Serve `test/` over http, since the extension does not fill `file://` pages:

```sh
python3 -m http.server -d test 8000
```

Then add an entry with URL `http://localhost:8000` to the vault, and use `login.html`, `hidden.html` and `frame.html` for manual checks M1 to M4.
