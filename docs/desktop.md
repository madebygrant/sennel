# The desktop app

[Back to the README](../README.md)

`sennel-desktop` is Sennel in a native window. It opens the same `.kdbx` files as the terminal app,
reads the same config file and keeps the same library of vaults. Both apps run on one Rust core, so
unlocking, saving, merging, undo, the recycle bin and Touch ID behave the same in each. Run both at
once if you like: the conflict check stops either one from writing over the other's changes.

It is a [Tauri](https://tauri.app) app. The window is the system webview (WKWebView on macOS,
WebKitGTK on Linux) showing a small Svelte page bundled into the binary. There is no web server and
no port. The page talks to the Rust side over Tauri's in-process IPC.

## Building

You need Rust 1.90 or later and Node.js. On Linux, install WebKitGTK and its companions first, as
listed in [Tauri's prerequisites](https://v2.tauri.app/start/prerequisites/#linux) (on Debian or
Ubuntu, `libwebkit2gtk-4.1-dev`, `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev` and
`librsvg2-dev`). Windows is not supported, the same as the terminal app.

```sh
cd crates/sennel-desktop
npm --prefix ui ci
ui/node_modules/.bin/tauri build
```

That builds the page and the release binary, then bundles them under `target/release/bundle/` at
the repository root, since the desktop app shares the workspace's `target`:

- macOS: `macos/Sennel.app` and `dmg/Sennel_<version>_<arch>.dmg`
- Linux: an AppImage and a `.deb`, built on Linux

`ui/node_modules/.bin/tauri dev` runs it with the page live-reloaded from Vite instead.

`scripts/install-desktop.sh` does the build and installs the result. On macOS it puts `Sennel.app` in
`/Applications`, or `~/Applications` if that is not writable. On Linux it installs the AppImage as
`~/.local/bin/sennel-desktop` with a menu entry.

The builds are signed ad hoc, not with a developer certificate. One you built yourself runs on the
Mac that built it. A copy downloaded or AirDropped to another Mac is quarantined: open it once, then
allow it under System Settings › Privacy & Security › Open Anyway. If macOS says the app is damaged
instead, clear the quarantine flag with `xattr -dr com.apple.quarantine Sennel.app`. Signing and
notarisation are on the roadmap, and only matter for sharing a build.

The desktop binary embeds the built page, so `cargo build --workspace` and `cargo clippy --workspace`
need `crates/sennel-desktop/ui/dist` to exist. Run `npm --prefix crates/sennel-desktop/ui run build`
once after a fresh clone. `cargo test` does not need it: the tests cover the library, which builds
without the page.

## Using it

The unlock screen takes a vault file, a password and an optional key file. **Library** lists the
vaults opened before in either app, newest first, and a click fills in the path. A path with no file
behind it creates a new vault, asking for the password twice. With `touch_id = true`, `enter` on an
empty password box after a lock asks for a fingerprint, as in the terminal.

The main window has groups on the left, entries in the middle and the selected entry on the right.
Typing in the search box at the top searches the whole vault. `#wo` instead lists the entries with a tag
starting `wo`, so `#work` finds what is tagged work and not "homework". Drag an entry onto a group to move it.

The keys are the terminal app's: a single key for each action, working whenever the cursor is not in
a text box, and ⌘ where the terminal uses Ctrl. ⌘F also searches, as in most Mac apps. `h` lists
them all, and `single_keys = false` in the config file turns the one-letter keys off.

| Key       | Does                                                           |
| --------- | -------------------------------------------------------------- |
| j k ↑ ↓   | move through the focused pane; g G jump to the top, bottom     |
| ← → tab   | switch between the groups and the entries                      |
| y p U t   | copy the username, password, website, one-time code           |
| ⏎         | on a group, go to its entries; on an entry, copy the password  |
| \*        | show the password                                              |
| a e D     | add, edit, delete an entry (D on a group deletes the group)    |
| A E       | add, rename a group                                            |
| X V       | cut an entry, paste it into the current group                  |
| P         | generate a password                                            |
| / ⌘F      | search; in the box, ↑ ↓ pick, ⏎ copies the password, esc clears |
| u         | undo the last change to the vault                              |
| ! F H     | needs attention, fields and attachments, history               |
| esc       | drop a cut entry, then clear the search                        |
| ⌘S ⌘L     | save, lock                                                     |
| h ?       | list the keys                                                  |

In a text box ⌘C, ⌘Z and the rest keep their usual meaning. Double-clicking an entry copies its
password, and clicking the username, website or one-time code row copies that field. The clipboard's
countdown sits at the top right.

Show lays the password out one character per numbered cell, with digits and symbols in their own
colours, so it can be read out or typed elsewhere without counting. Entries that the audit flags
(reused, weak, expired, empty or old) carry a red mark, and **Needs attention** lists them all.

A site's two-factor QR code goes straight into an entry. Copy a screenshot of it (⌘⇧⌃4 on a Mac), then
press **Paste QR** in the entry form or paste into the seed box, or drop a saved image of it onto the
form. The code is read in Rust, the clipboard is cleared afterwards since the screenshot is the secret,
and the form names the account the code is for. Only time-based codes are taken.

Every change saves at once, as in the terminal. If somebody else wrote the file meanwhile, a bar
offers to merge both, overwrite theirs, or reload theirs. Closing the window with changes that could
not be saved asks first.

## What is different from the terminal app

- The `db` key in the config is read but never written. Opening a vault puts it at the top of the
  library instead.
- There is no theme switcher. The window follows the system's light or dark setting.
- Settings come from the config file only. There are no command-line flags.

[Security](security.md#the-desktop-app) covers what the window can and cannot keep from a password.
