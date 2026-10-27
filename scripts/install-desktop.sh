#!/usr/bin/env bash
# Builds the desktop app and installs it for the current user.
# macOS: Sennel.app into /Applications, or ~/Applications when that is not writable.
# Linux: the AppImage as ~/.local/bin/sennel-desktop, with a menu entry.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
desktop="$root/crates/sennel-desktop"
bundle="$root/target/release/bundle"

for tool in cargo npm; do
  command -v "$tool" >/dev/null || { echo "install-desktop: $tool is not on PATH" >&2; exit 1; }
done

case "$(uname -s)" in
  Darwin) bundles=app ;;
  Linux) bundles=appimage ;;
  *) echo "install-desktop: only macOS and Linux are supported" >&2; exit 1 ;;
esac

npm --prefix "$desktop/ui" ci
(cd "$desktop" && ui/node_modules/.bin/tauri build --bundles "$bundles")

if [ "$bundles" = app ]; then
  apps=/Applications
  [ -w "$apps" ] || { apps="$HOME/Applications"; mkdir -p "$apps"; }
  rm -rf "$apps/Sennel.app.new"
  ditto "$bundle/macos/Sennel.app" "$apps/Sennel.app.new"
  rm -rf "$apps/Sennel.app"
  mv "$apps/Sennel.app.new" "$apps/Sennel.app"
  echo "Installed $apps/Sennel.app"
else
  image="$(ls -t "$bundle"/appimage/*.AppImage | head -n 1)"
  bin="$HOME/.local/bin"
  icons="$HOME/.local/share/icons/hicolor/128x128/apps"
  menu="$HOME/.local/share/applications"
  mkdir -p "$bin" "$icons" "$menu"
  install -m 755 "$image" "$bin/sennel-desktop"
  install -m 644 "$desktop/icons/128x128.png" "$icons/sennel.png"
  cat >"$menu/sennel.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Sennel
Comment=KeePass vaults in a native window
Exec="$bin/sennel-desktop"
Icon=sennel
Categories=Utility;Security;
EOF
  echo "Installed $bin/sennel-desktop"
fi
