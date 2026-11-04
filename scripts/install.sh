#!/usr/bin/env bash
# Builds and installs Sennel for this user: the CLI into ~/.cargo/bin, the desktop app into
# /Applications (~/Applications if not writable) or as ~/.local/bin/sennel-desktop on Linux, or both.
# Asks which in a terminal; --cli, --desktop or --both skip the question.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
desktop="$root/crates/sennel-desktop"
bundle="$root/target/release/bundle"

usage() {
  echo "usage: scripts/install.sh [--cli | --desktop | --both]"
}

choice=""
case "${1:-}" in
  --cli) choice=cli ;;
  --desktop) choice=desktop ;;
  --both) choice=both ;;
  -h | --help) usage; exit 0 ;;
  "") ;;
  *) echo "install: unknown option $1" >&2; usage >&2; exit 2 ;;
esac
[ $# -le 1 ] || { usage >&2; exit 2; }

if [ -z "$choice" ]; then
  # A pipe or CI has nobody to answer, so it must say what it wants.
  [ -t 0 ] || { echo "install: not a terminal, so pass --cli, --desktop or --both" >&2; exit 2; }
  echo "What should be installed?"
  echo "  1) both the terminal app and the desktop app"
  echo "  2) the terminal app and CLI only (sennel)"
  echo "  3) the desktop app only"
  while :; do
    read -r -p "Choose 1, 2 or 3 [1]: " answer || { echo; echo "install: cancelled" >&2; exit 1; }
    case "${answer:-1}" in
      1) choice=both; break ;;
      2) choice=cli; break ;;
      3) choice=desktop; break ;;
      *) echo "Type 1, 2 or 3." ;;
    esac
  done
fi

need=(cargo)
[ "$choice" = cli ] || need+=(npm rustc)
for tool in "${need[@]}"; do
  command -v "$tool" >/dev/null || { echo "install: $tool is not on PATH" >&2; exit 1; }
done

# Checked before anything builds, so `both` never leaves the CLI installed and the desktop failed.
if [ "$choice" != cli ]; then
  case "$(uname -s)" in
    Darwin) bundles=app ;;
    Linux) bundles=appimage ;;
    *) echo "install: the desktop app builds on macOS and Linux only · --cli works elsewhere" >&2; exit 1 ;;
  esac
  # From the clone, so a rust-toolchain.toml there picks the compiler it would build with.
  rust="$(cd "$root" && rustc --version | awk '{print $2}')"
  IFS=. read -r major minor _ <<<"$rust"
  if [ "$major" -lt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -lt 90 ]; }; then
    echo "install: the desktop app needs Rust 1.90 or later, and rustc here is $rust" >&2
    exit 1
  fi
fi

install_cli() {
  # --locked keeps the pins in Cargo.lock, which a plain `cargo install` ignores.
  cargo install --path "$root" --locked
  local bin="${CARGO_HOME:-$HOME/.cargo}/bin"
  echo "Installed $bin/sennel"
  case ":$PATH:" in
    *":$bin:"*) ;;
    *) echo "note: $bin is not on PATH · add it to run sennel by name" >&2 ;;
  esac
}

install_desktop() {
  npm --prefix "$desktop/ui" ci
  (cd "$desktop" && ui/node_modules/.bin/tauri build --bundles "$bundles")

  if [ "$bundles" = app ]; then
    local apps=/Applications
    [ -w "$apps" ] || { apps="$HOME/Applications"; mkdir -p "$apps"; }
    rm -rf "$apps/Sennel.app.new"
    ditto "$bundle/macos/Sennel.app" "$apps/Sennel.app.new"
    rm -rf "$apps/Sennel.app"
    mv "$apps/Sennel.app.new" "$apps/Sennel.app"
    echo "Installed $apps/Sennel.app"
  else
    local image bin icons menu
    image="$(ls -t "$bundle"/appimage/*.AppImage | head -n 1)"
    bin="$HOME/.local/bin"
    icons="$HOME/.local/share/icons/hicolor/128x128/apps"
    menu="$HOME/.local/share/applications"
    mkdir -p "$bin" "$icons" "$menu"
    install -m 755 "$image" "$bin/sennel-desktop"
    install -m 644 "$desktop/icons/128x128.png" "$icons/sennel.png"
    cat >"$menu/sennel.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Sennel
Comment=KeePass vaults in a native window
Exec="$bin/sennel-desktop"
Icon=sennel
Categories=Utility;Security;
DESKTOP
    echo "Installed $bin/sennel-desktop"
  fi
}

case "$choice" in
  cli) install_cli ;;
  desktop) install_desktop ;;
  both) install_cli; install_desktop ;;
esac
