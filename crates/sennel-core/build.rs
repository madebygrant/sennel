// The clipboard, file-mode and file-manager code is written for macOS and
// Linux only, so anywhere else fails here, before any dependency compiles.
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    assert!(
        os == "macos" || os == "linux",
        "sennel-core supports macOS and Linux only (target os: {os})"
    );
}
