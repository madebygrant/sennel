/* sennel-tui targets macOS and Linux only. Clipboard handling, the file-manager
   opener and file-mode enforcement are written against those two platforms,
   so compiling anywhere else would produce a binary nobody tested rather
   than an honest error. Fail here, before any dependency compiles. */
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    assert!(
        os == "macos" || os == "linux",
        "sennel-tui supports macOS and Linux only (target os: {os})"
    );
}
