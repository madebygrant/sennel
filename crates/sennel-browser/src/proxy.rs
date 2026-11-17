// The process a browser starts through native messaging. It says which host name it serves, then
// relays frames both ways between the browser's pipes and the desktop app's socket, byte for
// byte. It holds no keys and reads nothing it relays.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;

use crate::transport::{self, APP_HOST, KEEPASSXC_HOST};

// KeePassXC-Browser's store ids, from its Chrome Web Store, Edge Add-ons and Firefox Add-ons
// listings. Only these get the KeePassXC-compatible answers.
pub const KEEPASSXC_CHROME: &str = "oboonakemofpalcgghocfoadofidjkkk";
pub const KEEPASSXC_EDGE: &str = "pdffhmdngciaglkoonimfcmckehcpafo";
pub const KEEPASSXC_FIREFOX: &str = "keepassxc-browser@keepassxc.org";

// Sennel's own extension. The Chrome id follows from the public key in extension/manifest.json, so
// an unpacked build and the store build share it.
pub const SENNEL_CHROME: &str = "naibgmdhaebnonifkllpaiaflpnggnfa";
pub const SENNEL_FIREFOX: &str = "{11f92b7a-7cd2-477c-a988-2a64ef2e2091}";

/// The host name a browser started this process under, from the arguments it passes: Chrome-family
/// browsers pass the calling extension's origin, Firefox the manifest's path and the extension id.
/// None when these are not native messaging arguments.
pub fn host_from_args(args: &[String]) -> Option<&'static str> {
    let first = args.get(1)?;
    if let Some(origin) = first.strip_prefix("chrome-extension://") {
        let id = origin.trim_end_matches('/');
        return Some(if [KEEPASSXC_CHROME, KEEPASSXC_EDGE].contains(&id) {
            KEEPASSXC_HOST
        } else {
            APP_HOST
        });
    }
    let id = args.get(2)?;
    if !first.ends_with(".json") {
        return None;
    }
    Some(if id == KEEPASSXC_FIREFOX {
        KEEPASSXC_HOST
    } else {
        APP_HOST
    })
}

/// Relays until either side closes. The exit code is what the browser sees.
pub fn run(host: &str) -> i32 {
    let Some(path) = transport::socket_path() else {
        return 1;
    };
    let Ok(socket) = UnixStream::connect(&path) else {
        // The app is not running. The extension reads a closed pipe as "not connected".
        return 1;
    };
    let Ok(mut to_app) = socket.try_clone() else {
        return 1;
    };
    if transport::write_frame(&mut to_app, &transport::hello(host)).is_err() {
        return 1;
    }
    let mut from_app = socket;
    let back = std::thread::spawn(move || {
        let mut stdout = io::stdout().lock();
        while let Ok(Some(frame)) = transport::read_frame(&mut from_app) {
            if transport::write_frame(&mut stdout, &frame).is_err() {
                break;
            }
        }
        let _ = stdout.flush();
        // The app went away: ending here closes the browser's pipe, which the extension reads as
        // disconnected, instead of waiting on stdin for a request that would be dropped.
        std::process::exit(0);
    });
    let mut stdin = io::stdin().lock();
    while let Ok(Some(frame)) = transport::read_frame(&mut stdin) {
        if transport::write_frame(&mut to_app, &frame).is_err() {
            break;
        }
    }
    let _ = to_app.shutdown(std::net::Shutdown::Both);
    let _ = back.join();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_host_comes_from_the_caller() {
        let chrome = args(&[
            "sennel",
            "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/",
        ]);
        assert_eq!(host_from_args(&chrome), Some(KEEPASSXC_HOST));
        let edge = args(&[
            "sennel",
            "chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/",
            "--parent-window=0",
        ]);
        assert_eq!(host_from_args(&edge), Some(KEEPASSXC_HOST));
        let other = args(&[
            "sennel",
            "chrome-extension://aaaabbbbccccddddeeeeffffgggghhhh/",
        ]);
        assert_eq!(host_from_args(&other), Some(APP_HOST));
        let firefox = args(&[
            "sennel",
            "/x/org.keepassxc.keepassxc_browser.json",
            KEEPASSXC_FIREFOX,
        ]);
        assert_eq!(host_from_args(&firefox), Some(KEEPASSXC_HOST));
        let firefox_other = args(&["sennel", "/x/app.sennel.browser.json", "sennel@example"]);
        assert_eq!(host_from_args(&firefox_other), Some(APP_HOST));
    }

    #[test]
    fn an_ordinary_launch_is_not_native_messaging() {
        assert_eq!(host_from_args(&args(&["sennel"])), None);
        assert_eq!(host_from_args(&args(&["sennel", "--check"])), None);
        assert_eq!(host_from_args(&args(&["sennel", "vault.kdbx", "x"])), None);
    }
}
