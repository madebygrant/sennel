// Native messaging registrations: the manifest file each browser reads to find the program for a
// host name. Taking over KeePassXC-Browser's host means writing Sennel's manifest under its name,
// with KeePassXC's own file kept aside so giving it back restores exactly what was there.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::proxy::{KEEPASSXC_CHROME, KEEPASSXC_EDGE, KEEPASSXC_FIREFOX};
use crate::transport::KEEPASSXC_HOST;

// Marks a manifest as Sennel's whatever path it names, so one written by an older or moved copy of
// Sennel is never mistaken for KeePassXC's and kept aside in its place.
const MARK: &str = "Sennel serving KeePassXC-Browser";

pub struct Browser {
    pub name: &'static str,
    // The browser's own folder; a browser counts as installed when it exists.
    root: PathBuf,
    hosts: PathBuf,
    firefox: bool,
}

/// The browsers this user has a profile folder for.
pub fn browsers(home: &Path) -> Vec<Browser> {
    let list: &[(&str, &str, &str, bool)] = if cfg!(target_os = "macos") {
        &[
            (
                "Chrome",
                "Library/Application Support/Google/Chrome",
                "NativeMessagingHosts",
                false,
            ),
            (
                "Chromium",
                "Library/Application Support/Chromium",
                "NativeMessagingHosts",
                false,
            ),
            (
                "Edge",
                "Library/Application Support/Microsoft Edge",
                "NativeMessagingHosts",
                false,
            ),
            (
                "Brave",
                "Library/Application Support/BraveSoftware/Brave-Browser",
                "NativeMessagingHosts",
                false,
            ),
            (
                "Firefox",
                "Library/Application Support/Mozilla",
                "NativeMessagingHosts",
                true,
            ),
        ]
    } else {
        &[
            (
                "Chrome",
                ".config/google-chrome",
                "NativeMessagingHosts",
                false,
            ),
            (
                "Chromium",
                ".config/chromium",
                "NativeMessagingHosts",
                false,
            ),
            (
                "Edge",
                ".config/microsoft-edge",
                "NativeMessagingHosts",
                false,
            ),
            (
                "Brave",
                ".config/BraveSoftware/Brave-Browser",
                "NativeMessagingHosts",
                false,
            ),
            ("Firefox", ".mozilla", "native-messaging-hosts", true),
        ]
    };
    list.iter()
        .map(|(name, root, hosts, firefox)| {
            let root = home.join(root);
            Browser {
                name,
                hosts: root.join(hosts),
                root,
                firefox: *firefox,
            }
        })
        .filter(|b| b.root.is_dir())
        .collect()
}

impl Browser {
    fn file(&self) -> PathBuf {
        self.hosts.join(format!("{KEEPASSXC_HOST}.json"))
    }

    fn backup(&self, aside: &Path) -> PathBuf {
        aside.join(format!("{}-{KEEPASSXC_HOST}.json", self.name))
    }

    // Pinned to KeePassXC-Browser's store ids, so no other extension can reach Sennel through it.
    fn manifest(&self, exe: &Path) -> String {
        let mut value = json!({
            "name": KEEPASSXC_HOST,
            "description": MARK,
            "path": exe,
            "type": "stdio",
        });
        if self.firefox {
            value["allowed_extensions"] = json!([KEEPASSXC_FIREFOX]);
        } else {
            value["allowed_origins"] = json!([
                format!("chrome-extension://{KEEPASSXC_CHROME}/"),
                format!("chrome-extension://{KEEPASSXC_EDGE}/"),
            ]);
        }
        serde_json::to_string_pretty(&value).unwrap_or_default()
    }

    fn read(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&std::fs::read_to_string(self.file()).ok()?).ok()
    }

    // Written by some copy of Sennel.
    fn sennels(&self) -> bool {
        self.read()
            .is_some_and(|v| v.get("description").and_then(|d| d.as_str()) == Some(MARK))
    }

    // Written by this copy.
    fn ours(&self, exe: &Path) -> bool {
        self.sennels()
            && self
                .read()
                .and_then(|v| v.get("path")?.as_str().map(PathBuf::from))
                .is_some_and(|path| path == exe)
    }
}

/// Which installed browsers send KeePassXC-Browser to `exe` right now. KeePassXC rewrites these
/// files when it starts, so this is read fresh each time rather than remembered.
pub fn taken_over(home: &Path, exe: &Path) -> Vec<(&'static str, bool)> {
    browsers(home)
        .into_iter()
        .map(|b| (b.name, b.ours(exe)))
        .collect()
}

/// Points KeePassXC-Browser at `exe` in every installed browser, keeping KeePassXC's file in `aside`.
pub fn take_over(home: &Path, exe: &Path, aside: &Path) -> io::Result<Vec<&'static str>> {
    if let Some(why) = replaceable(exe) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, why));
    }
    private(aside)?;
    let mut done = Vec::new();
    for browser in browsers(home) {
        if browser.ours(exe) {
            done.push(browser.name);
            continue;
        }
        std::fs::create_dir_all(&browser.hosts)?;
        let file = browser.file();
        if file.exists() && !browser.sennels() {
            std::fs::copy(&file, browser.backup(aside))?;
        }
        write_atomic(&file, browser.manifest(exe).as_bytes())?;
        done.push(browser.name);
    }
    Ok(done)
}

/// Undoes `take_over`: KeePassXC's file comes back where there was one, and Sennel's is removed.
/// A file KeePassXC has rewritten since is left alone.
pub fn give_back(home: &Path, aside: &Path) -> io::Result<Vec<&'static str>> {
    let mut done = Vec::new();
    for browser in browsers(home) {
        if !browser.sennels() {
            continue;
        }
        let backup = browser.backup(aside);
        if backup.exists() {
            std::fs::rename(&backup, browser.file())?;
        } else {
            std::fs::remove_file(browser.file())?;
        }
        done.push(browser.name);
    }
    Ok(done)
}

// Why another account could swap the program every browser would start, or None. Programs of this
// user's can still replace it; nothing short of a signed, root-owned install stops that.
fn replaceable(exe: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid has no failure mode.
    let me = unsafe { libc::getuid() };
    for path in exe.ancestors() {
        let Ok(meta) = std::fs::metadata(path) else {
            return Some(format!("cannot check {}", path.display()));
        };
        // /Applications is writable by macOS's admin group, whose members can become root anyway.
        let admins = meta.gid() == 0 || (cfg!(target_os = "macos") && meta.gid() == 80);
        let others = meta.mode() & 0o002 != 0 || (meta.mode() & 0o020 != 0 && !admins);
        if others && meta.mode() & 0o1000 == 0 {
            return Some(format!(
                "{} can be changed by other accounts",
                path.display()
            ));
        }
        if meta.uid() != me && meta.uid() != 0 {
            return Some(format!("{} belongs to another account", path.display()));
        }
    }
    None
}

fn private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

// A browser starting at the same moment reads the old file or the new one, never half of one.
fn write_atomic(file: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = file.with_extension("json.sennel-new");
    std::fs::write(&temp, bytes)?;
    std::fs::rename(&temp, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taking_over_keeps_keepassxcs_file_and_giving_back_restores_it() {
        let home = std::env::temp_dir().join(format!("sennel-registration-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let names: Vec<&str> = browsers(Path::new("/nonexistent"))
            .iter()
            .map(|b| b.name)
            .collect();
        assert!(names.is_empty());
        let (chrome, firefox) = if cfg!(target_os = "macos") {
            (
                "Library/Application Support/Google/Chrome",
                "Library/Application Support/Mozilla",
            )
        } else {
            (".config/google-chrome", ".mozilla")
        };
        std::fs::create_dir_all(home.join(chrome)).unwrap();
        std::fs::create_dir_all(home.join(firefox)).unwrap();
        std::fs::create_dir_all(home.join("bin")).unwrap();
        let exe = &home.join("bin").join("sennel-desktop");
        std::fs::write(exe, "").unwrap();
        let aside = home.join("aside");
        let installed = browsers(&home);
        assert_eq!(installed.len(), 2);
        let theirs = r#"{"name":"org.keepassxc.keepassxc_browser","path":"/x/keepassxc-proxy"}"#;
        std::fs::create_dir_all(&installed[0].hosts).unwrap();
        std::fs::write(installed[0].file(), theirs).unwrap();

        assert_eq!(take_over(&home, exe, &aside).unwrap().len(), 2);
        assert!(taken_over(&home, exe).iter().all(|(_, on)| *on));
        let chrome_manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(installed[0].file()).unwrap()).unwrap();
        assert_eq!(
            chrome_manifest["allowed_origins"][0],
            format!("chrome-extension://{KEEPASSXC_CHROME}/")
        );
        let firefox_manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(installed[1].file()).unwrap()).unwrap();
        assert_eq!(firefox_manifest["allowed_extensions"][0], KEEPASSXC_FIREFOX);

        // A moved copy of Sennel takes over again without keeping the old copy's manifest aside.
        let moved = &home.join("bin").join("moved");
        std::fs::write(moved, "").unwrap();
        take_over(&home, moved, &aside).unwrap();
        assert!(taken_over(&home, moved).iter().all(|(_, on)| *on));

        assert_eq!(give_back(&home, &aside).unwrap().len(), 2);
        assert_eq!(
            std::fs::read_to_string(installed[0].file()).unwrap(),
            theirs
        );
        assert!(!installed[1].file().exists());
        assert!(taken_over(&home, exe).iter().all(|(_, on)| !*on));

        // A program others could replace is never registered.
        use std::os::unix::fs::PermissionsExt;
        let shared = home.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::write(shared.join("sennel"), "").unwrap();
        assert!(take_over(&home, &shared.join("sennel"), &aside).is_err());
        std::fs::remove_dir_all(&home).unwrap();
    }
}
