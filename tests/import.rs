// `sennel import` end to end: what a CSV can and cannot do to the vault it lands in.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const FIXTURE: &str = "tests/fixtures/keepassxc4.kdbx";
const PASSWORD: &str = "sennel-fixture\n";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sennel-import-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(FIXTURE, dir.join("vault.kdbx")).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }

    fn sennel(&self, args: &[&str]) -> (String, String, i32) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sennel"))
            .arg("--no-config")
            .args(args)
            .env("XDG_STATE_HOME", &self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("could not run sennel");
        if let Err(e) = child.stdin.take().unwrap().write_all(PASSWORD.as_bytes()) {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
        }
        let out = child.wait_with_output().unwrap();
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn csv_with_group_depth(depth: usize) -> String {
    format!(
        "Title,Username,Password,Group\nbottom,u,p,{}\n",
        vec!["g"; depth].join("/")
    )
}

#[test]
fn a_group_column_too_deep_to_reopen_leaves_the_vault_untouched() {
    let s = Scratch::new("deep");
    let db = s.path("vault.kdbx");
    let before = std::fs::read(&db).unwrap();
    std::fs::write(s.path("deep.csv"), csv_with_group_depth(64)).unwrap();

    let (_, err, code) = s.sennel(&["import", &s.path("deep.csv"), "--db", &db]);
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("row 1"), "{err}");
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

#[test]
fn the_deepest_group_column_allowed_imports_and_reopens() {
    let s = Scratch::new("fits");
    let db = s.path("vault.kdbx");
    std::fs::write(s.path("fits.csv"), csv_with_group_depth(63)).unwrap();

    let (out, err, code) = s.sennel(&["import", &s.path("fits.csv"), "--db", &db]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("imported 1 entries"), "{out}");

    let (out, err, code) = s.sennel(&["--list", "--db", &db]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("bottom"), "{out}");
}
