// KeePass field references end to end: `get` and `run` hand out what a reference points at, and a
// broken one is an error, never its raw `{REF:...}` text passed off as the value.

use std::io::Write;
use std::process::{Command, Stdio};

use sennel_core::vault::Vault;

const PASSWORD: &str = "references-test";

struct Temp(std::path::PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

// A vault with `mail`, an alias pointing at it by ID, and an alias pointing at nothing.
fn vault() -> Temp {
    let path = std::env::temp_dir().join(format!(
        "sennel-references-{}-{:?}.kdbx",
        std::process::id(),
        std::thread::current().id()
    ));
    let mut v = Vault::new();
    let root = v.root_id();
    let mail = v
        .create_entry(&root, "mail", "ada", "s3cret", "", "")
        .unwrap();
    let hex = v
        .get_entry(&mail)
        .unwrap()
        .id()
        .uuid()
        .simple()
        .to_string()
        .to_uppercase();
    v.create_entry(
        &root,
        "alias",
        &format!("{{REF:U@I:{hex}}}"),
        &format!("{{REF:P@I:{hex}}}"),
        "",
        "",
    )
    .unwrap();
    v.create_entry(
        &root,
        "broken",
        "",
        "{REF:P@I:00000000000000000000000000000000}",
        "",
        "",
    )
    .unwrap();
    // A reference carrying an escape: a shared vault's author can put this in any field.
    v.create_entry(
        &root,
        "escape",
        "",
        "{REF:P@I:\u{1b}]0;owned\u{7}zz}",
        "",
        "",
    )
    .unwrap();
    v.save_as(&path, PASSWORD, None).unwrap();
    Temp(path)
}

fn sennel(args: &[&str]) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .arg("--no-config")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not run sennel");
    let line = format!("{PASSWORD}\n");
    if let Err(e) = child.stdin.take().unwrap().write_all(line.as_bytes()) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn get_and_run_hand_out_what_a_reference_points_at() {
    let file = vault();
    let db = file.0.to_str().unwrap();
    let (out, err, code) = sennel(&["get", "alias", "-p", "--stdout", "--db", db]);
    assert_eq!((out.as_str(), code), ("s3cret\n", 0), "{err}");

    let (out, err, code) = sennel(&[
        "run",
        "--db",
        db,
        "-e",
        "PW=alias",
        "-e",
        "WHO=alias::username",
        "--",
        "sh",
        "-c",
        "printf '%s %s' \"$PW\" \"$WHO\"",
    ]);
    assert_eq!((out.as_str(), code), ("s3cret ada", 0), "{err}");
}

#[test]
fn a_broken_reference_is_an_error_and_never_handed_out() {
    let file = vault();
    let db = file.0.to_str().unwrap();
    let (out, err, code) = sennel(&["get", "broken", "-p", "--stdout", "--db", db]);
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "something was printed: {out}");
    assert!(err.contains("not in this vault"), "{err}");

    let (out, err, code) = sennel(&["run", "--db", db, "-e", "PW=broken", "--", "echo", "ran"]);
    assert_eq!(code, 1, "{err}");
    assert!(!out.contains("ran"), "the program started: {out}");
}

// The alias shares the target's password on purpose, so the audit must not call it reuse.
#[test]
fn the_audit_does_not_call_a_reference_reuse() {
    let file = vault();
    let (out, err, code) = sennel(&["audit", "--db", file.0.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("reused"), "{out}");
    assert!(
        !out.contains("alias"),
        "the alias was judged as a password: {out}"
    );
}

#[test]
fn a_reference_error_never_carries_vault_text_to_the_terminal() {
    let file = vault();
    let db = file.0.to_str().unwrap();
    let runs: [&[&str]; 2] = [
        &["get", "escape", "-p", "--stdout", "--db", db],
        &["run", "--db", db, "-e", "PW=escape", "--", "echo", "ran"],
    ];
    for args in runs {
        let (_, err, code) = sennel(args);
        assert_eq!(code, 1, "{err}");
        let raw = err.chars().find(|c| c.is_control() && *c != '\n');
        assert_eq!(raw, None, "{args:?} printed a control character: {err:?}");
    }
}
