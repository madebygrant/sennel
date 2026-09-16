/* `sennel get` end to end, through the binary cargo just built. Its contract
   is a process contract — what lands on stdout, what lands on stderr, and the
   exit code a script branches on — and none of that is reachable from a unit
   test of the functions inside.

   An integration test rather than one in `main.rs`, because
   `CARGO_BIN_EXE_sennel` is the only way to be sure the binary under test is
   the one from this build and not a stale one left in target/. */

use std::io::Write;
use std::process::{Command, Stdio};

/// A real KeePassXC-written vault, so this pins the non-interactive path
/// against somebody else's file and not only against one Sennel wrote.
const FIXTURE: &str = "tests/fixtures/keepassxc3.kdbx";
const PASSWORD: &str = "sennel-fixture\n";

fn run(args: &[&str]) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not run sennel");
    // The master password arrives down the pipe, which is how a script gives it.
    child
        .stdin
        .as_mut()
        .expect("no stdin")
        .write_all(PASSWORD.as_bytes())
        .expect("could not write the password");
    let out = child.wait_with_output().expect("sennel did not finish");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn get_prints_one_field_and_nothing_else() {
    let (out, err, code) = run(&["get", "xc entry", "-p", "--stdout", "--db", FIXTURE]);
    assert_eq!(code, 0, "{err}");
    /* Exactly the secret and a newline: `$(sennel get x -p --stdout)` has to
       be usable, so a label or a countdown on stdout would be a bug. */
    assert_eq!(out, "sennel-entry-pw\n");

    let (out, err, code) = run(&["get", "xc", "-u", "--stdout", "--db", FIXTURE]);
    assert_eq!((out.as_str(), code), ("octo\n", 0), "{err}");

    // The password defaults, so the common case needs no flag at all.
    let (out, _, code) = run(&["get", "xc", "--stdout", "--db", FIXTURE]);
    assert_eq!((out.as_str(), code), ("sennel-entry-pw\n", 0));
}

/* The codes a script branches on, kept apart: a retry with a longer needle
   wants to know whether it found too many or none at all. */
#[test]
fn get_separates_not_found_from_every_other_failure() {
    let (out, err, code) = run(&["get", "zzzznothing", "--stdout", "--db", FIXTURE]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("nothing matches"), "{err}");
    assert!(out.is_empty(), "a miss wrote to stdout: {out}");

    // A vault that is not there is an error, not a miss.
    let (_, err, code) = run(&["get", "xc", "--stdout", "--db", "/nope/missing.kdbx"]);
    assert_eq!(code, 1, "{err}");

    // So is a wrong password, and the message says which.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .args(["get", "xc", "--stdout", "--db", FIXTURE])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"wrong\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.to_lowercase().contains("password"), "{err}");
}

/* Two fields would mean one clipboard silently winning, and the user could
   not tell which one they pasted. */
#[test]
fn get_refuses_two_fields_at_once() {
    let (_, err, code) = run(&["get", "xc", "-p", "-u", "--stdout", "--db", FIXTURE]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("name one field"), "{err}");
}

/* An entry without the field asked for is an honest error rather than an
   empty line a script would paste as a password. */
#[test]
fn get_says_so_when_the_field_is_empty() {
    let (out, err, code) = run(&["get", "xc", "--otp", "--stdout", "--db", FIXTURE]);
    assert_eq!(code, 1, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("one-time code"), "{err}");
}

/* Vault text reaching a terminal is text somebody else may have written, and
   `--list` and `get` are the two places it leaves the TUI's cell buffer. */
#[test]
fn list_prints_the_inventory_without_secrets() {
    let (out, err, code) = run(&["--list", "--db", FIXTURE]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("xc entry"), "{out}");
    assert!(!out.contains("sennel-entry-pw"), "--list printed a password");
}
