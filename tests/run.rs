// `sennel run` end to end: the program it starts, the variables that program sees, and the exit
// code a script reads.

use std::io::Write;
use std::process::{Command, Stdio};

const FIXTURE: &str = "tests/fixtures/keepassxc3.kdbx";

fn run(args: &[&str], stdin: &str) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .args(["--no-config"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not run sennel");
    // A refusal before the prompt exits without reading, so a broken pipe is not a failure.
    if let Err(e) = child
        .stdin
        .take()
        .expect("no stdin")
        .write_all(stdin.as_bytes())
    {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe,
            "could not write stdin: {e}"
        );
    }
    let out = child.wait_with_output().expect("sennel did not finish");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn the_program_sees_each_field_in_its_variable() {
    let (out, err, code) = run(
        &[
            "run",
            "--db",
            FIXTURE,
            "-e",
            "PW=xc entry",
            "-e",
            "WHO=xc entry::username",
            "--",
            "sh",
            "-c",
            "printf '%s %s' \"$PW\" \"$WHO\"",
        ],
        "sennel-fixture\n",
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "sennel-entry-pw octo");
}

#[test]
fn the_programs_exit_code_is_the_exit_code() {
    let (_, err, code) = run(
        &[
            "run", "--db", FIXTURE, "-e", "PW=xc", "--", "sh", "-c", "exit 7",
        ],
        "sennel-fixture\n",
    );
    assert_eq!(code, 7, "{err}");
}

// The password is read a byte at a time, so the rest of the pipe is still there for the program.
#[test]
fn the_rest_of_the_pipe_reaches_the_program() {
    let (out, err, code) = run(
        &["run", "--db", FIXTURE, "-e", "PW=xc", "--", "cat"],
        "sennel-fixture\nfirst line for cat\nsecond\n",
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "first line for cat\nsecond\n");
}

// A file redirect, not a pipe. On Linux, reopening /dev/stdin starts a file over from the top,
// which would replay the master password into the program's stdin.
#[test]
fn a_redirected_file_does_not_hand_the_password_to_the_program() {
    let path = std::env::temp_dir().join(format!("sennel-run-stdin-{}", std::process::id()));
    std::fs::write(&path, "sennel-fixture\nrest of the file\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .args([
            "--no-config",
            "run",
            "--db",
            FIXTURE,
            "-e",
            "PW=xc",
            "--",
            "cat",
        ])
        .stdin(std::fs::File::open(&path).unwrap())
        .output()
        .expect("could not run sennel");
    std::fs::remove_file(&path).ok();
    let printed = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !printed.contains("sennel-fixture"),
        "the master password reached the program"
    );
    assert_eq!(printed, "rest of the file\n");
}

#[test]
fn a_missing_entry_or_field_never_starts_the_program() {
    let marker = "the program ran";
    let (out, err, code) = run(
        &[
            "run",
            "--db",
            FIXTURE,
            "-e",
            "PW=zzzznothing",
            "--",
            "echo",
            marker,
        ],
        "sennel-fixture\n",
    );
    assert_eq!(code, 3, "{err}");
    assert!(!out.contains(marker), "{out}");

    let (out, err, code) = run(
        &[
            "run",
            "--db",
            FIXTURE,
            "-e",
            "K=xc::api key",
            "--",
            "echo",
            marker,
        ],
        "sennel-fixture\n",
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("has no field api key"), "{err}");
    assert!(!out.contains(marker), "{out}");
}

// Refused before the prompt: nobody types a master password to be told the variable was a typo.
#[test]
fn a_bad_reference_is_refused_before_the_password() {
    for (bad, said) in [
        ("1PW=xc", "not an environment variable name"),
        ("PW", "needs the form VAR=NEEDLE"),
        ("PW=", "names no entry"),
        ("PW=xc::", "names no field"),
    ] {
        let (_, err, code) = run(&["run", "--db", FIXTURE, "-e", bad, "--", "true"], "");
        assert_eq!(code, 1, "{bad}: {err}");
        assert!(err.contains(said), "{bad}: {err}");
    }
    let (_, err, code) = run(
        &[
            "run",
            "--db",
            FIXTURE,
            "-e",
            "PW=xc",
            "-e",
            "PW=xc::url",
            "--",
            "true",
        ],
        "",
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("PW is set twice"), "{err}");
}

#[test]
fn an_env_file_names_the_entries_and_the_command_line_wins() {
    let path = std::env::temp_dir().join(format!("sennel-run-envfile-{}", std::process::id()));
    std::fs::write(
        &path,
        "# no secrets here\nPW=\"xc entry\"\nWHO=xc::username\n",
    )
    .unwrap();
    let file = path.to_str().unwrap();
    let (out, err, code) = run(
        &[
            "run",
            "--db",
            FIXTURE,
            "--env-file",
            file,
            "-e",
            "WHO=xc::url",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$PW\" \"$WHO\"",
        ],
        "sennel-fixture\n",
    );
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 0, "{err}");
    let (pw, who) = out.split_once('|').unwrap();
    assert_eq!(pw, "sennel-entry-pw");
    assert_ne!(who, "octo", "the command line did not override the file");
}

// The format accepts `.env` syntax, so a real `.env` full of secrets is an easy mistake. Its values
// must never come back in a message, where a terminal, a log or an agent would see them.
#[test]
fn a_real_dotenv_file_never_has_its_values_printed() {
    let path = std::env::temp_dir().join(format!("sennel-run-dotenv-{}", std::process::id()));
    std::fs::write(&path, "DATABASE_URL=postgres://app:s3cret@db/prod\n").unwrap();
    let file = path.to_str().unwrap();
    let (out, err, code) = run(
        &["run", "--db", FIXTURE, "--env-file", file, "--", "true"],
        "sennel-fixture\n",
    );
    assert_eq!(code, 3, "{err}");
    assert!(!err.contains("s3cret") && !out.contains("s3cret"), "{err}");
    assert!(err.contains(&format!("DATABASE_URL at {file}:1")), "{err}");

    std::fs::write(&path, "sk_live_s3cret\n").unwrap();
    let (_, err, code) = run(
        &["run", "--db", FIXTURE, "--env-file", file, "--", "true"],
        "",
    );
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 1, "{err}");
    assert!(!err.contains("s3cret"), "{err}");
    assert!(err.contains(&format!("{file}:1: needs the form")), "{err}");
}

#[test]
fn a_group_scopes_every_lookup() {
    let kdbx4 = "tests/fixtures/keepassxc4.kdbx";
    let (out, err, code) = run(
        &[
            "run",
            "--db",
            kdbx4,
            "--group",
            "banks",
            "-e",
            "WHO=checking::username",
            "--",
            "sh",
            "-c",
            "printf %s \"$WHO\"",
        ],
        "sennel-fixture\n",
    );
    assert_eq!((out.as_str(), code), ("octo", 0), "{err}");

    let (_, err, code) = run(
        &[
            "run",
            "--db",
            kdbx4,
            "--group",
            "Banks",
            "-e",
            "X=zzzznothing",
            "--",
            "true",
        ],
        "sennel-fixture\n",
    );
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("in Banks"), "{err}");

    let (_, err, code) = run(
        &[
            "run",
            "--db",
            kdbx4,
            "--group",
            "Nope",
            "-e",
            "X=checking",
            "--",
            "true",
        ],
        "sennel-fixture\n",
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("no group Nope"), "{err}");
}

#[test]
fn a_program_that_is_not_there_exits_127() {
    let (_, err, code) = run(
        &[
            "run",
            "--db",
            FIXTURE,
            "-e",
            "PW=xc",
            "--",
            "sennel-no-such-program",
        ],
        "sennel-fixture\n",
    );
    assert_eq!(code, 127, "{err}");
    assert!(err.contains("cannot run sennel-no-such-program"), "{err}");
}
