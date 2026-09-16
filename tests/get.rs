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

/* `sennel import` end to end. Migration is when people try a new password
   manager, so the thing worth pinning is that a real export from another tool
   lands, and that a dry run says so without touching the vault or asking for
   a password. */
#[test]
fn import_dry_run_needs_no_password_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("sennel-imp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("bitwarden.csv");
    std::fs::write(
        &csv,
        "folder,favorite,type,name,notes,login_uri,login_username,login_password\n\
         Work,,login,jira,a note,https://j.example,octo,pw\n\
         ,,login,mail,,https://m.example,octo,pw2\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .args([
            "import",
            csv.to_str().unwrap(),
            "--dry-run",
            "--db",
            FIXTURE,
        ])
        .stdin(Stdio::null())
        .output()
        .expect("could not run sennel");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stdout.contains("2 entries would go into"), "{stdout}");
    assert!(stdout.contains("jira"), "{stdout}");
    assert!(stdout.contains("(Work)"), "{stdout}");
    /* Columns nothing was done with are named, so nobody discovers the
       dropped ones months later. */
    assert!(stderr.contains("favorite"), "{stderr}");

    // A file with no title column is refused, and the message says what it saw.
    let bad = dir.join("bad.csv");
    std::fs::write(&bad, "user,pass\nocto,pw\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .args(["import", bad.to_str().unwrap(), "--dry-run", "--db", FIXTURE])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no title column"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_file(&csv).ok();
    std::fs::remove_file(&bad).ok();
}


/* `sennel audit` offline. The `--pwned` half is not tested here: it reaches
   the real Have I Been Pwned API, and a test that needs the internet fails on
   a train rather than when the code is wrong. Its arithmetic — the hash, the
   five characters that leave, the suffix match — is unit-tested instead. */
#[test]
fn audit_prints_the_findings_without_printing_the_passwords() {
    let (out, err, code) = run(&["audit", "--db", FIXTURE]);
    assert_eq!(code, 0, "{err}");
    /* The fixture's one entry has a strong unique password, so the clean
       answer is the one being pinned — including that it says so rather than
       printing nothing at all. */
    assert!(out.contains("nothing reused, weak, expired or empty"), "{out}");
    assert!(!out.contains("sennel-entry-pw"), "the audit printed a password");
}

/* Completions and the man page are generated from the same clap definition
   the binary parses with, so the only way they drift is if the generation
   stops running. That, and working without a vault, is what this pins. */
#[test]
fn completions_and_the_man_page_need_no_vault() {
    for shell in ["bash", "zsh", "fish", "elvish"] {
        let out = Command::new(env!("CARGO_BIN_EXE_sennel"))
            .args(["completions", shell])
            .env("HOME", "/nonexistent")
            .output()
            .unwrap();
        let script = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{shell}");
        assert!(!script.is_empty(), "{shell} produced nothing");
        // Every subcommand has to be in it, or the completion lies.
        for verb in ["get", "import", "audit"] {
            assert!(script.contains(verb), "{shell} completion is missing {verb}");
        }
    }

    let out = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .args(["man"])
        .env("HOME", "/nonexistent")
        .output()
        .unwrap();
    let page = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0));
    assert!(page.starts_with(".ie"), "not roff: {}", &page[..40.min(page.len())]);
    assert!(page.contains(".TH sennel 1"), "{page}");
}

/* Hardening has to cover every way into the program, not just the TUI. It
   used to sit on the TUI path only, so `get`, `audit` and `import` unlocked
   the vault with core dumps still enabled — and those are the two paths that
   sit around holding secrets, one sleeping out the clipboard wipe and one
   waiting on the network.

   Launched through `sh -c 'ulimit -c unlimited'`, because the limit is
   already 0 on a default macOS shell: spawning sennel directly would pass
   whether or not it hardens anything, which is what the first version of
   this test did. The parent raises the limit, so only sennel can lower it.

   `--check` reads the limit back rather than assuming it, and `--check` is
   itself one of the early returns, so seeing it there is the proof that
   `harden` runs ahead of all of them. */
#[test]
fn every_entry_point_disables_core_dumps() {
    let exe = env!("CARGO_BIN_EXE_sennel");
    let raised = Command::new("sh")
        .arg("-c")
        .arg(format!("ulimit -c unlimited 2>/dev/null; exec {exe} --check --no-config"))
        .output()
        .expect("could not run sennel under sh");
    let text = String::from_utf8_lossy(&raised.stdout);
    assert!(text.contains("hardened  core dumps off"), "{text}");
    assert!(!text.contains("STILL ON"), "{text}");

    /* And the check is not simply printing a constant: with the limit raised
       and the hardening skipped, it has to say so. `--version` exits before
       anything, so this asks the shell itself what it sees. */
    let unhardened = Command::new("sh")
        .arg("-c")
        .arg("ulimit -c unlimited 2>/dev/null; ulimit -c")
        .output()
        .unwrap();
    let limit = String::from_utf8_lossy(&unhardened.stdout).trim().to_string();
    assert!(
        limit == "unlimited" || limit.parse::<u64>().unwrap_or(0) > 0,
        "this machine will not raise the core limit, so the test above proves nothing · got {limit:?}"
    );
}

/* `sennel convert` end to end. A conversion is the one operation where a bug
   costs the whole vault, so what is pinned is mostly what it refuses to do:
   touch the original, overwrite anything, or claim success without reading
   back what it wrote. */
#[test]
fn convert_writes_a_kdbx4_copy_and_leaves_the_original_alone() {
    let dir = std::env::temp_dir().join(format!("sennel-conv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let old = dir.join("old.kdbx");
    let new = dir.join("old-kdbx4.kdbx");
    std::fs::remove_file(&new).ok();
    std::fs::copy(FIXTURE, &old).unwrap();
    let before = std::fs::read(&old).unwrap();

    let (out, err, code) = run(&["convert", "--db", old.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("KDBX 3.1 → KDBX 4"), "{out}");
    assert!(out.contains("verified"), "{out}");
    // The original is byte-for-byte what it was.
    assert_eq!(std::fs::read(&old).unwrap(), before, "the original was written to");

    /* The copy opens with the same password — no second prompt means the
       key came from the original, and this is the proof. */
    let (out, err, code) = run(&["get", "xc entry", "-p", "--stdout", "--db", new.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "sennel-entry-pw\n");

    // And it is writable, which was the entire point.
    let (out, _, _) = run(&["--check", "--db", new.to_str().unwrap()]);
    assert!(out.contains("writable"), "{out}");

    // Owner-only, like every other file Sennel writes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&new).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    /* Run again and it refuses rather than overwriting the copy it made. */
    let (_, err, code) = run(&["convert", "--db", old.to_str().unwrap()]);
    assert_eq!(code, 1, "a second convert overwrote the first");
    assert!(err.contains("already there"), "{err}");

    // A vault that is already KDBX 4 has nothing to convert, and says so.
    let (_, err, code) = run(&["convert", "--db", new.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("nothing to convert"), "{err}");

    // And it will not be aimed at the original.
    let (_, err, code) = run(&[
        "convert",
        "--db",
        old.to_str().unwrap(),
        "--to",
        old.to_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("over the original"), "{err}");

    std::fs::remove_file(&old).ok();
    std::fs::remove_file(&new).ok();
}

/* Every printing path survives a reader that stops early. `sennel --check |
   head` used to panic on the broken pipe, and `sennel man | head` reported
   "Error: Broken pipe" and exited 1 — both of them a normal thing to type,
   and neither of them a failure of the command. The vault-opening paths are
   the reason this is not left to SIGPIPE: dying by signal would skip every
   zeroize on the way out. */
#[test]
fn a_reader_that_stops_early_is_not_an_error() {
    for args in [
        vec!["--check"],
        vec!["man"],
        vec!["completions", "zsh"],
        vec!["--list", "--db", FIXTURE],
        vec!["audit", "--db", FIXTURE],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sennel"))
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("could not run sennel");
        let mut stdin = child.stdin.take().expect("no stdin");
        let _ = stdin.write_all(PASSWORD.as_bytes());
        drop(stdin);
        /* The reader closing before the writer is done, which is all `head`
           does. Dropped before the wait, so the writes land on a pipe with
           nobody on the other end. */
        drop(child.stdout.take());
        let out = child.wait_with_output().expect("sennel did not finish");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            !stderr.contains("panicked"),
            "{args:?} panicked into a closed pipe: {stderr}"
        );
        assert!(
            !stderr.contains("Broken pipe"),
            "{args:?} called a closed pipe an error: {stderr}"
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} exited {:?} · stderr: {stderr}",
            out.status.code()
        );
    }
}
