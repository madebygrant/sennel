// `sennel env` end to end: a .env file into the vault, back out, and into a program with `run`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FIXTURE: &str = "tests/fixtures/keepassxc4.kdbx";
const PASSWORD: &str = "sennel-fixture\n";

const DOTENV: &str = "\
# Database

# Main Postgres
DATABASE_URL=postgres://app:s3cret@db/app
# OLD_KEY=sk-old-s3cret
export API_KEY='k y'  # live
";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sennel-env-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(FIXTURE, dir.join("vault.kdbx")).unwrap();
        Scratch(dir)
    }

    fn vault(&self) -> String {
        self.0.join("vault.kdbx").to_str().unwrap().to_string()
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn sennel(&self, args: &[&str], stdin: &str) -> (String, String, i32) {
        sennel_in(&self.0, args, stdin)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn sennel_in(dir: &Path, args: &[&str], stdin: &str) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sennel"))
        .arg("--no-config")
        .args(args)
        // Backups of the scratch vault land in the scratch folder, not the user's state dir.
        .env("XDG_STATE_HOME", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not run sennel");
    if let Err(e) = child
        .stdin
        .take()
        .expect("no stdin")
        .write_all(stdin.as_bytes())
    {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().expect("sennel did not finish");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn an_imported_file_exports_as_it_was_and_runs_without_the_commented_out_key() {
    let s = Scratch::new("round");
    let db = s.vault();
    let file = s.file(".env", DOTENV);
    let (out, err, code) = s.sennel(&["env", "import", "Acme API", &file, "--db", &db], PASSWORD);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("stored 3 variables in Acme API"), "{out}");
    assert!(err.contains("still plaintext"), "{err}");
    assert!(
        !out.contains("s3cret") && !err.contains("s3cret"),
        "{out}{err}"
    );

    let (out, err, code) = s.sennel(&["env", "export", "Acme API", "--db", &db], PASSWORD);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        "# Database\n\n# Main Postgres\nDATABASE_URL=postgres://app:s3cret@db/app\n\
         # OLD_KEY=sk-old-s3cret\nexport API_KEY='k y' # live\n"
    );

    let (out, err, code) = s.sennel(
        &[
            "run",
            "--db",
            &db,
            "--entry",
            "Acme API",
            "-e",
            "API_KEY=checking::username",
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s' \"$DATABASE_URL\" \"$API_KEY\" \"${OLD_KEY-unset}\"",
        ],
        PASSWORD,
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "postgres://app:s3cret@db/app|octo|unset");
}

#[test]
fn importing_again_replaces_and_a_dry_run_writes_nothing() {
    let s = Scratch::new("again");
    let db = s.vault();
    let file = s.file(".env", "A=1\nB=2\n");
    let (_, err, code) = s.sennel(&["env", "import", "App", &file, "--db", &db], PASSWORD);
    assert_eq!(code, 0, "{err}");

    let before = std::fs::read(&db).unwrap();
    let file = s.file(".env", "A=1\nC=3\n");
    let (out, err, code) = s.sennel(
        &["env", "import", "App", &file, "--db", &db, "--dry-run"],
        PASSWORD,
    );
    assert_eq!(code, 0, "{err}");
    for line in ["same     A", "new      C", "removed  B", "would update App"] {
        assert!(out.contains(line), "{line:?} missing from {out}");
    }
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "a dry run wrote the vault"
    );

    let (_, err, code) = s.sennel(&["env", "import", "App", &file, "--db", &db], PASSWORD);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("would remove 1 variable the file does not have"),
        "{err}"
    );
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "a refused import wrote the vault"
    );

    let (_, err, code) = s.sennel(
        &["env", "import", "App", &file, "--db", &db, "--replace"],
        PASSWORD,
    );
    assert_eq!(code, 0, "{err}");
    let (out, _, _) = s.sennel(&["env", "export", "App", "--db", &db], PASSWORD);
    assert_eq!(out, "A=1\nC=3\n");
}

#[test]
fn two_entries_setting_one_variable_never_start_the_program() {
    let s = Scratch::new("twice");
    let db = s.vault();
    for title in ["One", "Two"] {
        let file = s.file(".env", "SHARED=x\n");
        let (_, err, code) = s.sennel(&["env", "import", title, &file, "--db", &db], PASSWORD);
        assert_eq!(code, 0, "{err}");
    }
    let (out, err, code) = s.sennel(
        &[
            "run", "--db", &db, "--entry", "One", "--entry", "Two", "--", "echo", "ran",
        ],
        PASSWORD,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("SHARED is set twice"), "{err}");
    assert!(!out.contains("ran"), "{out}");
}

#[test]
fn an_oversized_pipe_is_refused_by_size_before_the_password() {
    let s = Scratch::new("huge");
    let db = s.vault();
    // A multibyte character straddling the limit must not turn this into a UTF-8 error.
    let huge = "é".repeat(200 * 1024);
    let (_, err, code) = s.sennel(&["env", "import", "App", "-", "--db", &db], &huge);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("stdin is over 256 KB"), "{err}");
}

#[test]
fn a_bad_line_or_a_login_title_writes_nothing() {
    let s = Scratch::new("bad");
    let db = s.vault();
    let before = std::fs::read(&db).unwrap();
    let file = s.file(".env", "A=1\nsk_live_s3cret\n");
    let (_, err, code) = s.sennel(&["env", "import", "App", &file, "--db", &db], "");
    assert_eq!(code, 1, "{err}");
    assert!(err.contains(".env:2: not NAME=value"), "{err}");
    assert!(!err.contains("s3cret"), "{err}");

    let file = s.file(".env", "A=1\n");
    let (_, err, code) = s.sennel(&["env", "import", "checking", &file, "--db", &db], PASSWORD);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("checking is not an env entry"), "{err}");
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

#[test]
fn run_refuses_a_login_as_an_entry_and_a_run_with_nothing_to_set() {
    let (_, err, code) = sennel_in(
        &std::env::temp_dir(),
        &["run", "--db", FIXTURE, "--entry", "checking", "--", "true"],
        PASSWORD,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("checking is not an env entry"), "{err}");

    let (_, err, code) = sennel_in(
        &std::env::temp_dir(),
        &["run", "--db", FIXTURE, "--", "true"],
        "",
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--entry NEEDLE"), "{err}");
}

#[test]
fn a_file_on_stdin_leaves_the_password_to_the_terminal() {
    let s = Scratch::new("stdin");
    let db = s.vault();
    // The pipe carries the file, so there is no second line for the password, and no tty in a test.
    let (_, err, code) = s.sennel(&["env", "import", "App", "-", "--db", &db], "A=1\n");
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("password needs a terminal"), "{err}");
}
