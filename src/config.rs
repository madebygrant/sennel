use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

/// KeePass-style terminal password manager.
#[derive(Parser, Debug)]
#[command(name = "sennel", version, about, long_about = None)]
pub struct Cli {
    /// Path to the .kdbx database. Omit it and Sennel asks for one.
    #[arg(long, value_name = "PATH")]
    pub db: Option<String>,

    /// Seconds a copied secret stays on the clipboard before it is cleared
    #[arg(long, value_name = "SECS")]
    pub clipboard_timeout: Option<u64>,

    /// Seconds of idle time before the vault locks (0 disables)
    #[arg(long, value_name = "SECS")]
    pub lock_timeout: Option<u64>,

    /// Entries order the browser opens in: stored, name, recent or updated
    #[arg(long, value_name = "ORDER")]
    pub sort: Option<String>,

    /// Check the clipboard backend, the database path and the config, then exit
    #[arg(long)]
    pub check: bool,

    /// Print the group and entry inventory (titles only, no secrets), then exit
    #[arg(long, conflicts_with = "check")]
    pub list: bool,

    /// Read this config file instead of the one in ~/.config/sennel
    #[arg(long, value_name = "PATH")]
    pub config: Option<String>,

    /// Ignore the config file entirely
    #[arg(long, conflicts_with = "config")]
    pub no_config: bool,
}

/// Every field optional, so an absent key means "no opinion" and falls through
/// to the built-in default rather than overwriting it.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub db: Option<String>,
    pub clipboard_timeout: Option<u64>,
    pub lock_timeout: Option<u64>,
    /// stored · name · recent · updated. `o` cycles from here rather than
    /// from the built-in default, so the order survives a restart.
    pub sort: Option<String>,
    pub generator: Option<FileGenerator>,
    /// Wheel and click. On by default; off gives the terminal its own
    /// selection back.
    pub mouse: Option<bool>,
}

/// What `^s` produces. Hard-coded before this — 20 characters, no symbols —
/// which is wrong for every site that demands one and every site that
/// forbids them.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileGenerator {
    pub length: Option<usize>,
    pub symbols: Option<bool>,
    pub digits: Option<bool>,
    pub upper: Option<bool>,
    /// Exclude `l 1 I O 0`, which read alike in most fonts.
    pub ambiguous: Option<bool>,
}

/// The generator settings a session runs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generator {
    pub length: usize,
    pub classes: crate::generator::Classes,
    /// True keeps the lookalikes out of the pool.
    pub exclude_ambiguous: bool,
}

impl Default for Generator {
    fn default() -> Self {
        Generator {
            length: 20,
            classes: crate::generator::Classes::default(),
            exclude_ambiguous: true,
        }
    }
}

impl Generator {
    /// How the flash describes what it just made.
    pub fn describe(&self) -> String {
        let mut has = vec!["a–z"];
        if self.classes.upper {
            has.push("A–Z");
        }
        if self.classes.digits {
            has.push("0–9");
        }
        if self.classes.symbols {
            has.push("!@#");
        }
        has.join(" ")
    }
}

impl FileConfig {
    /// `required` when the path came from --config: naming a file Sennel
    /// then ignores is worse than no config at all, so only the default
    /// location is allowed to be absent.
    pub fn load(path: &std::path::Path, required: bool) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
                return Ok(Self::default());
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        /* A typo'd key silently ignored would look like Sennel disregarding
           the setting, so deny_unknown_fields turns it into a startup error. */
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }
}

/// How long a copied secret survives on the clipboard. Long enough to switch
/// windows and paste, short enough that it is gone before anyone goes looking.
pub const DEFAULT_CLIPBOARD_TIMEOUT: u64 = 15;
/// Idle seconds before the vault locks and its secrets are wiped. Zero
/// disables the lock, which is only sensible on a machine nobody else touches.
pub const DEFAULT_LOCK_TIMEOUT: u64 = 300;

pub fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map_or_else(|| expand("~/.config"), PathBuf::from);
    base.join("sennel").join("config.toml")
}

pub struct Config {
    /// The database to open. `None` means ask, since a password manager
    /// without a vault is a question, not an error.
    pub db: Option<PathBuf>,
    pub clipboard_timeout: u64,
    pub lock_timeout: u64,
    /// Where the entries pane starts. Session-only before this: pressing `o`
    /// four times after every restart is a setting nobody asked to retype.
    pub sort: crate::app::SortOrder,
    pub generator: Generator,
    pub mouse: bool,
    /// Where a setting changed in the tool gets written back. `None` under
    /// --no-config, which asked for the file to be left out of the run and
    /// so cannot be the place a choice is remembered.
    pub config_file: Option<PathBuf>,
    pub check: bool,
    pub list: bool,
}

impl Config {
    /* Values, not negations, so the rule is simpler than earworm's: the
       command line wins, then the file, then the built-in default. */
    pub fn build(cli: Cli) -> Result<Self> {
        let mut config_file = None;
        let file = if cli.no_config {
            FileConfig::default()
        } else {
            let named = cli.config.as_ref();
            let path = named.map_or_else(config_path, |p| expand(p));
            let loaded = FileConfig::load(&path, named.is_some())?;
            config_file = Some(path);
            loaded
        };

        let db = cli
            .db
            .map(|d| expand(&d))
            .or_else(|| file.db.as_deref().map(expand));

        Ok(Config {
            db,
            clipboard_timeout: cli
                .clipboard_timeout
                .or(file.clipboard_timeout)
                .unwrap_or(DEFAULT_CLIPBOARD_TIMEOUT),
            lock_timeout: cli
                .lock_timeout
                .or(file.lock_timeout)
                .unwrap_or(DEFAULT_LOCK_TIMEOUT),
            sort: order(cli.sort.as_deref().or(file.sort.as_deref()))?,
            generator: generator(file.generator.as_ref())?,
            mouse: file.mouse.unwrap_or(true),
            config_file,
            check: cli.check,
            list: cli.list,
        })
    }

    /// Shown in the help overlay, so a session's settings are visible without
    /// remembering which flags were passed.
    /* Unused until a settings write-back exists; kept because the wording is
       the one place the effective values are summarised in one line. */
    #[allow(dead_code)]
    pub fn describe(&self) -> String {
        let db = self
            .db
            .as_ref()
            .map_or_else(|| "no vault".to_string(), |p| p.display().to_string());
        format!(
            "db {db} · clipboard {}s · lock {}s",
            self.clipboard_timeout, self.lock_timeout
        )
    }
}

/* A name Sennel does not know is a startup error, not a silent fallback to
   stored order: an ignored setting looks like a setting that does nothing. */
fn order(name: Option<&str>) -> Result<crate::app::SortOrder> {
    let Some(name) = name else {
        return Ok(crate::app::SortOrder::default());
    };
    crate::app::SortOrder::from_name(name).ok_or_else(|| {
        anyhow::anyhow!("unknown sort {name:?} · stored, name, recent or updated")
    })
}

/* Every field optional, and a length that could never produce a password is
   a startup error rather than a surprise at `^s`. */
fn generator(file: Option<&FileGenerator>) -> Result<Generator> {
    let mut out = Generator::default();
    let Some(file) = file else {
        return Ok(out);
    };
    if let Some(length) = file.length {
        if !(4..=256).contains(&length) {
            anyhow::bail!("generator length {length} is outside 4–256");
        }
        out.length = length;
    }
    if let Some(on) = file.symbols {
        out.classes.symbols = on;
    }
    if let Some(on) = file.digits {
        out.classes.digits = on;
    }
    if let Some(on) = file.upper {
        out.classes.upper = on;
    }
    if let Some(on) = file.ambiguous {
        // The key reads as "allow ambiguous", the flag as "exclude them".
        out.exclude_ambiguous = !on;
    }
    Ok(out)
}

pub fn expand(path: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    if path == "~" {
        return PathBuf::from(home);
    }
    match path.strip_prefix("~/") {
        Some(rest) => PathBuf::from(home).join(rest),
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Runs the real argument parser over a throwaway config file, so the
    /// tests exercise the same parsing path the binary does.
    fn build(toml: &str, args: &[&str]) -> Config {
        let mut file = temp("build");
        write!(file.handle, "{toml}").unwrap();
        let mut argv = vec!["sennel".to_string(), "--config".into(), file.path.clone()];
        argv.extend(args.iter().map(|a| a.to_string()));
        run(argv)
    }

    /// Reads a config file back through the real parser, which is the only
    /// thing that proves a written setting survives a restart.
    fn run(argv: Vec<String>) -> Config {
        let cli = Cli::try_parse_from(argv).unwrap();
        Config::build(cli).unwrap()
    }

    struct Temp {
        handle: std::fs::File,
        path: String,
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /* Unique per call, not just per process: the harness runs tests in
       parallel, and two sharing a path would delete each other's file. */
    fn temp(tag: &str) -> Temp {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sennel-test-{tag}-{}-{n}.toml",
            std::process::id()
        ));
        Temp {
            handle: std::fs::File::create(&path).unwrap(),
            path: path.display().to_string(),
        }
    }

    #[test]
    fn file_supplies_settings() {
        let cfg = build("db = \"/tmp/vault.kdbx\"\nlock_timeout = 60\n", &[]);
        assert_eq!(cfg.db, Some(PathBuf::from("/tmp/vault.kdbx")));
        assert_eq!(cfg.lock_timeout, 60);
        assert_eq!(
            cfg.clipboard_timeout, DEFAULT_CLIPBOARD_TIMEOUT,
            "unmentioned keys keep the built-in default"
        );
    }

    #[test]
    fn command_line_beats_file() {
        let cfg = build("lock_timeout = 60\n", &["--lock-timeout", "10"]);
        assert_eq!(cfg.lock_timeout, 10);
    }

    #[test]
    fn no_config_falls_back_to_the_built_in_defaults() {
        let cfg = run(vec!["sennel".to_string(), "--no-config".into()]);
        assert_eq!(cfg.db, None);
        assert_eq!(cfg.clipboard_timeout, DEFAULT_CLIPBOARD_TIMEOUT);
        assert_eq!(cfg.lock_timeout, DEFAULT_LOCK_TIMEOUT);
    }

    #[test]
    fn no_config_and_config_together_are_rejected() {
        let err = Cli::try_parse_from(["sennel", "--no-config", "--config", "/tmp/x.toml"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn unknown_key_is_an_error() {
        let mut file = temp("unknown");
        writeln!(file.handle, "databse = \"/tmp/x.kdbx\"").unwrap();
        let err = FileConfig::load(std::path::Path::new(&file.path), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("parsing"), "{err}");
    }

    /* The entries order survives a restart, and a name Sennel does not know
       stops startup rather than quietly meaning "stored". */
    #[test]
    fn sort_comes_from_the_file_and_refuses_nonsense() {
        let cfg = build("sort = \"updated\"\n", &[]);
        assert_eq!(cfg.sort, crate::app::SortOrder::Updated);
        let cfg = build("sort = \"updated\"\n", &["--sort", "name"]);
        assert_eq!(cfg.sort, crate::app::SortOrder::Name, "the flag lost to the file");
        let cfg = build("", &[]);
        assert_eq!(cfg.sort, crate::app::SortOrder::Stored);

        let mut file = temp("sort");
        writeln!(file.handle, "sort = \"alphabetical\"").unwrap();
        let cli = Cli::try_parse_from(vec![
            "sennel".to_string(),
            "--config".into(),
            file.path.clone(),
        ])
        .unwrap();
        let err = match Config::build(cli) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an unknown sort name started the session"),
        };
        assert!(err.contains("unknown sort"), "{err}");
    }

    /* `^s` was 20 characters and no symbols, full stop — wrong for every site
       that demands one. A length that could never work stops startup. */
    #[test]
    fn the_generator_reads_the_file_and_refuses_nonsense() {
        let cfg = build("[generator]\nlength = 32\nsymbols = true\n", &[]);
        assert_eq!(cfg.generator.length, 32);
        assert!(cfg.generator.classes.symbols);
        assert!(cfg.generator.exclude_ambiguous, "the default flipped");

        let cfg = build("[generator]\nambiguous = true\n", &[]);
        assert!(!cfg.generator.exclude_ambiguous);

        let cfg = build("", &[]);
        assert_eq!(cfg.generator, Generator::default());

        let mut file = temp("genlen");
        writeln!(file.handle, "[generator]\nlength = 2").unwrap();
        let cli = Cli::try_parse_from(vec![
            "sennel".to_string(),
            "--config".into(),
            file.path.clone(),
        ])
        .unwrap();
        let err = match Config::build(cli) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a two-character generator started the session"),
        };
        assert!(err.contains("outside 4–256"), "{err}");
    }

    #[test]
    fn a_named_config_must_exist() {
        let missing = std::env::temp_dir().join("sennel-test-absent.toml");
        let _ = std::fs::remove_file(&missing);
        assert!(FileConfig::load(&missing, false).is_ok(), "default path may be absent");
        let err = FileConfig::load(&missing, true).unwrap_err().to_string();
        assert!(err.contains("reading"), "{err}");
    }
}
