use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

/// KeePass-style terminal password manager.
#[derive(Parser, Debug)]
#[command(name = "sennel", version, about, long_about = None)]
pub struct Cli {
    /// Path to the .kdbx database. Omit it and sennel asks for one.
    #[arg(long, value_name = "PATH")]
    pub db: Option<String>,

    /// Seconds a copied secret stays on the clipboard before it is cleared
    #[arg(long, value_name = "SECS")]
    pub clipboard_timeout: Option<u64>,

    /// Seconds of idle time before the vault locks (0 disables)
    #[arg(long, value_name = "SECS")]
    pub lock_timeout: Option<u64>,

    /// Check the clipboard backend, the database path and the config, then exit
    #[arg(long)]
    pub check: bool,

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
}

impl FileConfig {
    /// `required` when the path came from --config: naming a file sennel
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
        /* A typo'd key silently ignored would look like sennel disregarding
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
    /// Where a setting changed in the tool gets written back. `None` under
    /// --no-config, which asked for the file to be left out of the run and
    /// so cannot be the place a choice is remembered.
    pub config_file: Option<PathBuf>,
    pub check: bool,
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
            config_file,
            check: cli.check,
        })
    }

    /// Shown in the help overlay, so a session's settings are visible without
    /// remembering which flags were passed.
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

    #[test]
    fn a_named_config_must_exist() {
        let missing = std::env::temp_dir().join("sennel-test-absent.toml");
        let _ = std::fs::remove_file(&missing);
        assert!(FileConfig::load(&missing, false).is_ok(), "default path may be absent");
        let err = FileConfig::load(&missing, true).unwrap_err().to_string();
        assert!(err.contains("reading"), "{err}");
    }
}
