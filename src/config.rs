use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

/// KeePass-style terminal password manager.
#[derive(Parser, Debug)]
#[command(name = "sennel", version, about, long_about = None)]
pub struct Cli {
    /* Optional, so bare `sennel` still opens the TUI. Everything a
       subcommand needs from the flags above is marked global, or `sennel get
       x --db v.kdbx` would have to put the flag before the verb. */
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Path to the .kdbx database. Omit it and Sennel asks for one.
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<String>,

    /* Every subcommand opens a vault, and a vault with a key file could not
       be opened by any of them — they all passed `None`. Global, so `get`,
       `audit`, `import`, `convert` and `--list` all take it. */
    /// Key file the database also needs, if it has one
    #[arg(long, value_name = "PATH", global = true)]
    pub key_file: Option<String>,

    /// Seconds a copied secret stays on the clipboard before it is cleared
    #[arg(long, value_name = "SECS")]
    pub clipboard_timeout: Option<u64>,

    /// Seconds of idle time before the vault locks (0 disables)
    #[arg(long, value_name = "SECS")]
    pub lock_timeout: Option<u64>,

    /// Entries order the browser opens in: stored, name, recent or updated
    #[arg(long, value_name = "ORDER")]
    pub sort: Option<String>,

    /// Colours to draw in: warm, light, cool or neon
    #[arg(long, value_name = "THEME")]
    pub theme: Option<String>,

    /// Check the clipboard backend, the database path and the config, then exit
    #[arg(long)]
    pub check: bool,

    /// Print the group and entry inventory (titles only, no secrets), then exit
    #[arg(long, conflicts_with = "check")]
    pub list: bool,

    /// Read this config file instead of the one in ~/.config/sennel
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<String>,

    /// Ignore the config file entirely
    #[arg(long, conflicts_with = "config", global = true)]
    pub no_config: bool,
}

/* One verb so far. A subcommand rather than a flag because it takes a
   positional needle and changes what the whole run is for: `sennel` opens a
   TUI, `sennel get` answers a question and exits. */
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Copy one field of the entry a needle finds, without opening the TUI
    Get {
        /// What to look for: fuzzy over titles, usernames, urls and groups
        needle: String,

        /// Copy the username
        #[arg(short = 'u', long)]
        user: bool,

        /// Copy the password (the default when nothing else is named)
        #[arg(short = 'p', long)]
        password: bool,

        /// Copy the url
        #[arg(long)]
        url: bool,

        /// Copy the current one-time code, never the seed behind it
        #[arg(long)]
        otp: bool,

        /// Print the value instead of copying it. Refused into a terminal.
        #[arg(long)]
        stdout: bool,

        /// Print to a terminal anyway, scrollback and all
        #[arg(long, requires = "stdout")]
        force: bool,
    },

        /// Rewrite an older KDBX 3.1 database as KDBX 4, which Sennel can write
    Convert {
        /// Where to write it. Defaults to `<name>-kdbx4.kdbx` beside the original
        #[arg(long, value_name = "PATH")]
        to: Option<String>,
    },

    /// Print a shell completion script: bash, zsh, fish or elvish
    Completions {
        /// The shell to generate for
        shell: clap_complete::Shell,
    },

    /// Print the man page, for `sennel man | man -l -`
    Man,

    /// Print every reused, weak or empty password, without opening the TUI
    Audit {
        /// Also ask Have I Been Pwned whether each password is in a breach.
        /// Only the first five characters of each SHA-1 ever leave the machine.
        #[arg(long)]
        pwned: bool,
    },

    /// Read a CSV export from another password manager into the vault
    Import {
        /// The .csv file another tool exported
        file: String,

        /// Put everything under this group instead of `Imported <date>`
        #[arg(long, value_name = "NAME")]
        group: Option<String>,

        /// Say what would be imported and write nothing
        #[arg(long)]
        dry_run: bool,
    },
}

/// Which field `get` was asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    User,
    Password,
    Url,
    Otp,
}

impl Field {
    /// The one flag that was passed, or the password when none was.
    pub fn of(user: bool, password: bool, url: bool, otp: bool) -> Result<Field> {
        let asked: Vec<Field> = [
            (user, Field::User),
            (password, Field::Password),
            (url, Field::Url),
            (otp, Field::Otp),
        ]
        .into_iter()
        .filter_map(|(on, field)| on.then_some(field))
        .collect();
        match asked.len() {
            0 => Ok(Field::Password),
            1 => Ok(asked[0]),
            /* Refused rather than ranked: two fields means one clipboard
               would silently win, and the user cannot tell which. */
            _ => anyhow::bail!("name one field · -u, -p, --url or --otp"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Field::User => "username",
            Field::Password => "password",
            Field::Url => "url",
            Field::Otp => "one-time code",
        }
    }
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
    /// warm · light · cool · neon
    pub theme: Option<String>,
    /// `#rrggbb` per slot, on top of whichever theme is named.
    /* Ordered, not hashed: with two unusable colours in the table, a HashMap
       names whichever one it felt like this run. */
    pub colors: Option<std::collections::BTreeMap<String, String>>,
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
    /// The colours this session draws in.
    pub theme: crate::theme::Palette,
    /// Overridden colours that are hard to read on their own ground. Said
    /// once at startup rather than enforced: it is the user's screen.
    pub theme_warnings: Vec<String>,
    /// Whether a `[colors]` table is repainting the named theme. `^t` says so
    /// when it switches: the overrides stay in the file and outlive the walk.
    pub theme_overridden: bool,
    /// The subcommand, when one was given. `None` opens the TUI.
    pub command: Option<Command>,
    /// The key file every path opens with, when the vault has one.
    pub key_file: Option<PathBuf>,
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
        let (palette, warnings) = theme(
            cli.theme.as_deref().or(file.theme.as_deref()),
            file.colors.as_ref(),
        )?;
        let overridden = file.colors.as_ref().is_some_and(|c| !c.is_empty());

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
            theme: palette,
            theme_warnings: warnings,
            theme_overridden: overridden,
            command: cli.command,
            key_file: cli.key_file.map(|k| expand(&k)),
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

/* A name nobody ships is a startup error naming the ones that exist, not a
   silent fallback: a theme that quietly does not apply reads as a theme that
   does not work. */
fn theme(
    name: Option<&str>,
    colors: Option<&std::collections::BTreeMap<String, String>>,
) -> Result<(crate::theme::Palette, Vec<String>)> {
    let mut palette = match name {
        Some(name) => crate::theme::Palette::named(name).ok_or_else(|| {
            anyhow::anyhow!("unknown theme {name:?} · {}", crate::theme::Palette::names())
        })?,
        None => crate::theme::Palette::default(),
    };
    let Some(colors) = colors else {
        return Ok((palette, Vec::new()));
    };
    /* Applied on top of a named base, so an override is a diff rather than a
       whole palette: nobody should have to restate nine colours to change
       one. A key or a value that cannot work stops startup — a colour that
       silently does not apply reads as a theme that does not work. */
    for (slot, value) in colors {
        let color = hex(value)
            .with_context(|| format!("theme colour {slot} = {value:?}"))?;
        let field = palette.slot_mut(slot).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown theme colour {slot:?} · {}",
                crate::theme::Palette::slot_names()
            )
        })?;
        *field = color;
    }
    Ok((palette, palette.unreadable()))
}

/// `#rrggbb`, the only spelling worth supporting: it is what every palette,
/// picker and stylesheet in the world hands you.
fn hex(value: &str) -> Result<ratatui::style::Color> {
    /* The `#` is required, not merely tolerated: the error says `#rrggbb` and
       so does the README, and a second accepted spelling nobody documents is
       one more thing that works on one machine and not the next. */
    let Some(digits) = value.strip_prefix('#') else {
        anyhow::bail!("not a #rrggbb colour");
    };
    if digits.len() != 6 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("not a #rrggbb colour");
    }
    let byte = |at: usize| u8::from_str_radix(&digits[at..at + 2], 16);
    Ok(ratatui::style::Color::Rgb(byte(0)?, byte(2)?, byte(4)?))
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

/* Writing one key back into a file a person wrote by hand: the whole file is
   read, the `db` line swapped (or added at the top), and everything else —
   comments, ordering, keys Sennel does not know — comes through untouched. A
   serialize-the-struct round trip would eat all of it. */
pub fn remember_db(config_file: Option<&std::path::Path>, db: &std::path::Path) -> Result<()> {
    remember(config_file, "db", &db.display().to_string())
}

/// The same, for the palette a `^t` landed on.
pub fn remember_theme(config_file: Option<&std::path::Path>, theme: &str) -> Result<()> {
    remember(config_file, "theme", theme)
}

fn remember(config_file: Option<&std::path::Path>, key: &str, value: &str) -> Result<()> {
    let Some(path) = config_file else {
        anyhow::bail!("no config file in this session");
    };
    let line = format!("{key} = {}", quote(value));
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for text in existing.lines() {
        /* Only a top-level `db` key, and only before any [table] header: a
           `db` inside [generator] is a different key with the same name. */
        let is_key = !replaced
            && text
                .split_once('=')
                .is_some_and(|(found, _)| found.trim() == key);
        if is_key && !out.iter().any(|l: &String| l.trim_start().starts_with('[')) {
            out.push(line.clone());
            replaced = true;
        } else {
            out.push(text.to_string());
        }
    }
    if !replaced {
        /* Above any table header, or the key would be read as belonging to
           the last table in the file. */
        let at = out
            .iter()
            .position(|l| l.trim_start().starts_with('['))
            .unwrap_or(out.len());
        out.insert(at, line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    write_atomic(path, &text)
}

/// A TOML basic string. Paths can hold quotes and backslashes, and a path
/// written raw would make the file unparseable on the next run.
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/* Beside the target and renamed over it, the same rule the vault saves by: a
   half-written config is a session that will not start. */
fn write_atomic(path: &std::path::Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    /* Owner-only: it holds no secret, but it names where the vault lives,
       which is not something to hand every account on the machine. */
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(&temp);
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("writing {}", temp.display()))?;
    out.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", temp.display()))?;
    drop(out);
    std::fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

pub fn expand(path: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    if path == "~" {
        return PathBuf::from(home);
    }
    /* `~other/…` is somebody else's home, which needs the password database
       to resolve; taken literally it becomes a directory named `~other` that
       the unlock screen then offers to create. Left alone and reported by the
       caller instead of silently becoming a different path. */
    match path.strip_prefix("~/") {
        Some(rest) => PathBuf::from(home).join(rest),
        None => PathBuf::from(path),
    }
}

/// Whether a typed path names another user's home, which `expand` cannot
/// resolve — the unlock screen says so rather than creating `~octo`.
pub fn is_other_home(path: &str) -> bool {
    path.starts_with('~') && path != "~" && !path.starts_with("~/")
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

    /* A vault chosen in the app has to still be the vault next launch, and
       the file it is written into belongs to the user: comments, ordering and
       keys Sennel does not know all survive. */
    #[test]
    fn remembering_a_vault_rewrites_only_the_db_key() {
        let mut file = temp("remember");
        writeln!(
            file.handle,
            "# my settings\ndb = \"/old/path.kdbx\"\nlock_timeout = 90\n\n[generator]\nlength = 24"
        )
        .unwrap();
        let path = std::path::PathBuf::from(&file.path);

        remember_db(Some(&path), std::path::Path::new("/vaults/new.kdbx")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# my settings"), "the comment was eaten: {text}");
        assert!(text.contains("db = \"/vaults/new.kdbx\""), "{text}");
        assert!(!text.contains("/old/path.kdbx"), "the old path stayed: {text}");
        assert!(text.contains("lock_timeout = 90"), "{text}");
        assert!(text.contains("length = 24"), "the table was lost: {text}");

        // And it reads back through the real parser, which is the only proof.
        let cfg = run(vec![
            "sennel".to_string(),
            "--config".into(),
            file.path.clone(),
        ]);
        assert_eq!(cfg.db, Some(std::path::PathBuf::from("/vaults/new.kdbx")));
        assert_eq!(cfg.lock_timeout, 90);
        assert_eq!(cfg.generator.length, 24);
    }

    /* A file with no `db` line gains one above any table header, or the key
       would be read as part of the last table in the file. */
    #[test]
    fn remembering_adds_the_key_above_the_tables() {
        let mut file = temp("remember-add");
        writeln!(file.handle, "[generator]\nsymbols = true").unwrap();
        let path = std::path::PathBuf::from(&file.path);
        remember_db(Some(&path), std::path::Path::new("/vaults/first.kdbx")).unwrap();
        let cfg = run(vec![
            "sennel".to_string(),
            "--config".into(),
            file.path.clone(),
        ]);
        assert_eq!(cfg.db, Some(std::path::PathBuf::from("/vaults/first.kdbx")));
        assert!(cfg.generator.classes.symbols, "the table was orphaned");
    }

    /* --no-config asked for the file to be left out of the run, so it cannot
       be where a choice is kept. */
    #[test]
    fn no_config_has_nowhere_to_remember() {
        assert!(remember_db(None, std::path::Path::new("/vaults/x.kdbx")).is_err());
    }

    /* A theme comes from the file or the flag, and a name nobody ships stops
       startup naming the ones that do — the same contract as `sort`. */
    #[test]
    fn the_theme_reads_from_the_file_and_the_flag() {
        let cfg = build("theme = \"neon\"\n", &[]);
        assert_eq!(cfg.theme, crate::theme::NEON);
        assert_eq!(cfg.theme.name(), "neon");

        let cfg = build("theme = \"neon\"\n", &["--theme", "light"]);
        assert_eq!(cfg.theme, crate::theme::LIGHT, "the flag lost to the file");

        let cfg = build("", &[]);
        assert_eq!(cfg.theme, crate::theme::WARM, "the default moved");

        let mut file = temp("theme");
        writeln!(file.handle, "theme = \"dracula\"").unwrap();
        let cli = Cli::try_parse_from(vec![
            "sennel".to_string(),
            "--config".into(),
            file.path.clone(),
        ])
        .unwrap();
        let err = match Config::build(cli) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an unknown theme started the session"),
        };
        assert!(err.contains("unknown theme"), "{err}");
        // The message names what does exist, so the next try can work.
        for name in ["warm", "light", "cool", "neon"] {
            assert!(err.contains(name), "{err} does not name {name}");
        }
    }

    /* An override is a diff on top of a named theme, not a whole palette:
       changing one colour must not mean restating nine. */
    #[test]
    fn colours_override_one_slot_at_a_time() {
        let cfg = build(
            "theme = \"neon\"\n[colors]\ncursor = \"#00ff00\"\n",
            &[],
        );
        assert_eq!(cfg.theme.cursor, ratatui::style::Color::Rgb(0, 255, 0));
        // Everything else is still the theme it was built on.
        assert_eq!(cfg.theme.accent, crate::theme::NEON.accent);
        assert_eq!(cfg.theme.near, crate::theme::NEON.near);
        // And it stops being a built-in, which is what --check reports.
        assert_eq!(cfg.theme.name(), "custom");

        // Without a theme named, overrides land on the default.
        let cfg = build("[colors]\ntext = \"#ffffff\"\n", &[]);
        assert_eq!(cfg.theme.text, ratatui::style::Color::Rgb(255, 255, 255));
        assert_eq!(cfg.theme.accent, crate::theme::WARM.accent);
    }

    /* A colour that cannot work stops startup; one that merely measures badly
       warns and renders, because it is the user's screen. */
    #[test]
    fn bad_colours_stop_startup_and_dim_ones_only_warn() {
        for bad in ["\"#12345\"", "\"blue\"", "\"#gggggg\"", "\"ff8800\""] {
            let mut file = temp("badcolour");
            writeln!(file.handle, "[colors]\ntext = {bad}").unwrap();
            let cli = Cli::try_parse_from(vec![
                "sennel".to_string(),
                "--config".into(),
                file.path.clone(),
            ])
            .unwrap();
            let err = match Config::build(cli) {
                Err(e) => format!("{e:#}"),
                Ok(_) => panic!("{bad} started the session"),
            };
            assert!(err.contains("theme colour text"), "{err}");
        }

        // A slot nobody has is named, with the ones that exist.
        let mut file = temp("badslot");
        writeln!(file.handle, "[colors]\nbackground = \"#ffffff\"").unwrap();
        let cli = Cli::try_parse_from(vec![
            "sennel".to_string(),
            "--config".into(),
            file.path.clone(),
        ])
        .unwrap();
        let err = match Config::build(cli) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("an unknown slot started the session"),
        };
        assert!(err.contains("unknown theme colour"), "{err}");
        assert!(err.contains("muted"), "the message does not list the slots: {err}");

        /* `masked` and `ink` are palette slots that nothing draws in, so a
           config naming one is refused rather than quietly repainting a
           colour that never reaches the screen. */
        for dead in ["masked", "ink"] {
            let mut file = temp("deadslot");
            writeln!(file.handle, "[colors]\n{dead} = \"#ffffff\"").unwrap();
            let cli = Cli::try_parse_from(vec![
                "sennel".to_string(),
                "--config".into(),
                file.path.clone(),
            ])
            .unwrap();
            let err = match Config::build(cli) {
                Err(e) => format!("{e:#}"),
                Ok(_) => panic!("{dead} started the session"),
            };
            assert!(err.contains("unknown theme colour"), "{err}");
        }

        /* Legible-but-barely is a warning, not a refusal: the session starts,
           and the note names the slot and what it measured. */
        let cfg = build("[colors]\nmuted = \"#3a3a3a\"\n", &[]);
        assert_eq!(cfg.theme.muted, ratatui::style::Color::Rgb(58, 58, 58));
        assert!(
            cfg.theme_warnings.iter().any(|w| w.contains("muted")),
            "{:?}",
            cfg.theme_warnings
        );
        // And a palette nobody touched warns about nothing.
        assert!(build("theme = \"cool\"\n", &[]).theme_warnings.is_empty());

        /* Whether anything is repainting the theme, which `^t` says out loud:
           the walk moves the base and the table stays in the file. */
        assert!(build("[colors]\ncursor = \"#00ff88\"\n", &[]).theme_overridden);
        assert!(!build("theme = \"neon\"\n", &[]).theme_overridden);
        assert!(!build("[colors]\n", &[]).theme_overridden, "an empty table repaints nothing");
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
