use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Every field optional, so an absent key means "no opinion" and falls through
/// to the built-in default rather than overwriting it.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub db: Option<String>,
    /* Written by the app rather than by hand, which is why it is one line of
    paths and not a table: `^v` on the unlock screen picks from it. */
    /// Vaults opened before, newest first.
    pub recent: Option<Vec<String>>,
    pub clipboard_timeout: Option<u64>,
    pub lock_timeout: Option<u64>,
    pub backups: Option<usize>,
    /// `2` or `2:<serial>`: a YubiKey slot every vault is opened with by default.
    pub yubikey: Option<String>,
    /// Add the SSH keys a vault's KeeAgent settings name to ssh-agent when it unlocks.
    pub ssh_agent: Option<bool>,
    pub ssh_agent_lifetime: Option<u32>,
    /// Where backups go. Never beside the vault, which a sync client watches.
    pub backup_dir: Option<String>,
    /// stored · name · recent · updated. `o` cycles from here rather than
    /// from the built-in default, so the order survives a restart.
    pub sort: Option<String>,
    /// graphite · graphite-light · warm · light · cool · neon
    pub theme: Option<String>,
    /// `#rrggbb` per slot, on top of whichever theme is named.
    /* Ordered, not hashed: with two unusable colours in the table, a HashMap
    names whichever one it felt like this run. */
    pub colors: Option<std::collections::BTreeMap<String, String>>,
    pub generator: Option<FileGenerator>,
    /// Wheel and click. On by default; off gives the terminal its own
    /// selection back.
    pub mouse: Option<bool>,
    /// Enter on an empty password box unlocks with a fingerprint after a lock.
    pub touch_id: Option<bool>,
    /// The desktop window's one-letter keys, such as `p` to copy. Off leaves the ⌘ keys only.
    pub single_keys: Option<bool>,
}

/// What `^s` produces. Hard-coded before this — 20 characters, no symbols —
/// which is wrong for every site that demands one and every site that
/// forbids them.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileGenerator {
    /// complex · passphrase · pin. The default shape of every secret.
    pub kind: Option<String>,
    pub length: Option<usize>,
    /// Digits in a pin. Only read for that kind.
    pub pin_length: Option<usize>,
    /// How many words a passphrase holds. Only read for that kind.
    pub words: Option<usize>,
    pub symbols: Option<bool>,
    pub digits: Option<bool>,
    pub upper: Option<bool>,
    /// Exclude `l 1 I O 0`, which read alike in most fonts.
    pub ambiguous: Option<bool>,
}

/* One bound for the config file, `sennel gen --length` and the `P` popup,
so it cannot drift between them. Four is the floor because all four
classes have to fit. */
pub const LENGTH_RANGE: (usize, usize) = (4, 256);

/* The same, for passphrase words: one word is barely a secret, and past 64
the popup is a wall of text nobody reads before copying. */
pub const WORDS_RANGE: (usize, usize) = (1, 64);

// Digits in a pin: below 4 is not a pin, past 12 no screen asks for one.
pub const PIN_RANGE: (usize, usize) = (4, 12);

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
pub const DEFAULT_CLIPBOARD_TIMEOUT: u64 = 30;
/// Idle seconds before the vault locks and its secrets are wiped. Zero
/// disables the lock, which is only sensible on a machine nobody else touches.
pub const DEFAULT_LOCK_TIMEOUT: u64 = 300;
/// Copies of the vault kept beside it. Zero turns them off.
pub const DEFAULT_BACKUPS: usize = 3;
/// How many vaults the library remembers. Long enough for every vault anyone
/// juggles, short enough that the list is still a list and not a search.
pub const RECENT_MAX: usize = 10;

pub fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map_or_else(|| expand("~/.config"), PathBuf::from);
    base.join("sennel").join("config.toml")
}

// State rather than config or cache: data worth keeping that the user never edits.
pub fn default_backup_dir() -> PathBuf {
    let base = std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map_or_else(|| expand("~/.local/state"), PathBuf::from);
    base.join("sennel").join("backups")
}

/* Writing one key back into a file a person wrote by hand: the whole file is
read, the `db` line swapped (or added at the top), and everything else —
comments, ordering, keys Sennel does not know — comes through untouched. A
serialize-the-struct round trip would eat all of it. */
pub fn remember_db(config_file: Option<&std::path::Path>, db: &std::path::Path) -> Result<()> {
    remember(config_file, "db", &quote(&db.display().to_string()))
}

/// The same, for the palette a `^t` landed on.
pub fn remember_theme(config_file: Option<&std::path::Path>, theme: &str) -> Result<()> {
    remember(config_file, "theme", &quote(theme))
}

/// The vault library, newest first. Rewritten whole on every open: the order
/// is most of what the list is for, and it changes each time.
pub fn remember_recent(config_file: Option<&std::path::Path>, paths: &[PathBuf]) -> Result<()> {
    let list: Vec<String> = paths
        .iter()
        .map(|p| quote(&p.display().to_string()))
        .collect();
    remember(config_file, "recent", &format!("[{}]", list.join(", ")))
}

/// Drop a key entirely, value and all. `^d` on the startup vault has nothing
/// to write in its place: the next launch should ask, not reopen what was
/// just forgotten.
pub fn forget_db(config_file: Option<&std::path::Path>) -> Result<()> {
    rewrite(config_file, "db", None)
}

/// `value` arrives already spelled as TOML, so a caller can write an array as
/// easily as a string. `None` removes the key.
fn remember(config_file: Option<&std::path::Path>, key: &str, value: &str) -> Result<()> {
    rewrite(config_file, key, Some(value))
}

fn rewrite(config_file: Option<&std::path::Path>, key: &str, value: Option<&str>) -> Result<()> {
    let Some(path) = config_file else {
        anyhow::bail!("no config file in this session");
    };
    let line = value.map(|v| format!("{key} = {v}"));
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    let mut first_table: Option<usize> = None;
    /* Brackets still open from an earlier line, and whether those lines
    belong to the value being replaced. An array can span lines — every
    formatter writes ten paths that way — and swapping only its first line
    leaves the rest orphaned, which is a config file that no longer
    parses and an app that will not start until someone edits it by
    hand. */
    let mut depth = 0i32;
    let mut dropping = false;
    for text in existing.lines() {
        if depth > 0 {
            depth = scan(text, depth);
            if !dropping {
                out.push(text.to_string());
            }
            continue;
        }
        dropping = false;
        /* Only a top-level key, and only before any [table] header: a `db`
        inside [generator] is a different key with the same name. A `#`
        before it makes the whole line a comment, and `split_once` leaves
        the `#` on the name, so a commented-out key is never the match. */
        let is_key = !replaced
            && first_table.is_none()
            && text
                .split_once('=')
                .is_some_and(|(found, _)| found.trim() == key);
        if is_key {
            if let Some(line) = &line {
                out.push(line.clone());
            }
            replaced = true;
            depth = scan(text, 0);
            dropping = depth > 0;
            continue;
        }
        if text.trim_start().starts_with('[') {
            first_table.get_or_insert(out.len());
        }
        depth = scan(text, 0);
        out.push(text.to_string());
    }
    if !replaced && let Some(line) = line {
        /* Above any table header, or the key would be read as belonging to
        the last table in the file. */
        let at = first_table.unwrap_or(out.len());
        out.insert(at, line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    write_atomic(path, &text)
}

/* Bracket depth after this line, counting from `depth`. Quoted text and
comments are skipped, so a vault in a folder named `a]b` does not throw the
count off. A `"""` multi-line string would, but nothing Sennel reads or
writes uses one. */
fn scan(line: &str, depth: i32) -> i32 {
    let mut depth = depth;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '#' => break,
            '"' => {
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            chars.next();
                        }
                        '"' => break,
                        _ => {}
                    }
                }
            }
            // Literal strings take no escapes, so the first quote ends it.
            '\'' => {
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                }
            }
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    depth.max(0)
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
    /* Bytes before name, the same rule the vault saves by: a rename is atomic
    about the name only, and a config that comes back empty after a crash
    is a session that opens no vault. */
    out.sync_all()
        .with_context(|| format!("writing {}", temp.display()))?;
    drop(out);
    std::fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// A path that still names the same file tomorrow, from another directory.
/// `--db vault.kdbx` is relative to wherever it was typed, so remembering it
/// verbatim puts a row in the library that names a different file from
/// anywhere else — or no file at all.
pub fn absolute(path: &std::path::Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(dir) => dir.join(path),
            // Nothing better to say than what was asked for.
            Err(_) => return path.to_path_buf(),
        }
    };
    /* Resolved through the parent, never the file: the directory has to
    exist for a vault to be opened or created there, while the vault
    itself may not yet. It also leaves a vault file that is itself a
    symlink — into a synced folder, say — as the symlink, so saves still
    go through it. `..` and a symlinked folder both collapse here, which
    is what stops one vault holding two rows in the library. */
    let (Some(dir), Some(name)) = (joined.parent(), joined.file_name()) else {
        return joined;
    };
    match dir.canonicalize() {
        Ok(dir) => dir.join(name),
        // A folder that is not there yet cannot be resolved, only spelled out.
        Err(_) => joined,
    }
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

/// The generator settings a session runs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generator {
    pub kind: crate::generator::Kind,
    pub length: usize,
    /// Pin digits. Read only for that kind.
    pub pin_length: usize,
    /// Passphrase words. Read only for that kind; kept beside length so one
    /// struct answers every generator there is.
    pub words: usize,
    pub classes: crate::generator::Classes,
    /// True keeps the lookalikes out of the pool.
    pub exclude_ambiguous: bool,
}

impl Default for Generator {
    fn default() -> Self {
        Generator {
            kind: crate::generator::Kind::Complex,
            length: 20,
            pin_length: 6,
            words: 6,
            classes: crate::generator::Classes::default(),
            exclude_ambiguous: true,
        }
    }
}

impl Generator {
    /// How the flash describes what it just made.
    pub fn describe(&self) -> String {
        match self.kind {
            crate::generator::Kind::Complex => {
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
            crate::generator::Kind::Passphrase => {
                format!("{}-word list", crate::generator::word_count())
            }
            crate::generator::Kind::Pin => "0–9".to_string(),
        }
    }

    /// What was made, in its own units: `20 chars`, `6 words`, `6 digits`.
    pub fn amount(&self) -> String {
        match self.kind {
            crate::generator::Kind::Complex => format!("{} chars", self.length),
            crate::generator::Kind::Passphrase => format!("{} words", self.words),
            crate::generator::Kind::Pin => format!("{} digits", self.pin_length),
        }
    }

    /// Priced against what was drawn from: the class pool, the wordlist, or
    /// ten digits. One number the flashes and the popup can share.
    pub fn bits(&self) -> f64 {
        match self.kind {
            crate::generator::Kind::Complex => crate::generator::entropy_bits(
                self.length,
                self.classes.alphabet_len(self.exclude_ambiguous),
            ),
            crate::generator::Kind::Passphrase => crate::generator::passphrase_bits(self.words),
            crate::generator::Kind::Pin => crate::generator::pin_bits(self.pin_length),
        }
    }

    /// One secret in this shape.
    pub fn make(&self) -> Result<String, String> {
        match self.kind {
            crate::generator::Kind::Complex => {
                crate::generator::generate(self.length, self.classes, self.exclude_ambiguous)
            }
            crate::generator::Kind::Passphrase => crate::generator::generate_passphrase(self.words),
            crate::generator::Kind::Pin => crate::generator::generate_pin(self.pin_length),
        }
    }
}

// A key left in the agent must expire, so the lifetime cannot be zero or forever.
pub fn lifetime(seconds: Option<u32>) -> anyhow::Result<u32> {
    let seconds = seconds.unwrap_or(3600);
    if !(1..=604_800).contains(&seconds) {
        anyhow::bail!("ssh_agent_lifetime = {seconds} is outside 1–604800 seconds");
    }
    Ok(seconds)
}

// More than `BACKUPS_MAX` would not be found again by `--check` or deleted on a rekey.
pub fn backups(keep: Option<usize>) -> anyhow::Result<usize> {
    let keep = keep.unwrap_or(DEFAULT_BACKUPS);
    if keep > crate::vault::BACKUPS_MAX {
        anyhow::bail!(
            "backups = {keep} is outside 0–{}",
            crate::vault::BACKUPS_MAX
        );
    }
    Ok(keep)
}

/* Every field optional, and a length that could never produce a password is
a startup error rather than a surprise at `^s`. */
pub fn generator(file: Option<&FileGenerator>) -> anyhow::Result<Generator> {
    let mut out = Generator::default();
    let Some(file) = file else {
        return Ok(out);
    };
    if let Some(kind) = file.kind.as_deref() {
        out.kind = crate::generator::Kind::parse(kind).ok_or_else(|| {
            anyhow::anyhow!("generator kind {kind:?} is none of complex, passphrase, pin")
        })?;
    }
    if let Some(words) = file.words {
        let (min, max) = WORDS_RANGE;
        if !(min..=max).contains(&words) {
            anyhow::bail!("generator words {words} is outside {min}–{max}");
        }
        out.words = words;
    }
    if let Some(pin) = file.pin_length {
        let (min, max) = PIN_RANGE;
        if !(min..=max).contains(&pin) {
            anyhow::bail!("generator pin_length {pin} is outside {min}–{max}");
        }
        out.pin_length = pin;
    }
    if let Some(length) = file.length {
        let (min, max) = LENGTH_RANGE;
        if !(min..=max).contains(&length) {
            anyhow::bail!("generator length {length} is outside {min}–{max}");
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

#[cfg(test)]
mod tests {
    use super::*;

    /* --no-config asked for the file to be left out of the run, so it cannot
    be where a choice is kept. */
    #[test]
    fn no_config_has_nowhere_to_remember() {
        assert!(remember_db(None, std::path::Path::new("/vaults/x.kdbx")).is_err());
    }

    /* A relative path names a different file from every other directory, so
    the library cannot hold one. */
    #[test]
    fn a_relative_path_is_resolved_against_the_working_directory() {
        let here = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(
            absolute(std::path::Path::new("vault.kdbx")),
            here.join("vault.kdbx")
        );
        /* `..` collapses too, or one vault would hold two rows in the
        library. Through a folder that exists: one that does not cannot be
        resolved, and guessing past it is how `..` lands somewhere else
        entirely when a symlink is in the way. */
        assert_eq!(
            absolute(&here.join("src/../vault.kdbx")),
            here.join("vault.kdbx")
        );
        /* A folder that does not exist cannot be resolved, and saying so by
        leaving the path alone beats inventing one. */
        let absent = std::path::Path::new("/nowhere-at-all/x.kdbx");
        assert_eq!(absolute(absent), absent);
    }

    #[test]
    fn a_named_config_must_exist() {
        let missing = std::env::temp_dir().join("sennel-test-absent.toml");
        let _ = std::fs::remove_file(&missing);
        assert!(
            FileConfig::load(&missing, false).is_ok(),
            "default path may be absent"
        );
        let err = FileConfig::load(&missing, true).unwrap_err().to_string();
        assert!(err.contains("reading"), "{err}");
    }
}
