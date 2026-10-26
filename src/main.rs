mod app;
mod config;
mod theme;
#[cfg(test)]
mod touchid;
mod ui;

use sennel_core::{agent, clipboard, export, generator, import, pwned, search, vault};
#[cfg(not(test))]
use sennel_core::touchid;

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::SetTitle;
use zeroize::Zeroize;

use app::{App, Confirm};
use crate::clipboard::Board;
use config::{Cli, Command, Config, Field};
use keepass::db::GroupId;
use vault::{EntryExt, Vault, printable};

/* `sennel --check | head` is the reader having seen enough, not a failure.
   Rust ignores SIGPIPE so the write comes back EPIPE instead, and `say!`
   turns that into a panic — which on the paths that have a vault open would
   also skip every zeroize on the way out. Dropped instead: the command runs
   to its end, its destructors run, and what nobody is reading goes nowhere. */
macro_rules! say {
    () => {{
        use std::io::Write;
        let _ = writeln!(std::io::stdout());
    }};
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

fn main() -> Result<()> {
    /* First, before a config is read or a vault is opened. Every path below
       this can end up holding secrets — `get` sleeps out the clipboard wipe
       holding one, `audit --pwned` walks every password in the vault waiting
       on the network, `import` holds the lot twice — and all three used to
       reach that state with core dumps still enabled and, on Linux, still
       attachable. It sat further down, on the TUI path only, so a subcommand
       was one `return` away from missing it; up here a new one inherits it. */
    harden();
    let matches = Cli::command().get_matches();
    let cfg = Config::build(Cli::from_arg_matches(&matches)?)?;
    if cfg.check {
        return check(&cfg);
    }
    if cfg.list {
        return list(&cfg);
    }
    /* Answers a question and exits, so it runs before the terminal checks
       below: `sennel get` is the one path meant for a pipe. */
    if let Some(Command::Get { needle, user, password, url, otp, stdout, force }) = &cfg.command {
        let field = Field::of(*user, *password, *url, *otp)?;
        let (needle, stdout, force) = (needle.clone(), *stdout, *force);
        return get(&cfg, &needle, field, stdout, force);
    }
    /* Also before the terminal checks, and the one subcommand that opens no
       vault at all: a password you are not storing needs no database. */
    if let Some(Command::Gen {
        kind,
        length,
        words,
        symbols,
        no_symbols,
        no_digits,
        no_upper,
        ambiguous,
        count,
        stdout,
        force,
    }) = &cfg.command
    {
        let mut settings = cfg.generator;
        if let Some(kind) = kind {
            settings.kind = generator::Kind::parse(kind).ok_or_else(|| {
                anyhow::anyhow!("kind {kind:?} is none of complex, passphrase, pin")
            })?;
        }
        if let Some(len) = *length {
            let pin = settings.kind == generator::Kind::Pin;
            let (min, max) = if pin { config::PIN_RANGE } else { config::LENGTH_RANGE };
            if !(min..=max).contains(&len) {
                anyhow::bail!("length {len} is outside {min}–{max}");
            }
            if pin {
                settings.pin_length = len;
            } else {
                settings.length = len;
            }
        }
        if let Some(words) = *words {
            let (min, max) = config::WORDS_RANGE;
            if !(min..=max).contains(&words) {
                anyhow::bail!("words {words} is outside {min}–{max}");
            }
            settings.words = words;
        }
        if *symbols {
            settings.classes.symbols = true;
        }
        if *no_symbols {
            settings.classes.symbols = false;
        }
        if *no_digits {
            settings.classes.digits = false;
        }
        if *no_upper {
            settings.classes.upper = false;
        }
        if *ambiguous {
            settings.exclude_ambiguous = false;
        }
        // Said, not ignored: `gen --kind pin --symbols` must not look like it worked.
        if settings.kind != generator::Kind::Complex
            && (*symbols || *no_symbols || *no_digits || *no_upper || *ambiguous)
        {
            eprintln!("class flags shape complex passwords only  ·  ignored for {}", settings.kind.name());
        }
        if settings.kind == generator::Kind::Passphrase && length.is_some() {
            eprintln!("-n sets characters, not words  ·  --words controls passphrases");
        }
        if settings.kind != generator::Kind::Passphrase && words.is_some() {
            eprintln!("--words counts passphrase words  ·  ignored for {}", settings.kind.name());
        }
        return make_password(&cfg, settings, *count, *stdout, *force);
    }
    /* Before the config is even consulted: printing a completion script is
       not a session, and it must work on a machine with no vault. */
    if let Some(Command::Completions { shell }) = &cfg.command {
        let mut command = Cli::command();
        /* Into a buffer first: clap_complete unwraps the write, so generating
           straight into a closed pipe panics rather than returning. The
           script is a few kilobytes, so holding it costs nothing. */
        let mut script: Vec<u8> = Vec::new();
        clap_complete::generate(*shell, &mut command, "sennel", &mut script);
        use std::io::Write;
        let _ = std::io::stdout().write_all(&script);
        return Ok(());
    }
    if let Some(Command::Man) = &cfg.command {
        match clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout()) {
            // `sennel man | head` reported "Error: Broken pipe" and exited 1.
            Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => return Err(e.into()),
            _ => return Ok(()),
        }
    }
    if let Some(Command::Convert { to }) = &cfg.command {
        let to = to.clone();
        return convert(&cfg, to.as_deref());
    }
    if let Some(Command::Audit { pwned }) = &cfg.command {
        return audit(&cfg, *pwned);
    }
    if let Some(Command::Import { file, group, dry_run }) = &cfg.command {
        let (file, group, dry_run) = (file.clone(), group.clone(), *dry_run);
        return import_csv(&cfg, &file, group.as_deref(), dry_run);
    }
    if let Some(Command::Export { format, out, stdout, force, group }) = &cfg.command {
        return export_vault(&cfg, *format, out.as_deref(), *stdout, *force, group.as_deref());
    }
    /* Both ends, because the TUI needs to write frames and read keys. Piped
       or in CI, crossterm's raw mode fails with an OS error about a device
       that tells nobody which of the two is wrong or what does work here. */
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        anyhow::bail!("Sennel needs a terminal · --check works without one");
    }

    /* A crash must not cost the user their terminal, or leave the vault's
       name in the title bar. `ratatui::init` restores raw mode and the
       alternate screen on panic; mouse capture and the title are ours, so
       they are chained onto the same hook. */
    let mut terminal = ratatui::init();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(std::io::stdout(), DisableMouseCapture, DisableBracketedPaste, SetTitle(""));
        previous(info);
    }));
    /* Wheel and click, unless the config turned them off: capture takes the
       terminal's own selection with it, which some people would rather keep
       (shift usually still selects). */
    if cfg.mouse {
        let _ = execute!(std::io::stdout(), EnableMouseCapture);
    }
    // Without this a paste arrives as keystrokes, and its last newline presses Enter.
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    let mut app = App::new();
    /* Which file the lock screen is for, resolved once at startup. The draw
       loop must not stat: `refresh_db_state` runs here and after every save,
       and the cached `unlock_new` is all the draw ever reads. */
    app.set_db_path(cfg.db.clone());
    app.set_key_file(cfg.key_file.as_deref());
    app.set_yubikey(cfg.yubikey.clone());
    app.set_ssh_agent(cfg.ssh_agent, cfg.ssh_agent_lifetime);
    /* Where a chosen vault gets remembered, so the next launch opens it. */
    app.config_file = cfg.config_file.clone();
    app.configured_db = cfg.db.clone();
    /* And the vaults opened before this one, which `^v` picks from. */
    app.set_recent(cfg.recent.clone());
    app.refresh_db_state();
    // Nothing to unlock yet, so start on a picker.
    if cfg.db.is_none() {
        if cfg.recent.is_empty() {
            app.open_browse();
        } else {
            app.open_library();
        }
    }
    /* Armed once from config: 0 means the user asked for no lock, and the
       mapping lives in `App` so the frame loop below needs no branch. */
    app.set_lock_timeout(cfg.lock_timeout);
    app.set_backups(cfg.backups, cfg.backup_dir.clone());
    app.set_order(cfg.sort);
    app.theme = cfg.theme;
    app.mouse = cfg.mouse;
    app.session.touch_id = cfg.touch_id && cfg!(target_os = "macos");
    app.theme_overridden = cfg.theme_overridden;
    /* Said once, on the first frame, and then it is the user's screen: an
       override that measures badly is worth naming, not worth refusing. */
    for note in &cfg.theme_warnings {
        app.warn(format!("theme: {note}"));
    }
    app.set_generator(cfg.generator);
    /* The clipboard with its auto-clear timer, armed once like the lock:
       copies before this point cannot happen, since nothing is unlocked. */
    app.set_board(Board::new(cfg.clipboard_timeout));
    let result = run(&mut terminal, &mut app);
    /* Before anything else on the way out: the auto-clear lives in a thread
       that dies with this process, so quitting three seconds after a copy
       used to leave the password sitting on the clipboard. */
    app.clear_clipboard();
    app.agent_release();
    if cfg.mouse {
        let _ = execute!(std::io::stdout(), DisableMouseCapture);
    }
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    // The vault's name must not outlive the session in the window title.
    let _ = execute!(std::io::stdout(), SetTitle(""));
    result
}

/* Refuse to write the decrypted vault anywhere a crash could leave it. A
   core dump of this process holds every secret at once, and on Linux a
   dumpable process can also be attached to by anything running as the same
   user — which is the whole machine's worth of software the user has ever
   installed. Best effort: a platform that refuses either call is no worse
   off than before. */
/// Whether core dumps are actually off, read back rather than assumed. Shown
/// by `--check`, which is how the hardening becomes something a test outside
/// this process can see — and `--check` is itself an early return, so seeing
/// it there proves `harden` ran before any of them.
fn core_dumps_off() -> bool {
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    let read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    read == 0 && limit.rlim_cur == 0
}

fn harden() {
    unsafe {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/* The first thing to run on a new machine and the first thing to ask for in
   a bug report: what Sennel read, and whether the clipboard it copies to is
   there. Exits non-zero when copying could never work, so a script can act
   on it. */
fn check(cfg: &Config) -> Result<()> {
    say!("Sennel {}", env!("CARGO_PKG_VERSION"));
    say!(
        "config    {}",
        cfg.config_file
            .as_deref()
            .map_or("(none · --no-config)".to_string(), |p| p.display().to_string())
    );
    say!(
        "db        {}",
        cfg.db
            .as_deref()
            .map_or("(none · pass a file)".to_string(), |p| p.display().to_string())
    );
    /* What a bug report needs and what a first run wants to know: not only
       which file was configured, but whether it is there and writable. A
       vault Sennel cannot write is a vault that autosaves into an error. */
    match cfg.db.as_deref() {
        Some(path) if path.is_file() => {
            let writable = std::fs::OpenOptions::new().write(true).open(path).is_ok();
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            say!(
                "vault     found · {size} bytes · {}",
                if writable { "writable" } else { "READ-ONLY" }
            );
        }
        Some(_) => say!("vault     not there yet · unlocking creates it"),
        None => say!("vault     (none)"),
    }
    /* The library, since "which vaults does this machine know about" is a
       question a bug report asks and the TUI answers only behind `^v`. */
    if cfg.recent.is_empty() {
        say!("library   (none yet)");
    } else {
        for (n, path) in cfg.recent.iter().enumerate() {
            let label = if n == 0 { "library  " } else { "         " };
            let state = if path.is_file() { "" } else { " · missing" };
            say!("{label} {}{state}", path.display());
        }
    }
    say!(
        "hardened  {}",
        match core_dumps_off() {
            true => "core dumps off",
            /* Named rather than hidden: a machine where the limit will not
               take is one where a crash writes every secret to disk, and the
               user should hear that from --check and not from a forensics
               report. */
            false => "core dumps STILL ON · this machine refused the limit",
        }
    );
    say!("theme     {}", cfg.theme.name());
    for note in &cfg.theme_warnings {
        say!("          ! {note}");
    }
    say!("sort      {}", cfg.sort.short());
    say!(
        "generate  {} · {}",
        cfg.generator.amount(),
        cfg.generator.describe()
    );
    say!("mouse     {}", if cfg.mouse { "on" } else { "off" });
    say!(
        "touch id  {}",
        match (cfg.touch_id, cfg!(target_os = "macos")) {
            (false, _) => "off",
            (true, true) => "on · enter on an empty password box after a lock",
            (true, false) => "on · macOS only, so unused here",
        }
    );
    say!("clear in  {}s", cfg.clipboard_timeout);
    say!("lock in   {}s (0 = off)", cfg.lock_timeout);
    say!("backups   {} kept in {} (0 = off)", cfg.backups, cfg.backup_dir.display());
    let state = if cfg.ssh_agent { "on" } else { "off" };
    match agent::Agent::connect().and_then(|mut a| a.count()) {
        Ok(n) => say!("ssh agent {state} · reachable, holding {n} keys · lifetime {}s", cfg.ssh_agent_lifetime),
        Err(why) => say!("ssh agent {state} · {why}"),
    }
    if let Some(spec) = &cfg.yubikey {
        match keepass::ChallengeResponseKey::get_available_yubikeys() {
            Ok(keys) if keys.is_empty() => say!("yubikey   {spec} · no key connected"),
            Ok(keys) => {
                let serials: Vec<String> = keys.iter().map(|k| k.serial_number.to_string()).collect();
                say!("yubikey   {spec} · connected: {}", serials.join(", "));
            }
            Err(e) => say!("yubikey   {spec} · cannot look: {e}"),
        }
    }
    if let Some(db) = &cfg.db {
        for found in vault::backups_of(&cfg.backup_dir, db) {
            say!("          {}", found.display());
        }
    }
    match arboard::Clipboard::new() {
        Ok(_) => {
            say!("clipboard ok");
            Ok(())
        }
        Err(e) => {
            say!("clipboard unavailable · {e}");
            std::process::exit(1);
        }
    }
}

/* --list: the vault inventory without the secrets. Counts and entry titles
   only — the point is scripting and inventory, not display. */
fn list(cfg: &Config) -> Result<()> {
    let vault = unlock(cfg)?;
    say!("{} groups · {} entries", vault.num_groups(), vault.entry_count());
    /* Walk the whole tree root-down so the output reads like the browser. */
    for (id, depth) in walk_groups(&vault) {
        let indent = "  ".repeat(depth);
        say!("{}[{}]", indent, printable(&vault.get_group(&id).unwrap().name));
        for entry in vault.entries_in(&id) {
            /* A script reading the inventory should see what the browser
               sees, and "expired" is the one thing about an entry that can
               make the rest of the line misleading. */
            let stale = if vault::expired(&entry) { "  (expired)" } else { "" };
            say!("{}  {}{stale}", indent, printable(entry.title()));
        }
    }
    Ok(())
}

/* `sennel convert`: an older KDBX read in, a KDBX 4 written out.

   Never in place, and never over an existing file. A conversion is the one
   operation where a bug costs the whole vault, so the original is opened and
   never touched, the new file is created exclusively, and what was written is
   read back and compared before this says it worked. If the comparison fails
   the new file is removed, because a half-converted vault sitting next to a
   good one is the worst of both. */
fn convert(cfg: &Config, to: Option<&str>) -> Result<()> {
    let Some(from) = cfg.db.clone() else {
        anyhow::bail!("no database given · pass --db <file>");
    };
    /* `<name>-kdbx4.kdbx` beside the original: the same directory, because
       that is where the user keeps vaults, and a name that says what it is. */
    let out = match to {
        Some(path) => config::expand(path),
        None => {
            let stem = from
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "vault".to_string());
            from.with_file_name(format!("{stem}-kdbx4.kdbx"))
        }
    };
    if out == from {
        anyhow::bail!("that would write over the original · pick another --to");
    }
    if out.exists() {
        anyhow::bail!("{} is already there · move it or pick another --to", out.display());
    }

    let mut vault = unlock(cfg)?;
    let was = vault.format();
    if vault.writable() {
        anyhow::bail!("{} is already {was} · nothing to convert", from.display());
    }
    /* Read before the write, so the comparison below is against what came out
       of the original rather than against the copy in memory. */
    let before = vault::inventory(&vault);
    vault.convert_to_kdbx4().map_err(|e| anyhow::anyhow!("{e}"))?;

    /* No second password prompt: the key from the unlock is still held, so
       the copy carries the original's password and key file exactly. Asking
       again would be asking for the same secret twice, which is how people
       end up typing a different one by accident. */
    vault.save_copy(&out).map_err(|e| anyhow::anyhow!("{e}"))?;

    /* Opened again from disk with the same key, and compared field by field.
       A conversion that silently dropped an entry would otherwise be found
       months later, by which time the original may be gone. */
    let fresh = match vault.open_copy(&out) {
        Ok(fresh) => fresh,
        Err(e) => {
            let _ = std::fs::remove_file(&out);
            return Err(e).context("the converted file could not be reopened · it was removed");
        }
    };
    let after = vault::inventory(&fresh);
    if before != after {
        let _ = std::fs::remove_file(&out);
        anyhow::bail!(
            "the converted file does not match the original ({} entries in, {} out) · it was removed",
            before.len(),
            after.len()
        );
    }

    say!("{} → {}", from.display(), out.display());
    say!("{was} → {} · {} entries, verified", fresh.format(), after.len());
    say!("the original is untouched · open the new file in KeePassXC before you replace it");
    Ok(())
}

/* `sennel audit`: the same findings the TUI's `!` shows, printed. The network
   check lives out here rather than behind that key because a blocking http
   request inside a frame loop is how a TUI stops redrawing, and because an
   audit that reaches the internet should be something you typed. */
fn audit(cfg: &Config, pwned: bool) -> Result<()> {
    let vault = unlock(cfg)?;

    let found = vault::audit(&vault);
    for (id, issue) in &found {
        let Some(entry) = vault.get_entry(id) else {
            continue;
        };
        say!("{:<40}  {}", printable(entry.title()), issue.say());
    }
    if found.is_empty() {
        say!("nothing reused, weak, expired, empty or old");
    }
    if !pwned {
        return Ok(());
    }

    /* One request per prefix, not per entry. A vault where six entries
       share a password should ask once, and passwords that merely share the
       first five hex characters ride along in the same answer — which is the
       same property that makes the k-anonymity worth anything. */
    say!();
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut breached = 0usize;
    for entry in vault.entry_refs() {
        let secret = entry.password();
        if secret.is_empty() {
            continue;
        }
        let (prefix, suffix) = pwned::split_hash(secret);
        if !seen.contains_key(&prefix) {
            let body = pwned::fetch_range(&prefix).map_err(|e| anyhow::anyhow!("{e}"))?;
            seen.insert(prefix.clone(), body);
        }
        let count = pwned::count_in(&seen[&prefix], &suffix);
        if count > 0 {
            breached += 1;
            say!("{:<40}  in {count} known breaches", printable(entry.title()));
        }
    }
    match breached {
        0 => say!("no password in this vault is in a known breach"),
        n => say!("\n{n} password(s) are in a known breach · change those first"),
    }
    Ok(())
}

/* `sennel import`: somebody else's export, into a group of its own.

   Into a new group rather than merged into the tree the file describes:
   an import is the one operation most likely to be regretted, and one
   group is one thing to delete when it is. The file's own group column
   becomes a subgroup, so the shape survives without colonising the vault. */
// `sennel export`: everything, in plaintext. Every refusal comes before the password prompt, so nobody
// types a master password to be told the output has nowhere safe to go.
fn export_vault(
    cfg: &Config,
    format: config::ExportFormat,
    out: Option<&str>,
    to_stdout: bool,
    force: bool,
    group: Option<&str>,
) -> Result<()> {
    use std::io::Write;
    if out.is_none() && !to_stdout {
        anyhow::bail!("say where it goes · --out FILE, or --stdout");
    }
    if to_stdout && std::io::stdout().is_terminal() && !force {
        anyhow::bail!(
            "--stdout into a terminal would leave every password in your scrollback · pipe it, or --force"
        );
    }
    let target = out.map(config::expand);
    if let Some(path) = &target
        && path.exists()
    {
        anyhow::bail!("{} is already there · move it or pick another --out", path.display());
    }
    let vault = unlock(cfg)?;
    let exported = export::render(&vault, format, group).map_err(|e| anyhow::anyhow!("{e}"))?;
    match &target {
        Some(path) => vault::write_owner_only(path, exported.text.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write {} · {e}", path.display()))?,
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(exported.text.as_bytes())?;
            stdout.flush()?;
        }
    }
    let plural = if exported.entries == 1 { "entry" } else { "entries" };
    eprintln!("exported {} {plural}", exported.entries);
    if exported.left_out_fields + exported.left_out_files > 0 {
        eprintln!(
            "left out: {} custom fields, {} attachments · --format json keeps the fields and names the files",
            exported.left_out_fields, exported.left_out_files
        );
    }
    if let Some(path) = &target {
        eprintln!("{} is plaintext · delete it when you are done", path.display());
    }
    Ok(())
}

fn import_csv(cfg: &Config, file: &str, group: Option<&str>, dry_run: bool) -> Result<()> {
    let Some(path) = &cfg.db else {
        anyhow::bail!("no database given · pass --db <file>");
    };
    let mut text = std::fs::read_to_string(config::expand(file))
        .with_context(|| format!("reading {file}"))?;
    let found = import::read_csv(&text).map_err(|e| anyhow::anyhow!("{file}: {e}"));
    /* The whole export, every password in it, in one buffer. Wiped as soon as
       it has been parsed rather than left for the allocator — the rows that
       came out of it wipe themselves on drop. */
    text.zeroize();
    let found = found?;
    if found.rows.is_empty() {
        anyhow::bail!("{file} has a header and no entries");
    }
    /* Said before the password prompt: a dry run should not need the vault's
       password to tell you what is in somebody else's csv. */
    if !found.ignored.is_empty() {
        eprintln!(
            "ignoring {} column(s): {}",
            found.ignored.len(),
            found
                .ignored
                .iter()
                .map(|c| printable(c))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let into = group
        .map(|g| g.to_string())
        .unwrap_or_else(|| format!("Imported {}", chrono::Local::now().format("%Y-%m-%d")));

    if dry_run {
        say!("{} entries would go into {into}:", found.rows.len());
        for row in found.rows.iter().take(20) {
            let where_ = match row.group.trim() {
                "" => String::new(),
                g => format!("  ({})", printable(g)),
            };
            say!("  {}{where_}", printable(&row.title));
        }
        if found.rows.len() > 20 {
            say!("  … and {} more", found.rows.len() - 20);
        }
        return Ok(());
    }

    let mut vault = unlock(cfg)?;

    if !vault.writable() {
        anyhow::bail!(
            "{} is {} · Sennel writes KDBX 4.1 only · save a copy as KDBX 4.1 from KeePassXC first",
            path.display(),
            vault.format()
        );
    }
    let (added, skipped) = import::into_vault(&mut vault, &found.rows, &into)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for note in &skipped {
        eprintln!("{}", printable(note));
    }
    vault.save().map_err(|e| anyhow::anyhow!("{e}"))?;
    say!("imported {added} entries into {into}");
    /* The export is still sitting on disk in the clear, which is the part
       people forget once the import worked. */
    eprintln!("{file} is still plaintext on disk · delete it");
    Ok(())
}

/* Every non-interactive path opens the vault the same way: prompt (or read a
   piped line), read the key file if there is one, open, and wipe both. It was
   copied into four commands, and all four passed `None` for the key file — so
   a vault with one could not be reached from the command line at all. */
fn unlock(cfg: &Config) -> Result<Vault> {
    let Some(path) = &cfg.db else {
        anyhow::bail!("no database given · pass --db <file>");
    };
    let mut key_bytes = match &cfg.key_file {
        Some(at) => Some(
            std::fs::read(at).with_context(|| format!("reading key file {}", at.display()))?,
        ),
        None => None,
    };
    let mut password = ask_password("password: ")?;
    if let Some(spec) = &cfg.yubikey {
        eprintln!("yubikey {spec} · touch the key if it blinks");
    }
    let opened = Vault::open_with(path, &password, key_bytes.as_deref(), cfg.yubikey.as_ref())
        .map(|mut v| {
            v.set_backups(cfg.backups, &cfg.backup_dir);
            v
        })
        .map_err(|e| anyhow::anyhow!("{e}"));
    password.zeroize();
    if let Some(bytes) = key_bytes.as_mut() {
        // Key material too, and wiped whether or not the open worked.
        bytes.zeroize();
    }
    opened
}

/* The master password, from a terminal or from a pipe. rpassword needs a tty
   and fails with "Device not configured" without one, which makes `get`
   unusable from the very scripts it exists for. A piped stdin is read as one
   line instead — the way every other tool takes a passphrase from a pipe.

   The buffer is the caller's to zeroize; this hands back the only copy. */
fn ask_password(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        return Ok(rpassword::prompt_password(prompt)?);
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    // The newline is the pipe's, not the password's.
    let end = line.trim_end_matches(['\n', '\r']).len();
    line.truncate(end);
    Ok(line)
}

/* `sennel get`, the whole non-interactive path. Unlocks, resolves one entry,
   and either copies (staying alive for the wipe) or prints.

   Exit codes are the contract a script reads: 0 copied, 2 ambiguous, 3 not
   found, 1 for everything else. Ambiguous and not-found are separated because
   a script retrying with a longer needle wants to know which happened. */
fn get(cfg: &Config, needle: &str, field: Field, to_stdout: bool, force: bool) -> Result<()> {
    /* Refused before the password prompt, not after: making somebody type a
       master password and *then* telling them the output has nowhere safe to
       go is the rude order to do this in. */
    if to_stdout && std::io::stdout().is_terminal() && !force {
        anyhow::bail!(
            "--stdout into a terminal would leave the secret in your scrollback · pipe it, or --force"
        );
    }
    let vault = unlock(cfg)?;

    let mut searcher = search::Searcher::new();
    let id = match vault::resolve(&vault, &mut searcher, needle) {
        vault::Found::One(id) => id,
        vault::Found::Many(ids) => {
            eprintln!("{needle:?} matches {} entries:", ids.len());
            /* Titles only, and sanitised: this is vault text going to a
               terminal, and it may have been written by anyone. */
            for id in ids.iter().take(10) {
                if let Some(entry) = vault.get_entry(id) {
                    eprintln!("  {}", printable(entry.title()));
                }
            }
            if ids.len() > 10 {
                eprintln!("  … and {} more", ids.len() - 10);
            }
            std::process::exit(2);
        }
        vault::Found::None => {
            eprintln!("nothing matches {needle:?}");
            std::process::exit(3);
        }
    };
    let entry = vault.get_entry(&id).expect("resolve returned a live id");
    let title = printable(entry.title());
    /* Wiped when this returns: the copy path below holds it across a
       clipboard-timeout sleep, and a `get -p` that leaves the password in a
       freed allocation undoes the point of every zeroize above it. */
    let value = zeroize::Zeroizing::new(match field {
        Field::User => entry.username().to_string(),
        Field::Password => entry.password().to_string(),
        Field::Url => entry.url().to_string(),
        /* The code, never the seed: the same rule the TUI's `t` follows, and
           the reason `get` has no flag that would hand over the seed. */
        Field::Otp => match vault::totp_now(&entry) {
            Some((code, _)) => code,
            None => anyhow::bail!("{title} has no one-time code"),
        },
    });
    if value.is_empty() {
        anyhow::bail!("{title} has no {}", field.name());
    }
    if to_stdout {
        say!("{}", *value);
        return Ok(());
    }

    let board = Board::new(cfg.clipboard_timeout);
    board.copy(&value).map_err(|e| anyhow::anyhow!("{e}"))?;
    match board.timeout_secs() {
        /* The wipe is a thread inside this process, so exiting now would
           abandon the secret on the clipboard. Wait it out, say so, and wipe
           before returning — a `get` that exits instantly is a `get` that
           leaves a password sitting there. */
        Some(secs) => {
            eprintln!("copied the {} for {title} · clears in {secs}s", field.name());
            std::thread::sleep(Duration::from_secs(secs));
            board.clear_now();
        }
        // `clipboard_timeout = 0` asked for it to stay; nothing to wait for.
        None => {
            eprintln!("copied the {} for {title}", field.name());
            warn_copy_dies_on_exit();
        }
    }
    Ok(())
}

// Wayland and X11 serve a copy from the owning process, so it goes when we exit
// unless a clipboard manager took it.
fn warn_copy_dies_on_exit() {
    if cfg!(target_os = "linux") {
        eprintln!("the copy lasts only while a clipboard manager holds it  ·  use --stdout otherwise");
    }
}

/* `sennel gen`: the generator on its own, with no entry to write it into and
   no vault to unlock. Copies by default, like `get`, so the password is one
   paste away and gone on the same timer. */
fn make_password(
    cfg: &Config,
    settings: config::Generator,
    count: usize,
    to_stdout: bool,
    force: bool,
) -> Result<()> {
    if to_stdout && std::io::stdout().is_terminal() && !force {
        anyhow::bail!(
            "--stdout into a terminal would leave the password in your scrollback · pipe it, or --force"
        );
    }
    if count == 0 {
        anyhow::bail!("--count 0 would generate nothing");
    }
    let make = || {
        (match settings.kind {
            generator::Kind::Complex => {
                generator::generate(settings.length, settings.classes, settings.exclude_ambiguous)
            }
            generator::Kind::Passphrase => generator::generate_passphrase(settings.words),
            generator::Kind::Pin => generator::generate_pin(settings.pin_length),
        })
        .map_err(|e| anyhow::anyhow!("{e}"))
    };
    let bits = settings.bits();
    if to_stdout {
        for _ in 0..count {
            let mut password = make()?;
            say!("{password}");
            password.zeroize();
        }
        return Ok(());
    }

    let mut password = make()?;
    let board = Board::new(cfg.clipboard_timeout);
    /* Wiped before the error is raised, not after: `?` on the copy would
       return with the plaintext still in this frame's String. */
    let copied = board.copy(&password).map_err(|e| anyhow::anyhow!("{e}"));
    password.zeroize();
    copied?;
    match board.timeout_secs() {
        // The wipe is a thread in this process, so exiting now abandons it.
        Some(secs) => {
            eprintln!(
                "copied {} · {} · ~{bits:.0} bits · clears in {secs}s",
                settings.amount(),
                settings.describe()
            );
            std::thread::sleep(Duration::from_secs(secs));
            board.clear_now();
        }
        None => {
            eprintln!(
                "copied {} · {} · ~{bits:.0} bits",
                settings.amount(),
                settings.describe()
            );
            warn_copy_dies_on_exit();
        }
    }
    Ok(())
}

fn walk_groups(vault: &Vault) -> Vec<(GroupId, usize)> {
    let mut out = Vec::new();
    let mut stack = vec![(vault.root_id(), 0)];
    while let Some((id, depth)) = stack.pop() {
        out.push((id, depth));
        for child in vault.groups_in(&id).iter().rev() {
            stack.push((child.id(), depth + 1));
        }
    }
    out
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    /* The window title follows the vault, so a wall of terminals says which
       one holds what. Only written when it changes: an escape sequence per
       frame is a write per frame for nothing. */
    let mut titled = String::new();
    while !app.quit {
        app.expire_flash();
        /* Once per frame, not per keypress: idleness is the absence of keys,
           and nothing else on screen moves between messages to re-check it. */
        app.check_idle();
        terminal.draw(|frame| ui::draw(frame, app))?;
        /* After the frame, not in the key handler: Argon2 blocks this thread,
           and the screen has to carry "unlocking…" before it does. */
        if app.unlocking {
            unlock_now(app);
            terminal.draw(|frame| ui::draw(frame, app))?;
        }
        // Same for a save that waits on the hardware key.
        if app.has_pending() {
            app.flush_pending();
            terminal.draw(|frame| ui::draw(frame, app))?;
        }
        /* Sanitised: the title is a file name, and a file name may hold an
           escape — which would go straight into the terminal's OSC. */
        let title = printable(&app.window_title());
        if title != titled {
            let _ = execute!(std::io::stdout(), SetTitle(&title));
            titled = title;
        }
        app.tick = app.tick.wrapping_add(1);

        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    handle_key(app, key.code, key.modifiers);
                }
                Event::Mouse(mouse) => handle_mouse(app, mouse),
                Event::Paste(text) => handle_paste(app, text),
                _ => {}
            }
        }
    }
    Ok(())
}

/* Wheel scrolls the pane under the pointer, click selects a row and hands
   that pane the keys. Nothing here is the only way to do anything — the mouse
   is a convenience over a keyboard app, so it stays out of the popups, where
   a stray click would answer a question. */
fn handle_mouse(app: &mut App, mouse: event::MouseEvent) {
    app.drop_blocked_menu();
    // Ahead of `click`, whose copy rows match on the screen row alone and may sit under a menu row.
    if app.menu.is_some() {
        app.touch();
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => app.click_menu(mouse.column, mouse.row),
            MouseEventKind::Down(MouseButton::Right) => app.right_click_menu(mouse.column, mouse.row),
            MouseEventKind::ScrollDown => app.wheel_menu(mouse.column, mouse.row, true),
            MouseEventKind::ScrollUp => app.wheel_menu(mouse.column, mouse.row, false),
            _ => {}
        }
        return;
    }
    /* The popups that ask a question keep the mouse out, so a stray click
       cannot answer one. The detail popup is not a question — it is the only
       detail view a narrow terminal has, and its rows copy on click like the
       pane's do — so it stays in, and `click` only acts on a copy row while
       it is up. */
    if app.view != app::View::Browser || app.popup_open() {
        return;
    }
    app.touch();
    match mouse.kind {
        MouseEventKind::ScrollDown => app.wheel(mouse.column, mouse.row, true),
        MouseEventKind::ScrollUp => app.wheel(mouse.column, mouse.row, false),
        MouseEventKind::Down(MouseButton::Left) => app.click(mouse.column, mouse.row),
        MouseEventKind::Down(MouseButton::Right) => app.context_menu(mouse.column, mouse.row),
        _ => {}
    }
}

// A paste is fed as keystrokes to the focused box only. Line breaks are dropped (so the last one cannot
// press Enter) except in notes, and the pasted string is wiped, since it may be a password or a seed.
fn handle_paste(app: &mut App, mut text: String) {
    const LIMIT: usize = 16 * 1024;
    app.touch();
    if !app.takes_text() {
        app.say("nothing here takes pasted text");
    } else if text.len() > LIMIT {
        app.warn("that paste is too long to be a field  ·  ignored");
    } else {
        for c in text.chars() {
            match c {
                '\n' if app.in_notes() => app.form_newline(),
                c if c.is_control() => {}
                c => handle_key(app, KeyCode::Char(c), KeyModifiers::NONE),
            }
        }
    }
    text.zeroize();
}

// Any other key closes the menu and then does what it always does, so ^l still locks and `p` still copies.
fn handle_menu_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    match code {
        KeyCode::Esc => app.close_menu(),
        KeyCode::Down | KeyCode::Char('j') => app.step_menu(true),
        KeyCode::Up | KeyCode::Char('k') => app.step_menu(false),
        KeyCode::Right => app.shift_menu(true),
        KeyCode::Left => app.shift_menu(false),
        KeyCode::Enter => app.choose_menu(),
        _ => {
            app.close_menu();
            handle_key(app, code, mods);
        }
    }
}

fn handle_commands_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Esc => app.commands = None,
        // As in a menu: ^c closes the palette and then does what it does in the browser.
        KeyCode::Char('c') if ctrl => {
            app.commands = None;
            handle_key(app, code, mods);
        }
        KeyCode::Enter => app.run_command(),
        KeyCode::Down => app.step_command(true),
        KeyCode::Up => app.step_command(false),
        KeyCode::Char('n') if ctrl => app.step_command(true),
        KeyCode::Char('p') if ctrl => app.step_command(false),
        KeyCode::Char('u') if ctrl => app.command_clear(),
        KeyCode::Backspace => app.command_backspace(),
        KeyCode::Char(c) if !ctrl => app.command_type(c),
        _ => {}
    }
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    /* First, because this is the proof of presence: every key that reaches
       the session restarts the idle clock, including the ones swallowed
       below. The poll timeout is not presence, so `run` never touches it. */
    app.touch();
    app.drop_blocked_menu();
    /* Ahead of every screen's keys: it is the UI's own question and the
       answer must not also reach the list behind it. */
    if app.confirm.is_some() {
        handle_confirm_key(app, code, mods);
        return;
    }
    /* The entry form is modal the same way: typing lands in the boxes and
       the browser behind it must not also act on the key. */
    if app.form.is_some() {
        handle_form_key(app, code, mods);
        return;
    }
    if app.menu.is_some() {
        handle_menu_key(app, code, mods);
        return;
    }
    // Every printable key is part of the query, so `q` and `h` type here.
    if app.commands.is_some() {
        handle_commands_key(app, code, mods);
        return;
    }
    /* The group prompt is modal on the same terms, one box instead of five. */
    if app.group_prompt.is_some() {
        handle_group_prompt_key(app, code, mods);
        return;
    }
    /* Old versions of an entry: a list you steer, like the audit. */
    if app.history.is_some() {
        handle_history_key(app, code, mods);
        return;
    }
    /* The fields screen owns the keys, and its own add prompt owns them
       harder: every printable key is part of a field name or value there. */
    if app.fields.is_some() {
        handle_fields_key(app, code, mods);
        return;
    }
    /* The audit is a list you steer, so it owns the keys while it is up. */
    if app.audit.is_some() {
        handle_audit_key(app, code, mods);
        return;
    }
    /* So is the change-password prompt, and more so than most: every
       printable key is part of a master password, so `q` and `h` are text
       here the way they are on the lock screen. */
    if app.rekey.is_some() {
        handle_rekey_key(app, code, mods);
        return;
    }
    /* The search band is modal the same way: `q` types a letter into the
       needle, `h` too. Enter and Esc hand the keys back to the browser —
       routing reads `band`, not `search.is_some()`, because a kept filter
       must not swallow the browser's keys. */
    if app.band {
        handle_search_key(app, code, mods);
        return;
    }
    /* Enter's detail popup is modal too: the browser behind it must not move
       under a key aimed at the entry on screen. */
    if app.detail {
        handle_detail_key(app, code, mods);
        return;
    }
    /* The overlay swallows the next key rather than acting on it: anything
       else makes dismissing it a guess about what the key also did. `q`
       included — it used to fall through, which quit the session on the
       browser and typed a character into the master password on the lock
       screen, with the popup still up over the box it landed in. */
    if app.show_help {
        app.show_help = false;
        return;
    }
    /* The picker owns the keys while it is open: the boxes behind it must not
       take a letter meant to narrow a list. */
    if app.browse.is_some() {
        handle_browse_key(app, code, mods);
        return;
    }
    // The library owns the keys the same way, and for the same reason.
    if app.library.is_some() {
        handle_library_key(app, code, mods);
        return;
    }
    /* So does the generator: `y` copies what is on screen, and it must not
       also copy the username of whatever the browser's cursor is on. */
    if app.mint.is_some() {
        handle_mint_key(app, code, mods);
        return;
    }
    /* The lock screen owns every printable key, so the overlay needs one no
       password can contain: `h` there types an h, which left the bar's "h
       keys" promising a key that does not exist on the first screen anybody
       sees. */
    if matches!(code, KeyCode::F(1)) {
        app.open_help();
        return;
    }
    /* The lock screen owns its own keys: typing `q` or `h` must land in the
       box, not end the session or open the overlay. Only ^c quits here. */
    if app.view == app::View::Unlock {
        handle_unlock_key(app, code, mods);
        return;
    }
    /* The vault owns its own keys: movement, panes and (from later waves)
       copy, edit and search. The global match below stays for the views that
       have no screen of their own. */
    if app.view == app::View::Browser {
        handle_browser_key(app, code, mods);
        return;
    }
    match code {
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.quit = true,
        KeyCode::Char('h') | KeyCode::Char('?') => app.open_help(),
        KeyCode::Char('q') => app.ask_quit(),
        /* Esc never ends the session. There is no screen behind the lock yet,
           so it says so rather than going silent: a key that goes silent
           reads as a broken key. */
        KeyCode::Esc => app.say("this is the top  ·  q quits"),
        _ => {}
    }
}

 /* The vault's own keys: movement first, since a stuck cursor reads as a
    dead tool. Keys owned by later waves (/ search) say which wave they
    belong to rather than going silent: a key that goes silent reads as a
    broken key. */
fn handle_browser_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.quit = true,
        KeyCode::Char('h') | KeyCode::Char('?') => app.open_help(),
        KeyCode::Char('q') => app.ask_quit(),
        /* Esc unwinds the armed cut, then a kept filter, before its usual
           report: a mis-cut is one press from undone, a bad needle one press
           from gone, and Esc never quits. */
        KeyCode::Esc => {
            if !app.drop_cut() && !app.clear_search() {
                app.say("this is the top  ·  q quits");
            }
        }
        KeyCode::Char('j') | KeyCode::Down => app.step_pane(true),
        KeyCode::Char('k') | KeyCode::Up => app.step_pane(false),
        KeyCode::PageDown => app.page_pane(true),
        KeyCode::PageUp => app.page_pane(false),
        KeyCode::Char('d') if ctrl => app.page_pane(true),
        KeyCode::Char('u') if ctrl => app.page_pane(false),
        /* Locking on demand used to mean quitting: `^l` drops the vault and
           leaves the session on the password prompt. */
        KeyCode::Char('l') if ctrl => app.lock_now(),
        /* Sennel autosaves, so `^s` is mostly the key a hand presses anyway —
           and it is the retry when a save failed or was refused. */
        KeyCode::Char('s') if ctrl => app.save_now(),
        KeyCode::Char('r') if ctrl => app.reload_vault(),
        // `^m` is Enter to a terminal, so the merge sits on `^f` for fuse.
        KeyCode::Char('f') if ctrl => app.merge_vault(),
        /* `^t` walks the palettes: a theme is picked by looking at it, not by
           reading its name in a config file. */
        KeyCode::Char('t') if ctrl => app.cycle_theme(),
        /* `P`: a password with no entry to put it in. Shifted, beside the
           other structural verbs, and not `^g` — that already narrows the
           search to a group, and one key with two meanings in one keymap is
           a key nobody trusts. */
        KeyCode::Char('P') => app.open_mint(),
        KeyCode::Char('g') | KeyCode::Home => app.jump_pane(false),
        KeyCode::Char('G') | KeyCode::End => app.jump_pane(true),
        KeyCode::Tab => app.switch_pane(),
        KeyCode::Char('*') => app.toggle_password(),
        KeyCode::Char('y') => app.copy_username(),
        /* Before the bare `p`, which matches whatever modifiers are held:
           changing the master password sits one key away from copying one,
           so the ctrl arm has to be the one tested first. */
        KeyCode::Char('p') if ctrl => app.open_rekey(),
        KeyCode::Char('p') => app.copy_password(),
        KeyCode::Char('U') => app.copy_url(),
        KeyCode::Char('t') => app.copy_totp(),
        /* Case carries meaning: `a` adds, `A` names a group (wave 5), so
           the edit keys stay lowercase-shifted apart on purpose. */
        KeyCode::Char('a') => app.open_add_form(),
        KeyCode::Char('e') => app.open_edit_form(),
        /* Group keys. A and E name groups from either pane; D follows the
           pane — the cursor decides what deleting means. */
        /* `!`: what is wrong with this vault's passwords. Shift-1, so it is
           never a slip away from a movement key. */
        KeyCode::Char('!') => app.open_audit(),
        /* `F`: custom fields and attachments. Upper case, beside the other
           structural keys, and never a slip from `f`. */
        KeyCode::Char('F') => app.open_fields(),
        /* `H`: old versions, which only ever come from another client. */
        KeyCode::Char('H') => app.open_history(),
        /* `>` and `<` reorganise the tree without a cut-and-paste trip.
           Groups pane only: on entries the cursor is on a row, not a folder,
           and `X`/`V` is the move that means something there. */
        KeyCode::Char('>') if app.active_pane == app::Pane::Groups => app.reparent_group(true),
        KeyCode::Char('<') if app.active_pane == app::Pane::Groups => app.reparent_group(false),
        KeyCode::Char('A') => app.open_group_prompt_new(),
        KeyCode::Char('E') => app.open_group_prompt_rename(),
        KeyCode::Char('D') if app.active_pane == app::Pane::Groups => app.ask_delete_group(),
        KeyCode::Char('D') => app.ask_delete_entry(),
        KeyCode::Char('X') => app.cut_selected(),
        KeyCode::Char('V') => app.paste_cut(),
        /* Left folds on the groups pane and hops there from the entries pane;
           Right re-opens. `o` cycles the entries order. */
        KeyCode::Left if app.active_pane == app::Pane::Groups => app.collapse_group(),
        KeyCode::Left => app.switch_pane(),
        KeyCode::Right if app.active_pane == app::Pane::Groups => app.expand_group(),
        // Left hops back to the tree, so Right goes forward into the entry.
        KeyCode::Right => app.open_detail(),
        KeyCode::Char('o') => app.cycle_order(),
        /* n/N walk the matches while the band is live, and step entries
           otherwise — the same key, honest in both modes. */
        KeyCode::Char('n') => app.jump_match(true),
        KeyCode::Char('N') => app.jump_match(false),
        /* `u` undoes the last one-slot change; ^u stays page-up. */
        KeyCode::Char('u') => app.undo_last(),
        KeyCode::Char('/') => app.open_search(),
        KeyCode::Char(':') => app.open_commands(),
        /* The near misses of a keymap that means case: silence here reads as
           a broken key, and the message is the only thing that teaches the
           shift. */
        KeyCode::Char(c @ ('x' | 'v' | 'd')) => app.say(format!(
            "{} is {} here  ·  shift matters in this keymap",
            c,
            match c {
                'x' => "X (cut)",
                'v' => "V (paste)",
                _ => "D (delete)",
            }
        )),
        /* Enter opens what the cursor is on: a group unfolds and hands over
           its entries, an entry opens the detail popup. */
        KeyCode::Enter => app.open_selection(),
        _ => {}
    }
}

/* The detail popup's own keys: the copies and the reveal it advertises, and
   nothing that would move the list behind it. `e` edits the entry being read,
   which is where the hand already is. */
fn handle_detail_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.ask_quit(),
        // The one key that must work with a secret on screen.
        KeyCode::Char('l') if ctrl => app.lock_now(),
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.close_detail(),
        KeyCode::Char('*') => app.toggle_password(),
        KeyCode::Char('y') => app.copy_username(),
        KeyCode::Char('p') => app.copy_password(),
        KeyCode::Char('U') => app.copy_url(),
        KeyCode::Char('t') => app.copy_totp(),
        KeyCode::Char('e') => {
            app.close_detail();
            app.open_edit_form();
        }
        /* The popup is the detail view below 100 columns, so reading the next
           entry must not mean closing it, moving, and opening it again. */
        KeyCode::Char('j') | KeyCode::Down => app.step_detail(true),
        KeyCode::Char('k') | KeyCode::Up => app.step_detail(false),
        KeyCode::Char('n') => app.jump_match(true),
        KeyCode::Char('N') => app.jump_match(false),
        _ => app.say("esc closes the entry"),
    }
}

/* The search band owns every printable key while it is open — `q` types a
   letter, `h` types a letter — so only named chords and Enter/Esc are
   commands. The shape mirrors the form boxes exactly. */
fn handle_search_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.ask_quit(),
        KeyCode::Esc => {
            if !app.clear_search() {
                app.say("this is the top  ·  q quits");
            }
        }
        KeyCode::Enter => app.keep_search(),
        /* The list the band is filtering is the list the arrows move. Typing
           a needle and reaching for ↓ is what every fuzzy finder has taught,
           and the caret keys stay on ←/→ where the text is. */
        KeyCode::Down => app.step_entry(true),
        KeyCode::Up => app.step_entry(false),
        KeyCode::Char('n') if ctrl => app.step_entry(true),
        KeyCode::Char('p') if ctrl => app.step_entry(false),
        KeyCode::Char('u') if ctrl => app.search_clear(),
        KeyCode::Char('w') if ctrl => app.search_kill_word(),
        KeyCode::Char('g') if ctrl => app.toggle_search_scope(),
        KeyCode::Left if !ctrl => app.search_move(false),
        KeyCode::Right if !ctrl => app.search_move(true),
        KeyCode::Home if !ctrl => app.search_end(false),
        KeyCode::End if !ctrl => app.search_end(true),
        KeyCode::Char('a') if ctrl => app.search_end(false),
        KeyCode::Char('e') if ctrl => app.search_end(true),
        KeyCode::Delete if !ctrl => app.search_delete(),
        KeyCode::Backspace => app.search_backspace(),
        KeyCode::Char(c) if !ctrl => app.search_insert(c),
        _ => {}
    }
}

/* The form owns every printable key while it is open — `q` types a letter,
   `h` types a letter — so only named chords and Enter/Esc are commands. The
   shape mirrors the unlock boxes: Tab cycles, ^u/^w clear, Enter submits. */
fn handle_form_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        /* ^c asks the quit guard rather than dying mid-edit: the form may
           hold changes the autosave never got to make. */
        KeyCode::Char('c') if ctrl => app.ask_quit(),
        KeyCode::Esc => app.cancel_form(),
        KeyCode::Tab | KeyCode::Down if !ctrl => app.next_form_field(true),
        KeyCode::BackTab | KeyCode::Up if !ctrl => app.next_form_field(false),
        KeyCode::Char('u') if ctrl => app.form_clear(),
        /* ^s generates into the password box: a fresh secret without
           leaving the form, named in the flash with its entropy. */
        KeyCode::Char('s') if ctrl => app.form_generate(),
        /* ^y copies the password box before the entry is saved: paste it
           into the site first, then Enter keeps it. */
        KeyCode::Char('y') if ctrl => app.form_copy_password(),
        /* The lock screen's reveal, on the same key: a generated password
           masked end to end cannot be checked before it is stored. */
        KeyCode::Char('r') if ctrl => app.toggle_form_reveal(),
        /* Enter submits, so a line break needs a key of its own — otherwise
           notes can lose one and never gain one. */
        KeyCode::Enter if mods.contains(KeyModifiers::ALT) => app.form_newline(),
        KeyCode::Char('j') if ctrl => app.form_newline(),
        KeyCode::Char('w') if ctrl => app.form_kill_word(),
        KeyCode::Left if !ctrl => app.form_move(false),
        KeyCode::Right if !ctrl => app.form_move(true),
        KeyCode::Home if !ctrl => app.form_end(false),
        KeyCode::End if !ctrl => app.form_end(true),
        KeyCode::Char('a') if ctrl => app.form_end(false),
        KeyCode::Char('e') if ctrl => app.form_end(true),
        KeyCode::Delete if !ctrl => app.form_delete(),
        KeyCode::Backspace => app.form_backspace(),
        KeyCode::Enter => app.submit_form(),
        KeyCode::Char(c) if !ctrl => app.form_insert(c),
        _ => {}
    }
}

/* The group prompt: one box, so no cycling — just editing keys, Enter and
   Esc. Same shape as the entry form minus the field movement. */
/* Old versions of an entry. `D` clears the lot, which is the only write this
   screen has: there is no "restore this version", because that is an edit and
   the form is where edits happen. */
fn handle_history_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('H') => app.close_history(),
        KeyCode::Char('j') | KeyCode::Down => app.history_move(true),
        KeyCode::Char('k') | KeyCode::Up => app.history_move(false),
        KeyCode::Char('*') => app.history_reveal(),
        KeyCode::Char('D') => app.clear_history(),
        KeyCode::Char('c') if ctrl => app.quit = true,
        _ => {}
    }
}

/* The fields screen. While the add prompt is up it takes every printable
   key, because a field name or value can be any of them; otherwise this is a
   list you steer, with one key per verb. */
fn handle_fields_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    if app.fields.as_ref().is_some_and(|f| f.adding.is_some()) {
        match code {
            KeyCode::Esc => app.fields_add_cancel(),
            KeyCode::Tab | KeyCode::Down | KeyCode::Up => app.fields_add_next(),
            KeyCode::Enter => app.fields_add_submit(),
            KeyCode::Backspace => app.fields_add_backspace(),
            KeyCode::Char(c) if !ctrl => app.fields_add_insert(c),
            _ => {}
        }
        return;
    }
    match code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('F') => app.close_fields(),
        KeyCode::Char('j') | KeyCode::Down => app.fields_move(true),
        KeyCode::Char('k') | KeyCode::Up => app.fields_move(false),
        KeyCode::Char('*') => app.fields_reveal(),
        KeyCode::Char('y') => app.fields_copy(),
        KeyCode::Char('s') => app.fields_save(),
        KeyCode::Char('g') => app.fields_to_agent(),
        KeyCode::Char('a') => app.fields_add(false),
        KeyCode::Char('f') => app.fields_add(true),
        KeyCode::Char('D') => app.fields_remove(),
        KeyCode::Char('c') if ctrl => app.quit = true,
        _ => {}
    }
}

/* The audit list: move, open, leave. Enter is the whole point — a list of
   problems you cannot act on from where you are standing is a list nobody
   works through. */
fn handle_audit_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('!') => app.close_audit(),
        KeyCode::Char('j') | KeyCode::Down => app.audit_move(true),
        KeyCode::Char('k') | KeyCode::Up => app.audit_move(false),
        KeyCode::Enter => app.audit_open_selected(),
        KeyCode::Char('c') if ctrl => app.quit = true,
        _ => {}
    }
}

/* Two masked boxes and nothing else. Every printable key is text, including
   the ones that are verbs everywhere else, so the reveal is `^r` and the way
   out is Esc. */
fn handle_rekey_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Esc => app.close_rekey(),
        KeyCode::Char('r') if ctrl => app.rekey_reveal(),
        KeyCode::Tab | KeyCode::Down | KeyCode::Up => app.rekey_next_field(),
        KeyCode::Enter => app.submit_rekey(),
        KeyCode::Backspace => app.rekey_backspace(),
        KeyCode::Char(c) if !ctrl => app.rekey_insert(c),
        _ => {}
    }
}

fn handle_group_prompt_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.ask_quit(),
        KeyCode::Esc => app.cancel_group_prompt(),
        KeyCode::Char('u') if ctrl => app.group_prompt_clear(),
        KeyCode::Char('w') if ctrl => app.group_prompt_kill_word(),
        KeyCode::Left if !ctrl => app.group_prompt_move(false),
        KeyCode::Right if !ctrl => app.group_prompt_move(true),
        KeyCode::Home if !ctrl => app.group_prompt_end(false),
        KeyCode::End if !ctrl => app.group_prompt_end(true),
        KeyCode::Char('a') if ctrl => app.group_prompt_end(false),
        KeyCode::Char('e') if ctrl => app.group_prompt_end(true),
        KeyCode::Delete if !ctrl => app.group_prompt_delete(),
        KeyCode::Backspace => app.group_prompt_backspace(),
        KeyCode::Enter => app.submit_group_prompt(),
        KeyCode::Char(c) if !ctrl => app.group_prompt_insert(c),
        _ => {}
    }
}

/* The file picker: movement, a typed filter, and the two keys that leave it.
   Left goes up a directory rather than moving a caret — there is no text here
   to move through, only a tree. */
fn handle_browse_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.quit = true,
        KeyCode::Esc => app.close_browse(),
        KeyCode::Enter | KeyCode::Right => app.browse_choose(),
        KeyCode::Left => app.browse_up(),
        KeyCode::Up => app.browse_step(false),
        KeyCode::Down => app.browse_step(true),
        KeyCode::Char('p') if ctrl => app.browse_step(false),
        KeyCode::Char('n') if ctrl => app.browse_step(true),
        KeyCode::Home => app.browse_end(false),
        KeyCode::End => app.browse_end(true),
        KeyCode::Backspace => app.browse_backspace(),
        KeyCode::Char(c) if !ctrl => app.browse_filter(c),
        _ => {}
    }
}

/* The vault library. Same shape as the picker above, plus `^d`, which drops
   a row from the list and never touches the file behind it. */
fn handle_library_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.quit = true,
        KeyCode::Esc => app.close_library(),
        KeyCode::Enter => app.library_choose(),
        KeyCode::Up => app.library_step(false),
        KeyCode::Down => app.library_step(true),
        KeyCode::Char('p') if ctrl => app.library_step(false),
        KeyCode::Char('n') if ctrl => app.library_step(true),
        KeyCode::Char('d') if ctrl => app.library_forget(),
        KeyCode::Home => app.library_end(false),
        KeyCode::End => app.library_end(true),
        KeyCode::Backspace => app.library_backspace(),
        KeyCode::Char(c) if !ctrl => app.library_filter(c),
        _ => {}
    }
}

/* One key per knob, and every one of them rolls a new password: the screen
   must never describe settings the password on it was not drawn from. */
fn handle_mint_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.ask_quit(),
        // The one key that must work with a secret on screen.
        KeyCode::Char('l') if ctrl => app.lock_now(),
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('P') => app.close_mint(),
        KeyCode::Char('r') | KeyCode::Char(' ') => app.mint_reroll(),
        // `y` copies here as it does everywhere else in the browser.
        KeyCode::Char('y') | KeyCode::Enter => app.mint_copy(),
        /* `t` walks the kinds — complex, passphrase, pin — and rolls at
           each stop, so the screen never describes a secret it did not draw. */
        KeyCode::Char('t') => app.mint_cycle_kind(),
        KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Right => app.mint_resize(true),
        KeyCode::Char('-') | KeyCode::Char('_') | KeyCode::Left => app.mint_resize(false),
        KeyCode::Char('s') => app.mint_toggle(app::Knob::Symbols),
        KeyCode::Char('d') => app.mint_toggle(app::Knob::Digits),
        KeyCode::Char('u') => app.mint_toggle(app::Knob::Upper),
        KeyCode::Char('a') => app.mint_toggle(app::Knob::Ambiguous),
        _ => app.say("esc closes the generator"),
    }
}

/* Every printable key is text while the lock owns the screen, so `q` types a
   letter instead of ending the session. The shape mirrors earworm's prompt
   keys: Tab/Up/Down cycle boxes, ^u/^w clear, arrows move by char, Enter
   unlocks, Esc clears-or-reports, ^c quits. */
fn handle_unlock_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Char('c') if ctrl => app.quit = true,
        KeyCode::Esc if !app.active_unlock_value().is_empty() => app.unlock_clear(),
        /* The lock is the screen behind everything, so Esc has nothing to go
           back to. It says so rather than quitting: Esc means the same thing
           on every screen or it means nothing anywhere. */
        KeyCode::Esc => app.say("locked  ·  ^c quits"),
        KeyCode::Tab | KeyCode::Down if !ctrl => app.next_unlock_field(true),
        KeyCode::BackTab | KeyCode::Up if !ctrl => app.next_unlock_field(false),
        KeyCode::Char('u') if ctrl => app.unlock_clear(),
        KeyCode::Char('w') if ctrl => app.unlock_kill_word(),
        /* `^r` flips the password box to plain text, matching the browser's
           detail-pane reveal on a key a password cannot contain: every
           printable key here is text, `*` and all — a password with a star
           in it would have been typed missing it. */
        KeyCode::Char('r') if ctrl => app.toggle_unlock_reveal(),
        /* `^o`: pick the vault from a list instead of typing its path. */
        KeyCode::Char('o') if ctrl => app.open_browse(),
        // The library mixes vaults with and without a hardware key, so it is chosen here.
        KeyCode::Char('y') if ctrl => app.toggle_yubikey(),
        /* `^v`: the vaults this machine has opened before, which is a shorter
           list than the disk and the one a second vault lives on. */
        KeyCode::Char('v') if ctrl => app.open_library(),
        // The first screen anybody sees is the first one worth recolouring.
        KeyCode::Char('t') if ctrl => app.cycle_theme(),
        KeyCode::Left if !ctrl => app.unlock_move(false),
        KeyCode::Right if !ctrl => app.unlock_move(true),
        KeyCode::Home if !ctrl => app.unlock_end(false),
        KeyCode::End if !ctrl => app.unlock_end(true),
        KeyCode::Char('a') if ctrl => app.unlock_end(false),
        KeyCode::Char('e') if ctrl => app.unlock_end(true),
        KeyCode::Delete if !ctrl => app.unlock_delete(),
        KeyCode::Backspace => app.unlock_backspace(),
        /* The file box takes its own Enter: applying it is not an unlock, it
           names the vault the next unlock opens. */
        KeyCode::Enter if app.unlock_field == crate::app::UnlockField::File => {
            app.accept_file_box()
        }
        // Drawn once as "unlocking…" before the derivation takes the thread.
        KeyCode::Enter => app.begin_unlock(),
        KeyCode::Char(c) if !ctrl => app.unlock_insert(c),
        _ => {}
    }
}

// Enter on the lock screen. The typed secret is taken, used once and wiped here;
// the only copy `App` keeps is the one `touch_id` seals to the Enclave.
fn unlock_now(app: &mut App) {
    // Cleared before any early return, or the frame loop runs this again next frame.
    app.unlocking = false;
    /* Taken, not borrowed: `try_unlock` consumes and zeroizes on every path,
       and a take leaves `App` holding nothing the moment the key is read. */
    // Replaced, not taken: `mem::take` leaves zero capacity, so the next password
    // would grow through unwiped reallocations. See `app::secret_box`.
    let mut password: Vec<u8> =
        std::mem::replace(&mut app.unlock_password, app::secret_box()).into_bytes();
    /* Copied out first: the read below borrows `app` through the match, and a
       key-file error must still reach `say`. Key bytes are key material too,
       wiped the moment the attempt returns. */
    let key_path = app.unlock_keyfile.trim().to_string();
    let mut key_bytes: Option<Vec<u8>> = match key_path.as_str() {
        "" => None,
        path => match std::fs::read(path) {
            Ok(b) => Some(b),
            /* Named, not probed further: the next step is a path the user can
               check, and the content is key material that never reaches the
               screen. */
            Err(_) => {
                app.error(format!("cannot read key file {path}"));
                password.zeroize();
                return;
            }
        },
    };
    if !(password.is_empty() && app.quick_unlock(key_bytes.as_deref())) {
        app.try_unlock(&mut password, key_bytes.as_deref());
    }
    if let Some(b) = key_bytes.as_mut() {
        b.zeroize();
    }
}

/* `y` and Enter mean yes anywhere; `q` and `^c` only on the quit question,
   where they already mean quit — so `qq` still answers, and neither is a
   hidden yes on a delete. Everything else dismisses: an unrecognised key
   must not lose work. */
fn handle_confirm_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let quitting = matches!(app.confirm, Some(Confirm::Quit));
    let yes = matches!(code, KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter)
        || (quitting
            && (matches!(code, KeyCode::Char('q'))
                || (matches!(code, KeyCode::Char('c'))
                    && mods.contains(KeyModifiers::CONTROL))));
    let question = app.confirm.take();
    if yes {
        match question {
            Some(Confirm::Quit) => app.quit = true,
            /* The delete acts at once: the popup said what it was about, so
               a yes needs no second popup between answer and effect. */
            Some(Confirm::DeleteEntry { id, .. }) => app.confirm_delete_entry(id),
            Some(Confirm::DeleteGroup { id, .. }) => app.confirm_delete_group(id),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Confirm;
    use ratatui::crossterm::event::KeyModifiers;

    /* The guard on the one key that can still lose work, so an unrecognised
       key must not be an accidental yes. */
    #[test]
    fn only_a_deliberate_key_confirms_the_quit() {
        let asked = || {
            let mut app = App::new();
            app.confirm = Some(Confirm::Quit);
            app
        };

        for code in [
            KeyCode::Char('y'),
            KeyCode::Char('q'),
            KeyCode::Enter,
        ] {
            let mut app = asked();
            handle_confirm_key(&mut app, code, KeyModifiers::NONE);
            assert!(app.quit, "{code:?} was supposed to mean yes");
            assert_eq!(app.confirm, None, "{code:?} left the question open");
        }

        for code in [
            KeyCode::Esc,
            KeyCode::Char('n'),
            KeyCode::Char(' '),
            KeyCode::Backspace,
        ] {
            let mut app = asked();
            handle_confirm_key(&mut app, code, KeyModifiers::NONE);
            assert!(!app.quit, "{code:?} quit with nothing at stake");
            assert_eq!(app.confirm, None, "{code:?} left the question open");
        }
    }

    /* `q` means quit and `^c` means cancel everywhere else in the app: on a
       delete confirm, which advertises only `y`, neither may be a yes. */
    #[test]
    fn q_and_ctrl_c_do_not_confirm_a_delete() {
        for (code, mods) in [
            (KeyCode::Char('q'), KeyModifiers::NONE),
            (KeyCode::Char('c'), KeyModifiers::CONTROL),
        ] {
            let mut app = open_browser();
            handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
            handle_key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
            handle_key(&mut app, KeyCode::Char('D'), KeyModifiers::NONE);
            assert!(app.confirm.is_some(), "D deleted without asking");
            handle_key(&mut app, code, mods);
            assert_eq!(app.entry_rows().len(), 2, "{code:?} deleted the row");
            assert!(app.confirm.is_none(), "{code:?} left the question open");
            assert!(!app.quit, "{code:?} quit through the delete confirm");
        }
    }

    /* The overlay swallows whatever dismisses it. `q` used to fall through:
       on the browser that quit the session outright, and on the lock screen
       it typed into the master password while the popup stayed up. */
    #[test]
    fn any_key_closes_the_overlay_and_reaches_nothing_behind_it() {
        let mut app = open_browser();
        app.show_help = true;
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.quit, "q quit from behind the overlay");
        assert!(!app.show_help, "q left the overlay open");

        let mut app = App::new();
        app.show_help = true;
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(app.unlock_password, "", "a key reached the password box");
        assert!(!app.show_help, "q left the overlay open");
    }

    /* F1, because the lock screen takes every printable key as text and the
       bar promises a keys table there. */
    #[test]
    fn f1_opens_the_overlay_on_the_lock_screen() {
        let mut app = App::new();
        handle_key(&mut app, KeyCode::Char('h'), KeyModifiers::NONE);
        assert!(!app.show_help, "h opened the overlay instead of typing");
        assert_eq!(app.unlock_password, "h");
        handle_key(&mut app, KeyCode::F(1), KeyModifiers::NONE);
        assert!(app.show_help, "F1 did not open the overlay");
        assert_eq!(app.unlock_password, "h", "F1 typed into the password");
    }

    /* The band filters a list, and the arrows move it: Enter first was the
       only way to touch the results, which no fuzzy finder asks for. */
    #[test]
    fn the_band_moves_the_entry_cursor_while_it_filters() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto Banks
        handle_key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('/'), KeyModifiers::NONE);
        let first = app.entry_cursor;
        handle_key(&mut app, KeyCode::Down, KeyModifiers::NONE);
        assert_ne!(app.entry_cursor, first, "↓ did nothing inside the band");
        handle_key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(app.entry_cursor, first, "↑ did not come back");
    }

    /* A kept filter is about entries, so Enter leaves the keys there rather
       than on a tree the user has stopped looking at. */
    #[test]
    fn keeping_a_filter_hands_the_keys_to_the_results() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('/'), KeyModifiers::NONE);
        for ch in "check".chars() {
            handle_key(&mut app, KeyCode::Char(ch), KeyModifiers::NONE);
        }
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.active_pane, crate::app::Pane::Entries);
    }

    /* Near misses of a keymap that means case answer instead of going quiet,
       and Right goes forward into the entry the way Left goes back. */
    #[test]
    fn the_near_miss_keys_say_what_the_real_one_is() {
        for (typed, wanted) in [('x', "X (cut)"), ('v', "V (paste)"), ('d', "D (delete)")] {
            let mut app = open_browser();
            handle_key(&mut app, KeyCode::Char(typed), KeyModifiers::NONE);
            assert!(app.stage.contains(wanted), "{typed}: {}", app.stage);
        }
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Right, KeyModifiers::NONE);
        assert!(app.detail, "Right did not open the entry");
    }

    /* The hardening is two syscalls whose only proof is the limit they set:
       a core dump of this process would hold every secret at once. The
       companion check — that every entry point reaches it, not only the TUI —
       is `every_entry_point_disables_core_dumps` in tests/get.rs, which has
       to be out of process to see a real `main`. */
    #[test]
    fn hardening_forbids_core_dumps() {
        harden();
        assert!(core_dumps_off(), "core dumps are still allowed");
    }

    /* Esc on the lock screen unwinds nothing and ends nothing: it says what
       the way out is instead of going quiet. */
    #[test]
    fn esc_reports_rather_than_quitting() {
        let mut app = App::new();
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(!app.quit, "esc ended the session");
        assert!(app.stage.contains("^c quits"), "{}", app.stage);
    }

    /* The lock owns its keys: `q` and `h` are text in the password box, not
       commands. Only ^c quits without a vault open. */
    #[test]
    fn plain_keys_type_on_the_lock_screen() {
        let mut app = App::new();
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.quit, "q quit from the lock screen");
        assert_eq!(app.unlock_password, "q");
        handle_key(&mut app, KeyCode::Char('h'), KeyModifiers::NONE);
        assert!(!app.show_help, "h opened the overlay over the lock");
        assert_eq!(app.unlock_password, "qh");
    }

    // A paste is typing: it fills the focused box and its trailing newline does not press Enter.
    #[test]
    fn a_paste_fills_the_lock_screen_without_unlocking_it() {
        let mut app = App::new();
        handle_paste(&mut app, "hunter2 with spaces\r\n".to_string());
        assert_eq!(app.unlock_password, "hunter2 with spaces");
        assert!(!app.unlocking, "the trailing newline pressed Enter");
    }

    // In the browser every character would be a command, `D` among them.
    #[test]
    fn a_paste_into_the_browser_does_nothing() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "keep", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        handle_paste(&mut app, "DDDD/qq".to_string());
        assert!(app.confirm.is_none() && !app.band && !app.quit);
        assert_eq!(app.session.vault().unwrap().entry_count(), 1);
        assert!(app.stage.contains("nothing here takes pasted text"), "{}", app.stage);
    }

    #[test]
    fn a_paste_into_the_form_keeps_line_breaks_only_in_notes() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "x", "", "", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.open_add_form();
        handle_paste(&mut app, "a title\n".to_string());
        assert_eq!(app.form.as_ref().unwrap().title, "a title");
        assert!(app.form.is_some(), "the newline submitted the form");

        app.form.as_mut().unwrap().field = crate::app::FormField::Notes;
        handle_paste(&mut app, "line one\nline two\r\n".to_string());
        assert_eq!(app.form.as_ref().unwrap().notes, "line one\nline two\n");
    }

    #[test]
    fn a_huge_paste_is_refused_not_typed() {
        let mut app = App::new();
        handle_paste(&mut app, "x".repeat(100_000));
        assert!(app.unlock_password.is_empty());
    }

    /* `^r` on the lock flips the password box to plain text like the
       browser's `*` does — and `*` itself stays a password character, which
       is exactly why the lock's reveal cannot borrow the browser's key. */
    #[test]
    fn ctrl_r_reveals_on_the_lock_screen_and_star_types() {
        let mut app = App::new();
        handle_key(&mut app, KeyCode::Char('s'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('3'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('*'), KeyModifiers::NONE);
        assert!(!app.unlock_reveal, "* revealed instead of typing");
        assert_eq!(app.unlock_password, "s3*");
        handle_key(
            &mut app,
            KeyCode::Char('r'),
            KeyModifiers::CONTROL,
        );
        assert!(app.unlock_reveal, "^r did not reveal");
        handle_key(&mut app, KeyCode::Char('r'), KeyModifiers::CONTROL);
        assert!(!app.unlock_reveal, "second ^r did not re-mask");
    }

    /* Enter on the lock with no database configured says what to do rather
       than failing on an empty path. */
    #[test]
    fn enter_without_a_database_names_the_flag() {
        let mut app = App::new();
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        /* Enter arms the unlock and the loop performs it after one frame, so
           the screen can say "unlocking…" before Argon2 takes the thread. */
        assert!(app.unlocking, "enter did not arm the unlock");
        assert_eq!(app.stage, "unlocking…");
        unlock_now(&mut app);
        assert_eq!(app.view, crate::app::View::Unlock, "unlocked without a file");
        assert!(app.stage.contains("--db"), "{}", app.stage);
        assert!(!app.unlocking, "the busy state outlived the attempt");
    }

    // Enter on the lock screen as the frame loop runs it, which clears the flash queue.
    fn enter(app: &mut App) {
        app.begin_unlock();
        unlock_now(app);
    }

    // Unlocked once by typing, then locked, the way every quick unlock starts.
    fn typed_then_locked(touch_id: bool) -> (App, crate::app::tests::TempPath) {
        let (mut app, tmp) = crate::app::tests::locked_app_with_db("correct horse");
        app.session.touch_id = touch_id;
        app.unlock_password = "correct horse".into();
        enter(&mut app);
        assert!(app.session.is_open(), "the typed unlock failed: {}", app.stage);
        app.expire_now();
        app.lock_now();
        (app, tmp)
    }

    #[test]
    fn touch_id_opens_the_vault_after_a_lock() {
        let (mut app, _tmp) = typed_then_locked(true);
        assert_eq!(app.stage, "locked  ·  enter for Touch ID");
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.stage, "unlocking…  Touch ID");
        unlock_now(&mut app);
        assert!(app.session.is_open(), "the sealed password did not open it: {}", app.stage);
        assert_eq!(app.view, crate::app::View::Browser);
    }

    #[test]
    fn without_touch_id_an_empty_box_is_still_refused() {
        let (mut app, _tmp) = typed_then_locked(false);
        assert_eq!(app.stage, "locked  ·  password to return");
        assert!(!app.quick_ready());
        enter(&mut app);
        assert!(!app.session.is_open());
        assert!(app.stage.contains("empty password"), "{}", app.stage);
    }

    // A dismissed prompt is not a wrong password: the next Enter asks again.
    #[test]
    fn a_cancelled_prompt_keeps_touch_id_for_the_next_try() {
        let (mut app, _tmp) = typed_then_locked(true);
        refuse(Some(crate::touchid::Refused::Again("cancelled".into())));
        enter(&mut app);
        refuse(None);
        assert!(!app.session.is_open());
        assert!(!app.unlocking, "the frame loop would open the prompt again next frame");
        assert!(app.stage.contains("cancelled"), "{}", app.stage);
        assert!(app.quick_ready(), "a cancel forgot the sealed password");
        enter(&mut app);
        assert!(app.session.is_open(), "{}", app.stage);
    }

    fn refuse(with: Option<crate::touchid::Refused>) {
        crate::touchid::REFUSE.with_borrow_mut(|r| *r = with);
    }

    // A key voided by a change of enrolled fingers would otherwise be offered forever.
    #[test]
    fn a_void_key_stops_the_offer() {
        let (mut app, _tmp) = typed_then_locked(true);
        refuse(Some(crate::touchid::Refused::Void("item not found".into())));
        enter(&mut app);
        refuse(None);
        assert!(!app.session.is_open());
        assert!(!app.quick_ready());
        assert!(app.stage.contains("type the password"), "{}", app.stage);
    }

    // Only a refused password drops it: a vault that cannot be read right now still opens later.
    #[test]
    fn a_vault_that_cannot_be_read_keeps_touch_id() {
        use std::os::unix::fs::PermissionsExt;
        let (mut app, tmp) = typed_then_locked(true);
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o000)).unwrap();
        enter(&mut app);
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!app.session.is_open(), "opened an unreadable file");
        assert!(app.quick_ready(), "a read error dropped the sealed password");
        enter(&mut app);
        assert!(app.session.is_open(), "{}", app.stage);
    }

    // ^o and the file box can name the vault through a symlinked folder.
    #[test]
    fn touch_id_follows_the_vault_under_another_spelling() {
        let (mut app, tmp) = typed_then_locked(true);
        let link = std::env::temp_dir().join(format!("sennel-test-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(tmp.0.parent().unwrap(), &link).unwrap();
        app.set_db_path(Some(link.join(tmp.0.file_name().unwrap())));
        let ready = app.quick_ready();
        std::fs::remove_file(&link).unwrap();
        assert!(ready, "the same vault through a symlink lost Touch ID");
    }

    // Re-keyed from another app: the sealed password is wrong for good, so stop offering it.
    #[test]
    fn a_password_changed_elsewhere_stops_the_offer() {
        let (mut app, tmp) = typed_then_locked(true);
        crate::vault::Vault::new().save_as(&tmp.0, "changed elsewhere", None).unwrap();
        enter(&mut app);
        assert!(!app.session.is_open());
        assert!(!app.quick_ready(), "Enter would try the stale password forever");
    }

    #[test]
    fn touch_id_follows_a_master_password_change() {
        let (mut app, tmp) = typed_then_locked(true);
        enter(&mut app);
        app.open_rekey();
        for c in "battery staple".chars() {
            app.rekey_insert(c);
        }
        app.rekey_next_field();
        for c in "battery staple".chars() {
            app.rekey_insert(c);
        }
        app.submit_rekey();
        assert!(crate::vault::Vault::open(&tmp.0, "battery staple", None).is_ok());
        app.lock_now();
        enter(&mut app);
        assert!(app.session.is_open(), "sealed the old password: {}", app.stage);
    }

    // Sealed for one vault, never offered for another typed into the file box.
    #[test]
    fn touch_id_belongs_to_the_vault_it_opened() {
        let (mut app, _tmp) = typed_then_locked(true);
        let (_, other) = crate::app::tests::locked_app_with_db("other");
        app.unlock_file = other.0.display().to_string();
        enter(&mut app);
        assert!(!app.session.is_open());
        assert!(app.stage.contains("empty password"), "{}", app.stage);
    }

    fn open_browser() -> App {
        let mut vault = crate::vault::Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "checking", "u", "p", "", "").unwrap();
        vault.create_entry(&banks, "savings", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app
    }

    /* Tab hands the movement keys to the other pane: j after Tab steps
       entries, not groups. */
    #[test]
    fn tab_hands_movement_to_the_other_pane() {
        let mut app = open_browser();
        assert_eq!(app.active_pane, crate::app::Pane::Groups);
        // Root holds no entries: step onto Banks before handing over.
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.active_pane, crate::app::Pane::Entries);
        let first = app.entry_cursor;
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        assert_ne!(app.entry_cursor, first, "j moved groups, not entries");
        assert_ne!(app.entry_cursor, None);
    }

    /* q on the vault asks first when there are unsaved changes: quitting
       would take them with it. A second q answers, so qq never reads. */
    #[test]
    fn q_asks_before_dropping_unsaved_changes() {
        let mut app = open_browser();
        app.mark_dirty();
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.quit, "q quit over unsaved changes");
        assert!(app.confirm.is_some(), "no question was asked");
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(app.quit, "a second q did not answer the question");
    }

    /* Copy keys with no board wired (tests never touch the OS clipboard)
       report the missing board instead of reaching for one. */
    #[test]
    fn copy_without_a_board_says_so() {
        let mut app = open_browser();
        // Root holds no entries: step onto Banks before copying.
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('p'), KeyModifiers::NONE);
        assert!(app.stage.contains("not ready"), "{}", app.stage);
    }

    /* Keys owned by later waves report their wave: silence reads as a
       broken key. `e` is live now (wave 5), so on the entry-less root it
       names the miss instead of opening a form on nothing. */
    #[test]
    fn future_keys_name_their_wave() {
        /* One app per key: the first flash is still up when the second key
           lands, so the second message queues instead of showing. */
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('e'), KeyModifiers::NONE);
        assert!(app.stage.contains("no entry"), "{}", app.stage);
    }

    /* `/` opens the band and the band owns the keys: `q` types a letter
       rather than quitting, Enter keeps the filter and hands keys back. */
    #[test]
    fn slash_opens_the_band_and_typing_filters() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto Banks
        handle_key(&mut app, KeyCode::Char('/'), KeyModifiers::NONE);
        assert!(app.search.is_some(), "/ did not open the band");
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.quit, "q quit from inside the band");
        handle_key(&mut app, KeyCode::Char('z'), KeyModifiers::NONE);
        // No entry matches "qz", so the pane empties rather than lying.
        assert!(app.entry_rows().is_empty(), "a non-matching needle kept rows");
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.search.is_some(), "enter did not keep the filter");
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        // Keys returned to the browser: j moved the cursor again.
        assert_ne!(app.group_cursor, None);
    }

    /* Esc with text in the band clears the filter; Esc again falls through
       to the usual report. Esc never quits. */
    #[test]
    fn esc_clears_the_band_before_its_usual_report() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('/'), KeyModifiers::NONE);
        /* A needle nothing matches: "qz" is not in any haystack, so the
           pane empties instead of quietly ignoring the filter. */
        for ch in "qz".chars() {
            handle_key(&mut app, KeyCode::Char(ch), KeyModifiers::NONE);
        }
        assert!(app.entry_rows().is_empty(), "the needle did not filter");
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.search.is_none(), "esc did not clear the band");
        assert!(!app.entry_rows().is_empty(), "clearing did not restore rows");
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(!app.quit, "esc quit the session");
    }

    /* The form is modal: `a` opens it, `q` types a letter rather than
       quitting, Enter writes the row into the cursor group. */
    #[test]
    fn a_opens_the_form_and_typing_lands_in_it() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
        assert!(app.form.is_some(), "a did not open the form");
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.quit, "q quit from inside the form");
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.form.is_none(), "enter did not submit");
        let rows = app.entry_rows();
        assert_eq!(rows.len(), 3, "the typed row was not added");
        assert_eq!(
            app.session.vault().unwrap().get_entry(&rows[2]).unwrap().title(),
            "q"
        );
    }

    /* D asks, y answers, the row is gone. The full loop through the real
       key handler, not the app method alone. Tab first: D follows the pane,
       and deleting a group is a different question. */
    #[test]
    fn d_asks_and_y_deletes() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('D'), KeyModifiers::NONE);
        assert!(app.confirm.is_some(), "D deleted without asking");
        handle_key(&mut app, KeyCode::Char('y'), KeyModifiers::NONE);
        // Banks held two rows; one delete leaves the other intact.
        assert_eq!(app.entry_rows().len(), 1, "y deleted the wrong number of rows");
        assert!(app.confirm.is_none(), "y left the question open");
    }

    /* Esc on the form throws it away and returns the keys to the browser. */
    #[test]
    fn esc_closes_the_form_without_writing() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('x'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.form.is_none());
        assert_eq!(app.entry_rows().len(), 2, "esc wrote the row anyway");
    }

    /* `A` opens the group prompt and it is modal on the same terms: `q`
       types a letter rather than quitting. */
    #[test]
    fn a_opens_the_group_prompt_and_typing_lands_in_it() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('A'), KeyModifiers::NONE);
        assert!(app.group_prompt.is_some(), "A did not open the prompt");
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.quit, "q quit from inside the prompt");
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.group_prompt.is_none(), "enter did not submit");
        let tree = app.group_tree();
        let named = tree.iter().any(|(id, _)| {
            app.session.vault().unwrap().get_group(id).unwrap().name == "q"
        });
        assert!(named, "the typed name did not become a group");
    }

    /* V with an empty shelf says so instead of pasting nothing. */
    #[test]
    fn v_without_a_cut_says_so() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('V'), KeyModifiers::NONE);
        assert!(app.stage.contains("nothing cut"), "{}", app.stage);
    }

    /* Esc unwinds the armed cut first; only with an empty shelf does it fall
       through to the top-of-tree report. */
    #[test]
    fn esc_drops_the_cut_before_its_usual_report() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('X'), KeyModifiers::NONE);
        assert!(app.session.cut().is_some(), "X did not arm the shelf");
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.session.cut().is_none(), "esc did not drop the cut");
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        // Second Esc has nothing to unwind: the usual report returns and,
        // above all, Esc never quits.
        assert!(!app.quit, "esc quit the session");
    }

    /* Left on the entries pane hands the keys to the groups pane, where the
       fold keys live; Left on the groups pane folds instead. */
    #[test]
    fn left_hops_panes_from_entries_and_folds_on_groups() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto Banks
        let banks = app.group_cursor.unwrap();
        // Banks needs a subtree to fold: a leaf correctly refuses.
        app.session.vault_mut()
            .unwrap()
            .create_group(&banks, "Work")
            .unwrap();
        handle_key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.active_pane, crate::app::Pane::Entries);
        handle_key(&mut app, KeyCode::Left, KeyModifiers::NONE);
        assert_eq!(app.active_pane, crate::app::Pane::Groups, "Left did not hop");
        handle_key(&mut app, KeyCode::Left, KeyModifiers::NONE);
        assert_eq!(app.group_tree().len(), 2, "Left did not fold the tree");
    }

    /* `o` cycles the entries order from the browser; the flash names the new
       order so the key never reads as dead. */
    #[test]
    fn o_cycles_the_order_and_says_so() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto Banks
        handle_key(&mut app, KeyCode::Char('o'), KeyModifiers::NONE);
        assert_eq!(app.order, crate::app::SortOrder::Name);
        handle_key(&mut app, KeyCode::Char('o'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('o'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('o'), KeyModifiers::NONE);
        assert_eq!(app.order, crate::app::SortOrder::Stored, "o did not wrap");
    }

    /* n/N walk the matches while the band is live: n moves to the next hit,
       and running past the end says so instead of wrapping. */
    #[test]
    fn n_walks_matches_and_names_the_end() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto Banks
        handle_key(&mut app, KeyCode::Char('/'), KeyModifiers::NONE);
        for ch in "savi".chars() {
            handle_key(&mut app, KeyCode::Char(ch), KeyModifiers::NONE);
        }
        assert_eq!(app.entry_rows().len(), 1, "the needle filtered to one");
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        // With the band kept, n walks the (single) match list: at the end.
        handle_key(&mut app, KeyCode::Char('n'), KeyModifiers::NONE);
        assert!(app.stage.contains("last match"), "{}", app.stage);
        handle_key(&mut app, KeyCode::Char('N'), KeyModifiers::NONE);
        /* 'first match' queues behind the still-live 'last match' flash:
           force the expiry the frame loop would perform, then read. */
        app.expire_now();
        assert!(app.stage.contains("first match"), "{}", app.stage);
    }

    /* The generator draws over the detail pane, and the pane's copy rows
       match on the screen row alone — no column. A click one row under the
       generated password used to land on `CopyRow::Password` and put the
       selected *entry's* password on the clipboard instead. */
    #[test]
    fn the_generator_keeps_the_mouse_out() {
        use crate::vault::Vault;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut vault = Vault::new();
        let root = vault.root_id();
        vault
            .create_entry(&root, "bank", "octo", "vault-password", "", "")
            .unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.switch_pane();
        app.step_pane(true);

        /* Short enough that the popup, drawn centred, covers the detail
           pane's copy rows — which is the terminal the bug needed. */
        let mut t = Terminal::new(TestBackend::new(120, 18)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let rows = app.copy_rows.clone();
        assert!(!rows.is_empty(), "no copy row to click through");

        app.open_mint();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let before = app.stage.clone();
        for (row, _) in &rows {
            handle_mouse(
                &mut app,
                event::MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: 60,
                    row: *row,
                    modifiers: KeyModifiers::NONE,
                },
            );
        }
        assert_eq!(app.stage, before, "a click reached the vault behind the popup");

        // And the panes must not scroll under a popup that is not scrollable.
        let where_it_was = app.entry_cursor;
        handle_mouse(
            &mut app,
            event::MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 60,
                row: 3,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.entry_cursor, where_it_was, "the list moved behind the popup");
    }

    /* The form routes ^s to the generator; plainly typing 's' still types. */
    #[test]
    fn ctrl_s_generates_inside_the_form() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Char('e'), KeyModifiers::NONE); // edit form
        handle_key(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        let (filled, touched) = {
            let form = app.form.as_ref().expect("the form stayed open");
            (!form.password.is_empty(), form.password_touched)
        };
        assert!(filled, "^s did not fill the password box");
        assert!(touched, "^s did not arm the write");
    }

    /* `u` in the browser undoes the last change: ^u stays page-up. */
    #[test]
    fn u_undoes_the_last_change_from_the_browser() {
        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto Banks
        handle_key(&mut app, KeyCode::Char('e'), KeyModifiers::NONE);
        if let Some(form) = app.form.as_mut() {
            form.notes = "via u".into();
        }
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE); // submit
        handle_key(&mut app, KeyCode::Char('u'), KeyModifiers::NONE);
        let entry = app
            .session
            .vault()
            .unwrap()
            .get_entry(&app.entry_cursor.unwrap())
            .unwrap();
        assert_eq!(entry.notes(), "", "u did not restore the notes");
    }

    fn menu_item(menu: crate::app::MenuId, label: &str) -> crate::app::MenuItem {
        let (_, _, items) = crate::app::MENUS.iter().find(|(id, _, _)| *id == menu).unwrap();
        *items.iter().find(|item| item.label == label).unwrap()
    }

    // `D` and `X` follow the active pane on the keyboard; the menu names the kind of row instead.
    #[test]
    fn menu_delete_and_cut_act_on_the_kind_of_row_they_name() {
        use crate::app::{Cut, MenuId, Pane};

        let groups = || {
            let mut app = open_browser();
            handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto Banks
            assert_eq!(app.active_pane, Pane::Groups);
            app
        };
        let entries = || {
            let mut app = groups();
            handle_key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
            assert_eq!(app.active_pane, Pane::Entries);
            app
        };

        let mut app = groups();
        app.run_menu(&menu_item(MenuId::Entry, "Delete"));
        assert!(matches!(app.confirm, Some(Confirm::DeleteEntry { .. })), "{:?}", app.confirm);
        assert_eq!(app.active_pane, Pane::Groups, "the menu moved the pane");

        let mut app = entries();
        app.run_menu(&menu_item(MenuId::Group, "Delete"));
        assert!(matches!(app.confirm, Some(Confirm::DeleteGroup { .. })), "{:?}", app.confirm);

        let mut app = groups();
        app.run_menu(&menu_item(MenuId::Entry, "Cut"));
        assert!(matches!(app.session.cut(), Some(Cut::Entry(_))), "{:?}", app.session.cut());

        let mut app = entries();
        app.run_menu(&menu_item(MenuId::Group, "Cut"));
        assert!(matches!(app.session.cut(), Some(Cut::Group(_))), "{:?}", app.session.cut());
    }

    // On the fields screen `D` deletes a field without asking, and in the entry popup `p` copies.
    #[test]
    fn menus_do_nothing_under_a_popup() {
        use crate::app::MenuId;

        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        app.open_fields();
        assert!(app.fields.is_some());
        app.run_menu(&menu_item(MenuId::Entry, "Delete"));
        assert!(app.confirm.is_none(), "Delete reached the browser behind the fields screen");
        assert!(app.fields.is_some());

        let mut app = open_browser();
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        app.detail = true;
        app.run_menu(&menu_item(MenuId::Vault, "Change master password"));
        assert!(app.rekey.is_none(), "rekey opened behind the entry popup");
        app.run_menu(&menu_item(MenuId::Vault, "Lock"));
        assert_eq!(app.view, crate::app::View::Browser, "Lock ran behind the entry popup");
    }

    #[test]
    fn every_menu_shortcut_is_in_the_help_table() {
        let listed: Vec<&str> = crate::ui::BROWSER_KEYS
            .iter()
            .flat_map(|(_, keys, _)| keys.split_whitespace())
            .collect();
        for (menu, _, items) in crate::app::MENUS {
            // `h` opens the table, and the status bar is where it is advertised.
            if *menu == crate::app::MenuId::Help {
                continue;
            }
            for item in items.iter().filter(|item| !item.shortcut.is_empty()) {
                assert!(
                    listed.contains(&item.shortcut),
                    "{menu:?} › {} shows {}, which the help table does not list",
                    item.label,
                    item.shortcut
                );
            }
        }
    }

    fn left_click(app: &mut App, column: u16, row: u16) {
        handle_mouse(
            app,
            event::MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column,
                row,
                modifiers: KeyModifiers::NONE,
            },
        );
    }

    // An entry selected in the entries pane, drawn short enough that the detail pane's copy rows sit under a dropdown.
    fn menu_screen() -> (App, ratatui::Terminal<ratatui::backend::TestBackend>) {
        let mut vault = crate::vault::Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "bank", "octo", "vault-password", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.switch_pane();
        app.step_pane(true);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 18)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        (app, t)
    }

    fn open_menu(app: &mut App, t: &mut ratatui::Terminal<ratatui::backend::TestBackend>, menu: crate::app::MenuId) {
        let (at, _) = *app.menu_bar.iter().find(|(_, id)| *id == menu).unwrap();
        left_click(app, at.x, at.y);
        assert_eq!(app.menu, Some(menu));
        t.draw(|f| ui::draw(f, app)).unwrap();
    }

    #[test]
    fn clicking_a_menu_row_runs_it_and_closes_the_menu() {
        let (mut app, mut t) = menu_screen();
        open_menu(&mut app, &mut t, crate::app::MenuId::Group);
        let row = app.menu_row(0).unwrap();
        left_click(&mut app, row.x + 1, row.y);
        assert_eq!(app.menu, None);
        assert!(app.group_prompt.is_some(), "Group › Add did not open the prompt");
    }

    #[test]
    fn a_click_outside_the_menu_closes_it_and_goes_no_further() {
        let (mut app, mut t) = menu_screen();
        let (cursor, pane) = (app.entry_cursor, app.active_pane);
        open_menu(&mut app, &mut t, crate::app::MenuId::Vault);
        let groups = app.group_area;
        left_click(&mut app, groups.x + 1, groups.y);
        assert_eq!(app.menu, None);
        assert_eq!((app.entry_cursor, app.active_pane), (cursor, pane), "the click reached the panes");
    }

    #[test]
    fn a_menu_row_over_a_copy_row_does_not_copy() {
        let (mut app, mut t) = menu_screen();
        open_menu(&mut app, &mut t, crate::app::MenuId::Entry);
        let row = (0..app.menu_shown)
            .filter_map(|n| app.menu_row(n))
            .find(|at| app.copy_rows.iter().any(|(y, _)| *y == at.y))
            .expect("no menu row shares a screen row with a copy row");
        left_click(&mut app, row.x + 1, row.y);
        assert_eq!(app.copied, None, "the click copied through the menu");
        assert_eq!(app.menu, None);
    }

    #[test]
    fn menu_labels_are_dead_under_a_popup() {
        let opens: [fn(&mut App); 5] = [
            App::open_mint,
            |app| app.confirm = Some(Confirm::Quit),
            App::open_help,
            App::open_search,
            |app| app.detail = true,
        ];
        for open in opens {
            let (mut app, mut t) = menu_screen();
            let (label, id) = app.menu_bar[0];
            open(&mut app);
            t.draw(|f| ui::draw(f, &mut app)).unwrap();
            left_click(&mut app, label.x, label.y);
            assert_eq!(app.menu, None, "{id:?} opened under a popup");
        }
    }

    #[test]
    fn menu_keys_move_run_and_close() {
        let (mut app, mut t) = menu_screen();
        open_menu(&mut app, &mut t, crate::app::MenuId::Group);
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(app.menu, None);

        open_menu(&mut app, &mut t, crate::app::MenuId::View);
        handle_key(&mut app, KeyCode::Left, KeyModifiers::NONE);
        assert_eq!(app.menu, Some(crate::app::MenuId::Group));
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        handle_key(&mut app, KeyCode::Down, KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.menu, None);
        assert!(app.group_prompt.is_some(), "Group › Rename did not open the prompt");

        let (mut app, mut t) = menu_screen();
        open_menu(&mut app, &mut t, crate::app::MenuId::Vault);
        handle_key(&mut app, KeyCode::Char('l'), KeyModifiers::CONTROL);
        assert_eq!(app.menu, None);
        assert_eq!(app.view, crate::app::View::Unlock, "^l was swallowed by the open menu");
    }

    #[test]
    fn a_cut_off_menu_keeps_its_cursor_on_rows_it_drew() {
        let (mut app, _) = menu_screen();
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 8)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        open_menu(&mut app, &mut t, crate::app::MenuId::Entry);
        let drawn = app.menu_shown;
        assert!(drawn < app.menu_items().len(), "the box was not cut off");
        handle_key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(app.menu_cursor, drawn - 1, "the cursor wrapped onto a hidden item");
    }

    #[test]
    fn the_wheel_over_a_menu_steps_its_cursor() {
        let (mut app, mut t) = menu_screen();
        open_menu(&mut app, &mut t, crate::app::MenuId::Entry);
        let row = app.menu_row(0).unwrap();
        let cursor = app.entry_cursor;
        handle_mouse(
            &mut app,
            event::MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: row.x + 1,
                row: row.y,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.menu_cursor, 1);
        assert_eq!(app.entry_cursor, cursor, "the wheel scrolled the pane behind the menu");
    }

    fn right_click(app: &mut App, column: u16, row: u16) {
        handle_mouse(
            app,
            event::MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Right),
                column,
                row,
                modifiers: KeyModifiers::NONE,
            },
        );
    }

    #[test]
    fn right_clicking_a_row_selects_it_and_opens_its_menu_there() {
        use crate::app::{MenuId, Pane};
        let mut vault = crate::vault::Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "checking", "u", "p", "", "").unwrap();
        vault.create_entry(&banks, "savings", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 18)).unwrap();
        app.step_pane(true); // onto Banks
        t.draw(|f| ui::draw(f, &mut app)).unwrap();

        let groups = app.group_area;
        right_click(&mut app, groups.x + 2, groups.y + 1); // Banks
        assert_eq!((app.menu, app.active_pane), (Some(MenuId::Group), Pane::Groups));
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert_eq!((app.menu_area.x, app.menu_area.y), (groups.x + 2, groups.y + 2), "not at the pointer");
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);

        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let entries = app.entry_area;
        let first = app.entry_cursor;
        right_click(&mut app, entries.x + 2, entries.y + 1);
        assert_eq!((app.menu, app.active_pane), (Some(MenuId::Entry), Pane::Entries));
        assert_ne!(app.entry_cursor, first, "the right-click did not select its row");
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert_eq!(app.menu_area.x, entries.x + 2);
        assert!(app.menu_area.bottom() <= 18, "the menu ran off the screen");
        assert_eq!(app.menu_shown, app.menu_items().len(), "lifting it still cut items off");
    }

    #[test]
    fn a_right_click_never_copies() {
        let mut vault = crate::vault::Vault::new();
        let root = vault.root_id();
        for name in ["a", "b", "c", "d", "e", "f"] {
            vault.create_entry(&root, name, "octo", "vault-password", "", "").unwrap();
        }
        let mut app = App::new();
        app.open_vault(vault);
        app.switch_pane();
        app.step_pane(true);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 18)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let entries = app.entry_area;
        // A row holding both an entry and a copy target, which is what `click` would copy from.
        let row = app.copy_rows[0].0;
        assert!(entries.y <= row && row < entries.y + 6, "no entry row beside a copy row");
        right_click(&mut app, entries.x + 1, row);
        assert_eq!(app.copied, None, "the right-click copied a field");
        assert_eq!(app.menu, Some(crate::app::MenuId::Entry));

        // Labels hidden by a long flash do not close a menu opened at the pointer.
        app.error("save failed  ·  the disk is full and nothing was written at all, again");
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(app.menu_bar.is_empty());
        assert_eq!(app.menu, Some(crate::app::MenuId::Entry));
    }

    #[test]
    fn right_clicks_do_nothing_under_a_popup() {
        let opens: [fn(&mut App); 3] = [App::open_mint, |app| app.detail = true, App::open_search];
        for open in opens {
            let (mut app, mut t) = menu_screen();
            open(&mut app);
            t.draw(|f| ui::draw(f, &mut app)).unwrap();
            let entries = app.entry_area;
            right_click(&mut app, entries.x + 1, entries.y);
            assert_eq!(app.menu, None);
        }
    }

    #[test]
    fn a_right_click_on_empty_space_opens_nothing() {
        let (mut app, mut t) = menu_screen();
        let entries = app.entry_area;
        let selected = app.entry_cursor;
        right_click(&mut app, entries.x + 1, entries.bottom() - 1);
        assert_eq!(app.menu, None, "a menu opened over the row selected before");
        assert_eq!(app.entry_cursor, selected);
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
    }

    #[test]
    fn a_right_click_menu_hands_over_cleanly() {
        let mut vault = crate::vault::Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "checking", "u", "p", "", "").unwrap();
        vault.create_entry(&root, "savings", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let entries = app.entry_area;

        right_click(&mut app, entries.x + 1, entries.y);
        let first = app.entry_cursor;
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        // Left of the box, which opens at the first pointer's column.
        right_click(&mut app, entries.x, entries.y + 1);
        assert_eq!(app.menu_at, Some((entries.x, entries.y + 1)), "the second right-click was dropped");
        assert_ne!(app.entry_cursor, first);

        handle_key(&mut app, KeyCode::Right, KeyModifiers::NONE);
        assert_eq!(app.menu, Some(crate::app::MenuId::Group));
        assert_eq!(app.menu_at, None, "the next menu stayed at the pointer");

        right_click(&mut app, entries.x + 1, entries.y);
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!((app.menu, app.menu_at), (None, None));
    }

    #[test]
    fn arrows_keep_a_right_click_menu_open_when_the_labels_are_hidden() {
        let (mut app, mut t) = menu_screen();
        app.error("save failed  ·  the disk is full and nothing was written at all, again and again");
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(app.menu_bar.is_empty(), "the flash left room for the labels");
        let entries = app.entry_area;
        right_click(&mut app, entries.x + 1, entries.y);
        handle_key(&mut app, KeyCode::Right, KeyModifiers::NONE);
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert_eq!(app.menu, Some(crate::app::MenuId::Group), "the arrow closed the menu");
    }

    #[test]
    fn a_right_click_on_an_open_menu_selects_nothing_behind_it() {
        let mut vault = crate::vault::Vault::new();
        let root = vault.root_id();
        for name in ["a", "b", "c", "d"] {
            vault.create_entry(&root, name, "u", "p", "", "").unwrap();
        }
        let mut app = App::new();
        app.open_vault(vault);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let entries = app.entry_area;
        right_click(&mut app, entries.x + 1, entries.y);
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let selected = app.entry_cursor;
        let row = app.menu_row(1).unwrap();
        assert!(row.y < entries.y + 4, "the menu does not cover an entry row");
        right_click(&mut app, row.x + 1, row.y);
        assert_eq!(app.entry_cursor, selected, "the right-click selected the row behind the menu");
        assert_eq!(app.menu, Some(crate::app::MenuId::Entry));
    }

    #[test]
    fn each_paste_moves_only_its_own_kind() {
        use crate::app::{Cut, MenuId};
        // Two groups, so a paste from the other kind's menu would succeed and empty the shelf.
        let two_groups = || {
            let mut vault = crate::vault::Vault::new();
            let root = vault.root_id();
            let a = vault.create_group(&root, "A").unwrap();
            vault.create_group(&root, "B").unwrap();
            vault.create_entry(&a, "checking", "u", "p", "", "").unwrap();
            let mut app = App::new();
            app.open_vault(vault);
            handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto A
            app
        };

        let mut app = two_groups();
        app.run_menu(&menu_item(MenuId::Group, "Cut"));
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE); // onto B
        app.run_menu(&menu_item(MenuId::Entry, "Paste"));
        assert!(matches!(app.session.cut(), Some(Cut::Group(_))), "Entry › Paste moved the group");
        app.run_menu(&menu_item(MenuId::Group, "Paste"));
        assert_eq!(app.session.cut(), None, "Group › Paste did not move it");

        let mut app = two_groups();
        app.run_menu(&menu_item(MenuId::Entry, "Cut"));
        handle_key(&mut app, KeyCode::Char('j'), KeyModifiers::NONE);
        app.run_menu(&menu_item(MenuId::Group, "Paste"));
        assert!(matches!(app.session.cut(), Some(Cut::Entry(_))), "Group › Paste moved the entry");
        app.run_menu(&menu_item(MenuId::Entry, "Paste"));
        assert_eq!(app.session.cut(), None, "Entry › Paste did not move it");
    }

    #[test]
    fn clicking_the_label_of_a_right_click_menu_moves_it_under_the_label() {
        let (mut app, mut t) = menu_screen();
        let entries = app.entry_area;
        right_click(&mut app, entries.x + 1, entries.y);
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let (label, _) = *app.menu_bar.iter().find(|(_, id)| *id == crate::app::MenuId::Entry).unwrap();
        left_click(&mut app, label.x, label.y);
        assert_eq!(app.menu, Some(crate::app::MenuId::Entry), "the click closed the menu");
        assert_eq!(app.menu_at, None);
    }

    #[test]
    fn enter_runs_nothing_when_no_row_fits() {
        let (mut app, _) = menu_screen();
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 3)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        open_menu(&mut app, &mut t, crate::app::MenuId::Vault);
        assert_eq!(app.menu_shown, 0);
        let before = app.stage.clone();
        handle_key(&mut app, KeyCode::Down, KeyModifiers::NONE);
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.stage, before, "Enter ran Vault › Save or Reload off screen");
        assert_eq!(app.menu, None);
    }

    #[test]
    fn a_lifted_menu_stays_off_the_header() {
        let (mut app, _) = menu_screen();
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 12)).unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let entries = app.entry_area;
        right_click(&mut app, entries.x + 1, entries.y);
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(app.menu_area.y >= 1, "the box covered the header");
        // A click on its border does nothing, whatever lies under it.
        let corner = app.menu_area;
        left_click(&mut app, corner.x, corner.y);
        assert_eq!(app.menu, Some(crate::app::MenuId::Entry));
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            handle_key(app, KeyCode::Char(c), KeyModifiers::NONE);
        }
    }

    #[test]
    fn the_command_palette_finds_and_runs_an_action_by_name() {
        let (mut app, mut t) = menu_screen();
        handle_key(&mut app, KeyCode::Char(':'), KeyModifiers::NONE);
        assert!(app.commands.is_some());
        // Every menu row but the palette's own.
        let all: usize = crate::app::MENUS.iter().map(|(_, _, items)| items.len()).sum();
        assert_eq!(app.command_rows().len(), all - 1, "an empty query hid rows");
        assert!(app.command_rows().iter().all(|(_, item)| item.label != "Commands"));

        type_text(&mut app, "cp pass");
        let (menu, item) = app.command_rows()[0];
        assert_eq!((menu, item.label), ("Entry", "Copy password"), "the docs' example");
        app.command_clear();

        type_text(&mut app, "lock");
        let (menu, item) = app.command_rows()[0];
        assert_eq!((menu, item.label), ("Vault", "Lock"));
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let screen: String = (0..18)
            .map(|y| (0..120).map(|x| t.backend().buffer()[(x, y)].symbol().to_string()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen.contains("Vault › Lock"), "{screen}");

        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.commands.is_none());
        assert_eq!(app.view, crate::app::View::Unlock, "Vault › Lock did not lock");
    }

    #[test]
    fn the_command_palette_owns_the_keys_and_the_mouse() {
        let (mut app, _) = menu_screen();
        handle_key(&mut app, KeyCode::Char(':'), KeyModifiers::NONE);
        type_text(&mut app, "qh");
        assert!(!app.quit && !app.show_help, "q or h acted on the browser");
        assert_eq!(app.commands.as_ref().unwrap().query, "qh");

        let (label, _) = app.menu_bar[0];
        left_click(&mut app, label.x, label.y);
        let entries = app.entry_area;
        right_click(&mut app, entries.x + 1, entries.y);
        assert_eq!(app.menu, None, "a menu opened over the palette");

        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.commands.is_none());
        assert_eq!(app.view, crate::app::View::Browser);
    }

    #[test]
    fn the_command_palette_cursor_wraps_and_a_miss_runs_nothing() {
        let (mut app, _) = menu_screen();
        app.open_commands();
        handle_key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        let last = app.command_rows().len() - 1;
        assert_eq!(app.commands.as_ref().unwrap().cursor, last);

        type_text(&mut app, "zzzz");
        assert!(app.command_rows().is_empty());
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.commands.is_some(), "Enter on no match closed the palette");
    }

    #[test]
    fn a_paste_lands_in_the_palette_query() {
        let (mut app, _) = menu_screen();
        app.open_commands();
        handle_paste(&mut app, "lock\n".to_string());
        assert_eq!(app.commands.as_ref().unwrap().query, "lock");
        assert_eq!(app.view, crate::app::View::Browser, "the pasted newline ran the row");
    }

    #[test]
    fn ctrl_c_in_the_palette_closes_it_and_quits_as_the_browser_does() {
        let (mut app, _) = menu_screen();
        app.open_commands();
        handle_key(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.commands.is_none());
        assert!(app.quit);
    }

    #[test]
    fn a_short_screen_keeps_the_palette_cursor_in_view() {
        let (mut app, _) = menu_screen();
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 12)).unwrap();
        app.open_commands();
        handle_key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        let (menu, item) = *app.command_rows().last().unwrap();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let screen: String = (0..12)
            .map(|y| (0..80).map(|x| t.backend().buffer()[(x, y)].symbol().to_string()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen.contains(&format!("▌ {menu} › {}", item.label)), "{screen}");
    }

    #[test]
    fn a_long_palette_query_shows_its_end() {
        let (mut app, mut t) = menu_screen();
        app.open_commands();
        type_text(&mut app, &format!("{}tail", "x".repeat(80)));
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let screen: String = (0..18)
            .map(|y| (0..120).map(|x| t.backend().buffer()[(x, y)].symbol().to_string()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen.contains("tail█"), "{screen}");
    }
}
