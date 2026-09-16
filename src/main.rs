mod app;
mod clipboard;
mod config;
mod generator;
mod search;
mod theme;
mod ui;
mod vault;

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::SetTitle;
use zeroize::Zeroize;

use app::{App, Confirm};
use crate::clipboard::Board;
use config::{Cli, Config};
use keepass::db::GroupId;
use vault::{EntryExt, Vault, printable};

fn main() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cfg = Config::build(Cli::from_arg_matches(&matches)?)?;
    if cfg.check {
        return check(&cfg);
    }
    if cfg.list {
        return list(&cfg);
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
    harden();
    let mut terminal = ratatui::init();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(std::io::stdout(), DisableMouseCapture, SetTitle(""));
        previous(info);
    }));
    /* Wheel and click, unless the config turned them off: capture takes the
       terminal's own selection with it, which some people would rather keep
       (shift usually still selects). */
    if cfg.mouse {
        let _ = execute!(std::io::stdout(), EnableMouseCapture);
    }
    let mut app = App::new();
    /* Which file the lock screen is for, resolved once at startup. The draw
       loop must not stat: `refresh_db_state` runs here and after every save,
       and the cached `unlock_new` is all the draw ever reads. */
    app.set_db_path(cfg.db.clone());
    /* Where a chosen vault gets remembered, so the next launch opens it. */
    app.config_file = cfg.config_file.clone();
    app.configured_db = cfg.db.clone();
    app.refresh_db_state();
    /* Armed once from config: 0 means the user asked for no lock, and the
       mapping lives in `App` so the frame loop below needs no branch. */
    app.set_lock_timeout(cfg.lock_timeout);
    app.set_order(cfg.sort);
    app.theme = cfg.theme;
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
    if cfg.mouse {
        let _ = execute!(std::io::stdout(), DisableMouseCapture);
    }
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
    println!("Sennel {}", env!("CARGO_PKG_VERSION"));
    println!(
        "config    {}",
        cfg.config_file
            .as_deref()
            .map_or("(none · --no-config)".to_string(), |p| p.display().to_string())
    );
    println!(
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
            println!(
                "vault     found · {size} bytes · {}",
                if writable { "writable" } else { "READ-ONLY" }
            );
        }
        Some(_) => println!("vault     not there yet · unlocking creates it"),
        None => println!("vault     (none)"),
    }
    println!("theme     {}", cfg.theme.name());
    for note in &cfg.theme_warnings {
        println!("          ! {note}");
    }
    println!("sort      {}", cfg.sort.short());
    println!(
        "generate  {} chars · {}",
        cfg.generator.length,
        cfg.generator.describe()
    );
    println!("mouse     {}", if cfg.mouse { "on" } else { "off" });
    println!("clear in  {}s", cfg.clipboard_timeout);
    println!("lock in   {}s (0 = off)", cfg.lock_timeout);
    match arboard::Clipboard::new() {
        Ok(_) => {
            println!("clipboard ok");
            Ok(())
        }
        Err(e) => {
            println!("clipboard unavailable · {e}");
            std::process::exit(1);
        }
    }
}

/* --list: the vault inventory without the secrets. Counts and entry titles
   only — the point is scripting and inventory, not display. */
fn list(cfg: &Config) -> Result<()> {
    let Some(path) = &cfg.db else {
        anyhow::bail!("no database given · pass --db <file>");
    };
    let mut password = rpassword::prompt_password("password: ")?;
    let opened = Vault::open(path, &password, None).map_err(|e| anyhow::anyhow!("{e}"));
    // Used once; the key inside the vault is the only copy that lives on.
    password.zeroize();
    let vault = opened?;
    println!("{} groups · {} entries", vault.num_groups(), vault.entry_count());
    /* Walk the whole tree root-down so the output reads like the browser. */
    for (id, depth) in walk_groups(&vault) {
        let indent = "  ".repeat(depth);
        println!("{}[{}]", indent, printable(&vault.get_group(&id).unwrap().name));
        for entry in vault.entries_in(&id) {
            println!("{}  {}", indent, printable(entry.title()));
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
    if app.view != app::View::Browser
        || app.confirm.is_some()
        || app.form.is_some()
        || app.group_prompt.is_some()
        || app.detail
        || app.show_help
    {
        return;
    }
    app.touch();
    match mouse.kind {
        MouseEventKind::ScrollDown => app.wheel(mouse.column, mouse.row, true),
        MouseEventKind::ScrollUp => app.wheel(mouse.column, mouse.row, false),
        MouseEventKind::Down(MouseButton::Left) => app.click(mouse.column, mouse.row),
        _ => {}
    }
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    /* First, because this is the proof of presence: every key that reaches
       the session restarts the idle clock, including the ones swallowed
       below. The poll timeout is not presence, so `run` never touches it. */
    app.touch();
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
    /* The group prompt is modal on the same terms, one box instead of five. */
    if app.group_prompt.is_some() {
        handle_group_prompt_key(app, code, mods);
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
    /* The lock screen owns every printable key, so the overlay needs one no
       password can contain: `h` there types an h, which left the bar's "h
       keys" promising a key that does not exist on the first screen anybody
       sees. */
    if matches!(code, KeyCode::F(1)) {
        app.show_help = true;
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
        KeyCode::Char('h') | KeyCode::Char('?') => app.show_help = true,
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
        KeyCode::Char('h') | KeyCode::Char('?') => app.show_help = true,
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
        /* `^t` walks the palettes: a theme is picked by looking at it, not by
           reading its name in a config file. */
        KeyCode::Char('t') if ctrl => app.cycle_theme(),
        KeyCode::Char('g') | KeyCode::Home => app.jump_pane(false),
        KeyCode::Char('G') | KeyCode::End => app.jump_pane(true),
        KeyCode::Tab => app.switch_pane(),
        KeyCode::Char('*') => app.toggle_password(),
        KeyCode::Char('y') => app.copy_username(),
        KeyCode::Char('p') => app.copy_password(),
        KeyCode::Char('U') => app.copy_url(),
        KeyCode::Char('t') => app.copy_totp(),
        /* Case carries meaning: `a` adds, `A` names a group (wave 5), so
           the edit keys stay lowercase-shifted apart on purpose. */
        KeyCode::Char('a') => app.open_add_form(),
        KeyCode::Char('e') => app.open_edit_form(),
        /* Group keys. A and E name groups from either pane; D follows the
           pane — the cursor decides what deleting means. */
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

/* Enter on the lock screen. The secret buffers live here, not in `App`: the
   UI holds what it displays, and the secret it passes on is taken, used once,
   and wiped — never stored beside the state it unlocks. */
fn unlock_now(app: &mut App) {
    /* Taken, not borrowed: `try_unlock` consumes and zeroizes on every path,
       and a take leaves `App` holding nothing the moment the key is read. */
    let mut password: Vec<u8> = std::mem::take(&mut app.unlock_password).into_bytes();
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
    app.try_unlock(&mut password, key_bytes.as_deref());
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
       a core dump of this process would hold every secret at once. */
    #[test]
    fn hardening_forbids_core_dumps() {
        harden();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(read, 0, "getrlimit failed");
        assert_eq!(limit.rlim_cur, 0, "core dumps are still allowed");
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
            app.vault.as_ref().unwrap().get_entry(&rows[2]).unwrap().title(),
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
            app.vault.as_ref().unwrap().get_group(id).unwrap().name == "q"
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
        assert!(app.cut.is_some(), "X did not arm the shelf");
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.cut.is_none(), "esc did not drop the cut");
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
        app.vault
            .as_mut()
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
            .vault
            .as_ref()
            .unwrap()
            .get_entry(&app.entry_cursor.unwrap())
            .unwrap();
        assert_eq!(entry.notes(), "", "u did not restore the notes");
    }
}
