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
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use zeroize::Zeroize;

use app::{App, Confirm};
use crate::clipboard::Board;
use config::{Cli, Config};
use keepass_rs::NodeId;
use vault::Vault;

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
        anyhow::bail!("sennel needs a terminal · --check works without one");
    }

    let mut terminal = ratatui::init();
    let mut app = App::new();
    /* Which file the lock screen is for, resolved once at startup. The draw
       loop must not stat: `refresh_db_state` runs here and after every save,
       and the cached `unlock_new` is all the draw ever reads. */
    app.set_db_path(cfg.db.clone());
    app.refresh_db_state();
    /* Armed once from config: 0 means the user asked for no lock, and the
       mapping lives in `App` so the frame loop below needs no branch. */
    app.set_lock_timeout(cfg.lock_timeout);
    /* The clipboard with its auto-clear timer, armed once like the lock:
       copies before this point cannot happen, since nothing is unlocked. */
    app.set_board(Board::new(cfg.clipboard_timeout));
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

/* The first thing to run on a new machine and the first thing to ask for in
   a bug report: what sennel read, and whether the clipboard it copies to is
   there. Exits non-zero when copying could never work, so a script can act
   on it. */
fn check(cfg: &Config) -> Result<()> {
    println!("sennel {}", env!("CARGO_PKG_VERSION"));
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
    let password = rpassword::prompt_password("password: ")?;
    let vault = Vault::open(path, password.as_bytes(), None)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} groups · {} entries",
        vault.db().groups.len(),
        vault.db().entries.len()
    );
    /* Walk the whole tree root-down so the output reads like the browser. */
    for (id, depth) in walk_groups(&vault) {
        let indent = "  ".repeat(depth);
        println!("{}[{}]", indent, vault.db().groups[&id].title);
        for eid in &vault.db().groups[&id].child_entry_ids {
            if let Some(e) = vault.db().entries.get(eid) {
                println!("{}  {}", indent, e.title);
            }
        }
    }
    Ok(())
}

fn walk_groups(vault: &Vault) -> Vec<(NodeId, usize)> {
    let mut out = Vec::new();
    let mut stack = vec![(vault.root_id(), 0)];
    while let Some((id, depth)) = stack.pop() {
        out.push((id, depth));
        for child in vault.groups_in(&id).iter().rev() {
            stack.push((child.id, depth + 1));
        }
    }
    out
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.quit {
        app.expire_flash();
        /* Once per frame, not per keypress: idleness is the absence of keys,
           and nothing else on screen moves between messages to re-check it. */
        app.check_idle();
        terminal.draw(|frame| ui::draw(frame, app))?;
        app.tick = app.tick.wrapping_add(1);

        if event::poll(Duration::from_millis(120))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            handle_key(app, key.code, key.modifiers);
        }
    }
    Ok(())
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
    /* The overlay swallows the next key rather than acting on it: anything
       else makes dismissing it a guess about what the key also did. */
    if app.show_help && !matches!(code, KeyCode::Char('q')) {
        app.show_help = false;
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
        KeyCode::Char('g') => app.jump_pane(false),
        KeyCode::Char('G') => app.jump_pane(true),
        KeyCode::Tab => app.switch_pane(),
        KeyCode::Char('*') => app.toggle_password(),
        KeyCode::Char('y') => app.copy_username(),
        KeyCode::Char('p') => app.copy_password(),
        KeyCode::Char('U') => app.copy_url(),
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
        KeyCode::Char('o') => app.cycle_order(),
        /* n/N walk the matches while the band is live, and step entries
           otherwise — the same key, honest in both modes. */
        KeyCode::Char('n') => app.jump_match(true),
        KeyCode::Char('N') => app.jump_match(false),
        /* `u` undoes the last one-slot change; ^u stays page-up. */
        KeyCode::Char('u') => app.undo_last(),
        KeyCode::Char('/') => app.open_search(),
        _ => {}
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
        KeyCode::Char('u') if ctrl => app.search_clear(),
        KeyCode::Char('w') if ctrl => app.search_kill_word(),
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
        KeyCode::Left if !ctrl => app.unlock_move(false),
        KeyCode::Right if !ctrl => app.unlock_move(true),
        KeyCode::Home if !ctrl => app.unlock_end(false),
        KeyCode::End if !ctrl => app.unlock_end(true),
        KeyCode::Char('a') if ctrl => app.unlock_end(false),
        KeyCode::Char('e') if ctrl => app.unlock_end(true),
        KeyCode::Delete if !ctrl => app.unlock_delete(),
        KeyCode::Backspace => app.unlock_backspace(),
        KeyCode::Enter => unlock_now(app),
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
                app.say(format!("cannot read key file {path}"));
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

/* `y`, `q` and Enter all mean yes, so a second `q` answers the question the
   first one raised and nobody who meant it has to read the box. Everything
   else means no: this is the guard on the one key that can still lose work,
   so an unrecognised key must not be an accidental yes. */
fn handle_confirm_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    let yes = matches!(
        code,
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('q') | KeyCode::Enter
    ) || (matches!(code, KeyCode::Char('c')) && mods.contains(KeyModifiers::CONTROL));
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

    /* Enter on the lock with no database configured says what to do rather
       than failing on an empty path. */
    #[test]
    fn enter_without_a_database_names_the_flag() {
        let mut app = App::new();
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.view, crate::app::View::Unlock, "unlocked without a file");
        assert!(app.stage.contains("--db"), "{}", app.stage);
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
            app.vault.as_ref().unwrap().get_entry(&rows[2]).unwrap().title,
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
            app.vault.as_ref().unwrap().get_group(id).unwrap().title == "q"
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
        assert_eq!(entry.notes.as_str(), "", "u did not restore the notes");
    }
}
