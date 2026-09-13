mod app;
mod config;
mod theme;
mod ui;
mod vault;

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use zeroize::Zeroize;

use app::App;
use config::{Cli, Config};

fn main() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cfg = Config::build(Cli::from_arg_matches(&matches)?)?;
    if cfg.check {
        return check(&cfg);
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

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.quit {
        app.expire_flash();
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
    /* Ahead of every screen's keys: it is the UI's own question and the
       answer must not also reach the list behind it. */
    if app.confirm.is_some() {
        handle_confirm_key(app, code, mods);
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
    app.confirm = None;
    if yes {
        app.quit = true;
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
}
