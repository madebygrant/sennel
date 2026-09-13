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
        assert!(app.stage.contains("q quits"), "{}", app.stage);
    }
}
