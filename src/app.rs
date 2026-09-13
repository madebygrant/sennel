use std::collections::VecDeque;
use std::time::{Duration, Instant};

/* Which screen owns the keys. Unlock gates everything: with no open vault
   the browser has nothing to act on, so it is a screen and not a prompt. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Unlock,
    /* Constructed from Wave 1 on, once a vault is open. Kept here so the
       key-dispatch shape in main.rs is final from the start. */
    Browser,
}

/* A question the UI asks on its own account. Nothing is blocked on the
   answer, so it carries no reply channel: the session carries on behind it. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Confirm {
    Quit,
}

/* A flash is timed by its length: four fixed seconds fits "saved" and not a
   wrapped clipboard error, so the floor plus reading time travels with the
   message instead of one number for all of them. */
const FLASH: Duration = Duration::from_secs(2);
const PER_CHAR: Duration = Duration::from_millis(50);
const FLASH_MAX: Duration = Duration::from_secs(8);
/* Deep enough for two quick copies in a row, shallow enough that a backlog
   nobody is still reading cannot build up behind one flash. */
const QUEUE: usize = 3;

/* Rows of context kept either side of the cursor. `ListState` is built fresh
   every frame, so with no offset of our own ratatui scrolls the least it can
   to make the selection visible: past the first screenful the cursor sits on
   the last row for the rest of the list. */
pub const SCROLLOFF: usize = 2;

/// Where the list starts drawing from, given where it started last frame.
/// Only moves when the cursor comes within `SCROLLOFF` of an edge, so the
/// rows stay put while the cursor crosses the middle of the pane.
pub fn scroll_to(offset: usize, at: usize, len: usize, height: usize) -> usize {
    if height == 0 || len <= height {
        return 0;
    }
    // Halved on a short pane, where the cursor cannot clear both edges.
    let pad = SCROLLOFF.min((height - 1) / 2);
    let last = len - height;
    let highest = at.saturating_sub(pad).min(last);
    let lowest = (at + pad + 1).saturating_sub(height).min(last);
    offset.clamp(lowest, highest)
}

pub struct App {
    pub tick: usize,
    pub view: View,
    pub show_help: bool,
    pub stage: String,
    /// What the header goes back to once a flash expires.
    resting: String,
    flash_until: Option<Instant>,
    /// Messages that arrived while one was still being read.
    waiting: VecDeque<String>,
    /// A question the UI raised itself, waiting on y or n.
    pub confirm: Option<Confirm>,
    pub quit: bool,
}

impl App {
    pub fn new() -> Self {
        App {
            tick: 0,
            view: View::Unlock,
            show_help: false,
            stage: "locked".into(),
            resting: "locked".into(),
            flash_until: None,
            waiting: VecDeque::new(),
            confirm: None,
            quit: false,
        }
    }

    /// Something the UI itself has to say, where no vault or worker is
    /// involved. A key that deliberately does nothing has to report that, or
    /// it reads as a key that is broken.
    pub fn say(&mut self, text: impl Into<String>) {
        let text = text.into();
        /* A second message used to overwrite the first, so two quick copies
           arrived and left inside one blink and only the last was ever
           readable. */
        if self.flash_until.is_some() {
            if self.waiting.len() < QUEUE {
                self.waiting.push_back(text);
            }
            return;
        }
        self.show_flash(text);
    }

    fn show_flash(&mut self, text: String) {
        let reading = PER_CHAR * text.chars().count() as u32;
        self.flash_until = Some(Instant::now() + (FLASH + reading).min(FLASH_MAX));
        self.stage = text;
    }

    /// Called every frame: a flash has to expire on its own, since the thing
    /// that set it has already finished and will not send anything else.
    pub fn expire_flash(&mut self) {
        if !self.flash_until.is_some_and(|at| Instant::now() >= at) {
            return;
        }
        self.flash_until = None;
        match self.waiting.pop_front() {
            Some(next) => self.show_flash(next),
            None => self.stage = self.resting.clone(),
        }
    }

    /* `q` is the deliberate way out and stays one key everywhere nothing is
       running. Wave 2 arms the dirty guard behind `working()`; until then
       quitting costs nothing and asks nothing. */
    pub fn ask_quit(&mut self) {
        if self.working() {
            self.confirm = Some(Confirm::Quit);
        } else {
            self.quit = true;
        }
    }

    /// Whether anything is in flight that quitting would lose. One predicate
    /// for the guard, so the safe key is safe on the same set of screens that
    /// ask about it. False until Wave 2 tracks dirty vault state.
    pub fn working(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* Carried across frames, or ratatui recomputes the least scroll that
       makes the selection visible and pins the cursor to the last row. */
    #[test]
    fn scroll_holds_until_the_cursor_nears_an_edge() {
        // Fits: no scroll whatever the cursor does.
        assert_eq!(scroll_to(0, 9, 10, 10), 0);
        // Mid-list: the offset stays where it was.
        assert_eq!(scroll_to(0, 4, 40, 10), 0);
        // Within SCROLLOFF of the bottom edge: follows.
        assert_eq!(scroll_to(0, 9, 40, 10), 2);
        // Never past the last page.
        assert_eq!(scroll_to(0, 39, 40, 10), 30);
    }
}
