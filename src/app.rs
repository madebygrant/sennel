use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use keepass_rs::{Entry, Group, NodeId};
use zeroize::Zeroize;

use crate::vault::{Vault, VaultError};

/* Which screen owns the keys. Unlock gates everything: with no open vault
   the browser has nothing to act on, so it is a screen and not a prompt. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Unlock,
    /* Constructed from Wave 1 on, once a vault is open. Kept here so the
       key-dispatch shape in main.rs is final from the start. */
    Browser,
}

/* Which pane has the keys. The panes move different cursors over different
   lists, so a key live on the wrong one acts on a row that is not there. */
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Pane {
    #[default]
    Groups,
    Entries,
}

/* Which box on the unlock screen has the keys. Password first because it is
   the one every unlock needs; the confirm only exists in create mode. */
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum UnlockField {
    #[default]
    Password,
    KeyFile,
    Confirm,
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
    /* Selection state. Cursors hold NodeIds, never row positions: rows shift
       under every mutation and under the Wave 5/6 sort and filter views, while
       an id still names the same group or entry. */
    /// The open vault. None while locked; `try_unlock` opens real KDBX here.
    pub vault: Option<Vault>,
    /// Selected group. Always valid once a vault is open (`snap` keeps it so).
    pub group_cursor: Option<NodeId>,
    /// Selected entry within the cursor group. None when the group is empty.
    pub entry_cursor: Option<NodeId>,
    pub active_pane: Pane,
    /// Per-pane list offsets, carried across frames (see `scroll_to`).
    pub group_scroll: usize,
    pub entry_scroll: usize,
    /* Rows the live pane last drew with, set by the draw that knows. A page
       key has to move by what is on screen, and only the layout knows that. */
    pub viewport: usize,
    /* Unlock state. The path comes from the config once at startup;
       `unlock_new` caches whether it names a missing file so the draw loop
       never stats. */
    pub db_path: Option<PathBuf>,
    /// True when the configured file is missing: Enter creates, with a confirm.
    pub unlock_new: bool,
    pub unlock_field: UnlockField,
    pub unlock_password: String,
    pub unlock_keyfile: String,
    pub unlock_confirm: String,
    /// Where typing lands, as a char index into the focused box (see below).
    pub caret: usize,
    /// Unsaved changes. Set by every vault mutation; quitting while set asks.
    dirty: bool,
    /* Idle auto-lock. `None` is off. The deadline is checked once per frame
       in `run`, never in the draw, which must not mutate. */
    pub lock_after: Option<Duration>,
    pub last_activity: Instant,
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
            vault: None,
            group_cursor: None,
            entry_cursor: None,
            active_pane: Pane::Groups,
            group_scroll: 0,
            entry_scroll: 0,
            viewport: 1,
            db_path: None,
            unlock_new: false,
            unlock_field: UnlockField::Password,
            unlock_password: String::new(),
            unlock_keyfile: String::new(),
            unlock_confirm: String::new(),
            caret: 0,
            dirty: false,
            lock_after: None,
            last_activity: Instant::now(),
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

    /* `q` is the deliberate way out and stays one key everywhere nothing
       would be lost. With unsaved changes it asks first; a second `q`
       answers, so `qq` never reads the box. */
    pub fn ask_quit(&mut self) {
        if self.working() {
            self.confirm = Some(Confirm::Quit);
        } else {
            self.quit = true;
        }
    }

    /// Whether quitting would lose anything. One predicate behind both Esc
    /// reporting and `q` asking, so the safe key is safe on the same set of
    /// screens that ask about it.
    pub fn working(&self) -> bool {
        self.dirty
    }

    /// Mark the vault as holding unsaved changes. Called by every mutation
    /// path; the unlock path leaves it clear, so a fresh open quits straight
    /// out without interrogation.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /* Seconds of idleness before the vault locks itself. Zero means off:
       a `Duration::ZERO` deadline would lock on the next frame, which reads
       as the unlock failing. `None` is the absence of a deadline. */
    pub fn set_lock_timeout(&mut self, secs: u64) {
        self.lock_after = (secs > 0).then(|| Duration::from_secs(secs));
    }

    /// A keypress happened, so the idle clock restarts. Called at the top of
    /// key handling rather than per frame, or every redraw would defer the
    /// lock and an idle vault would never close.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /* Whether the vault has sat untouched past the deadline. Takes the clock
       so tests drive it without sleeping: the lock path is about elapsed
       time, not about whatever the frame loop happened to do. */
    pub fn idle_expired(&self, now: Instant) -> bool {
        let Some(after) = self.lock_after else {
            return false;
        };
        self.view == View::Browser
            && self.vault.is_some()
            && now.duration_since(self.last_activity) >= after
    }

    /* Drop the vault and go back behind the password prompt. Dropping is the
       wipe: secrets live in `ProtectedString` and the retained key, both of
       which zeroize on drop, so nothing may be copied out first. Called once
       per frame, not per keypress, since idleness is the absence of keys. */
    pub fn check_idle(&mut self) {
        if !self.idle_expired(Instant::now()) {
            return;
        }
        let secs = self.lock_after.map_or(0, |d| d.as_secs());
        self.vault = None;
        self.group_cursor = None;
        self.entry_cursor = None;
        self.unlock_password.clear();
        self.unlock_keyfile.clear();
        self.unlock_confirm.clear();
        self.caret = 0;
        self.dirty = false;
        self.view = View::Unlock;
        self.refresh_db_state();
        self.say(format!("locked after {secs} seconds idle"));
    }

    /// Where the vault file lives. Set once at startup from the config; the
    /// unlock screen reads it, and the refresh follows it.
    pub fn set_db_path(&mut self, path: Option<PathBuf>) {
        self.db_path = path;
        self.refresh_db_state();
    }

    /* Whether Enter will create rather than open. Cached on keypresses, not
       read per frame: the draw loop must not stat, and the answer only
       changes when the file does. */
    pub fn refresh_db_state(&mut self) {
        self.unlock_new = self.db_path.as_ref().is_some_and(|p| !p.is_file());
    }

    /* Unlock with the typed password (and optional key file), or create the
       database when the file is missing and the confirm matches. The password
       buffer is zeroized on every path out; the retained CompositeKey inside
       the vault is the only copy that survives, and it zeroizes on drop. */
    pub fn try_unlock(&mut self, password: &mut Vec<u8>, key_file: Option<&[u8]>) {
        let Some(path) = self.db_path.clone() else {
            self.say("no database configured  ·  sennel --help names --db");
            password.zeroize();
            return;
        };
        if password.is_empty() {
            self.say("empty password  ·  type one or ^c quits");
            password.zeroize();
            return;
        }
        let result = if self.unlock_new {
            if self.unlock_confirm.as_bytes() != password.as_slice() {
                self.say("passwords differ  ·  retype both fields");
                self.unlock_confirm.clear();
                self.caret = 0;
                password.zeroize();
                return;
            }
            let mut vault = Vault::new();
            vault.save_as(&path, password, key_file).map(|()| vault)
        } else {
            Vault::open(&path, password, key_file)
        };
        // The typed bytes have served: the key inside the vault is a copy.
        password.zeroize();
        match result {
            Ok(vault) => {
                let n = vault.entry_count();
                /* Typed secrets do not linger behind the browser. The key-file
                   path stays: it names a file, not a secret, and prefills the
                   next unlock after an auto-lock. */
                self.unlock_password.zeroize();
                self.unlock_password.clear();
                self.unlock_confirm.clear();
                self.unlock_field = UnlockField::Password;
                self.caret = 0;
                self.unlock_new = false;
                self.open_vault(vault);
                self.resting = "ready".into();
                let plural = if n == 1 { "entry" } else { "entries" };
                self.say(format!("unlocked {n} {plural}"));
            }
            Err(VaultError::WrongPassword) => {
                self.say("wrong password or key file  ·  try again");
            }
            Err(e) => self.say(format!("cannot open {}  ·  {e}", path.display())),
        }
    }

    /// Tab and shift-Tab through the unlock boxes, wrapping. Two boxes except
    /// in create mode, where the confirm joins them.
    pub fn next_unlock_field(&mut self, forward: bool) {
        let n = if self.unlock_new { 3 } else { 2 };
        let at = match self.unlock_field {
            UnlockField::Password => 0,
            UnlockField::KeyFile => 1,
            UnlockField::Confirm => 2,
        };
        self.unlock_field = match (at + if forward { 1 } else { n - 1 }) % n {
            0 => UnlockField::Password,
            1 => UnlockField::KeyFile,
            _ => UnlockField::Confirm,
        };
        // Behind the text, which is where an edit to a prefilled value starts.
        self.caret = self.active_unlock_value().chars().count();
    }

    /// The box the unlock keys are typing into.
    pub fn active_unlock_value(&mut self) -> &mut String {
        match self.unlock_field {
            UnlockField::Password => &mut self.unlock_password,
            UnlockField::KeyFile => &mut self.unlock_keyfile,
            UnlockField::Confirm => &mut self.unlock_confirm,
        }
    }

    /// Byte offset of the caret, for slicing. The caret is a char index: a
    /// byte one lands inside a multi-byte character the moment a password
    /// carries an accent, and `String::insert` panics on it.
    fn caret_byte(&self) -> usize {
        let value = match self.unlock_field {
            UnlockField::Password => &self.unlock_password,
            UnlockField::KeyFile => &self.unlock_keyfile,
            UnlockField::Confirm => &self.unlock_confirm,
        };
        value
            .char_indices()
            .nth(self.caret)
            .map_or(value.len(), |(at, _)| at)
    }

    pub fn unlock_insert(&mut self, c: char) {
        let at = self.caret_byte();
        self.active_unlock_value().insert(at, c);
        self.caret += 1;
    }

    pub fn unlock_backspace(&mut self) {
        if self.caret == 0 {
            return;
        }
        let at = self.caret_byte();
        let prev = self.active_unlock_value()[..at]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i);
        self.active_unlock_value().remove(prev);
        self.caret -= 1;
    }

    pub fn unlock_delete(&mut self) {
        let at = self.caret_byte();
        let has_tail = self
            .active_unlock_value()
            .get(at..)
            .is_some_and(|rest| !rest.is_empty());
        if has_tail {
            self.active_unlock_value().remove(at);
        }
    }

    pub fn unlock_move(&mut self, right: bool) {
        let len = self.active_unlock_value().chars().count();
        self.caret = if right {
            (self.caret + 1).min(len)
        } else {
            self.caret.saturating_sub(1)
        };
    }

    pub fn unlock_end(&mut self, end: bool) {
        self.caret = if end {
            self.active_unlock_value().chars().count()
        } else {
            0
        };
    }

    /// Clear the focused box. The other boxes hold answers being kept.
    pub fn unlock_clear(&mut self) {
        self.active_unlock_value().clear();
        self.caret = 0;
    }

    /* The same word delete the search box will take in Wave 6: muscle memory
       should not depend on which box has the keys. Deletes back to the word
       start, keeping whatever follows the caret. */
    pub fn unlock_kill_word(&mut self) {
        let at = self.caret_byte();
        let start = {
            let value = self.active_unlock_value();
            let before = value[..at].trim_end();
            before.rfind(' ').map_or(0, |i| i + 1)
        };
        /* Both bounds sit on ASCII (` `, or 0) or on the caret's own char
           boundary, so the drain cannot split a character. */
        self.active_unlock_value().drain(start..at);
        self.caret = self.active_unlock_value()[..start].chars().count();
    }

    /// Opens a vault into the browser: cursor on the root, first entry (if
    /// any) selected, groups pane active. The single entry point so Wave 2's
    /// unlock path cannot leave half-initialised selection behind.
    pub fn open_vault(&mut self, vault: Vault) {
        let root = vault.root_id();
        self.group_cursor = Some(root);
        self.entry_cursor = vault.entries_in(&root).first().map(|e| e.id);
        self.active_pane = Pane::Groups;
        self.group_scroll = 0;
        self.entry_scroll = 0;
        self.vault = Some(vault);
        self.view = View::Browser;
    }

    /* Pre-order walk of the whole tree as (id, depth) pairs. The groups pane
       reads this, not the raw child lists: one flat list means one cursor and
       one scroll, and collapse (Wave 5) prunes it without touching the vault.
       Root is always first, so an empty tree still shows one row. */
    pub fn group_tree(&self) -> Vec<(NodeId, usize)> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut stack = vec![(vault.root_id(), 0)];
        while let Some((id, depth)) = stack.pop() {
            out.push((id, depth));
            /* Reversed so the first child pops first and order matches the
               stored child list. */
            for child in vault.groups_in(&id).iter().rev() {
                stack.push((child.id, depth + 1));
            }
        }
        out
    }

    /// Entry ids of the cursor group in stored order. Positions, like the
    /// group tree above: the cursor holds the id, the list is rebuilt per
    /// frame, and the two meet in `snap`.
    pub fn entry_rows(&self) -> Vec<NodeId> {
        match (&self.vault, self.group_cursor) {
            (Some(vault), Some(group)) => {
                vault.entries_in(&group).iter().map(|e| e.id).collect()
            }
            _ => Vec::new(),
        }
    }

    pub fn selected_group(&self) -> Option<&Group> {
        let (vault, id) = (self.vault.as_ref()?, self.group_cursor?);
        vault.get_group(&id)
    }

    /* Filtered out means not selected: the entry cursor may name an entry of
       another group after the group cursor moved, and acting on it would edit
       a row that is not on screen. */
    pub fn selected_entry(&self) -> Option<&Entry> {
        let (vault, group, id) = (self.vault.as_ref()?, self.group_cursor?, self.entry_cursor?);
        vault
            .get_entry(&id)
            .filter(|_| vault.parent_group_of_entry(&id) == Some(group))
    }

    /* Puts both cursors back on rows that exist. Called after every mutation
       and every cursor move across groups: a cursor on a deleted group or an
       entry of another group is a selection nobody can see, and every command
       reads as dead until the next keypress moves it. */
    pub fn snap(&mut self) {
        let Some(vault) = &self.vault else {
            self.group_cursor = None;
            self.entry_cursor = None;
            return;
        };
        let tree = self.group_tree();
        if self.group_cursor.is_none_or(|id| vault.get_group(&id).is_none()) {
            self.group_cursor = tree.first().map(|(id, _)| *id);
        }
        let rows = self.entry_rows();
        if self.entry_cursor.is_none_or(|id| !rows.contains(&id)) {
            self.entry_cursor = rows.first().copied();
        }
    }

    /// Step the group cursor down (`true`) or up over the visible tree.
    pub fn step_group(&mut self, down: bool) {
        let tree = self.group_tree();
        let Some(at) = self.group_cursor.and_then(|id| tree.iter().position(|(g, _)| *g == id))
        else {
            self.snap();
            return;
        };
        let next = if down {
            (at + 1).min(tree.len().saturating_sub(1))
        } else {
            at.saturating_sub(1)
        };
        self.group_cursor = Some(tree[next].0);
        /* A new group brings its own entries: keeping the old entry cursor
           would point at another group's row, which `selected_entry` hides
           but which still reads as a stuck highlight. */
        self.entry_cursor = None;
        self.entry_scroll = 0;
        self.snap();
    }

    /// Step the entry cursor within the cursor group. Clamps at the ends:
    /// a jump that quietly wraps reads as a key that did nothing.
    pub fn step_entry(&mut self, down: bool) {
        let rows = self.entry_rows();
        if rows.is_empty() {
            self.entry_cursor = None;
            return;
        }
        let at = self
            .entry_cursor
            .and_then(|id| rows.iter().position(|e| *e == id))
            .unwrap_or(0);
        let next = if down {
            (at + 1).min(rows.len() - 1)
        } else {
            at.saturating_sub(1)
        };
        self.entry_cursor = Some(rows[next]);
    }

    /// First (`false`) or last group. Never wraps: reaching an end says so
    /// by staying put, and the move itself is the feedback.
    pub fn jump_group(&mut self, last: bool) {
        let tree = self.group_tree();
        if tree.is_empty() {
            return;
        }
        self.group_cursor = Some(if last {
            tree[tree.len() - 1].0
        } else {
            tree[0].0
        });
        self.entry_cursor = None;
        self.entry_scroll = 0;
        self.snap();
    }

    /// First or last entry of the cursor group. Clamps like `step_entry`:
    /// no wrap, the list ends where it ends.
    pub fn jump_entry(&mut self, last: bool) {
        let rows = self.entry_rows();
        if rows.is_empty() {
            self.entry_cursor = None;
            return;
        }
        self.entry_cursor = Some(if last {
            rows[rows.len() - 1]
        } else {
            rows[0]
        });
    }

    /// One step in whichever pane has the keys. Tab moves the keys, never
    /// the cursors, so this is the only mover that reads `active_pane`.
    pub fn step_pane(&mut self, down: bool) {
        match self.active_pane {
            Pane::Groups => self.step_group(down),
            Pane::Entries => self.step_entry(down),
        }
    }

    /// First (`false`) or last (`true`) row of the live pane.
    pub fn jump_pane(&mut self, last: bool) {
        match self.active_pane {
            Pane::Groups => self.jump_group(last),
            Pane::Entries => self.jump_entry(last),
        }
    }

    /// A screenful in the live pane. Loops the single-step movers rather
    /// than computing positions: they already clamp, and only the draw
    /// knows the true row count, which is what `viewport` carries.
    pub fn page_pane(&mut self, down: bool) {
        for _ in 0..self.viewport.max(1) {
            self.step_pane(down);
        }
    }

    /// Tab between the panes. The cursors stay where they were: leaving a
    /// pane must not lose the row you were reading.
    pub fn switch_pane(&mut self) {
        self.active_pane = match self.active_pane {
            Pane::Groups => Pane::Entries,
            Pane::Entries => Pane::Groups,
        };
        self.snap();
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

    fn open_app() -> App {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "checking", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app
    }

    /* Tab moves the keys, never the cursors: leaving a pane must not lose
       the row you were reading. */
    #[test]
    fn tab_switches_panes_and_keeps_both_cursors() {
        let mut app = open_app();
        assert_eq!(app.active_pane, Pane::Groups);
        let (group, entry) = (app.group_cursor, app.entry_cursor);
        app.switch_pane();
        assert_eq!(app.active_pane, Pane::Entries);
        assert_eq!((app.group_cursor, app.entry_cursor), (group, entry));
        app.switch_pane();
        assert_eq!(app.active_pane, Pane::Groups);
    }

    /* g/G land on the ends of the live pane: the group tree for Groups,
       the cursor group's entries for Entries. */
    #[test]
    fn jumps_land_on_the_live_panes_ends() {
        let mut app = open_app();
        app.jump_pane(true);
        let tree = app.group_tree();
        assert_eq!(app.group_cursor, Some(tree[tree.len() - 1].0));
        app.active_pane = Pane::Entries;
        // One entry: first and last are the same row.
        let rows = app.entry_rows();
        app.jump_pane(true);
        assert_eq!(app.entry_cursor, rows.last().copied());
        app.jump_pane(false);
        assert_eq!(app.entry_cursor, rows.first().copied());
    }

    /* A page moves by what the draw saw, which is what `viewport` carries:
       stepping one row would make PgDn a slow `j`. */
    #[test]
    fn a_page_moves_by_the_drawn_rows() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        for n in 0..10 {
            vault
                .create_entry(&banks, &format!("e{n}"), "u", "p", "", "")
                .unwrap();
        }
        let mut app = App::new();
        app.open_vault(vault);
        app.step_group(true);
        app.active_pane = Pane::Entries;
        app.viewport = 4;
        app.page_pane(true);
        let rows = app.entry_rows();
        assert_eq!(app.entry_cursor, Some(rows[4]));
    }

    /* No timeout configured means no deadline at all: a fresh open must never
       find itself locked on the next frame. */
    #[test]
    fn without_a_timeout_the_vault_never_locks() {
        let mut app = open_app();
        app.last_activity = Instant::now() - Duration::from_secs(3600);
        app.check_idle();
        assert_eq!(app.view, View::Browser);
        assert!(app.vault.is_some(), "an untimed vault was dropped");
    }

    /* Idleness past the deadline drops the vault and returns behind the
       password prompt. Dropping is the wipe; the assertion is that nothing
       selectable survives. */
    #[test]
    fn idleness_past_the_deadline_locks_and_wipes() {
        let mut app = open_app();
        app.set_lock_timeout(60);
        app.last_activity = Instant::now() - Duration::from_secs(61);
        app.check_idle();
        assert_eq!(app.view, View::Unlock);
        assert!(app.vault.is_none(), "the secrets survived the lock");
        assert!(app.group_cursor.is_none());
        assert!(app.entry_cursor.is_none());
        assert!(!app.dirty, "a lock invented unsaved changes");
        assert!(app.stage.contains("locked after 60 seconds idle"), "{}", app.stage);
    }

    /* Any keypress restarts the clock: activity just before the deadline is
       what keeps a working session open. */
    #[test]
    fn a_keypress_defers_the_lock() {
        let mut app = open_app();
        app.set_lock_timeout(60);
        app.last_activity = Instant::now() - Duration::from_secs(61);
        app.touch();
        app.check_idle();
        assert_eq!(app.view, View::Browser);
        assert!(app.vault.is_some());
    }

    /* Zero disables rather than arming a zero-second deadline, which would
       lock on the very next frame and read as the unlock failing. */
    #[test]
    fn zero_timeout_is_off_not_instant() {
        let mut app = open_app();
        app.set_lock_timeout(60);
        app.set_lock_timeout(0);
        app.last_activity = Instant::now() - Duration::from_secs(3600);
        app.check_idle();
        assert_eq!(app.view, View::Browser);
        assert!(app.vault.is_some());
    }

    /* Opening lands on the root with a valid selection, or the first keypress
       acts on nothing and reads as broken. */
    #[test]
    fn opening_a_vault_selects_root_and_snaps() {
        let app = open_app();
        let vault = app.vault.as_ref().unwrap();
        assert_eq!(app.group_cursor, Some(vault.root_id()));
        assert_eq!(app.view, View::Browser);
        assert!(app.selected_group().is_some());
    }

    /* The tree is pre-order with depths: the groups pane draws straight from
       this, indent included. */
    #[test]
    fn the_group_tree_walks_pre_order_with_depths() {
        let app = open_app();
        let vault = app.vault.as_ref().unwrap();
        let root = vault.root_id();
        let names: Vec<(String, usize)> = app
            .group_tree()
            .iter()
            .map(|(id, d)| (vault.get_group(id).unwrap().title.clone(), *d))
            .collect();
        assert_eq!(names, vec![
            ("Root".to_string(), 0),
            ("Banks".to_string(), 1)
        ]);
        assert_eq!(app.group_cursor, Some(root));
    }

    /* Deleting the selected group must not strand the cursor: snap falls back
       to the root, which always exists. */
    #[test]
    fn snap_recovers_the_group_cursor_after_a_delete() {
        let mut app = open_app();
        let banks = app.group_tree()[1].0;
        app.group_cursor = Some(banks);
        app.vault.as_mut().unwrap().delete_group(&banks).unwrap_err();
        // Non-empty: refused. Empty it, then delete for real.
        let e = app.entry_rows();
        assert!(!e.is_empty());
        app.vault.as_mut().unwrap().delete_entry(&e[0]).unwrap();
        app.vault.as_mut().unwrap().delete_group(&banks).unwrap();
        app.snap();
        let root = app.vault.as_ref().unwrap().root_id();
        assert_eq!(app.group_cursor, Some(root));
        assert!(app.selected_group().is_some());
    }

    /* Moving across groups drops the entry cursor onto the new group's first
       entry: the old id names another group's row. */
    #[test]
    fn stepping_groups_reselects_entries_in_the_new_group() {
        let mut app = open_app();
        assert_eq!(app.entry_rows().len(), 0, "root holds no entries");
        assert_eq!(app.entry_cursor, None);
        app.step_group(true);
        let banks = app.group_cursor.unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().get_group(&banks).unwrap().title,
            "Banks"
        );
        assert!(app.selected_entry().is_some());
        // Stepping past the last row clamps instead of wrapping.
        app.step_entry(true);
        let first = app.entry_cursor;
        app.step_entry(true);
        assert_eq!(app.entry_cursor, first);
    }

    /* An entry cursor from another group selects nothing: otherwise `e` would
       edit a row that is not on screen. */
    #[test]
    fn an_entry_of_another_group_is_not_selected() {
        let mut app = open_app();
        let banks = app.group_tree()[1].0;
        let eid = app.vault.as_ref().unwrap().entries_in(&banks)[0].id;
        // Still on root: the Banks entry must not resolve.
        app.entry_cursor = Some(eid);
        assert!(app.selected_entry().is_none());
        app.snap();
        assert_eq!(app.entry_cursor, None, "root is empty");
    }

    /* Unique per call, not just per process: the harness runs tests in
       parallel, and two sharing a path would delete each other's file. */
    fn temp_path(tag: &str) -> TempPath {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        TempPath(std::env::temp_dir().join(format!(
            "sennel-test-{tag}-{}-{n}.kdbx",
            std::process::id()
        )))
    }

    struct TempPath(std::path::PathBuf);

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A real KDBX file on disk behind a locked app, as main.rs builds it.
    fn locked_app_with_db(password: &[u8]) -> (App, TempPath) {
        let tmp = temp_path("unlock");
        let mut seed = Vault::new();
        seed.save_as(&tmp.0, password, None).unwrap();
        let mut app = App::new();
        app.set_db_path(Some(tmp.0.clone()));
        (app, tmp)
    }

    /* The happy path: the browser opens, and the typed bytes are gone from
       every buffer the UI held. The retained key inside the vault is the only
       copy, and it zeroizes on drop. */
    #[test]
    fn right_password_unlocks_and_wipes_the_buffers() {
        let (mut app, _tmp) = locked_app_with_db(b"correct horse");
        assert!(!app.unlock_new, "an existing file reads as create");
        let mut pw = b"correct horse".to_vec();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Browser);
        assert!(app.vault.is_some());
        assert!(pw.iter().all(|b| *b == 0), "password buffer survived unlock");
        assert!(app.unlock_password.is_empty());
        assert!(app.unlock_confirm.is_empty());
        assert_eq!(app.stage, "unlocked 0 entries");
    }

    /* A wrong password keeps the lock and says the next step, and still wipes
       the typed bytes: a failed guess is exactly what must not linger. */
    #[test]
    fn wrong_password_stays_locked_and_says_so() {
        let (mut app, _tmp) = locked_app_with_db(b"correct horse");
        let mut pw = b"wrong guess".to_vec();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Unlock);
        assert!(app.vault.is_none());
        assert!(app.stage.contains("try again"), "{}", app.stage);
        assert!(pw.iter().all(|b| *b == 0), "failed guess lingered");
    }

    /* A missing file is a create, not an error: a matching confirm writes the
       database and opens it. */
    #[test]
    fn missing_file_creates_when_the_confirm_matches() {
        let tmp = temp_path("create");
        let mut app = App::new();
        app.set_db_path(Some(tmp.0.clone()));
        assert!(app.unlock_new, "a missing file must read as create");
        app.unlock_confirm = "new secret".into();
        let mut pw = b"new secret".to_vec();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Browser);
        assert!(tmp.0.is_file(), "create wrote no file");
        // And the created file opens with the same password.
        assert!(Vault::open(&tmp.0, b"new secret", None).is_ok());
    }

    /* A mismatched confirm writes nothing: one stray keystroke must not mint
       a database the user can never open again. */
    #[test]
    fn missing_file_refuses_a_mismatched_confirm() {
        let tmp = temp_path("mismatch");
        let mut app = App::new();
        app.set_db_path(Some(tmp.0.clone()));
        app.unlock_confirm = "something else".into();
        let mut pw = b"new secret".to_vec();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Unlock);
        assert!(!tmp.0.exists(), "a mismatch still wrote a file");
        assert!(app.stage.contains("differ"), "{}", app.stage);
    }

    /* No --db and no config: the screen says where the answer lives instead
       of failing on an empty path. */
    #[test]
    fn no_database_configured_says_what_to_do() {
        let mut app = App::new();
        let mut pw = b"whatever".to_vec();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Unlock);
        assert!(app.stage.contains("--db"), "{}", app.stage);
    }

    /* Typing lands behind a char-indexed caret: a byte index splits an
       accented password and `String::insert` panics on it. */
    #[test]
    fn unlock_typing_moves_a_char_caret() {
        let mut app = App::new();
        app.unlock_insert('é');
        app.unlock_insert('x');
        assert_eq!(app.unlock_password, "éx");
        app.unlock_move(false);
        app.unlock_insert('a');
        assert_eq!(app.unlock_password, "éax");
        app.unlock_backspace();
        assert_eq!(app.unlock_password, "éx");
        app.unlock_end(false);
        app.unlock_delete();
        assert_eq!(app.unlock_password, "x");
        // Word kill takes the word back, keeping what follows the caret.
        app.unlock_clear();
        for c in "foo bar".chars() {
            app.unlock_insert(c);
        }
        app.unlock_end(false);
        for _ in 0..3 {
            app.unlock_move(true);
        }
        app.unlock_kill_word();
        assert_eq!(app.unlock_password, " bar");
    }

    /* Tab walks two boxes, three in create mode, and lands behind the text:
       an edit to a prefilled key-file path starts at its end. */
    #[test]
    fn tab_walks_two_boxes_three_when_creating() {
        let mut app = App::new();
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::KeyFile);
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::Password, "wrapped");
        app.unlock_new = true;
        app.next_unlock_field(false);
        assert_eq!(app.unlock_field, UnlockField::Confirm);
        app.unlock_keyfile = "/keys/k".into();
        app.unlock_field = UnlockField::Password;
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::KeyFile);
        assert_eq!(app.caret, 7, "caret did not land behind the path");
    }

    /* The dirty guard: a fresh unlock quits straight out, a mutation asks. */
    #[test]
    fn the_dirty_guard_asks_only_after_a_mutation() {
        let (mut app, _tmp) = locked_app_with_db(b"pw");
        let mut pw = b"pw".to_vec();
        app.try_unlock(&mut pw, None);
        app.ask_quit();
        assert!(app.quit, "a clean vault interrogated the quit");
        let (mut app, _tmp) = locked_app_with_db(b"pw");
        let mut pw = b"pw".to_vec();
        app.try_unlock(&mut pw, None);
        app.mark_dirty();
        app.ask_quit();
        assert!(!app.quit, "a dirty vault quit without asking");
        assert_eq!(app.confirm, Some(Confirm::Quit));
    }
}
