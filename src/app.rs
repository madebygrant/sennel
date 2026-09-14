use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use keepass_rs::{Entry, Group, NodeId};
use zeroize::Zeroize;

use crate::clipboard::Board;
use crate::generator::Classes;
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
    /// The database-path box. Typed as a plain string and applied on Enter,
    /// so one session can hop between vault files without restarting.
    File,
}

/* A question the UI asks on its own account. Nothing is blocked on the
   answer, so it carries no reply channel: the session carries on behind it. */
/* Copy was dropped when deletes joined: a delete confirm names the entry it
   is about, and the title text cannot be copied around a String. */
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Confirm {
    Quit,
    /* The title travels with the id for the prompt line. It is a display
       copy of a name field, never the password: the confirm popup must stay
       safe to screenshot with the vault unlocked. */
    DeleteEntry { id: NodeId, title: String },
    /* Same rule as the entry delete: the title rides along for the prompt
       line only, and the vault refuses non-empty groups before this ever
       fires, so a confirmed group delete cannot take a subtree with it. */
    DeleteGroup { id: NodeId, title: String },
}

/// Which box of the entry form the keys are typing into.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FormField {
    #[default]
    Title,
    Username,
    Password,
    Url,
    Notes,
}

/* Add or edit. The edit carries the entry id so submit writes to the row the
   form was opened from, not to wherever the cursor has drifted since. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormKind {
    Add,
    Edit(NodeId),
}

/* The modal entry editor. Values are plain Strings here: the password leaves
   ProtectedString only while the user is literally looking at it, and the
   form is closed (or the app exits) in every other state. */
pub struct Form {
    pub kind: FormKind,
    pub field: FormField,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Char index into the focused box, same rule as the unlock caret.
    pub caret: usize,
    /* Empty means keep — but only while untouched. A user who opened edit,
       typed over the password, then backspaced it empty meant to clear it,
       not to keep: so one keystroke in the box flips this latch, and submit
       reads it rather than guessing from emptiness. */
    pub password_touched: bool,
}

/* The one-box prompt behind `A` (new group) and `E` (rename group). One box,
   so unlike the entry form there is no field cycling — just a value, a caret
   and the same char-index rule as every other box. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupPromptKind {
    New,
    Rename(NodeId),
}

pub struct GroupPrompt {
    pub kind: GroupPromptKind,
    pub value: String,
    /// Char index into `value`, same rule as the unlock caret.
    pub caret: usize,
}

/* Something sitting on the shelf between `X` and `V`. The id travels alone:
   the title is looked up fresh wherever it is shown, so a rename between the
   cut and the paste still reads right, and a deleted source disarms itself
   rather than pasting a ghost. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cut {
    Entry(NodeId),
    Group(NodeId),
}

/* One slot, one undo. The snapshot carries the whole entry — secrets
   included, zeroized on drop like every other copy — because a field-by-field
   restore would miss the timestamps the form never touches. Group delete is
   not undoable: it only ever runs on an empty group behind a confirm, and
   its contents were moved or deleted through paths that arm their own undo. */
pub enum Undo {
    /// Before-state of an edited entry; restore swaps it wholesale.
    Edit { id: NodeId, before: Entry },
    /// A deleted entry, where it lived, and what it was.
    Delete {
        id: NodeId,
        parent: NodeId,
        before: Entry,
    },
    /// An added entry that `u` removes again.
    AddEntry { id: NodeId, title: String },
    /// A group rename that `u` turns back.
    Rename { id: NodeId, before: String },
}

/* How the entries pane orders itself. `Stored` is the file's own order; the
   rest are views over it — the vault vec is never re-ordered, so `o` cycling
   back always lands exactly where the file left things. Session-only for
   now: config has no write-back, so the choice does not survive a restart. */
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SortOrder {
    #[default]
    Stored,
    Name,
    Recent,
    Updated,
}

impl SortOrder {
    pub fn next(self) -> Self {
        match self {
            SortOrder::Stored => SortOrder::Name,
            SortOrder::Name => SortOrder::Recent,
            SortOrder::Recent => SortOrder::Updated,
            SortOrder::Updated => SortOrder::Stored,
        }
    }

    /// What the status flash calls it.
    pub fn label(self) -> &'static str {
        match self {
            SortOrder::Stored => "stored order",
            SortOrder::Name => "by name",
            SortOrder::Recent => "by recent",
            SortOrder::Updated => "by updated",
        }
    }
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

/// Byte offset of char index `at` in `s`. The carets count chars, Rust edits
/// count bytes; this is the bridge, and clamping past the end means "the end"
/// rather than a panic.
pub fn char_index_to_byte(s: &str, at: usize) -> usize {
    s.char_indices()
        .nth(at)
        .map_or(s.len(), |(byte, _)| byte)
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
    /* Whether the detail pane shows the real password. Off because the pane
       is what the eye lands on, and a shown password is one screenshot away
       from a leak. `*` flips it and says which way, so the key never reads
       as dead. */
    pub show_password: bool,
    /* Entries-pane ordering, cycled by `o`. A view over the stored vec, not
       a re-ordering of it (see SortOrder above). */
    pub order: SortOrder,
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
    /// The typed vault-file path. Prefilled from the config once; edits here
    /// stay across auto-locks, so switching vaults is a Tab away.
    pub unlock_file: String,
    /// Where typing lands, as a char index into the focused box (see below).
    pub caret: usize,
    /// Plain-text password on the unlock screen. `*` flips it, the way the
    /// browser's `*` flips the detail pane; a fresh unlock starts hidden.
    pub unlock_reveal: bool,
    /// Unsaved changes. Set by every vault mutation; quitting while set asks.
    dirty: bool,
    /* The modal entry editor. None when closed; the browser hands its keys
       over while Some, the way the unlock screen does. */
    pub form: Option<Form>,
    /* The one-box group prompt (A/E). None when closed; same handover rule
       as the entry form. */
    pub group_prompt: Option<GroupPrompt>,
    /* Armed cut waiting for V. None when the shelf is empty; Esc unwinds it
       before its usual report so a mis-cut is one press from undone. */
    pub cut: Option<Cut>,
    /* One undo slot, armed by the last mutation and consumed by `u`. */
    pub undo: Option<Undo>,
    /* Live fuzzy search. None when the band is closed; Some holds the typed
       needle and filters the entries pane as a predicate — the vault itself
       is never touched. `enter` closes the band keeping the filter; Esc
       clears the filter first (and only quits-ish reports once empty). */
    pub search: Option<String>,
    /* Whether the band has the keyboard. Some-without-band is a kept filter:
       Enter keeps the needle and hands the keys back to the browser, so key
       routing reads this flag, never `search.is_some()`. */
    pub band: bool,
    /// Char index into the search band, same rule as every other caret.
    pub search_caret: usize,
    /// Ranks the current needle against every entry's haystack, reusing its
    /// scratch buffers. Lives here so the band and `entry_rows` share one.
    pub searcher: crate::search::Searcher,
    /* Idle auto-lock. `None` is off. The deadline is checked once per frame
       in `run`, never in the draw, which must not mutate. */
    pub lock_after: Option<Duration>,
    pub last_activity: Instant,
    /* The OS clipboard with its auto-clear timer. `None` until startup wires
       it from the config: `App::new` must stay callable in tests without
       touching platform clipboard state. */
    board: Option<Board>,
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
            show_password: false,
            order: SortOrder::default(),
            db_path: None,
            unlock_new: false,
            unlock_field: UnlockField::Password,
            unlock_password: String::new(),
            unlock_keyfile: String::new(),
            unlock_file: String::new(),
            board: None,
            unlock_confirm: String::new(),
            caret: 0,
            unlock_reveal: false,
            dirty: false,
            form: None,
            group_prompt: None,
            cut: None,
            undo: None,
            search: None,
            band: false,
            search_caret: 0,
            searcher: crate::search::Searcher::new(),
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

    /// Test hook: forces the current flash to expire so a queued message
    /// surfaces. The frame loop does this naturally; tests have no loop.
    #[cfg(test)]
    pub fn expire_now(&mut self) {
        self.flash_until = Some(Instant::now() - Duration::from_secs(1));
        self.expire_flash();
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
    /* Test-only in practice: prod mutations cascade through persist(). Kept
       pub so tests can arm the quit guard directly. */
    #[allow(dead_code)]
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /* Flip the detail pane between bullets and the real password. Showing
       says so out loud: a silent reveal reads as a key that did nothing,
       and the next `*` press must find the pane hidden again. */
    pub fn toggle_password(&mut self) {
        self.show_password = !self.show_password;
        if self.show_password {
            self.say("password shown  ·  * hides it");
        }
    }

    /* Flip the lock screen between bullets and the typed master password.
       Same contract as the detail pane's `*`: the flip says so out loud, so
       a reveal never happens silently on the one screen that guards
       everything. Hiding deliberately says nothing — the bullets going back
       are visible proof enough. */
    pub fn toggle_unlock_reveal(&mut self) {
        self.unlock_reveal = !self.unlock_reveal;
        if self.unlock_reveal {
            self.say("password shown  ·  * hides it");
        }
    }

    /// Wire the OS clipboard from the config timeout. Called once at startup;
    /// `None` until then so tests never touch platform clipboard state.
    pub fn set_board(&mut self, board: Board) {
        self.board = Some(board);
    }

    /* One keypress onto the clipboard. An empty or missing field says which:
       copying an empty string would wipe whatever the user is holding in the
       clipboard to protect nothing, and silence reads as a broken key. */
    pub fn copy_username(&mut self) {
        self.copy_field("username", |e| e.username.as_str().to_string());
    }

    pub fn copy_password(&mut self) {
        self.copy_field("password", |e| e.password.as_str().to_string());
    }

    pub fn copy_url(&mut self) {
        self.copy_field("url", |e| e.url.clone());
    }

    fn copy_field(&mut self, label: &str, take: impl FnOnce(&Entry) -> String) {
        let Some(entry) = self.selected_entry() else {
            self.say("no entry here to copy from");
            return;
        };
        let text = take(entry);
        if text.is_empty() {
            self.say(format!("no {label} on this entry"));
            return;
        }
        let Some(board) = &self.board else {
            self.say("clipboard is not ready  ·  report this as a bug");
            return;
        };
        match board.copy(&text) {
            Ok(()) => match board.timeout_secs() {
                Some(secs) => self.say(format!("copied {label}  ·  clears in {secs}s")),
                None => self.say(format!("copied {label}")),
            },
            Err(e) => self.say(e),
        }
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
        self.unlock_reveal = false;
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
        /* Prefill the typed box only if the user has not typed their own:
           `set_db_path` runs once at startup, and a later call (vault switch)
           must not clobber whatever is mid-edit. */
        if self.unlock_file.is_empty()
            && let Some(p) = &self.db_path
        {
            self.unlock_file = p.display().to_string();
        }
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
            self.say("no database configured  ·  run `Sennel --help` for --db");
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
                /* The next screen opens on bullets again: a reveal is for
                   reading the box you are on, never a browser-side default. */
                self.unlock_reveal = false;
                self.unlock_field = UnlockField::Password;
                self.caret = 0;
                self.unlock_new = false;
                self.open_vault(vault);
                self.resting = "ready".into();
                let plural = if n == 1 { "entry" } else { "entries" };
                self.say(format!("unlocked {n} {plural}"));
            }
            Err(VaultError::WrongPassword) => {
                self.unlock_reveal = false;
                self.say("wrong password or key file  ·  try again");
            }
            Err(e) => self.say(format!("cannot open {}  ·  {e}", path.display())),
        }
    }

    /// Tab and shift-Tab through the unlock boxes, wrapping. Three boxes, or
    /// four in create mode where the confirm and the file box join.
    pub fn next_unlock_field(&mut self, forward: bool) {
        let n = if self.unlock_new { 4 } else { 3 };
        let at = match self.unlock_field {
            UnlockField::File => 0,
            UnlockField::Password => 1,
            UnlockField::KeyFile => 2,
            UnlockField::Confirm => 3,
        };
        self.unlock_field = match (at + if forward { 1 } else { n - 1 }) % n {
            0 => UnlockField::File,
            1 => UnlockField::Password,
            2 => UnlockField::KeyFile,
            _ => UnlockField::Confirm,
        };
        // Behind the text, which is where an edit to a prefilled value starts.
        self.caret = self.active_unlock_value().chars().count();
    }

    /// The box the unlock keys are typing into.
    pub fn active_unlock_value(&mut self) -> &mut String {
        match self.unlock_field {
            UnlockField::File => &mut self.unlock_file,
            UnlockField::Password => &mut self.unlock_password,
            UnlockField::KeyFile => &mut self.unlock_keyfile,
            UnlockField::Confirm => &mut self.unlock_confirm,
        }
    }

    /* Enter on the file box: make the typed path the vault this session
       unlocks. The path is display text, not a secret, and the flash names
       what it was set to so a typo reads as a typo. */
    pub fn accept_file_box(&mut self) {
        let typed = self.unlock_file.trim().to_string();
        if typed.is_empty() {
            self.say("type a path first");
            return;
        }
        self.db_path = Some(PathBuf::from(typed));
        self.refresh_db_state();
        self.unlock_field = UnlockField::Password;
        self.caret = 0;
        self.say(format!(
            "vault set{}  ·  enter the password",
            if self.unlock_new { "  ·  new vault" } else { "" }
        ));
    }

    /// Byte offset of the caret, for slicing. The caret is a char index: a
    /// byte one lands inside a multi-byte character the moment a password
    /// carries an accent, and `String::insert` panics on it.
    fn caret_byte(&self) -> usize {
        let value = match self.unlock_field {
            UnlockField::File => &self.unlock_file,
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
            /* A collapsed group hides its subtree but stays visible itself, so
               the cursor on it keeps a row and Right re-opens it. Groups are
               born expanded (keepass-rs defaults the flag true), so the tree
               only shrinks after an explicit Left. */
            let collapsed = vault.get_group(&id).is_some_and(|g| !g.is_expanded);
            if !collapsed {
                /* Reversed so the first child pops first and order matches the
                   stored child list. */
                for child in vault.groups_in(&id).iter().rev() {
                    stack.push((child.id, depth + 1));
                }
            }
        }
        out
    }

    /// Entry ids of the entries pane in the active order. Positions, like the
    /// group tree above: the cursor holds the id, the list is rebuilt per
    /// frame, and the two meet in `snap`.
    /* &mut self, not &self: the matcher scores with internal scratch state,
       so the filter loop borrows it mutably while the vault stays shared. */
    pub fn entry_rows(&mut self) -> Vec<NodeId> {
        /* A live needle widens the pane to the whole vault: search is the one
           question whose answer is rarely "the folder I was already in", and
           the count in the status bar already promised the matches existed. */
        let global = self
            .search
            .as_deref()
            .is_some_and(|n| !n.is_empty());
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let mut entries: Vec<&Entry> = if global {
            let mut all: Vec<&Entry> = vault.db().entries.values().collect();
            /* The map has no order of its own: a title sort gives the Stored
               view a stable base — and every other order a deterministic
               tiebreak — instead of whatever bucket iteration coughed up this
               frame. */
            all.sort_by_key(|a| a.title.to_lowercase());
            all
        } else {
            match self.group_cursor {
                Some(group) => vault.entries_in(&group),
                None => Vec::new(),
            }
        };
        /* Stable sorts: ties keep the file's own order, so equal timestamps
           never shuffle rows between presses of `o`. Missing timestamps sort
           last under Reverse, reading as "oldest". */
        match self.order {
            SortOrder::Stored => {}
            SortOrder::Name => entries.sort_by(|a, b| {
                a.title.to_lowercase().cmp(&b.title.to_lowercase())
            }),
            SortOrder::Recent => {
                entries.sort_by_key(|e| std::cmp::Reverse(e.creation_time.as_millis()))
            }
            SortOrder::Updated => {
                entries.sort_by_key(|e| std::cmp::Reverse(e.last_modification_time.as_millis()))
            }
        }
        let ids: Vec<NodeId> = entries.iter().map(|e| e.id).collect();
        if global {
            /* rank_entry, not raw rank: multi-word needles ("git octo")
               become Pattern atoms there, and the band must agree with the
               count in `entry_matches`, which uses the same predicate. */
            let needle = self.search.clone().unwrap_or_default();
            let mut hits: Vec<NodeId> = ids
                .into_iter()
                .filter(|id| {
                    self.searcher
                        .rank_entry(&needle, vault, id)
                        .is_some()
                })
                .collect();
            /* Relevance order while searching: the best hit first, so the
               cursor lands on the likely answer without a single j. Ties keep
               the sorted order above. */
            let mut scored: Vec<(NodeId, u16)> = hits
                .iter()
                .map(|id| {
                    let score = self
                        .searcher
                        .rank_entry(&needle, vault, id)
                        .unwrap_or(0);
                    (*id, score)
                })
                .collect();
            scored.sort_by_key(|a| std::cmp::Reverse(a.1));
            hits = scored.into_iter().map(|(id, _)| id).collect();
            return hits;
        }
        ids
    }

    /// How many entries the vault holds in total, for the "N of M shown"
    /// search count. Reads the raw map, not any view.
    pub fn entry_total(&self) -> usize {
        self.vault.as_ref().map_or(0, Vault::entry_count)
    }

    /// How many rows the filter leaves visible, across the whole vault. The
    /// entries pane only shows the cursor group, but the count tells the
    /// truth about the filter: the needle still matches rows elsewhere.
    /* &mut self for the same reason as entry_rows: the searcher scores with
       internal scratch state, and the draw path already holds &mut App. */
    pub fn entry_matches(&mut self) -> usize {
        let Some(vault) = &self.vault else {
            return 0;
        };
        let ids: Vec<NodeId> = vault.db().entries.keys().copied().collect();
        ids.iter().filter(|id| self.search_hit(**id)).count()
    }

    /* `o` cycles the entries-pane order. `snap` re-points the cursor because
       the id it held may have moved rows — the selection follows the entry,
       not the position, which is the whole reason cursors hold ids. */
    pub fn cycle_order(&mut self) {
        self.order = self.order.next();
        self.snap();
        self.say(format!("order: {}", self.order.label()));
    }

    /* Left on the groups pane folds the selected group. Only groups with
       subgroups fold: a leaf collapsing to no visible change would read as
       a dead key. An already-folded group reports rather than re-folding. */
    pub fn collapse_group(&mut self) {
        let Some(id) = self.group_cursor else {
            return;
        };
        let Some(vault) = &self.vault else {
            return;
        };
        if vault.groups_in(&id).is_empty() {
            self.say("a group without subgroups does not fold");
            return;
        }
        if !vault.get_group(&id).is_some_and(|g| g.is_expanded) {
            self.say("already folded");
            return;
        }
        self.vault
            .as_mut()
            .expect("checked above")
            .set_expanded(&id, false);
    }

    /// Right on the groups pane re-opens a folded group.
    pub fn expand_group(&mut self) {
        if let Some(id) = self.group_cursor
            && let Some(vault) = &mut self.vault
        {
            vault.set_expanded(&id, true);
        }
    }

    /* `/` opens the band over whatever was last searched, so refining a
       filter does not mean retyping it. The caret lands at the end: you came
       here to add characters. */
    pub fn open_search(&mut self) {
        let prior = self.search.clone().unwrap_or_default();
        self.search_caret = prior.chars().count();
        self.search = Some(prior);
        self.band = true;
    }

    /// Enter on the band: keep the filter, hand the keys back to the browser.
    pub fn keep_search(&mut self) {
        if self.search.as_deref().is_some_and(str::is_empty) {
            self.search = None;
        }
        self.band = false;
        self.snap();
    }

    /* Esc clears the filter — on the band itself or, once Enter has kept it,
       from the browser. With nothing to clear it reports false so the caller
       can fall through to its usual Esc report. */
    pub fn clear_search(&mut self) -> bool {
        let was_live = self.search.is_some();
        if was_live {
            self.search = None;
            self.search_caret = 0;
            self.band = false;
            self.snap();
        }
        was_live
    }

    /* The band owns its caret/word keys exactly like every other box. These
       mirror the form variants but write to `search` — small duplication for
       keeping each modal's logic readable in one place. */
    pub fn search_insert(&mut self, ch: char) {
        let Some(query) = &mut self.search else {
            return;
        };
        let at = char_index_to_byte(query, self.search_caret);
        query.insert(at, ch);
        self.search_caret += 1;
        self.search_changed();
    }

    pub fn search_backspace(&mut self) {
        let Some(query) = &mut self.search else {
            return;
        };
        if self.search_caret == 0 {
            return;
        }
        let start = char_index_to_byte(query, self.search_caret - 1);
        let end = char_index_to_byte(query, self.search_caret);
        query.drain(start..end);
        self.search_caret -= 1;
        self.search_changed();
    }

    pub fn search_delete(&mut self) {
        let Some(query) = &mut self.search else {
            return;
        };
        let len = query.chars().count();
        if self.search_caret >= len {
            return;
        }
        let start = char_index_to_byte(query, self.search_caret);
        let end = char_index_to_byte(query, self.search_caret + 1);
        query.drain(start..end);
        self.search_changed();
    }

    pub fn search_move(&mut self, right: bool) {
        let len = self
            .search
            .as_ref()
            .map(|q| q.chars().count())
            .unwrap_or(0);
        if right {
            self.search_caret = (self.search_caret + 1).min(len);
        } else {
            self.search_caret = self.search_caret.saturating_sub(1);
        }
    }

    pub fn search_end(&mut self, end: bool) {
        let len = self
            .search
            .as_ref()
            .map(|q| q.chars().count())
            .unwrap_or(0);
        self.search_caret = if end { len } else { 0 };
    }

    pub fn search_clear(&mut self) {
        if let Some(query) = &mut self.search {
            query.clear();
        }
        self.search_caret = 0;
        self.search_changed();
    }

    pub fn search_kill_word(&mut self) {
        let Some(query) = &mut self.search else {
            return;
        };
        /* Head is sliced out first so the drain below does not fight an
           immutable borrow: the caret maths needs the pre-edit head length. */
        let at = char_index_to_byte(query, self.search_caret);
        let head = query[..at].to_string();
        let Some(cut) = head.rfind(|c: char| !c.is_whitespace())
            .and_then(|end| head[..=end].rfind(char::is_whitespace))
        else {
            query.drain(..at);
            self.search_caret = 0;
            self.search_changed();
            return;
        };
        query.drain(cut..at);
        self.search_caret -= head[cut..].chars().count();
        self.search_changed();
    }

    /// The needle changed: re-point the cursor onto a row that survives the
    /// filter, exactly like any other view change.
    fn search_changed(&mut self) {
        self.snap();
    }

    /// Whether the current needle passes an entry. The single predicate the
    /// rows list and the status count both read, so they can never disagree.
    pub fn search_hit(&mut self, id: NodeId) -> bool {
        let Some(needle) = self.search.as_deref().filter(|n| !n.is_empty()) else {
            return true;
        };
        let Some(vault) = &self.vault else {
            return true;
        };
        self.searcher.rank_entry(needle, vault, &id).is_some()
    }

    pub fn selected_group(&self) -> Option<&Group> {
        let (vault, id) = (self.vault.as_ref()?, self.group_cursor?);
        vault.get_group(&id)
    }

    /// The root id of the open vault. Only reached from browser paths that
    /// already know a vault is open.
    fn root_id(&self) -> NodeId {
        self.vault.as_ref().expect("browser keys need a vault").root_id()
    }

    /* Filtered out means not selected: the entry cursor may name an entry of
       another group after the group cursor moved, and acting on it would edit
       a row that is not on screen. A live search relaxes the rule — the rows
       list is global then, and a hit from another folder is exactly the row
       the user asked to act on. */
    pub fn selected_entry(&self) -> Option<&Entry> {
        let (vault, group, id) = (self.vault.as_ref()?, self.group_cursor?, self.entry_cursor?);
        let searching = self.search.as_deref().is_some_and(|n| !n.is_empty());
        vault.get_entry(&id).filter(|_| {
            searching || vault.parent_group_of_entry(&id) == Some(group)
        })
    }

    /* Puts both cursors back on rows that exist. Called after every mutation
       and every cursor move across groups: a cursor on a deleted group or an
       entry of another group is a selection nobody can see, and every command
       reads as dead until the next keypress moves it. */
    pub fn snap(&mut self) {
        if self.vault.is_none() {
            self.group_cursor = None;
            self.entry_cursor = None;
            return;
        };
        let tree = self.group_tree();
        /* A cursor must rest on a *visible* row: a group that still exists
           but is folded shut inside its parent is not one anyone can see. */
        if self
            .group_cursor
            .is_none_or(|id| !tree.iter().any(|(g, _)| *g == id))
        {
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

    /* n/N walk the visible rows — which, while a needle is live, are the
       matches. Clamps at the ends and says so: a jump that quietly wraps
       reads as a key that did nothing. With no needle this is a plain
       cursor step, so n stays honest on a browser with no search. */
    pub fn jump_match(&mut self, next: bool) {
        let rows = self.entry_rows();
        if rows.is_empty() {
            self.say("no matches · esc clears the filter");
            return;
        }
        let at = self
            .entry_cursor
            .and_then(|id| rows.iter().position(|e| *e == id))
            .unwrap_or(0);
        if next && at + 1 >= rows.len() {
            self.say("last match");
            return;
        }
        if !next && at == 0 {
            self.say("first match");
            return;
        }
        self.entry_cursor = Some(rows[if next { at + 1 } else { at - 1 }]);
        self.entry_scroll = 0;
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

    /* ---- Entry form (Wave 5.1) ---- */

    /* Autosave after every mutation. Dirty is set before the attempt and
       cleared on success, so a failed save leaves the quit guard armed and
       the flash names the problem instead of pretending nothing happened.
       An in-memory vault (tests) has no path: it cannot save, so it stays
       dirty rather than silently discarding. */
    pub fn persist(&mut self) {
        let Some(vault) = &self.vault else {
            return;
        };
        if vault.path().is_none() {
            self.dirty = true;
            return;
        }
        match vault.save() {
            Ok(()) => self.dirty = false,
            Err(e) => {
                self.dirty = true;
                self.say(format!("save failed  ·  {e} · kept in memory"));
            }
        }
    }

    /* `a` on the browser: a blank form aimed at the cursor group. Requires a
       group because an entry must live somewhere, and the root always exists
       once a vault is open. */
    pub fn open_add_form(&mut self) {
        if self.vault.is_none() || self.group_cursor.is_none() {
            self.say("no vault open to add to");
            return;
        }
        self.form = Some(Form {
            kind: FormKind::Add,
            field: FormField::Title,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            caret: 0,
            password_touched: false,
        });
    }

    /* `e` on an entry: prefilled boxes. The password box starts empty and
       untouched — the one case where "empty" means keep — so the secret is
       not even in the form buffer until the user asks for it. */
    pub fn open_edit_form(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.say("no entry here to edit");
            return;
        };
        let id = entry.id;
        self.form = Some(Form {
            kind: FormKind::Edit(id),
            field: FormField::Title,
            title: entry.title.clone(),
            username: entry.username.as_str().to_string(),
            password: String::new(),
            url: entry.url.clone(),
            notes: entry.notes.as_str().to_string(),
            caret: entry.title.chars().count(),
            password_touched: false,
        });
    }

    /* `D` on an entry: ask first. The confirm carries the title for the
       prompt so the answer is about a row the user can see, not a blind id. */
    pub fn ask_delete_entry(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.say("no entry here to delete");
            return;
        };
        self.confirm = Some(Confirm::DeleteEntry {
            id: entry.id,
            title: entry.title.clone(),
        });
    }

    /// The yes side of the delete confirm. Kept off the key handler so the
    /// confirm popup and the delete itself cannot drift apart.
    pub fn confirm_delete_entry(&mut self, id: NodeId) {
        /* Snapshot before the delete — undo puts the whole entry back
           (restore appends it to its old parent; the list position is not
           reconstructible and does not matter). */
        let parent = self.vault.as_ref().and_then(|v| v.parent_group_of_entry(&id));
        let before = self.vault.as_ref().and_then(|v| v.get_entry(&id).cloned());
        if let (Some(vault), Some(parent), Some(before)) =
            (self.vault.as_mut(), parent, before)
        {
            match vault.delete_entry(&id) {
                Ok(()) => {
                    self.undo = Some(Undo::Delete {
                        id,
                        parent,
                        before,
                    });
                    self.entry_cursor = None;
                    self.snap();
                    self.persist();
                    self.say("entry deleted");
                }
                Err(e) => {
                    self.undo = None;
                    self.say(format!("cannot delete  ·  {e}"));
                }
            }
        }
    }

    /// Tab (or shift-Tab) through the five form boxes, wrapping.
    pub fn next_form_field(&mut self, forward: bool) {
        let Some(form) = &mut self.form else {
            return;
        };
        let order = [
            FormField::Title,
            FormField::Username,
            FormField::Password,
            FormField::Url,
            FormField::Notes,
        ];
        let at = order.iter().position(|f| *f == form.field).unwrap_or(0);
        let n = order.len();
        form.field = order[(at + if forward { 1 } else { n - 1 }) % n];
        // Behind the text, where an edit to a prefilled value starts.
        form.caret = form_field_value(form, form.field).chars().count();
    }

    /// The box the form keys are typing into.
    pub fn active_form_value(&mut self) -> &mut String {
        let form = self
            .form
            .as_mut()
            .expect("form keys only reach an open form");
        let field = form.field;
        form_field_value(form, field)
    }

    fn form_caret_byte(&self) -> usize {
        let form = self.form.as_ref().expect("form keys only reach an open form");
        let value = form_field_value_ref(form, form.field);
        value
            .char_indices()
            .nth(form.caret)
            .map_or(value.len(), |(at, _)| at)
    }

    pub fn form_insert(&mut self, c: char) {
        let at = self.form_caret_byte();
        let value = self.active_form_value();
        value.insert(at, c);
        let form = self.form.as_mut().expect("just inserted");
        form.caret += 1;
        if form.field == FormField::Password {
            form.password_touched = true;
        }
    }

    pub fn form_backspace(&mut self) {
        let caret = match &self.form {
            Some(f) if f.caret > 0 => f.caret,
            _ => return,
        };
        let at = self.form_caret_byte();
        let value = self.active_form_value();
        let prev = value[..at]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i);
        value.remove(prev);
        let form = self.form.as_mut().expect("backspacing");
        form.caret = caret - 1;
        if form.field == FormField::Password {
            form.password_touched = true;
        }
    }

    pub fn form_delete(&mut self) {
        let at = self.form_caret_byte();
        let has_tail = self
            .active_form_value()
            .get(at..)
            .is_some_and(|rest| !rest.is_empty());
        if has_tail {
            self.active_form_value().remove(at);
            let form = self.form.as_mut().expect("deleting");
            if form.field == FormField::Password {
                form.password_touched = true;
            }
        }
    }

    pub fn form_move(&mut self, right: bool) {
        let len = self.active_form_value().chars().count();
        let form = self.form.as_mut().expect("moving");
        form.caret = if right {
            (form.caret + 1).min(len)
        } else {
            form.caret.saturating_sub(1)
        };
    }

    pub fn form_end(&mut self, end: bool) {
        let len = self.active_form_value().chars().count();
        let form = self.form.as_mut().expect("jumping");
        form.caret = if end { len } else { 0 };
    }

    /// Clear the focused box.
    pub fn form_clear(&mut self) {
        self.active_form_value().clear();
        let form = self.form.as_mut().expect("clearing");
        form.caret = 0;
        if form.field == FormField::Password {
            form.password_touched = true;
        }
    }

    /* The same word delete the unlock box takes. Deletes back to the word
       start, keeping whatever follows the caret. */
    pub fn form_kill_word(&mut self) {
        let at = self.form_caret_byte();
        let start = {
            let value = self.active_form_value();
            let before = value[..at].trim_end();
            before.rfind(' ').map_or(0, |i| i + 1)
        };
        self.active_form_value().drain(start..at);
        let form = self.form.as_mut().expect("killing a word");
        form.caret = form_field_value_ref(form, form.field)[..start].chars().count();
        if form.field == FormField::Password {
            form.password_touched = true;
        }
    }

    /* Enter on the form: write through to the vault and autosave. The title
       is the only must — a password manager row without a name is unreadable
       in every list — and the flash names the box rather than failing
       silently. */
    pub fn submit_form(&mut self) {
        let Some(form) = self.form.take() else {
            return;
        };
        if form.title.trim().is_empty() {
            self.say("a title is the only must  ·  the form stays open");
            // Reopen the same form on the title box rather than losing input.
            self.form = Some(form);
            self.form.as_mut().unwrap().field = FormField::Title;
            self.form.as_mut().unwrap().caret =
                self.form.as_ref().unwrap().title.chars().count();
            return;
        }
        let result = match form.kind {
            FormKind::Add => {
                let group = self.group_cursor;
                let vault = self.vault.as_mut().expect("add form needs a vault");
                let Some(group) = group else {
                    self.say("no group selected  ·  the form stays open");
                    self.form = Some(form);
                    return;
                };
                vault
                    .create_entry(&group, &form.title, &form.username, &form.password, &form.url, &form.notes)
                    .map(Some)
            }
            FormKind::Edit(id) => {
                /* Empty and untouched keeps the stored password; anything
                   typed — including backspacing to empty — writes what the
                   box now holds. */
                let password = if form.password_touched {
                    Some(form.password.as_str())
                } else {
                    None
                };
                let vault = self.vault.as_mut().expect("edit form needs a vault");
                /* Snapshot before the write: undo restores the entry as the
                   form found it, password included. */
                if let Some(before) = vault.get_entry(&id) {
                    self.undo = Some(Undo::Edit {
                        id,
                        before: before.clone(),
                    });
                }
                vault
                    .update_entry(&id, &form.title, &form.username, password, &form.url, &form.notes)
                    .map(|()| None)
            }
        };
        match result {
            Ok(new_id) => {
                if let Some(id) = new_id {
                    self.undo = Some(Undo::AddEntry {
                        id,
                        title: form.title.clone(),
                    });
                    self.entry_cursor = Some(id);
                }
                self.snap();
                self.persist();
                self.say(match form.kind {
                    FormKind::Add => "entry added",
                    FormKind::Edit(_) => "entry saved",
                });
            }
            Err(e) => {
                self.say(format!("cannot save  ·  {e}"));
                self.undo = None;
                self.form = Some(form);
            }
        }
    }

    /// Esc on the form: throw away the boxes, no vault change, no autosave.
    pub fn cancel_form(&mut self) {
        if self.form.take().is_some() {
            self.say("form closed  ·  nothing changed");
        }
    }

    /* `A`: a new group goes inside the selected one, the way KeePass does it
       — the tree grows where the eye is, not always at the root. */
    pub fn open_group_prompt_new(&mut self) {
        if self.group_cursor.is_none() {
            self.say("no group selected");
            return;
        }
        self.group_prompt = Some(GroupPrompt {
            kind: GroupPromptKind::New,
            value: String::new(),
            caret: 0,
        });
    }

    /* `E`: rename whatever group is selected, from either pane — `e` stays
       the entry editor, so the case is what carries the target. */
    pub fn open_group_prompt_rename(&mut self) {
        let Some(group) = self.selected_group() else {
            self.say("no group here to rename");
            return;
        };
        let title = group.title.clone();
        self.group_prompt = Some(GroupPrompt {
            kind: GroupPromptKind::Rename(group.id),
            value: title.clone(),
            caret: title.chars().count(),
        });
    }

    /* Enter on the group prompt: write through and autosave. Same single
       must as the entry form — a nameless group is unreadable in the tree. */
    pub fn submit_group_prompt(&mut self) {
        let Some(prompt) = self.group_prompt.take() else {
            return;
        };
        if prompt.value.trim().is_empty() {
            self.say("a name is the only must  ·  the prompt stays open");
            self.group_prompt = Some(prompt);
            return;
        }
        let result = match prompt.kind {
            GroupPromptKind::New => {
                let parent = self.group_cursor;
                let vault = self.vault.as_mut().expect("group prompt needs a vault");
                match parent {
                    Some(parent) => vault.create_group(&parent, &prompt.value).map(Some),
                    None => Err(VaultError::GroupNotFound),
                }
            }
            GroupPromptKind::Rename(id) => {
                let vault = self.vault.as_mut().expect("group prompt needs a vault");
                /* Snapshot the old name before the rename so one `u` puts
                  GroupName back. */
                if let Some(group) = vault.get_group(&id) {
                    self.undo = Some(Undo::Rename {
                        id,
                        before: group.title.clone(),
                    });
                }
                vault.rename_group(&id, &prompt.value).map(|()| None)
            }
        };
        match result {
            Ok(new_id) => {
                if let Some(id) = new_id {
                    self.group_cursor = Some(id);
                }
                self.snap();
                self.persist();
                self.say(match prompt.kind {
                    GroupPromptKind::New => "group added",
                    GroupPromptKind::Rename(_) => "group renamed",
                });
            }
            Err(e) => {
                self.say(format!("cannot save  ·  {e}"));
                self.group_prompt = Some(prompt);
            }
        }
    }

    /// Esc on the group prompt: throw the box away, no vault change.
    pub fn cancel_group_prompt(&mut self) {
        if self.group_prompt.take().is_some() {
            self.say("prompt closed  ·  nothing changed");
        }
    }

    pub fn group_prompt_insert(&mut self, c: char) {
        let Some(prompt) = &mut self.group_prompt else {
            return;
        };
        let at = prompt
            .value
            .char_indices()
            .nth(prompt.caret)
            .map_or(prompt.value.len(), |(at, _)| at);
        prompt.value.insert(at, c);
        prompt.caret += 1;
    }

    pub fn group_prompt_backspace(&mut self) {
        let caret = match &self.group_prompt {
            Some(p) if p.caret > 0 => p.caret,
            _ => return,
        };
        let Some(prompt) = &mut self.group_prompt else {
            return;
        };
        let at = prompt
            .value
            .char_indices()
            .nth(caret)
            .map_or(prompt.value.len(), |(at, _)| at);
        let prev = prompt.value[..at]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i);
        prompt.value.remove(prev);
        prompt.caret = caret - 1;
    }

    pub fn group_prompt_delete(&mut self) {
        let Some(prompt) = &mut self.group_prompt else {
            return;
        };
        let at = prompt
            .value
            .char_indices()
            .nth(prompt.caret)
            .map_or(prompt.value.len(), |(at, _)| at);
        if prompt.value.get(at..).is_some_and(|rest| !rest.is_empty()) {
            prompt.value.remove(at);
        }
    }

    pub fn group_prompt_move(&mut self, right: bool) {
        let Some(prompt) = &mut self.group_prompt else {
            return;
        };
        let len = prompt.value.chars().count();
        prompt.caret = if right {
            (prompt.caret + 1).min(len)
        } else {
            prompt.caret.saturating_sub(1)
        };
    }

    pub fn group_prompt_end(&mut self, end: bool) {
        let Some(prompt) = &mut self.group_prompt else {
            return;
        };
        prompt.caret = if end { prompt.value.chars().count() } else { 0 };
    }

    pub fn group_prompt_clear(&mut self) {
        let Some(prompt) = &mut self.group_prompt else {
            return;
        };
        prompt.value.clear();
        prompt.caret = 0;
    }

    /* The same word delete the other boxes take: back to the word start,
       keeping whatever follows the caret. */
    pub fn group_prompt_kill_word(&mut self) {
        let Some(prompt) = &mut self.group_prompt else {
            return;
        };
        let at = prompt
            .value
            .char_indices()
            .nth(prompt.caret)
            .map_or(prompt.value.len(), |(at, _)| at);
        let start = prompt.value[..at].trim_end().rfind(' ').map_or(0, |i| i + 1);
        prompt.value.drain(start..at);
        prompt.caret = prompt.value[..start].chars().count();
    }

    /* `D` on the groups pane. The vault refuses non-empty groups, but the
       refusal is named here so the confirm never opens for a delete that
       cannot happen — the message points at X, which is the way out. */
    pub fn ask_delete_group(&mut self) {
        let Some(group) = self.selected_group() else {
            self.say("no group here to delete");
            return;
        };
        if group.id == self.root_id() {
            self.say("the root group cannot be deleted");
            return;
        }
        let has_contents = !self
            .vault
            .as_ref()
            .map(|v| {
                v.entries_in(&group.id).is_empty() && v.groups_in(&group.id).is_empty()
            })
            .unwrap_or(true);
        if has_contents {
            self.say("group not empty  ·  move or delete its contents first");
            return;
        }
        self.confirm = Some(Confirm::DeleteGroup {
            id: group.id,
            title: group.title.clone(),
        });
    }

    /// The yes side of the group delete confirm, kept off the key handler.
    pub fn confirm_delete_group(&mut self, id: NodeId) {
        let Some(vault) = &mut self.vault else {
            return;
        };
        match vault.delete_group(&id) {
            Ok(()) => {
                /* A cut pointing at the deleted group is a ghost: disarm it
                   rather than letting V paste nothing. */
                if self.cut == Some(Cut::Group(id)) {
                    self.cut = None;
                }
                self.group_cursor = None;
                self.snap();
                self.persist();
                self.say("group deleted");
            }
            Err(e) => self.say(format!("cannot delete  ·  {e}")),
        }
    }

    /* `X`: cut whatever the cursor is on. Groups pane cuts the group, entries
       pane cuts the entry — one key, pane decides, the status bar says which. */
    pub fn cut_selected(&mut self) {
        let Some(cut) = (match self.active_pane {
            Pane::Groups => match self.selected_group() {
                Some(g) if g.id != self.root_id() => Some(Cut::Group(g.id)),
                Some(_) => {
                    self.say("the root group cannot be cut");
                    None
                }
                None => {
                    self.say("no group here to cut");
                    None
                }
            },
            Pane::Entries => match self.selected_entry() {
                Some(e) => Some(Cut::Entry(e.id)),
                None => {
                    self.say("no entry here to cut");
                    None
                }
            },
        }) else {
            return;
        };
        self.cut = Some(cut);
        self.say(match cut {
            Cut::Group(_) => "group cut  ·  v pastes it under another group",
            Cut::Entry(_) => "entry cut  ·  v moves it to another group",
        });
    }

    /* `V`: paste the armed cut into the selected group, from either pane.
       One-shot: the shelf empties on a successful paste, and a failed one
       stays armed so a typo in the target costs nothing. */
    pub fn paste_cut(&mut self) {
        let Some(cut) = self.cut else {
            self.say("nothing cut  ·  x arms the shelf");
            return;
        };
        let Some(target) = self.group_cursor else {
            self.say("no group selected");
            return;
        };
        let Some(vault) = &mut self.vault else {
            return;
        };
        let result = match cut {
            Cut::Entry(id) => vault.move_entry(&id, &target).map(|()| Some(id)),
            Cut::Group(id) => vault.move_group(&id, &target).map(|()| Some(id)),
        };
        match result {
            Ok(moved) => {
                self.cut = None;
                match cut {
                    Cut::Entry(_) => self.entry_cursor = moved,
                    Cut::Group(_) => self.group_cursor = moved,
                }
                self.snap();
                self.persist();
                self.say(match cut {
                    Cut::Entry(_) => "entry moved",
                    Cut::Group(_) => "group moved",
                });
            }
            Err(e) => self.say(format!("cannot paste  ·  {e}")),
        }
    }

    /* Esc unwinds the shelf before its usual report: a mis-cut is one press
       from undone, and the message says so rather than the key reading dead. */
    pub fn drop_cut(&mut self) -> bool {
        if self.cut.take().is_some() {
            self.say("cut dropped");
            return true;
        }
        false
    }

    /// Status-bar note for an armed cut, with the title looked up fresh.
    pub fn cut_note(&self) -> Option<String> {
        let vault = self.vault.as_ref()?;
        match self.cut? {
            Cut::Entry(id) => vault
                .get_entry(&id)
                .map(|e| format!("cut: {}", e.title)),
            Cut::Group(id) => vault
                .get_group(&id)
                .map(|g| format!("cut: {}", g.title)),
        }
    }

    /* One slot, one undo: `u` consumes the slot. An older change simply
       becomes unundoable — a full history is a different product, and the
       status bar says what the slot holds so the key never surprises. */
    pub fn undo_last(&mut self) {
        let Some(undo) = self.undo.take() else {
            self.say("nothing to undo · the last change had no undo");
            return;
        };
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        match undo {
            Undo::Edit { id, before } => {
                let title = before.title.clone();
                /* Results ignored the way a rollback is: the mutation can
                   only fail on an id that no longer exists, and persist()
                   below reports anything the save kept from landing. */
                let _ = vault.replace_entry(before);
                self.entry_cursor = Some(id);
                self.snap();
                self.persist();
                self.say(format!("undid edit of {title}"));
            }
            Undo::Delete { id, parent, before } => {
                let title = before.title.clone();
                let _ = vault.restore_entry(before, &parent);
                self.entry_cursor = Some(id);
                self.snap();
                self.persist();
                self.say(format!("restored {title}"));
            }
            Undo::AddEntry { id, title } => {
                /* The add is rolled back by removing what it created, and the
                   undo slot empties instead of growing. */
                let _ = vault.expunge_entry(&id);
                self.entry_cursor = None;
                self.snap();
                self.persist();
                self.say(format!("removed {title}"));
            }
            Undo::Rename { id, before } => {
                let _ = vault.set_group_title(&id, &before);
                self.snap();
                self.persist();
                self.say(format!("restored name {before}"));
            }
        }
    }

    /// What the status bar says the undo slot holds, looked up fresh so a
    /// later rename or delete still names the thing it would restore.
    pub fn undo_note(&self) -> Option<String> {
        let note = match self.undo.as_ref()? {
            Undo::Edit { before, .. } => format!("undo: edit of {}", before.title),
            Undo::Delete { before, .. } => format!("undo: restore {}", before.title),
            Undo::AddEntry { title, .. } => format!("undo: remove {title}"),
            Undo::Rename { before, .. } => format!("undo: name {before}"),
        };
        Some(note)
    }

    /* ^s on the form: generate into the password box. Excludes ambiguous
       glyphs so a password read off this screen can be typed elsewhere —
       l1IO0 are the ones every font renders alike. Touching the box flips
       the keep-latch, so submit writes what was generated. */
    pub fn form_generate(&mut self) {
        let Some(form) = self.form.as_mut() else {
            return;
        };
        let generated = match crate::generator::generate(20, Classes::default(), true) {
            Ok(pw) => pw,
            Err(e) => {
                self.say(format!("cannot generate  ·  {e}"));
                return;
            }
        };
        form.password = generated;
        form.password_touched = true;
        form.caret = form.password.chars().count();
        let bits = crate::generator::entropy_bits(20, crate::generator::Classes::default().alphabet_len(false));
        self.say(format!("generated 20 chars  ·  ~{bits:.0} bits"));
    }
}

/* Mutable access to one form box by field. Free function rather than a
   method so the borrow of `form` stays local and the caret math above can
   read another field's value without fighting the borrow checker. */
fn form_field_value(form: &mut Form, field: FormField) -> &mut String {
    match field {
        FormField::Title => &mut form.title,
        FormField::Username => &mut form.username,
        FormField::Password => &mut form.password,
        FormField::Url => &mut form.url,
        FormField::Notes => &mut form.notes,
    }
}

fn form_field_value_ref(form: &Form, field: FormField) -> &str {
    match field {
        FormField::Title => &form.title,
        FormField::Username => &form.username,
        FormField::Password => &form.password,
        FormField::Url => &form.url,
        FormField::Notes => &form.notes,
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

    /* Copying with no entry under the cursor names the miss: the root group
       holds no entries, so a fresh open has nothing to copy. */
    #[test]
    fn copying_with_no_entry_says_so() {
        let mut app = open_app();
        app.copy_password();
        assert!(app.stage.contains("no entry"), "{}", app.stage);
    }

    /* An empty field is not copied: pushing an empty string would wipe
       whatever the user is holding in the clipboard to protect nothing. */
    #[test]
    fn copying_an_empty_field_names_the_field() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "empty", "u", "", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.step_group(true);
        app.copy_password();
        assert!(app.stage.contains("no password"), "{}", app.stage);
    }

    /* Tests never touch the OS clipboard, so with no board wired the copy
       reports the missing board instead of reaching for one. */
    #[test]
    fn copying_without_a_board_says_so() {
        let mut app = open_app();
        app.step_group(true);
        app.copy_password();
        assert!(app.stage.contains("not ready"), "{}", app.stage);
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

    /* The typed vault file outlives an auto-lock: it names a file, not a
       secret, and retyping a path to unlock the same or another vault after
       an idle lock would be overhead for nothing. */
    #[test]
    fn the_file_box_survives_the_idle_lock() {
        let mut app = open_app();
        app.unlock_file = "/vaults/personal.kdbx".into();
        app.set_lock_timeout(60);
        app.last_activity = Instant::now() - Duration::from_secs(61);
        app.check_idle();
        assert_eq!(app.view, View::Unlock);
        assert_eq!(
            app.unlock_file, "/vaults/personal.kdbx",
            "the path did not survive the lock"
        );
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

    /* A reveal stops at the door: unlocking (or failing to) puts the next
       lock screen back on bullets, so a plain-text peek never becomes the
       default view of the password that follows. */
    #[test]
    fn reveal_resets_after_unlock_attempts() {
        let (mut app, _tmp) = locked_app_with_db(b"correct horse");
        app.unlock_password = "correct horse".into();
        app.toggle_unlock_reveal();
        assert!(app.unlock_reveal);
        let mut pw = b"correct horse".to_vec();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Browser);
        assert!(!app.unlock_reveal, "reveal followed the unlock out");

        let (mut app, _tmp) = locked_app_with_db(b"correct horse");
        app.toggle_unlock_reveal();
        let mut pw = b"wrong guess".to_vec();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Unlock);
        assert!(!app.unlock_reveal, "failed attempt left the box bare");
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

    /* Tab walks three boxes, four in create mode, and lands behind the text:
       an edit to a prefilled key-file path starts at its end. The file box
       joins the cycle, so switching vaults is a Tab from the password. */
    #[test]
    fn tab_walks_three_boxes_four_when_creating() {
        let mut app = App::new();
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::KeyFile);
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::File, "wrapped through file");
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::Password);
        app.unlock_new = true;
        app.next_unlock_field(false);
        assert_eq!(app.unlock_field, UnlockField::File, "backward now cycles 4");
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::Password, "forward rejoins");
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::KeyFile);
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::Confirm, "create joins confirm");
        app.unlock_keyfile = "/keys/k".into();
        app.unlock_field = UnlockField::Password;
        app.next_unlock_field(true);
        assert_eq!(app.unlock_field, UnlockField::KeyFile);
        assert_eq!(app.caret, 7, "caret did not land behind the path");
    }

    /* Enter on the file box re-points the session: a second vault is a Tab
       and a path away, no restart needed. The typed file box is preserved
       across auto-locks, which is what makes the switch stick. */
    #[test]
    fn the_file_box_points_the_session_at_another_vault() {
        let (mut app, tmp) = locked_app_with_db(b"pw");
        let other = tmp
            .0
            .parent()
            .unwrap()
            .join("sennel-test-other.kdbx")
            .display()
            .to_string();
        app.unlock_file = other.clone();
        app.unlock_field = UnlockField::File;
        app.accept_file_box();
        assert_eq!(
            app.db_path,
            Some(tmp.0.parent().unwrap().join("sennel-test-other.kdbx")),
            "path applied"
        );
        assert!(app.unlock_new, "a missing file reads as create");
        assert_eq!(app.unlock_field, UnlockField::Password, "focus went home");
        assert!(app.stage.contains("vault set"), "{}", app.stage);
    }

    /* The file box prefill survives a lock–unlock round trip, so the second
       unlock does not have to retype the path. */
    #[test]
    fn the_file_box_prefills_from_the_config_once() {
        let mut app = App::new();
        app.set_db_path(Some(PathBuf::from("/vaults/main.kdbx")));
        assert_eq!(app.unlock_file, "/vaults/main.kdbx", "prefilled once");
        app.unlock_file = "/vaults/personal.kdbx".into();
        app.set_db_path(Some(PathBuf::from("/vaults/other.kdbx")));
        assert_eq!(
            app.unlock_file, "/vaults/personal.kdbx",
            "a later set must not clobber a mid-edit"
        );
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

    /* Hidden by default: the detail pane is what the eye lands on. Showing
       says so, so the key never reads as dead. */
    #[test]
    fn the_password_starts_hidden_and_showing_says_so() {
        use crate::vault::Vault;
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(&banks, "checking", "octo", "s3cret-pw", "", "")
            .unwrap();
        app.open_vault(vault);
        assert!(!app.show_password);
        app.toggle_password();
        assert!(app.show_password);
        assert!(app.stage.contains("shown"), "{}", app.stage);
        app.toggle_password();
        assert!(!app.show_password);
    }

    /* ---- Wave 5.1: entry form ---- */

    /* `a` on an open vault opens the form; Enter writes the entry into the
       cursor group, moves the entry cursor onto it, and the autosave marks
       an in-memory vault dirty (it has no path to save to). */
    #[test]
    fn add_form_creates_the_entry_on_enter() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.open_add_form();
        assert!(app.form.is_some());
        for c in "savings".chars() {
            app.form_insert(c);
        }
        app.next_form_field(true); // username
        for c in "me".chars() {
            app.form_insert(c);
        }
        app.next_form_field(true); // password
        for c in "pw".chars() {
            app.form_insert(c);
        }
        app.submit_form();
        assert!(app.form.is_none());
        let bank = app.group_cursor.unwrap();
        let rows = app.entry_rows();
        assert_eq!(rows.len(), 2, "the new entry did not land");
        let made = app.vault.as_ref().unwrap().get_entry(&rows[1]).unwrap();
        assert_eq!(made.title, "savings");
        assert_eq!(made.username.as_str(), "me");
        assert_eq!(made.password.as_str(), "pw");
        assert_eq!(app.entry_cursor, Some(rows[1]), "cursor stayed off the new row");
        assert!(app.working(), "in-memory add left no dirty flag");
        assert_eq!(app.stage, "entry added");
        let _ = bank;
    }

    /* An edit that never touched the password box keeps the stored secret:
       the box starts empty so the secret is not even copied into the form. */
    #[test]
    fn edit_with_untouched_password_keeps_the_secret() {
        let mut app = open_app();
        app.step_group(true);
        app.open_edit_form();
        app.next_form_field(true);
        app.next_form_field(true); // password box, empty
        app.next_form_field(true);
        app.next_form_field(true); // notes
        for c in "note".chars() {
            app.form_insert(c);
        }
        app.submit_form();
        let rows = app.entry_rows();
        let kept = app.vault.as_ref().unwrap().get_entry(&rows[0]).unwrap();
        assert_eq!(kept.password.as_str(), "p", "empty edit box overwrote the secret");
        assert_eq!(kept.notes.as_str(), "note");
    }

    /* Typing in the password box latches: backspacing back to empty writes
       empty, because a user who cleared the box meant to clear it. */
    #[test]
    fn edit_with_touched_password_writes_what_the_box_holds() {
        let mut app = open_app();
        app.step_group(true);
        app.open_edit_form();
        app.next_form_field(true);
        app.next_form_field(true); // password
        app.form_insert('x');
        app.form_backspace(); // empty again, but touched
        app.submit_form();
        let rows = app.entry_rows();
        let cleared = app.vault.as_ref().unwrap().get_entry(&rows[0]).unwrap();
        assert_eq!(cleared.password.as_str(), "", "backspace-to-empty did not clear");
    }

    /* Esc throws the form away: no vault change, no autosave, no dirty flag. */
    #[test]
    fn cancelling_the_form_changes_nothing() {
        let mut app = open_app();
        app.step_group(true);
        app.open_edit_form();
        for c in "renamed".chars() {
            app.form_insert(c);
        }
        app.cancel_form();
        assert!(app.form.is_none());
        assert!(!app.working(), "a cancelled form dirtied the vault");
        let rows = app.entry_rows();
        assert_eq!(app.vault.as_ref().unwrap().get_entry(&rows[0]).unwrap().title, "checking");
    }

    /* A title is the only must: submit without one reopens the form on the
       title box instead of writing an unreadable row. */
    #[test]
    fn a_titleless_form_stays_open() {
        let mut app = open_app();
        app.step_group(true);
        app.open_add_form();
        app.submit_form();
        assert!(app.form.is_some(), "empty form was accepted");
        assert!(app.stage.contains("title"), "{}", app.stage);
        assert_eq!(app.entry_rows().len(), 1, "a nameless row was written");
    }

    /* D asks first; y deletes, snaps the cursor somewhere real, and the
       autosave flags an in-memory vault dirty. */
    #[test]
    fn delete_asks_then_y_deletes() {
        let mut app = open_app();
        app.step_group(true);
        app.ask_delete_entry();
        assert!(app.confirm.is_some(), "delete went without asking");
        let Confirm::DeleteEntry { id, title } = app.confirm.clone().unwrap() else {
            panic!("wrong question raised");
        };
        assert_eq!(title, "checking");
        // The confirm handler takes the question before acting on the yes.
        app.confirm = None;
        app.confirm_delete_entry(id);
        assert!(app.confirm.is_none());
        assert!(app.entry_rows().is_empty(), "the row survived the yes");
        assert!(app.working(), "in-memory delete left no dirty flag");
    }

    /* Esc on the delete confirm keeps the row: no is the safe answer. */
    #[test]
    fn delete_confirm_dismissed_deletes_nothing() {
        let mut app = open_app();
        app.step_group(true);
        app.ask_delete_entry();
        app.confirm = None; // what Esc leaves behind
        assert_eq!(app.entry_rows().len(), 1);
    }

    /* Autosave against a real file: submit writes through, so a reopen sees
       the new entry without a manual save step. */
    #[test]
    fn submit_autosaves_to_disk() {
        let tmp = temp_path("autosave");
        let mut seed = Vault::new();
        seed.save_as(&tmp.0, b"pw", None).unwrap();
        let mut app = App::new();
        app.set_db_path(Some(tmp.0.clone()));
        let mut pw = b"pw".to_vec();
        app.try_unlock(&mut pw, None);
        app.open_add_form();
        for c in "bankcard".chars() {
            app.form_insert(c);
        }
        app.submit_form();
        assert!(!app.working(), "autosave left the vault dirty");
        let reopened = Vault::open(&tmp.0, b"pw", None).unwrap();
        let root = reopened.root_id();
        assert_eq!(reopened.entries_in(&root).len(), 1);
        assert_eq!(reopened.entries_in(&root)[0].title, "bankcard");
    }

    /* `A` grows the tree where the eye is: inside the selected group, and
       the cursor lands on the row it just made. */
    #[test]
    fn a_adds_a_group_under_the_selection() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.open_group_prompt_new();
        for c in "Cards".chars() {
            app.group_prompt_insert(c);
        }
        app.submit_group_prompt();
        let tree = app.group_tree();
        assert!(tree.iter().any(|(id, _)| {
            app.vault.as_ref().unwrap().get_group(id).unwrap().title == "Cards"
        }));
        let cursor = app.group_cursor.unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().get_group(&cursor).unwrap().title,
            "Cards"
        );
    }

    /* `E` renames from the prompt prefilled with the current name; the path
       read afterwards must show the new name, not the old one. */
    #[test]
    fn e_renames_the_selected_group() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.open_group_prompt_rename();
        assert_eq!(app.group_prompt.as_ref().unwrap().value, "Banks");
        app.group_prompt_clear();
        for c in "Ledgers".chars() {
            app.group_prompt_insert(c);
        }
        app.submit_group_prompt();
        let path = app
            .vault
            .as_ref()
            .unwrap()
            .group_path(&app.group_cursor.unwrap());
        assert!(path.contains(&"Ledgers".to_string()), "{path:?}");
    }

    #[test]
    fn an_empty_group_name_stays_open() {
        let mut app = open_app();
        app.open_group_prompt_new();
        app.submit_group_prompt();
        assert!(app.group_prompt.is_some(), "empty name closed the prompt");
        assert!(app.stage.contains("only must"), "{}", app.stage);
    }

    /* The vault refuses non-empty deletes; the app refuses even earlier and
       names the way out, so the confirm never opens for a delete that
       cannot happen. */
    #[test]
    fn d_on_a_full_group_refuses_and_names_the_way_out() {
        let mut app = open_app();
        app.step_group(true); // Banks holds an entry
        app.ask_delete_group();
        assert!(app.confirm.is_none(), "a full group opened the confirm");
        assert!(app.stage.contains("not empty"), "{}", app.stage);
    }

    #[test]
    fn d_on_an_empty_group_asks_then_y_deletes() {
        let mut app = open_app();
        app.step_group(true); // Banks
        app.open_group_prompt_new();
        for c in "Empty".chars() {
            app.group_prompt_insert(c);
        }
        app.submit_group_prompt();
        app.ask_delete_group();
        let Confirm::DeleteGroup { id, .. } = app.confirm.clone().unwrap() else {
            panic!("expected a group delete confirm");
        };
        app.confirm = None; // what the handler leaves behind before acting
        app.confirm_delete_group(id);
        let titles: Vec<_> = app
            .group_tree()
            .iter()
            .map(|(id, _)| app.vault.as_ref().unwrap().get_group(id).unwrap().title.clone())
            .collect();
        assert!(!titles.contains(&"Empty".to_string()), "{titles:?}");
    }

    /* X on an entry arms the shelf; V moves it into the selected group. The
       full trip ends with the row living under Root and the shelf empty. */
    #[test]
    fn x_cuts_an_entry_and_v_moves_it() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.switch_pane(); // X follows the pane: entries pane cuts the row
        app.cut_selected();
        assert!(matches!(app.cut, Some(Cut::Entry(_))));
        app.step_group(false); // back to Root as the paste target
        app.paste_cut();
        assert!(app.cut.is_none(), "paste left the shelf armed");
        let root = app.root_id();
        let rows = app.vault.as_ref().unwrap().entries_in(&root);
        assert_eq!(rows.len(), 1, "the entry did not move to Root");
    }

    /* A group cut pastes under the selected group; moving Banks under Work
       leaves it out of the root's child list. */
    #[test]
    fn x_cuts_a_group_and_v_moves_it_under_another() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_group(&root, "Work").unwrap();
        vault.create_entry(&banks, "checking", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.step_group(true); // onto Banks
        app.cut_selected();
        app.step_group(true); // onto Work
        app.paste_cut();
        assert!(app.cut.is_none(), "paste left the shelf armed");
        /* The cursor lands on the moved group, so Work is found by name. */
        let work = app
            .group_tree()
            .iter()
            .map(|(id, _)| *id)
            .find(|id| app.vault.as_ref().unwrap().get_group(id).unwrap().title == "Work")
            .unwrap();
        let under_work = app.vault.as_ref().unwrap().groups_in(&work);
        assert_eq!(under_work.len(), 1, "Banks did not land under Work");
        assert_eq!(under_work[0].title, "Banks");
    }

    /* The cycle guard: pasting a group under itself would vanish it from
       every path, so the vault refuses and the shelf stays armed. The flash
       queue holds the message behind the cut notice, so the assertions read
       state, not the stage text. */
    #[test]
    fn pasting_a_group_under_itself_names_the_cycle() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.cut_selected();
        app.paste_cut(); // target is still Banks
        assert!(app.cut.is_some(), "a failed paste disarmed the shelf");
        let banks = app.group_cursor.unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().parent_group(&banks),
            Some(app.root_id()),
            "Banks moved despite the cycle guard"
        );
    }

    /* Esc unwinds the shelf before its usual report, so a mis-cut is one
       press from undone. The return value carries the answer; the flash
       queue holds the wording behind the cut notice. */
    #[test]
    fn esc_drops_an_armed_cut_before_its_usual_report() {
        let mut app = open_app();
        app.step_group(true);
        app.cut_selected();
        assert!(app.drop_cut(), "an armed cut should be dropped");
        assert!(app.cut.is_none());
        assert!(!app.drop_cut(), "an empty shelf is not a drop");
    }

    /* Three entries whose stored order is neither alphabetical nor by time:
       sorting views have to visibly rearrange them, and cycling back to
       Stored has to restore the file's own order exactly. */
    fn sorted_app() -> App {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "zebra", "u", "p", "", "").unwrap();
        vault.create_entry(&banks, "apple", "u", "p", "", "").unwrap();
        vault.create_entry(&banks, "mango", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.step_group(true); // onto Banks
        app
    }

    fn titles(app: &mut App) -> Vec<String> {
        app.entry_rows()
            .iter()
            .map(|id| {
                app.vault
                    .as_ref()
                    .unwrap()
                    .get_entry(id)
                    .unwrap()
                    .title
                    .clone()
            })
            .collect()
    }

    #[test]
    fn o_cycles_the_orders_and_back_to_stored() {
        let mut app = sorted_app();
        assert_eq!(titles(&mut app), ["zebra", "apple", "mango"]);
        app.cycle_order(); // Name
        assert_eq!(titles(&mut app), ["apple", "mango", "zebra"]);
        app.cycle_order(); // Recent (equal timestamps keep stored order)
        app.cycle_order(); // Updated
        app.cycle_order(); // back to Stored
        assert_eq!(titles(&mut app), ["zebra", "apple", "mango"]);
        /* Stage text queues behind the first flash, so assert the state. */
        assert_eq!(app.order, SortOrder::Stored, "o did not wrap");
    }

    #[test]
    fn updated_order_puts_the_newest_first() {
        let mut app = sorted_app();
        /* Stamp the middle entry newest directly: the editor is the only
           mutator in prod, and a test should not depend on clock ticks. */
        let id = app.entry_rows()[1];
        let vault = app.vault.as_mut().unwrap();
        vault.db_mut().get_entry_mut(&id).unwrap().last_modification_time =
            keepass_rs::DateInstant::EpochMillis(9_000_000_000_000);
        app.cycle_order(); // Name first — cycle once more for Updated.
        app.cycle_order();
        app.cycle_order();
        assert_eq!(titles(&mut app)[0], "apple", "the newest entry leads");
    }

    /* A collapsed group hides its subtree but keeps its own row, so the
       cursor on it stays put and Right re-opens it. */
    #[test]
    fn left_folds_a_group_and_right_reopens_it() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        let banks = app.group_cursor.unwrap();
        /* Banks needs a subtree to fold: a leaf correctly refuses. */
        app.vault.as_mut().unwrap().create_group(&banks, "Work").unwrap();
        app.collapse_group();
        let tree = app.group_tree();
        /* A folded group keeps its own row: only its subtree hides. */
        assert_eq!(
            tree,
            vec![(app.root_id(), 0), (banks, 1)],
            "Work hid but Banks stayed"
        );
        assert_eq!(app.group_cursor, Some(banks), "the row itself stays");
        app.expand_group();
        assert!(app.group_tree().len() > 1, "Right re-opened the tree");
    }

    /* Snap must fall back from a group a fold just hid: a cursor pointing at
       an invisible row is a selection nobody can see. */
    #[test]
    fn snapping_never_rests_on_a_hidden_group() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let outer = vault.create_group(&root, "Outer").unwrap();
        let inner = vault.create_group(&outer, "Inner").unwrap();
        vault.create_entry(&inner, "deep", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.step_group(true); // Outer
        app.step_group(true); // Inner
        app.step_group(false); // back onto Outer — the fold target
        app.collapse_group(); // folds Outer with Inner inside
        app.snap();
        assert_ne!(app.group_cursor, Some(inner), "cursor fell out of the fold");
        assert!(
            app.group_tree().iter().all(|(id, _)| *id != inner),
            "Inner is not a row anyone can see"
        );
    }

    /* A leaf has nothing to fold, and a fold repeated twice is a no-op: both
       report instead of reading as dead keys. */
    #[test]
    fn folding_a_leaf_or_twice_says_so() {
        let mut app = open_app();
        app.collapse_group(); // root has children — folds
        assert_eq!(app.group_tree().len(), 1, "the tree folded to the root");
        app.collapse_group(); // already folded now
        assert!(app.stage.contains("already folded"), "{}", app.stage);
    }

    /* A live needle widens the entries pane to the whole vault: a hit in a
       folder the cursor is not in still shows, and acts on. */
    #[test]
    fn a_needle_searches_the_whole_vault() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "checking", "octo", "p", "", "").unwrap();
        let work = vault.create_group(&root, "Work").unwrap();
        vault.create_entry(&work, "github token", "robot", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.open_search();
        for ch in "github".chars() {
            app.search_insert(ch);
        }
        let rows = app.entry_rows();
        assert_eq!(rows.len(), 1, "{rows:?}");
        let hit = rows[0];
        assert_eq!(
            app.vault.as_ref().unwrap().get_entry(&hit).unwrap().title,
            "github token"
        );
        /* The relaxed selection rule: a global hit from another folder is
           actable — the user searched for it. */
        assert!(app.selected_entry().is_some());
    }

    /* An empty state must name the way out: the pane going blank under a
       bad needle is a filter, not an empty vault. */
    #[test]
    fn an_empty_search_state_is_a_filter_message() {
        let mut app = open_app();
        app.step_group(true); // root holds no entries; Banks does
        app.open_search();
        for ch in "zzz".chars() {
            app.search_insert(ch);
        }
        assert!(app.entry_rows().is_empty());
        /* The draw path renders the words; here we pin the predicate that
           drives them: needle live, rows gone, band still open. */
        assert!(app.search.is_some());
        assert!(app.clear_search());
        assert!(!app.entry_rows().is_empty(), "esc restored the rows");
    }

    /* n/N walk the matches with no wrap: the ends say so. Relevance order
       can tie, so the walk is asserted relative to the rows list, not to a
       guessed starting row. */
    #[test]
    fn n_and_n_walk_matches_without_wrapping() {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "one mail", "u", "p", "", "").unwrap();
        vault.create_entry(&banks, "two mail", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app.step_group(true);
        app.open_search();
        for ch in "mail".chars() {
            app.search_insert(ch);
        }
        assert_eq!(app.entry_rows().len(), 2, "both entries match 'mail'");
        let start = app.entry_cursor.unwrap();
        app.jump_match(true); // n to the other match
        let rows = app.entry_rows();
        let at = rows.iter().position(|e| *e == start).unwrap_or(0);
        assert_eq!(
            app.entry_cursor,
            Some(rows[(at + 1).min(rows.len() - 1)]),
            "n moved to the neighbouring match"
        );
        let second = app.entry_cursor.unwrap();
        app.jump_match(true); // already last
        assert!(app.stage.contains("last match"), "{}", app.stage);
        app.jump_match(false); // N back
        assert_ne!(app.entry_cursor, Some(second), "N walked back");
        app.jump_match(false); // already first
        /* 'first match' queued behind the still-live 'last match' flash:
           force the expiry the frame loop would perform, then read. */
        app.expire_now();
        assert!(app.stage.contains("first match"), "{}", app.stage);
    }

    /* ^s fills the box and flips the keep-latch: submit writes what was
       generated, not the kept secret. */
    #[test]
    fn ctrl_s_generates_into_the_password_box() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.open_edit_form();
        app.form_generate();
        let (filled, touched) = {
            let form = app.form.as_ref().unwrap();
            (!form.password.is_empty(), form.password_touched)
        };
        assert!(filled, "^s left the box empty");
        assert!(touched, "^s did not arm the write");
    }

    #[test]
    fn u_restores_an_edited_entry_password() {
        let mut app = open_app();
        app.step_group(true);
        app.open_edit_form();
        app.form_generate(); // new secret, touches the latch
        app.submit_form();
        let changed = open_password(&app);
        assert_ne!(changed, "p", "the generated password did not write");
        app.undo_last();
        assert_eq!(open_password(&app), "p", "u did not put the old secret back");
    }

    fn open_password(app: &App) -> String {
        let id = app.entry_cursor.unwrap();
        app.vault.as_ref().unwrap().get_entry(&id).unwrap()
            .password.as_str().to_string()
    }

    /* u brings a deleted entry back, under the group it came from. */
    #[test]
    fn u_restores_a_deleted_entry() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        let id = app.entry_cursor.unwrap();
        app.ask_delete_entry();
        let Some(Confirm::DeleteEntry { id: _, .. }) = app.confirm else {
            panic!("delete did not ask");
        };
        app.confirm = None; // handler-takes-first convention
        app.confirm_delete_entry(id);
        assert!(app.entry_rows().is_empty(), "the entry did not go");
        app.undo_last();
        let rows = app.entry_rows();
        assert_eq!(rows.len(), 1, "u did not restore the entry");
        let vault = app.vault.as_ref().unwrap();
        assert_eq!(
            vault.parent_group_of_entry(&rows[0]),
            Some(app.group_cursor.unwrap()),
            "restored into the wrong group"
        );
    }

    /* u rolls an add back by removing what it created. */
    #[test]
    fn u_removes_an_just_added_entry() {
        let mut app = open_app();
        app.step_group(true);
        app.open_add_form();
        if let Some(form) = app.form.as_mut() {
            form.title = "fresh".into();
        }
        app.submit_form();
        assert!(
            app.entry_rows().iter().any(|id| {
                app.vault.as_ref().unwrap().get_entry(id).unwrap().title == "fresh"
            }),
            "the add did not land"
        );
        app.undo_last();
        let titles: Vec<String> = app
            .entry_rows()
            .iter()
            .map(|id| app.vault.as_ref().unwrap().get_entry(id).unwrap().title.clone())
            .collect();
        assert!(!titles.contains(&"fresh".to_string()), "u did not remove the add");
    }

    #[test]
    fn u_restores_a_group_rename() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        let banks = app.group_cursor.unwrap();
        app.open_group_prompt_rename();
        if let Some(prompt) = app.group_prompt.as_mut() {
            prompt.value = "Savings".into();
            prompt.caret = 7;
        }
        app.submit_group_prompt();
        assert_eq!(app.vault.as_ref().unwrap().get_group(&banks).unwrap().title, "Savings");
        app.undo_last();
        assert_eq!(
            app.vault.as_ref().unwrap().get_group(&banks).unwrap().title,
            "Banks",
            "u did not put the old name back"
        );
    }

    /* One slot: once spent, an older change has no undo and the key says so. */
    #[test]
    fn the_second_u_says_actually_nothing_to_undo() {
        let mut app = open_app();
        app.step_group(true);
        app.open_edit_form();
        if let Some(form) = app.form.as_mut() {
            form.notes = "touched".into();
        }
        app.submit_form();
        app.undo_last();
        app.expire_now(); // promotes the queued 'undid edit of …' flash
        app.undo_last();
        app.expire_now(); // promotes 'nothing to undo'
        assert!(
            app.stage.contains("nothing to undo"),
            "{}",
            app.stage
        );
    }

    #[test]
    fn u_with_no_history_says_so() {
        let mut app = open_app();
        app.undo_last();
        assert!(app.stage.contains("nothing to undo"), "{}", app.stage);
    }
}
