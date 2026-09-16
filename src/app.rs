use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use keepass::db::{Entry, EntryId, GroupId};
use ratatui::layout::Rect;
use zeroize::Zeroize;

use crate::clipboard::Board;
use crate::vault::{EntryExt, Vault, VaultError};

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
    /* `forever` is the difference between moving a row to the bin and
       destroying it, which are different questions: the popup asks the one
       that matches, so a user in the bin is never told `u` will save them
       from something it cannot. */
    DeleteEntry { id: EntryId, title: String, forever: bool },
    /* Same rule as the entry delete: the title rides along for the prompt
       line only. A group goes to the bin with its whole subtree, so the
       non-empty refusal is gone and `forever` carries the same meaning. */
    DeleteGroup { id: GroupId, title: String, forever: bool },
}

/// Which box of the entry form the keys are typing into.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FormField {
    #[default]
    Title,
    Username,
    Password,
    Url,
    /// The one-time seed: an `otpauth://` url, or the base32 a site prints
    /// beside its QR code.
    Otp,
    Notes,
}

/* Add or edit. The edit carries the entry id so submit writes to the row the
   form was opened from, not to wherever the cursor has drifted since. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormKind {
    Add,
    Edit(EntryId),
}

/* The modal entry editor. Values are plain Strings here: the password leaves
   ProtectedString only while the user is literally looking at it, and the
   form is closed (or the app exits) in every other state. */
/* The form holds plaintext until it is submitted or thrown away, and both
   end in a drop: a generated password and a one-time seed would otherwise be
   freed intact. Notes come too — they are stored protected in the vault, and
   a recovery code is exactly the kind of thing people keep there. */
impl Drop for Form {
    fn drop(&mut self) {
        self.password.zeroize();
        self.otp.zeroize();
        self.notes.zeroize();
    }
}

impl Form {
    /* One latch per secret box: empty means "keep what is stored" only while
       the box has not been touched, so backspacing one empty clears it and
       never looking at it keeps it. */
    fn touch_secret(&mut self) {
        match self.field {
            FormField::Password => self.password_touched = true,
            FormField::Otp => self.otp_touched = true,
            _ => {}
        }
    }
}

pub struct Form {
    pub kind: FormKind,
    pub field: FormField,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    /// Typed one-time seed. Empty and untouched keeps whatever the entry
    /// already has, the same latch the password box uses.
    pub otp: String,
    pub notes: String,
    /// Char index into the focused box, same rule as the unlock caret.
    pub caret: usize,
    /* Empty means keep — but only while untouched. A user who opened edit,
       typed over the password, then backspaced it empty meant to clear it,
       not to keep: so one keystroke in the box flips this latch, and submit
       reads it rather than guessing from emptiness. */
    pub password_touched: bool,
    pub otp_touched: bool,
    /// Whether this entry already carries a code, so the box can say that
    /// leaving it empty keeps it rather than that there is nothing there.
    pub had_otp: bool,
    /* Whether the password box shows what it holds. Off by default and per
       form: `^s` generates into a masked box, and a secret you cannot read is
       one you cannot check before saving. */
    pub reveal: bool,
}

/* The one-box prompt behind `A` (new group) and `E` (rename group). One box,
   so unlike the entry form there is no field cycling — just a value, a caret
   and the same char-index rule as every other box. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupPromptKind {
    New,
    Rename(GroupId),
}

pub struct GroupPrompt {
    pub kind: GroupPromptKind,
    pub value: String,
    /// Char index into `value`, same rule as the unlock caret.
    pub caret: usize,
}

/* The `F` screen: everything on an entry the five fixed rows cannot show.
   Rows are recomputed from the vault on every open and after every change —
   the list is short, and a cached copy of a custom field is a cached copy of
   a secret. */
pub struct Fields {
    pub entry: EntryId,
    pub rows: Vec<crate::vault::Extra>,
    pub cursor: usize,
    /// `*`, the same rule as the password: masked until asked for.
    pub reveal: bool,
    /// The add prompt, when it is open: name then value.
    pub adding: Option<AddField>,
}

/// Adding a custom field, or attaching a file.
#[derive(Default)]
pub struct AddField {
    pub name: String,
    pub value: String,
    /// True once the name is in and the keys have moved to the value.
    pub on_value: bool,
    pub caret: usize,
    /* A file rather than a string: the value box is then a path to read, and
       what lands in the vault is its bytes. */
    pub from_file: bool,
}

impl Drop for AddField {
    fn drop(&mut self) {
        // A custom field is usually a secret; the box that held it is wiped.
        self.value.zeroize();
    }
}

/* The `H` screen: old versions of an entry, which only ever arrive from
   another client. Held rather than recomputed because it carries passwords,
   and rebuilding it per frame would mean rebuilding those per frame. */
pub struct History {
    pub entry: EntryId,
    pub rows: Vec<crate::vault::Version>,
    pub cursor: usize,
    pub reveal: bool,
}

/* What `!` found, held rather than recomputed: the walk touches every entry
   and every password in the vault, which is fine once and wrong per frame. */
pub struct Audit {
    pub rows: Vec<(EntryId, crate::vault::Issue)>,
    pub cursor: usize,
}

/// Which box of the change-password prompt the keys are typing into.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RekeyField {
    #[default]
    New,
    Again,
}

/* Changing the master password: the new one, typed twice. Both boxes mask,
   and both are zeroized on drop like every other typed secret — this prompt
   holds the only plaintext copy of what is about to become the key to
   everything. */
#[derive(Default)]
pub struct Rekey {
    pub password: String,
    pub confirm: String,
    pub field: RekeyField,
    /// Char index into whichever box has the keys, same rule as the unlock caret.
    pub caret: usize,
    /// `^r`, for reading back what was typed before committing to it.
    pub reveal: bool,
}

impl Drop for Rekey {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
    }
}

/* Something sitting on the shelf between `X` and `V`. The id travels alone:
   the title is looked up fresh wherever it is shown, so a rename between the
   cut and the paste still reads right, and a deleted source disarms itself
   rather than pasting a ghost. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cut {
    Entry(EntryId),
    Group(GroupId),
}

/* One step of work, undone. The snapshot carries the whole entry — secrets
   included, zeroized on drop like every other copy — because a field-by-field
   restore would miss the timestamps the form never touches. */
pub enum Undo {
    /// Before-state of an edited entry; restore swaps it wholesale.
    Edit { id: EntryId, before: Entry },
    /// An entry destroyed inside the bin, which only a snapshot brings back.
    Delete {
        id: EntryId,
        parent: GroupId,
        before: Entry,
    },
    /* An entry moved to the bin. It still exists, so undo is a move home and
       the snapshot rides along only to name it in the status bar. */
    Recycle {
        id: EntryId,
        parent: GroupId,
        before: Entry,
    },
    /// A group moved to the bin, with everything under it.
    RecycleGroup { id: GroupId, parent: GroupId, title: String },
    /// An added entry that `u` removes again.
    AddEntry { id: EntryId, title: String },
    /// A group rename that `u` turns back.
    Rename { id: GroupId, before: String },
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

    /// The config file's name for it, and back. One spelling in `config.toml`
    /// and in the flash would be nicer, but "by name" is prose, not a key.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "stored" => Some(SortOrder::Stored),
            "name" => Some(SortOrder::Name),
            "recent" => Some(SortOrder::Recent),
            "updated" => Some(SortOrder::Updated),
            _ => None,
        }
    }

    /// One word for the pane header, where "by name" would read as part of
    /// the breadcrumb beside it.
    pub fn short(self) -> &'static str {
        match self {
            SortOrder::Stored => "stored",
            SortOrder::Name => "name",
            SortOrder::Recent => "recent",
            SortOrder::Updated => "updated",
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

/// How a flash reads at a glance. Every message rendered the same cream, so
/// "save failed" and "unlocked 42 entries" were one colour apart from each
/// other: none.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Level {
    #[default]
    Info,
    Warn,
    Error,
}

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

/// Where the picker starts when nothing else says: `$HOME`, or the working
/// directory on a machine that has no home to speak of.
fn home() -> PathBuf {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// The vault's file name — the whole path would push the header off the row,
/// and the directory is not what tells two vaults apart.
fn vault_name(path: &std::path::Path) -> String {
    path.file_name()
        .map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

/// One row of the file picker: a directory to step into, or a vault to open.
pub struct Listing {
    pub name: String,
    pub dir: bool,
}

/* The file picker behind `^o` on the unlock screen. Typing a path is fine
   when you know it; nobody knows the path to a vault they have not opened
   yet, and `~/Library/Mobile Documents/com~apple~CloudDocs/…` is not a thing
   to type twice. */
pub struct Browse {
    pub dir: PathBuf,
    pub rows: Vec<Listing>,
    pub cursor: usize,
    /// Typed narrowing, as a plain substring: the list is a directory, not a
    /// vault, so fuzzy ranking would be more machinery than it is worth.
    pub filter: String,
    /// What went wrong reading this directory, if anything did.
    pub problem: Option<String>,
}

impl Browse {
    /// Rows after the filter, which is what the popup draws and what the
    /// cursor indexes into.
    pub fn shown(&self) -> Vec<&Listing> {
        let needle = self.filter.to_lowercase();
        self.rows
            .iter()
            .filter(|row| needle.is_empty() || row.name.to_lowercase().contains(&needle))
            .collect()
    }
}

/// Everything `entry_rows` reads. Two equal keys must mean two equal answers,
/// so anything that reorders or refilters the pane belongs in here.
#[derive(PartialEq, Eq)]
struct RowsKey {
    revision: u64,
    needle: Option<String>,
    global: bool,
    order: SortOrder,
    group: Option<GroupId>,
}

pub struct App {
    pub tick: usize,
    pub view: View,
    pub show_help: bool,
    /* The colours this session draws in. A value on `App`, not a global: a
       theme that can be switched at runtime cannot live in a OnceLock, and a
       mutable global would make the per-theme tests race each other. */
    pub theme: crate::theme::Palette,
    /* Whether a `[colors]` table is repainting the theme. `^t` has to say so:
       it walks the built-ins, but the overrides stay in the file, so the
       palette it writes down is not the one the next launch draws. */
    pub theme_overridden: bool,
    pub stage: String,
    /// What the header goes back to once a flash expires.
    resting: String,
    /// What the flash on screen is: colour, not text, so a failure reads as
    /// one before it is read.
    pub level: Level,
    flash_until: Option<Instant>,
    /// Messages that arrived while one was still being read.
    waiting: VecDeque<(String, Level)>,
    /// A question the UI raised itself, waiting on y or n.
    pub confirm: Option<Confirm>,
    pub quit: bool,
    /* Selection state. Cursors hold ids, never row positions: rows shift
       under every mutation and under the Wave 5/6 sort and filter views, while
       an id still names the same group or entry. */
    /// The open vault. None while locked; `try_unlock` opens real KDBX here.
    pub vault: Option<Vault>,
    /// Selected group. Always valid once a vault is open (`snap` keeps it so).
    pub group_cursor: Option<GroupId>,
    /// Selected entry within the cursor group. None when the group is empty.
    pub entry_cursor: Option<EntryId>,
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
    /* Enter's detail popup: the side pane wants 100 columns, and a terminal
       opens with 80. */
    pub detail: bool,
    /// Whether the last frame had room for the side pane, set by the draw
    /// that knows (as `viewport` is): `*` must refuse where nothing shows.
    pub wide: bool,
    /// Whether that frame had room for the pane headers, which own the
    /// breadcrumb and the match count when they are drawn.
    pub heads: bool,
    /* Where the lists were last drawn, so a click can be turned into a row.
       Only the draw knows this, the same deal as `viewport`. */
    pub group_area: Rect,
    pub entry_area: Rect,
    /* Entries-pane ordering, cycled by `o`. A view over the stored vec, not
       a re-ordering of it (see SortOrder above). */
    pub order: SortOrder,
    /// Length and character classes for `^s`, from the config.
    generator: crate::config::Generator,
    /* Unlock state. The path comes from the config once at startup;
       `unlock_new` caches whether it names a missing file so the draw loop
       never stats. */
    pub db_path: Option<PathBuf>,
    /// True when the configured file is missing: Enter creates, with a confirm.
    pub unlock_new: bool,
    /* Enter has been pressed and the key derivation has not started yet. KDBX4
       unlocks run Argon2 on this thread, which freezes the frame for a second
       or more; the loop draws once with this set so the screen says what is
       happening rather than appearing to have died. */
    pub unlocking: bool,
    pub unlock_field: UnlockField,
    pub unlock_password: String,
    pub unlock_keyfile: String,
    pub unlock_confirm: String,
    /// The typed vault-file path. Prefilled from the config once; edits here
    /// stay across auto-locks, so switching vaults is a Tab away.
    pub unlock_file: String,
    /// The file picker, while it is open. `^o` on the unlock screen.
    pub browse: Option<Browse>,
    /* Where a chosen vault is remembered, and what is already written there.
       Both `None` under --no-config, which asked for the file to be left out
       of the run and so cannot be where a choice is kept. */
    pub config_file: Option<PathBuf>,
    pub configured_db: Option<PathBuf>,
    /// Where typing lands, as a char index into the focused box (see below).
    pub caret: usize,
    /// Plain-text password on the unlock screen. `^r` flips it, the way the
    /// browser's `*` flips the detail pane; a fresh unlock starts hidden.
    pub unlock_reveal: bool,
    /// Unsaved changes. Set by every vault mutation; quitting while set asks.
    dirty: bool,
    /* Bumped by `persist`, which every mutation calls. The row cache keys on
       it, so a cache can never outlive the vault it described. */
    revision: u64,
    /* The last answer `entry_rows` gave, and what it was an answer to.
       Ranking the whole vault took 45ms on five thousand entries and ran two
       or three times a frame, so typing in the search band redrew at about
       twelve frames a second. */
    rows_cache: Option<(RowsKey, Vec<EntryId>)>,
    /// A save was refused because the file changed underneath. The next `^s`
    /// means "overwrite theirs", which is a thing to do on purpose or not at
    /// all.
    overwrite_armed: bool,
    /* The modal entry editor. None when closed; the browser hands its keys
       over while Some, the way the unlock screen does. */
    pub form: Option<Form>,
    /* The one-box group prompt (A/E). None when closed; same handover rule
       as the entry form. */
    pub group_prompt: Option<GroupPrompt>,
    /// The change-master-password prompt, when it is open.
    pub rekey: Option<Rekey>,
    /// The password audit, when it is open. Computed once on open: it walks
    /// every entry, which is not a thing to do per frame.
    pub audit: Option<Audit>,
    /// The custom-fields and attachments screen, when it is open.
    pub fields: Option<Fields>,
    /// Old versions of an entry, when that screen is open.
    pub history: Option<History>,
    /* Armed cut waiting for V. None when the shelf is empty; Esc unwinds it
       before its usual report so a mis-cut is one press from undone. */
    pub cut: Option<Cut>,
    /* A stack, newest last, pushed by every mutation and popped by `u`.
       Bounded, because each Delete carries a whole entry and an unbounded
       stack is an unbounded pile of plaintext passwords in memory — the
       snapshots zeroize on drop, so dropping the oldest is also the thing
       that wipes it. */
    pub undo: Vec<Undo>,
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
    /* Whether a live needle searches the whole vault or only the group the
       cursor is in. Whole-vault is right most of the time — it is why people
       search — but it happens silently, and `^g` makes it a choice. */
    pub search_global: bool,
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
            theme: crate::theme::WARM,
            theme_overridden: false,
            stage: "locked".into(),
            resting: "locked".into(),
            level: Level::default(),
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
            detail: false,
            wide: false,
            heads: false,
            group_area: Rect::ZERO,
            entry_area: Rect::ZERO,
            order: SortOrder::default(),
            generator: crate::config::Generator::default(),
            db_path: None,
            unlock_new: false,
            unlocking: false,
            unlock_field: UnlockField::Password,
            unlock_password: String::new(),
            unlock_keyfile: String::new(),
            unlock_file: String::new(),
            browse: None,
            config_file: None,
            configured_db: None,
            board: None,
            unlock_confirm: String::new(),
            caret: 0,
            unlock_reveal: false,
            dirty: false,
            revision: 0,
            rows_cache: None,
            overwrite_armed: false,
            form: None,
            group_prompt: None,
            rekey: None,
            audit: None,
            fields: None,
            history: None,
            cut: None,
            undo: Vec::new(),
            search: None,
            band: false,
            search_global: true,
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
        self.flash(text, Level::Info);
    }

    /// Something to look at but not a failure: a refusal, a mismatch, a
    /// secret now on screen.
    pub fn warn(&mut self, text: impl Into<String>) {
        self.flash(text, Level::Warn);
    }

    /// Something did not work. Red, because a save that failed must not look
    /// like a save that worked.
    pub fn error(&mut self, text: impl Into<String>) {
        self.flash(text, Level::Error);
    }

    fn flash(&mut self, text: impl Into<String>, level: Level) {
        let text = text.into();
        /* A second message used to overwrite the first, so two quick copies
           arrived and left inside one blink and only the last was ever
           readable. */
        if self.flash_until.is_some() {
            /* Except a failure, which takes the header now: a save that was
               refused must not wait behind "copied username" for six
               seconds, and by then the user has pressed three more keys. */
            if level == Level::Error {
                self.show_flash(text, level);
                return;
            }
            // Pressing the same key twice should not queue the same sentence.
            if self.waiting.iter().any(|(queued, _)| queued == &text) {
                return;
            }
            if self.waiting.len() < QUEUE {
                self.waiting.push_back((text, level));
            }
            return;
        }
        self.show_flash(text, level);
    }

    fn show_flash(&mut self, text: String, level: Level) {
        let reading = PER_CHAR * text.chars().count() as u32;
        self.flash_until = Some(Instant::now() + (FLASH + reading).min(FLASH_MAX));
        self.stage = text;
        self.level = level;
    }

    /// Called every frame: a flash has to expire on its own, since the thing
    /// that set it has already finished and will not send anything else.
    pub fn expire_flash(&mut self) {
        if !self.flash_until.is_some_and(|at| Instant::now() >= at) {
            return;
        }
        self.flash_until = None;
        match self.waiting.pop_front() {
            Some((next, level)) => self.show_flash(next, level),
            None => {
                self.stage = self.resting.clone();
                self.level = Level::Info;
            }
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
        /* Nowhere to show it is a refusal, not a flip: the flash would
           otherwise announce a reveal the screen has no room for. */
        if !self.wide && !self.detail {
            self.warn("no detail pane this narrow  ·  enter opens the entry");
            return;
        }
        self.show_password = !self.show_password;
        if self.show_password {
            self.warn("password shown  ·  * hides it");
        }
    }

    /* Enter on the browser. On the groups pane it opens the group — unfold it
       and hand the keys to its entries; on an entry it opens the detail
       popup, which is the only detail there is below 100 columns. */
    pub fn open_selection(&mut self) {
        match self.active_pane {
            Pane::Groups => {
                if self.group_cursor.is_none() {
                    self.say("no group here to open");
                    return;
                }
                self.expand_group();
                self.active_pane = Pane::Entries;
                self.snap();
                if self.entry_cursor.is_none() {
                    self.say("no entries in this group  ·  a adds one");
                }
            }
            Pane::Entries => self.open_detail(),
        }
    }

    /* Walking entries with the popup open. The reveal drops on the way, the
       same rule as closing it: a password shown for one entry is not consent
       for the next. */
    pub fn step_detail(&mut self, down: bool) {
        self.active_pane = Pane::Entries;
        self.show_password = false;
        self.step_entry(down);
        if self.selected_entry().is_none() {
            self.close_detail();
            self.say("no entry here");
        }
    }

    pub fn open_detail(&mut self) {
        if self.selected_entry().is_none() {
            self.say("no entry here to open");
            return;
        }
        self.detail = true;
    }

    /// Closing re-masks: a reveal is for the view you are in, never a state
    /// left armed behind a popup that is gone.
    pub fn close_detail(&mut self) {
        self.detail = false;
        self.show_password = false;
    }

    /* Flip the lock screen between bullets and the typed master password.
       Same contract as the detail pane's `*`, on `^r` because a printable
       key would steal characters from real passwords. The flip says so out
       loud, so a reveal never happens silently on the one screen that guards
       everything. Hiding deliberately says nothing — the bullets going back
       are visible proof enough. */
    pub fn toggle_unlock_reveal(&mut self) {
        self.unlock_reveal = !self.unlock_reveal;
        if self.unlock_reveal {
            self.warn("password shown  ·  ^r hides it");
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
        self.copy_field("username", |e| e.username().to_string());
    }

    pub fn copy_password(&mut self) {
        self.copy_field("password", |e| e.password().to_string());
    }

    /* `t`: the one-time code, not the secret behind it. Copying the seed
       would put a permanent credential on the clipboard to save typing six
       digits. */
    pub fn copy_totp(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.say("no entry here to copy from");
            return;
        };
        let Some((code, left)) = crate::vault::totp_now(&entry) else {
            self.say("no one-time code on this entry");
            return;
        };
        let Some(board) = &self.board else {
            self.say("clipboard is not ready  ·  report this as a bug");
            return;
        };
        match board.copy(&code) {
            Ok(()) => self.say(format!("copied the code  ·  good for {left}s")),
            Err(e) => self.error(e),
        }
    }

    pub fn copy_url(&mut self) {
        self.copy_field("url", |e| e.url().to_string());
    }

    /* EntryRef derefs to Entry, so the take closure reads both the ref the
       selection hands over and the record type the crate stores. */
    /* A value that is already in hand rather than read off the cursor's
       entry: the fields screen has its own selection, and a custom field is
       as much a secret as a password, so it goes through the same board and
       the same auto-clear. */
    pub fn copy_named(&mut self, label: &str, text: &str) {
        if text.is_empty() {
            self.say(format!("{label} is empty"));
            return;
        }
        let Some(board) = &self.board else {
            self.say("clipboard is not ready  ·  report this as a bug");
            return;
        };
        match board.copy(text) {
            Ok(()) => match board.timeout_secs() {
                Some(secs) => self.say(format!("copied {label}  ·  clears in {secs}s")),
                None => self.say(format!("copied {label}")),
            },
            Err(e) => self.error(e),
        }
    }

    fn copy_field(&mut self, label: &str, take: impl FnOnce(&keepass::db::Entry) -> String) {
        let Some(entry) = self.selected_entry() else {
            self.say("no entry here to copy from");
            return;
        };
        let text = take(&entry);
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
        self.lock();
        self.warn(format!("locked after {secs} seconds idle"));
    }

    /* `^l`: the same wipe on purpose rather than on a timer. Locking used to
       mean quitting, which is a strange thing to have to do to step away. */
    pub fn lock_now(&mut self) {
        if self.vault.is_none() {
            self.say("already locked");
            return;
        }
        self.lock();
        self.say("locked  ·  password to return");
    }

    /* Drop the vault and go back behind the password prompt. Dropping is the
       wipe: secrets live in `ProtectedString` and the retained key, both of
       which zeroize on drop, so nothing may be copied out first. */
    fn lock(&mut self) {
        self.vault = None;
        self.group_cursor = None;
        self.entry_cursor = None;
        /* Zeroized, not cleared: `String::clear` sets the length to zero and
           leaves the bytes in the allocation, and this is the path whose
           whole job is getting the typed password out of memory. */
        self.unlock_password.zeroize();
        self.unlock_keyfile.zeroize();
        self.unlock_confirm.zeroize();
        self.unlock_reveal = false;
        self.caret = 0;
        self.dirty = false;
        self.overwrite_armed = false;
        /* Nothing that was about the open vault may outlive it: a form, a
           kept filter or an armed cut would come back over the next one. */
        self.detail = false;
        self.show_password = false;
        self.form = None;
        self.group_prompt = None;
        /* Dropping it zeroizes both boxes: a half-typed master password must
           not survive the lock that was supposed to clear the screen. */
        self.rekey = None;
        self.audit = None;
        /* Holds field values, which are secrets as often as not, and the
           add prompt's own box. Dropping it wipes them. */
        self.fields = None;
        // Holds old passwords, which is the whole reason it is worth showing.
        self.history = None;
        self.confirm = None;
        self.cut = None;
        /* Dropping the snapshots zeroizes them: an undo stack that outlived a
           lock would be a pile of plaintext passwords behind a locked screen. */
        self.undo.clear();
        self.search = None;
        self.band = false;
        self.view = View::Unlock;
        self.resting = "locked".into();
        self.refresh_db_state();
    }

    /// Wipe the clipboard if what is on it is still ours. Called on the way
    /// out, where the auto-clear thread cannot help.
    pub fn clear_clipboard(&self) {
        if let Some(board) = &self.board {
            board.clear_now();
        }
    }

    /// Seconds until the clipboard wipes what was copied, for the status bar.
    pub fn clipboard_left(&self) -> Option<u64> {
        self.board.as_ref().and_then(Board::clears_in)
    }

    /// The open vault's file name, or empty while locked. The header's
    /// right-hand end, so identity survives a flash.
    pub fn vault_name(&self) -> String {
        match (&self.vault, &self.db_path) {
            (Some(_), Some(path)) => vault_name(path),
            _ => String::new(),
        }
    }

    /* Writes the opened vault into the config as `db`, unless it is already
       there or this session has no config file (--no-config). Says so out
       loud: a tool that edits your dotfiles without a word is a tool you stop
       trusting with your dotfiles. */
    fn remember_vault(&mut self, path: &Path) {
        if self.configured_db.as_deref() == Some(path) {
            return;
        }
        let Some(file) = self.config_file.clone() else {
            return;
        };
        match crate::config::remember_db(Some(&file), path) {
            Ok(()) => {
                self.configured_db = Some(path.to_path_buf());
                self.say(format!(
                    "remembered {}  ·  next launch opens it",
                    vault_name(path)
                ));
            }
            /* Not fatal: the vault is open, and the only thing lost is the
               convenience. Worth naming, since the next launch will not do
               what the user just asked for. */
            Err(e) => self.warn(format!("cannot save your choice  ·  {e}")),
        }
    }

    /// What the terminal window is called. The vault while one is open, so a
    /// tab strip of terminals says which is which.
    pub fn window_title(&self) -> String {
        match (&self.vault, &self.db_path) {
            (Some(_), Some(path)) => format!("Sennel — {}", vault_name(path)),
            _ => "Sennel".to_string(),
        }
    }

    /* `^t`: walk the shipped palettes with the screen in front of you, which
       is the only way anyone picks a theme. The choice is written back the
       way an opened vault is, so the next launch keeps it. */
    pub fn cycle_theme(&mut self) {
        self.theme = self.theme.next();
        let name = self.theme.name();
        /* The walk only moves the base palette; a `[colors]` table in the
           file is applied on top of whatever is named, and outlives this. So
           the screen now and the screen next launch are different, and the
           only honest thing is to say which key is still doing it. */
        let kept = if self.theme_overridden {
            "  ·  [colors] still repaints it"
        } else {
            ""
        };
        match self.config_file.clone() {
            Some(file) => match crate::config::remember_theme(Some(&file), name) {
                Ok(()) => self.say(format!("theme: {name}  ·  remembered{kept}")),
                /* Not fatal: the theme applied, and only the remembering
                   failed — but the next launch will not do what was asked. */
                Err(e) => self.warn(format!("theme: {name}  ·  cannot save your choice · {e}")),
            },
            // --no-config asked for the file to be left out of the run.
            None => self.say(format!("theme: {name}{kept}")),
        }
    }

    /// What `^s` makes, from the config.
    pub fn set_generator(&mut self, settings: crate::config::Generator) {
        self.generator = settings;
    }

    /// The order the entries pane opens in, from the config. `o` still cycles
    /// from here: the file says where the session starts, not where it stays.
    pub fn set_order(&mut self, order: SortOrder) {
        self.order = order;
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
        /* No path from the config or --db: the first thing to fill is the file
           box, not the password. Default focus is Password (right when a vault
           is already named); with nothing configured, land on File so a typed
           path goes where it belongs instead of into the password box. */
        if self.db_path.is_none() {
            self.unlock_field = UnlockField::File;
        }
    }

    /* Whether Enter will create rather than open. Cached on keypresses, not
       read per frame: the draw loop must not stat, and the answer only
       changes when the file does. */
    pub fn refresh_db_state(&mut self) {
        self.unlock_new = self.db_path.as_ref().is_some_and(|p| !p.is_file());
    }

    /* Unlock with the typed password (and optional key file), or create the
       database when the file is missing and the confirm matches. The password
       buffer is zeroized on every path out; the retained DatabaseKey inside
       the vault is the only copy that survives, and it zeroizes on drop. */
    /* Enter on the lock screen: say so, then let the loop draw before the
       derivation starts. A second of frozen screen with the old stage on it
       reads as a hang. */
    pub fn begin_unlock(&mut self) {
        self.unlocking = true;
        self.stage = "unlocking…".into();
        self.level = Level::Info;
        self.flash_until = None;
        self.waiting.clear();
    }

    pub fn try_unlock(&mut self, password: &mut Vec<u8>, key_file: Option<&[u8]>) {
        self.unlocking = false;
        /* A path typed in the file box but never confirmed with Enter (Tab
           jumped to the password instead) is still the vault the user means:
           apply it here so unlock reads the path off the box it was typed in
           rather than reporting that no vault was configured. */
        if self.db_path.is_none() {
            let typed = self.unlock_file.trim();
            if !typed.is_empty() {
                self.db_path = Some(crate::config::expand(typed));
                self.refresh_db_state();
            }
        }
        let Some(path) = self.db_path.clone() else {
            self.warn("no database configured  ·  run `Sennel --help` for --db");
            password.zeroize();
            return;
        };
        if password.is_empty() {
            self.warn("empty password  ·  type one or ^c quits");
            password.zeroize();
            return;
        }
        /* Borrow, do not copy: a lossy into_owned() would leave an extra
           plaintext master password that nothing zeroizes, and it would
           silently rewrite non-UTF8 bytes into a different (wrong) password.
           keepass 0.13's DatabaseKey speaks &str, so refuse raw-byte
           passwords honestly instead of guessing at them. */
        let Ok(pw) = std::str::from_utf8(password) else {
            self.error("password has bytes that are not text · keepass cannot use it");
            password.zeroize();
            return;
        };
        let result = if self.unlock_new {
            if self.unlock_confirm.as_bytes() != password.as_slice() {
                self.warn("passwords differ  ·  retype both fields");
                self.unlock_confirm.zeroize();
                self.caret = 0;
                password.zeroize();
                return;
            }
            let mut vault = Vault::new();
            vault.save_as(&path, pw, key_file).map(|()| vault)
        } else {
            Vault::open(&path, pw, key_file)
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
                self.unlock_confirm.zeroize();
                /* The next screen opens on bullets again: a reveal is for
                   reading the box you are on, never a browser-side default. */
                self.unlock_reveal = false;
                self.unlock_field = UnlockField::Password;
                self.caret = 0;
                self.unlock_new = false;
                let created = self.unlock_new;
                self.open_vault(vault);
                /* Which vault is open, for the rest of the session: pointing
                   one session at any vault is the app's headline feature, and
                   "ready" made two vaults look identical. */
                self.resting = vault_name(&path);
                if created {
                    // The first screen of an empty vault, which has nothing to show.
                    self.say(format!("created {}  ·  a adds your first entry", vault_name(&path)));
                } else {
                    let plural = if n == 1 { "entry" } else { "entries" };
                    self.say(format!("unlocked {n} {plural}"));
                }
                /* A vault that opened is a vault worth remembering: pointing
                   the session somewhere new used to last exactly as long as
                   the session. Written after the unlock, never before, so a
                   mistyped path cannot become the default. */
                self.remember_vault(&path);
            }
            Err(VaultError::WrongPassword) => {
                self.unlock_reveal = false;
                self.error("wrong password or key file  ·  try again");
            }
            Err(e) => self.error(format!("cannot open {}  ·  {e}", path.display())),
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

    /* `^o`: open the picker on the directory the current path names, or on
       home when there is nothing to go by. */
    pub fn open_browse(&mut self) {
        let start = {
            let typed = crate::config::expand(self.unlock_file.trim());
            if self.unlock_file.trim().is_empty() {
                home()
            } else if typed.is_dir() {
                typed
            } else {
                typed.parent().map_or_else(home, Path::to_path_buf)
            }
        };
        self.browse = Some(Browse {
            dir: start,
            rows: Vec::new(),
            cursor: 0,
            filter: String::new(),
            problem: None,
        });
        self.read_dir();
    }

    pub fn close_browse(&mut self) {
        self.browse = None;
    }

    /* Directories and vaults, nothing else: a picker that lists every file on
       the disk makes the reader do the filtering. Dotfiles stay hidden until
       the filter asks for them, the way a shell hides them. */
    fn read_dir(&mut self) {
        let Some(browse) = &mut self.browse else {
            return;
        };
        let wants_hidden = browse.filter.starts_with('.');
        let mut rows = Vec::new();
        let mut problem = None;
        match std::fs::read_dir(&browse.dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with('.') && !wants_hidden {
                        continue;
                    }
                    let dir = entry.file_type().is_ok_and(|t| t.is_dir());
                    let vault = name.to_lowercase().ends_with(".kdbx");
                    if dir || vault {
                        rows.push(Listing { name, dir });
                    }
                }
            }
            /* Named rather than shown as an empty directory: "permission
               denied" and "there is nothing here" are different answers. */
            Err(e) => problem = Some(e.to_string()),
        }
        rows.sort_by(|a, b| b.dir.cmp(&a.dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        browse.rows = rows;
        browse.cursor = 0;
        browse.problem = problem;
    }

    pub fn browse_step(&mut self, down: bool) {
        let Some(browse) = &mut self.browse else {
            return;
        };
        let len = browse.shown().len();
        if len == 0 {
            browse.cursor = 0;
            return;
        }
        browse.cursor = if down {
            (browse.cursor + 1).min(len - 1)
        } else {
            browse.cursor.saturating_sub(1)
        };
    }

    pub fn browse_end(&mut self, end: bool) {
        let Some(browse) = &mut self.browse else {
            return;
        };
        let len = browse.shown().len();
        browse.cursor = if end { len.saturating_sub(1) } else { 0 };
    }

    /// Up one directory. The filter goes with it: it was about this listing.
    pub fn browse_up(&mut self) {
        let Some(browse) = &mut self.browse else {
            return;
        };
        match browse.dir.parent() {
            Some(parent) => {
                browse.dir = parent.to_path_buf();
                browse.filter.clear();
                self.read_dir();
            }
            None => self.say("this is the root of the disk"),
        }
    }

    pub fn browse_filter(&mut self, c: char) {
        if let Some(browse) = &mut self.browse {
            browse.filter.push(c);
            browse.cursor = 0;
            /* A leading dot asks for the hidden entries, so the listing is
               re-read rather than merely narrowed. */
            if browse.filter == "." {
                self.read_dir();
            }
        }
    }

    pub fn browse_backspace(&mut self) {
        let Some(browse) = &mut self.browse else {
            return;
        };
        let was_hidden = browse.filter.starts_with('.');
        browse.filter.pop();
        browse.cursor = 0;
        if was_hidden && !browse.filter.starts_with('.') {
            self.read_dir();
        }
    }

    /* Enter on the picker: step into a directory, or take a vault and hand
       the keys back to the password box, which is the next thing to fill. */
    pub fn browse_choose(&mut self) {
        let Some(browse) = &self.browse else {
            return;
        };
        let Some(row) = browse.shown().get(browse.cursor).map(|r| (r.name.clone(), r.dir)) else {
            self.say("nothing here to choose");
            return;
        };
        let path = browse.dir.join(&row.0);
        if row.1 {
            if let Some(browse) = &mut self.browse {
                browse.dir = path;
                browse.filter.clear();
            }
            self.read_dir();
            return;
        }
        self.unlock_file = path.display().to_string();
        self.db_path = Some(path);
        self.browse = None;
        self.refresh_db_state();
        self.unlock_field = UnlockField::Password;
        self.caret = 0;
        self.say(format!("vault set  ·  {}", row.0));
    }

    /* Enter on the file box: make the typed path the vault this session
       unlocks. The path is display text, not a secret, and the flash names
       what it was set to so a typo reads as a typo. */
    pub fn accept_file_box(&mut self) {
        /* Not taken literally: `~` means home the way it does in the config
           file, so a typed `~/Downloads/x.kdbx` finds the vault instead of
           opening a file literally named `~` and offering to create one. */
        if self.unlock_file.trim().is_empty() {
            self.say("type a path first");
            return;
        }
        /* `~octo/vault.kdbx` cannot be resolved without the password
           database, and taking it literally would offer to create a folder
           named `~octo`. */
        if crate::config::is_other_home(self.unlock_file.trim()) {
            self.warn("another user's ~ cannot be resolved  ·  type the full path");
            return;
        }
        self.db_path = Some(crate::config::expand(self.unlock_file.trim()));
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
        // The box being cleared is usually the password one.
        self.active_unlock_value().zeroize();
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
        self.entry_cursor = vault.entries_in(&root).first().map(|e| e.id());
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
    pub fn group_tree(&self) -> Vec<(GroupId, usize)> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut stack = vec![(vault.root_id(), 0)];
        while let Some((id, depth)) = stack.pop() {
            out.push((id, depth));
            /* A collapsed group hides its subtree but stays visible itself, so
               the cursor on it keeps a row and Right re-opens it. Groups are
               born expanded (KeePass defaults the flag true), so the tree
               only shrinks after an explicit Left. */
            let collapsed = vault.get_group(&id).is_some_and(|g| !g.is_expanded);
            if !collapsed {
                /* Reversed so the first child pops first and order matches the
                   stored child list. */
                for child in vault.groups_in(&id).iter().rev() {
                    stack.push((child.id(), depth + 1));
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
    /* The pane's rows, memoized. Three callers a frame (the header's count,
       the pane itself, the status bar) each used to re-rank the whole vault,
       and a keystroke in the band redraws — so the answer is kept until
       something it depends on moves. */
    pub fn entry_rows(&mut self) -> Vec<EntryId> {
        let key = self.rows_key();
        if let Some((cached, rows)) = &self.rows_cache
            && *cached == key
        {
            return rows.clone();
        }
        let rows = self.compute_rows();
        self.rows_cache = Some((key, rows.clone()));
        rows
    }

    fn rows_key(&self) -> RowsKey {
        RowsKey {
            revision: self.revision,
            needle: self.search.clone(),
            global: self.search_global,
            order: self.order,
            group: self.group_cursor,
        }
    }

    fn compute_rows(&mut self) -> Vec<EntryId> {
        /* A live needle widens the pane to the whole vault: search is the one
           question whose answer is rarely "the folder I was already in", and
           the count in the status bar already promised the matches existed. */
        let global = self.search_global
            && self
                .search
                .as_deref()
                .is_some_and(|n| !n.is_empty());
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let mut entries: Vec<keepass::db::EntryRef<'_>> = if global {
            let mut all: Vec<keepass::db::EntryRef<'_>> = vault.entry_refs();
            /* The store has no order of its own: a title sort gives the Stored
               view a stable base — and every other order a deterministic
               tiebreak — instead of whatever bucket iteration coughed up this
               frame. */
            all.sort_by_key(|a| a.title().to_lowercase());
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
                a.title().to_lowercase().cmp(&b.title().to_lowercase())
            }),
            SortOrder::Recent => {
                entries.sort_by_key(|e| std::cmp::Reverse(e.times.creation))
            }
            SortOrder::Updated => {
                entries.sort_by_key(|e| std::cmp::Reverse(e.times.last_modification))
            }
        }
        let ids: Vec<EntryId> = entries.iter().map(|e| e.id()).collect();
        if global {
            /* rank_entry, not raw rank: multi-word needles ("git octo")
               become Pattern atoms there, and the band must agree with the
               count in `entry_matches`, which uses the same predicate. */
            let needle = self.search.clone().unwrap_or_default();
            let mut hits: Vec<EntryId> = ids
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
            let mut scored: Vec<(EntryId, u16)> = hits
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
    /// The folder the cursor is in, as a path. What the tree cannot say once
    /// it starts truncating names.
    pub fn here(&self) -> String {
        let (Some(vault), Some(id)) = (&self.vault, self.group_cursor) else {
            return "no group".to_string();
        };
        vault
            .get_group(&id)
            .map(|_| vault.group_path(&id).join("/"))
            .unwrap_or_else(|| "no group".to_string())
    }

    /// How many entries a group holds, for the counts in the tree.
    pub fn entries_in(&self, id: &GroupId) -> usize {
        self.vault.as_ref().map_or(0, |v| v.entries_in(id).len())
    }

    pub fn entry_total(&self) -> usize {
        if !self.search_global {
            return self.group_cursor.map_or(0, |id| self.entries_in(&id));
        }
        self.vault.as_ref().map_or(0, Vault::entry_count)
    }

    /// How many rows the filter leaves visible, across the whole vault. The
    /// entries pane only shows the cursor group, but the count tells the
    /// truth about the filter: the needle still matches rows elsewhere.
    /* &mut self for the same reason as entry_rows: the searcher scores with
       internal scratch state, and the draw path already holds &mut App. */
    /* Counted over whatever the needle is searching: with `^g` narrowing it
       to one folder, a whole-vault count is an answer to a question nobody
       asked. */
    pub fn entry_matches(&mut self) -> usize {
        /* The rows *are* the matches while the needle is live — a second
           whole-vault pass to count what the first one just filtered was the
           most expensive redundancy in the frame. */
        self.entry_rows().len()
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

    /* A click lands on a row, not on an index: the pane knows where it drew,
       and the scroll offset says which row that pixel belongs to. Clicking
       the pane at all hands it the keys, which is what a click means
       everywhere else. */
    pub fn click(&mut self, column: u16, row: u16) {
        let inside = |area: Rect| {
            area.width > 0
                && (area.left()..area.right()).contains(&column)
                && (area.top()..area.bottom()).contains(&row)
        };
        if inside(self.group_area) {
            let at = self.group_scroll + (row - self.group_area.top()) as usize;
            self.active_pane = Pane::Groups;
            let tree = self.group_tree();
            if let Some((id, _)) = tree.get(at) {
                self.group_cursor = Some(*id);
            }
            self.snap();
        } else if inside(self.entry_area) {
            let at = self.entry_scroll + (row - self.entry_area.top()) as usize;
            self.active_pane = Pane::Entries;
            let rows = self.entry_rows();
            if let Some(id) = rows.get(at) {
                self.entry_cursor = Some(*id);
            }
        }
    }

    /// Wheel over a pane scrolls that pane, whichever one has the keys.
    pub fn wheel(&mut self, column: u16, row: u16, down: bool) {
        let over_groups = self.group_area.width > 0
            && (self.group_area.left()..self.group_area.right()).contains(&column)
            && (self.group_area.top()..self.group_area.bottom()).contains(&row);
        if over_groups {
            self.step_group(down);
        } else {
            self.step_entry(down);
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

    /* `^g` in the band: swap between filtering the whole vault and filtering
       the folder the cursor is in. Both are useful; the point is that the
       screen says which one is happening. */
    pub fn toggle_search_scope(&mut self) {
        self.search_global = !self.search_global;
        self.snap();
        if self.search_global {
            self.say("searching the whole vault");
        } else {
            self.say(format!("searching {} only", self.here()));
        }
    }

    /// Enter on the band: keep the filter, hand the keys back to the browser.
    pub fn keep_search(&mut self) {
        let kept = !self.search.as_deref().unwrap_or_default().is_empty();
        if !kept {
            self.search = None;
        }
        self.band = false;
        /* The filter is about entries, so the keys go where the results are:
           Enter used to hand them back to the groups pane, and `j` then moved
           a tree the user had stopped looking at. */
        if kept {
            self.active_pane = Pane::Entries;
        }
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

    pub fn selected_group(&self) -> Option<keepass::db::GroupRef<'_>> {
        let (vault, id) = (self.vault.as_ref()?, self.group_cursor?);
        vault.get_group(&id)
    }

    /// The root id of the open vault. Only reached from browser paths that
    /// already know a vault is open.
    fn root_id(&self) -> GroupId {
        self.vault.as_ref().expect("browser keys need a vault").root_id()
    }

    /* Filtered out means not selected: the entry cursor may name an entry of
       another group after the group cursor moved, and acting on it would edit
       a row that is not on screen. A live search relaxes the rule — the rows
       list is global then, and a hit from another folder is exactly the row
       the user asked to act on. */
    pub fn selected_entry(&self) -> Option<keepass::db::EntryRef<'_>> {
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
        /* Every mutation lands here to put the cursors back on real rows, and
           it runs before the autosave — so this, not `persist`, is the first
           moment the cached rows can be out of date. */
        self.rows_cache = None;
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
        /* Every mutation lands here on its way to disk, which makes it the
           one place that can say "the vault is not what it was". */
        self.revision = self.revision.wrapping_add(1);
        self.rows_cache = None;
        let Some(vault) = &mut self.vault else {
            return;
        };
        if vault.path().is_none() {
            self.dirty = true;
            return;
        }
        match vault.save() {
            Ok(()) => {
                self.dirty = false;
                self.overwrite_armed = false;
            }
            /* Somebody else wrote the file. Refusing is the whole point: the
               alternative is this session quietly winning every race. */
            Err(VaultError::ChangedOnDisk) => {
                self.dirty = true;
                self.overwrite_armed = true;
                self.error("vault changed on disk  ·  ^s overwrites  ·  ^r reloads theirs");
            }
            Err(e) => {
                self.dirty = true;
                self.error(format!("save failed  ·  {e} · kept in memory"));
            }
        }
    }

    /* `^s`: save now. Sennel autosaves, so this is mostly the key everyone
       presses out of habit — but it is also the retry after a failed save and
       the second press that overrides a file somebody else changed. */
    pub fn save_now(&mut self) {
        let Some(vault) = &mut self.vault else {
            self.say("no vault open to save");
            return;
        };
        if vault.path().is_none() {
            self.warn("this vault has no file yet  ·  nothing to save to");
            return;
        }
        if self.overwrite_armed {
            match vault.save_over() {
                Ok(()) => {
                    self.dirty = false;
                    self.overwrite_armed = false;
                    self.warn("saved over the copy on disk");
                }
                Err(e) => self.error(format!("save failed  ·  {e} · kept in memory")),
            }
            return;
        }
        if !self.dirty {
            self.say("nothing to save  ·  every change saves itself");
            return;
        }
        self.persist();
        if !self.dirty {
            self.say("saved");
        }
    }

    /* `^r` on a conflict: take the copy on disk and lose the changes this
       session could not write. Only offered while a save has actually been
       refused, so it can never be a surprise reload of somebody's work. */
    pub fn reload_vault(&mut self) {
        if !self.overwrite_armed {
            self.say("nothing to reload  ·  the file has not changed");
            return;
        }
        let Some(vault) = &mut self.vault else {
            return;
        };
        match vault.reload() {
            Ok(()) => {
                self.dirty = false;
                self.overwrite_armed = false;
                /* The database was replaced wholesale, so every snapshot on
                   the stack describes a vault that is no longer there. */
                self.undo.clear();
                self.cut = None;
                self.snap();
                self.warn("reloaded from disk  ·  your unsaved changes are gone");
            }
            Err(e) => self.error(format!("cannot reload  ·  {e}")),
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
            otp: String::new(),
            otp_touched: false,
            had_otp: false,
            reveal: false,
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
        let id = entry.id();
        self.form = Some(Form {
            kind: FormKind::Edit(id),
            field: FormField::Title,
            title: entry.title().to_string(),
            username: entry.username().to_string(),
            password: String::new(),
            url: entry.url().to_string(),
            notes: entry.notes().to_string(),
            caret: entry.title().chars().count(),
            password_touched: false,
            /* The stored seed never prefills the box: it is a secret, and a
               masked run of bullets forty characters long teaches nobody
               anything. Empty-and-untouched keeps it, the password's rule. */
            otp: String::new(),
            otp_touched: false,
            had_otp: crate::vault::raw_otp(&entry).is_some(),
            reveal: false,
        });
    }

    /* `D` on an entry: ask first. The confirm carries the title for the
       prompt so the answer is about a row the user can see, not a blind id.
       It also carries whether this is the recoverable delete or the real one,
       because those are different questions and deserve different words. */
    pub fn ask_delete_entry(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.say("no entry here to delete");
            return;
        };
        let id = entry.id();
        let title = entry.title().to_string();
        let forever = self.vault.as_ref().is_some_and(|v| v.is_recycled(&id));
        self.confirm = Some(Confirm::DeleteEntry { id, title, forever });
    }

    /// The yes side of the delete confirm. Kept off the key handler so the
    /// confirm popup and the delete itself cannot drift apart.
    pub fn confirm_delete_entry(&mut self, id: EntryId) {
        /* Snapshot before either delete. The bin path does not need it (the
           entry lives on and undo moves it home), but the expunge path does,
           and taking it once keeps the two branches the same shape. */
        let parent = self.vault.as_ref().and_then(|v| v.parent_group_of_entry(&id));
        let before: Option<keepass::db::Entry> =
            self.vault.as_ref().and_then(|v| v.get_entry(&id).map(|e| e.clone()));
        let forever = self.vault.as_ref().is_some_and(|v| v.is_recycled(&id));
        if let (Some(vault), Some(parent), Some(before)) =
            (self.vault.as_mut(), parent, before)
        {
            let done = if forever {
                vault.expunge_entry(&id)
            } else {
                vault.recycle_entry(&id)
            };
            match done {
                Ok(()) => {
                    self.push_undo(if forever {
                        Undo::Delete { id, parent, before }
                    } else {
                        Undo::Recycle { id, parent, before }
                    });
                    self.entry_cursor = None;
                    self.snap();
                    self.persist();
                    self.say(if forever {
                        "entry deleted for good  ·  u restores it"
                    } else {
                        "entry moved to the recycle bin  ·  u restores it"
                    });
                }
                Err(e) => self.say(format!("cannot delete  ·  {e}")),
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
            FormField::Otp,
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

    /* `^r` in the form, the same key the lock screen uses: a generated
       password is worth reading once before it is stored. */
    pub fn toggle_form_reveal(&mut self) {
        let Some(form) = self.form.as_mut() else {
            return;
        };
        form.reveal = !form.reveal;
        if form.reveal {
            self.warn("password shown  ·  ^r hides it");
        }
    }

    /* alt+enter (or ^j) in the notes box: Enter submits the form, so without
       this a note could hold a line break but never gain one. Refused
       elsewhere, where a newline is not a thing a field can hold. */
    pub fn form_newline(&mut self) {
        let Some(form) = self.form.as_ref() else {
            return;
        };
        if form.field != FormField::Notes {
            self.say("only notes hold more than one line");
            return;
        }
        self.form_insert('\n');
    }

    pub fn form_insert(&mut self, c: char) {
        let at = self.form_caret_byte();
        let value = self.active_form_value();
        value.insert(at, c);
        let form = self.form.as_mut().expect("just inserted");
        form.caret += 1;
        form.touch_secret();
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
        form.touch_secret();
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
            form.touch_secret();
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
        // Might be the password or the seed box; zeroize covers all of them.
        self.active_form_value().zeroize();
        let form = self.form.as_mut().expect("clearing");
        form.caret = 0;
        form.touch_secret();
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
        form.touch_secret();
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
        /* The seed is checked before anything is written: a secret that
           cannot mint a code is worse than no secret at all, because the
           entry then looks set up and answers with nothing. */
        let otp: Option<Option<String>> = if !form.otp_touched {
            None
        } else if form.otp.trim().is_empty() {
            Some(None)
        } else {
            match crate::vault::totp_url(&form.otp, &form.title, &form.username) {
                Ok(url) => Some(Some(url)),
                Err(why) => {
                    self.warn(format!("{why}  ·  the form stays open"));
                    self.form = Some(form);
                    let form = self.form.as_mut().expect("just put back");
                    form.field = FormField::Otp;
                    form.caret = form.otp.chars().count();
                    return;
                }
            }
        };
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
                    .map(|id| {
                        if let Some(Some(url)) = otp.as_ref() {
                            let _ = vault.set_otp(&id, Some(url));
                        }
                        Some(id)
                    })
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
                /* Snapshot before the write, and before the mutable borrow:
                   undo restores the entry as the form found it, password
                   included. */
                let before = self
                    .vault
                    .as_ref()
                    .and_then(|v| v.get_entry(&id).map(|e| e.clone()));
                if let Some(before) = before {
                    self.push_undo(Undo::Edit { id, before });
                }
                let vault = self.vault.as_mut().expect("edit form needs a vault");
                vault
                    .update_entry(&id, &form.title, &form.username, password, &form.url, &form.notes)
                    .and_then(|()| match otp.as_ref() {
                        // Untouched keeps whatever the entry already carried.
                        None => Ok(()),
                        Some(url) => vault.set_otp(&id, url.as_deref()),
                    })
                    .map(|()| None)
            }
        };
        match result {
            Ok(new_id) => {
                if let Some(id) = new_id {
                    self.push_undo(Undo::AddEntry {
                        id,
                        title: form.title.clone(),
                    });
                    self.entry_cursor = Some(id);
                }
                self.snap();
                self.persist();
                let note = match otp {
                    Some(Some(_)) => "  ·  one-time code set",
                    Some(None) if form.had_otp => "  ·  one-time code removed",
                    _ => "",
                };
                self.say(match form.kind {
                    FormKind::Add => format!("entry added{note}"),
                    FormKind::Edit(_) => format!("entry saved{note}"),
                });
            }
            Err(e) => {
                self.say(format!("cannot save  ·  {e}"));
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
        let title = group.name.clone();
        self.group_prompt = Some(GroupPrompt {
            kind: GroupPromptKind::Rename(group.id()),
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
                /* Snapshot the old name before the rename, and before the
                   mutable borrow, so one `u` puts it back. */
                let before = self
                    .vault
                    .as_ref()
                    .and_then(|v| v.get_group(&id).map(|g| g.name.clone()));
                if let Some(before) = before {
                    self.push_undo(Undo::Rename { id, before });
                }
                let vault = self.vault.as_mut().expect("group prompt needs a vault");
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

    /* `^p`: change the master password. Only on an open vault with a file
       behind it — an unsaved vault has no password to change yet, and the
       unlock screen is where that one is set. */
    pub fn open_rekey(&mut self) {
        let has_file = self.vault.as_ref().is_some_and(|v| v.path().is_some());
        if !has_file {
            self.say("no vault file to re-key  ·  unlock one first");
            return;
        }
        self.rekey = Some(Rekey::default());
    }

    pub fn close_rekey(&mut self) {
        // The drop zeroizes; taking it is what makes the drop happen now.
        self.rekey = None;
        self.say("password unchanged");
    }

    pub fn rekey_next_field(&mut self) {
        let Some(rekey) = &mut self.rekey else {
            return;
        };
        rekey.field = match rekey.field {
            RekeyField::New => RekeyField::Again,
            RekeyField::Again => RekeyField::New,
        };
        rekey.caret = match rekey.field {
            RekeyField::New => rekey.password.chars().count(),
            RekeyField::Again => rekey.confirm.chars().count(),
        };
    }

    pub fn rekey_reveal(&mut self) {
        if let Some(rekey) = &mut self.rekey {
            rekey.reveal = !rekey.reveal;
        }
    }

    pub fn rekey_insert(&mut self, c: char) {
        let Some(rekey) = &mut self.rekey else {
            return;
        };
        let caret = rekey.caret;
        let field = match rekey.field {
            RekeyField::New => &mut rekey.password,
            RekeyField::Again => &mut rekey.confirm,
        };
        let at = field
            .char_indices()
            .nth(caret)
            .map_or(field.len(), |(at, _)| at);
        field.insert(at, c);
        rekey.caret += 1;
    }

    pub fn rekey_backspace(&mut self) {
        let Some(rekey) = &mut self.rekey else {
            return;
        };
        if rekey.caret == 0 {
            return;
        }
        let caret = rekey.caret;
        let field = match rekey.field {
            RekeyField::New => &mut rekey.password,
            RekeyField::Again => &mut rekey.confirm,
        };
        let at = field
            .char_indices()
            .nth(caret - 1)
            .map_or(field.len(), |(at, _)| at);
        field.remove(at);
        rekey.caret -= 1;
    }

    /* Enter on the prompt. Both boxes must agree, because the only check on a
       new master password is that it was typed the same way twice: nothing
       else in the app will ever be able to tell the user what it was. */
    pub fn submit_rekey(&mut self) {
        let Some(rekey) = self.rekey.take() else {
            return;
        };
        if rekey.password.is_empty() {
            self.warn("empty password  ·  the prompt stays open");
            self.rekey = Some(rekey);
            return;
        }
        if rekey.password != rekey.confirm {
            /* The second box clears, not the first: the retype is what went
               wrong, and making them type both again is a punishment. */
            let mut rekey = rekey;
            rekey.confirm.zeroize();
            rekey.field = RekeyField::Again;
            rekey.caret = 0;
            self.rekey = Some(rekey);
            self.warn("passwords differ  ·  retype the second box");
            return;
        }
        /* A key file is part of the key, so a rekey that forgets it writes a
           vault the user cannot open. The path is the one the unlock screen
           still holds; it names a file, not a secret. */
        let key_path = self.unlock_keyfile.trim().to_string();
        let mut key_bytes: Option<Vec<u8>> = None;
        if !key_path.is_empty() {
            match std::fs::read(&key_path) {
                Ok(bytes) => key_bytes = Some(bytes),
                Err(_) => {
                    self.error(format!(
                        "cannot read key file {key_path}  ·  password unchanged"
                    ));
                    return;
                }
            }
        }
        let done = self
            .vault
            .as_mut()
            .expect("the prompt only opens on an open vault")
            .rekey(&rekey.password, key_bytes.as_deref());
        if let Some(b) = key_bytes.as_mut() {
            b.zeroize();
        }
        match done {
            Ok(()) => {
                /* The file on disk is now the new password's, so anything the
                   session had pending is written too. Nothing is left dirty. */
                self.dirty = false;
                self.overwrite_armed = false;
                self.say(match key_path.is_empty() {
                    true => "master password changed".to_string(),
                    false => format!("master password changed  ·  key file {key_path} kept"),
                });
            }
            Err(e) => {
                /* The vault still opens with the old password: `rekey` writes
                   before it swaps. Say which one is live, because "failed" on
                   a password change is the most frightening word in the app. */
                self.error(format!("password unchanged  ·  {e}"));
            }
        }
    }

    /* `F`: everything on the entry the five fixed rows cannot show. Custom
       fields and attachments were visible as a count ("2 more fields") and
       nothing else, which is a dead end: people keep recovery codes and ssh
       keys in attachments, and an entry you can see holds one but cannot open
       is an entry you have to open another app for. */
    pub fn open_fields(&mut self) {
        let Some(id) = self.entry_cursor else {
            self.say("no entry here");
            return;
        };
        self.fields = Some(Fields {
            entry: id,
            rows: self.extra_rows(&id),
            cursor: 0,
            reveal: false,
            adding: None,
        });
        if self.fields.as_ref().is_some_and(|f| f.rows.is_empty()) {
            self.say("no extra fields  ·  a adds one, f attaches a file");
        }
    }

    fn extra_rows(&self, id: &EntryId) -> Vec<crate::vault::Extra> {
        self.vault
            .as_ref()
            .and_then(|v| v.get_entry(id))
            .map(|e| crate::vault::extra_rows(&e))
            .unwrap_or_default()
    }

    /// Re-read after a change, so the list never shows what is no longer there.
    fn refresh_fields(&mut self) {
        let Some(id) = self.fields.as_ref().map(|f| f.entry) else {
            return;
        };
        let rows = self.extra_rows(&id);
        if let Some(fields) = &mut self.fields {
            fields.cursor = fields.cursor.min(rows.len().saturating_sub(1));
            fields.rows = rows;
        }
    }

    pub fn close_fields(&mut self) {
        self.fields = None;
    }

    pub fn fields_move(&mut self, down: bool) {
        let Some(fields) = &mut self.fields else {
            return;
        };
        let last = fields.rows.len().saturating_sub(1);
        fields.cursor = match down {
            true => (fields.cursor + 1).min(last),
            false => fields.cursor.saturating_sub(1),
        };
    }

    pub fn fields_reveal(&mut self) {
        if let Some(fields) = &mut self.fields {
            fields.reveal = !fields.reveal;
        }
    }

    fn fields_selected(&self) -> Option<&crate::vault::Extra> {
        let fields = self.fields.as_ref()?;
        fields.rows.get(fields.cursor)
    }

    /* `y` on a field copies its value, through the same board and the same
       auto-clear as a password: a recovery code is a secret too. */
    pub fn fields_copy(&mut self) {
        let what = match self.fields_selected() {
            Some(crate::vault::Extra::Field { name, value, .. }) => {
                Some((name.clone(), value.clone()))
            }
            Some(crate::vault::Extra::File { .. }) => None,
            None => return,
        };
        match what {
            Some((name, value)) => self.copy_named(&name, &value),
            // A file is bytes; `s` writes it out, the clipboard is for text.
            None => self.say("that is a file  ·  s writes it out"),
        }
    }

    /* `s` on an attachment writes it beside the vault, owner-only. The file
       leaves the vault's protection the moment it lands, so the mode is set
       from the first byte and the message says where it went. */
    pub fn fields_save(&mut self) {
        let Some(crate::vault::Extra::File { name, .. }) = self.fields_selected() else {
            self.say("that is a field  ·  y copies it");
            return;
        };
        let name = name.clone();
        let Some(id) = self.fields.as_ref().map(|f| f.entry) else {
            return;
        };
        let Some(bytes) = self.vault.as_ref().and_then(|v| v.attachment_bytes(&id, &name)) else {
            self.error("the attachment is not there any more");
            return;
        };
        /* Beside the vault, not in the working directory: the vault's folder
           is somewhere the user already keeps secrets, and cwd is wherever
           they happened to launch from. */
        let Some(dir) = self
            .vault
            .as_ref()
            .and_then(|v| v.path())
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        else {
            self.error("no vault file to write beside");
            return;
        };
        /* The name comes out of the vault and may hold anything, including a
           path separator: take the last component only, so an attachment
           called "../../.ssh/authorized_keys" lands as a file, not a write
           somewhere else entirely. */
        let leaf = std::path::Path::new(&name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty() && n != "." && n != "..")
            .unwrap_or_else(|| "attachment".to_string());
        let at = dir.join(&leaf);
        match crate::vault::write_owner_only(&at, &bytes) {
            Ok(()) => self.warn(format!(
                "wrote {} ·  {} bytes, owner-only, outside the vault",
                at.display(),
                bytes.len()
            )),
            Err(e) => self.error(format!("cannot write {} · {e}", at.display())),
        }
    }

    /* `a` adds a custom field, `f` attaches a file. Two boxes either way:
       the name, then the value or the path it is read from. */
    pub fn fields_add(&mut self, from_file: bool) {
        if let Some(fields) = &mut self.fields {
            let mut add = AddField::default();
            add.from_file = from_file;
            fields.adding = Some(add);
        }
    }

    pub fn fields_add_insert(&mut self, c: char) {
        let Some(add) = self.fields.as_mut().and_then(|f| f.adding.as_mut()) else {
            return;
        };
        let caret = add.caret;
        let box_ = if add.on_value { &mut add.value } else { &mut add.name };
        let at = box_.char_indices().nth(caret).map_or(box_.len(), |(at, _)| at);
        box_.insert(at, c);
        add.caret += 1;
    }

    pub fn fields_add_backspace(&mut self) {
        let Some(add) = self.fields.as_mut().and_then(|f| f.adding.as_mut()) else {
            return;
        };
        if add.caret == 0 {
            return;
        }
        let caret = add.caret;
        let box_ = if add.on_value { &mut add.value } else { &mut add.name };
        let at = box_.char_indices().nth(caret - 1).map_or(box_.len(), |(at, _)| at);
        box_.remove(at);
        add.caret -= 1;
    }

    pub fn fields_add_next(&mut self) {
        let Some(add) = self.fields.as_mut().and_then(|f| f.adding.as_mut()) else {
            return;
        };
        add.on_value = !add.on_value;
        add.caret = match add.on_value {
            true => add.value.chars().count(),
            false => add.name.chars().count(),
        };
    }

    pub fn fields_add_cancel(&mut self) {
        if let Some(fields) = &mut self.fields {
            // The drop wipes the value box.
            fields.adding = None;
        }
    }

    /* Enter on the add prompt. A field goes in protected, because a field
       somebody added by hand to a password manager is more likely to be a
       secret than not; a file is read from the path and goes in the same way. */
    pub fn fields_add_submit(&mut self) {
        let Some(fields) = &mut self.fields else {
            return;
        };
        let Some(add) = fields.adding.take() else {
            return;
        };
        let id = fields.entry;
        if add.name.trim().is_empty() {
            self.warn("a name is the only must  ·  the prompt stays open");
            if let Some(fields) = &mut self.fields {
                fields.adding = Some(add);
            }
            return;
        }
        let done = if add.from_file {
            let path = crate::config::expand(add.value.trim());
            match std::fs::read(&path) {
                Ok(bytes) => self
                    .vault
                    .as_mut()
                    .expect("the screen only opens on a vault")
                    .add_attachment(&id, add.name.trim(), bytes),
                Err(e) => {
                    self.error(format!("cannot read {} · {e}", path.display()));
                    return;
                }
            }
        } else {
            self.vault
                .as_mut()
                .expect("the screen only opens on a vault")
                .set_field(&id, add.name.trim(), &add.value, true)
        };
        match done {
            Ok(()) => {
                let name = add.name.trim().to_string();
                self.snap();
                self.persist();
                self.refresh_fields();
                self.say(match add.from_file {
                    true => format!("attached {name}"),
                    false => format!("added field {name}"),
                });
            }
            Err(e) => self.error(format!("cannot add · {e}")),
        }
    }

    /* `D` removes the row under the cursor. No confirm and no undo slot: a
       custom field is one `a` from being retyped, and an attachment is still
       in whatever file it came from. The message says which it was. */
    pub fn fields_remove(&mut self) {
        let Some(row) = self.fields_selected().cloned() else {
            return;
        };
        let Some(id) = self.fields.as_ref().map(|f| f.entry) else {
            return;
        };
        let vault = self.vault.as_mut().expect("the screen only opens on a vault");
        let (done, said) = match &row {
            crate::vault::Extra::Field { name, .. } => {
                (vault.remove_field(&id, name), format!("removed field {name}"))
            }
            crate::vault::Extra::File { name, .. } => {
                (vault.remove_attachment(&id, name), format!("removed {name}"))
            }
        };
        match done {
            Ok(()) => {
                self.snap();
                self.persist();
                self.refresh_fields();
                self.warn(said);
            }
            Err(e) => self.error(format!("cannot remove · {e}")),
        }
    }

    /* `H`: the old versions an entry carries. Sennel writes none — its edits
       leave no history record on purpose — but KeePassXC does, so an entry
       imported from there arrives holding every password it ever had. The
       docs used to say "use KeePassXC if you need to purge it", which is a
       strange place for a password manager to leave somebody. */
    pub fn open_history(&mut self) {
        let Some(id) = self.entry_cursor else {
            self.say("no entry here");
            return;
        };
        let rows = self
            .vault
            .as_ref()
            .and_then(|v| v.get_entry(&id))
            .map(|e| crate::vault::history(&e))
            .unwrap_or_default();
        if rows.is_empty() {
            self.say("no old versions  ·  Sennel's own edits keep none");
            return;
        }
        self.history = Some(History { entry: id, rows, cursor: 0, reveal: false });
    }

    pub fn close_history(&mut self) {
        self.history = None;
    }

    pub fn history_move(&mut self, down: bool) {
        let Some(history) = &mut self.history else {
            return;
        };
        let last = history.rows.len().saturating_sub(1);
        history.cursor = match down {
            true => (history.cursor + 1).min(last),
            false => history.cursor.saturating_sub(1),
        };
    }

    pub fn history_reveal(&mut self) {
        if let Some(history) = &mut self.history {
            history.reveal = !history.reveal;
        }
    }

    /* `D` on the history screen: throw the lot away. All of it rather than
       one version, because the reason to be here is "I do not want this vault
       carrying my old passwords" and deleting them one at a time is a chore
       that ends in the same place. */
    pub fn clear_history(&mut self) {
        let Some(id) = self.history.as_ref().map(|h| h.entry) else {
            return;
        };
        let done = self
            .vault
            .as_mut()
            .expect("the screen only opens on a vault")
            .clear_history(&id);
        match done {
            Ok(gone) => {
                self.history = None;
                self.snap();
                self.persist();
                let plural = if gone == 1 { "version" } else { "versions" };
                self.warn(format!("cleared {gone} old {plural}  ·  this has no undo"));
            }
            Err(e) => self.error(format!("cannot clear · {e}")),
        }
    }

    /* `!`: what is wrong with this vault's passwords. A list, not a score:
       a number out of ten tells nobody which entry to open next. */
    pub fn open_audit(&mut self) {
        let Some(vault) = &self.vault else {
            self.say("no vault open");
            return;
        };
        let rows = crate::vault::audit(vault);
        if rows.is_empty() {
            self.say("nothing to fix  ·  no reused, weak or empty passwords");
            return;
        }
        self.audit = Some(Audit { rows, cursor: 0 });
    }

    pub fn close_audit(&mut self) {
        self.audit = None;
    }

    pub fn audit_move(&mut self, down: bool) {
        let Some(audit) = &mut self.audit else {
            return;
        };
        let last = audit.rows.len().saturating_sub(1);
        audit.cursor = match down {
            true => (audit.cursor + 1).min(last),
            false => audit.cursor.saturating_sub(1),
        };
    }

    /* Enter on a row: close the audit and put the cursor on that entry, in
       its own group. A list of problems nobody can act on from where they are
       standing is a list nobody acts on. */
    pub fn audit_open_selected(&mut self) {
        let Some(audit) = &self.audit else {
            return;
        };
        let Some((id, _)) = audit.rows.get(audit.cursor).copied() else {
            return;
        };
        self.audit = None;
        /* Into the group that holds it, or the row would be filtered out of
           a pane pointed somewhere else entirely. */
        if let Some(parent) = self.vault.as_ref().and_then(|v| v.parent_group_of_entry(&id)) {
            self.group_cursor = Some(parent);
        }
        self.search = None;
        self.band = false;
        self.entry_cursor = Some(id);
        self.active_pane = Pane::Entries;
        self.snap();
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

    /* `D` on the groups pane. A group goes to the bin with everything under
       it, so the old "not empty, move its contents first" refusal is gone:
       nothing is destroyed and `u` puts the whole subtree back. Inside the
       bin the same key is the real delete, and it has no undo. */
    pub fn ask_delete_group(&mut self) {
        let Some(group) = self.selected_group() else {
            self.say("no group here to delete");
            return;
        };
        if group.id() == self.root_id() {
            self.say("the root group cannot be deleted");
            return;
        }
        let forever = self
            .vault
            .as_ref()
            .is_some_and(|v| v.in_recycle_bin(&group.id()));
        self.confirm = Some(Confirm::DeleteGroup {
            id: group.id(),
            forever,
            title: group.name.clone(),
        });
    }

    /// The yes side of the group delete confirm, kept off the key handler.
    pub fn confirm_delete_group(&mut self, id: GroupId) {
        let parent = self.vault.as_ref().and_then(|v| v.get_group(&id).and_then(|g| g.parent().map(|p| p.id())));
        let title = self
            .vault
            .as_ref()
            .and_then(|v| v.get_group(&id).map(|g| g.name.clone()))
            .unwrap_or_default();
        let Some(vault) = &mut self.vault else {
            return;
        };
        let forever = vault.in_recycle_bin(&id);
        /* Inside the bin `D` destroys the group and everything under it, and
           there is no snapshot big enough to undo a subtree — so that path
           clears the slot rather than leaving a stale one armed. */
        let done = if forever {
            vault.delete_group_tree(&id)
        } else {
            vault.recycle_group(&id)
        };
        match done {
            Ok(()) => {
                /* A cut pointing at the deleted group is a ghost: disarm it
                   rather than letting V paste nothing. */
                if self.cut == Some(Cut::Group(id)) {
                    self.cut = None;
                }
                /* A permanent group delete takes a subtree with it and no
                   snapshot is big enough to put that back, so it arms
                   nothing — and leaves earlier steps alone to be undone. */
                if let (false, Some(parent)) = (forever, parent) {
                    self.push_undo(Undo::RecycleGroup { id, parent, title });
                }
                self.group_cursor = None;
                self.snap();
                self.persist();
                self.say(if forever {
                    "group deleted for good"
                } else {
                    "group moved to the recycle bin  ·  u restores it"
                });
            }
            Err(e) => self.say(format!("cannot delete  ·  {e}")),
        }
    }

    /* `X`: cut whatever the cursor is on. Groups pane cuts the group, entries
       pane cuts the entry — one key, pane decides, the status bar says which. */
    pub fn cut_selected(&mut self) {
        let Some(cut) = (match self.active_pane {
            Pane::Groups => match self.selected_group() {
                Some(g) if g.id() != self.root_id() => Some(Cut::Group(g.id())),
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
                Some(e) => Some(Cut::Entry(e.id())),
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
            Cut::Group(_) => "group cut  ·  V pastes it under another group",
            Cut::Entry(_) => "entry cut  ·  V moves it to another group",
        });
    }

    /* `V`: paste the armed cut into the selected group, from either pane.
       One-shot: the shelf empties on a successful paste, and a failed one
       stays armed so a typo in the target costs nothing. */
    pub fn paste_cut(&mut self) {
        let Some(cut) = self.cut else {
            self.say("nothing cut  ·  X arms the shelf");
            return;
        };
        let Some(target) = self.group_cursor else {
            self.say("no group selected");
            return;
        };
        let Some(vault) = &mut self.vault else {
            return;
        };
        /* The two ids split by arm: a cut knows which kind it is, so each
           arm sets exactly the cursor that kind owns. */
        match cut {
            Cut::Entry(id) => match vault.move_entry(&id, &target) {
                Ok(()) => {
                    self.cut = None;
                    self.entry_cursor = Some(id);
                    self.snap();
                    self.persist();
                    self.say("entry moved");
                }
                Err(e) => self.say(format!("cannot paste  ·  {e}")),
            },
            Cut::Group(id) => match vault.move_group(&id, &target) {
                Ok(()) => {
                    self.cut = None;
                    self.group_cursor = Some(id);
                    self.snap();
                    self.persist();
                    self.say("group moved");
                }
                Err(e) => self.say(format!("cannot paste  ·  {e}")),
            },
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
                .map(|e| format!("cut: {}", e.title())),
            Cut::Group(id) => vault
                .get_group(&id)
                .map(|g| format!("cut: {}", g.name)),
        }
    }

    /* `u` walks back through the session's changes, newest first. It used to
       be one slot, which meant a mistake noticed one keystroke too late was
       already permanent — the most common way to actually lose work here.

       Still session-only and still bounded: this is a way back out of what
       you just did, not a history of the vault. */
    /* Bounded on purpose. Each Delete holds a whole entry, secrets included,
       so an unbounded stack is an unbounded pile of plaintext in memory —
       and dropping the oldest is what zeroizes it. Deep enough to cover a
       mistake noticed several steps later, which is the case one slot
       could not. */
    const UNDO_DEPTH: usize = 32;

    fn push_undo(&mut self, step: Undo) {
        if self.undo.len() == Self::UNDO_DEPTH {
            self.undo.remove(0);
        }
        self.undo.push(step);
    }

    pub fn undo_last(&mut self) {
        let Some(undo) = self.undo.pop() else {
            self.say("nothing to undo · nothing changed this session");
            return;
        };
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        match undo {
            Undo::Edit { id, before } => {
                let title = before.title().to_string();
                /* Results ignored the way a rollback is: the mutation can
                   only fail on an id that no longer exists, and persist()
                   below reports anything the save kept from landing. */
                let _ = vault.replace_entry(&before);
                self.entry_cursor = Some(id);
                self.snap();
                self.persist();
                self.say(format!("undid edit of {title}"));
            }
            Undo::Delete { id, parent, before } => {
                let title = before.title().to_string();
                let _ = vault.restore_entry(&before, &parent);
                self.entry_cursor = Some(id);
                self.snap();
                self.persist();
                self.say(format!("restored {title}"));
            }
            /* Out of the bin rather than back from the dead: the entry never
               stopped existing, so this keeps its id, history and timestamps
               instead of overwriting them with the snapshot's. */
            Undo::Recycle { id, parent, before } => {
                let title = before.title().to_string();
                let _ = vault.move_entry(&id, &parent);
                self.entry_cursor = Some(id);
                self.snap();
                self.persist();
                self.say(format!("restored {title}"));
            }
            Undo::RecycleGroup { id, parent, title } => {
                let _ = vault.move_group(&id, &parent);
                self.group_cursor = Some(id);
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
        let deeper = match self.undo.len() {
            0 | 1 => String::new(),
            n => format!(" +{}", n - 1),
        };
        let note = match self.undo.last()? {
            Undo::Edit { before, .. } => format!("undo: edit of {}", before.title()),
            Undo::Delete { before, .. } => format!("undo: restore {}", before.title()),
            Undo::Recycle { before, .. } => format!("undo: restore {}", before.title()),
            Undo::RecycleGroup { title, .. } => format!("undo: restore {title}"),
            Undo::AddEntry { title, .. } => format!("undo: remove {title}"),
            Undo::Rename { before, .. } => format!("undo: name {before}"),
        };
        Some(format!("{note}{deeper}"))
    }

    /* ^s on the form: generate into the password box. Excludes ambiguous
       glyphs so a password read off this screen can be typed elsewhere —
       l1IO0 are the ones every font renders alike. Touching the box flips
       the keep-latch, so submit writes what was generated. */
    pub fn form_generate(&mut self) {
        let settings = self.generator;
        let Some(form) = self.form.as_mut() else {
            return;
        };
        let generated = match crate::generator::generate(
            settings.length,
            settings.classes,
            settings.exclude_ambiguous,
        ) {
            Ok(pw) => pw,
            Err(e) => {
                self.error(format!("cannot generate  ·  {e}"));
                return;
            }
        };
        form.password = generated;
        form.password_touched = true;
        form.caret = form.password.chars().count();
        /* Priced against the pool it was drawn from: excluding the lookalikes
           shrinks the alphabet, and the estimate used to quote the wider one,
           which overstates a secret in the one direction it must not. */
        let bits = crate::generator::entropy_bits(
            settings.length,
            settings.classes.alphabet_len(settings.exclude_ambiguous),
        );
        self.say(format!(
            "generated {} chars  ·  {}  ·  ~{bits:.0} bits",
            settings.length,
            settings.describe()
        ));
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
        FormField::Otp => &mut form.otp,
        FormField::Notes => &mut form.notes,
    }
}

fn form_field_value_ref(form: &Form, field: FormField) -> &str {
    match field {
        FormField::Title => &form.title,
        FormField::Username => &form.username,
        FormField::Password => &form.password,
        FormField::Url => &form.url,
        FormField::Otp => &form.otp,
        FormField::Notes => &form.notes,
    }
}

#[cfg(test)]
pub mod tests {
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
        // What an unlock leaves behind, and what the lock has to take back.
        app.resting = "ready".into();
        app.last_activity = Instant::now() - Duration::from_secs(61);
        app.check_idle();
        assert_eq!(app.view, View::Unlock);
        assert!(app.vault.is_none(), "the secrets survived the lock");
        assert!(app.group_cursor.is_none());
        assert!(app.entry_cursor.is_none());
        assert!(!app.dirty, "a lock invented unsaved changes");
        assert!(app.stage.contains("locked after 60 seconds idle"), "{}", app.stage);
        /* And once the flash has been read the header says locked, not the
           "ready" the open vault left behind. */
        app.expire_now();
        assert_eq!(app.stage, "locked");
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
            .map(|(id, d)| (vault.get_group(id).unwrap().name.clone(), *d))
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
        // Straight to the bin, contents and all, which is what `D` now does.
        app.vault.as_mut().unwrap().recycle_group(&banks).unwrap();
        app.vault.as_mut().unwrap().delete_group_tree(&banks).unwrap();
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
            app.vault.as_ref().unwrap().get_group(&banks).unwrap().name,
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
        let eid = app.vault.as_ref().unwrap().entries_in(&banks)[0].id();
        // Still on root: the Banks entry must not resolve.
        app.entry_cursor = Some(eid);
        assert!(app.selected_entry().is_none());
        app.snap();
        assert_eq!(app.entry_cursor, None, "root is empty");
    }

    /* Unique per call, not just per process: the harness runs tests in
       parallel, and two sharing a path would delete each other's file. */
    pub(crate) fn temp_path(tag: &str) -> TempPath {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        TempPath(std::env::temp_dir().join(format!(
            "sennel-test-{tag}-{}-{n}.kdbx",
            std::process::id()
        )))
    }

    pub(crate) struct TempPath(pub std::path::PathBuf);

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A real KDBX file on disk behind a locked app, as main.rs builds it.
    pub(crate) fn locked_app_with_db(password: &str) -> (App, TempPath) {
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
        let (mut app, _tmp) = locked_app_with_db("correct horse");
        assert!(!app.unlock_new, "an existing file reads as create");
        let mut pw = "correct horse".to_owned().into_bytes();
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
        let (mut app, _tmp) = locked_app_with_db("correct horse");
        app.unlock_password = "correct horse".into();
        app.toggle_unlock_reveal();
        assert!(app.unlock_reveal);
        let mut pw = "correct horse".to_owned().into_bytes();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Browser);
        assert!(!app.unlock_reveal, "reveal followed the unlock out");

        let (mut app, _tmp) = locked_app_with_db("correct horse");
        app.toggle_unlock_reveal();
        let mut pw = "wrong guess".to_owned().into_bytes();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Unlock);
        assert!(!app.unlock_reveal, "failed attempt left the box bare");
    }

    /* A wrong password keeps the lock and says the next step, and still wipes
       the typed bytes: a failed guess is exactly what must not linger. */
    #[test]
    fn wrong_password_stays_locked_and_says_so() {
        let (mut app, _tmp) = locked_app_with_db("correct horse");
        let mut pw = "wrong guess".to_owned().into_bytes();
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
        let mut pw = "new secret".to_owned().into_bytes();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Browser);
        assert!(tmp.0.is_file(), "create wrote no file");
        // And the created file opens with the same password.
        assert!(Vault::open(&tmp.0, "new secret", None).is_ok());
    }

    /* A mismatched confirm writes nothing: one stray keystroke must not mint
       a database the user can never open again. */
    #[test]
    fn missing_file_refuses_a_mismatched_confirm() {
        let tmp = temp_path("mismatch");
        let mut app = App::new();
        app.set_db_path(Some(tmp.0.clone()));
        app.unlock_confirm = "something else".into();
        let mut pw = "new secret".to_owned().into_bytes();
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
        let mut pw = "whatever".to_owned().into_bytes();
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
        let (mut app, tmp) = locked_app_with_db("pw");
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

    /* A `~` path types like it reads: the file box expands it against HOME
       the way the config file does, so an existing vault is found rather
       than read as a new file literally named `~`. */
    #[test]
    fn the_file_box_expands_a_home_path() {
        let (mut app, _tmp) = locked_app_with_db("pw");
        app.unlock_file = "~/Downloads/sites.kdbx".into();
        app.unlock_field = UnlockField::File;
        app.accept_file_box();
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(
            app.db_path,
            Some(
                std::path::PathBuf::from(home)
                    .join("Downloads")
                    .join("sites.kdbx")
            ),
            "tilda stayed literal"
        );
        /* Whatever is_file says locally, it must not read as create-only
           when HOME-side path exists; here it is simply expanded. */
        assert_eq!(app.unlock_field, UnlockField::Password, "focus went home");
    }

    /* The reported bug: a path typed into the file box but Tab-passed (never
       Enter-committed) still names the vault. Unlock applies it off the box
       instead of answering "no database configured". */
    #[test]
    fn a_path_typed_but_unconfirmed_still_unlocks() {
        let (mut app, tmp) = locked_app_with_db("pw");
        app.db_path = None;
        app.unlock_file = String::new();
        app.unlock_field = UnlockField::Password;
        app.unlock_file = tmp.0.display().to_string();
        let mut pw = "pw".to_owned().into_bytes();
        app.try_unlock(&mut pw, None);
        assert_eq!(app.view, View::Browser, "unconfirmed path refused");
        assert!(app.vault.is_some());
    }

    /* With no configured vault the file box is focused first: the natural
       first action is to point Sennel at a database, and typing into the
       password box by mistake is what made an existing vault unreadable. */
    #[test]
    fn no_configured_vault_starts_on_the_file_box() {
        let mut app = App::new();
        app.set_db_path(None);
        assert_eq!(app.unlock_field, UnlockField::File, "file box not focused");
        let (app, _tmp) = locked_app_with_db("pw");
        assert_eq!(
            app.unlock_field,
            UnlockField::Password,
            "a named vault should start on the password"
        );
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
        let (mut app, _tmp) = locked_app_with_db("pw");
        let mut pw = "pw".to_owned().into_bytes();
        app.try_unlock(&mut pw, None);
        app.ask_quit();
        assert!(app.quit, "a clean vault interrogated the quit");
        let (mut app, _tmp) = locked_app_with_db("pw");
        let mut pw = "pw".to_owned().into_bytes();
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
        // What a wide-enough draw sets; there is no frame in a unit test.
        app.wide = true;
        assert!(!app.show_password);
        app.toggle_password();
        assert!(app.show_password);
        assert!(app.stage.contains("shown"), "{}", app.stage);
        app.toggle_password();
        assert!(!app.show_password);
    }

    /* Below the detail pane's width there is nowhere for a revealed password
       to appear, so `*` refuses and names the way to one instead of claiming
       a reveal the screen cannot show. */
    #[test]
    fn star_refuses_where_no_detail_fits() {
        let mut app = open_app();
        app.step_group(true);
        app.wide = false;
        app.toggle_password();
        assert!(!app.show_password, "* revealed with nowhere to show it");
        assert!(app.stage.contains("enter opens"), "{}", app.stage);
        // The popup is that room: with it open, the same key flips.
        app.switch_pane();
        app.open_detail();
        app.toggle_password();
        assert!(app.show_password, "* refused inside the detail popup");
    }

    /* Enter opens what the cursor is on: a group hands over its entries, an
       entry opens the popup that is the only detail below 100 columns. */
    #[test]
    fn enter_opens_the_group_then_the_entry() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.open_selection();
        assert_eq!(app.active_pane, Pane::Entries, "enter did not open the group");
        assert!(!app.detail, "enter opened a popup from the groups pane");
        app.open_selection();
        assert!(app.detail, "enter did not open the entry");
        // Closing re-masks: a reveal never outlives the view it was for.
        app.toggle_password();
        app.close_detail();
        assert!(!app.show_password, "the reveal survived the popup");
    }

    /* An unlocked session says which vault it is in — the header's resting
       stage and the window title both name the file, since pointing one
       session at any vault is the whole feature. */
    #[test]
    fn an_open_vault_names_itself() {
        let (mut app, tmp) = locked_app_with_db("pw");
        let name = tmp.0.file_name().unwrap().to_string_lossy().into_owned();
        let mut password = b"pw".to_vec();
        app.try_unlock(&mut password, None);
        assert!(app.vault.is_some(), "{}", app.stage);
        assert_eq!(app.window_title(), format!("Sennel — {name}"));
        app.expire_now();
        assert_eq!(app.stage, name, "the header did not name the vault");
        // Locked again, the title and the header drop the vault with it.
        app.set_lock_timeout(1);
        app.last_activity = Instant::now() - Duration::from_secs(2);
        app.check_idle();
        assert_eq!(app.window_title(), "Sennel");
        app.expire_now();
        assert_eq!(app.stage, "locked");
    }

    /* A failure must not render as a success: the flash carries a level, and
       it goes back to Info once the message has been read. */
    #[test]
    fn failures_flash_at_their_own_level() {
        let mut app = App::new();
        app.set_db_path(Some(std::path::PathBuf::from("/nowhere/none.kdbx")));
        app.unlock_new = false;
        let mut password = b"pw".to_vec();
        app.try_unlock(&mut password, None);
        assert_eq!(app.level, Level::Error, "{}", app.stage);
        app.expire_now();
        assert_eq!(app.level, Level::Info, "the level outlived the flash");
    }

    /* `^l` is the idle lock on purpose: the same wipe, and nothing about the
       open vault — a form, a kept filter, an armed cut — survives it. */
    #[test]
    fn lock_now_wipes_what_the_idle_lock_wipes() {
        let mut app = open_app();
        app.step_group(true);
        app.open_search();
        app.search_insert('a');
        app.cut_selected();
        app.open_add_form();
        app.lock_now();
        assert_eq!(app.view, View::Unlock);
        assert!(app.vault.is_none(), "the secrets survived ^l");
        assert!(app.form.is_none(), "the form outlived the vault");
        assert!(app.cut.is_none(), "the cut outlived the vault");
        assert!(app.search.is_none(), "the filter outlived the vault");
        /* Earlier flashes are still queued, so drain them: the header lands
           on the resting stage, which the lock has taken back to "locked". */
        for _ in 0..QUEUE + 2 {
            app.expire_now();
        }
        assert_eq!(app.stage, "locked");
        // A second press has nothing to lock and says so rather than nothing.
        app.lock_now();
        assert!(app.stage.contains("already locked"), "{}", app.stage);
    }

    /* The app side of the same race: an autosave that is refused leaves the
       work in memory, says so in RED, and arms `^s` as the deliberate
       override. Nothing is lost without somebody choosing to lose it. */
    #[test]
    fn a_changed_file_arms_the_override_instead_of_overwriting() {
        let (mut app, tmp) = locked_app_with_db("pw");
        let mut password = b"pw".to_vec();
        app.try_unlock(&mut password, None);
        assert!(app.vault.is_some(), "{}", app.stage);

        // Somebody else writes the file while this session holds it.
        let mut theirs = Vault::open(&tmp.0, "pw", None).unwrap();
        let root = theirs.root_id();
        theirs.create_entry(&root, "added elsewhere", "", "", "", "").unwrap();
        theirs.save().unwrap();

        app.open_add_form();
        app.form.as_mut().unwrap().title = "mine".into();
        app.submit_form();
        assert!(app.working(), "the refused save left no unsaved work");
        assert!(app.overwrite_armed, "the override was not armed");
        assert_eq!(app.level, Level::Error);
        assert!(app.stage.contains("changed on disk"), "{}", app.stage);
        // Theirs survived.
        assert_eq!(Vault::open(&tmp.0, "pw", None).unwrap().entry_count(), 1);

        // `^s` is the deliberate override, and it says what it did.
        app.save_now();
        assert!(!app.working(), "the override did not save");
        assert!(!app.overwrite_armed);
        assert_eq!(Vault::open(&tmp.0, "pw", None).unwrap().entry_count(), 1);
    }

    /* `^s` with nothing to do says so rather than going quiet — it is the key
       every hand presses, so it must always answer. */
    #[test]
    fn save_now_answers_even_when_there_is_nothing_to_save() {
        let (mut app, _tmp) = locked_app_with_db("pw");
        let mut password = b"pw".to_vec();
        app.try_unlock(&mut password, None);
        app.expire_now();
        app.save_now();
        assert!(app.stage.contains("nothing to save"), "{}", app.stage);

        let mut app = App::new();
        app.save_now();
        assert!(app.stage.contains("no vault open"), "{}", app.stage);
    }

    /* A click is a selection and a focus change, the way it is everywhere
       else; the wheel moves whichever pane it is over. */
    #[test]
    fn a_click_selects_the_row_it_landed_on() {
        let mut app = open_app();
        app.group_area = ratatui::layout::Rect::new(0, 2, 20, 10);
        app.entry_area = ratatui::layout::Rect::new(20, 2, 40, 10);
        // Second row of the tree is Banks, under Root.
        app.click(3, 3);
        assert_eq!(app.active_pane, Pane::Groups);
        assert_eq!(app.group_cursor, Some(app.group_tree()[1].0));
        // And a click in the entries pane takes the keys with it.
        app.click(25, 2);
        assert_eq!(app.active_pane, Pane::Entries);
        let first = app.entry_rows().first().copied();
        assert_eq!(app.entry_cursor, first);
        // The wheel moves the pane under the pointer, not the live one.
        let entry = app.entry_cursor;
        app.wheel(3, 5, true);
        assert_eq!(app.entry_cursor, entry, "the wheel moved the wrong pane");
    }

    /* `^g` narrows the needle to the cursor's folder and says so. */
    #[test]
    fn the_search_scope_can_be_narrowed_to_this_group() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        app.open_search();
        app.search_insert('e');
        let global = app.entry_rows().len();
        app.toggle_search_scope();
        assert!(app.stage.contains("only"), "{}", app.stage);
        assert!(
            app.entry_rows().len() <= global,
            "narrowing widened the list"
        );
        app.toggle_search_scope();
        assert_eq!(app.entry_rows().len(), global, "the scope did not come back");
    }

    /* The whole loop through the form: a printed secret typed into the otp
       box becomes a working code on the entry, and the flash says so. */
    #[test]
    fn the_form_gives_an_entry_a_working_one_time_code() {
        let mut app = open_app();
        app.step_group(true);
        app.switch_pane();
        app.open_edit_form();
        app.form.as_mut().unwrap().field = FormField::Otp;
        for c in "jbsw y3dp ehpk 3pxp".chars() {
            app.form_insert(c);
        }
        app.submit_form();
        assert!(app.form.is_none(), "the form did not submit: {}", app.stage);
        assert!(app.stage.contains("one-time code set"), "{}", app.stage);

        let entry = app.selected_entry().expect("the entry went missing");
        let (code, left) = crate::vault::totp_now(&entry).expect("no code on the entry");
        assert_eq!(code.len(), 6, "{code}");
        assert!(left > 0 && left <= 30, "{left}");

        // `t` copies the code, not the seed behind it.
        let stored = crate::vault::raw_otp(&entry).unwrap();
        assert!(stored.contains("JBSWY3DPEHPK3PXP"), "{stored}");
    }

    /* A seed that cannot mint a code never reaches the vault: the form stays
       open on the box that is wrong, with what was typed still in it. */
    #[test]
    fn a_bad_seed_keeps_the_form_open() {
        let mut app = open_app();
        app.step_group(true);
        app.switch_pane();
        app.open_edit_form();
        app.form.as_mut().unwrap().field = FormField::Otp;
        for c in "nope!!".chars() {
            app.form_insert(c);
        }
        app.submit_form();
        let form = app.form.as_ref().expect("the form closed over a bad seed");
        assert_eq!(form.field, FormField::Otp, "focus did not land on the box");
        assert_eq!(form.otp, "nope!!", "the typed text was thrown away");
        assert_eq!(app.level, Level::Warn);
        let entry = app.selected_entry().unwrap();
        assert!(crate::vault::raw_otp(&entry).is_none(), "a bad seed was stored");
    }

    /* Untouched keeps the stored seed; cleared on purpose removes it — the
       password box's latch, applied to the other secret in the form. */
    #[test]
    fn an_untouched_otp_box_keeps_the_code_and_a_cleared_one_drops_it() {
        let mut app = open_app();
        app.step_group(true);
        app.switch_pane();
        let id = app.entry_cursor.unwrap();
        let url = crate::vault::totp_url("JBSWY3DPEHPK3PXP", "Bank", "me").unwrap();
        app.vault.as_mut().unwrap().set_otp(&id, Some(&url)).unwrap();

        // An edit that never looks at the box keeps it.
        app.open_edit_form();
        assert!(app.form.as_ref().unwrap().had_otp, "the form did not see the code");
        app.form_insert('x'); // types into the title
        app.submit_form();
        let entry = app.selected_entry().unwrap();
        assert!(crate::vault::raw_otp(&entry).is_some(), "the code was dropped");

        // Touching it and leaving it empty removes it.
        app.open_edit_form();
        app.form.as_mut().unwrap().field = FormField::Otp;
        app.form_insert('q');
        app.form_backspace();
        app.submit_form();
        let entry = app.selected_entry().unwrap();
        assert!(crate::vault::raw_otp(&entry).is_none(), "the code survived");
        // The earlier save's flash is still up, so drain before reading.
        app.expire_now();
        assert!(app.stage.contains("removed"), "{}", app.stage);
    }

    /* Pointing the session at a vault used to last exactly as long as the
       session. A vault that opens is written into the config, once, and the
       flash says so rather than editing a dotfile in silence. */
    #[test]
    fn an_opened_vault_becomes_the_default_for_next_time() {
        let (mut app, tmp) = locked_app_with_db("pw");
        let config = temp_path("config");
        std::fs::write(&config.0, "lock_timeout = 90\n").unwrap();
        app.config_file = Some(config.0.clone());
        app.configured_db = None;

        let mut password = b"pw".to_vec();
        app.try_unlock(&mut password, None);
        assert!(app.vault.is_some(), "{}", app.stage);

        let text = std::fs::read_to_string(&config.0).unwrap();
        assert!(text.contains(&tmp.0.display().to_string()), "{text}");
        assert!(text.contains("lock_timeout = 90"), "the file was rewritten: {text}");
        app.expire_now();
        assert!(app.stage.contains("remembered"), "{}", app.stage);

        /* Already the configured vault: nothing is written and nothing is
           said, or every unlock would narrate a file that did not change. */
        let before = std::fs::metadata(&config.0).unwrap().len();
        app.lock_now();
        let mut password = b"pw".to_vec();
        app.try_unlock(&mut password, None);
        assert_eq!(std::fs::metadata(&config.0).unwrap().len(), before);
    }

    /* The picker walks a real directory: folders step in, vaults are chosen,
       and choosing one points the session at it and moves to the password. */
    #[test]
    fn the_picker_walks_folders_and_chooses_a_vault() {
        let dir = std::env::temp_dir().join(format!("sennel-pick-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Vaults")).unwrap();
        std::fs::write(dir.join("Vaults").join("personal.kdbx"), b"x").unwrap();
        std::fs::write(dir.join("loose.txt"), b"x").unwrap();

        let mut app = App::new();
        app.unlock_file = dir.display().to_string();
        app.open_browse();
        {
            let browse = app.browse.as_ref().expect("the picker did not open");
            let names: Vec<&str> = browse.shown().iter().map(|r| r.name.as_str()).collect();
            assert_eq!(names, ["Vaults"], "only folders and vaults are listed");
        }

        // Enter on a folder steps in rather than choosing it.
        app.browse_choose();
        assert!(app.browse.is_some(), "a folder closed the picker");
        assert!(app.db_path.is_none(), "a folder was taken as a vault");
        {
            let browse = app.browse.as_ref().unwrap();
            assert_eq!(browse.shown().len(), 1);
            assert!(browse.dir.ends_with("Vaults"));
        }

        // Enter on a vault takes it and hands the keys to the password box.
        app.browse_choose();
        assert!(app.browse.is_none(), "choosing left the picker open");
        assert_eq!(app.db_path, Some(dir.join("Vaults").join("personal.kdbx")));
        assert!(app.unlock_file.ends_with("personal.kdbx"), "{}", app.unlock_file);
        assert_eq!(app.unlock_field, UnlockField::Password);

        // And ← climbs back out of a folder.
        app.open_browse();
        let before = app.browse.as_ref().unwrap().dir.clone();
        app.browse_up();
        assert_ne!(app.browse.as_ref().unwrap().dir, before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /* The claim in the README, pinned: a lock leaves no typed secret behind,
       and `String::clear` — which only moves the length — is not enough. The
       test reads the buffer the string still owns. */
    #[test]
    fn locking_zeroizes_the_typed_secrets() {
        let mut app = open_app();
        app.unlock_password = "master-secret".into();
        app.unlock_confirm = "master-secret".into();
        app.unlock_keyfile = "/keys/secret.key".into();
        /* Capacity survives a zeroize, so the bytes behind the empty string
           are readable from the test — which is the point. */
        let (ptr, cap) = (app.unlock_password.as_ptr(), app.unlock_password.capacity());
        app.lock_now();
        assert!(app.unlock_password.is_empty());
        let bytes = unsafe { std::slice::from_raw_parts(ptr, cap) };
        assert!(
            !bytes.windows(6).any(|w| w == b"secret"),
            "the master password survived the lock in freed memory"
        );
        assert!(app.unlock_confirm.is_empty());
        assert!(app.unlock_keyfile.is_empty());
    }

    /* Same promise for the form: cancelling or saving drops it, and a
       generated password must not be left intact in the allocation. */
    #[test]
    fn dropping_the_form_zeroizes_what_was_typed_in_it() {
        let mut app = open_app();
        app.step_group(true);
        app.open_add_form();
        let form = app.form.as_mut().unwrap();
        form.password = "generated-secret".into();
        form.otp = "JBSWY3DPEHPK3PXP".into();
        form.notes = "recovery-secret".into();
        let (ptr, cap) = (form.password.as_ptr(), form.password.capacity());
        app.cancel_form();
        let bytes = unsafe { std::slice::from_raw_parts(ptr, cap) };
        assert!(
            !bytes.windows(6).any(|w| w == b"secret"),
            "a cancelled form left its password in memory"
        );
    }

    /* `^t` walks the shipped palettes and writes the landing spot back, so a
       theme picked by looking at it survives the session that picked it. */
    #[test]
    fn cycling_the_theme_remembers_where_it_landed() {
        let mut app = open_app();
        let config = temp_path("theme");
        std::fs::write(&config.0, "lock_timeout = 90\n").unwrap();
        app.config_file = Some(config.0.clone());

        assert_eq!(app.theme, crate::theme::WARM);
        app.cycle_theme();
        assert_ne!(app.theme, crate::theme::WARM, "^t did not move");
        let landed = app.theme.name();
        assert!(app.stage.contains(landed), "{}", app.stage);

        let text = std::fs::read_to_string(&config.0).unwrap();
        assert!(text.contains(&format!("theme = \"{landed}\"")), "{text}");
        assert!(text.contains("lock_timeout = 90"), "the file was rewritten: {text}");

        /* Round the houses and back: the walk covers every shipped palette
           and returns, so no theme is reachable only by editing a file. */
        let mut seen = vec![app.theme.name()];
        // One press per remaining palette lands back where it started.
        for _ in 1..crate::theme::BUILT_INS.len() {
            app.cycle_theme();
            seen.push(app.theme.name());
        }
        assert_eq!(app.theme, crate::theme::WARM, "the cycle did not wrap");
        for (name, _) in crate::theme::BUILT_INS {
            if name != "warm" {
                assert!(seen.contains(&name), "{name} is not reachable by ^t");
            }
        }
    }

    /* A `[colors]` table outlives the walk: `^t` writes the base palette down
       and the overrides go on repainting it, so the screen the user stopped
       on is not the screen the next launch draws unless they are told. */
    #[test]
    fn cycling_a_repainted_theme_says_what_is_still_repainting_it() {
        let mut app = open_app();
        app.config_file = None;
        app.theme_overridden = true;
        app.cycle_theme();
        assert!(app.stage.contains("[colors]"), "{}", app.stage);

        // And a theme nobody repainted says nothing about it.
        let mut plain = open_app();
        plain.config_file = None;
        plain.cycle_theme();
        assert!(!plain.stage.contains("[colors]"), "{}", plain.stage);
    }

    /* --no-config asked for the file to be left out of the run, so the theme
       still switches and nothing is written. */
    #[test]
    fn cycling_without_a_config_switches_and_says_nothing_about_saving() {
        let mut app = open_app();
        app.config_file = None;
        app.cycle_theme();
        assert_ne!(app.theme, crate::theme::WARM);
        assert!(!app.stage.contains("remembered"), "{}", app.stage);
    }

    /* ---- Undo depth ---- */

    /* The case one slot could not cover: a mistake noticed a few keystrokes
       too late. `u` walks back through the session, newest first. */
    #[test]
    fn u_walks_back_through_several_changes() {
        let mut app = open_app();
        app.step_group(true);
        let id = app.entry_cursor.unwrap();
        let before = app.vault.as_ref().unwrap().get_entry(&id).unwrap().title().to_string();

        // Three changes, then three undos.
        app.open_edit_form();
        app.form.as_mut().unwrap().title = "first-edit".into();
        app.submit_form();
        app.open_edit_form();
        app.form.as_mut().unwrap().title = "second-edit".into();
        app.submit_form();
        app.ask_delete_entry();
        app.confirm = None;
        app.confirm_delete_entry(id);
        assert_eq!(app.undo.len(), 3, "the stack did not grow");

        let title = |app: &App| {
            app.vault.as_ref().unwrap().get_entry(&id).unwrap().title().to_string()
        };
        app.undo_last(); // out of the bin
        assert!(!app.vault.as_ref().unwrap().is_recycled(&id));
        app.undo_last(); // back to first-edit
        assert_eq!(title(&app), "first-edit");
        app.undo_last(); // back to where it started
        assert_eq!(title(&app), before);
        assert!(app.undo.is_empty());

        /* Drain first: the flash queue is bounded, so a message sent while
           six others are waiting is dropped rather than queued, and the
           assertion below would be reading somebody else's sentence. */
        for _ in 0..12 {
            app.expire_now();
        }
        // And the bottom of the stack says so rather than undoing twice.
        app.undo_last();
        assert_eq!(title(&app), before);
        assert!(app.stage.contains("nothing to undo"), "{}", app.stage);
    }

    /* Each Delete snapshot holds a whole entry, secrets included, so the
       stack is bounded — and dropping the oldest is what zeroizes it. */
    #[test]
    fn the_undo_stack_stops_growing() {
        let mut app = open_app();
        app.step_group(true);
        let id = app.entry_cursor.unwrap();
        for n in 0..App::UNDO_DEPTH + 5 {
            app.open_edit_form();
            app.form.as_mut().unwrap().title = format!("edit-{n}");
            app.submit_form();
        }
        assert_eq!(app.undo.len(), App::UNDO_DEPTH, "the stack is unbounded");
        /* The oldest steps fell off, so the walk back stops at the oldest
           one kept rather than at the original title. */
        for _ in 0..App::UNDO_DEPTH {
            app.undo_last();
        }
        let title = app.vault.as_ref().unwrap().get_entry(&id).unwrap().title().to_string();
        assert_eq!(title, "edit-4", "{title}");
    }

    /* A stack of snapshots is a pile of plaintext passwords, so it cannot
       outlive the screen that was locked. */
    #[test]
    fn locking_empties_the_undo_stack() {
        let mut app = open_app();
        app.step_group(true);
        app.open_edit_form();
        app.form.as_mut().unwrap().title = "edited".into();
        app.submit_form();
        assert!(!app.undo.is_empty());
        app.lock();
        assert!(app.undo.is_empty(), "snapshots survived the lock");
    }

    /* The bar names the next step and how many are behind it, so `u` never
       surprises. */
    #[test]
    fn the_bar_counts_what_is_left_to_undo() {
        let mut app = open_app();
        app.step_group(true);
        assert_eq!(app.undo_note(), None);
        app.open_edit_form();
        app.form.as_mut().unwrap().title = "once".into();
        app.submit_form();
        let note = app.undo_note().unwrap();
        assert!(note.contains("undo: edit"), "{note}");
        assert!(!note.contains('+'), "one step advertised a queue: {note}");

        app.open_edit_form();
        app.form.as_mut().unwrap().title = "twice".into();
        app.submit_form();
        assert!(app.undo_note().unwrap().ends_with(" +1"), "{:?}", app.undo_note());
    }

    /* ---- Change the master password ---- */

    /* The whole point: after a rekey the file opens with the new password and
       refuses the old one. Through a real file, because an in-memory swap
       that never reaches disk is the failure this feature would have. */
    #[test]
    fn changing_the_master_password_rewrites_the_file_under_it() {
        let tmp = temp_path("rekey");
        let mut app = App::new();
        app.db_path = Some(tmp.0.clone());
        app.unlock_new = true;
        app.unlock_confirm = "first-pw".into();
        let mut typed = b"first-pw".to_vec();
        app.try_unlock(&mut typed, None);
        assert!(app.vault.is_some(), "the vault did not open: {}", app.stage);
        let root = app.vault.as_ref().unwrap().root_id();
        app.vault.as_mut().unwrap().create_entry(&root, "mail", "u", "p", "", "").unwrap();
        app.persist();

        app.open_rekey();
        assert!(app.rekey.is_some(), "the prompt did not open: {}", app.stage);
        for c in "second-pw".chars() {
            app.rekey_insert(c);
        }
        app.rekey_next_field();
        for c in "second-pw".chars() {
            app.rekey_insert(c);
        }
        app.submit_rekey();
        assert!(app.rekey.is_none(), "the prompt stayed open: {}", app.stage);
        app.expire_now();
        assert!(app.stage.contains("changed"), "{}", app.stage);

        // The file on disk is the new password's, and only the new one's.
        assert!(crate::vault::Vault::open(&tmp.0, "second-pw", None).is_ok());
        assert!(
            crate::vault::Vault::open(&tmp.0, "first-pw", None).is_err(),
            "the old password still opens the vault"
        );
        // And the session kept working against the file it just rewrote.
        let entry = app.entry_rows()[0];
        app.vault.as_mut().unwrap().update_entry(&entry, "mail2", "u", None, "", "").unwrap();
        app.persist();
        assert!(!app.stage.contains("cannot"), "{}", app.stage);
    }

    /* Typed twice, and the prompt says so rather than setting a password
       nobody meant: the retype is the only check there will ever be. */
    #[test]
    fn a_mistyped_retype_keeps_the_prompt_and_the_old_password() {
        let tmp = temp_path("rekey-differ");
        let mut app = App::new();
        app.db_path = Some(tmp.0.clone());
        app.unlock_new = true;
        app.unlock_confirm = "first-pw".into();
        let mut typed = b"first-pw".to_vec();
        app.try_unlock(&mut typed, None);

        app.open_rekey();
        for c in "second-pw".chars() {
            app.rekey_insert(c);
        }
        app.rekey_next_field();
        for c in "secnod-pw".chars() {
            app.rekey_insert(c);
        }
        app.submit_rekey();
        let rekey = app.rekey.as_ref().expect("the prompt closed on a mismatch");
        assert_eq!(rekey.password, "second-pw", "the first box was cleared too");
        assert!(rekey.confirm.is_empty(), "the retype box kept the typo");
        assert_eq!(rekey.field, crate::app::RekeyField::Again, "focus did not go back");
        app.expire_now();
        assert!(app.stage.contains("differ"), "{}", app.stage);
        // Nothing was written: the old password still opens the file.
        assert!(crate::vault::Vault::open(&tmp.0, "first-pw", None).is_ok());
    }

    /* Empty is not a password, and `esc` leaves the old one alone. */
    #[test]
    fn an_empty_or_cancelled_rekey_changes_nothing() {
        let tmp = temp_path("rekey-empty");
        let mut app = App::new();
        app.db_path = Some(tmp.0.clone());
        app.unlock_new = true;
        app.unlock_confirm = "first-pw".into();
        let mut typed = b"first-pw".to_vec();
        app.try_unlock(&mut typed, None);

        app.open_rekey();
        app.submit_rekey();
        assert!(app.rekey.is_some(), "an empty password closed the prompt");
        app.expire_now();
        assert!(app.stage.contains("empty"), "{}", app.stage);

        app.close_rekey();
        assert!(app.rekey.is_none());
        assert!(crate::vault::Vault::open(&tmp.0, "first-pw", None).is_ok());
    }

    /* The prompt holds the only plaintext copy of what is about to become the
       key to everything, so locking has to take it with everything else. */
    #[test]
    fn locking_takes_a_half_typed_master_password_with_it() {
        let mut app = open_app();
        app.rekey = Some(crate::app::Rekey::default());
        for c in "half-typed".chars() {
            app.rekey_insert(c);
        }
        app.lock();
        assert!(app.rekey.is_none(), "the prompt survived the lock");
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
        assert_eq!(made.title(), "savings");
        assert_eq!(made.username(), "me");
        assert_eq!(made.password(), "pw");
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
        app.next_form_field(true); // url
        app.next_form_field(true); // otp, also empty and untouched
        app.next_form_field(true); // notes
        for c in "note".chars() {
            app.form_insert(c);
        }
        app.submit_form();
        let rows = app.entry_rows();
        let kept = app.vault.as_ref().unwrap().get_entry(&rows[0]).unwrap();
        assert_eq!(kept.password(), "p", "empty edit box overwrote the secret");
        assert_eq!(kept.notes(), "note");
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
        assert_eq!(cleared.password(), "", "backspace-to-empty did not clear");
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
        assert_eq!(app.vault.as_ref().unwrap().get_entry(&rows[0]).unwrap().title(), "checking");
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
        let Confirm::DeleteEntry { id, title, .. } = app.confirm.clone().unwrap() else {
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
        seed.save_as(&tmp.0, "pw", None).unwrap();
        let mut app = App::new();
        app.set_db_path(Some(tmp.0.clone()));
        let mut pw = "pw".to_owned().into_bytes();
        app.try_unlock(&mut pw, None);
        app.open_add_form();
        for c in "bankcard".chars() {
            app.form_insert(c);
        }
        app.submit_form();
        assert!(!app.working(), "autosave left the vault dirty");
        let reopened = Vault::open(&tmp.0, "pw", None).unwrap();
        let root = reopened.root_id();
        assert_eq!(reopened.entries_in(&root).len(), 1);
        assert_eq!(reopened.entries_in(&root)[0].title(), "bankcard");
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
            app.vault.as_ref().unwrap().get_group(id).unwrap().name == "Cards"
        }));
        let cursor = app.group_cursor.unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().get_group(&cursor).unwrap().name,
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

    /* A group with entries in it used to be refused. It now goes to the bin
       whole and comes back whole, which is why the refusal could go. */
    #[test]
    fn d_on_a_full_group_bins_the_subtree_and_u_brings_it_back() {
        let mut app = open_app();
        app.step_group(true); // Banks holds an entry
        let banks = app.group_cursor.unwrap();
        let entry = app.entry_rows()[0];
        app.ask_delete_group();
        let Confirm::DeleteGroup { id, forever, .. } = app.confirm.clone().unwrap() else {
            panic!("a full group did not open the confirm");
        };
        assert!(!forever, "a live group asked the permanent question");
        app.confirm = None;
        app.confirm_delete_group(id);

        let vault = app.vault.as_ref().unwrap();
        assert!(vault.in_recycle_bin(&banks), "the group is not in the bin");
        assert!(vault.is_recycled(&entry), "the entry did not ride along");
        assert!(app.stage.contains("recycle bin"), "{}", app.stage);

        app.undo_last();
        let vault = app.vault.as_ref().unwrap();
        assert!(!vault.in_recycle_bin(&banks), "u left the group in the bin");
        assert!(!vault.is_recycled(&entry), "u left the entry in the bin");
    }

    /* Inside the bin `D` is the real delete, and it says so rather than
       promising an undo it does not have. */
    #[test]
    fn d_inside_the_bin_asks_the_permanent_question() {
        let mut app = open_app();
        app.step_group(true);
        let id = app.entry_cursor.unwrap();
        app.ask_delete_entry();
        app.confirm = None;
        app.confirm_delete_entry(id); // to the bin
        app.undo.clear();

        // Onto the binned row, which lives under the bin group now.
        app.entry_cursor = Some(id);
        app.group_cursor = app.vault.as_ref().unwrap().parent_group_of_entry(&id);
        app.ask_delete_entry();
        let Confirm::DeleteEntry { id, forever, .. } = app.confirm.clone().unwrap() else {
            panic!("no confirm in the bin");
        };
        assert!(forever, "the bin asked the recoverable question");
        app.confirm = None;
        app.confirm_delete_entry(id);
        assert!(app.vault.as_ref().unwrap().get_entry(&id).is_none(), "it survived");
        // The first delete's flash is still showing; this is the next one.
        app.expire_now();
        assert!(app.stage.contains("for good"), "{}", app.stage);
    }

    #[test]
    fn d_on_an_empty_group_asks_then_y_deletes() {
        let mut app = open_app();
        app.step_group(true); // Banks
        let banks = app.group_cursor.unwrap();
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
        /* Still in the tree, because the bin is a group like any other — but
           under the bin, which is what the pane and KeePassXC both show. */
        assert!(app.vault.as_ref().unwrap().in_recycle_bin(&id));
        let under_banks: Vec<String> = app
            .vault
            .as_ref()
            .unwrap()
            .groups_in(&banks)
            .iter()
            .map(|g| g.name.clone())
            .collect();
        assert!(!under_banks.contains(&"Empty".to_string()), "{under_banks:?}");
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
            .find(|id| app.vault.as_ref().unwrap().get_group(id).unwrap().name == "Work")
            .unwrap();
        let under_work = app.vault.as_ref().unwrap().groups_in(&work);
        assert_eq!(under_work.len(), 1, "Banks did not land under Work");
        assert_eq!(under_work[0].name, "Banks");
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
                    .title()
                    .to_string()
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
        /* Stamp every entry but 'apple' oldest directly: the editor is the
           only mutator in prod, and a test should not depend on clock ticks. */
        let other: Vec<_> = app
            .entry_rows()
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, id)| *id)
            .collect();
        let vault = app.vault.as_mut().unwrap();
        for id in other {
            vault
                .db_mut()
                .entry_mut(id)
                .unwrap()
                .edit(|e| e.times.last_modification = Some(keepass::db::Times::epoch()));
        }
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
            app.vault.as_ref().unwrap().get_entry(&hit).unwrap().title(),
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
            .password().to_string()
    }

    /* u brings a deleted entry back, under the group it came from. */
    #[test]
    fn u_restores_a_deleted_entry() {
        let mut app = open_app();
        app.step_group(true); // onto Banks
        let id = app.entry_cursor.unwrap();
        app.ask_delete_entry();
        let Some(Confirm::DeleteEntry { .. }) = app.confirm else {
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
                app.vault.as_ref().unwrap().get_entry(id).unwrap().title() == "fresh"
            }),
            "the add did not land"
        );
        app.undo_last();
        let titles: Vec<String> = app
            .entry_rows()
            .iter()
            .map(|id| app.vault.as_ref().unwrap().get_entry(id).unwrap().title().to_string())
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
        assert_eq!(app.vault.as_ref().unwrap().get_group(&banks).unwrap().name, "Savings");
        app.undo_last();
        assert_eq!(
            app.vault.as_ref().unwrap().get_group(&banks).unwrap().name,
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
