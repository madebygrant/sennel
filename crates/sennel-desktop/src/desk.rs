// What the window's commands share, and the logic behind each of them. Kept free of Tauri so the
// tests drive it directly. Secrets cross to the webview only on `reveal`; copying stays here.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use keepass::db::{EntryId, GroupId};
use serde::{Deserialize, Serialize};
use sennel_core::clipboard::Board;
use sennel_core::config;
use sennel_core::search::Searcher;
use sennel_core::sort::SortOrder;
use sennel_core::session::{
    Cut, Delete, EntryError, EntryInput, EntryTarget, Extract, Paste, QuickError, Reparent, Resolve, SaveNow, Saved,
    Sealing, Session, Undo, UnlockError, Undone, Unlocked,
};
use sennel_core::touchid::{Refused, Sealed};
use sennel_core::vault::{EntryExt, Extra};
use zeroize::{Zeroize, Zeroizing};

use crate::settings::Settings;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// One line for the status bar.
#[derive(Serialize, Clone, Debug)]
pub struct Note {
    pub level: Level,
    pub text: String,
}

fn info(text: impl Into<String>) -> Note {
    Note { level: Level::Info, text: text.into() }
}

fn warn(text: impl Into<String>) -> Note {
    Note { level: Level::Warn, text: text.into() }
}

fn error(text: impl Into<String>) -> Note {
    Note { level: Level::Error, text: text.into() }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub open: bool,
    pub db: Option<String>,
    pub vault_name: Option<String>,
    pub creates: bool,
    pub recent: Vec<String>,
    pub touch_id: bool,
    pub yubikey: Option<String>,
    pub dirty: bool,
    pub conflict: bool,
    pub clears_in: Option<u64>,
    pub undo: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct GroupRow {
    pub id: String,
    pub name: String,
    pub depth: usize,
    pub entries: usize,
    pub bin: bool,
}

#[derive(Serialize, Debug)]
pub struct EntryRow {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub id: String,
    pub group: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub expires: String,
    pub has_password: bool,
    pub has_otp: bool,
    pub extras: usize,
    pub recycled: bool,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FieldRow {
    pub name: String,
    pub file: bool,
    pub secret: bool,
    /// Withheld when secret: a protected field crosses to the webview only on reveal.
    pub value: Option<String>,
    pub bytes: Option<usize>,
}

#[derive(Serialize, Debug)]
pub struct AuditRow {
    pub id: String,
    pub title: String,
    pub issue: String,
}

#[derive(Serialize, Debug)]
pub struct VersionRow {
    pub at: usize,
    pub title: String,
    pub username: String,
    pub modified: String,
}

/// The entry form, as typed. `password` and `otp` are null when their box was never touched.
#[derive(Deserialize, Debug)]
pub struct EntryForm {
    pub title: String,
    pub username: String,
    pub password: Option<String>,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub expires: String,
    pub otp: Option<String>,
}

impl Drop for EntryForm {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            p.zeroize();
        }
        if let Some(o) = self.otp.as_mut() {
            o.zeroize();
        }
    }
}

#[derive(Serialize, Debug)]
pub struct Reply {
    pub notes: Vec<Note>,
    /// The entry or group an action landed on, for the window to select.
    pub select: Option<String>,
    /// False when the action was refused and a form should stay open.
    pub ok: bool,
}

impl Reply {
    fn notes(notes: Vec<Note>) -> Self {
        Reply { notes, select: None, ok: true }
    }

    fn refused(note: Note) -> Self {
        Reply { notes: vec![note], select: None, ok: false }
    }

    fn one(note: Note) -> Self {
        Reply::notes(vec![note])
    }
}

// The last rows asked for: revision, group and needle, then the answer.
type RowsKey = (u64, Option<String>, Option<String>);

pub struct Desk {
    session: Mutex<Session<Sealed>>,
    db: Mutex<Option<PathBuf>>,
    recent: Mutex<Vec<PathBuf>>,
    /// None in tests, which must not touch the system clipboard.
    board: Option<Board>,
    settings: Settings,
    rows: Mutex<(Option<RowsKey>, Vec<EntryId>, Searcher)>,
    // Says "touch your key" before a write that blocks on one, since nothing else would.
    prompt: Option<Box<dyn Fn(Note) + Send + Sync>>,
}

pub fn entry_id(text: &str) -> Result<EntryId, String> {
    uuid::Uuid::parse_str(text).map(EntryId::from_uuid).map_err(|_| "not an entry id".to_string())
}

pub fn group_id(text: &str) -> Result<GroupId, String> {
    uuid::Uuid::parse_str(text).map(GroupId::from_uuid).map_err(|_| "not a group id".to_string())
}

fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

impl Desk {
    pub fn new(settings: Settings, board: Option<Board>) -> Self {
        let mut session = Session::new();
        session.set_backups(settings.backups, settings.backup_dir.clone());
        session.set_ssh_agent(settings.ssh_agent, settings.ssh_lifetime);
        session.set_lock_timeout(settings.lock_timeout);
        session.touch_id = settings.touch_id;
        let db = settings.db.as_deref().or(settings.recent.first().map(PathBuf::as_path)).map(config::absolute);
        session.aim(db.as_deref());
        Desk {
            session: Mutex::new(session),
            db: Mutex::new(db),
            recent: Mutex::new(settings.recent.clone()),
            board,
            settings,
            rows: Mutex::new((None, Vec::new(), Searcher::new())),
            prompt: None,
        }
    }

    pub fn with_prompt(mut self, prompt: impl Fn(Note) + Send + Sync + 'static) -> Self {
        self.prompt = Some(Box::new(prompt));
        self
    }

    fn ask_for_key(&self, s: &Session<Sealed>, what: &str) {
        let keyed = s.vault().is_some_and(sennel_core::vault::Vault::has_challenge);
        if let (true, Some(prompt)) = (keyed, &self.prompt) {
            prompt(info(format!("touch your key {what}…")));
        }
    }

    fn ask_for_key_to_unlock(&self) {
        if let (Some(spec), Some(prompt)) = (&self.settings.yubikey, &self.prompt) {
            prompt(info(format!("touch your key ({spec}) to unlock…")));
        }
    }

    /// Whether quitting now would lose work: a save that failed or was refused.
    pub fn unsaved(&self) -> bool {
        let s = self.session();
        s.is_dirty() || s.in_conflict()
    }

    // A poisoned lock means a command panicked mid-way; the session is still the best state there is.
    pub fn session(&self) -> MutexGuard<'_, Session<Sealed>> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn db(&self) -> Option<PathBuf> {
        self.db.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn status(&self) -> Status {
        let db = self.db();
        let s = self.session();
        let undo = s.undo_steps().last().map(|step| match step {
            Undo::Edit { before, .. } => format!("edit of {}", before.title()),
            Undo::Delete { before, .. } | Undo::Recycle { before, .. } => {
                format!("restore {}", before.title())
            }
            Undo::RecycleGroup { title, .. } => format!("restore {title}"),
            Undo::AddEntry { title, .. } => format!("remove {title}"),
            Undo::Rename { before, .. } => format!("name {before}"),
        });
        Status {
            open: s.is_open(),
            vault_name: db.as_deref().filter(|_| s.is_open()).map(name_of),
            creates: db.as_ref().is_some_and(|p| !p.is_file()),
            db: db.map(|p| p.display().to_string()),
            recent: self.recent.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|p| p.display().to_string()).collect(),
            touch_id: s.quick_here(),
            yubikey: self.settings.yubikey.as_ref().map(ToString::to_string),
            dirty: s.is_dirty(),
            conflict: s.in_conflict(),
            clears_in: self.board.as_ref().and_then(Board::clears_in),
            undo,
        }
    }

    /// Points the window at a vault file, typed or picked from the library.
    pub fn choose(&self, typed: &str) -> Result<Status, String> {
        let typed = typed.trim();
        if config::is_other_home(typed) {
            return Err("another user's ~ cannot be resolved · type the full path".into());
        }
        let path = (!typed.is_empty()).then(|| config::absolute(&config::expand(typed)));
        self.session().aim(path.as_deref());
        *self.db.lock().unwrap_or_else(|e| e.into_inner()) = path;
        Ok(self.status())
    }

    pub fn touch(&self) {
        self.session().touch();
    }

    // The password arrives as a JS string, which cannot be wiped on that side; the bytes here are.
    pub fn unlock(&self, mut password: String, key_file: Option<String>, confirm: Option<String>) -> Reply {
        let mut bytes = password.as_bytes().to_vec();
        password.zeroize();
        let confirm = confirm.map(Zeroizing::new);
        let Some(path) = self.db() else {
            bytes.zeroize();
            return Reply::one(warn("choose a vault file first"));
        };
        let key = match self.read_key(key_file.as_deref()) {
            Ok(key) => key,
            Err(note) => {
                bytes.zeroize();
                return Reply::one(note);
            }
        };
        let creating = !path.is_file();
        if creating && confirm.is_none() {
            bytes.zeroize();
            return Reply::one(warn("no vault there yet · type the password twice to create it"));
        }
        let again = confirm.as_deref().filter(|_| creating).map(String::as_bytes);
        self.ask_for_key_to_unlock();
        let result = self.session().unlock(
            &path,
            &mut bytes,
            key.as_deref().map(|k| k.as_slice()),
            self.settings.yubikey.as_ref(),
            again,
        );
        self.after_unlock(&path, result.map_err(QuickError::Unlock))
    }

    pub fn quick_unlock(&self, key_file: Option<String>) -> Reply {
        let Some(path) = self.db() else {
            return Reply::one(warn("choose a vault file first"));
        };
        let key = match self.read_key(key_file.as_deref()) {
            Ok(key) => key,
            Err(note) => return Reply::one(note),
        };
        self.ask_for_key_to_unlock();
        let result = self.session().quick_unlock(key.as_deref().map(|k| k.as_slice()), self.settings.yubikey.as_ref());
        self.after_unlock(&path, result)
    }

    fn read_key(&self, key_file: Option<&str>) -> Result<Option<Zeroizing<Vec<u8>>>, Note> {
        match key_file.map(str::trim).filter(|k| !k.is_empty()) {
            None => Ok(None),
            Some(path) => std::fs::read(config::expand(path))
                .map(|bytes| Some(Zeroizing::new(bytes)))
                .map_err(|e| error(format!("cannot read key file {path} · {e}"))),
        }
    }

    fn after_unlock(&self, path: &Path, result: Result<Unlocked, QuickError>) -> Reply {
        let unlocked = match result {
            Ok(unlocked) => unlocked,
            Err(QuickError::Nothing) => return Reply::one(warn("nothing sealed for this vault · type the password")),
            Err(QuickError::Refused(Refused::Again(why))) => {
                return Reply::one(warn(format!("Touch ID {why} · try again, or type the password")));
            }
            Err(QuickError::Refused(Refused::Void(why))) => {
                return Reply::one(warn(format!("Touch ID cannot open this any more · {why} · type the password")));
            }
            Err(QuickError::Unlock(e)) => {
                return Reply::one(match e {
                    UnlockError::Empty => warn("empty password"),
                    UnlockError::NotText => error("password has bytes that are not text"),
                    UnlockError::Mismatch => warn("passwords differ · retype both"),
                    UnlockError::WrongPassword => error("wrong password or key file"),
                    UnlockError::Open(e) => error(format!("cannot open {} · {e}", path.display())),
                });
            }
        };
        let mut notes = Vec::new();
        let agent = unlocked.agent;
        if let Some(first) = agent.problems.first() {
            notes.push(warn(format!("ssh agent: {first}")));
        } else if agent.added > 0 {
            notes.push(info(format!("{} ssh key(s) added to the agent for {}s", agent.added, agent.lifetime)));
        }
        notes.push(info(match unlocked.created {
            true => format!("created {}", name_of(path)),
            false => format!("unlocked {} {}", unlocked.entries, if unlocked.entries == 1 { "entry" } else { "entries" }),
        }));
        if let Sealing::Off(why) = unlocked.sealing {
            notes.push(warn(format!("Touch ID off this session · {why}")));
        }
        if let Some(format) = unlocked.read_only {
            notes.push(error(format!("{format} · read-only · edits cannot be saved")));
        }
        self.remember(path);
        Reply::notes(notes)
    }

    // The same library the terminal app keeps, newest first. Silent on failure: it is bookkeeping.
    fn remember(&self, path: &Path) {
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        let before = recent.clone();
        recent.retain(|p| p != path);
        recent.insert(0, path.to_path_buf());
        recent.truncate(config::RECENT_MAX);
        if *recent != before && self.settings.config_file.is_some() {
            let _ = config::remember_recent(self.settings.config_file.as_deref(), &recent);
        }
    }

    pub fn lock(&self) -> Reply {
        let failed = self.session().lock();
        let mut notes = vec![info("locked")];
        if failed > 0 {
            notes.push(warn(format!("ssh agent: {failed} key(s) not removed · they expire on their own")));
        }
        Reply::notes(notes)
    }

    /// Locks when the vault has sat idle past the timeout. Called by the window's timer thread.
    // Returns the lock's notes, or None while the vault stays open.
    pub fn lock_if_idle(&self, now: Instant) -> Option<Vec<Note>> {
        let mut s = self.session();
        if !s.idle_expired(now) {
            return None;
        }
        let failed = s.lock();
        let mut notes = vec![warn(format!("locked after {} seconds idle", self.settings.lock_timeout))];
        if failed > 0 {
            notes.push(warn(format!("ssh agent: {failed} key(s) not removed · they expire on their own")));
        }
        Some(notes)
    }

    pub fn tree(&self) -> Vec<GroupRow> {
        let s = self.session();
        let Some(vault) = s.vault() else {
            return Vec::new();
        };
        let bin = vault.recycle_bin_id();
        let mut out = Vec::new();
        let mut stack = vec![(vault.root_id(), 0)];
        while let Some((id, depth)) = stack.pop() {
            let Some(group) = vault.get_group(&id) else {
                continue;
            };
            out.push(GroupRow {
                id: id.to_string(),
                name: group.name.clone(),
                depth,
                entries: vault.entries_in(&id).len(),
                bin: Some(id) == bin,
            });
            for child in vault.groups_in(&id).iter().rev() {
                stack.push((child.id(), depth + 1));
            }
        }
        out
    }

    // A group's entries in stored order, or with a needle the whole vault ranked best first. The
    // same rows the terminal app shows, kept until the vault, group or needle moves.
    pub fn entries(&self, group: Option<&str>, needle: Option<&str>) -> Result<Vec<EntryRow>, String> {
        let needle = needle.map(str::trim).filter(|n| !n.is_empty());
        let s = self.session();
        let Some(vault) = s.vault() else {
            return Ok(Vec::new());
        };
        let group = match group {
            Some(g) => group_id(g)?,
            None => vault.root_id(),
        };
        let key = (s.revision(), Some(group.to_string()), needle.map(String::from));
        let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        if rows.0.as_ref() != Some(&key) {
            let ids = sennel_core::search::rows(vault, needle.is_some(), Some(group), needle, SortOrder::Stored, &mut rows.2);
            *rows = (Some(key), ids, std::mem::take(&mut rows.2));
        }
        Ok(rows
            .1
            .iter()
            .filter_map(|id| {
                vault.get_entry(id).map(|e| EntryRow {
                    id: id.to_string(),
                    title: e.title().to_string(),
                    username: e.username().to_string(),
                    url: e.url().to_string(),
                })
            })
            .collect())
    }

    pub fn entry(&self, id: &str) -> Result<EntryView, String> {
        let id = entry_id(id)?;
        let s = self.session();
        let vault = s.vault().ok_or("locked")?;
        let e = vault.get_entry(&id).ok_or("that entry is gone")?;
        let group = vault
            .parent_group_of_entry(&id)
            .map(|g| vault.group_path(&g).into_iter().skip(1).collect::<Vec<_>>().join(" / "))
            .unwrap_or_default();
        Ok(EntryView {
            id: id.to_string(),
            group,
            title: e.title().to_string(),
            username: e.username().to_string(),
            url: e.url().to_string(),
            notes: e.notes().to_string(),
            tags: e.tags.join(", "),
            expires: sennel_core::vault::expires_at(&e).map(|at| at.format("%Y-%m-%d").to_string()).unwrap_or_default(),
            has_password: !e.password().is_empty(),
            has_otp: sennel_core::vault::raw_otp(&e).is_some(),
            extras: sennel_core::vault::extra_rows(&e).len(),
            recycled: vault.is_recycled(&id),
        })
    }

    /// The one path that hands a password to the webview: a reveal the user asked for.
    // Wiped here once Tauri has serialized it; the IPC buffer that carried it is not.
    pub fn reveal(&self, id: &str) -> Result<Zeroizing<String>, String> {
        let id = entry_id(id)?;
        let s = self.session();
        let vault = s.vault().ok_or("locked")?;
        let e = vault.get_entry(&id).ok_or("that entry is gone")?;
        Ok(Zeroizing::new(e.password().to_string()))
    }

    /// One of the fixed fields: password, username, url or otp.
    pub fn copy(&self, id: &str, field: &str) -> Note {
        match self.field_text(id, Field::Fixed(field)) {
            Ok(text) => self.to_board(field, &text),
            Err(why) => warn(why),
        }
    }

    /// A custom field by name, which may share a name with a fixed one.
    pub fn copy_field(&self, id: &str, name: &str) -> Note {
        match self.field_text(id, Field::Custom(name)) {
            Ok(text) => self.to_board(name, &text),
            Err(why) => warn(why),
        }
    }

    // Text the window already holds, a generated or typed password, copied through the same
    // board so it clears like every other copy.
    pub fn copy_text(&self, label: &str, mut text: String) -> Note {
        let note = match text.is_empty() {
            true => warn(format!("{label} is empty")),
            false => self.to_board(label, &text),
        };
        text.zeroize();
        note
    }

    fn field_text(&self, id: &str, field: Field<'_>) -> Result<Zeroizing<String>, String> {
        let id = entry_id(id)?;
        let s = self.session();
        let vault = s.vault().ok_or("locked")?;
        let e = vault.get_entry(&id).ok_or("that entry is gone")?;
        let label = match field {
            Field::Fixed(name) | Field::Custom(name) => name,
        };
        let text = match field {
            Field::Fixed("password") => e.password().to_string(),
            Field::Fixed("username") => e.username().to_string(),
            Field::Fixed("url") => e.url().to_string(),
            Field::Fixed("otp") => {
                sennel_core::vault::totp_now(&e).map(|(code, _)| code).ok_or("no one-time code on this entry")?
            }
            Field::Fixed(other) => return Err(format!("no field {other}")),
            Field::Custom(name) => sennel_core::vault::extra_rows(&e)
                .iter()
                .find_map(|row| match row {
                    Extra::Field { name: n, value, .. } if n == name => Some(value.clone()),
                    _ => None,
                })
                .ok_or_else(|| format!("no field {name}"))?,
        };
        if text.is_empty() {
            return Err(format!("no {label} on this entry"));
        }
        Ok(Zeroizing::new(text))
    }

    fn to_board(&self, label: &str, text: &str) -> Note {
        let Some(board) = &self.board else {
            return info(format!("copied {label}"));
        };
        match board.copy(text) {
            Ok(()) => match board.timeout_secs() {
                Some(secs) => info(format!("copied {label} · clears in {secs}s")),
                None => info(format!("copied {label}")),
            },
            Err(e) => error(e),
        }
    }

    pub fn generate(&self) -> Result<Zeroizing<String>, String> {
        self.settings.generator.make().map(Zeroizing::new)
    }

    // Every change lands on disk before the reply, the autosave the terminal app makes.
    fn saved(&self, s: &mut Session<Sealed>, said: Note) -> Vec<Note> {
        let mut notes = vec![said];
        self.ask_for_key(s, "to save");
        match s.persist(true) {
            Saved::Written | Saved::Locked | Saved::NoFile | Saved::Deferred(_) => {}
            Saved::Conflict => notes.push(error("vault changed on disk · merge, overwrite or reload")),
            Saved::Failed(e) => notes.push(error(format!("save failed · {e} · kept in memory"))),
        }
        notes
    }

    pub fn save_entry(&self, target: Option<&str>, group: Option<&str>, form: &EntryForm) -> Result<Reply, String> {
        let target = match target {
            Some(id) => EntryTarget::Edit(entry_id(id)?),
            None => EntryTarget::Add(group.map(group_id).transpose()?),
        };
        let input = EntryInput {
            title: &form.title,
            username: &form.username,
            password: form.password.as_deref(),
            url: &form.url,
            notes: &form.notes,
            tags: &form.tags,
            expires: &form.expires,
            otp: form.otp.as_deref(),
        };
        let mut s = self.session();
        let saved = match s.save_entry(target, &input) {
            Ok(saved) => saved,
            Err(e) => {
                return Ok(Reply::refused(warn(match e {
                    EntryError::NoTitle => "a title is the only must".to_string(),
                    EntryError::Expiry(why) | EntryError::Otp(why) => why,
                    EntryError::NoGroup => "no group selected".to_string(),
                    EntryError::Vault(e) => format!("cannot save · {e}"),
                })));
            }
        };
        let note = match saved.otp {
            Some(true) => " · one-time code set",
            Some(false) => " · one-time code removed",
            None => "",
        };
        let said = match target {
            EntryTarget::Add(_) => info(format!("entry added{note}")),
            EntryTarget::Edit(_) => info(format!("entry saved{note}")),
        };
        let select = saved.id.map(|id| id.to_string());
        Ok(Reply { notes: self.saved(&mut s, said), select, ok: true })
    }

    pub fn delete_entry(&self, id: &str) -> Result<Reply, String> {
        let id = entry_id(id)?;
        let mut s = self.session();
        Ok(Reply::notes(match s.delete_entry(id) {
            Ok(true) => self.saved(&mut s, warn("entry deleted for good · undo restores it")),
            Ok(false) => self.saved(&mut s, info("entry moved to the recycle bin · undo restores it")),
            Err(Delete::Missing) => Vec::new(),
            Err(Delete::Vault(e)) => vec![warn(format!("cannot delete · {e}"))],
        }))
    }

    pub fn move_entry(&self, id: &str, group: &str) -> Result<Reply, String> {
        self.paste(Cut::Entry(entry_id(id)?), group_id(group)?)
    }

    pub fn move_group(&self, id: &str, group: &str) -> Result<Reply, String> {
        self.paste(Cut::Group(group_id(id)?), group_id(group)?)
    }

    fn paste(&self, cut: Cut, target: GroupId) -> Result<Reply, String> {
        let mut s = self.session();
        s.arm_cut(cut);
        let notes = match s.paste(Some(target)) {
            Ok(Cut::Entry(_)) => self.saved(&mut s, info("entry moved")),
            Ok(Cut::Group(_)) => self.saved(&mut s, info("group moved")),
            Err(Paste::Locked | Paste::Nothing | Paste::NoGroup) => Vec::new(),
            Err(Paste::Vault(e)) => {
                s.drop_cut();
                vec![warn(format!("cannot move · {e}"))]
            }
        };
        Ok(Reply::notes(notes))
    }

    pub fn reparent(&self, id: &str, deeper: bool) -> Result<Reply, String> {
        let id = group_id(id)?;
        let mut s = self.session();
        Ok(Reply::notes(match s.reparent_group(id, deeper) {
            Ok(()) => self.saved(&mut s, info("group moved")),
            Err(Reparent::Missing) => Vec::new(),
            Err(Reparent::Root) => vec![info("the root group cannot move")],
            Err(Reparent::InBin) => vec![info("that group is in the recycle bin")],
            Err(Reparent::NothingAbove) => vec![info("nothing above it to go into")],
            Err(Reparent::AtTop) => vec![info("already at the top")],
            Err(Reparent::Vault(e)) => vec![warn(format!("cannot move · {e}"))],
        }))
    }

    pub fn add_group(&self, parent: &str, name: &str) -> Result<Reply, String> {
        if name.trim().is_empty() {
            return Ok(Reply::one(warn("a name is the only must")));
        }
        let parent = group_id(parent)?;
        let mut s = self.session();
        Ok(match s.add_group(Some(parent), name) {
            Ok(id) => Reply { notes: self.saved(&mut s, info("group added")), select: Some(id.to_string()), ok: true },
            Err(e) => Reply::one(warn(format!("cannot add · {e}"))),
        })
    }

    pub fn rename_group(&self, id: &str, name: &str) -> Result<Reply, String> {
        if name.trim().is_empty() {
            return Ok(Reply::one(warn("a name is the only must")));
        }
        let id = group_id(id)?;
        let mut s = self.session();
        Ok(Reply::notes(match s.rename_group(id, name) {
            Ok(()) => self.saved(&mut s, info("group renamed")),
            Err(e) => vec![warn(format!("cannot rename · {e}"))],
        }))
    }

    pub fn delete_group(&self, id: &str) -> Result<Reply, String> {
        let id = group_id(id)?;
        let mut s = self.session();
        Ok(Reply::notes(match s.delete_group(id) {
            Ok(true) => self.saved(&mut s, warn("group deleted for good")),
            Ok(false) => self.saved(&mut s, info("group moved to the recycle bin · undo restores it")),
            Err(Delete::Missing) => Vec::new(),
            Err(Delete::Vault(e)) => vec![warn(format!("cannot delete · {e}"))],
        }))
    }

    pub fn undo(&self) -> Reply {
        let mut s = self.session();
        let Some(undone) = s.undo() else {
            return Reply::one(info("nothing to undo"));
        };
        let (said, select) = match undone {
            Undone::Edit { id, title } => (format!("undid edit of {title}"), Some(id.to_string())),
            Undone::Entry { id, title } => (format!("restored {title}"), Some(id.to_string())),
            Undone::Group { id, title } => (format!("restored {title}"), Some(id.to_string())),
            Undone::Removed { title } => (format!("removed {title}"), None),
            Undone::Renamed { before } => (format!("restored name {before}"), None),
        };
        Reply { notes: self.saved(&mut s, info(said)), select, ok: true }
    }

    pub fn save(&self) -> Reply {
        let mut s = self.session();
        self.ask_for_key(&s, "to save");
        Reply::one(match s.save_now(true) {
            SaveNow::Locked => info("no vault open"),
            SaveNow::NoFile => warn("this vault has no file yet"),
            SaveNow::Deferred(_) => info("waiting for your key"),
            SaveNow::Overwrote => warn("saved over the copy on disk"),
            SaveNow::OverwriteFailed(e) => error(format!("save failed · {e}")),
            SaveNow::Clean => info("nothing to save · every change saves itself"),
            SaveNow::Saved(Saved::Written) => info("saved"),
            SaveNow::Saved(Saved::Conflict) => error("vault changed on disk · merge, overwrite or reload"),
            SaveNow::Saved(Saved::Failed(e)) => error(format!("save failed · {e} · kept in memory")),
            SaveNow::Saved(_) => info("not saved"),
        })
    }

    pub fn merge(&self) -> Reply {
        let mut s = self.session();
        self.ask_for_key(&s, "twice: to read the file, then to save");
        Reply::one(match s.merge(true) {
            Ok(summary) => info(format!("merged with the file on disk · {}", summary.describe())),
            Err(e) => resolve_note(e),
        })
    }

    pub fn reload(&self) -> Reply {
        Reply::one(match self.session().reload() {
            Ok(()) => warn("reloaded from disk · your unsaved changes are gone"),
            Err(e) => resolve_note(e),
        })
    }

    pub fn audit(&self) -> Vec<AuditRow> {
        let s = self.session();
        let Some(vault) = s.vault() else {
            return Vec::new();
        };
        sennel_core::vault::audit(vault)
            .into_iter()
            .filter_map(|(id, issue)| {
                vault.get_entry(&id).map(|e| AuditRow {
                    id: id.to_string(),
                    title: e.title().to_string(),
                    issue: issue.say(),
                })
            })
            .collect()
    }

    pub fn history(&self, id: &str) -> Result<Vec<VersionRow>, String> {
        let id = entry_id(id)?;
        let s = self.session();
        let vault = s.vault().ok_or("locked")?;
        let e = vault.get_entry(&id).ok_or("that entry is gone")?;
        Ok(sennel_core::vault::history(&e)
            .into_iter()
            .map(|v| VersionRow {
                at: v.at,
                title: v.title.clone(),
                username: v.username.clone(),
                modified: v.modified.map(|m| m.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(),
            })
            .collect())
    }

    pub fn clear_history(&self, id: &str) -> Result<Reply, String> {
        let id = entry_id(id)?;
        let mut s = self.session();
        Ok(Reply::notes(match s.clear_history(id) {
            Ok(gone) => self.saved(&mut s, warn(format!("cleared {gone} old version(s) · this has no undo"))),
            Err(e) => vec![error(format!("cannot clear · {e}"))],
        }))
    }

    pub fn fields(&self, id: &str) -> Result<Vec<FieldRow>, String> {
        let id = entry_id(id)?;
        let s = self.session();
        let vault = s.vault().ok_or("locked")?;
        let e = vault.get_entry(&id).ok_or("that entry is gone")?;
        Ok(sennel_core::vault::extra_rows(&e)
            .iter()
            .map(|row| match row {
                Extra::Field { name, value, secret } => FieldRow {
                    name: name.clone(),
                    file: false,
                    secret: *secret,
                    value: (!secret).then(|| value.clone()),
                    bytes: None,
                },
                Extra::File { name, bytes } => FieldRow {
                    name: name.clone(),
                    file: true,
                    secret: false,
                    value: None,
                    bytes: Some(*bytes),
                },
            })
            .collect())
    }

    pub fn add_field(&self, id: &str, name: &str, value: &str) -> Result<Reply, String> {
        if name.trim().is_empty() {
            return Ok(Reply::one(warn("a name is the only must")));
        }
        let id = entry_id(id)?;
        let mut s = self.session();
        Ok(Reply::notes(match s.add_field(id, name.trim(), value) {
            Ok(()) => self.saved(&mut s, info(format!("added field {}", name.trim()))),
            Err(e) => vec![error(format!("cannot add · {e}"))],
        }))
    }

    pub fn attach(&self, id: &str, name: &str, path: &str) -> Result<Reply, String> {
        if name.trim().is_empty() {
            return Ok(Reply::one(warn("a name is the only must")));
        }
        let id = entry_id(id)?;
        let path = config::expand(path.trim());
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => return Ok(Reply::one(error(format!("cannot read {} · {e}", path.display())))),
        };
        let mut s = self.session();
        Ok(Reply::notes(match s.attach(id, name.trim(), bytes) {
            Ok(()) => self.saved(&mut s, info(format!("attached {}", name.trim()))),
            Err(e) => vec![error(format!("cannot attach · {e}"))],
        }))
    }

    pub fn remove_field(&self, id: &str, name: &str, file: bool) -> Result<Reply, String> {
        let id = entry_id(id)?;
        let row = match file {
            true => Extra::File { name: name.to_string(), bytes: 0 },
            false => Extra::Field { name: name.to_string(), value: String::new(), secret: false },
        };
        let mut s = self.session();
        Ok(Reply::notes(match s.remove_extra(id, &row) {
            Ok(()) => self.saved(&mut s, warn(format!("removed {name}"))),
            Err(e) => vec![error(format!("cannot remove · {e}"))],
        }))
    }

    pub fn extract(&self, id: &str, name: &str) -> Result<Note, String> {
        let id = entry_id(id)?;
        Ok(match self.session().extract(id, name) {
            Ok((at, len)) => warn(format!("wrote {} · {len} bytes, owner-only, outside the vault", at.display())),
            Err(Extract::Gone) => error("the attachment is not there any more"),
            Err(Extract::NoFolder) => error("no vault file to write beside"),
            Err(Extract::Exists(at)) => warn(format!("{} is already there · move it first", at.display())),
            Err(Extract::Write(at, e)) => error(format!("cannot write {} · {e}", at.display())),
        })
    }

    pub fn agent_give(&self, id: &str, name: &str) -> Result<Note, String> {
        let id = entry_id(id)?;
        Ok(match self.session().agent_give(id, name) {
            Ok(Some(lifetime)) => info(format!("{name} given to the agent for {lifetime}s")),
            Ok(None) => info("locked"),
            Err(why) => warn(format!("ssh agent: {why}")),
        })
    }

    /// On the way out: wipe what is still ours on the clipboard, and lock.
    pub fn shutdown(&self) {
        if let Some(board) = &self.board {
            board.clear_now();
        }
        self.session().lock();
    }
}

enum Field<'a> {
    Fixed(&'a str),
    Custom(&'a str),
}

fn resolve_note(e: Resolve) -> Note {
    match e {
        Resolve::NoConflict => info("the file has not changed"),
        Resolve::Locked => info("no vault open"),
        Resolve::Deferred => info("waiting for your key"),
        Resolve::Failed(e) => error(format!("{e}")),
    }
}

#[cfg(test)]
pub fn open_with(vault: sennel_core::vault::Vault) -> Desk {
    let desk = Desk::new(Settings::default(), None);
    desk.session().open(vault);
    desk
}
