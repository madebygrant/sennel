// One open vault and everything a session keeps about it: save state, undo, the cut, keys lent to
// the agent, the Touch ID copy of the password and the idle clocks. Methods report what happened
// and never word it; each front end says it in its own way.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use keepass::db::{Entry, EntryId, GroupId};
use zeroize::{Zeroize, Zeroizing};

use crate::agent::Loaded;
use crate::touchid::Refused;
use crate::vault::{EntryExt, Extra, MergeSummary, Vault, VaultError, YubiSpec};

/// A password sealed so only the user's presence opens it again. Generic so a test can stand in
/// for the Secure Enclave without any binary linking the stand-in.
pub trait Seal: Sized {
    fn seal(secret: &[u8]) -> Result<Self, String>;
    fn open(&self) -> Result<Zeroizing<Vec<u8>>, Refused>;
}

// Something sitting on the shelf between a cut and a paste. The id travels alone, so a rename in
// between still reads right and a deleted source disarms itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cut {
    Entry(EntryId),
    Group(GroupId),
}

/// A write that waits for the hardware key, so the screen can ask for the touch first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pending {
    Save,
    Overwrite,
    Merge,
}

// One step of work, undone. The snapshot carries the whole entry, secrets included and zeroized
// on drop, because a field-by-field restore would miss the timestamps the form never touches.
pub enum Undo {
    /// Before-state of an edited entry; restore swaps it wholesale.
    Edit { id: EntryId, before: Entry },
    /// An entry destroyed inside the bin, which only a snapshot brings back.
    Delete {
        id: EntryId,
        parent: GroupId,
        before: Entry,
    },
    // An entry moved to the bin. It still exists, so undo is a move home and the snapshot rides
    // along only to name it.
    Recycle {
        id: EntryId,
        parent: GroupId,
        before: Entry,
    },
    /// A group moved to the bin, with everything under it.
    RecycleGroup {
        id: GroupId,
        parent: GroupId,
        title: String,
    },
    /// An added entry that undo removes again.
    AddEntry { id: EntryId, title: String },
    /// A group rename that undo turns back.
    Rename { id: GroupId, before: String },
}

/// What an undo did, and where the cursor belongs afterwards.
pub enum Undone {
    Edit { id: EntryId, title: String },
    Entry { id: EntryId, title: String },
    Group { id: GroupId, title: String },
    Removed { title: String },
    Renamed { before: String },
}

/// What an autosave came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Saved {
    /// No vault open.
    Locked,
    /// An in-memory vault with no file: it stays dirty rather than silently discarding.
    NoFile,
    /// Waiting on a hardware key touch; `flush` writes it.
    Deferred(Pending),
    Written,
    /// The file changed underneath. Merge, overwrite or reload decide.
    Conflict,
    Failed(String),
}

/// What an explicit save came to.
#[derive(Debug, PartialEq, Eq)]
pub enum SaveNow {
    Locked,
    NoFile,
    Deferred(Pending),
    /// Written over a file somebody else changed, on purpose.
    Overwrote,
    OverwriteFailed(String),
    /// Nothing changed since the last write.
    Clean,
    Saved(Saved),
}

/// Why a merge or reload did not happen.
#[derive(Debug)]
pub enum Resolve {
    /// No save has been refused, so there is nothing to resolve.
    NoConflict,
    Locked,
    Deferred,
    Failed(VaultError),
}

/// Whether the Touch ID copy was made at unlock.
pub enum Sealing {
    /// Off, or this unlock came from the copy itself.
    Skipped,
    Sealed,
    /// Off for the rest of the session, so a Mac without a sensor says so once.
    Off(String),
}

/// Keys the agent was given when a vault opened.
#[derive(Default)]
pub struct AgentReport {
    pub added: usize,
    pub lifetime: u32,
    pub problems: Vec<String>,
}

pub struct Unlocked {
    pub entries: usize,
    pub created: bool,
    /// The format, when it opened but can never be written.
    pub read_only: Option<String>,
    pub sealing: Sealing,
    pub agent: AgentReport,
}

#[derive(Debug)]
pub enum UnlockError {
    Empty,
    /// keepass speaks `&str`, and guessing at raw bytes would open nothing or the wrong thing.
    NotText,
    /// Creating, and the two boxes differ.
    Mismatch,
    /// The password or key file was refused.
    WrongPassword,
    Open(VaultError),
}

#[derive(Debug)]
pub enum QuickError {
    /// Nothing sealed for this vault.
    Nothing,
    Refused(Refused),
    Unlock(UnlockError),
}

/// The boxes of the entry form, as typed.
pub struct EntryInput<'a> {
    pub title: &'a str,
    pub username: &'a str,
    /// None keeps the stored password.
    pub password: Option<&'a str>,
    pub url: &'a str,
    pub notes: &'a str,
    pub tags: &'a str,
    pub expires: &'a str,
    /// None keeps the stored seed, an empty one removes it.
    pub otp: Option<&'a str>,
}

#[derive(Debug)]
pub enum EntryError {
    NoTitle,
    Expiry(String),
    Otp(String),
    NoGroup,
    Vault(VaultError),
}

pub struct EntrySaved {
    /// The new entry, when one was added.
    pub id: Option<EntryId>,
    /// Some(true) when a seed was set, Some(false) when one was removed.
    pub otp: Option<bool>,
}

/// Why a delete did not happen.
#[derive(Debug)]
pub enum Delete {
    /// No vault, or the entry is already gone: nothing to say.
    Missing,
    Vault(VaultError),
}

#[derive(Debug)]
pub enum Reparent {
    /// No vault, or the tree has no parent to go by: nothing to say.
    Missing,
    Root,
    InBin,
    NothingAbove,
    AtTop,
    Vault(VaultError),
}

#[derive(Debug)]
pub enum Paste {
    Locked,
    Nothing,
    NoGroup,
    Vault(VaultError),
}

pub struct Rekeyed {
    pub removed: usize,
    /// Why Touch ID is off until the next typed unlock, when resealing failed.
    pub touch_id_off: Option<String>,
}

#[derive(Debug)]
pub enum Extract {
    Gone,
    NoFolder,
    Exists(PathBuf),
    Write(PathBuf, VaultError),
}

// Bounded on purpose: each Delete holds a whole entry, so an unbounded stack is an unbounded pile
// of plaintext in memory, and dropping the oldest is what zeroizes it.
pub const UNDO_DEPTH: usize = 32;

pub struct Session<S> {
    // Private, so `open` stays the only way in and undo stays bounded.
    vault: Option<Vault>,
    cut: Option<Cut>,
    // Newest last.
    undo: Vec<Undo>,
    dirty: bool,
    // Bumped whenever the vault changes or is swapped, so anything cached against it knows it moved.
    revision: u64,
    // A save was refused because the file changed underneath.
    conflict: bool,
    pending: Option<Pending>,
    // The Touch ID copy and the vault it was sealed for. A lock keeps it: it is what unlocks.
    quick: Option<(PathBuf, S)>,
    quick_here: bool,
    pub touch_id: bool,
    agent_keys: Vec<Loaded>,
    ssh_agent: bool,
    ssh_lifetime: u32,
    backups: usize,
    backup_dir: PathBuf,
    pub lock_after: Option<Duration>,
    pub last_activity: Instant,
    // `Instant` stops during suspend on macOS and Linux, so idleness reads both clocks.
    pub last_activity_wall: SystemTime,
}

impl<S: Seal> Default for Session<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Seal> Session<S> {
    pub fn new() -> Self {
        Session {
            vault: None,
            cut: None,
            undo: Vec::new(),
            dirty: false,
            revision: 0,
            conflict: false,
            pending: None,
            quick: None,
            quick_here: false,
            touch_id: false,
            agent_keys: Vec::new(),
            ssh_agent: false,
            ssh_lifetime: 3600,
            backups: 0,
            backup_dir: PathBuf::new(),
            lock_after: None,
            last_activity: Instant::now(),
            last_activity_wall: SystemTime::now(),
        }
    }

    pub fn is_open(&self) -> bool {
        self.vault.is_some()
    }

    pub fn vault(&self) -> Option<&Vault> {
        self.vault.as_ref()
    }

    /// For changes that are not session work, such as which groups are folded.
    pub fn vault_mut(&mut self) -> Option<&mut Vault> {
        self.vault.as_mut()
    }

    pub fn cut(&self) -> Option<Cut> {
        self.cut
    }

    pub fn arm_cut(&mut self, cut: Cut) {
        self.cut = Some(cut);
    }

    pub fn drop_cut(&mut self) -> Option<Cut> {
        self.cut.take()
    }

    /// Undo steps, oldest first.
    pub fn undo_steps(&self) -> &[Undo] {
        &self.undo
    }

    fn moved(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Arms the quit guard without a mutation, for tests of what asks before quitting.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Whether the last save was refused because the file changed underneath.
    pub fn in_conflict(&self) -> bool {
        self.conflict
    }

    pub fn pending(&self) -> Option<Pending> {
        self.pending
    }

    pub fn take_pending(&mut self) -> Option<Pending> {
        self.pending.take()
    }

    pub fn set_backups(&mut self, keep: usize, dir: PathBuf) {
        self.backups = keep;
        self.backup_dir = dir;
    }

    pub fn set_ssh_agent(&mut self, on: bool, lifetime: u32) {
        self.ssh_agent = on;
        self.ssh_lifetime = lifetime;
    }

    pub fn ssh_lifetime(&self) -> u32 {
        self.ssh_lifetime
    }

    pub fn set_lock_timeout(&mut self, secs: u64) {
        self.lock_after = (secs > 0).then(|| Duration::from_secs(secs));
    }

    /// Opens a vault into the session. The single way in, so backups and the agent are never skipped.
    pub fn open(&mut self, mut vault: Vault) -> AgentReport {
        // Unset (empty) in tests, which must not write backups anywhere.
        if !self.backup_dir.as_os_str().is_empty() {
            vault.set_backups(self.backups, &self.backup_dir);
        }
        self.vault = Some(vault);
        self.moved();
        self.agent_load()
    }

    // Opens `path`, or creates it when `confirm` is given. The password is wiped on every path out.
    pub fn unlock(
        &mut self,
        path: &Path,
        password: &mut Vec<u8>,
        key_file: Option<&[u8]>,
        yubikey: Option<&YubiSpec>,
        confirm: Option<&[u8]>,
    ) -> Result<Unlocked, UnlockError> {
        self.unlock_from(path, password, key_file, yubikey, confirm, false)
    }

    fn unlock_from(
        &mut self,
        path: &Path,
        password: &mut Vec<u8>,
        key_file: Option<&[u8]>,
        yubikey: Option<&YubiSpec>,
        confirm: Option<&[u8]>,
        from_sealed: bool,
    ) -> Result<Unlocked, UnlockError> {
        let result = self.open_or_create(path, password, key_file, yubikey, confirm);
        // Sealed before the wipe, while these bytes are still the password.
        let sealing = match (&result, self.touch_id && !from_sealed) {
            (Ok(_), true) => match S::seal(password) {
                Ok(sealed) => {
                    self.quick = Some((crate::config::absolute(path), sealed));
                    self.quick_here = true;
                    Sealing::Sealed
                }
                Err(why) => {
                    self.quick = None;
                    self.touch_id = false;
                    Sealing::Off(why)
                }
            },
            _ => Sealing::Skipped,
        };
        password.zeroize();
        let vault = result?;
        let entries = vault.entry_count();
        let read_only = (!vault.writable()).then(|| vault.format());
        let agent = self.open(vault);
        Ok(Unlocked {
            entries,
            created: confirm.is_some(),
            read_only,
            sealing,
            agent,
        })
    }

    fn open_or_create(
        &self,
        path: &Path,
        password: &[u8],
        key_file: Option<&[u8]>,
        yubikey: Option<&YubiSpec>,
        confirm: Option<&[u8]>,
    ) -> Result<Vault, UnlockError> {
        if password.is_empty() {
            return Err(UnlockError::Empty);
        }
        // Borrowed, not copied: a lossy copy would leave a plaintext password nothing zeroizes.
        let Ok(pw) = std::str::from_utf8(password) else {
            return Err(UnlockError::NotText);
        };
        let result = match confirm {
            Some(again) if again != password => return Err(UnlockError::Mismatch),
            Some(_) => {
                let mut vault = Vault::new();
                vault
                    .save_as_with(path, pw, key_file, yubikey)
                    .map(|()| vault)
            }
            None => Vault::open_with(path, pw, key_file, yubikey),
        };
        result.map_err(|e| match e {
            VaultError::WrongPassword => UnlockError::WrongPassword,
            e => UnlockError::Open(e),
        })
    }

    /// Points the Touch ID copy at the vault about to be unlocked. Called when that changes, since
    /// comparing paths stats the disk and a draw must not.
    pub fn aim(&mut self, path: Option<&Path>) {
        // Through `absolute`: a picker and a typed box spell the same vault differently.
        self.quick_here = match (&self.quick, path) {
            (Some((db, _)), Some(path)) => crate::config::absolute(path) == *db,
            _ => false,
        };
    }

    /// Whether a fingerprint can open the vault last aimed at.
    pub fn quick_here(&self) -> bool {
        self.quick_here && self.quick.is_some()
    }

    // The fingerprint prompt, then the unlock. A copy the vault refuses, or that can never open
    // again, is dropped, so it does not fail the same way every time.
    pub fn quick_unlock(
        &mut self,
        key_file: Option<&[u8]>,
        yubikey: Option<&YubiSpec>,
    ) -> Result<Unlocked, QuickError> {
        if !self.quick_here() {
            return Err(QuickError::Nothing);
        }
        let Some((path, sealed)) = &self.quick else {
            return Err(QuickError::Nothing);
        };
        let path = path.clone();
        let mut password = match sealed.open() {
            Ok(password) => password,
            Err(refused) => {
                if matches!(refused, Refused::Void(_)) {
                    self.quick = None;
                }
                return Err(QuickError::Refused(refused));
            }
        };
        let result = self.unlock_from(&path, &mut password, key_file, yubikey, None, true);
        if let Err(UnlockError::WrongPassword) = result {
            self.quick = None;
        }
        result.map_err(QuickError::Unlock)
    }

    /// A keypress or click happened, so the idle clock restarts.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        self.last_activity_wall = SystemTime::now();
    }

    // Whether the open vault has sat untouched past the deadline. Takes the clock so tests drive it
    // without sleeping. Whichever clock says more time passed wins: the monotonic one alone sleeps
    // through a suspend, and the wall one alone can be set back.
    pub fn idle_expired(&self, now: Instant) -> bool {
        self.locks_in(now).is_some_and(|left| left.is_zero())
    }

    /// Time left before the idle lock, or None while nothing is open or the lock is off.
    pub fn locks_in(&self, now: Instant) -> Option<Duration> {
        let after = self.lock_after.filter(|_| self.vault.is_some())?;
        let idle = now
            .duration_since(self.last_activity)
            // A backwards jump reads as no time passed, not as negative time.
            .max(self.last_activity_wall.elapsed().unwrap_or_default());
        Some(after.saturating_sub(idle))
    }

    // Drops the vault. Dropping is the wipe: secrets live in `ProtectedString` and the retained key,
    // which zeroize on drop. Returns how many keys the agent would not give back.
    pub fn lock(&mut self) -> usize {
        let failed = self.agent_release();
        self.vault = None;
        self.moved();
        self.dirty = false;
        self.conflict = false;
        self.pending = None;
        self.cut = None;
        // An undo stack that outlived a lock would be a pile of plaintext behind a locked screen.
        self.undo.clear();
        failed
    }

    // Autosave after every mutation. Dirty is set before the attempt and cleared on success, so a
    // failed save leaves the quit guard armed. `may_block` is false until the screen has asked for
    // a hardware key touch.
    pub fn persist(&mut self, may_block: bool) -> Saved {
        self.moved();
        let Some(vault) = &mut self.vault else {
            return Saved::Locked;
        };
        if vault.path().is_none() {
            self.dirty = true;
            return Saved::NoFile;
        }
        if vault.has_challenge() && !may_block {
            self.dirty = true;
            self.pending = Some(Pending::Save);
            return Saved::Deferred(Pending::Save);
        }
        match vault.save() {
            Ok(()) => {
                self.dirty = false;
                self.conflict = false;
                Saved::Written
            }
            // Refusing is the point: the alternative is this session quietly winning every race.
            Err(VaultError::ChangedOnDisk) => {
                self.dirty = true;
                self.conflict = true;
                Saved::Conflict
            }
            Err(e) => {
                self.dirty = true;
                Saved::Failed(e.to_string())
            }
        }
    }

    /// A save on request: the retry after a failure, and the second press that overwrites a conflict.
    pub fn save_now(&mut self, may_block: bool) -> SaveNow {
        let Some(vault) = &mut self.vault else {
            return SaveNow::Locked;
        };
        if vault.path().is_none() {
            return SaveNow::NoFile;
        }
        if self.conflict {
            if vault.has_challenge() && !may_block {
                self.pending = Some(Pending::Overwrite);
                return SaveNow::Deferred(Pending::Overwrite);
            }
            return match vault.save_over() {
                Ok(()) => {
                    self.dirty = false;
                    self.conflict = false;
                    SaveNow::Overwrote
                }
                Err(e) => SaveNow::OverwriteFailed(e.to_string()),
            };
        }
        if !self.dirty {
            return SaveNow::Clean;
        }
        SaveNow::Saved(self.persist(may_block))
    }

    // Keeps both sides of a conflict. A merge the crate cannot make leaves the file and the session
    // untouched.
    pub fn merge(&mut self, may_block: bool) -> Result<MergeSummary, Resolve> {
        if !self.conflict {
            return Err(Resolve::NoConflict);
        }
        let Some(vault) = &mut self.vault else {
            return Err(Resolve::Locked);
        };
        if vault.has_challenge() && !may_block {
            self.pending = Some(Pending::Merge);
            return Err(Resolve::Deferred);
        }
        let summary = vault.merge_from_disk().map_err(Resolve::Failed)?;
        self.resolved();
        Ok(summary)
    }

    /// Takes the copy on disk and drops what this session could not write.
    pub fn reload(&mut self) -> Result<(), Resolve> {
        if !self.conflict {
            return Err(Resolve::NoConflict);
        }
        let Some(vault) = &mut self.vault else {
            return Err(Resolve::Locked);
        };
        vault.reload().map_err(Resolve::Failed)?;
        self.resolved();
        Ok(())
    }

    // The tree changed under every snapshot, so none of them describes this vault any more.
    fn resolved(&mut self) {
        self.moved();
        self.dirty = false;
        self.conflict = false;
        self.undo.clear();
        self.cut = None;
    }

    /// To the recycle bin, or for good when it is already there. Returns which.
    pub fn delete_entry(&mut self, id: EntryId) -> Result<bool, Delete> {
        let vault = self.vault.as_mut().ok_or(Delete::Missing)?;
        let parent = vault.parent_group_of_entry(&id).ok_or(Delete::Missing)?;
        let before = vault
            .get_entry(&id)
            .map(|e| e.clone())
            .ok_or(Delete::Missing)?;
        let forever = vault.is_recycled(&id);
        match forever {
            true => vault.expunge_entry(&id),
            false => vault.recycle_entry(&id),
        }
        .map_err(Delete::Vault)?;
        self.push_undo(match forever {
            true => Undo::Delete { id, parent, before },
            false => Undo::Recycle { id, parent, before },
        });
        Ok(forever)
    }

    // Inside the bin this destroys the subtree, and no snapshot is big enough to put that back, so
    // it arms no undo and leaves earlier steps alone.
    pub fn delete_group(&mut self, id: GroupId) -> Result<bool, Delete> {
        let vault = self.vault.as_mut().ok_or(Delete::Missing)?;
        let (parent, title) = match vault.get_group(&id) {
            Some(g) => (g.parent().map(|p| p.id()), g.name.clone()),
            None => (None, String::new()),
        };
        let forever = vault.in_recycle_bin(&id);
        match forever {
            true => vault.delete_group_tree(&id),
            false => vault.recycle_group(&id),
        }
        .map_err(Delete::Vault)?;
        // A cut pointing at the deleted group would paste nothing.
        if self.cut == Some(Cut::Group(id)) {
            self.cut = None;
        }
        if let (false, Some(parent)) = (forever, parent) {
            self.push_undo(Undo::RecycleGroup { id, parent, title });
        }
        Ok(forever)
    }

    /// Moves the cut into `target`. One-shot: the shelf empties on success and stays armed on failure.
    pub fn paste(&mut self, target: Option<GroupId>) -> Result<Cut, Paste> {
        let cut = self.cut.ok_or(Paste::Nothing)?;
        let target = target.ok_or(Paste::NoGroup)?;
        let vault = self.vault.as_mut().ok_or(Paste::Locked)?;
        match cut {
            Cut::Entry(id) => vault.move_entry(&id, &target),
            Cut::Group(id) => vault.move_group(&id, &target),
        }
        .map_err(Paste::Vault)?;
        self.cut = None;
        Ok(cut)
    }

    // One step in or out of the tree. In makes the group a child of the sibling directly above,
    // the only group "indent" can mean; out makes it a sibling of its parent.
    pub fn reparent_group(&mut self, id: GroupId, deeper: bool) -> Result<(), Reparent> {
        let vault = self.vault.as_mut().ok_or(Reparent::Missing)?;
        let root = vault.root_id();
        if id == root {
            return Err(Reparent::Root);
        }
        if vault.in_recycle_bin(&id) {
            return Err(Reparent::InBin);
        }
        let parent_of = |vault: &Vault, id: &GroupId| {
            vault.get_group(id).and_then(|g| g.parent().map(|p| p.id()))
        };
        let parent = parent_of(vault, &id).ok_or(Reparent::Missing)?;
        let target = if deeper {
            let siblings: Vec<GroupId> = vault.groups_in(&parent).iter().map(|g| g.id()).collect();
            let at = siblings.iter().position(|s| *s == id).unwrap_or(0);
            at.checked_sub(1)
                .and_then(|prev| siblings.get(prev).copied())
                .ok_or(Reparent::NothingAbove)?
        } else {
            if parent == root {
                return Err(Reparent::AtTop);
            }
            parent_of(vault, &parent).ok_or(Reparent::Missing)?
        };
        vault.move_group(&id, &target).map_err(Reparent::Vault)?;
        // Expanded, or the group vanishes inside a folded parent and reads as a delete.
        vault.set_expanded(&target, true);
        Ok(())
    }

    // Adds to `group`, or edits `id`. Every box is checked before anything is written, so a bad date
    // or seed cannot leave half an entry behind.
    pub fn save_entry(
        &mut self,
        target: EntryTarget,
        input: &EntryInput<'_>,
    ) -> Result<EntrySaved, EntryError> {
        if input.title.trim().is_empty() {
            return Err(EntryError::NoTitle);
        }
        let expires = parse_expiry(input.expires).map_err(EntryError::Expiry)?;
        let otp: Option<Option<String>> = match input.otp {
            None => None,
            Some(seed) if seed.trim().is_empty() => Some(None),
            Some(seed) => Some(Some(
                crate::vault::totp_url(seed, input.title, input.username)
                    .map_err(EntryError::Otp)?,
            )),
        };
        let tags = split_tags(input.tags);
        let vault = self
            .vault
            .as_mut()
            .ok_or(EntryError::Vault(VaultError::EntryNotFound))?;
        let id = match target {
            EntryTarget::Add(group) => {
                let group = group.ok_or(EntryError::NoGroup)?;
                let password = input.password.unwrap_or("");
                let id = vault
                    .create_entry(
                        &group,
                        input.title,
                        input.username,
                        password,
                        input.url,
                        input.notes,
                    )
                    .map_err(EntryError::Vault)?;
                if let Some(Some(url)) = otp.as_ref() {
                    let _ = vault.set_otp(&id, Some(url));
                }
                let _ = vault.set_tags(&id, &tags);
                let _ = vault.set_expiry(&id, expires);
                self.push_undo(Undo::AddEntry {
                    id,
                    title: input.title.to_string(),
                });
                Some(id)
            }
            EntryTarget::Edit(id) => {
                // Taken before the write and pushed only once it lands.
                let before = vault.get_entry(&id).map(|e| e.clone());
                vault
                    .update_entry(
                        &id,
                        input.title,
                        input.username,
                        input.password,
                        input.url,
                        input.notes,
                    )
                    .and_then(|()| vault.set_tags(&id, &tags))
                    .and_then(|()| vault.set_expiry(&id, expires))
                    .and_then(|()| match otp.as_ref() {
                        None => Ok(()),
                        Some(url) => vault.set_otp(&id, url.as_deref()),
                    })
                    .map_err(EntryError::Vault)?;
                if let Some(before) = before {
                    self.push_undo(Undo::Edit { id, before });
                }
                None
            }
        };
        Ok(EntrySaved {
            id,
            otp: otp.map(|o| o.is_some()),
        })
    }

    pub fn add_group(
        &mut self,
        parent: Option<GroupId>,
        name: &str,
    ) -> Result<GroupId, VaultError> {
        let parent = parent.ok_or(VaultError::GroupNotFound)?;
        let vault = self.vault.as_mut().ok_or(VaultError::GroupNotFound)?;
        vault.create_group(&parent, name)
    }

    pub fn rename_group(&mut self, id: GroupId, name: &str) -> Result<(), VaultError> {
        let vault = self.vault.as_mut().ok_or(VaultError::GroupNotFound)?;
        let before = vault.get_group(&id).map(|g| g.name.clone());
        vault.rename_group(&id, name)?;
        if let Some(before) = before {
            self.push_undo(Undo::Rename { id, before });
        }
        Ok(())
    }

    fn push_undo(&mut self, step: Undo) {
        if self.undo.len() == UNDO_DEPTH {
            self.undo.remove(0);
        }
        self.undo.push(step);
    }

    // Walks back one step, newest first. Results are ignored the way a rollback's are: a step can
    // only fail on an id that is gone, and the persist after it reports anything that did not land.
    pub fn undo(&mut self) -> Option<Undone> {
        let vault = self.vault.as_mut()?;
        Some(match self.undo.pop()? {
            Undo::Edit { id, before } => {
                let _ = vault.replace_entry(&before);
                Undone::Edit {
                    id,
                    title: before.title().to_string(),
                }
            }
            Undo::Delete { id, parent, before } => {
                let _ = vault.restore_entry(&before, &parent);
                Undone::Entry {
                    id,
                    title: before.title().to_string(),
                }
            }
            // Out of the bin rather than back from the dead, so the entry keeps its id and history.
            Undo::Recycle { id, parent, before } => {
                let _ = vault.move_entry(&id, &parent);
                Undone::Entry {
                    id,
                    title: before.title().to_string(),
                }
            }
            Undo::RecycleGroup { id, parent, title } => {
                let _ = vault.move_group(&id, &parent);
                Undone::Group { id, title }
            }
            Undo::AddEntry { id, title } => {
                let _ = vault.expunge_entry(&id);
                Undone::Removed { title }
            }
            Undo::Rename { id, before } => {
                let _ = vault.set_group_title(&id, &before);
                Undone::Renamed { before }
            }
        })
    }

    // The file on disk becomes the new password's, so nothing is left dirty. The Touch ID copy held
    // the old password, so it is sealed again.
    pub fn rekey(
        &mut self,
        password: &str,
        key_file: Option<&[u8]>,
    ) -> Result<Rekeyed, VaultError> {
        let vault = self.vault.as_mut().ok_or(VaultError::Unsaved)?;
        let removed = vault.rekey(password, key_file)?;
        self.moved();
        self.dirty = false;
        self.conflict = false;
        let mut touch_id_off = None;
        if let Some((db, _)) = self.quick.take() {
            match S::seal(password.as_bytes()) {
                Ok(sealed) => self.quick = Some((db, sealed)),
                Err(why) => touch_id_off = Some(why),
            }
        }
        Ok(Rekeyed {
            removed,
            touch_id_off,
        })
    }

    /// Added protected: a field somebody adds by hand to a password manager is more often a secret than not.
    pub fn add_field(&mut self, id: EntryId, name: &str, value: &str) -> Result<(), VaultError> {
        let vault = self.vault.as_mut().ok_or(VaultError::EntryNotFound)?;
        vault.set_field(&id, name, value, true)
    }

    pub fn attach(&mut self, id: EntryId, name: &str, bytes: Vec<u8>) -> Result<(), VaultError> {
        let vault = self.vault.as_mut().ok_or(VaultError::EntryNotFound)?;
        vault.add_attachment(&id, name, bytes)
    }

    pub fn remove_extra(&mut self, id: EntryId, row: &Extra) -> Result<(), VaultError> {
        let vault = self.vault.as_mut().ok_or(VaultError::EntryNotFound)?;
        match row {
            Extra::Field { name, .. } => vault.remove_field(&id, name),
            Extra::File { name, .. } => vault.remove_attachment(&id, name),
        }
    }

    /// Drops every old version of an entry. Returns how many went; there is no undo for this.
    pub fn clear_history(&mut self, id: EntryId) -> Result<usize, VaultError> {
        let vault = self.vault.as_mut().ok_or(VaultError::EntryNotFound)?;
        vault.clear_history(&id)
    }

    // Writes an attachment beside the vault, owner-only: that folder is where the user already keeps
    // secrets, and the working directory is wherever they launched from. Returns where and how big.
    pub fn extract(&self, id: EntryId, name: &str) -> Result<(PathBuf, usize), Extract> {
        let vault = self.vault.as_ref().ok_or(Extract::Gone)?;
        let bytes = vault.attachment_bytes(&id, name).ok_or(Extract::Gone)?;
        let dir = vault
            .path()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .ok_or(Extract::NoFolder)?;
        // The name comes out of the vault and may hold a path separator, so only its last part counts.
        let leaf = Path::new(name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty() && n != "." && n != "..")
            .unwrap_or_else(|| "attachment".to_string());
        let at = dir.join(&leaf);
        // Named before the write: the exclusive create would only say "File exists".
        if at.exists() {
            return Err(Extract::Exists(at));
        }
        match crate::vault::write_owner_only(&at, &bytes) {
            Ok(()) => Ok((at, bytes.len())),
            Err(e) => Err(Extract::Write(at, e)),
        }
    }

    // Gives the agent the keys this vault's KeeAgent entries ask for. Opt-in, since it hands keys to
    // another process, and never a failed unlock.
    fn agent_load(&mut self) -> AgentReport {
        let mut report = AgentReport {
            lifetime: self.ssh_lifetime,
            ..AgentReport::default()
        };
        let Some(vault) = self.vault.as_ref().filter(|_| self.ssh_agent) else {
            return report;
        };
        let mut agent = match crate::agent::Agent::connect() {
            Ok(agent) => agent,
            Err(why) => {
                report.problems.push(why);
                return report;
            }
        };
        let outcome = crate::agent::load_vault(&mut agent, vault, self.ssh_lifetime);
        report.added = outcome.added.len();
        report.problems = outcome.problems;
        for key in outcome.added {
            if !self.agent_keys.iter().any(|k| k.blob == key.blob) {
                self.agent_keys.push(key);
            }
        }
        report
    }

    // Takes back the keys this session gave out, except those whose settings say to leave them;
    // those expire on their own, as every key would after a crash. Returns how many stayed.
    pub fn agent_release(&mut self) -> usize {
        let (remove, _kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.agent_keys)
            .into_iter()
            .partition(|k| k.remove_at_close);
        if remove.is_empty() {
            return 0;
        }
        match crate::agent::Agent::connect() {
            Ok(mut agent) => remove
                .iter()
                .filter(|k| agent.remove(&k.blob).is_err())
                .count(),
            Err(_) => remove.len(),
        }
    }

    // Hands one attachment's key to the agent, with the entry's password as its passphrase. Taken back
    // on lock even when the key's own settings would leave it.
    // None when no vault is open, which has nothing to say.
    pub fn agent_give(&mut self, id: EntryId, name: &str) -> Result<Option<u32>, String> {
        let lifetime = self.ssh_lifetime;
        let mut agent = crate::agent::Agent::connect()?;
        let Some(vault) = self.vault.as_ref() else {
            return Ok(None);
        };
        let settings = vault
            .attachment_bytes(&id, crate::agent::SETTINGS)
            .and_then(|bytes| crate::agent::parse_settings(&bytes));
        let mut key =
            crate::agent::add_entry_key(&mut agent, vault, &id, name, settings.as_ref(), lifetime)?;
        key.remove_at_close = true;
        if !self.agent_keys.iter().any(|k| k.blob == key.blob) {
            self.agent_keys.push(key);
        }
        Ok(Some(lifetime))
    }
}

/// Where the entry form writes.
#[derive(Clone, Copy, Debug)]
pub enum EntryTarget {
    Add(Option<GroupId>),
    Edit(EntryId),
}

// `YYYY-MM-DD`, or empty for "does not expire". It lands at the end of the day named: an expiry of
// "2026-09-16" should not go off at midnight that morning.
pub fn parse_expiry(text: &str) -> Result<Option<chrono::NaiveDateTime>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let date = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .map_err(|_| format!("{text:?} is not a date · use YYYY-MM-DD, or leave it empty"))?;
    let at = date
        .and_hms_opt(23, 59, 59)
        .ok_or_else(|| "that date has no end".to_string())?;
    Ok(Some(at))
}

/// Commas, trimmed, empties dropped: "work, , urgent," is two tags.
pub fn split_tags(text: &str) -> Vec<String> {
    text.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static REFUSE: RefCell<Option<Refused>> = const { RefCell::new(None) };
        static NO_SENSOR: Cell<bool> = const { Cell::new(false) };
    }

    // Stands in for the Secure Enclave: opens without a finger unless told to refuse.
    struct Fake(Vec<u8>);

    impl Seal for Fake {
        fn seal(secret: &[u8]) -> Result<Self, String> {
            match NO_SENSOR.get() {
                true => Err("no sensor".into()),
                false => Ok(Fake(secret.to_vec())),
            }
        }

        fn open(&self) -> Result<Zeroizing<Vec<u8>>, Refused> {
            match REFUSE.with_borrow(Clone::clone) {
                Some(refused) => Err(refused),
                None => Ok(Zeroizing::new(self.0.clone())),
            }
        }
    }

    struct Temp(PathBuf);

    impl Temp {
        fn new(tag: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Temp(std::env::temp_dir().join(format!(
                "sennel-session-{tag}-{}-{n}.kdbx",
                std::process::id()
            )))
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn session() -> Session<Fake> {
        Session::new()
    }

    // An in-memory vault with one group holding one entry.
    fn open() -> (Session<Fake>, GroupId, EntryId) {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        let entry = vault
            .create_entry(&banks, "checking", "u", "p", "", "")
            .unwrap();
        let mut s = session();
        s.open(vault);
        (s, banks, entry)
    }

    fn create(s: &mut Session<Fake>, file: &Temp, password: &str) -> Result<Unlocked, UnlockError> {
        let mut typed = password.as_bytes().to_vec();
        s.unlock(&file.0, &mut typed, None, None, Some(password.as_bytes()))
    }

    fn unlock(s: &mut Session<Fake>, file: &Temp, password: &str) -> Result<Unlocked, UnlockError> {
        let mut typed = password.as_bytes().to_vec();
        let result = s.unlock(&file.0, &mut typed, None, None, None);
        assert!(
            typed.iter().all(|b| *b == 0),
            "the typed password outlived the unlock"
        );
        result
    }

    #[test]
    fn a_created_vault_opens_again_and_refuses_the_wrong_password() {
        let file = Temp::new("create");
        let mut s = session();
        let made = create(&mut s, &file, "pw").unwrap();
        assert!(made.created && made.entries == 0);
        s.lock();
        assert!(!s.is_open());
        assert!(matches!(
            unlock(&mut s, &file, "nope"),
            Err(UnlockError::WrongPassword)
        ));
        assert!(unlock(&mut s, &file, "pw").is_ok());
    }

    #[test]
    fn a_create_with_differing_boxes_writes_nothing() {
        let file = Temp::new("mismatch");
        let mut s = session();
        let mut typed = b"one".to_vec();
        let result = s.unlock(&file.0, &mut typed, None, None, Some(b"two"));
        assert!(matches!(result, Err(UnlockError::Mismatch)));
        assert!(!file.0.exists() && !s.is_open());
        assert!(matches!(unlock(&mut s, &file, ""), Err(UnlockError::Empty)));
    }

    #[test]
    fn a_vault_written_elsewhere_is_a_conflict_until_resolved() {
        let file = Temp::new("conflict");
        let mut s = session();
        create(&mut s, &file, "pw").unwrap();
        let mut other = Vault::open_with(&file.0, "pw", None, None).unwrap();
        let root = other.root_id();
        other.create_group(&root, "theirs").unwrap();
        other.save().unwrap();

        let ours = s
            .add_group(s.vault.as_ref().map(Vault::root_id), "ours")
            .unwrap();
        assert_eq!(s.persist(true), Saved::Conflict);
        assert!(s.in_conflict() && s.is_dirty());
        s.cut = Some(Cut::Group(ours));
        let summary = s.merge(true).unwrap();
        assert!(!summary.describe().is_empty());
        assert!(!s.in_conflict() && !s.is_dirty());
        assert!(
            s.cut.is_none() && s.undo.is_empty(),
            "a merge kept state about the old tree"
        );
        assert!(matches!(s.reload(), Err(Resolve::NoConflict)));
    }

    #[test]
    fn a_save_on_request_overwrites_a_conflict() {
        let file = Temp::new("overwrite");
        let mut s = session();
        create(&mut s, &file, "pw").unwrap();
        assert_eq!(s.save_now(true), SaveNow::Clean);
        let mut other = Vault::open_with(&file.0, "pw", None, None).unwrap();
        let root = other.root_id();
        other.create_group(&root, "theirs").unwrap();
        other.save().unwrap();
        s.add_group(s.vault.as_ref().map(Vault::root_id), "ours")
            .unwrap();
        assert_eq!(s.persist(true), Saved::Conflict);
        assert_eq!(s.save_now(true), SaveNow::Overwrote);
        let back = Vault::open_with(&file.0, "pw", None, None).unwrap();
        let names: Vec<String> = back
            .groups_in(&back.root_id())
            .iter()
            .map(|g| g.name.clone())
            .collect();
        assert_eq!(names, ["ours"]);
    }

    #[test]
    fn an_in_memory_vault_stays_dirty_and_bumps_the_revision() {
        let (mut s, ..) = open();
        let before = s.revision();
        assert_eq!(s.persist(true), Saved::NoFile);
        assert!(s.is_dirty() && s.revision() != before);
        assert_eq!(s.save_now(true), SaveNow::NoFile);
    }

    // A front end caches rows against the revision, so swapping the vault in or out must move it.
    #[test]
    fn the_revision_moves_when_the_vault_is_swapped() {
        let (mut s, ..) = open();
        let open_at = s.revision();
        s.lock();
        let locked_at = s.revision();
        assert_ne!(locked_at, open_at, "a lock left the revision where it was");
        s.open(Vault::new());
        assert_ne!(
            s.revision(),
            locked_at,
            "an open left the revision where it was"
        );
    }

    #[test]
    fn a_missing_vault_or_entry_is_nothing_to_report() {
        let (mut s, _, entry) = open();
        s.lock();
        assert!(matches!(s.delete_entry(entry), Err(Delete::Missing)));
        assert!(matches!(s.paste(None), Err(Paste::Nothing)));
        s.arm_cut(Cut::Entry(entry));
        assert!(matches!(
            s.paste(Some(Vault::new().root_id())),
            Err(Paste::Locked)
        ));
    }

    #[test]
    fn delete_goes_to_the_bin_then_for_good_and_undo_brings_it_back() {
        let (mut s, banks, entry) = open();
        assert!(
            !s.delete_entry(entry).unwrap(),
            "the first delete was not to the bin"
        );
        assert!(s.vault.as_ref().unwrap().is_recycled(&entry));
        assert!(matches!(s.undo(), Some(Undone::Entry { id, .. }) if id == entry));
        assert_eq!(
            s.vault.as_ref().unwrap().parent_group_of_entry(&entry),
            Some(banks)
        );

        s.delete_entry(entry).unwrap();
        assert!(
            s.delete_entry(entry).unwrap(),
            "a delete inside the bin was not for good"
        );
        assert!(s.vault.as_ref().unwrap().get_entry(&entry).is_none());
        assert!(matches!(s.undo(), Some(Undone::Entry { title, .. }) if title == "checking"));
        assert!(s.vault.as_ref().unwrap().get_entry(&entry).is_some());
    }

    #[test]
    fn deleting_a_cut_group_disarms_the_cut() {
        let (mut s, banks, _) = open();
        s.cut = Some(Cut::Group(banks));
        assert!(!s.delete_group(banks).unwrap());
        assert!(s.cut.is_none());
        assert!(matches!(s.undo(), Some(Undone::Group { id, .. }) if id == banks));
    }

    #[test]
    fn a_paste_empties_the_shelf_and_a_failed_one_keeps_it() {
        let (mut s, banks, entry) = open();
        let root = s.vault.as_ref().unwrap().root_id();
        assert!(matches!(s.paste(Some(root)), Err(Paste::Nothing)));
        s.cut = Some(Cut::Group(root));
        assert!(matches!(s.paste(Some(banks)), Err(Paste::Vault(_))));
        assert_eq!(
            s.cut,
            Some(Cut::Group(root)),
            "a failed paste emptied the shelf"
        );
        s.cut = Some(Cut::Entry(entry));
        assert_eq!(s.paste(Some(root)).unwrap(), Cut::Entry(entry));
        assert!(s.cut.is_none());
        assert_eq!(
            s.vault.as_ref().unwrap().parent_group_of_entry(&entry),
            Some(root)
        );
    }

    #[test]
    fn a_group_moves_one_step_in_or_out_and_says_why_not() {
        let (mut s, banks, _) = open();
        let root = s.vault.as_ref().unwrap().root_id();
        let cards = s.add_group(Some(root), "Cards").unwrap();
        assert!(matches!(s.reparent_group(root, true), Err(Reparent::Root)));
        assert!(matches!(
            s.reparent_group(banks, true),
            Err(Reparent::NothingAbove)
        ));
        assert!(matches!(
            s.reparent_group(cards, false),
            Err(Reparent::AtTop)
        ));
        s.reparent_group(cards, true).unwrap();
        assert_eq!(
            s.vault.as_ref().unwrap().group_path(&cards),
            ["Root", "Banks", "Cards"]
        );
        s.reparent_group(cards, false).unwrap();
        assert_eq!(
            s.vault.as_ref().unwrap().group_path(&cards),
            ["Root", "Cards"]
        );
    }

    fn input<'a>(title: &'a str, expires: &'a str, otp: Option<&'a str>) -> EntryInput<'a> {
        EntryInput {
            title,
            username: "octo",
            password: Some("pw"),
            url: "",
            notes: "",
            tags: "work, , urgent,",
            expires,
            otp,
        }
    }

    #[test]
    fn a_form_that_cannot_be_saved_writes_nothing() {
        let (mut s, banks, _) = open();
        let before = s.vault.as_ref().unwrap().entry_count();
        let add = EntryTarget::Add(Some(banks));
        assert!(matches!(
            s.save_entry(add, &input(" ", "", None)),
            Err(EntryError::NoTitle)
        ));
        assert!(matches!(
            s.save_entry(add, &input("x", "16/09/2026", None)),
            Err(EntryError::Expiry(_))
        ));
        assert!(matches!(
            s.save_entry(add, &input("x", "", Some("not base32!"))),
            Err(EntryError::Otp(_))
        ));
        assert!(matches!(
            s.save_entry(EntryTarget::Add(None), &input("x", "", None)),
            Err(EntryError::NoGroup)
        ));
        assert_eq!(s.vault.as_ref().unwrap().entry_count(), before);
        assert!(s.undo.is_empty());
    }

    #[test]
    fn an_added_entry_carries_its_tags_and_undo_removes_it() {
        let (mut s, banks, _) = open();
        let saved = s
            .save_entry(
                EntryTarget::Add(Some(banks)),
                &input("new", "2026-09-16", None),
            )
            .unwrap();
        let id = saved.id.unwrap();
        assert_eq!(saved.otp, None);
        let vault = s.vault.as_ref().unwrap();
        assert_eq!(vault.get_entry(&id).unwrap().tags, ["work", "urgent"]);
        assert!(crate::vault::expires_at(&vault.get_entry(&id).unwrap()).is_some());
        assert!(matches!(s.undo(), Some(Undone::Removed { title }) if title == "new"));
        assert!(s.vault.as_ref().unwrap().get_entry(&id).is_none());
    }

    #[test]
    fn an_edit_keeps_an_untouched_password_and_undo_puts_the_old_one_back() {
        let (mut s, _, entry) = open();
        let mut keep = input("renamed", "", None);
        keep.password = None;
        s.save_entry(EntryTarget::Edit(entry), &keep).unwrap();
        let read = |s: &Session<Fake>| {
            let e = s.vault.as_ref().unwrap().get_entry(&entry).unwrap();
            (e.title().to_string(), e.password().to_string())
        };
        assert_eq!(read(&s), ("renamed".into(), "p".into()));
        s.save_entry(EntryTarget::Edit(entry), &input("renamed", "", None))
            .unwrap();
        assert_eq!(read(&s).1, "pw");
        s.undo();
        assert_eq!(read(&s), ("renamed".into(), "p".into()));
    }

    #[test]
    fn undo_is_bounded() {
        let (mut s, banks, _) = open();
        for n in 0..UNDO_DEPTH + 5 {
            s.rename_group(banks, &format!("name {n}")).unwrap();
        }
        assert_eq!(s.undo.len(), UNDO_DEPTH);
    }

    #[test]
    fn a_lock_wipes_the_session_but_keeps_the_touch_id_copy() {
        let file = Temp::new("lock");
        let mut s = session();
        s.touch_id = true;
        create(&mut s, &file, "pw").unwrap();
        let root = s.vault.as_ref().map(Vault::root_id);
        let group = s.add_group(root, "g").unwrap();
        s.cut = Some(Cut::Group(group));
        s.mark_dirty();
        s.lock();
        assert!(!s.is_open() && !s.is_dirty() && s.cut.is_none() && s.undo.is_empty());
        assert!(s.quick_here(), "the lock dropped what unlocks it");
        let opened = s.quick_unlock(None, None).unwrap();
        assert!(
            matches!(opened.sealing, Sealing::Skipped),
            "a fingerprint unlock sealed again"
        );
    }

    #[test]
    fn a_dismissed_prompt_keeps_the_copy_and_a_void_one_drops_it() {
        let file = Temp::new("refuse");
        let mut s = session();
        s.touch_id = true;
        create(&mut s, &file, "pw").unwrap();
        s.lock();
        REFUSE.set(Some(Refused::Again("cancelled".into())));
        assert!(matches!(
            s.quick_unlock(None, None),
            Err(QuickError::Refused(Refused::Again(_)))
        ));
        assert!(s.quick_here());
        REFUSE.set(Some(Refused::Void("fingers changed".into())));
        assert!(matches!(
            s.quick_unlock(None, None),
            Err(QuickError::Refused(Refused::Void(_)))
        ));
        assert!(!s.quick_here());
        REFUSE.set(None);
        assert!(matches!(
            s.quick_unlock(None, None),
            Err(QuickError::Nothing)
        ));
    }

    #[test]
    fn the_copy_belongs_to_one_vault_and_follows_a_password_change() {
        let file = Temp::new("aim");
        let mut s = session();
        s.touch_id = true;
        create(&mut s, &file, "old").unwrap();
        s.rekey("new", None).unwrap();
        s.lock();
        s.aim(Some(Path::new("/elsewhere/other.kdbx")));
        assert!(
            !s.quick_here(),
            "a copy sealed for one vault offered to open another"
        );
        s.aim(Some(&file.0));
        assert!(
            s.quick_unlock(None, None).is_ok(),
            "the copy still held the old password"
        );
    }

    #[test]
    fn a_mac_without_a_sensor_turns_touch_id_off_once() {
        let file = Temp::new("nosensor");
        let mut s = session();
        s.touch_id = true;
        NO_SENSOR.set(true);
        let made = create(&mut s, &file, "pw");
        NO_SENSOR.set(false);
        assert!(matches!(made.unwrap().sealing, Sealing::Off(_)));
        assert!(!s.touch_id && !s.quick_here());
    }

    #[test]
    fn idleness_counts_only_with_a_vault_open() {
        let (mut s, ..) = open();
        let later = Instant::now() + Duration::from_secs(61);
        assert!(!s.idle_expired(later), "no timeout set, yet it expired");
        s.set_lock_timeout(60);
        assert!(s.idle_expired(later));
        s.touch();
        assert!(!s.idle_expired(Instant::now()));
        s.lock();
        assert!(!s.idle_expired(later));
    }

    #[test]
    fn the_time_left_counts_down_to_the_lock() {
        let (mut s, ..) = open();
        assert_eq!(
            s.locks_in(Instant::now()),
            None,
            "no timeout set, yet a lock is due"
        );
        s.set_lock_timeout(60);
        s.touch();
        let now = Instant::now();
        let left = s.locks_in(now + Duration::from_secs(20)).unwrap();
        assert!(
            left <= Duration::from_secs(40) && left > Duration::from_secs(38),
            "{left:?}"
        );
        assert_eq!(
            s.locks_in(now + Duration::from_secs(90)),
            Some(Duration::ZERO)
        );
        s.lock();
        assert_eq!(s.locks_in(now), None);
    }
}
