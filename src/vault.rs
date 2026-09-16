/* Thin adapter over the `keepass` crate's Database, which already is the
   domain model (groups/entries keyed by stable uuid ids, secrets held in
   zeroizing SecretBoxes). No parallel model: a second Group/Entry pair would
   need a mapping layer and every op implemented twice. This module adds only
   what Sennel needs on top: guarded moves/deletes, paths, and ordered child
   views for the panes. File IO lives here too.

   Why keepass 13 not keepass-rs 02: keepass-rs 0.2 cannot read real
   KeePassXC files — a correct password fails parsing (CBC padding / header
   HMAC errors on vanilla KDBX 3.1 and 4.1). The `keepass` crate round-trips
   with keepassxc-cli in both directions, which is the bar. */

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use keepass::{
    db::{Entry, EntryId, EntryMut, EntryRef, GroupId, GroupRef, Times},
    error::{
        CryptographyError, DatabaseKeyError, DatabaseOpenError, DestinationGroupNotFoundError,
        DuplicateEntryIdError, MoveGroupError,
    },
    Database, DatabaseKey,
};

/* The five standard field names. Strings rather than the crate's constants:
   they are stable parts of the KDBX format, and one less re-export to chase. */
pub const TITLE: &str = "Title";
pub const USERNAME: &str = "UserName";
pub const PASSWORD: &str = "Password";
pub const URL: &str = "URL";
pub const NOTES: &str = "Notes";

/// Field reads as plain strings, defaulting to "" — KDBX entries may omit
/// any field, and the UI and search want a printable &str, not Options.
pub trait EntryExt {
    fn title(&self) -> &str;
    fn username(&self) -> &str;
    fn password(&self) -> &str;
    fn url(&self) -> &str;
    fn notes(&self) -> &str;
}

/* Field reads as plain strings, defaulting to "" — KDBX entries may omit
   any field, and the UI and search want a printable &str, not Options.
   Macro-read: the same five reads apply to the owned record and to the
   crate's borrowed Ref wrappers (the blanket-impl route collides because
   Deref overlaps Entry itself). */
macro_rules! impl_entry_ext {
    ($t:ty) => {
        impl EntryExt for $t {
            fn title(&self) -> &str {
                self.get_title().unwrap_or("")
            }
            fn username(&self) -> &str {
                self.get_username().unwrap_or("")
            }
            fn password(&self) -> &str {
                self.get_password().unwrap_or("")
            }
            fn url(&self) -> &str {
                self.get_url().unwrap_or("")
            }
            fn notes(&self) -> &str {
                self.get(NOTES).unwrap_or("")
            }
        }
    };
}

impl_entry_ext!(Entry);
impl_entry_ext!(EntryRef<'_>);
impl_entry_ext!(EntryMut<'_>);

/// What a guarded vault op refused, and why. A plain enum rather than anyhow:
/// the UI matches on variants to name the next step ("empty the group first").
/* Payloads are Strings, not sources: io and database errors stay
   assert_eq-friendly, and the UI only ever displays them. */
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VaultError {
    GroupNotFound,
    EntryNotFound,
    GroupNotEmpty,
    CannotDeleteRoot,
    CannotMoveRoot,
    WouldCycle,
    /// Password, key file, or both did not open the database.
    WrongPassword,
    /// `save` before any `open` or `save_as` gave the vault a path and a key.
    Unsaved,
    /// The file changed under us since it was opened or last written, so a
    /// save would overwrite whatever wrote it. Refused until forced.
    ChangedOnDisk,
    Io(String),
    Db(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::GroupNotFound => write!(f, "no such group"),
            VaultError::EntryNotFound => write!(f, "no such entry"),
            VaultError::GroupNotEmpty => write!(f, "group is not empty"),
            VaultError::CannotDeleteRoot => write!(f, "cannot delete the root group"),
            VaultError::CannotMoveRoot => write!(f, "cannot move the root group"),
            VaultError::WouldCycle => write!(f, "cannot move a group into itself"),
            VaultError::WrongPassword => write!(f, "wrong password or key file"),
            VaultError::Unsaved => write!(f, "nothing to save to yet"),
            VaultError::ChangedOnDisk => write!(f, "the file changed on disk"),
            VaultError::Io(e) => write!(f, "file error: {e}"),
            VaultError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for VaultError {}

pub struct Vault {
    db: Database,
    /* The key stays with the vault so `save` needs no password prompt:
       re-asking on every save would train "type it without thinking".
       DatabaseKey zeroizes on drop, so holding it is holding secrets right.
       It is held by value: `save` consumes a clone of it. */
    key: Option<DatabaseKey>,
    path: Option<PathBuf>,
    /* What the file looked like when this vault last agreed with it. Sennel
       autosaves after every change, so without this a KeePassXC edit (or a
       sync client, or a second Sennel) is overwritten by the next keypress
       here, atomically and without a word. */
    stamp: Option<Stamp>,
}

/// Enough of a file's identity to notice somebody else wrote it. Modified
/// time and length rather than a hash: a vault is megabytes and this runs on
/// every save.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Stamp {
    modified: Option<std::time::SystemTime>,
    len: u64,
}

impl Stamp {
    /// `None` when the file is not there to stamp — which is itself a change
    /// worth refusing on, since something removed it.
    fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Stamp {
            modified: meta.modified().ok(),
            len: meta.len(),
        })
    }
}

impl Vault {
    /// Fresh KDBX4 database with one empty root group. `Database::new`
    /// generates the root itself; this just names it.
    pub fn new() -> Self {
        let mut db = Database::new();
        db.root_mut().name = "Root".into();
        Vault {
            db,
            key: None,
            path: None,
            stamp: None,
        }
    }

    /* A wrong key shows differently by version: KDBX4 verifies the header
       HMAC first (IncorrectKey), while a KDBX3 file decrypts your key into
       garbage that fails the final padding check (InvalidPadding). Both are
       "the key did not open it". A genuinely bad password on a corrupt file
       keeps arriving as one of these, which is exactly what users see in
       KeePass clients. The converse is inherent to KDBX3 (it has no header
       HMAC): a corrupt or truncated KDBX3 body also fails the padding check
       and reports as WrongPassword even with the right key. No client can
       tell those apart before decrypting, so we do not pretend to. */
    fn map_db_error(e: DatabaseOpenError) -> VaultError {
        match e {
            DatabaseOpenError::Key(ref key_err)
                if matches!(key_err, DatabaseKeyError::IncorrectKey) =>
            {
                VaultError::WrongPassword
            }
            DatabaseOpenError::Cryptography(ref crypto_err) => {
                if matches!(crypto_err, CryptographyError::InvalidPadding(_)) {
                    VaultError::WrongPassword
                } else {
                    VaultError::Db(e.to_string())
                }
            }
            other => VaultError::Db(other.to_string()),
        }
    }

    fn build_key(password: &str, key_file: Option<&[u8]>) -> Result<DatabaseKey, VaultError> {
        let mut key = DatabaseKey::new().with_password(password);
        if let Some(data) = key_file {
            /* with_keyfile wants a reader, not bytes. */
            key = key
                .with_keyfile(&mut std::io::Cursor::new(data))
                .map_err(|e| VaultError::Io(e.to_string()))?;
        }
        Ok(key)
    }

    /// Open an existing `.kdbx` file. The password string is copied into the
    /// retained key; the caller zeroizes its own buffer.
    pub fn open(
        path: &Path,
        password: &str,
        key_file: Option<&[u8]>,
    ) -> Result<Self, VaultError> {
        let mut file = std::fs::File::open(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let key = Self::build_key(password, key_file)?;
        let db = Database::open(&mut file, key.clone()).map_err(Self::map_db_error)?;
        Ok(Vault {
            db,
            key: Some(key),
            path: Some(path.to_path_buf()),
            stamp: Stamp::of(path),
        })
    }

    /// Write to the path this vault was opened from or last saved to.
    /// Refuses with `ChangedOnDisk` when somebody else wrote the file since;
    /// `save_over` is the deliberate way past that.
    pub fn save(&mut self) -> Result<(), VaultError> {
        if self.changed_on_disk() {
            return Err(VaultError::ChangedOnDisk);
        }
        self.write_and_stamp()
    }

    /// Save regardless of what is on disk now. The caller has told the user
    /// what they are about to lose and been told to go ahead.
    pub fn save_over(&mut self) -> Result<(), VaultError> {
        self.write_and_stamp()
    }

    /// Whether the file has moved on without us. False for a vault with no
    /// path (nothing to disagree with) and for one never yet written.
    pub fn changed_on_disk(&self) -> bool {
        let (Some(path), Some(stamp)) = (self.path.as_ref(), self.stamp) else {
            return false;
        };
        Stamp::of(path) != Some(stamp)
    }

    /// Re-read the file this vault came from, using the key already held —
    /// the way out of a conflict that keeps the other program's work.
    pub fn reload(&mut self) -> Result<(), VaultError> {
        let (Some(path), Some(key)) = (self.path.clone(), self.key.clone()) else {
            return Err(VaultError::Unsaved);
        };
        let mut file = std::fs::File::open(&path).map_err(|e| VaultError::Io(e.to_string()))?;
        self.db = Database::open(&mut file, key).map_err(Self::map_db_error)?;
        self.stamp = Stamp::of(&path);
        Ok(())
    }

    fn write_and_stamp(&mut self) -> Result<(), VaultError> {
        let (Some(path), Some(key)) = (self.path.clone(), self.key.as_ref()) else {
            return Err(VaultError::Unsaved);
        };
        Self::write_file(&self.db, key, &path)?;
        self.stamp = Stamp::of(&path);
        Ok(())
    }

    /// First save of a new vault: records the path and key, so later `save`
    /// calls need neither.
    pub fn save_as(
        &mut self,
        path: &Path,
        password: &str,
        key_file: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        let key = Self::build_key(password, key_file)?;
        Self::write_file(&self.db, &key, path)?;
        self.key = Some(key);
        self.path = Some(path.to_path_buf());
        self.stamp = Stamp::of(path);
        Ok(())
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /* Beside the target and renamed over it: a truncated write turns a
       half-written kdbx into nothing. Mode 0600, because this file holds
       every secret at once. */
    fn write_file(db: &Database, key: &DatabaseKey, path: &Path) -> Result<(), VaultError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| VaultError::Io(e.to_string()))?;
        }
        let temp = path.with_extension(format!("{}.tmp", std::process::id()));
        use std::os::unix::fs::OpenOptionsExt;
        /* 0600 from the first byte: File::create + set_permissions afterwards
           would leave a umask-wide window holding a full plaintext-free but
           still sensitive copy of the vault. */
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| VaultError::Io(e.to_string()));
        let mut out = match opened {
            Ok(f) => f,
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                return Err(e);
            }
        };
        if let Err(e) = db.save(&mut out, key.clone()) {
            drop(out);
            let _ = std::fs::remove_file(&temp);
            return Err(VaultError::Db(e.to_string()));
        }
        drop(out);
        if let Err(e) = std::fs::rename(&temp, path) {
            let _ = std::fs::remove_file(&temp);
            return Err(VaultError::Io(e.to_string()));
        }
        Ok(())
    }

    /* Escape hatch for exceptional reads. The 0.13 rewrite left no prod
       caller (previous uses read password strings and entry maps), but it
       stays as the sanctioned read-only back door so tests and future
       scripts do not bypass the guarded methods. */
    #[allow(dead_code)]
    pub fn db(&self) -> &Database {
        &self.db
    }

    /* Test-only: prod paths go through guarded Vault methods that keep the
       cursors and the dirty flag consistent. db_mut escapes those guards,
       so it stays behind this comment as the documented back door for tests
       that need to stamp timestamps directly. */
    #[allow(dead_code)]
    pub fn db_mut(&mut self) -> &mut Database {
        &mut self.db
    }

    pub fn root_id(&self) -> GroupId {
        /* Set by new() and never cleared: root deletion is refused below. */
        self.db.root().id()
    }

    pub fn get_group(&self, id: &GroupId) -> Option<GroupRef<'_>> {
        self.db.group(*id)
    }

    pub fn get_entry(&self, id: &EntryId) -> Option<EntryRef<'_>> {
        self.db.entry(*id)
    }

    /// Total entries across all groups, for the unlock flash.
    pub fn entry_count(&self) -> usize {
        self.db.num_entries() - self.recycled().len()
    }

    /// Total groups, for the --list header.
    pub fn num_groups(&self) -> usize {
        self.db.num_groups()
    }

    /* Recycle-bin entries are trash: the group walk still surfaces the bin to
       a user who goes looking for it (it is a group like any other), but
       counts and the flattened global scope skip its subtree. A real
       KeePassXC vault parks deleted entries there, and an honest
       "unlocked N entries" or search hit must not include deleted things. */
    fn recycled(&self) -> HashSet<EntryId> {
        let mut out = HashSet::new();
        let Some(bin) = self.db.recycle_bin() else {
            return out;
        };
        let mut stack = vec![bin.id()];
        while let Some(id) = stack.pop() {
            let Some(group) = self.db.group(id) else {
                continue;
            };
            out.extend(group.entry_ids());
            stack.extend(group.group_ids());
        }
        out
    }

    /// Every live entry id in the file, for the global search scope.
    pub fn all_entry_ids(&self) -> Vec<EntryId> {
        let dead = self.recycled();
        self.db.iter_all_entries().map(|e| e.id()).filter(|id| !dead.contains(id)).collect()
    }

    /// Every live entry as a ref in one borrowed batch: the entries-pane
    /// views sort and filter across all of them per call.
    pub fn entry_refs(&self) -> Vec<EntryRef<'_>> {
        let dead = self.recycled();
        self.db.iter_all_entries().filter(|e| !dead.contains(&e.id())).collect()
    }

    /* Expansion is presentation, not data: toggling it does not mark the vault
       dirty, so folding the tree never triggers the quit guard. KeePass does
       store the flag, so it rides along on the next real save. */
    pub fn set_expanded(&mut self, id: &GroupId, expanded: bool) {
        if let Some(mut group) = self.db.group_mut(*id) {
            group.edit(|g| g.is_expanded = expanded);
        }
    }

    /// Children of a group in stored order. Order is a view concern (Wave 5
    /// sorts on top of this); the vec order is insertion order.
    pub fn groups_in(&self, parent: &GroupId) -> Vec<GroupRef<'_>> {
        self.db
            .group(*parent)
            .map(|g| g.group_ids().filter_map(|id| self.db.group(id)).collect())
            .unwrap_or_default()
    }

    pub fn entries_in(&self, group: &GroupId) -> Vec<EntryRef<'_>> {
        self.db
            .group(*group)
            .map(|g| g.entry_ids().filter_map(|id| self.db.entry(id)).collect())
            .unwrap_or_default()
    }

    /// Titles from the root down to `id`, for the "General / Banks" breadcrumb
    /// and the search haystack. Root itself yields one element.
    pub fn group_path(&self, id: &GroupId) -> Vec<String> {
        let mut path = Vec::new();
        let mut at = *id;
        loop {
            let Some(group) = self.db.group(at) else {
                return Vec::new();
            };
            path.push(group.name.clone());
            let Some(parent) = group.parent() else {
                break;
            };
            at = parent.id();
        }
        path.reverse();
        path
    }

    /// Parent of a group via the stored back-pointer.
    #[allow(dead_code)]
    pub fn parent_group(&self, id: &GroupId) -> Option<GroupId> {
        self.db.group(*id).map(|g| g.parent().map(|p| p.id())).unwrap_or(None)
    }

    pub fn parent_group_of_entry(&self, id: &EntryId) -> Option<GroupId> {
        self.db.entry(*id).map(|e| e.parent().id())
    }

    pub fn create_group(&mut self, parent: &GroupId, name: &str) -> Result<GroupId, VaultError> {
        if self.db.group(*parent).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        let mut parent = self
            .db
            .group_mut(*parent)
            .expect("just checked the group exists");
        let mut child = parent.add_group();
        child.name = name.to_string();
        Ok(child.id())
    }

    pub fn rename_group(&mut self, id: &GroupId, name: &str) -> Result<(), VaultError> {
        let Some(mut group) = self.db.group_mut(*id) else {
            return Err(VaultError::GroupNotFound);
        };
        group.name = name.to_string();
        Ok(())
    }

    /* A group moves with its whole subtree: children live behind the group's
       id, so only the child lists change. The move_to guard mirrors ours. */
    pub fn move_group(&mut self, id: &GroupId, new_parent: &GroupId) -> Result<(), VaultError> {
        if *id == self.root_id() {
            return Err(VaultError::CannotMoveRoot);
        }
        if self.db.group(*new_parent).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        let Some(mut group) = self.db.group_mut(*id) else {
            return Err(VaultError::GroupNotFound);
        };
        group.move_to(*new_parent).map_err(|e| match e {
            MoveGroupError::CannotMoveRoot => VaultError::CannotMoveRoot,
            MoveGroupError::NotFound(_) => VaultError::GroupNotFound,
            MoveGroupError::WouldCreateCycle => VaultError::WouldCycle,
            _ => VaultError::Db(e.to_string()),
        })
    }

    /* Refuses non-empty groups rather than deleting recursively: a recursive
       delete is one keypress from losing a subtree. The guard runs before
       GroupMut::remove, which recurses, so the recursion never fires here. */
    pub fn delete_group(&mut self, id: &GroupId) -> Result<(), VaultError> {
        if *id == self.root_id() {
            return Err(VaultError::CannotDeleteRoot);
        }
        let Some(group) = self.db.group(*id) else {
            return Err(VaultError::GroupNotFound);
        };
        if group.entry_ids().next().is_some() || group.group_ids().next().is_some() {
            return Err(VaultError::GroupNotEmpty);
        }
        let Some(group) = self.db.group_mut(*id) else {
            return Err(VaultError::GroupNotFound);
        };
        group.remove();
        Ok(())
    }

    /* Notes ride protected here where KeePass convention stores them in the
       clear. It round-trips (a keepassxc-cli-written fixture's notes read
       back; our files open there too) and protecting them only ever hides
       more — left as-is deliberately. */
    pub fn create_entry(
        &mut self,
        group: &GroupId,
        title: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
    ) -> Result<EntryId, VaultError> {
        if self.db.group(*group).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        let mut parent = self
            .db
            .group_mut(*group)
            .expect("just checked the group exists");
        let mut entry = parent.add_entry();
        entry.set_unprotected(TITLE, title);
        entry.set_unprotected(USERNAME, username);
        entry.set_protected(PASSWORD, password);
        entry.set_unprotected(URL, url);
        entry.set_protected(NOTES, notes);
        Ok(entry.id())
    }

    pub fn update_entry(
        &mut self,
        id: &EntryId,
        title: &str,
        username: &str,
        password: Option<&str>,
        url: &str,
        notes: &str,
    ) -> Result<(), VaultError> {
        /* Password is Option: the edit form sends None when the box was left
           untouched, so an edit that never looked at the secret keeps it. */
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        entry.set_unprotected(TITLE, title);
        entry.set_unprotected(USERNAME, username);
        if let Some(pw) = password {
            entry.set_protected(PASSWORD, pw);
        }
        entry.set_unprotected(URL, url);
        entry.set_protected(NOTES, notes);
        /* The editor is the only thing that mutates an entry in Sennel, so
           this is where the modification stamp moves forward (`updated`
           sort reads it). */
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    /* EntryMut::move_to keeps both child lists and the back-pointer in step
       with one call. */
    pub fn move_entry(&mut self, id: &EntryId, new_group: &GroupId) -> Result<(), VaultError> {
        if self.db.group(*new_group).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        entry
            .move_to(*new_group)
            .map_err(|_: DestinationGroupNotFoundError| VaultError::GroupNotFound)
    }

    /* Direct delete, no recycle bin in v1: the vault keeps deleted objects in
       the file's recycle bin only if KeePass itself routed them there, and
       the confirm prompt is what guards it here. */
    pub fn delete_entry(&mut self, id: &EntryId) -> Result<(), VaultError> {
        let Some(entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        entry.remove();
        Ok(())
    }

    /* Undo support (Wave 7): the app snapshots whole entries and calls back
       here to restore them. */
    /// Swap an entry wholesale — the original timestamps ride along, which
    /// an update_entry-based undo would not preserve.
    pub fn replace_entry(&mut self, entry: &Entry) -> Result<(), VaultError> {
        let Some(mut slot) = self.db.entry_mut(entry.id()) else {
            return Err(VaultError::EntryNotFound);
        };
        *slot = entry.clone();
        Ok(())
    }

    /// Re-insert a deleted entry under `parent`. Appends at the end: the
    /// snapshot carries the record but not its slot in the child list, and
    /// a one-level undo that restores content is worth the position it
    /// cannot bring back.
    /* The caller must hand back the parent the snapshot was taken from —
       that is what the undo slot records — because the whole-record clone
       also carries the snapshot's own back-pointer, and a different parent
       would leave group child list and entry pointing at different places
       (Entry's parent field is crate-private, so we cannot fix it here).
       DuplicateEntryIdError maps to EntryNotFound as "cannot restore into
       a slot that is not empty": the entry exists where it should not. */
    pub fn restore_entry(&mut self, entry: &Entry, parent: &GroupId) -> Result<(), VaultError> {
        let Some(mut group) = self.db.group_mut(*parent) else {
            return Err(VaultError::GroupNotFound);
        };
        let mut slot = group
            .add_entry_with_id(entry.id())
            .map_err(|_: DuplicateEntryIdError| VaultError::EntryNotFound)?;
        *slot = entry.clone();
        Ok(())
    }

    /// Hard-remove an entry an undo needs to disappear again (an add that
    /// `u` takes back). No tombstone — this rolls back, it does not delete.
    pub fn expunge_entry(&mut self, id: &EntryId) -> Result<(), VaultError> {
        self.delete_entry(id)
    }

    /// Title write for rename undo.
    pub fn set_group_title(&mut self, id: &GroupId, title: &str) -> Result<(), VaultError> {
        let Some(mut group) = self.db.group_mut(*id) else {
            return Err(VaultError::GroupNotFound);
        };
        group.name = title.to_string();
        Ok(())
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        Vault::new()
    }

    #[test]
    fn a_new_vault_holds_one_empty_root() {
        let v = vault();
        let root = v.root_id();
        assert_eq!(v.get_group(&root).unwrap().name, "Root");
        assert!(v.groups_in(&root).is_empty());
        assert!(v.entries_in(&root).is_empty());
    }

    #[test]
    fn groups_create_nest_and_rename_keeping_stable_ids() {
        let mut v = vault();
        let root = v.root_id();
        let banks = v.create_group(&root, "Banks").unwrap();
        let savings = v.create_group(&banks, "Savings").unwrap();
        v.rename_group(&banks, "Money").unwrap();

        assert_eq!(v.get_group(&banks).unwrap().name, "Money");
        assert_eq!(v.group_path(&savings), vec!["Root", "Money", "Savings"]);
        let kids: Vec<GroupId> = v.groups_in(&root).iter().map(|g| g.id()).collect();
        assert_eq!(kids, vec![banks]);
    }

    #[test]
    fn deleting_a_non_empty_group_refuses_then_succeeds_once_emptied() {
        let mut v = vault();
        let root = v.root_id();
        let g = v.create_group(&root, "Mail").unwrap();
        v.create_entry(&g, "inbox", "u", "p", "", "").unwrap();

        assert_eq!(v.delete_group(&g), Err(VaultError::GroupNotEmpty));
        assert!(v.get_group(&g).is_some(), "refused delete still removed it");

        let e = v.entries_in(&g)[0].id();
        v.delete_entry(&e).unwrap();
        v.delete_group(&g).unwrap();
        assert!(v.get_group(&g).is_none());
    }

    #[test]
    fn the_root_can_neither_move_nor_go() {
        let mut v = vault();
        let root = v.root_id();
        let other = v.create_group(&root, "Other").unwrap();
        assert_eq!(v.delete_group(&root), Err(VaultError::CannotDeleteRoot));
        assert_eq!(
            v.move_group(&root, &other),
            Err(VaultError::CannotMoveRoot)
        );
    }

    #[test]
    fn a_group_cannot_move_into_its_own_subtree() {
        let mut v = vault();
        let root = v.root_id();
        let a = v.create_group(&root, "a").unwrap();
        let b = v.create_group(&a, "b").unwrap();
        assert_eq!(v.move_group(&a, &b), Err(VaultError::WouldCycle));
        assert!(v.parent_group(&a).is_some());
    }

    #[test]
    fn groups_move_with_their_subtree_intact() {
        let mut v = vault();
        let root = v.root_id();
        let a = v.create_group(&root, "a").unwrap();
        let b = v.create_group(&root, "b").unwrap();
        let e = v.create_entry(&a, "t", "u", "p", "", "").unwrap();

        v.move_group(&a, &b).unwrap();
        assert_eq!(v.parent_group(&a), Some(b));
        assert_eq!(v.entries_in(&a).len(), 1);
        assert_eq!(v.parent_group_of_entry(&e), Some(a));
    }

    #[test]
    fn entries_create_edit_move_and_delete() {
        let mut v = vault();
        let root = v.root_id();
        let g = v.create_group(&root, "g").unwrap();
        let e = v.create_entry(&g, "github", "octo", "s3cret", "https://x", "n").unwrap();

        v.update_entry(&e, "github", "octo2", None, "https://x", "n")
            .unwrap();
        let kept = v.get_entry(&e).unwrap();
        assert_eq!(kept.username(), "octo2");
        assert_eq!(kept.password(), "s3cret", "untouched password changed");

        v.move_entry(&e, &root).unwrap();
        assert_eq!(v.parent_group_of_entry(&e), Some(root));
        assert!(v.entries_in(&g).is_empty());

        v.delete_entry(&e).unwrap();
        assert!(v.get_entry(&e).is_none());
        assert_eq!(v.delete_entry(&e), Err(VaultError::EntryNotFound));
    }

    #[test]
    fn unknown_ids_are_an_error_not_a_panic() {
        let mut v = vault();
        let ghost = GroupId::new();
        let ghost_entry = EntryId::new();
        let root = v.root_id();
        assert_eq!(v.rename_group(&ghost, "x"), Err(VaultError::GroupNotFound));
        assert_eq!(v.move_entry(&ghost_entry, &root), Err(VaultError::EntryNotFound));
        assert!(v.group_path(&ghost).is_empty());
    }

    /* Unique per call, not just per process: the harness runs tests in
       parallel, and two sharing a path would delete each other's file. */
    struct Temp {
        path: std::path::PathBuf,
    }

    impl Temp {
        fn new(tag: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Temp {
                path: std::env::temp_dir()
                    .join(format!("sennel-test-{tag}-{}-{n}.kdbx", std::process::id())),
            }
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn saved_vault(file: &Temp) -> Vault {
        let mut v = vault();
        let root = v.root_id();
        let banks = v.create_group(&root, "Banks").unwrap();
        v.create_entry(&banks, "checking", "octo", "s3cret", "https://x", "n")
            .unwrap();
        v.save_as(&file.path, "correct horse", None).unwrap();
        v
    }

    #[test]
    fn a_saved_vault_reopens_with_everything_it_held() {
        let file = Temp::new("roundtrip");
        let saved = saved_vault(&file);
        assert_eq!(saved.path(), Some(file.path.as_path()));

        let open = Vault::open(&file.path, "correct horse", None).unwrap();
        let banks = open.groups_in(&open.root_id())[0].id();
        assert_eq!(open.group_path(&banks), vec!["Root", "Banks"]);
        let entry = &open.entries_in(&banks)[0];
        assert_eq!(entry.title(), "checking");
        assert_eq!(entry.username(), "octo");
        assert_eq!(entry.password(), "s3cret");
        assert_eq!(open.path(), Some(file.path.as_path()));
    }

    #[test]
    fn a_wrong_password_is_a_wrong_password_not_a_corrupt_file() {
        let file = Temp::new("wrongpw");
        saved_vault(&file);
        assert!(
            matches!(
                Vault::open(&file.path, "wrong battery", None),
                Err(VaultError::WrongPassword)
            ),
            "a wrong password came back as something else"
        );
    }

    #[test]
    fn a_missing_file_is_an_io_error() {
        let missing = std::env::temp_dir().join(format!(
            "sennel-test-absent-{}.kdbx",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        assert!(matches!(
            Vault::open(&missing, "pw", None),
            Err(VaultError::Io(_))
        ));
    }

    #[test]
    fn save_before_any_path_is_an_error_not_a_panic() {
        let mut v = vault();
        assert_eq!(v.save(), Err(VaultError::Unsaved));
    }

    /* Sennel autosaves after every change, so a vault that has moved on under
       us must refuse the write: the alternative is this session silently
       winning every race with KeePassXC or a sync client. */
    #[test]
    fn a_file_written_by_somebody_else_refuses_the_next_save() {
        let file = Temp::new("conflict");
        let mut ours = vault();
        ours.save_as(&file.path, "pw", None).unwrap();

        // Another program writes the same vault, from its own copy.
        let mut theirs = Vault::open(&file.path, "pw", None).unwrap();
        let root = theirs.root_id();
        theirs.create_entry(&root, "added elsewhere", "", "", "", "").unwrap();
        /* Stamps are seconds-granular on some filesystems, so make the length
           differ too — which a real edit does anyway. */
        theirs.save().unwrap();

        assert!(ours.changed_on_disk(), "the change went unnoticed");
        assert_eq!(ours.save(), Err(VaultError::ChangedOnDisk));
        // Their entry is still there: the refusal actually protected it.
        let reread = Vault::open(&file.path, "pw", None).unwrap();
        assert_eq!(reread.entry_count(), 1);

        // Deliberately overriding writes ours and re-agrees with the file.
        ours.save_over().unwrap();
        assert!(!ours.changed_on_disk());
        assert_eq!(Vault::open(&file.path, "pw", None).unwrap().entry_count(), 0);
    }

    /* The other way out of a conflict: take theirs, using the key already
       held so nobody retypes a master password to resolve a race. */
    #[test]
    fn reload_takes_the_copy_on_disk() {
        let file = Temp::new("reload");
        let mut ours = vault();
        ours.save_as(&file.path, "pw", None).unwrap();
        let mut theirs = Vault::open(&file.path, "pw", None).unwrap();
        let root = theirs.root_id();
        theirs.create_entry(&root, "added elsewhere", "", "", "", "").unwrap();
        theirs.save().unwrap();

        assert_eq!(ours.entry_count(), 0);
        ours.reload().unwrap();
        assert_eq!(ours.entry_count(), 1, "reload did not take theirs");
        assert!(!ours.changed_on_disk(), "reload left the stamp stale");
        ours.save().unwrap();
    }

    #[test]
    fn edits_save_through_the_retained_key_and_path() {
        let file = Temp::new("resave");
        let mut v = saved_vault(&file);
        let banks = v.groups_in(&v.root_id())[0].id();
        let e = v.entries_in(&banks)[0].id();
        v.update_entry(&e, "checking", "octo2", None, "https://x", "n")
            .unwrap();
        v.save().unwrap();

        let open = Vault::open(&file.path, "correct horse", None).unwrap();
        let entry = &open.entries_in(&banks)[0];
        assert_eq!(entry.username(), "octo2");
        assert_eq!(entry.password(), "s3cret", "untouched password changed");
    }

    /* The file holds every secret at once: group-readable is a leak, and the
       temp-file dance must not be what widens it. */
    #[test]
    #[cfg(unix)]
    fn the_saved_file_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let file = Temp::new("mode");
        saved_vault(&file);
        let mode = std::fs::metadata(&file.path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the save widened who can read the vault");
    }

    /* The file this whole migration exists for: a vault written by
       KeePassXC, not by our own library. keepass-rs 0.2 round-tripped
       perfectly with itself and still could not open these — every test
       passed while the real thing failed. This fixture is generated by
       keepassxc-cli (see the git history of this test) with a known
       password, so it pins the third-party-writer class of bug for good.
       Synthetic vault only: real .kdbx files must never enter the repo. */
    #[test]
    fn a_keepassxc_written_vault_opens_with_the_right_password() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keepassxc3.kdbx");
        let vault = Vault::open(&path, "sennel-fixture", None).unwrap();
        let ids = vault.all_entry_ids();
        let entry = vault.get_entry(&ids[0]).unwrap();
        assert_eq!(entry.title(), "xc entry");
        assert_eq!(entry.username(), "octo");
        assert_eq!(entry.url(), "https://example.test");
        assert_eq!(entry.password(), "sennel-entry-pw");
    }

    /* And the failure mode has to stay honest: wrong key on a real-world
       file says the key was wrong, not that the file is broken. */
    #[test]
    fn a_keepassxc_written_vault_names_a_wrong_password_honestly() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keepassxc3.kdbx");
        assert!(matches!(
            Vault::open(&path, "not the password", None),
            Err(VaultError::WrongPassword)
        ));
    }
}
