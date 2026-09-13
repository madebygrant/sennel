/* Thin wrapper over keepass-rs's Database, which already is the domain
   model (HashMap groups/entries keyed by stable NodeIds, ProtectedStrings
   that zeroize on drop). No parallel model: a second Group/Entry pair would
   need a mapping layer in Wave 2 and every op implemented twice. This module
   adds only what sennel needs on top: guarded moves/deletes, paths, and
   ordered child views for the panes. File IO lives here too in Wave 2. */

use std::path::{Path, PathBuf};

use keepass_rs::{
    open_database, save_database, CompositeKey, Database, DatabaseError, DatabaseVersion, Entry,
    Group, NodeId, ProtectedString,
};

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
       CompositeKey zeroizes on drop, so holding it is holding secrets right. */
    key: Option<CompositeKey>,
    path: Option<PathBuf>,
}

impl Vault {
    /// Fresh KDBX4 database with one empty root group. `Database::new` leaves
    /// `root_group_id` unset, and every op below assumes a root exists.
    pub fn new() -> Self {
        let mut db = Database::new(DatabaseVersion::KDBX4);
        let mut root = Group::new(NodeId::new_uuid());
        root.title = "Root".into();
        let id = root.id;
        db.groups.insert(id, root);
        db.root_group_id = Some(id);
        Vault {
            db,
            key: None,
            path: None,
        }
    }

    /* KDBX4 verifies the header HMAC before decrypting, so a wrong password
       arrives as DecryptionError("Header HMAC mismatch") rather than
       InvalidCredentials. An HMAC mismatch is cryptographically
       indistinguishable from a wrong key, which is why KeePass clients report
       both the same way; a genuinely corrupt file just keeps saying it. */
    fn map_db_error(e: DatabaseError) -> VaultError {
        match e {
            DatabaseError::InvalidKey
            | DatabaseError::InvalidCredentials
            | DatabaseError::DecryptionError(_) => VaultError::WrongPassword,
            other => VaultError::Db(other.to_string()),
        }
    }

    fn build_key(password: &[u8], key_file: Option<&[u8]>) -> CompositeKey {
        let mut key = CompositeKey::new().with_password(password);
        if let Some(data) = key_file {
            key = key.with_key_file(data);
        }
        key
    }

    /// Open an existing `.kdbx` file. The password bytes are copied into the
    /// retained key; the caller zeroizes its own buffer.
    pub fn open(
        path: &Path,
        password: &[u8],
        key_file: Option<&[u8]>,
    ) -> Result<Self, VaultError> {
        let file = std::fs::File::open(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let key = Self::build_key(password, key_file);
        let db = open_database(file, &key).map_err(Self::map_db_error)?;
        Ok(Vault {
            db,
            key: Some(key),
            path: Some(path.to_path_buf()),
        })
    }

    /// Write to the path this vault was opened from or last saved to.
    pub fn save(&self) -> Result<(), VaultError> {
        let (Some(path), Some(key)) = (self.path.as_ref(), self.key.as_ref()) else {
            return Err(VaultError::Unsaved);
        };
        Self::write_file(&self.db, key, path)
    }

    /// First save of a new vault: records the path and key, so later `save`
    /// calls need neither.
    pub fn save_as(
        &mut self,
        path: &Path,
        password: &[u8],
        key_file: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        let key = Self::build_key(password, key_file);
        Self::write_file(&self.db, &key, path)?;
        self.key = Some(key);
        self.path = Some(path.to_path_buf());
        Ok(())
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /* Beside the target and renamed over it: `save_database` truncates first
       through an interrupted write, and a half-written kdbx opens as nothing.
       Mode 0600, because this file holds every secret at once. */
    fn write_file(db: &Database, key: &CompositeKey, path: &Path) -> Result<(), VaultError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| VaultError::Io(e.to_string()))?;
        }
        let temp = path.with_extension(format!(
            "{}.tmp",
            std::process::id()
        ));
        let mut out = std::fs::File::create(&temp).map_err(|e| VaultError::Io(e.to_string()))?;
        save_database(&mut out, db, key).map_err(Self::map_db_error)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| VaultError::Io(e.to_string()))?;
        std::fs::rename(&temp, path).map_err(|e| VaultError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn db_mut(&mut self) -> &mut Database {
        &mut self.db
    }

    pub fn root_id(&self) -> NodeId {
        /* Set by new() and never cleared: root deletion is refused below. */
        self.db.root_group_id.expect("vault without a root group")
    }

    pub fn get_group(&self, id: &NodeId) -> Option<&Group> {
        self.db.get_group(id)
    }

    pub fn get_entry(&self, id: &NodeId) -> Option<&Entry> {
        self.db.get_entry(id)
    }

    pub fn is_modified(&self) -> bool {
        self.db.data_modified
    }

    /// Children of a group in stored order. Order is a view concern (Wave 5
    /// sorts on top of this); the vec order is insertion order.
    pub fn groups_in(&self, parent: &NodeId) -> Vec<&Group> {
        self.db
            .get_group(parent)
            .map(|g| {
                g.child_group_ids
                    .iter()
                    .filter_map(|id| self.db.get_group(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn entries_in(&self, group: &NodeId) -> Vec<&Entry> {
        self.db.get_entries_in_group(group)
    }

    /// Titles from the root down to `id`, for the "General / Banks" breadcrumb
    /// and the search haystack. Root itself yields one element.
    pub fn group_path(&self, id: &NodeId) -> Vec<String> {
        let mut path = Vec::new();
        let mut at = *id;
        loop {
            let Some(group) = self.db.get_group(&at) else {
                return Vec::new();
            };
            path.push(group.title.clone());
            let Some(parent) = self.parent_group(&at) else {
                break;
            };
            at = parent;
        }
        path.reverse();
        path
    }

    /// Parent found by scan: groups hold no back-pointer, and NodeIds are the
    /// only stable handle (positions shift under every mutation).
    pub fn parent_group(&self, id: &NodeId) -> Option<NodeId> {
        self.db
            .groups
            .iter()
            .find(|(_, g)| g.child_group_ids.contains(id))
            .map(|(pid, _)| *pid)
    }

    pub fn parent_group_of_entry(&self, id: &NodeId) -> Option<NodeId> {
        self.db.find_parent_group_of_entry(id)
    }

    pub fn create_group(&mut self, parent: &NodeId, name: &str) -> Result<NodeId, VaultError> {
        if self.db.get_group(parent).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        let mut group = Group::new(NodeId::new_uuid());
        group.title = name.to_string();
        let id = group.id;
        /* add_group links into the parent's child list and marks modified. */
        self.db.add_group(group, parent);
        Ok(id)
    }

    pub fn rename_group(&mut self, id: &NodeId, name: &str) -> Result<(), VaultError> {
        let Some(group) = self.db.get_group_mut(id) else {
            return Err(VaultError::GroupNotFound);
        };
        group.title = name.to_string();
        self.db.mark_modified();
        Ok(())
    }

    /* A group moves with its whole subtree: children live behind the group's
       id, so only the two child lists change. The cycle walk goes up from the
       destination, since a group moved under its own descendant would vanish
       from every path computation. */
    pub fn move_group(&mut self, id: &NodeId, new_parent: &NodeId) -> Result<(), VaultError> {
        if *id == self.root_id() {
            return Err(VaultError::CannotMoveRoot);
        }
        if self.db.get_group(id).is_none() || self.db.get_group(new_parent).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        let mut at = *new_parent;
        loop {
            if at == *id {
                return Err(VaultError::WouldCycle);
            }
            match self.parent_group(&at) {
                Some(p) => at = p,
                None => break,
            }
        }
        if let Some(old) = self.parent_group(id)
            && let Some(parent) = self.db.get_group_mut(&old)
        {
            parent.child_group_ids.retain(|g| g != id);
        }
        if let Some(parent) = self.db.get_group_mut(new_parent) {
            parent.child_group_ids.retain(|g| g != id);
            parent.child_group_ids.push(*id);
        }
        self.db.mark_modified();
        Ok(())
    }

    /* Refuses non-empty groups rather than deleting recursively: a recursive
       delete is one keypress from losing a subtree, and keepass-rs's own
       remove_group does recurse, which is why this doesn't call it. */
    pub fn delete_group(&mut self, id: &NodeId) -> Result<(), VaultError> {
        if *id == self.root_id() {
            return Err(VaultError::CannotDeleteRoot);
        }
        let Some(group) = self.db.get_group(id) else {
            return Err(VaultError::GroupNotFound);
        };
        if !group.child_group_ids.is_empty() || !group.child_entry_ids.is_empty() {
            return Err(VaultError::GroupNotEmpty);
        }
        if let Some(old) = self.parent_group(id)
            && let Some(parent) = self.db.get_group_mut(&old)
        {
            parent.child_group_ids.retain(|g| g != id);
        }
        self.db.groups.remove(id);
        self.db.mark_modified();
        Ok(())
    }

    pub fn create_entry(
        &mut self,
        group: &NodeId,
        title: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
    ) -> Result<NodeId, VaultError> {
        if self.db.get_group(group).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        let mut entry = Entry::new(NodeId::new_uuid());
        entry.title = title.to_string();
        entry.username = ProtectedString::new_protected(username);
        entry.password = ProtectedString::new_protected(password);
        entry.url = url.to_string();
        entry.notes = ProtectedString::new_protected(notes);
        let id = entry.id;
        self.db.add_entry(entry, group);
        Ok(id)
    }

    pub fn update_entry(
        &mut self,
        id: &NodeId,
        title: &str,
        username: &str,
        password: Option<&str>,
        url: &str,
        notes: &str,
    ) -> Result<(), VaultError> {
        /* Password is Option: the edit form sends None when the box was left
           untouched, so an edit that never looked at the secret keeps it. */
        let Some(entry) = self.db.get_entry_mut(id) else {
            return Err(VaultError::EntryNotFound);
        };
        entry.title = title.to_string();
        entry.username = ProtectedString::new_protected(username);
        if let Some(pw) = password {
            entry.password = ProtectedString::new_protected(pw);
        }
        entry.url = url.to_string();
        entry.notes = ProtectedString::new_protected(notes);
        self.db.mark_modified();
        Ok(())
    }

    /* keepass-rs's move_entry is private and remove_entry leaves a tombstone,
       so a move does its own child-list surgery: no tombstone for an id that
       still exists. */
    pub fn move_entry(&mut self, id: &NodeId, new_group: &NodeId) -> Result<(), VaultError> {
        if self.db.get_entry(id).is_none() {
            return Err(VaultError::EntryNotFound);
        }
        if self.db.get_group(new_group).is_none() {
            return Err(VaultError::GroupNotFound);
        }
        if let Some(old) = self.db.find_parent_group_of_entry(id)
            && let Some(parent) = self.db.get_group_mut(&old)
        {
            parent.child_entry_ids.retain(|e| e != id);
        }
        if let Some(parent) = self.db.get_group_mut(new_group) {
            parent.child_entry_ids.retain(|e| e != id);
            parent.child_entry_ids.push(*id);
        }
        self.db.mark_modified();
        Ok(())
    }

    /* Direct delete, no recycle bin in v1: Wave 7 decides whether deleted
       entries go somewhere recoverable. The confirm prompt is what guards it. */
    pub fn delete_entry(&mut self, id: &NodeId) -> Result<(), VaultError> {
        match self.db.remove_entry(id, false) {
            Some(_) => Ok(()),
            None => Err(VaultError::EntryNotFound),
        }
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
        assert_eq!(v.get_group(&root).unwrap().title, "Root");
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

        assert_eq!(v.get_group(&banks).unwrap().title, "Money");
        assert_eq!(v.group_path(&savings), vec!["Root", "Money", "Savings"]);
        let kids: Vec<NodeId> = v.groups_in(&root).iter().map(|g| g.id).collect();
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

        let e = v.entries_in(&g)[0].id;
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
        assert_eq!(kept.username.as_str(), "octo2");
        assert_eq!(kept.password.as_str(), "s3cret", "untouched password changed");

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
        let ghost = NodeId::new_uuid();
        let root = v.root_id();
        assert_eq!(v.rename_group(&ghost, "x"), Err(VaultError::GroupNotFound));
        assert_eq!(v.move_entry(&ghost, &root), Err(VaultError::EntryNotFound));
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
        v.save_as(&file.path, b"correct horse", None).unwrap();
        v
    }

    #[test]
    fn a_saved_vault_reopens_with_everything_it_held() {
        let file = Temp::new("roundtrip");
        let saved = saved_vault(&file);
        assert_eq!(saved.path(), Some(file.path.as_path()));

        let open = Vault::open(&file.path, b"correct horse", None).unwrap();
        let banks = open.groups_in(&open.root_id())[0].id;
        assert_eq!(open.group_path(&banks), vec!["Root", "Banks"]);
        let entry = open.entries_in(&banks)[0];
        assert_eq!(entry.title, "checking");
        assert_eq!(entry.username.as_str(), "octo");
        assert_eq!(entry.password.as_str(), "s3cret");
        assert_eq!(open.path(), Some(file.path.as_path()));
    }

    #[test]
    fn a_wrong_password_is_a_wrong_password_not_a_corrupt_file() {
        let file = Temp::new("wrongpw");
        saved_vault(&file);
        assert!(
            matches!(
                Vault::open(&file.path, b"wrong battery", None),
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
            Vault::open(&missing, b"pw", None),
            Err(VaultError::Io(_))
        ));
    }

    #[test]
    fn save_before_any_path_is_an_error_not_a_panic() {
        let v = vault();
        assert_eq!(v.save(), Err(VaultError::Unsaved));
    }

    #[test]
    fn edits_save_through_the_retained_key_and_path() {
        let file = Temp::new("resave");
        let mut v = saved_vault(&file);
        let banks = v.groups_in(&v.root_id())[0].id;
        let e = v.entries_in(&banks)[0].id;
        v.update_entry(&e, "checking", "octo2", None, "https://x", "n")
            .unwrap();
        v.save().unwrap();

        let open = Vault::open(&file.path, b"correct horse", None).unwrap();
        let entry = open.entries_in(&banks)[0];
        assert_eq!(entry.username.as_str(), "octo2");
        assert_eq!(entry.password.as_str(), "s3cret", "untouched password changed");
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
}
