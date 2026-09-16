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

/// What KeePassXC calls the group it routes deletes to.
pub const RECYCLE_BIN: &str = "Recycle Bin";

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

/* Text from a vault, on its way somewhere that is not the TUI. Ratatui drops
   control characters on the way into its cell buffer, so the browser is safe
   by construction; `println!` and the terminal-title escape are not, and a
   `.kdbx` is a file that can arrive from anyone. An entry titled
   "\x1b]0;owned\x07" would otherwise retitle the window of whoever ran
   `--list`, and OSC 52 can reach the clipboard on some terminals. */
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '·' } else { c })
        .collect()
}

/// The raw `otp` field, which is an `otpauth://` URL when there is one.
pub fn raw_otp(entry: &EntryRef<'_>) -> Option<String> {
    entry.get_raw_otp_value().map(str::to_string)
}

/* What a site gives you is either a long `otpauth://` URL (behind the QR
   code) or a run of base32 with spaces in it ("JBSW Y3DP EHPK 3PXP"). Both
   have to work: retyping the second into the first by hand is exactly the
   kind of chore a password manager exists to absorb. The URL is what KDBX
   stores, so a bare secret gets wrapped in one. */
pub fn totp_url(input: &str, title: &str, username: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("nothing to read".into());
    }
    if input.starts_with("otpauth://") {
        let url = with_digits(input);
        return url
            .parse::<keepass::db::TOTP>()
            .map(|_| url)
            .map_err(|e| format!("{e}"));
    }
    /* Groupings and hyphens are how the secret is printed, never part of it,
       and base32 is case-insensitive. */
    let secret: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    if secret.is_empty() {
        return Err("nothing to read".into());
    }
    /* Checked against the base32 alphabet before it is put in a url, or a
       "secret" carrying `&algorithm=SHA512` would smuggle its own parameters
       in beside ours — base32 decoding never sees them, so nothing else would
       catch it. */
    if !secret
        .chars()
        .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c) || c == '=')
    {
        return Err("not a base32 secret or an otpauth:// url".into());
    }
    let label = if username.is_empty() {
        title.to_string()
    } else {
        format!("{title}:{username}")
    };
    /* Digits and period spelled out rather than left to a default: see
       `with_digits` for why the default is the one thing here that cannot be
       left unsaid. */
    let url = format!(
        "otpauth://totp/{}?secret={secret}&digits=6&period=30",
        urlish(&label)
    );
    /* Parsed before it is stored: a seed that cannot produce a code must be
       refused while the form is still open and the text still on screen. */
    url.parse::<keepass::db::TOTP>()
        .map(|_| url)
        .map_err(|_| "not a base32 secret or an otpauth:// url".to_string())
}

/* RFC 6238 and every authenticator app treat six digits as the default when
   an `otpauth://` url does not say — the keepass crate treats it as eight, so
   a url written by a site that left `digits` out would produce codes that are
   the right secret and the wrong length. Spelled out on the way in and on the
   way to the screen, and never by rewriting what is stored. */
fn with_digits(url: &str) -> String {
    if url.contains("digits=") || !url.contains('?') {
        return url.to_string();
    }
    format!("{url}&digits=6")
}

/// Percent-encodes what a label may hold. Small by hand: the only characters
/// a title realistically brings are spaces, slashes and the odd accent.
fn urlish(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The one-time code an entry carries, if it carries one. KeePassXC writes
/// `otp` as a field; without this an entry that has one looks like an entry
/// that does not, and the user goes back to their phone.
pub fn totp_now(entry: &EntryRef<'_>) -> Option<(String, u64)> {
    let raw = entry.get_raw_otp_value()?;
    let totp: keepass::db::TOTP = with_digits(raw).parse().ok()?;
    let code = totp.value_now().ok()?;
    Some((code.code, code.valid_for.as_secs()))
}

/// The five Sennel has a row for, plus the seed. Everything else on an entry
/// is a custom field, which is a thing KeePassXC users really do use.
pub const STANDARD: [&str; 6] = [TITLE, USERNAME, PASSWORD, URL, NOTES, "otp"];

/// One line of the `F` screen: a custom string field, or a file.
#[derive(Clone, PartialEq, Debug)]
pub enum Extra {
    Field {
        name: String,
        value: String,
        /// Protected fields mask until `*`, the same rule as the password.
        secret: bool,
    },
    File {
        name: String,
        bytes: usize,
    },
}

impl Extra {
    pub fn name(&self) -> &str {
        match self {
            Extra::Field { name, .. } | Extra::File { name, .. } => name,
        }
    }
}

/* Everything on an entry that the five fixed rows cannot show. Fields first,
   then files, each alphabetical: this list is read, and a list that reorders
   itself between openings cannot be. */
pub fn extra_rows(entry: &EntryRef<'_>) -> Vec<Extra> {
    let mut fields: Vec<Extra> = entry
        .fields
        .iter()
        .filter(|(name, _)| !STANDARD.contains(&name.as_str()))
        .map(|(name, value)| Extra::Field {
            name: name.clone(),
            value: value.get().clone(),
            secret: value.is_protected(),
        })
        .collect();
    fields.sort_by_key(|row| row.name().to_lowercase());
    let mut files: Vec<Extra> = entry
        .attachments_named()
        .map(|(name, attachment)| Extra::File {
            name: name.to_string(),
            bytes: attachment.data.get().len(),
        })
        .collect();
    files.sort_by_key(|row| row.name().to_lowercase());
    fields.extend(files);
    fields
}

/// Fields Sennel has no row for — KeePassXC custom strings, and attachments.
/// Named rather than shown: an entry whose extra fields are invisible reads
/// as an entry that lost them.
/* An attachment on its way out of the vault, written the way the vault
   itself is: created exclusively so a symlink planted at the path cannot
   redirect it, and 0600 from the first byte. The file loses every protection
   the vault gave it the moment it lands, so the least this can do is not
   hand it to the rest of the machine. */
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| VaultError::Io(format!("{e}")))?;
    file.write_all(bytes).map_err(|e| VaultError::Io(e.to_string()))?;
    Ok(())
}

pub fn extras(entry: &EntryRef<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let fields: Vec<&String> = entry
        .fields
        .keys()
        .filter(|k| !STANDARD.contains(&k.as_str()))
        .collect();
    if !fields.is_empty() {
        let plural = if fields.len() == 1 { "field" } else { "fields" };
        out.push(format!("{} more {plural}", fields.len()));
    }
    let files = entry.attachments().count();
    if files > 0 {
        let plural = if files == 1 { "attachment" } else { "attachments" };
        out.push(format!("{files} {plural}"));
    }
    if !entry.tags.is_empty() {
        out.push(format!("tags: {}", entry.tags.join(", ")));
    }
    out
}

/// What a guarded vault op refused, and why. A plain enum rather than anyhow:
/// the UI matches on variants to name the next step ("empty the group first").
/* Payloads are Strings, not sources: io and database errors stay
   assert_eq-friendly, and the UI only ever displays them. */
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VaultError {
    GroupNotFound,
    EntryNotFound,
    /// `D` on something already in the bin, where the next `D` is the real one.
    AlreadyRecycled,
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
            VaultError::AlreadyRecycled => write!(f, "already in the recycle bin"),
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

    /* Re-key: the same database, written again under a new password. The
       file is written before the key is swapped, so a refused or failed write
       leaves the vault openable with the password it already had — a rekey
       that half-lands is a vault nobody can open.

       Guarded like `save`, because it is a save: re-keying over somebody
       else's write would lose their work *and* change the password they would
       need to get it back. */
    pub fn rekey(&mut self, password: &str, key_file: Option<&[u8]>) -> Result<(), VaultError> {
        let Some(path) = self.path.clone() else {
            return Err(VaultError::Unsaved);
        };
        if self.changed_on_disk() {
            return Err(VaultError::ChangedOnDisk);
        }
        let key = Self::build_key(password, key_file)?;
        // KeePassXC shows this, and a vault that never records it reads as one
        // whose password has never been changed.
        let was = self.db.meta.master_key_changed;
        self.db.meta.master_key_changed = Some(Times::now());
        if let Err(e) = Self::write_file(&self.db, &key, &path) {
            self.db.meta.master_key_changed = was;
            return Err(e);
        }
        self.key = Some(key);
        self.stamp = Stamp::of(&path);
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
           still sensitive copy of the vault.

           create_new, not create: in a directory somebody else can write to,
           a symlink planted at this path would be followed and the vault
           written wherever it points — 0600 on a file that is not ours. A
           leftover from a killed process is removed first, since the name
           carries our own pid. */
        let _ = std::fs::remove_file(&temp);
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
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
    pub fn recycled(&self) -> HashSet<EntryId> {
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
    /* Test-only since the row cache took over the counting: kept because the
       KeePassXC fixture reads entries without knowing their ids. */
    #[cfg(test)]
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

    /* The recursive delete `delete_group` refuses to be. Only reachable on a
       group already inside the bin, where the subtree has been deleted once
       already and the confirm says it cannot be undone. */
    pub fn delete_group_tree(&mut self, id: &GroupId) -> Result<(), VaultError> {
        if *id == self.root_id() {
            return Err(VaultError::CannotDeleteRoot);
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

    /* The bin every other KeePass client routes deletes through, found by
       the uuid in the file's own metadata or created on the first delete.
       KeePassXC writes exactly this: a root-level group, its uuid in
       `recyclebin_uuid`, and the enabled flag set. */
    pub fn ensure_recycle_bin(&mut self) -> Result<GroupId, VaultError> {
        if let Some(bin) = self.recycle_bin_id() {
            return Ok(bin);
        }
        let root = self.root_id();
        let bin = self.create_group(&root, RECYCLE_BIN)?;
        self.db.meta.recyclebin_uuid = Some(bin.uuid());
        self.db.meta.recyclebin_enabled = Some(true);
        self.db.meta.recyclebin_changed = Some(Times::now());
        Ok(bin)
    }

    /// The bin, if the file names one that still exists. A uuid pointing at a
    /// group somebody deleted is stale metadata, not a bin.
    pub fn recycle_bin_id(&self) -> Option<GroupId> {
        self.db.recycle_bin().map(|g| g.id())
    }

    /// Whether this group is the bin or lives inside it. What the pane asks
    /// before it offers `u`, and what `get` asks before it resolves a needle.
    pub fn in_recycle_bin(&self, id: &GroupId) -> bool {
        let Some(bin) = self.recycle_bin_id() else {
            return false;
        };
        let mut at = *id;
        loop {
            if at == bin {
                return true;
            }
            let Some(group) = self.db.group(at) else {
                return false;
            };
            match group.parent() {
                Some(parent) => at = parent.id(),
                None => return false,
            }
        }
    }

    /// Whether an entry is in the bin, which is to say already deleted.
    pub fn is_recycled(&self, id: &EntryId) -> bool {
        self.parent_group_of_entry(id)
            .is_some_and(|parent| self.in_recycle_bin(&parent))
    }

    /* `D` on a live entry. A move, not a removal: the entry keeps its id and
       its history, KeePassXC shows it under Recycle Bin, and undo is a move
       home rather than a resurrection from a snapshot. An entry already in
       the bin is deleted for real by `expunge_entry`. */
    pub fn recycle_entry(&mut self, id: &EntryId) -> Result<(), VaultError> {
        if self.db.entry(*id).is_none() {
            return Err(VaultError::EntryNotFound);
        }
        let bin = self.ensure_recycle_bin()?;
        self.move_entry(id, &bin)
    }

    /* `D` on a group. The whole subtree rides along, which is why this no
       longer refuses a non-empty group the way a recursive *removal* had to:
       nothing is destroyed, and one keypress undoes it. */
    pub fn recycle_group(&mut self, id: &GroupId) -> Result<(), VaultError> {
        if *id == self.root_id() {
            return Err(VaultError::CannotDeleteRoot);
        }
        if self.in_recycle_bin(id) {
            return Err(VaultError::AlreadyRecycled);
        }
        let bin = self.ensure_recycle_bin()?;
        if *id == bin {
            return Err(VaultError::CannotDeleteRoot);
        }
        self.move_group(id, &bin)
    }

    /* Undo support (Wave 7): the app snapshots whole entries and calls back
       here to restore them. */
    /* The `otp` field, set or cleared. Protected, like the password: it is a
       seed that mints codes forever, so it must not sit in the file in the
       clear. */
    pub fn set_otp(&mut self, id: &EntryId, url: Option<&str>) -> Result<(), VaultError> {
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        match url {
            Some(url) => entry.set_protected("otp", url),
            None => {
                entry.fields.remove("otp");
            }
        }
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

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

    /* The bytes of one attachment, for writing it out. Cloned rather than
       borrowed: the caller writes it to a file and drops it, and threading a
       borrow of the database through that is not worth the lifetime. */
    pub fn attachment_bytes(&self, id: &EntryId, name: &str) -> Option<Vec<u8>> {
        self.db
            .entry(*id)?
            .attachment_by_name(name)
            .map(|a| a.data.get().clone())
    }

    /* A custom field, set or replaced. Protected by default for the same
       reason notes are: a field somebody added by hand to a password manager
       is more likely to be a secret than not, and protecting it only ever
       hides more. */
    pub fn set_field(
        &mut self,
        id: &EntryId,
        name: &str,
        value: &str,
        secret: bool,
    ) -> Result<(), VaultError> {
        if name.trim().is_empty() {
            return Err(VaultError::Db("a field needs a name".into()));
        }
        /* The five fixed rows have their own editor; letting this one write
           them would mean two paths to the same field disagreeing. */
        if STANDARD.contains(&name) {
            return Err(VaultError::Db(format!("{name} has its own row in the form")));
        }
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        match secret {
            true => entry.set_protected(name, value),
            false => entry.set_unprotected(name, value),
        }
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    pub fn remove_field(&mut self, id: &EntryId, name: &str) -> Result<(), VaultError> {
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        if entry.fields.remove(name).is_none() {
            return Err(VaultError::EntryNotFound);
        }
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    /* A file into the vault, protected. KDBX stores attachments in a shared
       pool keyed off the entry, which the crate handles; what matters here is
       that it goes in protected, because an attachment is usually the most
       sensitive thing on the entry. */
    pub fn add_attachment(
        &mut self,
        id: &EntryId,
        name: &str,
        data: Vec<u8>,
    ) -> Result<(), VaultError> {
        if name.trim().is_empty() {
            return Err(VaultError::Db("an attachment needs a name".into()));
        }
        // Checked through the read side, before taking the mutable borrow.
        if self
            .db
            .entry(*id)
            .is_some_and(|e| e.attachment_by_name(name).is_some())
        {
            return Err(VaultError::Db(format!("{name} is already attached")));
        }
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        entry.add_attachment(name, keepass::db::Value::protected(data));
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    pub fn remove_attachment(&mut self, id: &EntryId, name: &str) -> Result<(), VaultError> {
        if self
            .db
            .entry(*id)
            .is_none_or(|e| e.attachment_by_name(name).is_none())
        {
            return Err(VaultError::EntryNotFound);
        }
        let Some(mut entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        /* Through the entry, not through the attachment. `AttachmentMut::
           remove` clears the back-references it knows about, and a file
           loaded from disk arrives with those back-references empty — so it
           dropped the bytes and left the entry pointing at them, which is a
           panic the next time anything reads the list. */
        entry.remove_attachment_by_name(name);
        entry.times.last_modification = Some(Times::now());
        Ok(())
    }

    /* Gone for good: an add that `u` takes back, and `D` on something
       already in the bin. The one path in Sennel that destroys an entry, and
       both callers have either just created it or already deleted it once. */
    pub fn expunge_entry(&mut self, id: &EntryId) -> Result<(), VaultError> {
        let Some(entry) = self.db.entry_mut(*id) else {
            return Err(VaultError::EntryNotFound);
        };
        entry.remove();
        Ok(())
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

/// What is wrong with an entry's password, worst first when one entry has
/// more than one problem.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Issue {
    /// No password at all.
    Empty,
    /// The same password as this many other entries.
    Reused(usize),
    /// Fewer bits than a password worth having, by the form's own estimate.
    Weak(f64),
}

impl Issue {
    /// Worst first, so a list sorted by this reads as a to-do list.
    pub fn rank(self) -> u8 {
        match self {
            Issue::Empty => 0,
            Issue::Reused(_) => 1,
            Issue::Weak(_) => 2,
        }
    }

    pub fn say(self) -> String {
        match self {
            Issue::Empty => "no password".to_string(),
            Issue::Reused(n) => format!("reused across {} entries", n + 1),
            Issue::Weak(bits) => format!("~{bits:.0} bits · {}", crate::generator::strength(bits)),
        }
    }
}

/// Below this, the entry form already draws the estimate in `warn`. The audit
/// uses the same line rather than inventing a second opinion.
const WEAK_BITS: f64 = 60.0;

/* Everything wrong with the vault's passwords, in one pass. Reuse first
   because it is the finding that matters most and the one a person cannot
   possibly spot themselves: a weak password costs one account, a reused one
   costs every account that shares it.

   Passwords are grouped by hash, not by keeping a map of the plaintext:
   equality is all this needs, and a table of every password in the vault is
   not a thing to build when a count will do. SipHash is not a security claim
   here — a collision would mean one wrong "reused" line, not an exposure. */
pub fn audit(vault: &Vault) -> Vec<(EntryId, Issue)> {
    use std::collections::HashMap;
    use std::hash::{Hash, Hasher};

    let entries = vault.entry_refs();
    let mut counts: HashMap<u64, usize> = HashMap::new();
    let digest = |password: &str| {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        password.hash(&mut hasher);
        hasher.finish()
    };
    for entry in &entries {
        let password = entry.password();
        if !password.is_empty() {
            *counts.entry(digest(password)).or_default() += 1;
        }
    }
    let mut out: Vec<(EntryId, Issue)> = Vec::new();
    for entry in &entries {
        let password = entry.password();
        let issue = if password.is_empty() {
            Issue::Empty
        } else if let Some(others) = counts.get(&digest(password)).filter(|n| **n > 1) {
            Issue::Reused(others - 1)
        } else {
            let bits = crate::generator::typed_bits(password);
            if bits >= WEAK_BITS {
                continue;
            }
            Issue::Weak(bits)
        };
        out.push((entry.id(), issue));
    }
    /* Worst first, then by title, so the list is stable between openings —
       a to-do list that reshuffles itself is one nobody works through. */
    out.sort_by(|a, b| {
        a.1.rank().cmp(&b.1.rank()).then_with(|| {
            let name = |id: &EntryId| {
                vault.get_entry(id).map(|e| e.title().to_lowercase()).unwrap_or_default()
            };
            name(&a.0).cmp(&name(&b.0))
        })
    });
    out
}

/// What a needle found, for a caller with no screen to show a list on.
#[derive(Debug, PartialEq, Eq)]
pub enum Found {
    One(EntryId),
    /// More than one, best first, for a message that names the candidates.
    Many(Vec<EntryId>),
    None,
}

/* Resolving a needle with nobody to ask. The TUI can show a list and let the
   cursor decide; `sennel get` has one shot, so the rules have to be ones a
   user can predict:

   an exact title match, case-insensitive, wins outright even when a dozen
   entries fuzzy-match it — "mail" should find the entry called "mail" and not
   the one called "mailchimp-api-key". Failing that, a single fuzzy match
   wins. Anything else is ambiguous and gets listed rather than guessed at.

   Binned entries are not candidates. Copying the password of something
   deleted last week is the one outcome worth engineering against. */
pub fn resolve(vault: &Vault, searcher: &mut crate::search::Searcher, needle: &str) -> Found {
    let live: Vec<EntryId> = vault
        .entry_refs()
        .iter()
        .map(|e| e.id())
        .collect();
    let exact: Vec<EntryId> = live
        .iter()
        .copied()
        .filter(|id| {
            vault
                .get_entry(id)
                .is_some_and(|e| e.title().eq_ignore_ascii_case(needle))
        })
        .collect();
    if exact.len() == 1 {
        return Found::One(exact[0]);
    }
    let mut hits: Vec<(u16, EntryId)> = live
        .into_iter()
        .filter_map(|id| searcher.rank_entry(needle, vault, &id).map(|score| (score, id)))
        .collect();
    // Best first, so an ambiguous answer lists the likeliest candidate first.
    hits.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    match hits.len() {
        0 => Found::None,
        1 => Found::One(hits[0].1),
        /* Two entries with the same title are ambiguous even when one scores
           higher: the score is not something the user can see or reason
           about, so it must not be what picks their password. */
        _ => Found::Many(hits.into_iter().map(|(_, id)| id).collect()),
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

    /* A group goes to the bin whole. It used to be refused while it held
       anything, on the grounds that a recursive delete is one keypress from
       losing a subtree — which stops being true once the keypress is a move
       that `u` takes back. */
    #[test]
    fn deleting_a_group_moves_it_and_its_contents_to_the_bin() {
        let mut v = vault();
        let root = v.root_id();
        let g = v.create_group(&root, "Mail").unwrap();
        let e = v.create_entry(&g, "inbox", "u", "p", "", "").unwrap();

        v.recycle_group(&g).unwrap();
        let bin = v.recycle_bin_id().expect("no bin was made");
        assert_eq!(v.get_group(&g).unwrap().parent().unwrap().id(), bin);
        assert!(v.in_recycle_bin(&g), "the group is not in the bin");
        // The entry rode along, and counts stop seeing it.
        assert!(v.is_recycled(&e), "the entry did not follow its group");
        assert_eq!(v.entry_count(), 0);

        // Inside the bin, the same key destroys the subtree for good.
        v.delete_group_tree(&g).unwrap();
        assert!(v.get_group(&g).is_none());
        assert!(v.get_entry(&e).is_none(), "the subtree survived");
    }

    /* The bin is the one KeePassXC looks for: a root-level group whose uuid
       is in the file's own metadata, created on the first delete. */
    #[test]
    fn the_first_delete_makes_the_bin_the_format_describes() {
        let mut v = vault();
        let root = v.root_id();
        assert_eq!(v.recycle_bin_id(), None, "a fresh vault has a bin already");
        let e = v.create_entry(&root, "mail", "u", "p", "", "").unwrap();

        v.recycle_entry(&e).unwrap();
        let bin = v.recycle_bin_id().expect("no bin was made");
        assert_eq!(v.get_group(&bin).unwrap().name, RECYCLE_BIN);
        assert_eq!(v.get_group(&bin).unwrap().parent().unwrap().id(), root);
        assert!(v.is_recycled(&e));
        // Live counts and the global search scope skip it.
        assert_eq!(v.entry_count(), 0);
        assert!(v.entry_refs().is_empty());

        // A second delete reuses the bin rather than making another.
        let f = v.create_entry(&root, "chat", "u", "p", "", "").unwrap();
        v.recycle_entry(&f).unwrap();
        assert_eq!(v.recycle_bin_id(), Some(bin));
        assert_eq!(v.groups_in(&root).len(), 1);

        // And undo is a move home, not a resurrection: the id survives.
        v.move_entry(&e, &root).unwrap();
        assert!(!v.is_recycled(&e));
        assert_eq!(v.entry_count(), 1);
    }

    /* The bin survives a round trip, so KeePassXC opens the file and shows
       the deleted entry under Recycle Bin rather than losing it. */
    #[test]
    fn the_bin_round_trips_through_the_file() {
        let dir = std::env::temp_dir().join(format!("sennel-bin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bin.kdbx");
        let mut v = vault();
        let root = v.root_id();
        let e = v.create_entry(&root, "mail", "u", "p", "", "").unwrap();
        v.recycle_entry(&e).unwrap();
        v.save_as(&path, "pw", None).unwrap();

        let back = Vault::open(&path, "pw", None).unwrap();
        let bin = back.recycle_bin_id().expect("the bin did not survive the save");
        assert_eq!(back.get_group(&bin).unwrap().name, RECYCLE_BIN);
        assert!(back.is_recycled(&e), "the entry is not in the reopened bin");
        assert_eq!(back.entry_count(), 0);
        std::fs::remove_file(&path).ok();
    }

    /* Custom fields and attachments used to be a count and nothing else.
       These are the reads the `F` screen is built on. */
    #[test]
    fn the_extras_list_holds_fields_and_files_with_their_values() {
        let mut v = vault();
        let root = v.root_id();
        let id = v.create_entry(&root, "vpn", "u", "p", "", "notes").unwrap();
        v.set_field(&id, "recovery", "8888-4444", true).unwrap();
        v.set_field(&id, "account", "AC-9", false).unwrap();
        v.add_attachment(&id, "key.pem", b"-----BEGIN-----".to_vec()).unwrap();

        let rows = crate::vault::extra_rows(&v.get_entry(&id).unwrap());
        assert_eq!(rows.len(), 3, "{rows:?}");
        /* Fields first, then files, each alphabetical: a list that is read
           cannot reorder itself between openings. */
        assert_eq!(rows[0].name(), "account");
        assert_eq!(rows[1].name(), "recovery");
        assert_eq!(rows[2].name(), "key.pem");
        assert_eq!(
            rows[1],
            crate::vault::Extra::Field {
                name: "recovery".into(),
                value: "8888-4444".into(),
                secret: true,
            }
        );
        // A field added by hand goes in protected; one asked for plainly does not.
        assert!(matches!(&rows[0], crate::vault::Extra::Field { secret: false, .. }));
        assert_eq!(rows[2], crate::vault::Extra::File { name: "key.pem".into(), bytes: 15 });

        // The five fixed rows keep their own editor and never appear here.
        for standard in crate::vault::STANDARD {
            assert!(rows.iter().all(|r| r.name() != standard), "{standard} leaked in");
            assert!(v.set_field(&id, standard, "x", false).is_err(), "{standard} was writable");
        }
    }

    /* The bytes have to survive the file, or "attachment" is a label on
       something nobody can get back. */
    #[test]
    fn attachments_round_trip_through_the_file() {
        let dir = std::env::temp_dir().join(format!("sennel-att-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("att.kdbx");
        let mut v = vault();
        let root = v.root_id();
        let id = v.create_entry(&root, "vpn", "u", "p", "", "").unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        v.add_attachment(&id, "blob.bin", data.clone()).unwrap();
        v.set_field(&id, "recovery", "8888", true).unwrap();
        v.save_as(&path, "pw", None).unwrap();

        let back = Vault::open(&path, "pw", None).unwrap();
        assert_eq!(back.attachment_bytes(&id, "blob.bin"), Some(data));
        let rows = crate::vault::extra_rows(&back.get_entry(&id).unwrap());
        assert!(rows.iter().any(|r| r.name() == "recovery"));
        // Twice under one name would be two files nobody can tell apart.
        let mut back = back;
        assert!(back.add_attachment(&id, "blob.bin", vec![1]).is_err());
        back.remove_attachment(&id, "blob.bin").unwrap();
        assert_eq!(back.attachment_bytes(&id, "blob.bin"), None);
        back.remove_field(&id, "recovery").unwrap();
        assert!(crate::vault::extra_rows(&back.get_entry(&id).unwrap()).is_empty());
        std::fs::remove_file(&path).ok();
    }

    /* A file leaving the vault loses every protection the vault gave it, so
       the least the write can do is not hand it to the rest of the machine. */
    #[test]
    fn an_extracted_attachment_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sennel-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let at = dir.join("out.bin");
        std::fs::remove_file(&at).ok();
        crate::vault::write_owner_only(&at, b"secret").unwrap();
        let mode = std::fs::metadata(&at).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        // Exclusive: a symlink planted at the path cannot redirect the write.
        assert!(crate::vault::write_owner_only(&at, b"again").is_err());
        std::fs::remove_file(&at).ok();
    }

    /* Reuse is the finding a person cannot possibly spot themselves, and the
       one that costs more than one account when it bites. */
    #[test]
    fn the_audit_finds_reused_weak_and_empty_passwords() {
        let mut v = vault();
        let root = v.root_id();
        let shared = "correct-horse";
        let a = v.create_entry(&root, "aaa", "u", shared, "", "").unwrap();
        let b = v.create_entry(&root, "bbb", "u", shared, "", "").unwrap();
        let weak = v.create_entry(&root, "ccc", "u", "hunter2", "", "").unwrap();
        let empty = v.create_entry(&root, "ddd", "u", "", "", "").unwrap();
        // Long, mixed and unique: nothing to say about it.
        let fine = v
            .create_entry(&root, "eee", "u", "Xq7!vm2Zt4&pLr9Wd6*Ks1", "", "")
            .unwrap();

        let found = audit(&v);
        let issue = |id: &EntryId| found.iter().find(|(e, _)| e == id).map(|(_, i)| *i);
        // Both sides of a shared password are named, each counting the other.
        assert_eq!(issue(&a), Some(Issue::Reused(1)));
        assert_eq!(issue(&b), Some(Issue::Reused(1)));
        assert!(matches!(issue(&weak), Some(Issue::Weak(_))));
        assert_eq!(issue(&empty), Some(Issue::Empty));
        assert_eq!(issue(&fine), None, "a good password was flagged");

        /* Worst first, and stable: a to-do list that reshuffles itself
           between openings is one nobody works through. */
        let order: Vec<u8> = found.iter().map(|(_, i)| i.rank()).collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order, sorted, "the list is not worst-first");
        assert_eq!(audit(&v), found, "two runs disagreed");

        // An empty password is not "reused" with every other empty one.
        v.create_entry(&root, "fff", "u", "", "", "").unwrap();
        assert_eq!(
            audit(&v).iter().filter(|(_, i)| matches!(i, Issue::Reused(_))).count(),
            2,
            "empty passwords were counted as reuse"
        );
    }

    /* A deleted entry is not a password worth changing, and telling somebody
       to go fix one is how an audit loses their trust. */
    #[test]
    fn the_audit_leaves_the_recycle_bin_out() {
        let mut v = vault();
        let root = v.root_id();
        let live = v.create_entry(&root, "live", "u", "hunter2", "", "").unwrap();
        let dead = v.create_entry(&root, "dead", "u", "hunter2", "", "").unwrap();
        // Two entries share it, so both are reuse while both are live.
        assert_eq!(audit(&v).len(), 2);

        v.recycle_entry(&dead).unwrap();
        let found = audit(&v);
        assert_eq!(found.len(), 1, "the bin is still being audited");
        assert_eq!(found[0].0, live);
        /* And the survivor stops being "reused": the only other copy was the
           one that was thrown away. */
        assert!(matches!(found[0].1, Issue::Weak(_)), "{:?}", found[0].1);
    }

    /* `get` has one shot and nobody to ask, so the rules have to be ones a
       user can predict before they type. */
    #[test]
    fn a_needle_resolves_to_one_entry_or_says_why_not() {
        let mut v = vault();
        let root = v.root_id();
        let mail = v.create_entry(&root, "mail", "u", "p", "", "").unwrap();
        let chimp = v.create_entry(&root, "mailchimp-api-key", "u", "p", "", "").unwrap();
        let mut s = crate::search::Searcher::new();

        /* An exact title wins outright, even though "mail" fuzzy-matches the
           longer one too — otherwise the entry actually called "mail" would
           be unreachable by its own name. */
        assert_eq!(resolve(&v, &mut s, "mail"), Found::One(mail));
        assert_eq!(resolve(&v, &mut s, "MAIL"), Found::One(mail), "case mattered");
        // A single fuzzy hit is unambiguous even without an exact title.
        assert_eq!(resolve(&v, &mut s, "chimp"), Found::One(chimp));
        assert_eq!(resolve(&v, &mut s, "nothinglikethis"), Found::None);

        // Two hits and no exact title: listed, never guessed at.
        let Found::Many(ids) = resolve(&v, &mut s, "mai") else {
            panic!("an ambiguous needle picked one");
        };
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&mail) && ids.contains(&chimp));

        /* Two entries with the same title stay ambiguous: the score that
           separates them is not something the user can see. */
        let twin = v.create_entry(&root, "mail", "other", "p", "", "").unwrap();
        let Found::Many(ids) = resolve(&v, &mut s, "mail") else {
            panic!("two entries named mail resolved to one");
        };
        assert!(ids.contains(&mail) && ids.contains(&twin));
    }

    /* Copying the password of something deleted last week is the outcome
       worth engineering against, so the bin is not a candidate. */
    #[test]
    fn a_needle_never_resolves_into_the_recycle_bin() {
        let mut v = vault();
        let root = v.root_id();
        let live = v.create_entry(&root, "mail", "u", "live-pw", "", "").unwrap();
        let dead = v.create_entry(&root, "mail-old", "u", "dead-pw", "", "").unwrap();
        v.recycle_entry(&dead).unwrap();
        let mut s = crate::search::Searcher::new();

        assert_eq!(resolve(&v, &mut s, "mail"), Found::One(live));
        // Even asked for by its exact name, a binned entry is not there.
        assert_eq!(resolve(&v, &mut s, "mail-old"), Found::None);

        // And once it is out of the bin it answers again.
        v.move_entry(&dead, &root).unwrap();
        assert_eq!(resolve(&v, &mut s, "mail-old"), Found::One(dead));
    }

    #[test]
    fn the_root_can_neither_move_nor_go() {
        let mut v = vault();
        let root = v.root_id();
        let other = v.create_group(&root, "Other").unwrap();
        assert_eq!(v.delete_group_tree(&root), Err(VaultError::CannotDeleteRoot));
        assert_eq!(v.recycle_group(&root), Err(VaultError::CannotDeleteRoot));
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

        v.expunge_entry(&e).unwrap();
        assert!(v.get_entry(&e).is_none());
        assert_eq!(v.expunge_entry(&e), Err(VaultError::EntryNotFound));
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
    /* What a site hands over is either the long url behind its QR code or a
       run of base32 with spaces in it. Both have to reach the same stored
       url, and anything that cannot mint a code has to be refused before it
       is written. */
    #[test]
    fn a_seed_is_taken_as_a_url_or_as_the_printed_secret() {
        /* A url that leaves `digits` out gets it spelled in: the crate would
           otherwise mint eight digits where the site expects six. */
        let url = totp_url("otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP", "x", "y").unwrap();
        assert_eq!(url, "otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP&digits=6");

        // Printed with groupings, lowercase, hyphenated: all the same secret.
        let from_print = totp_url("jbsw y3dp-ehpk 3pxp", "Bank", "me").unwrap();
        assert!(from_print.starts_with("otpauth://totp/Bank:me?secret="), "{from_print}");
        assert!(from_print.contains("secret=JBSWY3DPEHPK3PXP"), "{from_print}");
        assert!(from_print.contains("digits=6"), "{from_print}");

        // And both produce the same six digits.
        let a: keepass::db::TOTP = url.parse().unwrap();
        let b: keepass::db::TOTP = from_print.parse().unwrap();
        assert_eq!(a.value_now().unwrap().code, b.value_now().unwrap().code);
        assert_eq!(a.value_now().unwrap().code.len(), 6, "not six digits");

        // Nonsense is refused rather than stored as a code that never works.
        assert!(totp_url("not base32 at all!!", "x", "").is_err());
        assert!(totp_url("otpauth://totp/x?issuer=nobody", "x", "").is_err());
        assert!(totp_url("   ", "x", "").is_err());
    }

    /* An entry written by something that left `digits` out still reads as six
       digits here, without rewriting what is in the file. */
    #[test]
    fn a_url_without_digits_still_reads_as_six() {
        let mut v = vault();
        let root = v.root_id();
        let id = v.create_entry(&root, "Bank", "me", "pw", "", "").unwrap();
        v.set_otp(&id, Some("otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP"))
            .unwrap();
        let entry = v.get_entry(&id).unwrap();
        let (code, _) = totp_now(&entry).expect("no code");
        assert_eq!(code.len(), 6, "{code}");
        // And the file still holds exactly what was put in it.
        assert_eq!(
            raw_otp(&entry).as_deref(),
            Some("otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP")
        );
    }

    /* A "secret" that carries its own url parameters must not reach the
       stored url: base32 decoding never sees them, so the alphabet check is
       the only thing between a phishing setup key and a code that quietly
       uses somebody else's algorithm. */
    #[test]
    fn a_seed_cannot_smuggle_url_parameters() {
        assert!(totp_url("JBSWY3DPEHPK3PXP&algorithm=SHA512", "x", "").is_err());
        assert!(totp_url("JBSWY3DPEHPK3PXP?digits=8", "x", "").is_err());
        assert!(totp_url("JBSWY3DPEHPK3PXP#frag", "x", "").is_err());
        // The real thing still passes, in every shape a site prints it.
        assert!(totp_url("jbsw y3dp-ehpk 3pxp", "x", "").is_ok());
    }

    /* Vault text on its way to a terminal keeps its characters and loses its
       control codes: the TUI is safe by construction, `--list` is not. */
    #[test]
    fn printable_strips_escapes_but_keeps_the_text() {
        assert_eq!(printable("ev\u{1b}]0;pwned\u{7}il"), "ev·]0;pwned·il");
        assert_eq!(printable("Commonwealth Bank — 银行"), "Commonwealth Bank — 银行");
        assert_eq!(printable("a\nb\tc"), "a·b·c");
    }

    /* Set, read back, and cleared — stored protected, because the seed mints
       codes forever while a code is worth thirty seconds. */
    #[test]
    fn an_entry_takes_and_drops_its_one_time_secret() {
        let mut v = vault();
        let root = v.root_id();
        let id = v.create_entry(&root, "Bank", "me", "pw", "", "").unwrap();
        assert!(raw_otp(&v.get_entry(&id).unwrap()).is_none());

        let url = totp_url("JBSWY3DPEHPK3PXP", "Bank", "me").unwrap();
        v.set_otp(&id, Some(&url)).unwrap();
        let entry = v.get_entry(&id).unwrap();
        assert_eq!(raw_otp(&entry).as_deref(), Some(url.as_str()));
        let (code, left) = totp_now(&entry).expect("no code from a good seed");
        assert_eq!(code.len(), 6);
        assert!(left <= 30 && left > 0, "{left}");
        assert!(
            entry.fields.get("otp").is_some_and(keepass::db::Value::is_protected),
            "the seed was stored in the clear"
        );

        v.set_otp(&id, None).unwrap();
        assert!(raw_otp(&v.get_entry(&id).unwrap()).is_none());
    }

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
