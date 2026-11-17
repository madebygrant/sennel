// Paired browsers, stored the way KeePassXC 2.7 stores them (seen in a vault it paired): one item of
// the vault's custom data per browser, `KPXC_BROWSER_<name>` holding the base64 public half of the
// browser's identification key, and `_CREATED_<name>` holding when, as text.

use keepass::db::CustomDataValue;
use sennel_core::session::{Seal, Session};
use sha2::{Digest, Sha256};

use crate::crypto;
use sennel_core::vault::{Vault, VaultError};

const PREFIX: &str = "KPXC_BROWSER_";
const CREATED: &str = "_CREATED_";

pub struct Pairing {
    pub name: String,
    pub key: String,
}

pub fn pairings(vault: &Vault) -> Vec<Pairing> {
    let mut found: Vec<Pairing> = vault
        .meta_data()
        .filter_map(|(key, value)| {
            Some(Pairing {
                name: key.strip_prefix(PREFIX)?.to_string(),
                key: as_text(value),
            })
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

pub fn is_paired(vault: &Vault, name: &str, key: &str) -> bool {
    !name.is_empty()
        && vault
            .meta_data()
            .any(|(k, v)| k.strip_prefix(PREFIX) == Some(name) && as_text(v) == key)
}

pub fn name_taken(vault: &Vault, name: &str) -> bool {
    let wanted = format!("{PREFIX}{name}");
    vault.meta_data().any(|(k, _)| k == wanted)
}

pub fn pair<S: Seal>(session: &mut Session<S>, name: &str, key: &str) -> Result<(), VaultError> {
    // KeePassXC writes the local time in this form; it is only ever shown.
    let created = chrono::Local::now()
        .format("%d/%m/%Y %-I:%M %P")
        .to_string();
    session.set_vault_data(&format!("{PREFIX}{name}"), Some(key))?;
    session.set_vault_data(&format!("{CREATED}{name}"), Some(&created))
}

pub fn revoke<S: Seal>(session: &mut Session<S>, name: &str) -> Result<(), VaultError> {
    session.set_vault_data(&format!("{PREFIX}{name}"), None)?;
    session.set_vault_data(&format!("{CREATED}{name}"), None)
}

/// The vault's identity as KeePassXC reports it: SHA-256 of the root group's uuid in lowercase hex,
/// checked against KeePassXC's answer for the fixture vault.
pub fn database_hash(vault: &Vault) -> String {
    let root = vault.root_id().uuid().simple().to_string();
    hex(&Sha256::digest(root.as_bytes()))
}

/// What the approval dialog shows, so a user can tell two browsers apart.
pub fn fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    digest[..8].chunks(2).map(hex).collect::<Vec<_>>().join(":")
}

// A key read back as the bytes keepass decoded it to is compared as the base64 it was stored as.
fn as_text(value: &CustomDataValue) -> String {
    match value {
        CustomDataValue::String(text) => text.clone(),
        CustomDataValue::Binary(bytes) => crypto::encode(bytes),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
