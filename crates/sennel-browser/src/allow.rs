// "Always allow" answers, kept in the vault's own custom data so they travel with it and are
// encrypted with it, never in the plain config file. Each entry's own record is left untouched,
// so the first release still writes nothing to an entry.

use std::collections::BTreeMap;

use keepass::db::{CustomDataValue, EntryId};
use sennel_core::session::{Seal, Session};
use sennel_core::vault::{Vault, VaultError};

// One key per host, so a merge of two copies of the vault keeps the hosts each side remembered.
const PREFIX: &str = "sennel.browser.allow.";
// Every host in one JSON map, as the first builds wrote it. Read, and split up on the next write.
const LEGACY: &str = "sennel.browser.allow";

type Allowed = BTreeMap<String, Vec<String>>;

fn parse<T: serde::de::DeserializeOwned>(value: &CustomDataValue) -> Option<T> {
    match value {
        CustomDataValue::String(text) => serde_json::from_str(text).ok(),
        CustomDataValue::Binary(bytes) => serde_json::from_slice(bytes).ok(),
    }
}

fn read(vault: &Vault) -> Allowed {
    let mut all: Allowed = vault
        .meta_data()
        .find(|(k, _)| *k == LEGACY)
        .and_then(|(_, v)| parse(v))
        .unwrap_or_default();
    for (key, value) in vault.meta_data() {
        if let (Some(host), Some(ids)) = (key.strip_prefix(PREFIX), parse(value)) {
            all.insert(host.to_string(), ids);
        }
    }
    all
}

fn uuid(id: &EntryId) -> String {
    id.uuid().simple().to_string()
}

/// The entries `host` may always have, read once for a whole lookup.
pub fn for_host(vault: &Vault, host: &str) -> Vec<EntryId> {
    read(vault)
        .remove(&host.to_ascii_lowercase())
        .unwrap_or_default()
        .iter()
        .filter_map(|id| uuid::Uuid::parse_str(id).ok().map(EntryId::from_uuid))
        .collect()
}

pub fn allowed(vault: &Vault, host: &str, id: &EntryId) -> bool {
    for_host(vault, host).contains(id)
}

fn write<S: Seal>(session: &mut Session<S>, host: &str, ids: &[String]) -> Result<(), VaultError> {
    let text = serde_json::to_string(ids).unwrap_or_default();
    session.set_vault_data(&format!("{PREFIX}{host}"), Some(&text))
}

// The legacy map becomes one key per host before any change, so it is never written again.
fn split_legacy<S: Seal>(session: &mut Session<S>) -> Result<(), VaultError> {
    let Some(vault) = session.vault() else {
        return Ok(());
    };
    if !vault.meta_data().any(|(k, _)| k == LEGACY) {
        return Ok(());
    }
    for (host, ids) in read(vault) {
        write(session, &host, &ids)?;
    }
    session.set_vault_data(LEGACY, None)
}

pub fn remember<S: Seal>(
    session: &mut Session<S>,
    host: &str,
    ids: &[EntryId],
) -> Result<(), VaultError> {
    split_legacy(session)?;
    let host = host.to_ascii_lowercase();
    let mut list = session
        .vault()
        .map(read)
        .unwrap_or_default()
        .remove(&host)
        .unwrap_or_default();
    for id in ids {
        let id = uuid(id);
        if !list.contains(&id) {
            list.push(id);
        }
    }
    write(session, &host, &list)
}

/// Every host with a remembered answer, and how many entries each may have.
pub fn hosts(vault: &Vault) -> Vec<(String, usize)> {
    read(vault)
        .into_iter()
        .map(|(h, ids)| (h, ids.len()))
        .collect()
}

pub fn forget<S: Seal>(session: &mut Session<S>, host: &str) -> Result<(), VaultError> {
    split_legacy(session)?;
    let key = format!("{PREFIX}{}", host.to_ascii_lowercase());
    session.set_vault_data(&key, None)
}
