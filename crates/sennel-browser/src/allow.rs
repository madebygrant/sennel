// "Always allow" answers, kept in the vault's own custom data so they travel with it and are
// encrypted with it, never in the plain config file. Each entry's own record is left untouched,
// so the first release still writes nothing to an entry.

use std::collections::BTreeMap;

use keepass::db::{CustomDataValue, EntryId};
use sennel_core::session::{Seal, Session};
use sennel_core::vault::{Vault, VaultError};

const KEY: &str = "sennel.browser.allow";

type Allowed = BTreeMap<String, Vec<String>>;

fn read(vault: &Vault) -> Allowed {
    vault
        .meta_data()
        .find(|(k, _)| *k == KEY)
        .and_then(|(_, v)| match v {
            CustomDataValue::String(text) => serde_json::from_str(text).ok(),
            CustomDataValue::Binary(bytes) => serde_json::from_slice(bytes).ok(),
        })
        .unwrap_or_default()
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

pub fn remember<S: Seal>(
    session: &mut Session<S>,
    host: &str,
    ids: &[EntryId],
) -> Result<(), VaultError> {
    let mut all = session.vault().map(read).unwrap_or_default();
    let list = all.entry(host.to_ascii_lowercase()).or_default();
    for id in ids {
        let id = uuid(id);
        if !list.contains(&id) {
            list.push(id);
        }
    }
    let text = serde_json::to_string(&all).unwrap_or_default();
    session.set_vault_data(KEY, Some(&text))
}

/// Every host with a remembered answer, and how many entries each may have.
pub fn hosts(vault: &Vault) -> Vec<(String, usize)> {
    read(vault)
        .into_iter()
        .map(|(h, ids)| (h, ids.len()))
        .collect()
}

pub fn forget<S: Seal>(session: &mut Session<S>, host: &str) -> Result<(), VaultError> {
    let mut all = session.vault().map(read).unwrap_or_default();
    all.remove(&host.to_ascii_lowercase());
    if all.is_empty() {
        return session.set_vault_data(KEY, None);
    }
    let text = serde_json::to_string(&all).unwrap_or_default();
    session.set_vault_data(KEY, Some(&text))
}
