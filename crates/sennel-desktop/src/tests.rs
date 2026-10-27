use std::time::{Duration, Instant};

use sennel_core::vault::Vault;

use crate::desk::{Desk, EntryForm, Level, open_with};
use crate::settings::Settings;

fn vault() -> Vault {
    let mut vault = Vault::new();
    let root = vault.root_id();
    let banks = vault.create_group(&root, "Banks").unwrap();
    vault.create_entry(&banks, "checking", "octo", "hunter2", "https://bank.test", "").unwrap();
    vault
}

fn form(title: &str, password: Option<&str>) -> EntryForm {
    EntryForm {
        title: title.into(),
        username: "u".into(),
        password: password.map(Into::into),
        url: String::new(),
        notes: String::new(),
        tags: "a, b".into(),
        expires: String::new(),
        otp: None,
    }
}

fn group(desk: &Desk, name: &str) -> String {
    desk.tree().into_iter().find(|g| g.name == name).unwrap().id
}

#[test]
fn the_tree_and_rows_carry_no_passwords() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let rows = desk.entries(Some(&banks), None).unwrap();
    assert_eq!(rows.len(), 1);
    let view = desk.entry(&rows[0].id).unwrap();
    assert!(view.has_password && view.group == "Banks");
    let shown = format!("{rows:?}{view:?}");
    assert!(!shown.contains("hunter2"), "a password reached a row or the detail: {shown}");
    assert_eq!(desk.reveal(&rows[0].id).unwrap().as_str(), "hunter2");
}

#[test]
fn a_search_ranks_the_whole_vault() {
    let desk = open_with(vault());
    let hits = desk.entries(None, Some("chk")).unwrap();
    assert_eq!(hits.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(), ["checking"]);
    assert!(desk.entries(None, Some("zzzz")).unwrap().is_empty());
}

#[test]
fn an_entry_is_added_edited_and_undone() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let added = desk.save_entry(None, Some(&banks), &form("savings", Some("pw"))).unwrap();
    let id = added.select.expect("the new entry was not selected");
    assert_eq!(desk.entry(&id).unwrap().tags, "a, b");
    // An untouched password box keeps what is stored.
    desk.save_entry(Some(&id), None, &form("savings 2", None)).unwrap();
    assert_eq!(desk.reveal(&id).unwrap().as_str(), "pw");
    let refused = desk.save_entry(None, Some(&banks), &form(" ", None)).unwrap();
    assert!(!refused.ok && refused.notes[0].level == Level::Warn);
    desk.undo();
    assert_eq!(desk.entry(&id).unwrap().title, "savings");
}

#[test]
fn a_moved_entry_lands_in_its_group_and_a_delete_goes_to_the_bin() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let root = group(&desk, "Root");
    let id = desk.entries(Some(&banks), None).unwrap()[0].id.clone();
    desk.move_entry(&id, &root).unwrap();
    assert!(desk.entries(Some(&banks), None).unwrap().is_empty());
    desk.delete_entry(&id).unwrap();
    assert!(desk.entry(&id).unwrap().recycled);
    assert!(desk.tree().iter().any(|g| g.bin), "the bin is not marked in the tree");
}

#[test]
fn copying_never_returns_the_secret() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let id = desk.entries(Some(&banks), None).unwrap()[0].id.clone();
    let note = desk.copy(&id, "password");
    assert!(note.text.contains("copied password") && !note.text.contains("hunter2"), "{}", note.text);
    assert_eq!(desk.copy(&id, "otp").level, Level::Warn);
}

#[test]
fn an_idle_vault_locks_on_the_rust_timer() {
    let desk = Desk::new(Settings { lock_timeout: 60, ..Settings::default() }, None);
    desk.session().open(vault());
    assert!(desk.lock_if_idle(Instant::now()).is_none());
    let notes = desk.lock_if_idle(Instant::now() + Duration::from_secs(61)).expect("it did not lock");
    assert!(notes[0].text.contains("60 seconds idle"), "{:?}", notes);
    assert!(!desk.status().open && desk.tree().is_empty());
}

#[test]
fn a_vault_is_created_then_unlocked_from_its_file() {
    let path = std::env::temp_dir().join(format!("sennel-desk-{}.kdbx", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let desk = Desk::new(Settings::default(), None);
    desk.choose(&path.display().to_string()).unwrap();
    assert!(desk.status().creates);
    let refused = desk.unlock("pw".into(), None, None);
    assert!(!desk.status().open, "{:?}", refused.notes);
    desk.unlock("pw".into(), None, Some("pw".into()));
    assert!(desk.status().open);
    desk.lock();
    let wrong = desk.unlock("nope".into(), None, None);
    assert_eq!(wrong.notes[0].level, Level::Error);
    desk.unlock("pw".into(), None, None);
    assert!(desk.status().open);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_custom_field_named_like_a_fixed_one_copies_itself() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let id = desk.entries(Some(&banks), None).unwrap()[0].id.clone();
    desk.add_field(&id, "password", "custom-value").unwrap();
    assert!(desk.copy_field(&id, "password").text.contains("copied password"));
    assert_eq!(desk.copy_field(&id, "nope").level, Level::Warn);
    assert_eq!(desk.copy_text("x", String::new()).level, Level::Warn, "an empty copy went through");
}

#[test]
fn a_tag_needle_filters_instead_of_ranking() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    desk.save_entry(None, Some(&banks), &form("work thing", Some("pw"))).unwrap();
    let tagged = desk.entries(None, Some("#a")).unwrap();
    assert_eq!(tagged.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(), ["work thing"]);
}

#[test]
fn an_in_memory_vault_counts_as_unsaved() {
    let desk = open_with(vault());
    assert!(!desk.unsaved());
    let banks = group(&desk, "Banks");
    desk.add_group(&banks, "more").unwrap();
    assert!(desk.unsaved(), "a change with nowhere to go did not hold the quit");
}

#[test]
fn a_yubikey_unlock_says_to_touch_it_first() {
    use std::sync::{Arc, Mutex};
    let said: Arc<Mutex<Vec<String>>> = Arc::default();
    let heard = Arc::clone(&said);
    let settings = Settings { yubikey: Some("2".parse().unwrap()), ..Settings::default() };
    let desk = Desk::new(settings, None).with_prompt(move |n| heard.lock().unwrap().push(n.text));
    desk.choose("/nowhere/at/all.kdbx").unwrap();
    desk.unlock("pw".into(), None, Some("pw".into()));
    assert!(said.lock().unwrap().iter().any(|t| t.contains("touch your key")), "{:?}", said.lock().unwrap());
}
