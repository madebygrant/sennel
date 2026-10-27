use std::time::{Duration, Instant};

use sennel_core::vault::Vault;

use crate::desk::{Desk, EntryForm, Level, OtpShape, Pick, Style, open_with};
use crate::settings::Settings;

fn vault() -> Vault {
    let mut vault = Vault::new();
    let root = vault.root_id();
    let banks = vault.create_group(&root, "Banks").unwrap();
    vault
        .create_entry(
            &banks,
            "checking",
            "octo",
            "hunter2",
            "https://bank.test",
            "",
        )
        .unwrap();
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
    assert_eq!(view.password_length, "hunter2".chars().count());
    let shown = format!("{rows:?}{view:?}");
    assert!(
        !shown.contains("hunter2"),
        "a password reached a row or the detail: {shown}"
    );
    assert_eq!(desk.reveal(&rows[0].id).unwrap().as_str(), "hunter2");
}

#[test]
fn a_search_ranks_the_whole_vault() {
    let desk = open_with(vault());
    let hits = desk.entries(None, Some("chk")).unwrap();
    assert_eq!(
        hits.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(),
        ["checking"]
    );
    assert!(desk.entries(None, Some("zzzz")).unwrap().is_empty());
}

#[test]
fn an_entry_is_added_edited_and_undone() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let added = desk
        .save_entry(None, Some(&banks), &form("savings", Some("pw")))
        .unwrap();
    let id = added.select.expect("the new entry was not selected");
    assert_eq!(desk.entry(&id).unwrap().tags, "a, b");
    // An untouched password box keeps what is stored.
    desk.save_entry(Some(&id), None, &form("savings 2", None))
        .unwrap();
    assert_eq!(desk.reveal(&id).unwrap().as_str(), "pw");
    let refused = desk
        .save_entry(None, Some(&banks), &form(" ", None))
        .unwrap();
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
    assert!(
        desk.tree().iter().any(|g| g.bin),
        "the bin is not marked in the tree"
    );
}

#[test]
fn copying_never_returns_the_secret() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let id = desk.entries(Some(&banks), None).unwrap()[0].id.clone();
    let note = desk.copy(&id, "password");
    assert!(
        note.text.contains("copied password") && !note.text.contains("hunter2"),
        "{}",
        note.text
    );
    assert_eq!(desk.copy(&id, "otp").level, Level::Warn);
}

#[test]
fn an_entry_carries_its_code_timing_and_never_the_code() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let mut with_otp = form("totp", Some("pw"));
    with_otp.otp = Some("JBSWY3DPEHPK3PXP".into());
    let id = desk
        .save_entry(None, Some(&banks), &with_otp)
        .unwrap()
        .select
        .unwrap();
    let view = desk.entry(&id).unwrap();
    assert!(view.has_otp);
    assert_eq!(
        view.otp,
        Some(OtpShape {
            period: 30,
            digits: 6
        })
    );
    assert!(
        !format!("{view:?}").contains("JBSWY3DP"),
        "the seed reached the detail"
    );
}

#[test]
fn a_qr_image_fills_in_a_seed_with_its_timing() {
    let desk = open_with(vault());
    let qr = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/otp-qr.png"
    );
    let scanned = desk.scan_file(qr, "Example", "ada").unwrap();
    assert!(
        scanned.url.contains("secret=JBSWY3DPEHPK3PXP"),
        "{}",
        scanned.url.as_str()
    );
    assert_eq!(
        scanned.otp,
        Some(OtpShape {
            period: 30,
            digits: 6
        })
    );
    assert_eq!(scanned.label.as_deref(), Some("Example:ada@example.com"));
    let why = desk.scan_file("/nowhere/qr.png", "", "").unwrap_err();
    assert!(why.starts_with("cannot read"), "{why}");
}

// A command missing from build.rs or the capability file is refused at run time, and the
// webview mocks used to check the page never see that.
#[test]
fn every_command_is_declared_and_granted() {
    let lib = include_str!("lib.rs");
    let build = include_str!("../build.rs");
    let granted = include_str!("../capabilities/default.json");
    let handler = lib
        .split("generate_handler![")
        .nth(1)
        .unwrap()
        .split(']')
        .next()
        .unwrap();
    for name in handler.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        assert!(
            build.contains(&format!("\"{name}\"")),
            "{name} is not in build.rs COMMANDS"
        );
        let permission = format!("\"allow-{}\"", name.replace('_', "-"));
        assert!(
            granted.contains(&permission),
            "{name} is not granted in capabilities/default.json"
        );
    }
}

#[test]
fn an_idle_vault_locks_on_the_rust_timer() {
    let desk = Desk::new(
        Settings {
            lock_timeout: 60,
            ..Settings::default()
        },
        None,
    );
    desk.session().open(vault());
    assert!(desk.lock_if_idle(Instant::now()).is_none());
    let notes = desk
        .lock_if_idle(Instant::now() + Duration::from_secs(61))
        .expect("it did not lock");
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
fn a_new_master_password_opens_the_file_and_the_old_one_does_not() {
    let path = std::env::temp_dir().join(format!("sennel-rekey-{}.kdbx", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let desk = Desk::new(Settings::default(), None);
    desk.choose(&path.display().to_string()).unwrap();
    desk.unlock("old".into(), None, Some("old".into()));
    assert!(desk.status().open);

    let empty = desk.rekey(String::new(), String::new());
    assert!(!empty.ok, "an empty password was taken");
    let differ = desk.rekey("new".into(), "neu".into());
    assert!(
        !differ.ok && differ.notes[0].text.contains("differ"),
        "{:?}",
        differ.notes
    );

    let done = desk.rekey("new".into(), "new".into());
    assert!(
        done.ok && done.notes[0].text.contains("master password changed"),
        "{:?}",
        done.notes
    );
    desk.lock();
    let old = desk.unlock("old".into(), None, None);
    assert_eq!(
        old.notes[0].level,
        Level::Error,
        "the old password still opens it"
    );
    desk.unlock("new".into(), None, None);
    assert!(desk.status().open);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_new_master_password_keeps_the_key_file_in_the_key() {
    let path = std::env::temp_dir().join(format!("sennel-rekey-kf-{}.kdbx", std::process::id()));
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/keyfile4.key"
    );
    let _ = std::fs::remove_file(&path);
    let desk = Desk::new(Settings::default(), None);
    desk.choose(&path.display().to_string()).unwrap();
    desk.unlock("old".into(), Some(key.into()), Some("old".into()));
    assert!(desk.status().open);
    let done = desk.rekey("new".into(), "new".into());
    assert!(done.notes[0].text.contains("key file"), "{:?}", done.notes);
    desk.lock();
    let without = desk.unlock("new".into(), None, None);
    assert_eq!(
        without.notes[0].level,
        Level::Error,
        "the key file fell out of the key"
    );
    desk.unlock("new".into(), Some(key.into()), None);
    assert!(desk.status().open);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_broken_config_opens_on_defaults_and_says_why() {
    let settings = Settings::fallback("unknown sort \"nmae\"".into());
    assert!(
        settings.config_file.is_none(),
        "a fallback must not write the broken file"
    );
    assert!(settings.backups > 0, "backups went quiet on a typo");
    let desk = Desk::new(settings, None);
    let why = desk.status().config_error.unwrap();
    assert!(why.contains("nmae") && why.contains("defaults"), "{why}");
}

#[test]
fn o_walks_the_entries_through_each_order() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    for title in ["alpha", "Zulu"] {
        desk.save_entry(None, Some(&banks), &form(title, Some("pw")))
            .unwrap();
    }
    let titles = |desk: &Desk| -> Vec<String> {
        desk.entries(Some(&banks), None)
            .unwrap()
            .into_iter()
            .map(|r| r.title)
            .collect()
    };
    assert_eq!(desk.status().sort, "stored");
    assert_eq!(titles(&desk), ["checking", "alpha", "Zulu"]);
    assert!(desk.cycle_sort().text.contains("by name"));
    assert_eq!(desk.status().sort, "name");
    assert_eq!(titles(&desk), ["alpha", "checking", "Zulu"]);
    for _ in 0..3 {
        desk.cycle_sort();
    }
    assert_eq!(desk.status().sort, "stored", "the walk did not wrap");
}

#[test]
fn a_custom_field_named_like_a_fixed_one_copies_itself() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    let id = desk.entries(Some(&banks), None).unwrap()[0].id.clone();
    desk.add_field(&id, "password", "custom-value").unwrap();
    assert!(
        desk.copy_field(&id, "password")
            .text
            .contains("copied password")
    );
    assert_eq!(desk.copy_field(&id, "nope").level, Level::Warn);
    assert_eq!(
        desk.copy_text("x", String::new()).level,
        Level::Warn,
        "an empty copy went through"
    );
}

#[test]
fn a_tag_needle_filters_instead_of_ranking() {
    let desk = open_with(vault());
    let banks = group(&desk, "Banks");
    desk.save_entry(None, Some(&banks), &form("work thing", Some("pw")))
        .unwrap();
    let tagged = desk.entries(None, Some("#a")).unwrap();
    assert_eq!(
        tagged.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(),
        ["work thing"]
    );
}

#[test]
fn an_in_memory_vault_counts_as_unsaved() {
    let desk = open_with(vault());
    assert!(!desk.unsaved());
    let banks = group(&desk, "Banks");
    desk.add_group(&banks, "more").unwrap();
    assert!(
        desk.unsaved(),
        "a change with nowhere to go did not hold the quit"
    );
}

#[test]
fn a_yubikey_unlock_says_to_touch_it_first() {
    use std::sync::{Arc, Mutex};
    let said: Arc<Mutex<Vec<String>>> = Arc::default();
    let heard = Arc::clone(&said);
    let settings = Settings {
        yubikey: Some("2".parse().unwrap()),
        ..Settings::default()
    };
    let desk = Desk::new(settings, None).with_prompt(move |n| heard.lock().unwrap().push(n.text));
    desk.choose("/nowhere/at/all.kdbx").unwrap();
    desk.unlock("pw".into(), None, Some("pw".into()));
    assert!(
        said.lock()
            .unwrap()
            .iter()
            .any(|t| t.contains("touch your key")),
        "{:?}",
        said.lock().unwrap()
    );
}

#[test]
fn the_config_kind_is_only_the_default() {
    let desk = Desk::new(Settings::default(), None);
    let made = desk.generate(&pick(None, None)).unwrap();
    assert_eq!((made.kind, made.value.len()), ("complex", 20));

    let pin = desk.generate(&pick(Some("pin"), None)).unwrap();
    assert_eq!(pin.kind, "pin");
    assert!(pin.value.chars().all(|c| c.is_ascii_digit()));

    let words = desk.generate(&pick(Some("passphrase"), None)).unwrap();
    assert_eq!(words.value.split('-').count(), 6);
    assert_eq!(
        desk.generate(&pick(None, None)).unwrap().kind,
        "complex",
        "a pick for one password stuck"
    );

    assert!(desk.generate(&pick(Some("words"), None)).is_err());
}

#[test]
fn a_size_counts_in_the_kind_and_keeps_to_the_config_bounds() {
    let desk = Desk::new(Settings::default(), None);
    assert_eq!(
        desk.generate(&pick(None, Some(32))).unwrap().value.len(),
        32
    );
    let words = desk.generate(&pick(Some("passphrase"), Some(3))).unwrap();
    assert_eq!((words.value.split('-').count(), words.size), (3, 3));
    assert_eq!(
        desk.generate(&pick(Some("pin"), Some(8)))
            .unwrap()
            .value
            .len(),
        8
    );

    assert!(
        desk.generate(&pick(None, Some(3))).is_err(),
        "shorter than the config allows"
    );
    assert!(desk.generate(&pick(Some("pin"), Some(13))).is_err());
    assert_eq!(
        desk.generate(&pick(None, None)).unwrap().size,
        20,
        "a size for one password stuck"
    );
}

fn pick(kind: Option<&str>, size: Option<usize>) -> Pick {
    Pick {
        kind: kind.map(str::to_string),
        size,
        style: None,
    }
}

#[test]
fn a_style_shapes_the_password_for_that_password_only() {
    let desk = Desk::new(Settings::default(), None);
    let style = Style {
        upper: false,
        digits: false,
        symbols: true,
        no_lookalikes: true,
    };
    let made = desk
        .generate(&Pick {
            size: Some(64),
            style: Some(style),
            ..Pick::default()
        })
        .unwrap();
    assert_eq!(made.style, style);
    assert!(
        !made
            .value
            .chars()
            .any(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    );
    assert!(made.value.chars().any(|c| !c.is_ascii_alphanumeric()));

    let plain = desk.generate(&Pick::default()).unwrap();
    assert!(plain.style.upper && plain.style.digits && !plain.style.symbols);
}
