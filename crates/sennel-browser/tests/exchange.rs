use std::path::PathBuf;

use crypto_box::{PublicKey, SecretKey};
use keepass::db::{CustomDataItem, CustomDataValue, EntryId};
use sennel_browser::crypto::{self, Channel};
use sennel_browser::server::VERSION;
use sennel_browser::{Answer, Effect, Handled, Prompt, Server, Step, allow, pairing};
use sennel_core::session::Session;
use sennel_core::touchid::Sealed;
use sennel_core::vault::Vault;
use serde_json::{Value, json};

// KeePassXC 2.8.0 paired this copy of the fixture with a client it named `sennel-test`, and
// remembered "allow" for bank.example and www.bank.example on the `checking` entry.
const PAIRED: &str = "keepassxc4-paired.kdbx";
const PAIRED_NAME: &str = "sennel-test";
const PAIRED_KEY: &str = "4PGdlkL0KsIDFZpui/7FOMpDataIxr6g2K9FTAzDxV4=";
// What KeePassXC answered to get-databasehash for that vault.
const PAIRED_HASH: &str = "2a9cf8a01cfa3f563d4f7b241fe343cdd994bfc345fb8c665723bb631e3d6e43";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[derive(Default)]
struct Answers {
    name: Option<String>,
    site: bool,
    always: bool,
    totp: bool,
    pairs_asked: usize,
    sites_asked: Vec<(String, Vec<String>)>,
    totps_asked: Vec<String>,
}

impl Answers {
    fn answer(&mut self, prompt: &Prompt) -> Answer {
        let yes = |y: bool| if y { Answer::Yes } else { Answer::No };
        match prompt {
            Prompt::Pair { fingerprint } => {
                assert_eq!(fingerprint.len(), 19, "four colon-separated pairs of bytes");
                self.pairs_asked += 1;
                self.name.clone().map_or(Answer::No, Answer::Named)
            }
            Prompt::Site { host, titles } => {
                self.sites_asked.push((host.clone(), titles.clone()));
                if self.always {
                    return Answer::Always;
                }
                yes(self.site)
            }
            Prompt::Totp { title } => {
                self.totps_asked.push(title.clone());
                yes(self.totp)
            }
        }
    }
}

// What a front end does: answer any question, with the session free while it waits.
fn run(
    server: &mut Server,
    session: &mut Session<Sealed>,
    ask: &mut Answers,
    raw: &[u8],
) -> Handled {
    match server.handle(session, raw) {
        Step::Reply(handled) => handled,
        Step::Ask(question) => {
            let answer = ask.answer(&question.prompt);
            server.resume(session, question, answer)
        }
    }
}

// A browser's side of the protocol, written from the protocol document and KeePassXC's replies.
struct Browser {
    secret: SecretKey,
    id: String,
    channel: Option<Channel>,
    identity: String,
}

impl Browser {
    fn new() -> Self {
        Browser {
            secret: crypto::generate_secret(),
            id: crypto::encode(&crypto::random_nonce()),
            channel: None,
            identity: crypto::encode(crypto::generate_secret().public_key().as_bytes()),
        }
    }

    fn public(&self) -> String {
        crypto::encode(self.secret.public_key().as_bytes())
    }

    fn exchange(&mut self, server: &mut Server, session: &mut Session<Sealed>) {
        let nonce = crypto::random_nonce();
        let request = json!({
            "action": "change-public-keys",
            "publicKey": self.public(),
            "nonce": crypto::encode(&nonce),
            "clientID": self.id,
        });
        let handled = run(
            server,
            session,
            &mut Answers::default(),
            request.to_string().as_bytes(),
        );
        let reply: Value = serde_json::from_slice(&handled.reply).unwrap();
        assert_eq!(reply["success"], "true");
        assert_eq!(reply["version"], VERSION);
        assert_eq!(reply["nonce"], crypto::encode(&crypto::increment(&nonce)));
        let host: PublicKey = crypto::decode_key(reply["publicKey"].as_str().unwrap()).unwrap();
        self.channel = Some(Channel::new(&self.secret, &host));
    }

    fn envelope(&mut self, inner: &Value, nonce: &crypto::Nonce) -> Vec<u8> {
        let cipher = self
            .channel
            .as_mut()
            .unwrap()
            .seal(nonce, inner.to_string().as_bytes())
            .unwrap();
        json!({
            "action": inner["action"],
            "message": crypto::encode(&cipher),
            "nonce": crypto::encode(nonce),
            "clientID": self.id,
        })
        .to_string()
        .into_bytes()
    }

    // The decrypted reply, or the clear error reply.
    fn send(
        &mut self,
        server: &mut Server,
        session: &mut Session<Sealed>,
        ask: &mut Answers,
        inner: Value,
    ) -> (Value, Effect) {
        let nonce = crypto::random_nonce();
        let raw = self.envelope(&inner, &nonce);
        self.read(run(server, session, ask, &raw), &inner, &nonce)
    }

    fn read(&mut self, handled: Handled, inner: &Value, nonce: &crypto::Nonce) -> (Value, Effect) {
        let reply: Value = serde_json::from_slice(&handled.reply).unwrap();
        assert_eq!(reply["action"], inner["action"]);
        let Some(message) = reply["message"].as_str() else {
            return (reply, handled.effect);
        };
        let reply_nonce = crypto::increment(nonce);
        assert_eq!(reply["nonce"], crypto::encode(&reply_nonce));
        let cipher = crypto::decode(message).unwrap();
        let plain = self
            .channel
            .as_mut()
            .unwrap()
            .open(&reply_nonce, &cipher)
            .unwrap();
        let body: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(body["success"], "true");
        assert_eq!(body["nonce"], reply["nonce"]);
        (body, handled.effect)
    }

    fn keys(&self, name: &str) -> Value {
        json!([{ "id": name, "key": self.identity }])
    }
}

fn session_with(vault: Vault) -> Session<Sealed> {
    let mut session = Session::new();
    session.open(vault);
    session
}

fn new_vault() -> (Vault, EntryId) {
    let mut vault = Vault::new();
    let root = vault.root_id();
    let id = vault
        .create_entry(&root, "site", "ada", "hunter2", "https://site.example", "")
        .unwrap();
    (vault, id)
}

fn error_code(reply: &Value) -> &str {
    reply["errorCode"].as_str().unwrap_or("none")
}

#[test]
fn a_browser_exchanges_keys_pairs_and_gets_a_login() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);

    let mut ask = Answers {
        name: Some("laptop".into()),
        site: true,
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    let (reply, effect) = browser.send(&mut server, &mut session, &mut ask, associate);
    assert_eq!(reply["id"], "laptop");
    assert_eq!(effect, Effect::Changed);
    assert_eq!(ask.pairs_asked, 1);
    let vault = session.vault().unwrap();
    assert_eq!(reply["hash"], pairing::database_hash(vault));
    let stored = pairing::pairings(vault);
    assert_eq!(
        (stored[0].name.as_str(), stored[0].key.as_str()),
        ("laptop", browser.identity.as_str())
    );

    let test = json!({"action": "test-associate", "id": "laptop", "key": browser.identity});
    let (reply, effect) = browser.send(&mut server, &mut session, &mut ask, test);
    assert_eq!(
        (reply["id"].as_str(), effect),
        (Some("laptop"), Effect::None)
    );

    let lookup = json!({"action": "get-logins", "url": "https://site.example/login", "keys": browser.keys("laptop")});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, lookup);
    assert_eq!(reply["count"], 1);
    let entry = &reply["entries"][0];
    assert_eq!(
        (entry["login"].as_str(), entry["password"].as_str()),
        (Some("ada"), Some("hunter2"))
    );
    assert_eq!(entry["name"], "site");
    assert_eq!(entry["stringFields"], json!([]));
    assert_eq!(
        ask.sites_asked,
        vec![("site.example".to_string(), vec!["site".to_string()])]
    );
}

#[test]
fn the_pairing_keepassxc_made_is_found_and_its_remembered_answers_kept() {
    let vault = Vault::open(&fixture(PAIRED), "sennel-fixture", None).unwrap();
    assert_eq!(pairing::database_hash(&vault), PAIRED_HASH);
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers::default();

    let test = json!({"action": "test-associate", "id": PAIRED_NAME, "key": PAIRED_KEY});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, test);
    assert_eq!(
        (reply["id"].as_str(), reply["hash"].as_str()),
        (Some(PAIRED_NAME), Some(PAIRED_HASH))
    );

    let keys = json!([{ "id": PAIRED_NAME, "key": PAIRED_KEY }]);
    let lookup = json!({"action": "get-logins", "url": "https://bank.example/", "keys": keys});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, lookup);
    let entry = &reply["entries"][0];
    assert_eq!(
        (entry["login"].as_str(), entry["password"].as_str()),
        (Some("octo"), Some("pw-two"))
    );
    // The same fields and uuid form KeePassXC sent for this entry.
    assert_eq!(entry["uuid"], "7ba556a2543e40259394290c77d61037");
    assert_eq!(entry["group"], "Banks");
    assert!(
        ask.sites_asked.is_empty(),
        "the remembered allow should stand"
    );

    // KeePassXC matches subdomains by default; Sennel does not.
    let lookup = json!({"action": "get-logins", "url": "https://www.bank.example/", "keys": keys});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, lookup);
    assert_eq!(error_code(&reply), "15");
}

#[test]
fn a_replayed_message_is_refused() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let inner = json!({"action": "get-databasehash"});
    let nonce = crypto::random_nonce();
    let raw = browser.envelope(&inner, &nonce);
    let mut ask = Answers::default();
    let (first, _) = browser.read(
        run(&mut server, &mut session, &mut ask, &raw),
        &inner,
        &nonce,
    );
    assert!(first["hash"].is_string());
    let again: Value =
        serde_json::from_slice(&run(&mut server, &mut session, &mut ask, &raw).reply).unwrap();
    assert_eq!(error_code(&again), "4");
    assert!(again.get("message").is_none());
}

#[test]
fn every_refused_action_gets_an_error_and_leaves_the_vault_alone() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        site: true,
        totp: true,
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate);
    let before = session.vault().unwrap().db().clone();
    let revision = session.revision();
    let keys = browser.keys("laptop");

    let refused = [
        json!({"action": "set-login", "url": "https://site.example", "login": "eve", "password": "x", "uuid": "", "keys": keys}),
        json!({"action": "create-new-group", "groupName": "Evil"}),
        json!({"action": "get-database-groups"}),
        json!({"action": "generate-password", "requestID": "abcd1234"}),
        json!({"action": "passkeys-register", "publicKey": {}, "origin": "https://site.example", "keys": keys}),
        json!({"action": "passkeys-get", "publicKey": {}, "origin": "https://site.example", "keys": keys}),
        json!({"action": "request-autotype", "search": "site.example"}),
    ];
    for inner in refused {
        let action = inner["action"].clone();
        let (reply, effect) = browser.send(&mut server, &mut session, &mut ask, inner);
        assert_eq!(error_code(&reply), "12", "{action}");
        assert!(
            reply["error"]
                .as_str()
                .unwrap()
                .contains("not available in Sennel yet"),
            "{action}"
        );
        assert_eq!(effect, Effect::None, "{action}");
    }
    assert_eq!(session.vault().unwrap().db(), &before);
    assert_eq!(session.revision(), revision);
}

#[test]
fn nothing_is_answered_while_the_vault_is_locked() {
    let mut session: Session<Sealed> = Session::new();
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers::default();
    for inner in [
        json!({"action": "get-databasehash"}),
        json!({"action": "get-logins", "url": "https://site.example", "keys": browser.keys("x")}),
    ] {
        let (reply, _) = browser.send(&mut server, &mut session, &mut ask, inner);
        assert_eq!(error_code(&reply), "1");
    }
    assert_eq!(Server::notice(true), br#"{"action":"database-locked"}"#);
}

#[test]
fn an_unpaired_browser_gets_no_logins_and_no_codes() {
    let (vault, id) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        site: true,
        totp: true,
        ..Answers::default()
    };
    let lookup = json!({"action": "get-logins", "url": "https://site.example", "keys": browser.keys("laptop")});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, lookup);
    assert_eq!(error_code(&reply), "8");
    let uuid = id.uuid().simple().to_string();
    let (reply, _) = browser.send(
        &mut server,
        &mut session,
        &mut ask,
        json!({"action": "get-totp", "uuid": uuid}),
    );
    assert_eq!(error_code(&reply), "8");
    let (reply, effect) = browser.send(
        &mut server,
        &mut session,
        &mut ask,
        json!({"action": "lock-database"}),
    );
    assert_eq!((error_code(&reply), effect), ("8", Effect::None));
    assert!(ask.sites_asked.is_empty() && ask.totps_asked.is_empty());
}

#[test]
fn pairing_refuses_a_relayed_key_a_refusal_and_a_read_only_vault() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);

    let mut ask = Answers {
        name: Some("laptop".into()),
        ..Answers::default()
    };
    let other = crypto::encode(crypto::generate_secret().public_key().as_bytes());
    let relayed = json!({"action": "associate", "key": other, "idKey": browser.identity});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, relayed);
    assert_eq!((error_code(&reply), ask.pairs_asked), ("8", 0));

    let mut no = Answers::default();
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    let (reply, effect) = browser.send(&mut server, &mut session, &mut no, associate.clone());
    assert_eq!((error_code(&reply), effect), ("8", Effect::None));
    assert!(pairing::pairings(session.vault().unwrap()).is_empty());

    let old = Vault::open(&fixture("keepassxc3.kdbx"), "sennel-fixture", None).unwrap();
    let mut session = session_with(old);
    browser.exchange(&mut server, &mut session);
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, associate);
    assert_eq!((error_code(&reply), ask.pairs_asked), ("8", 0));
}

#[test]
fn a_one_time_code_needs_its_own_yes_and_a_login_given_first() {
    let (mut vault, id) = new_vault();
    vault
        .set_otp(
            &id,
            Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6"),
        )
        .unwrap();
    let root = vault.root_id();
    let other = vault
        .create_entry(&root, "other", "bob", "pw", "https://elsewhere.example", "")
        .unwrap();
    vault
        .set_otp(
            &other,
            Some("otpauth://totp/y?secret=JBSWY3DPEHPK3PXP&digits=6"),
        )
        .unwrap();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        site: true,
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate);
    let totp = |id: EntryId| json!({"action": "get-totp", "uuid": id.uuid().simple().to_string()});

    // Not given to this browser through get-logins yet, so no code and no prompt.
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, totp(id));
    assert_eq!(error_code(&reply), "18");
    assert!(ask.totps_asked.is_empty());

    let lookup = json!({"action": "get-logins", "url": "https://site.example/", "keys": browser.keys("laptop")});
    browser.send(&mut server, &mut session, &mut ask, lookup);
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, totp(id));
    assert_eq!(error_code(&reply), "18");
    ask.totp = true;
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, totp(id));
    assert_eq!(reply["totp"].as_str().unwrap().len(), 6);
    assert_eq!(ask.totps_asked, vec!["site", "site"]);

    // An entry for another site stays out of reach.
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, totp(other));
    assert_eq!(error_code(&reply), "18");
}

#[test]
fn revoking_a_pairing_or_opening_another_vault_ends_the_connection_trust() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate);

    pairing::revoke(&mut session, "laptop").unwrap();
    let (reply, effect) = browser.send(
        &mut server,
        &mut session,
        &mut ask,
        json!({"action": "lock-database"}),
    );
    assert_eq!((error_code(&reply), effect), ("8", Effect::None));

    let (other, _) = new_vault();
    session.lock();
    session.open(other);
    let (reply, _) = browser.send(
        &mut server,
        &mut session,
        &mut ask,
        json!({"action": "lock-database"}),
    );
    assert_eq!(error_code(&reply), "8");
}

#[test]
fn an_answer_is_checked_again_against_what_changed_while_the_user_was_asked() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate.clone());

    // A login request waits on the user while another vault is opened.
    let lookup = json!({"action": "get-logins", "url": "https://site.example/", "keys": browser.keys("laptop")});
    let nonce = crypto::random_nonce();
    let raw = browser.envelope(&lookup, &nonce);
    let Step::Ask(question) = server.handle(&session, &raw) else {
        panic!("the site has no remembered answer, so the user is asked");
    };
    let (other, _) = new_vault();
    session.lock();
    session.open(other);
    let handled = server.resume(&mut session, question, Answer::Yes);
    let (reply, _) = browser.read(handled, &lookup, &nonce);
    assert_eq!(error_code(&reply), "8");

    // A pairing question answered after the browser exchanged keys again is dropped.
    let nonce = crypto::random_nonce();
    let raw = browser.envelope(&associate, &nonce);
    let Step::Ask(question) = server.handle(&session, &raw) else {
        panic!("pairing always asks");
    };
    browser.exchange(&mut server, &mut session);
    let reply: Value = serde_json::from_slice(
        &server
            .resume(&mut session, question, Answer::Named("x".into()))
            .reply,
    )
    .unwrap();
    assert_eq!(error_code(&reply), "4");
    assert!(pairing::pairings(session.vault().unwrap()).is_empty());
}

#[test]
fn an_entry_hidden_from_the_browser_in_keepassxc_is_never_offered() {
    // A copy of the paired fixture with "Hide this entry from the browser extension" ticked on
    // `checking`, saved by KeePassXC 2.8.0.
    let vault = Vault::open(&fixture("keepassxc4-hidden.kdbx"), "sennel-fixture", None).unwrap();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        site: true,
        ..Answers::default()
    };
    let keys = json!([{ "id": PAIRED_NAME, "key": PAIRED_KEY }]);
    let lookup = json!({"action": "get-logins", "url": "https://bank.example/", "keys": keys});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, lookup);
    assert_eq!(error_code(&reply), "15");
}

#[test]
fn denied_entries_and_extra_urls_follow_the_entry() {
    let (mut vault, id) = new_vault();
    let root = vault.root_id();
    let other = vault
        .create_entry(&root, "other", "bob", "pw", "https://elsewhere.example", "")
        .unwrap();
    vault
        .set_field(&other, "KP2A_URL_1", "https://site.example", false)
        .unwrap();
    vault.db_mut().entry_mut(id).unwrap().custom_data.insert(
        "KeePassXC-Browser Settings".into(),
        CustomDataItem {
            value: Some(CustomDataValue::String(
                r#"{"Allow":[],"Deny":["site.example"],"Realm":""}"#.into(),
            )),
            last_modification_time: None,
        },
    );
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        site: true,
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate);

    let lookup = json!({"action": "get-logins", "url": "https://site.example/", "keys": browser.keys("laptop")});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, lookup);
    let names: Vec<&str> = reply["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["other"]);
}

#[test]
fn a_request_whose_clear_action_differs_from_the_sealed_one_is_refused() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let nonce = crypto::random_nonce();
    let mut raw: Value =
        serde_json::from_slice(&browser.envelope(&json!({"action": "get-databasehash"}), &nonce))
            .unwrap();
    raw["action"] = json!("test-associate");
    let reply: Value = serde_json::from_slice(
        &run(
            &mut server,
            &mut session,
            &mut Answers::default(),
            raw.to_string().as_bytes(),
        )
        .reply,
    )
    .unwrap();
    assert_eq!(error_code(&reply), "12");
}

#[test]
fn garbage_gets_an_error_not_a_panic() {
    let mut session: Session<Sealed> = Session::new();
    let mut server = Server::new();
    for raw in [
        &b""[..],
        b"{",
        b"[]",
        br#"{"action":"get-logins","clientID":"x","nonce":"AAAA","message":"!!"}"#,
    ] {
        let reply: Value = serde_json::from_slice(
            &run(&mut server, &mut session, &mut Answers::default(), raw).reply,
        )
        .unwrap();
        assert!(reply["errorCode"].is_string());
    }
}

#[test]
fn a_pairing_survives_a_save_and_a_reopen() {
    let dir = std::env::temp_dir().join(format!("sennel-browser-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("paired.kdbx");
    let (mut vault, _) = new_vault();
    vault.save_as(&path, "pw", None).unwrap();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    let (_, effect) = browser.send(&mut server, &mut session, &mut ask, associate);
    assert_eq!(effect, Effect::Changed);
    session.vault_mut().unwrap().save().unwrap();

    let reopened = Vault::open(&path, "pw", None).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(pairing::is_paired(&reopened, "laptop", &browser.identity));
    let mut session = session_with(reopened);
    pairing::revoke(&mut session, "laptop").unwrap();
    assert!(pairing::pairings(session.vault().unwrap()).is_empty());
}

#[test]
fn sennels_own_host_gives_the_hash_only_after_a_pairing_is_shown() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::strict();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        ..Answers::default()
    };
    let hash = json!({"action": "get-databasehash"});
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, hash.clone());
    assert_eq!(error_code(&reply), "8");
    assert!(!server.known());
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate);
    let (reply, _) = browser.send(&mut server, &mut session, &mut ask, hash);
    assert!(reply["hash"].is_string());
    assert!(server.known());
}

#[test]
fn always_is_remembered_in_the_vault_and_asked_no_more() {
    let (vault, id) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        always: true,
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate);
    let lookup = json!({"action": "get-logins", "url": "https://site.example/", "keys": browser.keys("laptop")});
    let (reply, effect) = browser.send(&mut server, &mut session, &mut ask, lookup.clone());
    assert_eq!(
        (reply["count"].as_u64(), effect),
        (Some(1), Effect::Changed)
    );
    assert!(allow::allowed(
        session.vault().unwrap(),
        "site.example",
        &id
    ));
    // The entry itself is not written to.
    let entry = session.vault().unwrap().get_entry(&id).unwrap();
    assert!(entry.custom_data.is_empty());

    let (reply, effect) = browser.send(&mut server, &mut session, &mut ask, lookup.clone());
    assert_eq!((reply["count"].as_u64(), effect), (Some(1), Effect::None));
    assert_eq!(ask.sites_asked.len(), 1);

    allow::forget(&mut session, "site.example").unwrap();
    assert!(allow::hosts(session.vault().unwrap()).is_empty());
    browser.send(&mut server, &mut session, &mut ask, lookup);
    assert_eq!(ask.sites_asked.len(), 2);
}

#[test]
fn always_after_the_pairing_was_revoked_meanwhile_remembers_nothing() {
    let (vault, _) = new_vault();
    let mut session = session_with(vault);
    let mut server = Server::new();
    let mut browser = Browser::new();
    browser.exchange(&mut server, &mut session);
    let mut ask = Answers {
        name: Some("laptop".into()),
        ..Answers::default()
    };
    let associate =
        json!({"action": "associate", "key": browser.public(), "idKey": browser.identity});
    browser.send(&mut server, &mut session, &mut ask, associate);
    let lookup = json!({"action": "get-logins", "url": "https://site.example/", "keys": browser.keys("laptop")});
    let nonce = crypto::random_nonce();
    let raw = browser.envelope(&lookup, &nonce);
    let Step::Ask(question) = server.handle(&session, &raw) else {
        panic!("the site has no remembered answer, so the user is asked");
    };
    pairing::revoke(&mut session, "laptop").unwrap();
    let handled = server.resume(&mut session, question, Answer::Always);
    assert_eq!(handled.effect, Effect::None);
    let (reply, _) = browser.read(handled, &lookup, &nonce);
    assert_eq!(error_code(&reply), "8");
    assert!(allow::hosts(session.vault().unwrap()).is_empty());
}
