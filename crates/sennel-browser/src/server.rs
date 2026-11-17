use std::collections::{HashMap, HashSet};

use crypto_box::{PublicKey, SecretKey};
use keepass::db::{EntryId, EntryRef};
use sennel_core::session::{Seal, Session};
use sennel_core::vault::{self, Vault};
use sennel_core::wiped::WipedBytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::{self, Channel, CryptoError, Nonce};
use crate::matching::{self, Page, Remembered};
use crate::{allow, pairing};

/// The KeePassXC version Sennel answers as. The extension turns features on by it.
pub const VERSION: &str = "2.8.0";

/// Sennel's own additions to the protocol, so its extension can check for them. 1 has none yet.
pub const SENNEL_PROTOCOL: u32 = 1;

// Bounds the per-connection state a flood of key exchanges could pile up.
const MAX_CLIENTS: usize = 64;

/// What `handle` came to: a reply now, or a question for the user first.
pub enum Step {
    Reply(Handled),
    Ask(Box<Question>),
}

/// What the front end has to do after a request, besides sending the reply.
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    /// The vault changed (a pairing was added) and needs saving.
    Changed,
    /// The browser asked to lock. Every connection gets `notice(true)` once the lock is done.
    Lock,
}

pub struct Handled {
    pub reply: Vec<u8>,
    pub effect: Effect,
}

/// What the user is asked.
#[derive(Debug, PartialEq, Eq)]
pub enum Prompt {
    /// Pair a browser, under a name the user gives.
    Pair {
        fingerprint: String,
    },
    /// Let `host` have these entries, none of which has a remembered answer for it.
    Site {
        host: String,
        titles: Vec<String>,
    },
    Totp {
        title: String,
    },
}

pub enum Answer {
    No,
    Yes,
    /// Yes, and remember it for this host, in the vault.
    Always,
    Named(String),
}

// A request waiting on the user. The front end lets go of the session while the prompt is up and
// passes this back to `resume`, which checks again everything that could have changed meanwhile.
pub struct Question {
    pub prompt: Prompt,
    client: String,
    epoch: u64,
    action: String,
    reply: Nonce,
    hash: String,
    pending: Pending,
}

enum Pending {
    Pair {
        id_key: String,
    },
    Logins {
        page: Page,
        allowed: Vec<EntryId>,
        asked: Vec<EntryId>,
    },
    Totp {
        entry: EntryId,
    },
}

// Error codes and wording as KeePassXC sends them, seen by asking it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    DatabaseNotOpened = 1,
    CannotDecrypt = 4,
    AssociationFailed = 8,
    IncorrectAction = 12,
    NoLogins = 15,
    NoValidUuid = 18,
}

impl Code {
    fn text(self) -> &'static str {
        match self {
            Code::DatabaseNotOpened => "Database not opened",
            Code::CannotDecrypt => "Cannot decrypt message",
            Code::AssociationFailed => "KeePassXC association failed, try again",
            Code::IncorrectAction => "Incorrect action",
            Code::NoLogins => "No logins found",
            Code::NoValidUuid => "No valid UUID provided",
        }
    }
}

// Writes the vault or needs a feature the first release leaves out. `generate-password` is here
// too: a generated password filled into a sign-up form, with no way to save it, is lost.
const NOT_YET: &[(&str, &str)] = &[
    ("set-login", "Saving logins"),
    ("create-new-group", "Creating groups"),
    ("get-database-groups", "Choosing a group"),
    ("generate-password", "Generating passwords"),
    ("passkeys-register", "Passkeys"),
    ("passkeys-get", "Passkeys"),
    ("request-autotype", "Auto-Type"),
];

const REUSED: &str = "Message refused: nonce reused";

#[derive(Deserialize)]
struct Envelope {
    action: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(rename = "clientID", default)]
    client_id: Option<String>,
    #[serde(rename = "publicKey", default)]
    public_key: Option<String>,
}

// The pairing a connection proved, checked against the open vault on every use, so a revoke or a
// different vault ends it.
struct Trust {
    name: String,
    key: String,
    hash: String,
}

struct Client {
    key: PublicKey,
    channel: Channel,
    // Which key exchange this is, so a question cannot be answered on a newer one.
    epoch: u64,
    trust: Option<Trust>,
    // Entries this connection was given through get-logins: the only ones get-totp will serve.
    released: HashSet<EntryId>,
}

impl Client {
    fn trusted(&self, vault: &Vault) -> bool {
        self.trust.as_ref().is_some_and(|t| {
            t.hash == pairing::database_hash(vault) && pairing::is_paired(vault, &t.name, &t.key)
        })
    }

    fn trust(&mut self, name: &str, key: &str, hash: &str) {
        if self.trust.as_ref().is_some_and(|t| t.hash != hash) {
            self.released.clear();
        }
        self.trust = Some(Trust {
            name: name.to_string(),
            key: key.to_string(),
            hash: hash.to_string(),
        });
    }
}

#[derive(Default)]
pub struct Server {
    clients: HashMap<String, Client>,
    epochs: u64,
    // The vault's hash goes only to a connection that proved a pairing. Sennel's own host works
    // this way; KeePassXC-Browser needs the hash first to choose which pairing to prove.
    strict: bool,
    // Some connection here has proved a pairing, so it may bring the window forward to unlock.
    known: bool,
}

type Fail = (Code, Option<String>);
type Done = Result<(WipedBytes, Effect), Fail>;

enum Outcome {
    Done(Done),
    Ask(Prompt, Pending),
}

#[derive(Serialize)]
struct Login<'a> {
    group: &'a str,
    login: &'a str,
    name: &'a str,
    password: &'a str,
    #[serde(rename = "stringFields")]
    string_fields: [(); 0],
    uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expired: Option<&'static str>,
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn strict() -> Self {
        Server {
            strict: true,
            ..Self::default()
        }
    }

    /// Whether a connection here has shown a pairing since this server started.
    pub fn known(&self) -> bool {
        self.known
    }

    /// The unprompted message KeePassXC sends every connection when the vault locks or unlocks.
    pub fn notice(locked: bool) -> Vec<u8> {
        let action = if locked {
            "database-locked"
        } else {
            "database-unlocked"
        };
        serde_json::to_vec(&serde_json::json!({ "action": action })).unwrap_or_default()
    }

    /// Answers one request, or returns the question to put to the user first. Reads the session
    /// only; every change happens in `resume`. Never panics on what a browser sends.
    pub fn handle<S: Seal>(&mut self, session: &Session<S>, raw: &[u8]) -> Step {
        let Ok(envelope) = serde_json::from_slice::<Envelope>(raw) else {
            return Step::Reply(refuse("", Code::IncorrectAction, None));
        };
        let action = envelope.action.clone();
        if action == "change-public-keys" {
            return Step::Reply(self.exchange(envelope));
        }
        let (Some(id), Some(nonce), Some(message)) =
            (&envelope.client_id, &envelope.nonce, &envelope.message)
        else {
            return Step::Reply(refuse(&action, Code::CannotDecrypt, None));
        };
        let Some(client) = self.clients.get_mut(id) else {
            return Step::Reply(refuse(&action, Code::CannotDecrypt, None));
        };
        let (Ok(nonce), Some(cipher)) = (crypto::decode_nonce(nonce), crypto::decode(message))
        else {
            return Step::Reply(refuse(&action, Code::CannotDecrypt, None));
        };
        let reply = crypto::increment(&nonce);
        // Checked before anything runs, so an answer is never given that could not be sealed.
        if client.channel.spent(&reply) {
            return Step::Reply(refuse(&action, Code::CannotDecrypt, Some(REUSED)));
        }
        let plain = match client.channel.open(&nonce, &cipher) {
            Ok(plain) => plain,
            Err(CryptoError::Replayed) => {
                return Step::Reply(refuse(&action, Code::CannotDecrypt, Some(REUSED)));
            }
            Err(_) => return Step::Reply(refuse(&action, Code::CannotDecrypt, None)),
        };
        let Ok(inner) = serde_json::from_slice::<Value>(&plain) else {
            return Step::Reply(refuse(&action, Code::CannotDecrypt, None));
        };
        // The clear action is what a proxy or log sees; it has to be the one that runs.
        if inner.get("action").and_then(Value::as_str) != Some(action.as_str()) {
            return Step::Reply(refuse(&action, Code::IncorrectAction, None));
        }
        let outcome = answer(client, session.vault(), &action, &inner, self.strict);
        self.known |= client.trust.is_some();
        match outcome {
            Outcome::Done(done) => Step::Reply(finish(client, &action, &reply, done)),
            Outcome::Ask(prompt, pending) => Step::Ask(Box::new(Question {
                prompt,
                client: id.clone(),
                epoch: client.epoch,
                action,
                reply,
                hash: session
                    .vault()
                    .map(pairing::database_hash)
                    .unwrap_or_default(),
                pending,
            })),
        }
    }

    /// Finishes a request once the user has answered its question.
    pub fn resume<S: Seal>(
        &mut self,
        session: &mut Session<S>,
        question: Box<Question>,
        answer: Answer,
    ) -> Handled {
        let Question {
            client: id,
            epoch,
            action,
            reply,
            hash,
            pending,
            ..
        } = *question;
        let Some(client) = self.clients.get_mut(&id).filter(|c| c.epoch == epoch) else {
            return refuse(&action, Code::CannotDecrypt, None);
        };
        let done = match session.vault() {
            None => Err((Code::DatabaseNotOpened, None)),
            // Another vault was opened while the prompt was up.
            Some(vault) if pairing::database_hash(vault) != hash => {
                Err((Code::AssociationFailed, None))
            }
            Some(_) => match pending {
                Pending::Pair { id_key } => paired(client, session, answer, &id_key, &hash),
                Pending::Logins {
                    page,
                    mut allowed,
                    asked,
                } => {
                    let always = matches!(answer, Answer::Always);
                    if always || matches!(answer, Answer::Yes) {
                        allowed.extend(asked.iter().copied());
                    }
                    let done = logins(client, session.vault(), &page, &allowed, &hash);
                    // Remembered only once the logins went out, so a refused or emptied request
                    // leaves no rule behind.
                    match done {
                        Ok((bytes, _))
                            if always && allow::remember(session, page.host(), &asked).is_ok() =>
                        {
                            Ok((bytes, Effect::Changed))
                        }
                        other => other,
                    }
                }
                Pending::Totp { entry } => match answer {
                    Answer::Yes | Answer::Always => totp(client, session.vault(), entry),
                    _ => Err((
                        Code::NoValidUuid,
                        Some("Access to the one-time code was refused".into()),
                    )),
                },
            },
        };
        self.known |= client.trust.is_some();
        finish(client, &action, &reply, done)
    }

    fn exchange(&mut self, envelope: Envelope) -> Handled {
        let action = "change-public-keys";
        let key = envelope.public_key.as_deref().and_then(crypto::decode_key);
        let nonce = envelope.nonce.as_deref().map(crypto::decode_nonce);
        let (Some(key), Some(Ok(nonce)), Some(id)) = (key, nonce, envelope.client_id) else {
            return refuse(action, Code::CannotDecrypt, None);
        };
        // A browser that restarts may come back with the same id, so a new exchange replaces the
        // old one, trust included. Room for a new id is made from an untrusted one first.
        if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(&id) {
            let evicted = self
                .clients
                .iter()
                .find(|(_, c)| c.trust.is_none())
                .or_else(|| self.clients.iter().next())
                .map(|(id, _)| id.clone());
            if let Some(evicted) = evicted {
                self.clients.remove(&evicted);
            }
        }
        let host: SecretKey = crypto::generate_secret();
        let public = host.public_key();
        self.epochs += 1;
        self.clients.insert(
            id,
            Client {
                channel: Channel::new(&host, &key),
                key,
                epoch: self.epochs,
                trust: None,
                released: HashSet::new(),
            },
        );
        let mut body = serde_json::json!({
            "action": action,
            "nonce": crypto::encode(&crypto::increment(&nonce)),
            "publicKey": crypto::encode(public.as_bytes()),
            "success": "true",
            "version": VERSION,
        });
        // Tells Sennel's extension it reached Sennel rather than KeePassXC. KeePassXC-Browser's
        // replies stay exactly as KeePassXC's are.
        if self.strict {
            body["sennel"] = serde_json::json!(SENNEL_PROTOCOL);
        }
        Handled {
            reply: serde_json::to_vec(&body).unwrap_or_default(),
            effect: Effect::None,
        }
    }
}

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn answer(
    client: &mut Client,
    vault: Option<&Vault>,
    action: &str,
    inner: &Value,
    strict: bool,
) -> Outcome {
    if let Some((_, feature)) = NOT_YET.iter().find(|(a, _)| *a == action) {
        return Outcome::Done(Err((
            Code::IncorrectAction,
            Some(format!("{feature} is not available in Sennel yet")),
        )));
    }
    let Some(vault) = vault else {
        return Outcome::Done(Err((Code::DatabaseNotOpened, None)));
    };
    let hash = pairing::database_hash(vault);
    let done = match action {
        "get-databasehash" if strict && !client.trusted(vault) => {
            Err((Code::AssociationFailed, None))
        }
        "get-databasehash" => body(&serde_json::json!({ "hash": hash })),
        "test-associate" => {
            let (name, key) = (field(inner, "id"), field(inner, "key"));
            if !pairing::is_paired(vault, name, key) {
                return Outcome::Done(Err((Code::AssociationFailed, None)));
            }
            client.trust(name, key, &hash);
            body(&serde_json::json!({ "hash": hash, "id": name }))
        }
        "associate" => return associate(client, vault, inner),
        "get-logins" => return lookup(client, vault, inner, &hash),
        "get-totp" => return code(client, vault, field(inner, "uuid")),
        "lock-database" if client.trusted(vault) => {
            body(&serde_json::json!({})).map(|(bytes, _)| (bytes, Effect::Lock))
        }
        "lock-database" => Err((Code::AssociationFailed, None)),
        _ => Err((Code::IncorrectAction, None)),
    };
    Outcome::Done(done)
}

fn associate(client: &Client, vault: &Vault, inner: &Value) -> Outcome {
    // The session key in the message has to be this connection's, or the request was relayed.
    if crypto::decode_key(field(inner, "key")).as_ref() != Some(&client.key) {
        return Outcome::Done(Err((Code::AssociationFailed, None)));
    }
    let id_key = field(inner, "idKey");
    let Some(id_bytes) = crypto::decode_key(id_key) else {
        return Outcome::Done(Err((Code::AssociationFailed, None)));
    };
    if !vault.writable() {
        return Outcome::Done(Err((
            Code::AssociationFailed,
            Some("This vault's format is read-only in Sennel".into()),
        )));
    }
    Outcome::Ask(
        Prompt::Pair {
            fingerprint: pairing::fingerprint(id_bytes.as_bytes()),
        },
        Pending::Pair {
            id_key: id_key.to_string(),
        },
    )
}

fn paired<S: Seal>(
    client: &mut Client,
    session: &mut Session<S>,
    answer: Answer,
    id_key: &str,
    hash: &str,
) -> Done {
    let Answer::Named(name) = answer else {
        return Err((Code::AssociationFailed, Some("Pairing was refused".into())));
    };
    let name = name.trim();
    if name.is_empty() || session.vault().is_none_or(|v| pairing::name_taken(v, name)) {
        return Err((
            Code::AssociationFailed,
            Some("A browser is already paired under that name".into()),
        ));
    }
    if pairing::pair(session, name, id_key).is_err() {
        return Err((Code::AssociationFailed, None));
    }
    client.trust(name, id_key, hash);
    body(&serde_json::json!({ "hash": hash, "id": name }))
        .map(|(bytes, _)| (bytes, Effect::Changed))
}

fn lookup(client: &mut Client, vault: &Vault, inner: &Value, hash: &str) -> Outcome {
    let proved = inner
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| {
            keys.iter().find_map(|k| {
                let (name, key) = (field(k, "id"), field(k, "key"));
                pairing::is_paired(vault, name, key).then_some((name, key))
            })
        });
    let Some((name, key)) = proved else {
        return Outcome::Done(Err((Code::AssociationFailed, None)));
    };
    client.trust(name, key, hash);
    let Some(page) = Page::parse(field(inner, "url")) else {
        return Outcome::Done(Err((Code::NoLogins, None)));
    };
    let mut allowed = Vec::new();
    let mut asked = Vec::new();
    let mut titles = Vec::new();
    let always = allow::for_host(vault, page.host());
    for entry in candidates(vault, &page) {
        let remembered = match matching::remembered(&entry, &page) {
            Remembered::Unknown if always.contains(&entry.id()) => Remembered::Allowed,
            other => other,
        };
        match remembered {
            Remembered::Allowed => allowed.push(entry.id()),
            Remembered::Unknown => {
                asked.push(entry.id());
                titles.push(entry.get_title().unwrap_or("").to_string());
            }
            Remembered::Denied => {}
        }
    }
    if asked.is_empty() {
        return Outcome::Done(logins(client, Some(vault), &page, &allowed, hash));
    }
    Outcome::Ask(
        Prompt::Site {
            host: page.host().to_string(),
            titles,
        },
        Pending::Logins {
            page,
            allowed,
            asked,
        },
    )
}

// Entries a page may be offered: not in the bin (`entry_refs` leaves those out), not hidden from
// browsers, and with a URL for the page.
fn candidates<'v>(vault: &'v Vault, page: &Page) -> impl Iterator<Item = EntryRef<'v>> {
    vault
        .entry_refs()
        .into_iter()
        .filter(move |e| !matching::hidden(e) && matching::entry_matches(e, page))
}

// Builds the reply from entries chosen earlier, keeping only those that still qualify, since the
// vault may have changed while the user was asked.
fn logins(
    client: &mut Client,
    vault: Option<&Vault>,
    page: &Page,
    ids: &[EntryId],
    hash: &str,
) -> Done {
    let vault = vault.ok_or((Code::DatabaseNotOpened, None))?;
    if !client.trusted(vault) {
        return Err((Code::AssociationFailed, None));
    }
    let chosen: Vec<EntryRef<'_>> = candidates(vault, page)
        .filter(|e| ids.contains(&e.id()) && matching::remembered(e, page) != Remembered::Denied)
        .collect();
    // Resolved field references live here until the reply is written, then are wiped.
    let mut values: Vec<(Zeroizing<String>, Zeroizing<String>, &EntryRef<'_>)> = Vec::new();
    for entry in &chosen {
        let (Ok(login), Ok(password)) = (
            vault::resolved(vault, entry, "UserName"),
            vault::resolved(vault, entry, "Password"),
        ) else {
            continue;
        };
        values.push((login, password, entry));
    }
    if values.is_empty() {
        return Err((Code::NoLogins, None));
    }
    let groups: Vec<String> = values
        .iter()
        .map(|(_, _, e)| e.parent().name.clone())
        .collect();
    let entries: Vec<Login<'_>> = values
        .iter()
        .zip(&groups)
        .map(|((login, password, entry), group)| Login {
            group,
            login,
            name: entry.get_title().unwrap_or(""),
            password,
            string_fields: [],
            uuid: entry.id().uuid().simple().to_string(),
            expired: vault::expired(entry).then_some("true"),
        })
        .collect();
    client
        .released
        .extend(values.iter().map(|(_, _, e)| e.id()));
    #[derive(Serialize)]
    struct Logins<'a> {
        count: usize,
        entries: &'a [Login<'a>],
        hash: &'a str,
        id: &'static str,
    }
    body(&Logins {
        count: entries.len(),
        entries: &entries,
        hash,
        id: "",
    })
}

fn code(client: &Client, vault: &Vault, uuid: &str) -> Outcome {
    if !client.trusted(vault) {
        return Outcome::Done(Err((Code::AssociationFailed, None)));
    }
    let Some(entry) = released(client, vault, uuid) else {
        return Outcome::Done(Err((Code::NoValidUuid, None)));
    };
    if !vault::has_otp(&entry) {
        return Outcome::Done(body(&serde_json::json!({ "totp": "" })));
    }
    Outcome::Ask(
        Prompt::Totp {
            title: entry.get_title().unwrap_or("").to_string(),
        },
        Pending::Totp { entry: entry.id() },
    )
}

// Only an entry this connection was already given for a page, and one still fit to give.
fn released<'v>(client: &Client, vault: &'v Vault, uuid: &str) -> Option<EntryRef<'v>> {
    let id = client
        .released
        .iter()
        .find(|id| id.uuid().simple().to_string().eq_ignore_ascii_case(uuid))?;
    let entry = vault.get_entry(id)?;
    (!vault.is_recycled(id) && !matching::hidden(&entry)).then_some(entry)
}

fn totp(client: &Client, vault: Option<&Vault>, entry: EntryId) -> Done {
    let vault = vault.ok_or((Code::DatabaseNotOpened, None))?;
    if !client.trusted(vault) {
        return Err((Code::AssociationFailed, None));
    }
    let uuid = entry.uuid().simple().to_string();
    let entry = released(client, vault, &uuid).ok_or((Code::NoValidUuid, None))?;
    let code = Zeroizing::new(
        vault::totp_now(&entry)
            .map(|(code, _)| code)
            .unwrap_or_default(),
    );
    #[derive(Serialize)]
    struct Totp<'a> {
        totp: &'a str,
    }
    body(&Totp { totp: &code })
}

// The reply body before `success`, `version` and `nonce` are added, written into wiped memory.
fn body(value: &impl Serialize) -> Done {
    let mut out = WipedBytes::with_capacity(256);
    serde_json::to_writer(&mut out, value).map_err(|_| (Code::CannotDecrypt, None))?;
    Ok((out, Effect::None))
}

fn finish(client: &mut Client, action: &str, nonce: &Nonce, done: Done) -> Handled {
    match done {
        Ok((body, effect)) => match seal(client, action, nonce, body) {
            Some(reply) => Handled { reply, effect },
            None => refuse(action, Code::CannotDecrypt, None),
        },
        Err((code, text)) => refuse(action, code, text.as_deref()),
    }
}

fn seal(client: &mut Client, action: &str, nonce: &Nonce, body: WipedBytes) -> Option<Vec<u8>> {
    let encoded = crypto::encode(nonce);
    let tail = format!(",\"nonce\":\"{encoded}\",\"success\":\"true\",\"version\":\"{VERSION}\"}}");
    // Splices the common fields into the object `body` wrote, so no secret passes through a Value.
    let mut plain = WipedBytes::with_capacity(body.len() + tail.len());
    let open = body.strip_suffix(b"}")?;
    plain.extend_from_slice(open);
    if open.len() == 1 {
        plain.extend_from_slice(&tail.as_bytes()[1..]);
    } else {
        plain.extend_from_slice(tail.as_bytes());
    }
    let cipher = client.channel.seal(nonce, &plain).ok()?;
    let reply = serde_json::json!({
        "action": action,
        "message": crypto::encode(&cipher),
        "nonce": encoded,
    });
    serde_json::to_vec(&reply).ok()
}

fn refuse(action: &str, code: Code, text: Option<&str>) -> Handled {
    let body = serde_json::json!({
        "action": action,
        "error": text.unwrap_or(code.text()),
        "errorCode": (code as u8).to_string(),
    });
    Handled {
        reply: serde_json::to_vec(&body).unwrap_or_default(),
        effect: Effect::None,
    }
}
