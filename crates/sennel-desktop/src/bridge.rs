// Browsers reach the open vault through here: a socket the proxy connects to, one thread per
// connection, and the protocol server from sennel-browser. Questions go to native dialogs with the
// session released, so the idle lock and the window keep working while one is open.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sennel_browser::transport::{self, APP_HOST};
use sennel_browser::{Answer, Effect, Prompt, Server, Step, allow, pairing, registration};
use serde::Serialize;

use crate::desk::{Desk, Note, info, warn};

// Each connection is a thread; a browser opens one or two.
const MAX_CONNECTIONS: usize = 16;
// A proxy says hello at once, and a browser that stops reading must not stall the others.
const HELLO_WITHIN: Duration = Duration::from_secs(5);
const WRITE_WITHIN: Duration = Duration::from_secs(2);
// A locked vault brings the window forward for a paired browser at most this often.
const RAISE_EVERY: Duration = Duration::from_secs(30);

/// What the bridge needs from the window.
pub trait Ui: Send + Sync + 'static {
    /// Puts a question to the user in a native dialog and waits for the answer.
    fn ask(&self, prompt: &Prompt) -> Answer;
    /// Brings the window forward so the user can unlock.
    fn raise(&self);
    /// Status lines, and whether the vault locked.
    fn tell(&self, notes: Vec<Note>, locked: bool);
}

#[derive(Default)]
pub struct Bridge {
    conns: Mutex<HashMap<u64, Arc<Mutex<UnixStream>>>>,
    // Every connection with a thread, counted from accept, before any check.
    live: AtomicUsize,
    next: AtomicU64,
    raised: Mutex<Option<Instant>>,
    open: Mutex<Option<bool>>,
    // One dialog at a time, however many browsers ask.
    asking: Mutex<()>,
    // Why the socket is not there, for the settings screen.
    down: Mutex<Option<String>>,
}

fn held<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Bridge {
    /// Listens on `path` for proxies started from `exe`. A failure is kept for the settings screen.
    pub fn start(self: &Arc<Self>, desk: Arc<Desk>, ui: Arc<dyn Ui>, path: &Path, exe: PathBuf) {
        let listener = match transport::listen(path) {
            Ok(listener) => listener,
            Err(e) => {
                *held(&self.down) = Some(e.to_string());
                return;
            }
        };
        let bridge = Arc::clone(self);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                if bridge.live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    bridge.live.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let (bridge, desk, ui, exe) = (
                    Arc::clone(&bridge),
                    Arc::clone(&desk),
                    Arc::clone(&ui),
                    exe.clone(),
                );
                std::thread::spawn(move || {
                    bridge.serve(&desk, &*ui, stream, &exe);
                    bridge.live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }

    pub fn down(&self) -> Option<String> {
        held(&self.down).clone()
    }

    fn serve(&self, desk: &Desk, ui: &dyn Ui, stream: UnixStream, exe: &Path) {
        if !transport::peer_is(&stream, exe) {
            return;
        }
        let Ok(mut reader) = stream.try_clone() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(HELLO_WITHIN));
        let _ = stream.set_write_timeout(Some(WRITE_WITHIN));
        let Some(host) = transport::read_frame(&mut reader)
            .ok()
            .flatten()
            .and_then(|f| transport::read_hello(&f))
        else {
            return;
        };
        // After the hello a browser may sit idle for hours between requests.
        let _ = stream.set_read_timeout(None);
        let mut server = if host == APP_HOST {
            Server::strict()
        } else {
            Server::new()
        };
        let writer = Arc::new(Mutex::new(stream));
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        held(&self.conns).insert(id, Arc::clone(&writer));
        while let Ok(Some(frame)) = transport::read_frame(&mut reader) {
            // Only a lookup brings the window forward, not the extension's background checks.
            if server.known() && wants_logins(&frame) && !desk.session().is_open() {
                self.raise(ui);
            }
            // The session guard lives only for the call, never across a dialog.
            let step = server.handle(&desk.session(), &frame);
            let handled = match step {
                Step::Reply(handled) => handled,
                Step::Ask(question) => {
                    let answer = {
                        let _one = held(&self.asking);
                        ui.ask(&question.prompt)
                    };
                    server.resume(&mut desk.session(), question, answer)
                }
            };
            match handled.effect {
                Effect::None => {}
                Effect::Changed => {
                    let mut s = desk.session();
                    let notes = desk.saved(&mut s, info("browser access saved to the vault"));
                    drop(s);
                    ui.tell(notes, false);
                }
                Effect::Lock => {
                    let notes = desk.lock_for_browser();
                    // The lock is refused when it would lose unsaved work.
                    let open = desk.session().is_open();
                    ui.tell(notes, !open);
                    self.watch(open);
                }
            }
            if transport::write_frame(&mut *held(&writer), &handled.reply).is_err() {
                break;
            }
        }
        held(&self.conns).remove(&id);
    }

    fn raise(&self, ui: &dyn Ui) {
        let mut last = held(&self.raised);
        if last.is_some_and(|at| at.elapsed() < RAISE_EVERY) {
            return;
        }
        *last = Some(Instant::now());
        ui.raise();
    }

    /// Tells every connected browser when the vault locks or unlocks. Called on a timer and after a
    /// browser's own lock, so every way of locking is covered.
    pub fn watch(&self, open: bool) {
        let mut was = held(&self.open);
        if *was == Some(open) {
            return;
        }
        let first = was.is_none();
        *was = Some(open);
        drop(was);
        if first {
            return;
        }
        let notice = Server::notice(!open);
        // Copied out so no lock is held while writing; each write gives up after WRITE_WITHIN.
        let conns: Vec<_> = held(&self.conns).values().cloned().collect();
        for conn in conns {
            let _ = transport::write_frame(&mut *held(&conn), &notice);
        }
    }
}

fn wants_logins(frame: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Action<'a> {
        action: &'a str,
    }
    serde_json::from_slice::<Action<'_>>(frame).is_ok_and(|a| a.action == "get-logins")
}

/// The browsers part of the settings screen.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BrowserState {
    /// Installed browsers, and whether KeePassXC-Browser in each reaches Sennel now.
    pub takeover: Vec<(String, bool)>,
    /// Pairings in the open vault, by name. Empty while locked.
    pub paired: Vec<String>,
    /// Hosts with a remembered "always", and how many entries each may have.
    pub sites: Vec<(String, usize)>,
    pub locked: bool,
    pub down: Option<String>,
}

pub fn state(desk: &Desk, bridge: &Bridge, home: &Path, exe: &Path) -> BrowserState {
    let s = desk.session();
    let vault = s.vault();
    BrowserState {
        takeover: registration::taken_over(home, exe)
            .into_iter()
            .map(|(name, on)| (name.to_string(), on))
            .collect(),
        paired: vault
            .map(|v| pairing::pairings(v).into_iter().map(|p| p.name).collect())
            .unwrap_or_default(),
        sites: vault.map(allow::hosts).unwrap_or_default(),
        locked: vault.is_none(),
        down: bridge.down(),
    }
}

pub fn set_takeover(on: bool, home: &Path, exe: &Path, aside: &Path) -> Note {
    let done = if on {
        registration::take_over(home, exe, aside)
    } else {
        registration::give_back(home, aside)
    };
    match done {
        Ok(names) if names.is_empty() && on => warn("no supported browser is installed"),
        Ok(names) if names.is_empty() => info("KeePassXC-Browser was not set to Sennel"),
        Ok(names) if on => info(format!(
            "KeePassXC-Browser now reaches Sennel in {}",
            names.join(", ")
        )),
        Ok(names) => info(format!(
            "KeePassXC-Browser goes back to KeePassXC in {}",
            names.join(", ")
        )),
        Err(e) => warn(format!("browser registration not changed · {e}")),
    }
}

pub fn revoke(desk: &Desk, name: &str) -> Vec<Note> {
    let mut s = desk.session();
    match pairing::revoke(&mut s, name) {
        Ok(()) => desk.saved(
            &mut s,
            info(format!("{name} can no longer reach this vault")),
        ),
        Err(e) => vec![warn(format!("not removed · {e}"))],
    }
}

pub fn forget(desk: &Desk, host: &str) -> Vec<Note> {
    let mut s = desk.session();
    match allow::forget(&mut s, host) {
        Ok(()) => desk.saved(&mut s, info(format!("{host} will be asked about again"))),
        Err(e) => vec![warn(format!("not forgotten · {e}"))],
    }
}

// What a paired browser is called: its key's fingerprint, unique in practice and the same thing the
// dialog showed.
pub fn pairing_name(fingerprint: &str) -> String {
    format!("browser {}", fingerprint.replace(':', ""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sennel_browser::crypto::{self, Channel};
    use serde_json::{Value, json};

    struct Stub {
        asked: Mutex<Vec<String>>,
        told: Mutex<Vec<bool>>,
    }

    impl Ui for Stub {
        fn ask(&self, prompt: &Prompt) -> Answer {
            held(&self.asked).push(format!("{prompt:?}"));
            match prompt {
                Prompt::Pair { fingerprint } => Answer::Named(pairing_name(fingerprint)),
                _ => Answer::Yes,
            }
        }
        fn raise(&self) {}
        fn tell(&self, _: Vec<Note>, locked: bool) {
            held(&self.told).push(locked);
        }
    }

    // The proxy's side, over the real socket: the peer check passes because this test binary is
    // both ends.
    struct Client {
        socket: UnixStream,
        channel: Option<Channel>,
        secret: crypto_box::SecretKey,
        id: String,
    }

    impl Client {
        fn connect(path: &Path, host: &str) -> Client {
            let mut socket = UnixStream::connect(path).unwrap();
            transport::write_frame(&mut socket, &transport::hello(host)).unwrap();
            let secret = crypto::generate_secret();
            let id = crypto::encode(&crypto::random_nonce());
            let mut client = Client {
                socket,
                channel: None,
                secret,
                id,
            };
            let nonce = crypto::encode(&crypto::random_nonce());
            let public = crypto::encode(client.secret.public_key().as_bytes());
            let reply = client.raw(json!({"action": "change-public-keys", "publicKey": public, "nonce": nonce, "clientID": client.id}));
            let host = crypto::decode_key(reply["publicKey"].as_str().unwrap()).unwrap();
            client.channel = Some(Channel::new(&client.secret, &host));
            client
        }

        fn raw(&mut self, value: Value) -> Value {
            transport::write_frame(&mut self.socket, value.to_string().as_bytes()).unwrap();
            self.read()
        }

        fn read(&mut self) -> Value {
            let frame = transport::read_frame(&mut self.socket).unwrap().unwrap();
            serde_json::from_slice(&frame).unwrap()
        }

        fn send(&mut self, inner: Value) -> Value {
            let nonce = crypto::random_nonce();
            let cipher = self
                .channel
                .as_mut()
                .unwrap()
                .seal(&nonce, inner.to_string().as_bytes())
                .unwrap();
            let reply = self.raw(json!({"action": inner["action"], "message": crypto::encode(&cipher), "nonce": crypto::encode(&nonce), "clientID": self.id}));
            let Some(message) = reply["message"].as_str() else {
                return reply;
            };
            let plain = self
                .channel
                .as_mut()
                .unwrap()
                .open(
                    &crypto::increment(&nonce),
                    &crypto::decode(message).unwrap(),
                )
                .unwrap();
            serde_json::from_slice(&plain).unwrap()
        }
    }

    #[test]
    fn a_browser_pairs_fills_and_hears_the_vault_lock_over_the_socket() {
        let dir = std::env::temp_dir().join(format!("sennel-bridge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("run").join("b.sock");
        let mut vault = sennel_core::vault::Vault::new();
        let root = vault.root_id();
        vault
            .create_entry(&root, "site", "ada", "hunter2", "https://site.example", "")
            .unwrap();
        let desk = Arc::new(crate::desk::open_with(vault));
        let stub = Arc::new(Stub {
            asked: Mutex::default(),
            told: Mutex::default(),
        });
        let bridge = Arc::new(Bridge::default());
        bridge.start(
            Arc::clone(&desk),
            Arc::clone(&stub) as Arc<dyn Ui>,
            &path,
            std::env::current_exe().unwrap(),
        );
        bridge.watch(true);

        // Sennel's own host keeps the hash from a browser that has not paired.
        let mut strict = Client::connect(&path, APP_HOST);
        let reply = strict.send(json!({"action": "get-databasehash"}));
        assert_eq!(reply["errorCode"], "8");

        let mut browser = Client::connect(&path, transport::KEEPASSXC_HOST);
        assert!(browser.send(json!({"action": "get-databasehash"}))["hash"].is_string());
        let identity = crypto::encode(crypto::generate_secret().public_key().as_bytes());
        let public = crypto::encode(browser.secret.public_key().as_bytes());
        let reply = browser.send(json!({"action": "associate", "key": public, "idKey": identity}));
        let name = reply["id"].as_str().unwrap().to_string();
        assert!(name.starts_with("browser "));
        assert_eq!(
            held(&stub.told).as_slice(),
            &[false],
            "the pairing was saved"
        );

        let keys = json!([{ "id": name, "key": identity }]);
        let reply = browser
            .send(json!({"action": "get-logins", "url": "https://site.example/", "keys": keys}));
        assert_eq!(reply["entries"][0]["password"], "hunter2");
        assert_eq!(held(&stub.asked).len(), 2);

        // A lock from anywhere reaches every connected browser.
        desk.lock_for_browser();
        bridge.watch(false);
        assert_eq!(browser.read(), json!({"action": "database-locked"}));
        assert_eq!(strict.read(), json!({"action": "database-locked"}));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_browser_cannot_lock_away_changes_that_cannot_be_saved() {
        // A vault with no file yet cannot be saved, so a lock would lose its changes.
        let desk = crate::desk::open_with(sennel_core::vault::Vault::new());
        desk.session().mark_dirty();
        let notes = desk.lock_for_browser();
        assert!(desk.session().is_open());
        assert!(notes[0].text.contains("not locked"));
    }
}
