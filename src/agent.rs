// ssh-agent integration: reads the KeeAgent settings KeePassXC stores beside an SSH key, and hands
// that key to the running agent. The key goes straight from the vault's memory to the agent's
// socket; it is never written to disk, and every buffer that held it is wiped.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use keepass::db::EntryId;
use ssh_key::{PrivateKey, private::KeypairData};
use zeroize::Zeroizing;

use crate::vault::{EntryExt, Vault};

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const REMOVE_IDENTITY: u8 = 18;
const ADD_ID_CONSTRAINED: u8 = 25;
const SUCCESS: u8 = 6;
const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_CONFIRM: u8 = 2;
// No agent answer is this large, and a hostile socket should not make us allocate it.
const MAX_REPLY: usize = 1 << 20;

/// The attachment KeePassXC and KeeAgent keep an entry's SSH settings in.
pub const SETTINGS: &str = "KeeAgent.settings";

pub struct Agent {
    stream: UnixStream,
}

impl Agent {
    pub fn connect() -> Result<Self, String> {
        let path = std::env::var_os("SSH_AUTH_SOCK")
            .filter(|p| !p.is_empty())
            .ok_or("SSH_AUTH_SOCK is not set · start ssh-agent first")?;
        Self::connect_to(Path::new(&path))
    }

    pub fn connect_to(path: &Path) -> Result<Self, String> {
        let stream = UnixStream::connect(path)
            .map_err(|e| format!("cannot reach the agent at {} · {e}", path.display()))?;
        // A confirm constraint waits on a person, so the wait is long but not endless.
        let wait = Some(Duration::from_secs(30));
        let _ = stream.set_read_timeout(wait);
        let _ = stream.set_write_timeout(wait);
        Ok(Agent { stream })
    }

    fn call(&mut self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let io = |e: std::io::Error| format!("ssh-agent: {e}");
        let mut message = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
        message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        message.extend_from_slice(payload);
        self.stream.write_all(&message).map_err(io)?;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).map_err(io)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_REPLY {
            return Err("ssh-agent sent a reply that is not one".to_string());
        }
        let mut reply = Zeroizing::new(vec![0u8; len]);
        self.stream.read_exact(&mut reply).map_err(io)?;
        Ok(reply)
    }

    fn expect_success(reply: &[u8], what: &str) -> Result<(), String> {
        match reply.first() {
            Some(&SUCCESS) => Ok(()),
            _ => Err(format!("ssh-agent refused to {what}")),
        }
    }

    /// Hands the key to the agent. `lifetime` makes the agent forget it by itself.
    pub fn add(&mut self, key: &PrivateKey, lifetime: Option<u32>, confirm: bool) -> Result<(), String> {
        let payload = add_message(key, lifetime, confirm)?;
        let reply = self.call(&payload)?;
        Self::expect_success(&reply, "take the key")
    }

    /// Takes the key out again, by its public half.
    pub fn remove(&mut self, blob: &[u8]) -> Result<(), String> {
        let mut payload = vec![REMOVE_IDENTITY];
        put_string(&mut payload, blob);
        let reply = self.call(&payload)?;
        Self::expect_success(&reply, "remove the key")
    }

    /// How many keys the agent holds. Also the cheapest proof that it answers.
    pub fn count(&mut self) -> Result<usize, String> {
        let reply = self.call(&[REQUEST_IDENTITIES])?;
        match reply.as_slice() {
            [IDENTITIES_ANSWER, n @ ..] if n.len() >= 4 => {
                Ok(u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize)
            }
            _ => Err("ssh-agent did not list its keys".to_string()),
        }
    }
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

// An unsigned big-endian number as the agent wants it: no leading zeros, one back in if the top bit is set.
fn put_mpint(out: &mut Vec<u8>, be: &[u8]) {
    let be = &be[be.iter().take_while(|b| **b == 0).count()..];
    if be.first().is_some_and(|b| b & 0x80 != 0) {
        put_u32(out, be.len() as u32 + 1);
        out.push(0);
    } else {
        put_u32(out, be.len() as u32);
    }
    out.extend_from_slice(be);
}

// SSH2_AGENTC_ADD_ID_CONSTRAINED: the key type, its private fields, a comment, then constraints.
fn add_message(
    key: &PrivateKey,
    lifetime: Option<u32>,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(vec![ADD_ID_CONSTRAINED]);
    put_string(&mut out, key.algorithm().as_str().as_bytes());
    match key.key_data() {
        KeypairData::Ed25519(pair) => {
            put_string(&mut out, pair.public.as_ref());
            // Seed then public key, which is the 64 bytes the agent expects.
            put_string(&mut out, &pair.to_bytes());
        }
        KeypairData::Rsa(pair) => {
            for n in [&pair.public.n, &pair.public.e, &pair.private.d, &pair.private.iqmp, &pair.private.p, &pair.private.q] {
                put_string(&mut out, n.as_bytes());
            }
        }
        KeypairData::Ecdsa(pair) => {
            put_string(&mut out, pair.curve().as_str().as_bytes());
            put_string(&mut out, pair.public_key_bytes());
            put_mpint(&mut out, pair.private_key_bytes());
        }
        _ => return Err(format!("{} keys cannot be given to the agent", key.algorithm())),
    }
    put_string(&mut out, key.comment().as_bytes());
    if let Some(seconds) = lifetime {
        out.push(CONSTRAIN_LIFETIME);
        put_u32(&mut out, seconds);
    }
    if confirm {
        out.push(CONSTRAIN_CONFIRM);
    }
    Ok(out)
}

/// What an entry's `KeeAgent.settings` attachment says to do with its key.
#[derive(Debug, PartialEq, Eq)]
pub struct Settings {
    pub allow: bool,
    pub add_at_open: bool,
    pub remove_at_close: bool,
    pub confirm: bool,
    pub lifetime: Option<u32>,
    /// The attachment holding the key. `None` when the settings point at a file on disk instead.
    pub attachment: Option<String>,
}

pub fn parse_settings(bytes: &[u8]) -> Option<Settings> {
    let xml = decode_text(bytes)?;
    let tag = |name: &str| -> Option<String> {
        let open = format!("<{name}");
        let at = xml.find(&open)? + open.len();
        let rest = &xml[at..];
        // `<Name/>` is an empty value, `<Name>text</Name>` is the text.
        if rest.starts_with('/') {
            return Some(String::new());
        }
        let rest = rest.strip_prefix('>')?;
        Some(rest[..rest.find("</")?].trim().to_string())
    };
    let flag = |name: &str| tag(name).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    xml.contains("<EntrySettings").then_some(())?;
    let lifetime = flag("UseLifetimeConstraintWhenAdding")
        .then(|| tag("LifetimeConstraintDuration")?.parse().ok())
        .flatten();
    let in_attachment = tag("SelectedType").is_some_and(|t| t.eq_ignore_ascii_case("attachment"));
    Some(Settings {
        allow: flag("AllowUseOfSshKey"),
        add_at_open: flag("AddAtDatabaseOpen"),
        remove_at_close: flag("RemoveAtDatabaseClose"),
        confirm: flag("UseConfirmConstraintWhenAdding"),
        lifetime,
        attachment: tag("AttachmentName").filter(|n| in_attachment && !n.is_empty()),
    })
}

// KeeAgent writes UTF-16 with a byte order mark; KeePassXC writes UTF-8.
fn decode_text(bytes: &[u8]) -> Option<String> {
    let units = |pairs: Vec<u16>| String::from_utf16(&pairs).ok();
    match bytes {
        [0xff, 0xfe, rest @ ..] => units(rest.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()),
        [0xfe, 0xff, rest @ ..] => units(rest.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()),
        [0xef, 0xbb, 0xbf, rest @ ..] => String::from_utf8(rest.to_vec()).ok(),
        _ => String::from_utf8(bytes.to_vec()).ok(),
    }
}

/// A key now in the agent, remembered so it can be taken out again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub blob: Vec<u8>,
    pub label: String,
    pub remove_at_close: bool,
}

#[derive(Default)]
pub struct Outcome {
    pub added: Vec<Loaded>,
    pub problems: Vec<String>,
}

/* The key in one attachment of one entry, decrypted with the entry's password and
   given to the agent. The longest the agent may keep it is `max_lifetime`, or the
   entry's own shorter one: a crash then cannot leave it there for good. */
pub fn add_entry_key(
    agent: &mut Agent,
    vault: &Vault,
    id: &EntryId,
    attachment: &str,
    settings: Option<&Settings>,
    max_lifetime: u32,
) -> Result<Loaded, String> {
    let entry = vault.get_entry(id).ok_or("the entry is gone")?;
    let title = entry.title().to_string();
    let bytes = vault.attachment_bytes(id, attachment).ok_or_else(|| format!("{title}: no attachment named {attachment}"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{title}: {attachment} is not a text key file"))?;
    let key = PrivateKey::from_openssh(text).map_err(|_| {
        format!("{title}: {attachment} is not an OpenSSH private key (PuTTY and old PEM keys are not supported)")
    })?;
    let key = if key.is_encrypted() {
        key.decrypt(entry.password()).map_err(|why| match why {
            // ssh-key 0.6.7 cannot read some valid ECDSA keys (a short private scalar), which is not a wrong password.
            ssh_key::Error::Encoding(_) => {
                format!("{title}: {attachment} is a key the library cannot read (some ECDSA keys) · try ed25519 or RSA")
            }
            _ => format!("{title}: the entry's password does not open {attachment}"),
        })?
    } else {
        key
    };
    let lifetime = settings.and_then(|s| s.lifetime).map_or(max_lifetime, |own| own.min(max_lifetime));
    let confirm = settings.is_some_and(|s| s.confirm);
    agent.add(&key, Some(lifetime), confirm).map_err(|e| format!("{title}: {e}"))?;
    let blob = key.public_key().to_bytes().map_err(|e| format!("{title}: {e}"))?;
    Ok(Loaded {
        blob,
        label: title,
        remove_at_close: settings.is_none_or(|s| s.remove_at_close),
    })
}

/// Every key the vault's KeeAgent settings ask to be added when it opens.
pub fn load_vault(agent: &mut Agent, vault: &Vault, max_lifetime: u32) -> Outcome {
    let mut outcome = Outcome::default();
    for entry in vault.entry_refs() {
        let id = entry.id();
        let Some(raw) = vault.attachment_bytes(&id, SETTINGS) else {
            continue;
        };
        let Some(settings) = parse_settings(&raw) else {
            outcome.problems.push(format!("{}: unreadable {SETTINGS}", entry.title()));
            continue;
        };
        if !settings.allow || !settings.add_at_open {
            continue;
        }
        let Some(name) = settings.attachment.clone() else {
            outcome.problems.push(format!("{}: the key is a file on disk, and only attachments are read", entry.title()));
            continue;
        };
        match add_entry_key(agent, vault, &id, &name, Some(&settings), max_lifetime) {
            Ok(loaded) => outcome.added.push(loaded),
            Err(why) => outcome.problems.push(why),
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEEPASSXC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<EntrySettings>
 <AllowUseOfSshKey>true</AllowUseOfSshKey>
 <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
 <RemoveAtDatabaseClose>false</RemoveAtDatabaseClose>
 <UseConfirmConstraintWhenAdding>true</UseConfirmConstraintWhenAdding>
 <UseLifetimeConstraintWhenAdding>true</UseLifetimeConstraintWhenAdding>
 <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
 <Location>
  <SelectedType>attachment</SelectedType>
  <AttachmentName>id_ed25519</AttachmentName>
  <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
  <FileName/>
 </Location>
</EntrySettings>"#;

    #[test]
    fn keepassxc_settings_are_read() {
        let s = parse_settings(KEEPASSXC.as_bytes()).unwrap();
        assert_eq!(
            s,
            Settings {
                allow: true,
                add_at_open: true,
                remove_at_close: false,
                confirm: true,
                lifetime: Some(600),
                attachment: Some("id_ed25519".to_string()),
            }
        );
    }

    #[test]
    fn keeagent_writes_utf16_and_a_file_location_is_not_an_attachment() {
        let xml = KEEPASSXC.replace("attachment</Sel", "file</Sel").replace("<FileName/>", "<FileName>/k</FileName>");
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let s = parse_settings(&utf16).unwrap();
        assert_eq!(s.attachment, None);
        assert!(s.allow);
    }

    #[test]
    fn lifetime_needs_its_switch_and_nonsense_is_not_settings() {
        let off = KEEPASSXC.replace("<UseLifetimeConstraintWhenAdding>true", "<UseLifetimeConstraintWhenAdding>false");
        assert_eq!(parse_settings(off.as_bytes()).unwrap().lifetime, None);
        assert_eq!(parse_settings(b"just text"), None);
        assert_eq!(parse_settings(&[0xff, 0xfe, 0x00, 0xd8]), None, "a lone surrogate");
        assert!(parse_settings(b"<EntrySettings></EntrySettings>").is_some_and(|s| !s.allow));
    }

    #[test]
    fn mpints_drop_leading_zeros_and_keep_numbers_positive() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0, 0, 0x7f, 1]);
        assert_eq!(out, [0, 0, 0, 2, 0x7f, 1]);
        let mut out = Vec::new();
        put_mpint(&mut out, &[0, 0x80, 1]);
        assert_eq!(out, [0, 0, 0, 3, 0, 0x80, 1]);
        let mut out = Vec::new();
        put_mpint(&mut out, &[0, 0]);
        assert_eq!(out, [0, 0, 0, 0]);
    }

    /* The one check that the wire format is right: a real ssh-agent on a private socket takes every
       key type, lists it by fingerprint, honours the remove, and obeys a vault's KeeAgent entry.
       Does nothing on a machine without OpenSSH's tools. */
    #[test]
    fn a_real_agent_takes_every_key_type_and_a_vaults_keeagent_entry() {
        use std::process::{Command, Stdio};
        for tool in ["ssh-agent", "ssh-add", "ssh-keygen"] {
            if Command::new(tool).arg("-?").output().is_err() {
                eprintln!("no {tool} here · skipped");
                return;
            }
        }
        // Short and under /tmp: a unix socket path may not pass about a hundred bytes.
        let dir = std::path::PathBuf::from(format!("/tmp/sennel-ag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("a.sock");
        let mut child = Command::new("ssh-agent")
            .args(["-D", "-a"]).arg(&sock).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let listing = || {
            let out = Command::new("ssh-add").arg("-l").env("SSH_AUTH_SOCK", &sock).output().unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        let make = |kind: &str, bits: &str, pass: &str| {
            let path = dir.join(format!("k_{kind}{bits}"));
            let _ = std::fs::remove_file(&path);
            let ok = Command::new("ssh-keygen")
                .args(["-q", "-t", kind, "-b", bits, "-N", pass, "-C", "test-comment", "-f"])
                .arg(&path).status().unwrap().success();
            assert!(ok);
            std::fs::read_to_string(path).unwrap()
        };

        let mut client = Agent::connect_to(&sock).unwrap();
        for (kind, bits) in [("ed25519", "256"), ("rsa", "2048"), ("ecdsa", "256"), ("ecdsa", "384"), ("ecdsa", "521")] {
            // ssh-key 0.6.7 cannot read about 1 in 20 ECDSA keys, so make another until one reads.
            let key = (0..30)
                .find_map(|_| PrivateKey::from_openssh(make(kind, bits, "pass phrase")).ok()?.decrypt("pass phrase").ok())
                .expect("no key of this type could be read");
            client.add(&key, Some(60), false).unwrap();
            let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
            assert!(listing().contains(&fingerprint), "{kind} {bits} is not in:\n{}", listing());
            client.remove(&key.public_key().to_bytes().unwrap()).unwrap();
            assert!(!listing().contains(&fingerprint), "{kind} {bits} was not removed");
        }
        assert_eq!(client.count().unwrap(), 0);

        // A vault entry the way KeePassXC stores it: key attachment, settings, passphrase = password.
        let mut vault = Vault::new();
        let root = vault.root_id();
        let id = vault.create_entry(&root, "deploy key", "git", "entry pw", "", "").unwrap();
        vault.add_attachment(&id, "id_ed25519", make("ed25519", "256", "entry pw").into_bytes()).unwrap();
        vault.add_attachment(&id, SETTINGS, KEEPASSXC.as_bytes().to_vec()).unwrap();
        let outcome = load_vault(&mut client, &vault, 3600);
        assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
        assert_eq!(outcome.added.len(), 1);
        assert!(!outcome.added[0].remove_at_close, "KEEPASSXC says to leave it");
        assert_eq!(client.count().unwrap(), 1);
        client.remove(&outcome.added[0].blob).unwrap();

        // The wrong passphrase is named, not added.
        vault.set_field(&id, "x", "y", false).unwrap();
        let bad = Vault::new();
        assert!(load_vault(&mut client, &bad, 3600).added.is_empty());

        // The wrong passphrase is named as such and nothing is added.
        let mut wrong = Vault::new();
        let root = wrong.root_id();
        let entry = wrong.create_entry(&root, "locked", "git", "not the passphrase", "", "").unwrap();
        wrong.add_attachment(&entry, "id_ed25519", make("ed25519", "256", "entry pw").into_bytes()).unwrap();
        wrong.add_attachment(&entry, SETTINGS, KEEPASSXC.as_bytes().to_vec()).unwrap();
        let outcome = load_vault(&mut client, &wrong, 3600);
        assert!(outcome.added.is_empty() && outcome.problems[0].contains("does not open id_ed25519"), "{:?}", outcome.problems);
        assert_eq!(client.count().unwrap(), 0);

        assert!(Agent::connect_to(&dir.join("none.sock")).err().unwrap().contains("cannot reach the agent"));
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
