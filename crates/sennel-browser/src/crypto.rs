use std::collections::{HashSet, VecDeque};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

// How many recent nonces a channel remembers. An older replay gets through, but its reply is sealed
// to the client's key, so whoever replays it reads nothing.
const REMEMBERED: usize = 4096;

pub type Nonce = [u8; NONCE_LEN];

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    BadNonce,
    Replayed,
    Undecryptable,
}

/// One side of an encrypted session: our secret key against the other side's public key.
pub struct Channel {
    sealed: SalsaBox,
    // Ours and theirs: both directions share one key, so a nonce we replied with is spent too.
    used: HashSet<Nonce>,
    order: VecDeque<Nonce>,
}

impl Channel {
    pub fn new(ours: &SecretKey, theirs: &PublicKey) -> Self {
        Channel {
            sealed: SalsaBox::new(theirs, ours),
            used: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    pub fn spent(&self, nonce: &Nonce) -> bool {
        self.used.contains(nonce)
    }

    fn spend(&mut self, nonce: &Nonce) -> bool {
        if !self.used.insert(*nonce) {
            return false;
        }
        self.order.push_back(*nonce);
        if self.order.len() > REMEMBERED
            && let Some(oldest) = self.order.pop_front()
        {
            self.used.remove(&oldest);
        }
        true
    }

    pub fn open(
        &mut self,
        nonce: &Nonce,
        cipher: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if self.spent(nonce) {
            return Err(CryptoError::Replayed);
        }
        let plain = self
            .sealed
            .decrypt(nonce.into(), cipher)
            .map_err(|_| CryptoError::Undecryptable)?;
        // Only an authentic message burns the nonce, so garbage cannot fill the set.
        self.spend(nonce);
        Ok(Zeroizing::new(plain))
    }

    pub fn seal(&mut self, nonce: &Nonce, plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.spend(nonce) {
            return Err(CryptoError::Replayed);
        }
        self.sealed
            .encrypt(nonce.into(), plain)
            .map_err(|_| CryptoError::Undecryptable)
    }
}

pub fn generate_secret() -> SecretKey {
    SecretKey::generate(&mut OsRng)
}

pub fn random_nonce() -> Nonce {
    SalsaBox::generate_nonce(&mut OsRng).into()
}

/// The nonce a reply carries: the request's, plus one, read as a little-endian number.
pub fn increment(nonce: &Nonce) -> Nonce {
    let mut next = *nonce;
    for byte in next.iter_mut() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            break;
        }
    }
    next
}

pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

pub fn decode_nonce(text: &str) -> Result<Nonce, CryptoError> {
    decode(text)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(CryptoError::BadNonce)
}

pub fn decode_key(text: &str) -> Option<PublicKey> {
    let bytes: [u8; KEY_LEN] = decode(text)?.try_into().ok()?;
    Some(PublicKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Channel, Channel) {
        let (a, b) = (generate_secret(), generate_secret());
        (
            Channel::new(&a, &b.public_key()),
            Channel::new(&b, &a.public_key()),
        )
    }

    #[test]
    fn a_message_sealed_on_one_side_opens_on_the_other() {
        let (mut client, mut host) = pair();
        let nonce = random_nonce();
        let cipher = client.seal(&nonce, b"hello").unwrap();
        assert_eq!(&**host.open(&nonce, &cipher).unwrap(), b"hello");
    }

    #[test]
    fn a_replayed_nonce_is_refused_even_with_a_valid_message() {
        let (mut client, mut host) = pair();
        let nonce = random_nonce();
        let cipher = client.seal(&nonce, b"one").unwrap();
        host.open(&nonce, &cipher).unwrap();
        assert_eq!(host.open(&nonce, &cipher), Err(CryptoError::Replayed));
    }

    #[test]
    fn a_nonce_the_host_replied_with_is_refused_from_the_client() {
        let (_, mut host) = pair();
        let nonce = random_nonce();
        host.seal(&nonce, b"reply").unwrap();
        assert_eq!(host.open(&nonce, b"anything"), Err(CryptoError::Replayed));
        assert_eq!(host.seal(&nonce, b"again"), Err(CryptoError::Replayed));
    }

    #[test]
    fn a_tampered_message_does_not_open_and_does_not_burn_the_nonce() {
        let (mut client, mut host) = pair();
        let nonce = random_nonce();
        let mut cipher = client.seal(&nonce, b"hello").unwrap();
        cipher[0] ^= 1;
        assert_eq!(host.open(&nonce, &cipher), Err(CryptoError::Undecryptable));
        cipher[0] ^= 1;
        assert!(host.open(&nonce, &cipher).is_ok());
    }

    #[test]
    fn a_long_session_keeps_working_and_remembers_only_recent_nonces() {
        let (mut client, mut host) = pair();
        let first = random_nonce();
        let cipher = client.seal(&first, b"x").unwrap();
        host.open(&first, &cipher).unwrap();
        for _ in 0..REMEMBERED {
            let nonce = random_nonce();
            let cipher = client.seal(&nonce, b"x").unwrap();
            host.open(&nonce, &cipher).unwrap();
        }
        assert_eq!(host.used.len(), REMEMBERED);
        assert!(!host.spent(&first));
    }

    #[test]
    fn increment_carries_from_the_first_byte() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 0xff;
        nonce[1] = 0x01;
        let next = increment(&nonce);
        assert_eq!((next[0], next[1]), (0x00, 0x02));
        assert_eq!(increment(&[0xff; NONCE_LEN]), [0u8; NONCE_LEN]);
    }
}
