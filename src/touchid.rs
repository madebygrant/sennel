// The master password sealed to a Secure Enclave key only a fingerprint can use.
// The key is never written to a keychain, so it dies with the process.

pub use imp::{Sealed, seal};
#[cfg(test)]
pub use imp::REFUSE;

/// Why a sealed password did not come back.
#[derive(Clone, Debug)]
pub enum Refused {
    /// Dismissed, or no sensor right now (a closed lid): the next try may work.
    Again(String),
    /// The key cannot be used again, such as after the enrolled fingers changed.
    Void(String),
}

#[cfg(all(target_os = "macos", not(test)))]
mod imp {
    use super::Refused;
    use security_framework::access_control::SecAccessControl;
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework_sys::access_control::{
        kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
    };
    use zeroize::Zeroizing;

    const SEAL: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

    pub struct Sealed {
        key: SecKey,
        blob: Vec<u8>,
    }

    // CurrentSet, not Any: adding or removing any finger voids the key.
    pub fn seal(secret: &[u8]) -> Result<Sealed, String> {
        let access = SecAccessControl::create_with_flags(
            kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
        )
        .map_err(|e| e.to_string())?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(access);
        let key = SecKey::new(&options).map_err(|e| e.to_string())?;
        let public = key.public_key().ok_or("the enclave gave no public key")?;
        let blob = public.encrypt_data(SEAL, secret).map_err(|e| e.to_string())?;
        Ok(Sealed { key, blob })
    }

    impl Sealed {
        // Blocks until the fingerprint is read or the prompt is dismissed.
        pub fn open(&self) -> Result<Zeroizing<Vec<u8>>, Refused> {
            self.key.decrypt_data(SEAL, &self.blob).map(Zeroizing::new).map_err(|e| {
                classify(&e.domain().to_string(), e.code(), e.to_string())
            })
        }
    }

    // Only errors known to pass are kept. Anything unknown drops the sealed
    // password, which costs one typed unlock rather than a dead prompt forever.
    fn classify(domain: &str, code: isize, text: String) -> Refused {
        match (domain, code) {
            ("NSOSStatusErrorDomain", -128) => Refused::Again("cancelled".into()),
            // LAError: user, fallback, system and app cancels.
            ("com.apple.LocalAuthentication", -2 | -3 | -4 | -9) => {
                Refused::Again("cancelled".into())
            }
            // No match, no sensor right now, locked out, no window, sensor unplugged.
            ("com.apple.LocalAuthentication", -1 | -6 | -8 | -1004 | -13) => Refused::Again(text),
            _ => Refused::Void(text),
        }
    }
}

#[cfg(all(not(target_os = "macos"), not(test)))]
mod imp {
    use super::Refused;
    use zeroize::Zeroizing;

    pub enum Sealed {}

    pub fn seal(_: &[u8]) -> Result<Sealed, String> {
        Err("Touch ID is macOS only".into())
    }

    impl Sealed {
        pub fn open(&self) -> Result<Zeroizing<Vec<u8>>, Refused> {
            match *self {}
        }
    }
}

#[cfg(test)]
mod imp {
    use super::Refused;
    use std::cell::RefCell;
    use zeroize::Zeroizing;

    thread_local! {
        pub static REFUSE: RefCell<Option<Refused>> = const { RefCell::new(None) };
    }

    pub struct Sealed(Zeroizing<Vec<u8>>);

    pub fn seal(secret: &[u8]) -> Result<Sealed, String> {
        Ok(Sealed(Zeroizing::new(secret.to_vec())))
    }

    impl Sealed {
        pub fn open(&self) -> Result<Zeroizing<Vec<u8>>, Refused> {
            match REFUSE.with_borrow(Clone::clone) {
                Some(refused) => Err(refused),
                None => Ok(self.0.clone()),
            }
        }
    }
}
