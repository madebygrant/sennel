// Stands in for the Secure Enclave key in this crate's tests. It lives here, under
// cfg(test), so no build of the binary can link a key that opens without a finger.

pub use sennel_core::touchid::Refused;

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
