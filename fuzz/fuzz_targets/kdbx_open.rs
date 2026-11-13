#![no_main]

use std::io::Cursor;

use keepass::DatabaseKey;
use libfuzzer_sys::fuzz_target;
use sennel_core::kdfcap;
use sennel_core::vault::read_database;

// Within `kdfcap`'s limits a flipped byte can still ask for seconds of work, hiding real hangs.
fn too_slow_to_fuzz(file: &[u8]) -> bool {
    let w = kdfcap::work(file);
    w.aes_rounds.is_some_and(|r| r > 100_000)
        || w.argon2_memory.is_some_and(|m| m > 16 << 20)
        || w.argon2_passes.is_some_and(|p| p > 10)
}

// The fixtures' password, so the unmutated seeds parse all the way through. A mutated file fails its
// header hash or HMAC before the inner XML, and keepass does not expose that parser to call directly.
// `read_database` turns keepass's panics into errors, so this finds hangs and memory errors, not those.
fuzz_target!(|file: &[u8]| {
    if too_slow_to_fuzz(file) {
        return;
    }
    let key = DatabaseKey::new().with_password("sennel-fixture");
    let _ = read_database(&mut Cursor::new(file), key);
});
