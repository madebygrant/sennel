#![no_main]

use std::io::Cursor;

use keepass::DatabaseKey;
use libfuzzer_sys::fuzz_target;
use sennel_core::vault::read_database;

// The fixtures' password, so the unmutated seeds parse all the way through. A mutated file fails its
// header hash or HMAC before the inner XML, and keepass does not expose that parser to call directly.
// `read_database` turns keepass's panics into errors, so this finds hangs and memory errors, not those.
// A KDBX 3 file sets its own AES rounds and nothing checks them before they are spent, so one flipped
// byte is minutes of work. Skipped because that cost is the format's, and it hides real hangs.
fn asks_for_too_many_rounds(file: &[u8]) -> bool {
    const MAX_ROUNDS: u64 = 10_000_000;
    if file.get(10..12) != Some(&[3, 0]) {
        return false;
    }
    let mut at = 12;
    while let Some(&[id, low, high]) = file.get(at..at + 3).and_then(|f| f.first_chunk::<3>()) {
        let end = at + 3 + usize::from(u16::from_le_bytes([low, high]));
        let rounds = file.get(at + 3..end).and_then(|v| v.first_chunk::<8>());
        if id == 6 && rounds.is_some_and(|r| u64::from_le_bytes(*r) > MAX_ROUNDS) {
            return true;
        }
        at = end;
    }
    false
}

fuzz_target!(|file: &[u8]| {
    if asks_for_too_many_rounds(file) {
        return;
    }
    let key = DatabaseKey::new().with_password("sennel-fixture");
    let _ = read_database(&mut Cursor::new(file), key);
});
