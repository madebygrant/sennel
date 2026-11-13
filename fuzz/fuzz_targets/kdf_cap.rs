#![no_main]

use libfuzzer_sys::fuzz_target;

// The header reader runs on every file before anything else touches it, so it must never panic.
fuzz_target!(|file: &[u8]| {
    let _ = sennel_core::kdfcap::refusal(file);
});
