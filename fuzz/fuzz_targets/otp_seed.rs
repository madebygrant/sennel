#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = sennel_core::qr::seed(text, "title", "username");
});
