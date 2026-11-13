#![no_main]

use libfuzzer_sys::fuzz_target;

// A stored `otp` never passes the checks a typed seed gets, so the code is also computed straight
// from the text, the way the entry pane does on every frame.
fuzz_target!(|text: &str| {
    if let Ok(url) = sennel_core::qr::seed(text, "title", "username") {
        let _ = sennel_core::vault::totp_code_of(&url);
    }
    let _ = sennel_core::vault::totp_code_of(text);
    let _ = sennel_core::vault::totp_shape_of(text);
});
