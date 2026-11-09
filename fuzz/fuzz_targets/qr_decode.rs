#![no_main]

use libfuzzer_sys::fuzz_target;

// Width, height, then one bit per pixel: a flipped bit is a flipped module, which reaches the QR
// decoder far more often than mutating raw RGBA does.
fuzz_target!(|data: &[u8]| {
    let [width, height, bits @ ..] = data else {
        return;
    };
    let (width, height) = (usize::from(*width), usize::from(*height));
    let rgba: Vec<u8> = (0..width * height)
        .flat_map(|at| {
            let dark = bits.get(at / 8).is_some_and(|b| b >> (at % 8) & 1 == 1);
            let shade = if dark { 0 } else { 255 };
            [shade, shade, shade, 255]
        })
        .collect();
    let _ = sennel_core::qr::decode(width, height, &rgba);
});
