#![no_main]

use libfuzzer_sys::fuzz_target;
use sennel_core::envfile;

fuzz_target!(|text: &str| {
    let _ = envfile::parse(text);
    let _ = envfile::write_layout(&envfile::read_layout(text));
});
