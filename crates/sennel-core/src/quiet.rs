// Third-party parsers that panic on bad input (keepass on a short header, rqrr on a crafted QR code)
// run through `quietly`, so the panic becomes a `None` and its message stays off the terminal.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, and returns `None` if it panicked, without printing the panic.
pub fn quietly<T>(f: impl FnOnce() -> T) -> Option<T> {
    // Installed at the first call, so it wraps the terminal app's hook, which restores the
    // terminal, and keeps that from running for a panic that was caught.
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET.get() {
                previous(info);
            }
        }));
    });
    let was = QUIET.replace(true);
    let result = catch_unwind(AssertUnwindSafe(f));
    QUIET.set(was);
    result.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_inside_comes_back_as_none_and_the_flag_is_reset() {
        assert_eq!(quietly(|| 7), Some(7));
        let caught: Option<u8> = quietly(|| panic!("from a parser"));
        assert_eq!(caught, None);
        assert!(!QUIET.get());
        // Nested, the outer call stays quiet after the inner one returns.
        let outer = quietly(|| {
            let _ = quietly(|| 1);
            assert!(QUIET.get());
            2
        });
        assert_eq!(outer, Some(2));
    }
}
