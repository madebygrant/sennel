use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arboard::Clipboard;

// Set while a copy is waiting for its wipe, for `emergency_clear` to find from a panic hook or a
// signal, where no `Board` is to hand.
static OUTSTANDING: AtomicBool = AtomicBool::new(false);

/// The OS clipboard with an auto-clear timer.
///
/// A copy that lingers is a password sitting where anything can paste it, so
/// every copy starts a timer that wipes the clipboard — unless the user asked
/// for no timer with `clipboard_timeout = 0`, which means "leave it there".
#[derive(Clone)]
pub struct Board {
    // One lock for the copy, the clearer's check and its wipe, so a copy landing as an older timer
    // fires can never be wiped by it or left on the clipboard with the quit-wipe disarmed.
    state: Arc<Mutex<State>>,
    // Seconds, 0 for no clear. Shared by clones, so a settings change reaches every holder.
    timeout: Arc<AtomicU64>,
}

#[derive(Default)]
struct State {
    // Each copy bumps this; a clearer thread only wipes while its own generation is current.
    epoch: u64,
    // When the copy is wiped, on the wall clock: a sleeping thread does not run during a suspend.
    until: Option<SystemTime>,
    // Kept for the life of the board. On X11, dropping the last one hands the copy to the clipboard
    // manager and gives up the selection, so a later wipe would clear nothing of ours.
    clipboard: Option<Clipboard>,
}

impl State {
    fn clipboard(&mut self) -> Result<&mut Clipboard, arboard::Error> {
        if self.clipboard.is_none() {
            self.clipboard = Some(Clipboard::new()?);
        }
        Ok(self.clipboard.as_mut().expect("just set"))
    }

    // Whatever is on the clipboard now: it cannot tell a later copy from another app from ours.
    fn wipe(&mut self) {
        if let Ok(board) = self.clipboard() {
            let _ = board.clear();
        }
        self.until = None;
        self.epoch += 1;
        OUTSTANDING.store(false, Ordering::SeqCst);
    }
}

impl Board {
    pub fn new(timeout_secs: u64) -> Self {
        Board {
            state: Arc::new(Mutex::new(State::default())),
            // Zero is "leave it there", matching lock_timeout's reading of 0
            // as off rather than as immediate.
            timeout: Arc::new(AtomicU64::new(timeout_secs)),
        }
    }

    // A poisoned lock would take the app down on the next copy, and nothing behind it can be left
    // half-written, so keep going with what survived.
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// From the next copy on; a countdown already running keeps its deadline.
    pub fn set_timeout(&self, secs: u64) {
        self.timeout.store(secs, Ordering::Relaxed);
    }

    fn timeout(&self) -> Option<Duration> {
        let secs = self.timeout.load(Ordering::Relaxed);
        (secs > 0).then(|| Duration::from_secs(secs))
    }

    /// Seconds before a copy clears, for the confirmation message.
    pub fn timeout_secs(&self) -> Option<u64> {
        self.timeout().map(|d| d.as_secs())
    }

    /// Whole seconds left before the clipboard is wiped, or `None` when
    /// nothing of ours is on it (or the wipe is switched off).
    pub fn clears_in(&self) -> Option<u64> {
        let until = self.state().until?;
        let left = until.duration_since(SystemTime::now()).ok()?;
        // Round up, so the last fraction of a second is not shown as zero.
        Some(left.as_secs() + u64::from(left.subsec_millis() > 0))
    }

    /// Wipes now if a copy is waiting for its wipe. Quitting must do this: the timer is a thread
    /// inside this process. Nothing waiting, or `clipboard_timeout = 0`, leaves the clipboard alone.
    pub fn clear_now(&self) {
        let mut state = self.state();
        if state.until.is_some() {
            state.wipe();
        }
    }

    /// Copies text and re-arms the auto-clear. The failure message names the
    /// fix and never echoes the text back: it is usually a password.
    pub fn copy(&self, text: &str) -> Result<(), String> {
        let mut state = self.state();
        let board = state.clipboard().map_err(|e| {
            format!("no clipboard to copy to · {e} · needs wl-clipboard on Wayland, xclip on X11")
        })?;
        // Borrowed, so arboard makes the only copy rather than one more nobody wipes.
        concealed(board.set())
            .text(text)
            .map_err(|e| format!("clipboard refused the copy · {e}"))?;
        state.epoch += 1;
        let generation = state.epoch;
        let Some(wait) = self.timeout() else {
            state.until = None;
            OUTSTANDING.store(false, Ordering::SeqCst);
            return Ok(());
        };
        let deadline = SystemTime::now() + wait;
        state.until = Some(deadline);
        OUTSTANDING.store(true, Ordering::SeqCst);
        drop(state);
        let board = self.clone();
        std::thread::spawn(move || {
            // Sliced: a thread asleep through a suspend wakes owing the rest of its nap.
            // Each slice re-reads the wall clock, so waking ends the wait.
            let monotonic = std::time::Instant::now() + wait;
            loop {
                // Whichever clock runs out first ends the wait: wall catches suspend,
                // monotonic catches a clock set backwards.
                let left = deadline
                    .duration_since(SystemTime::now())
                    .unwrap_or_default()
                    .min(monotonic.saturating_duration_since(std::time::Instant::now()));
                if left.is_zero() {
                    break;
                }
                std::thread::sleep(left.min(Duration::from_secs(1)));
                // A newer copy has a thread of its own, and this one must not wipe it.
                if board.state().epoch != generation {
                    return;
                }
            }
            let mut state = board.state();
            if state.epoch == generation {
                state.wipe();
            }
        });
        Ok(())
    }
}

/// From a panic hook or a signal: wipes the clipboard if a timed copy is still waiting for its
/// wipe. Opens a clipboard of its own, since the board may be behind a lock nobody will release.
pub fn emergency_clear() {
    if OUTSTANDING.swap(false, Ordering::SeqCst) {
        let _ = Clipboard::new().and_then(|mut c| c.clear());
    }
}

// The 30-second wipe clears the clipboard, not a clipboard manager's history, so every copy is
// marked for those managers to skip: macOS's ConcealedType, KDE's password hint (read on X11 and
// Wayland), and on Windows a flag that keeps it out of both local history and cloud sync.
#[cfg(target_os = "macos")]
fn concealed(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtApple;
    set.exclude_from_history()
}

#[cfg(windows)]
fn concealed(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtWindows;
    set.exclude_from_monitoring()
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
fn concealed(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtLinux;
    set.exclude_from_history()
}

#[cfg(not(any(
    target_os = "macos",
    windows,
    all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    )
)))]
fn concealed(set: arboard::Set<'_>) -> arboard::Set<'_> {
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    // What a copy does to the generation and the deadline, without touching a real clipboard.
    fn armed(board: &Board, secs: u64) -> u64 {
        let mut state = board.state();
        state.epoch += 1;
        state.until = Some(SystemTime::now() + Duration::from_secs(secs));
        state.epoch
    }

    /* The countdown the status bar reads: armed by a copy, and never a stale
    number once the wipe has landed. */
    #[test]
    fn the_countdown_is_armed_and_runs_out() {
        let board = Board::new(15);
        assert_eq!(board.clears_in(), None, "nothing copied yet");
        armed(&board, 9);
        assert_eq!(board.clears_in(), Some(9));
        board.state().until = Some(SystemTime::now() - Duration::from_secs(1));
        assert_eq!(board.clears_in(), None, "a past deadline still counted");
    }

    /* Quitting must not abandon a secret: the wipe deadline is dropped and
    the generation bumped, so the sleeping thread cannot wipe whatever the
    user copies next. */
    #[test]
    fn clearing_on_exit_disarms_the_pending_wipe() {
        let board = Board::new(15);
        let generation = armed(&board, 9);
        board.clear_now();
        assert_eq!(board.clears_in(), None, "the deadline survived");
        assert_ne!(
            board.state().epoch,
            generation,
            "the sleeping clearer stayed current"
        );
        // Nothing of ours on the board: no clipboard call, no surprise wipe.
        let quiet = Board::new(15);
        quiet.clear_now();
        assert_eq!(quiet.state().epoch, 0);
    }

    #[test]
    fn an_emergency_clear_with_nothing_waiting_does_nothing() {
        OUTSTANDING.store(false, Ordering::SeqCst);
        emergency_clear();
        assert!(!OUTSTANDING.load(Ordering::SeqCst));
    }

    #[test]
    fn zero_timeout_means_no_clear() {
        assert!(Board::new(0).timeout().is_none());
        assert_eq!(Board::new(15).timeout(), Some(Duration::from_secs(15)));
        let board = Board::new(15);
        board.clone().set_timeout(0);
        assert!(
            board.timeout_secs().is_none(),
            "a clone's change did not reach the original"
        );
    }

    /* Needs a real display server, so it never runs in CI. Run it by hand
    with `cargo test -- --ignored` on a machine with a clipboard. */
    #[test]
    #[ignore]
    fn copy_reaches_the_clipboard_and_the_wipe_clears_it() {
        let board = Board::new(1);
        board.copy("sennel-probe").unwrap();
        assert_eq!(
            Clipboard::new().unwrap().get_text().unwrap(),
            "sennel-probe"
        );
        assert!(OUTSTANDING.load(Ordering::SeqCst));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(Clipboard::new().unwrap().get_text().is_err(), "not wiped");
        assert!(!OUTSTANDING.load(Ordering::SeqCst));
    }
}
