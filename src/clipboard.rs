use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arboard::Clipboard;

/// The OS clipboard with an auto-clear timer.
///
/// A copy that lingers is a password sitting where anything can paste it, so
/// every copy starts a timer that wipes the clipboard — unless the user asked
/// for no timer with `clipboard_timeout = 0`, which means "leave it there".
#[derive(Clone)]
pub struct Board {
    /* Each copy bumps this; the clearer thread only wipes when its own
       generation is still current. A second copy re-arms the timer instead of
       being wiped early by the first one's thread. */
    epoch: Arc<Mutex<u64>>,
    timeout: Option<Duration>,
    /* When the secret on the clipboard stops being there. The status bar
       counts this down: "clears in 15s" is a promise shown for three seconds
       and then gone, while the secret is still sitting there.

       On the wall clock, not the monotonic one: a sleeping thread does not
       run during a system suspend, so a fifteen-second wipe used to become
       "fifteen seconds of the machine being awake" — a password left on the
       pasteboard across a closed lid. */
    until: Arc<Mutex<Option<SystemTime>>>,
}

impl Board {
    pub fn new(timeout_secs: u64) -> Self {
        Board {
            epoch: Arc::new(Mutex::new(0)),
            until: Arc::new(Mutex::new(None)),
            // Zero is "leave it there", matching lock_timeout's reading of 0
            // as off rather than as immediate.
            timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs)),
        }
    }

    /// Next copy generation. Bumped once per copy, read back by the clearer.
    fn claim(&self) -> u64 {
        /* A poisoned mutex would otherwise take the whole TUI down on the
           next copy; the counter is the only thing behind it, so keep going
           with whatever value survived. */
        let mut epoch = self.epoch.lock().unwrap_or_else(|e| e.into_inner());
        *epoch += 1;
        *epoch
    }

    fn stale(&self, generation: u64) -> bool {
        *self.epoch.lock().unwrap_or_else(|e| e.into_inner()) != generation
    }

    /// Seconds before a copy clears, for the confirmation message.
    pub fn timeout_secs(&self) -> Option<u64> {
        self.timeout.map(|d| d.as_secs())
    }

    /// Whole seconds left before the clipboard is wiped, or `None` when
    /// nothing of ours is on it (or the wipe is switched off).
    pub fn clears_in(&self) -> Option<u64> {
        let until = (*self.until.lock().unwrap_or_else(|e| e.into_inner()))?;
        let left = until.duration_since(SystemTime::now()).ok()?;
        // Round up, so the last fraction of a second is not shown as zero.
        Some(left.as_secs() + u64::from(left.subsec_millis() > 0))
    }

    /* Wipe now, if what is on the clipboard is still ours. The timer is a
       thread inside this process, so quitting used to abandon a password on
       the pasteboard — on macOS it is system-owned and sits there until
       something else copies. A cleared deadline means either nothing of ours
       is there or the user asked for no wipe at all (`clipboard_timeout =
       0`), and both are left alone. */
    pub fn clear_now(&self) {
        let mut until = self.until.lock().unwrap_or_else(|e| e.into_inner());
        if until.is_none() {
            return;
        }
        *until = None;
        drop(until);
        // Bumped so the sleeping clearer does not wipe a later copy of theirs.
        self.claim();
        let _ = Clipboard::new().and_then(|mut c| c.clear());
    }

    /// Copies text and re-arms the auto-clear. The failure message names the
    /// fix and never echoes the text back: it is usually a password.
    pub fn copy(&self, text: &str) -> Result<(), String> {
        let mut board = Clipboard::new().map_err(|e| {
            format!(
                "no clipboard to copy to · {e} · needs wl-clipboard on Wayland, xclip on X11"
            )
        })?;
        board
            .set_text(text.to_owned())
            .map_err(|e| format!("clipboard refused the copy · {e}"))?;
        let generation = self.claim();
        if let Some(wait) = self.timeout {
            let deadline = SystemTime::now() + wait;
            *self.until.lock().unwrap_or_else(|e| e.into_inner()) = Some(deadline);
            let board = self.clone();
            std::thread::spawn(move || {
                /* Sliced rather than one long sleep: a thread asleep when the
                   machine suspends wakes up owing the rest of its nap, so the
                   wipe landed a quarter of an hour of *uptime* later however
                   long the lid was shut. Each slice re-reads the wall clock,
                   so waking is what ends the wait. */
                let monotonic = std::time::Instant::now() + wait;
                loop {
                    /* Whichever clock runs out first ends the wait. The wall
                       clock is the one that notices a suspend; the monotonic
                       one is what stops a clock set backwards from holding a
                       password on the pasteboard for as long as it likes. */
                    let left = deadline
                        .duration_since(SystemTime::now())
                        .unwrap_or_default()
                        .min(monotonic.saturating_duration_since(std::time::Instant::now()));
                    if left.is_zero() {
                        break;
                    }
                    std::thread::sleep(left.min(Duration::from_secs(1)));
                    /* A newer copy has a thread of its own; this one is done
                       and must not wipe what that one put there. */
                    if board.stale(generation) {
                        return;
                    }
                }
                /* Best effort and generation-checked: by now the user may have
                   copied something else themselves, and wiping that would
                   destroy their data to protect ours. */
                if !board.stale(generation) {
                    let _ = Clipboard::new().and_then(|mut c| c.clear());
                    *board.until.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* The whole auto-clear contract without touching a real clipboard: the
       generation is what the clearer thread decides on. */
    #[test]
    fn copies_bump_the_generation() {
        let board = Board::new(15);
        assert_eq!(board.claim(), 1);
        assert_eq!(board.claim(), 2);
    }

    #[test]
    fn a_newer_copy_marks_the_older_stale() {
        let board = Board::new(15);
        let first = board.claim();
        assert!(!board.stale(first));
        let second = board.claim();
        assert!(board.stale(first), "the first copy still reads as current");
        assert!(!board.stale(second));
    }

    /* The countdown the status bar reads: armed by a copy, and never a stale
       number once the wipe has landed. */
    #[test]
    fn the_countdown_is_armed_and_runs_out() {
        let board = Board::new(15);
        assert_eq!(board.clears_in(), None, "nothing copied yet");
        *board.until.lock().unwrap() = Some(SystemTime::now() + Duration::from_secs(9));
        assert_eq!(board.clears_in(), Some(9));
        *board.until.lock().unwrap() = Some(SystemTime::now() - Duration::from_secs(1));
        assert_eq!(board.clears_in(), None, "a past deadline still counted");
    }

    /* Quitting must not abandon a secret: the wipe deadline is dropped and
       the generation bumped, so the sleeping thread cannot wipe whatever the
       user copies next. */
    #[test]
    fn clearing_on_exit_disarms_the_pending_wipe() {
        let board = Board::new(15);
        *board.until.lock().unwrap() = Some(SystemTime::now() + Duration::from_secs(9));
        let generation = *board.epoch.lock().unwrap();
        board.clear_now();
        assert_eq!(board.clears_in(), None, "the deadline survived");
        assert!(board.stale(generation), "the sleeping clearer stayed current");
        // Nothing of ours on the board: no clipboard call, no surprise wipe.
        let quiet = Board::new(15);
        quiet.clear_now();
        assert_eq!(quiet.clears_in(), None);
    }

    #[test]
    fn zero_timeout_means_no_clear() {
        assert!(Board::new(0).timeout.is_none());
        assert_eq!(Board::new(15).timeout, Some(Duration::from_secs(15)));
    }

    /* Needs a real display server, so it never runs in CI. Run it by hand
       with `cargo test -- --ignored` on a machine with a clipboard. */
    #[test]
    #[ignore]
    fn copy_reaches_the_clipboard() {
        Board::new(0).copy("sennel-probe").unwrap();
        let back = Clipboard::new().unwrap().get_text().unwrap();
        assert_eq!(back, "sennel-probe");
    }
}
