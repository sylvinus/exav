//! Panics a decoder contains on purpose.
//!
//! libFuzzer's panic hook aborts the process on every panic, one that a
//! `catch_unwind` is about to catch included. A third-party reader that panics
//! on hostile input, and that the walk wraps so that only the read that failed
//! is lost, would then end every run at the first such input and hide whatever
//! lies past it.

use std::panic;
use std::sync::Once;

/// The functions of exav that run a third-party reader inside a `catch_unwind`
/// of their own: `contained` in exav-unpack's `formats/fat.rs` (fatfs panics on
/// a cluster chain through cluster 1). The backtrace names a generic function
/// without its path.
pub const CONTAINED: &[&str] = &["contained<"];

/// Lets a panic through to its `catch_unwind` when `frames` names a function
/// the panic is raised under (a part of its path, as the backtrace prints it);
/// every other panic goes to the hook that was there, which aborts.
///
/// Call it from the target on every run: it installs the hook once.
pub fn tolerate_inside(frames: &'static [&'static str]) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let before = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let trace = std::backtrace::Backtrace::force_capture().to_string();
            if frames.iter().any(|f| trace.contains(f)) {
                return;
            }
            before(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static REACHED_THE_OTHER_HOOK: AtomicUsize = AtomicUsize::new(0);

    #[inline(never)]
    fn contained_here() -> bool {
        panic::catch_unwind(|| panic!("contained")).is_err()
    }

    #[inline(never)]
    fn not_contained_here() -> bool {
        panic::catch_unwind(|| panic!("not contained")).is_err()
    }

    #[test]
    fn only_a_panic_under_the_named_function_is_let_through() {
        panic::set_hook(Box::new(|_| {
            REACHED_THE_OTHER_HOOK.fetch_add(1, Ordering::SeqCst);
        }));
        tolerate_inside(&["tests::contained_here"]);
        assert!(contained_here());
        assert_eq!(REACHED_THE_OTHER_HOOK.load(Ordering::SeqCst), 0);
        assert!(not_contained_here());
        assert_eq!(REACHED_THE_OTHER_HOOK.load(Ordering::SeqCst), 1);
    }
}
