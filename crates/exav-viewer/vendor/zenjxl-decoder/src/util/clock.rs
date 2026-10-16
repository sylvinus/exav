// exav: not part of upstream. See ../../EXAV.md.

//! The clock the decoder times its phases with (`JXL_PHASE_TIMING`, off).
//!
//! `std::time::Instant::now()` panics on `wasm32-unknown-unknown`, which has no
//! clock, and the decoder reads it whether or not timing is wanted. On that
//! target the clock reads zero: nothing in the decoder depends on a time, and a
//! browser build must not import one from its host.

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::time::Duration;

    #[derive(Clone, Copy, Debug)]
    pub struct Instant;

    impl Instant {
        pub fn now() -> Self {
            Instant
        }

        pub fn elapsed(&self) -> Duration {
            Duration::ZERO
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::Instant;
