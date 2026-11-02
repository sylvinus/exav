//! Optional per-matcher profiling.
//!
//! Implemented in [`exav_unpack::profile`](https://docs.rs/exav-unpack) — shared
//! scan infra at the bottom of the dependency stack, so the packer emulator in
//! `exav-unpack` and the matchers here record into the same thread-local
//! profile. Re-exported so existing paths keep working.
pub use exav_unpack::profile::{Profile, Stat, enable, take, timed};
