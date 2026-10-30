// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Simple profiling infrastructure for hot path timing.
//!
//! Enable with the `profiling` feature. When enabled, tracks cumulative time
//! spent in instrumented functions and prints a report when `print_profile_report()`
//! is called.

#[cfg(feature = "profiling")]
mod inner {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    /// Profiling counters for different hot paths.
    /// Each counter tracks cumulative nanoseconds.
    pub struct ProfileCounters {
        pub dequant_transform_ns: AtomicU64,
        pub dequant_transform_calls: AtomicU64,
        pub dct_ns: AtomicU64,
        pub dct_calls: AtomicU64,
        pub entropy_decode_ns: AtomicU64,
        pub entropy_decode_calls: AtomicU64,
        pub chroma_upsample_ns: AtomicU64,
        pub chroma_upsample_calls: AtomicU64,
        pub render_pipeline_ns: AtomicU64,
        pub render_pipeline_calls: AtomicU64,
        pub modular_decode_ns: AtomicU64,
        pub modular_decode_calls: AtomicU64,
    }

    impl ProfileCounters {
        pub const fn new() -> Self {
            Self {
                dequant_transform_ns: AtomicU64::new(0),
                dequant_transform_calls: AtomicU64::new(0),
                dct_ns: AtomicU64::new(0),
                dct_calls: AtomicU64::new(0),
                entropy_decode_ns: AtomicU64::new(0),
                entropy_decode_calls: AtomicU64::new(0),
                chroma_upsample_ns: AtomicU64::new(0),
                chroma_upsample_calls: AtomicU64::new(0),
                render_pipeline_ns: AtomicU64::new(0),
                render_pipeline_calls: AtomicU64::new(0),
                modular_decode_ns: AtomicU64::new(0),
                modular_decode_calls: AtomicU64::new(0),
            }
        }

        #[allow(dead_code)] // Available for manual profiling reset
        pub fn reset(&self) {
            self.dequant_transform_ns.store(0, Ordering::Relaxed);
            self.dequant_transform_calls.store(0, Ordering::Relaxed);
            self.dct_ns.store(0, Ordering::Relaxed);
            self.dct_calls.store(0, Ordering::Relaxed);
            self.entropy_decode_ns.store(0, Ordering::Relaxed);
            self.entropy_decode_calls.store(0, Ordering::Relaxed);
            self.chroma_upsample_ns.store(0, Ordering::Relaxed);
            self.chroma_upsample_calls.store(0, Ordering::Relaxed);
            self.render_pipeline_ns.store(0, Ordering::Relaxed);
            self.render_pipeline_calls.store(0, Ordering::Relaxed);
            self.modular_decode_ns.store(0, Ordering::Relaxed);
            self.modular_decode_calls.store(0, Ordering::Relaxed);
        }
    }

    pub static COUNTERS: ProfileCounters = ProfileCounters::new();

    /// RAII guard that measures elapsed time and adds it to a counter.
    pub struct ProfileGuard {
        start: Instant,
        ns_counter: &'static AtomicU64,
        call_counter: &'static AtomicU64,
    }

    impl ProfileGuard {
        #[inline]
        pub fn new(ns_counter: &'static AtomicU64, call_counter: &'static AtomicU64) -> Self {
            Self {
                start: Instant::now(),
                ns_counter,
                call_counter,
            }
        }
    }

    impl Drop for ProfileGuard {
        #[inline]
        fn drop(&mut self) {
            let elapsed = self.start.elapsed().as_nanos() as u64;
            // Use separate load/store instead of fetch_add to avoid lock prefix.
            // This generates plain `addq`/`incq` vs `lock addq`/`lock incq`.
            // Racy but acceptable for profiling - we just want approximate counts.
            let ns = self.ns_counter.load(Ordering::Relaxed);
            self.ns_counter.store(ns + elapsed, Ordering::Relaxed);
            let calls = self.call_counter.load(Ordering::Relaxed);
            self.call_counter.store(calls + 1, Ordering::Relaxed);
        }
    }

    /// Print a profile report to stderr.
    pub fn print_profile_report() {
        let c = &COUNTERS;

        eprintln!("\n=== JXL-RS Profile Report ===\n");

        let entries = [
            (
                "dequant_transform",
                c.dequant_transform_ns.load(Ordering::Relaxed),
                c.dequant_transform_calls.load(Ordering::Relaxed),
            ),
            (
                "dct/idct",
                c.dct_ns.load(Ordering::Relaxed),
                c.dct_calls.load(Ordering::Relaxed),
            ),
            (
                "entropy_decode",
                c.entropy_decode_ns.load(Ordering::Relaxed),
                c.entropy_decode_calls.load(Ordering::Relaxed),
            ),
            (
                "chroma_upsample",
                c.chroma_upsample_ns.load(Ordering::Relaxed),
                c.chroma_upsample_calls.load(Ordering::Relaxed),
            ),
            (
                "render_pipeline",
                c.render_pipeline_ns.load(Ordering::Relaxed),
                c.render_pipeline_calls.load(Ordering::Relaxed),
            ),
            (
                "modular_decode",
                c.modular_decode_ns.load(Ordering::Relaxed),
                c.modular_decode_calls.load(Ordering::Relaxed),
            ),
        ];

        let total_ns: u64 = entries.iter().map(|(_, ns, _)| ns).sum();

        eprintln!(
            "{:<20} {:>12} {:>12} {:>10} {:>8}",
            "Function", "Time (ms)", "Calls", "Avg (µs)", "% Total"
        );
        eprintln!("{:-<66}", "");

        for (name, ns, calls) in entries {
            if calls > 0 {
                let ms = ns as f64 / 1_000_000.0;
                let avg_us = (ns as f64 / calls as f64) / 1_000.0;
                let pct = if total_ns > 0 {
                    (ns as f64 / total_ns as f64) * 100.0
                } else {
                    0.0
                };
                eprintln!(
                    "{:<20} {:>12.2} {:>12} {:>10.2} {:>7.1}%",
                    name, ms, calls, avg_us, pct
                );
            }
        }

        eprintln!("{:-<66}", "");
        eprintln!("{:<20} {:>12.2}", "TOTAL", total_ns as f64 / 1_000_000.0);
        eprintln!();
    }

    /// Reset all counters.
    #[allow(dead_code)] // Available for manual profiling reset
    pub fn reset_profile_counters() {
        COUNTERS.reset();
    }
}

#[cfg(not(feature = "profiling"))]
#[allow(dead_code)]
mod inner {
    /// No-op guard when profiling is disabled.
    #[derive(Default)]
    pub struct ProfileGuard;

    impl ProfileGuard {
        #[inline(always)]
        pub fn new() -> Self {
            Self
        }
    }

    #[inline(always)]
    pub fn print_profile_report() {}

    #[inline(always)]
    pub fn reset_profile_counters() {}
}

#[allow(unused_imports)]
pub use inner::*;

/// Macro to create a profile guard for a specific counter.
/// When profiling is disabled, this is a no-op.
#[cfg(feature = "profiling")]
#[macro_export]
macro_rules! profile {
    (dequant_transform) => {
        let _guard = $crate::util::ProfileGuard::new(
            &$crate::util::COUNTERS.dequant_transform_ns,
            &$crate::util::COUNTERS.dequant_transform_calls,
        );
    };
    (dct) => {
        let _guard = $crate::util::ProfileGuard::new(
            &$crate::util::COUNTERS.dct_ns,
            &$crate::util::COUNTERS.dct_calls,
        );
    };
    (entropy_decode) => {
        let _guard = $crate::util::ProfileGuard::new(
            &$crate::util::COUNTERS.entropy_decode_ns,
            &$crate::util::COUNTERS.entropy_decode_calls,
        );
    };
    (chroma_upsample) => {
        let _guard = $crate::util::ProfileGuard::new(
            &$crate::util::COUNTERS.chroma_upsample_ns,
            &$crate::util::COUNTERS.chroma_upsample_calls,
        );
    };
    (render_pipeline) => {
        let _guard = $crate::util::ProfileGuard::new(
            &$crate::util::COUNTERS.render_pipeline_ns,
            &$crate::util::COUNTERS.render_pipeline_calls,
        );
    };
    (modular_decode) => {
        let _guard = $crate::util::ProfileGuard::new(
            &$crate::util::COUNTERS.modular_decode_ns,
            &$crate::util::COUNTERS.modular_decode_calls,
        );
    };
}

#[cfg(not(feature = "profiling"))]
#[macro_export]
macro_rules! profile {
    ($name:ident) => {};
}
