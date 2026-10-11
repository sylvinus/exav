#![no_main]
//! CVD/CLD container parsing (header + gzip + tar) on hostile bytes, and the
//! files it yields through the loader.
//!
//! A mirror serves these, so what comes out of the tar is an attacker's
//! signature text: each member goes to `loader::Builder::add_named_bytes` as a
//! signed database's members do (`official`), and the scanner is built, which
//! is the whole of what `freshclam`'s output goes through on its way to a scan.
//! The bounds are tighter than a real database's (`CvdLimits`), so that a
//! gzip bomb is a refusal and not a minute.
//!
//! Seed: a container of `fuzz/db/` (`scripts/fuzz-seeds.sh`).
use exav_core::cvd::{self, CvdLimits};
use exav_core::loader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = CvdLimits {
        max_tar_bytes: 16 << 20,
        max_total_bytes: 16 << 20,
        max_files: 1_000,
    };
    let Ok((_header, files)) = cvd::read_with_limits(data, &limits) else {
        return;
    };
    let mut b = loader::Builder::new();
    for f in &files {
        b.add_named_bytes(&f.name, &f.data, true);
    }
    let _ = b.build();
});
