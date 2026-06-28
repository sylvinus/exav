#![no_main]
//! Archive extraction on hostile bytes, tried as each supported type, with
//! default budgets. Must terminate and stay within the budget (libFuzzer's
//! rss limit catches runaway allocation).
use libfuzzer_sys::fuzz_target;
use exav_unpack::{Format, Budget, Limits, extract};

fuzz_target!(|data: &[u8]| {
    for fmt in [Format::Zip, Format::Gzip, Format::Tar, Format::Zstd] {
        let mut budget = Budget::new(Limits::default());
        let _ = extract(fmt, data, &mut budget);
    }
});
