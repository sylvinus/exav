#![no_main]
//! Archive extraction on hostile bytes, tried as each supported type, with
//! default budgets. Must terminate and stay within the budget (libFuzzer's
//! rss limit catches runaway allocation).
use libfuzzer_sys::fuzz_target;
use exav_core::filetype::FileType;
use exav_core::unpack::{extract, Budget, Limits};

fuzz_target!(|data: &[u8]| {
    for ft in [FileType::Zip, FileType::Gzip, FileType::Tar] {
        let mut budget = Budget::new(Limits::default());
        let _ = extract(ft, data, &mut budget);
    }
});
