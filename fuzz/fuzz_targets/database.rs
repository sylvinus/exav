#![no_main]
//! The prebuilt database file (`.exavdb`): `database::read` on hostile bytes,
//! and what comes back.
//!
//! A deployment loads one of these from a mirror it trusts, but a mirror is
//! reached over a network and the file is a MessagePack stream whose lengths
//! size allocations (`database::enc_bytes`), so a length that lies is an
//! allocation the reader must refuse and not make.
//!
//! The seed is a database written by `scripts/fuzz-seeds.sh` from `fuzz/db/`.
//! Checked beyond "does not panic": a database that reads scans, and writes
//! back to one that reads and scans the same.
use exav_core::{ScanOptions, analyze, database};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(db) = database::read(data) else {
        return;
    };
    let sample = b"MZ\x90\x00 sample X5O!P%@AP content for the scan to look at";
    let opts = ScanOptions::default();
    let first = analyze(&db, sample, &opts).verdict;

    let mut again = Vec::new();
    if database::write(&db, &mut again).is_err() {
        return;
    }
    let back = database::read(again.as_slice()).expect("a database written out reads");
    assert_eq!(
        analyze(&back, sample, &opts).verdict,
        first,
        "a database read, written and read scans differently"
    );
});
