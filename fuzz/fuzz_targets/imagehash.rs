#![no_main]
//! Image hashing on hostile bytes: every decoder exav-imagehash has, with
//! both presets' grey conversions and resizes, within a small decode budget.
use exav_imagehash::{Hasher, Params};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for p in [Params::CLAMAV, Params::IMAGEHASH_PHASH] {
        let h = Hasher::with_params(Params {
            max_decode_bytes: 64 << 20,
            ..p
        })
        .expect("valid parameters");
        let _ = h.hash(data);
    }
});
