#![no_main]
//! Camera RAW files on hostile bytes, as @exav/viewer opens them:
//! `image::raw`'s detection and its choice of a preview (the TIFF
//! directories, the ISO base media boxes, the JPEG stream search, the
//! uncompressed samples and the orientation), within a small decode budget,
//! then `decode_any`, which tries a RAW file first and reads the rest as the
//! image it is.
use libfuzzer_sys::fuzz_target;

/// A decode of this size costs seconds under the sanitizer: what a preview of
/// a few megapixels does, which is all the target needs to reach the decoder.
const BUDGET: u64 = 16 << 20;

fuzz_target!(|data: &[u8]| {
    exav_fuzz_support::panics::contained_panics();
    let _ = exav_render::image::raw::detect(data);
    let _ = exav_render::image::raw::preview(data, BUDGET);
    let _ = exav_render::image::decode_any(data, BUDGET);
});
