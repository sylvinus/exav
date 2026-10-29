#![no_main]
//! Image decoding on hostile bytes: every decoder exav-imagehash has (JPEG
//! 2000 and JBIG2 included), with both presets' grey conversions and resizes,
//! within a small decode budget; then exav-render's `decode_any`, and the
//! JPXDecode, JBIG2Decode and CCITTFaxDecode decoders @exav/viewer gives
//! pdf.js, with parameters taken from the input's length (JBIG2 with and
//! without a globals stream).
use exav_imagehash::{Hasher, Params};
use exav_render::pdf_image::{CcittParams, JpxParams, decode_ccitt, decode_jbig2, decode_jpx};
use libfuzzer_sys::fuzz_target;

const BUDGET: u64 = 64 << 20;

/// What the hasher may decode: the grey conversion and resize of a 16 MiB
/// image took 10 s under the sanitizer for 805 bytes of JPEG (0.4 s in
/// release), and what they cost is not what the target looks for. The decoders
/// still get `BUDGET` through `decode_any` below.
const HASH_BUDGET: u64 = 4 << 20;

fuzz_target!(|data: &[u8]| {
    for p in [Params::CLAMAV, Params::IMAGEHASH_PHASH] {
        let h = Hasher::with_params(Params {
            max_decode_bytes: HASH_BUDGET,
            ..p
        })
        .expect("valid parameters");
        let _ = h.hash(data);
    }
    let _ = exav_render::image::decode_any(data, BUDGET);

    let n = data.len();
    let jpx = JpxParams {
        num_components: [0, 1, 3, 4][n % 4],
        indexed: n & 4 != 0,
        smask_in_data: n & 8 != 0,
        reduce_power: (n >> 4) as u32 & 1,
    };
    let _ = decode_jpx(data, jpx, BUDGET);
    // A JBIG2 file's segments are an embedded stream once its header (ID,
    // flags, and the page count unless unknown) is skipped.
    let embedded = match data {
        [0x97, b'J', b'B', b'2', 0x0D, 0x0A, 0x1A, 0x0A, flags, ..] => data
            .get(if flags & 2 != 0 { 9 } else { 13 }..)
            .unwrap_or_default(),
        _ => data,
    };
    let _ = decode_jbig2(embedded, 97, 61, None, BUDGET);
    // The JBIG2Globals stream a PDF shares among its images (symbol
    // dictionaries, mostly), from the front of the input: the only way
    // segments in one stream refer to segments in another.
    let (globals, page) = embedded.split_at(embedded.len() / 3);
    let _ = decode_jbig2(page, 97, 61, Some(globals), BUDGET);
    let fax = CcittParams {
        width: 97,
        height: 61,
        k: [-1, 0, 1][n % 3],
        end_of_line: n & 1 != 0,
        encoded_byte_align: n & 2 != 0,
        black_is_1: n & 4 != 0,
        columns: 97,
        rows: if n & 8 != 0 { 0 } else { 61 },
    };
    let _ = decode_ccitt(data, fax, BUDGET);
});
