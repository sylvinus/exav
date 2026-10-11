#![no_main]
//! DWG into exav-render's drawing model (`exav_render::cad::read_dwg`): the
//! bit codes, the sections the file header locates (R13 to R2000) or the
//! R2004 container's decrypted maps, checksummed pages and decompression
//! (R2007's: Reed-Solomon coded, CRC-checked, its own decompression), the
//! object map and the objects with their string streams
//! (`exav_unpack::dwg`), and what the tables and blocks mean, proxy
//! graphics streams included, on hostile bytes; and the thumbnail read
//! without reading the drawing (`cad::preview`). The scanner reaches only the file header and the preview
//! (`unpack`, `analyze`). Every panic is a finding: the model's code denies
//! indexing and `unwrap`, and in the browser a panic traps the wasm
//! instance. Decompression is held to 64 MiB, so that an expanding page is
//! not mistaken for a hang.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = exav_render::cad::Limits {
        max_entities: 100_000,
        max_items: 100_000,
        max_string_bytes: 1 << 16,
        max_warnings: 100,
        max_decompressed_bytes: 1 << 26,
    };
    if let Ok(d) = exav_render::cad::read_dwg_with(data, &limits) {
        let _ = exav_render::cad::to_json(&d);
    }
    let _ = exav_render::cad::preview(data);
});
