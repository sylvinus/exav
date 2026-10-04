#![no_main]
//! DXF into exav-render's drawing model (`exav_render::cad`), and the model
//! into JSON: what each group code means in each record, proxy graphics
//! streams included, on hostile bytes; and the thumbnail found from the end
//! of the file (`cad::preview`).
//! The scanner reaches DXF's pairs and records through exav-unpack (`unpack`,
//! `analyze`), but never this reading of them. Every panic is a finding: the
//! model's code denies indexing and `unwrap`, and in the browser a panic
//! traps the wasm instance.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = exav_render::cad::Limits {
        max_entities: 100_000,
        max_items: 100_000,
        max_string_bytes: 1 << 16,
        max_warnings: 100,
        max_decompressed_bytes: 1 << 26,
    };
    if let Ok(d) = exav_render::cad::read_dxf_with(data, &limits) {
        let _ = exav_render::cad::to_json(&d);
    }
    let _ = exav_render::cad::preview(data);
});
