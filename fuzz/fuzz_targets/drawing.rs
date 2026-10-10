#![no_main]
//! DWG and DXF on hostile bytes: exav-render's parse (the drawing model's
//! DXF and DWG readers) and the tessellation of every layout on both grounds, as
//! @exav/viewer's DWG module runs them. `Document::parse` catches a reader panic where it
//! can unwind, but libFuzzer's panic hook aborts first: in the browser the
//! same panic traps the wasm instance, so every one is a finding.
use exav_render::dwg::Document;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = Document::parse(data) else {
        return;
    };
    for layout in doc.layouts() {
        for ground in [[255, 255, 255], [33, 40, 48]] {
            let _ = doc.tessellate(Some(&layout.name), Some(ground));
        }
    }
});
