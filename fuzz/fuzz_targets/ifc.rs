#![no_main]
//! IFC and STL on hostile bytes: exav-render's STEP reader, IFC geometry
//! engine and STL reader, as @exav/viewer's model module runs them, with a
//! small triangle budget so that a run stays fast. In the browser a panic
//! traps the wasm instance, so every one is a finding.
use exav_render::{ifc, stl};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ifc::read(
        data,
        &ifc::Limits {
            max_triangles: 200_000,
        },
    );
    let _ = stl::read(data, 200_000);
});
