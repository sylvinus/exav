#![no_main]
//! OBJ, PLY and glTF on hostile bytes: exav-render's three mesh readers, as
//! @exav/viewer's model module runs them, with a small triangle budget so
//! that a run stays fast. In the browser a panic traps the wasm instance, so
//! every one is a finding.
use exav_render::{gltf, obj, ply};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for scene in [
        obj::read(data, 200_000).ok(),
        ply::read(data, 200_000).ok(),
        gltf::read(data, 200_000).ok(),
    ]
    .into_iter()
    .flatten()
    {
        // What the viewer relies on: whole triangles, in range, finite.
        for b in &scene.batches {
            assert_eq!(b.indices.len() % 3, 0);
            let vertices = (b.positions.len() / 3) as u32;
            assert!(b.indices.iter().all(|&i| i < vertices));
            assert!(b.positions.iter().all(|v| v.is_finite()));
        }
    }
});
