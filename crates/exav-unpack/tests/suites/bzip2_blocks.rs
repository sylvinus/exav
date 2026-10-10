//! A bzip2 block of incompressible data compresses to more bytes than the block
//! holds. The decoder must still read it whole, not stop at the block size.

use std::io::Write;

use exav_unpack::{extract, Budget, Format, Limits};

/// Bytes no compressor can shrink, from a fixed seed.
fn noise(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level));
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn incompressible_blocks_are_decoded() {
    // Level 1 is 100k blocks, so this is two full blocks and a partial one.
    let data = noise(250_000);
    for level in [1, 9] {
        let bz = compress(&data, level);
        assert!(bz.len() > data.len(), "the input must not compress");
        let mut budget = Budget::new(Limits::default());
        let out = extract(Format::Bzip2, &bz, &mut budget)
            .unwrap_or_else(|e| panic!("level {level}: {e:?}"));
        assert_eq!(out.len(), 1, "level {level}");
        assert!(out[0].data == data, "level {level}: decoded bytes differ");
    }
}
