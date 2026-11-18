//! A member said to be larger than what is left of the extraction total is left
//! out before it is decoded and costs nothing of it, so the members after it
//! are still extracted.

use exav_unpack::{Budget, Format, Limits, extract};
use std::io::Write;

/// A ZIP read by its local headers alone, its directory gone.
#[test]
fn a_zip_member_over_what_is_left_of_the_total_costs_nothing() {
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    // Bytes deflate cannot shrink, so the member is decoded to its end.
    let noise: Vec<u8> = (0..100u32 << 10)
        .scan(1u32, |s, _| {
            *s = s.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            Some((*s >> 16) as u8)
        })
        .collect();
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("big.bin", deflated).unwrap();
    w.write_all(&noise).unwrap();
    w.start_file("small.txt", deflated).unwrap();
    w.write_all(b"after the big one").unwrap();
    let zip = w.finish().unwrap().into_inner();
    let directory = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    let mut limits = Limits::default();
    limits.max_extracted_bytes = 64 << 10;
    let entries = extract(Format::Zip, &&zip[..directory], &mut Budget::new(limits)).unwrap();
    let big = entries.iter().find(|e| e.name == "big.bin");
    assert!(
        big.is_some_and(|e| e.data.is_empty() && e.unsupported.is_some()),
        "{big:?}"
    );
    let small = entries.iter().find(|e| e.name == "small.txt");
    assert_eq!(small.map(|e| &e.data[..]), Some(&b"after the big one"[..]));
}
