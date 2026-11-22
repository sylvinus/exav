//! What the ZIP writer produces, read back by exav's own ZIP reader.

use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
use exav_unpack::{Budget, Format, Limits, Member, MemberMeta, walk};
use std::io::{Cursor, Write};

fn read_back(zip: &[u8], budget: &mut Budget) -> Vec<(String, Option<u16>, Vec<u8>)> {
    let mut seen = Vec::new();
    let _ = walk::<()>(
        Format::Zip,
        &zip,
        budget,
        &mut |meta: &MemberMeta, content: Option<Member<'_>>, _b: &mut Budget| {
            let mut d = Vec::new();
            match content {
                None => {}
                Some(Member::Bytes(b)) => d = b,
                Some(Member::Stream(r)) => {
                    let _ = r.read_to_end(&mut d);
                }
            }
            seen.push((meta.name.clone(), meta.unsupported.map(|_| 1), d));
            None
        },
    );
    seen
}

#[test]
fn stored_deflated_and_non_ascii_members_are_read_back() {
    let noise: Vec<u8> = (0..70_000u32)
        .map(|i| (i.wrapping_mul(i) >> 5) as u8)
        .collect();
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    let stored = FileOptions::default().method(Method::Stored);
    w.start_file("a.txt", stored).unwrap();
    w.write_all(b"stored body").unwrap();
    w.start_file("d/é.bin", FileOptions::default()).unwrap();
    w.write_all(&noise).unwrap();
    w.start_file("empty", FileOptions::default()).unwrap();
    let zip = w.finish().unwrap().into_inner();
    let seen = read_back(&zip, &mut Budget::new(Limits::default()));
    let names: Vec<&str> = seen.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(names, ["a.txt", "d/é.bin", "empty"]);
    assert!(seen.iter().all(|m| m.1.is_none()), "{seen:?}");
    assert_eq!(seen[0].2, b"stored body");
    assert_eq!(seen[1].2, noise);
    assert_eq!(seen[2].2, b"");
}

/// A member of ZipCrypto, and one of a ZIP64 directory (more than 65534
/// members), both written as `unzip` reads them.
#[test]
fn a_zip64_directory_and_an_encrypted_member_are_read_back() {
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    let stored = FileOptions::default().method(Method::Stored);
    for i in 0..70_000u32 {
        w.start_file(&format!("m{i}"), stored).unwrap();
    }
    w.start_file("locked", stored.zipcrypto(b"pw")).unwrap();
    w.write_all(b"the secret").unwrap();
    let zip = w.finish().unwrap().into_inner();
    let mut limits = Limits::default();
    limits.max_members = 1 << 20;
    let mut budget = Budget::with_passwords(limits, vec!["pw".to_string()]);
    let seen = read_back(&zip, &mut budget);
    assert_eq!(seen.len(), 70_001);
    assert_eq!(seen[69_999].0, "m69999");
    assert_eq!(seen[70_000].0, "locked");
    if cfg!(feature = "decrypt") {
        assert_eq!(seen[70_000].2, b"the secret");
    }
}
