//! A ZIP whose central directory and local headers disagree holds one member for
//! a reader that believes the directory (the `zip` crate, 7-Zip) and another for
//! a reader that believes the local header (Info-ZIP `unzip`). Each is a thing
//! a user extracts, so a payload in either must be scanned.
//!
//! Each archive here has a member whose payload is deflated EICAR, and one field
//! of its directory record that does not match its local header. Nothing in the
//! file is the string itself, so only a reader that decodes the member the way
//! the local header says finds it.

use exav_unpack::{Budget, Format, Limits, Member, MemberMeta, extract, walk};
use std::io::Write;

fn eicar_text() -> Vec<u8> {
    // Repetitive, so that deflate codes it and the string is not in the bytes.
    [exav_unpack::eicar(), b"\n"].concat().repeat(40)
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// What a header says of the member.
#[derive(Clone)]
struct Fields {
    method: u16,
    comp: u32,
    usize_: u32,
    name: &'static str,
}

/// A one-member ZIP: `local` is the local header's reading, `dir` the central
/// directory's, `data` what lies after the local header.
fn zip(local: &Fields, dir: &Fields, data: &[u8], crc: u32) -> Vec<u8> {
    let mut z = Vec::new();
    z.extend_from_slice(b"PK\x03\x04");
    z.extend_from_slice(&20u16.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(&local.method.to_le_bytes());
    z.extend_from_slice(&[0; 4]);
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&local.comp.to_le_bytes());
    z.extend_from_slice(&local.usize_.to_le_bytes());
    z.extend_from_slice(&(local.name.len() as u16).to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(local.name.as_bytes());
    z.extend_from_slice(data);
    let cd_at = z.len() as u32;
    let mut cd = b"PK\x01\x02".to_vec();
    cd.extend_from_slice(&20u16.to_le_bytes());
    cd.extend_from_slice(&20u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&dir.method.to_le_bytes());
    cd.extend_from_slice(&[0; 4]);
    cd.extend_from_slice(&crc.to_le_bytes());
    cd.extend_from_slice(&dir.comp.to_le_bytes());
    cd.extend_from_slice(&dir.usize_.to_le_bytes());
    cd.extend_from_slice(&(dir.name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&[0; 12]);
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(dir.name.as_bytes());
    z.extend_from_slice(&cd);
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    z.extend_from_slice(&cd_at.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

/// Every member the two paths a scan takes find, their bytes.
fn members(blob: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut budget = Budget::new(Limits::default());
    let mut buffered = Vec::new();
    if let Ok(entries) = extract(Format::Zip, &blob, &mut budget) {
        buffered = entries.into_iter().map(|e| e.data).collect();
    }
    let mut budget = Budget::new(Limits::default());
    let mut streamed = Vec::new();
    let mut visit = |_: &MemberMeta, content: Option<Member<'_>>, _: &mut Budget| {
        match content {
            Some(Member::Bytes(d)) => streamed.push(d),
            Some(Member::Stream(r)) => {
                // A member the directory misdescribes may fail its checksum
                // part way; what was read is what a scan would have matched.
                let mut d = Vec::new();
                let _ = std::io::Read::read_to_end(r, &mut d);
                streamed.push(d);
            }
            None => {}
        }
        None::<()>
    };
    let _ = walk(Format::Zip, &blob, &mut budget, &mut visit);
    (buffered, streamed)
}

fn holds_the_payload(found: &[Vec<u8>]) -> bool {
    let eicar = exav_unpack::eicar();
    found
        .iter()
        .any(|d| d.windows(eicar.len()).any(|w| w == eicar))
}

fn assert_both_paths_find_it(name: &str, blob: &[u8]) {
    let eicar = exav_unpack::eicar();
    assert!(
        !blob.windows(eicar.len()).any(|w| w == eicar),
        "{name}: the string must not be in the file's bytes"
    );
    let (buffered, streamed) = members(blob);
    assert!(
        holds_the_payload(&buffered),
        "{name}: the buffered path missed it"
    );
    assert!(
        holds_the_payload(&streamed),
        "{name}: the streaming path missed it"
    );
}

#[test]
fn a_directory_that_says_stored_for_a_deflated_member() {
    let text = eicar_text();
    let comp = deflate(&text);
    let local = Fields {
        method: 8,
        comp: comp.len() as u32,
        usize_: text.len() as u32,
        name: "e.com",
    };
    // Same size, so a reader that takes the directory at its word takes the
    // compressed bytes for the file.
    let dir = Fields {
        method: 0,
        ..local.clone()
    };
    assert_both_paths_find_it("method", &zip(&local, &dir, &comp, crc32(&text)));
}

#[test]
fn a_directory_that_gives_a_deflated_member_no_size() {
    let text = eicar_text();
    let comp = deflate(&text);
    let local = Fields {
        method: 8,
        comp: comp.len() as u32,
        usize_: text.len() as u32,
        name: "e.com",
    };
    for short in [0, 3] {
        let dir = Fields {
            comp: short,
            ..local.clone()
        };
        assert_both_paths_find_it(
            &format!("size {short}"),
            &zip(&local, &dir, &comp, crc32(&text)),
        );
    }
}

#[test]
fn a_directory_that_names_the_member_as_another() {
    // The record's name is not the local header's: `unzip` goes by the header.
    let text = eicar_text();
    let comp = deflate(&text);
    let local = Fields {
        method: 8,
        comp: comp.len() as u32,
        usize_: text.len() as u32,
        name: "e.com",
    };
    let dir = Fields {
        name: "x.txt",
        method: 0,
        comp: 0,
        usize_: 0,
    };
    assert_both_paths_find_it("name", &zip(&local, &dir, &comp, crc32(&text)));
}

#[test]
fn an_archive_whose_headers_agree_has_no_member_twice() {
    let text = eicar_text();
    let comp = deflate(&text);
    let f = Fields {
        method: 8,
        comp: comp.len() as u32,
        usize_: text.len() as u32,
        name: "e.com",
    };
    let (buffered, streamed) = members(&zip(&f, &f, &comp, crc32(&text)));
    assert_eq!(buffered.len(), 1);
    assert_eq!(streamed.len(), 1);
    assert!(holds_the_payload(&buffered) && holds_the_payload(&streamed));
}
