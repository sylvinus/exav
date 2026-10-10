//! A ZIP member compressed with PPMd (method 98), as 7-Zip and WinZip write
//! it, at the verdict level: its content is scanned.

use std::io::Write;

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// The 2-byte parameter header (APPNOTE 5.10.4) and the stream from the
/// reference `ppmd-rust` PPMd8 encoder: order 6, 1 MB, restart.
fn ppmd_member(data: &[u8]) -> Vec<u8> {
    let mut out = (6u16 - 1).to_le_bytes().to_vec();
    let mut enc =
        ppmd_rust::Ppmd8Encoder::new(&mut out, 6, 1 << 20, ppmd_rust::RestoreMethod::Restart)
            .unwrap();
    enc.write_all(data).unwrap();
    enc.finish(false).unwrap();
    out
}

/// A one-member ZIP, central directory included.
fn zip_one(name: &str, method: u16, packed: &[u8], data: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    let fields = |v: &mut Vec<u8>| {
        v.extend_from_slice(&63u16.to_le_bytes()); // version needed (PPMd: 6.3)
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&method.to_le_bytes());
        v.extend_from_slice(&[0; 4]); // time, date
        v.extend_from_slice(&crc.sum().to_le_bytes());
        v.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // extra
    };
    let mut z = b"PK\x03\x04".to_vec();
    fields(&mut z);
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(packed);
    let cd_at = z.len() as u32;
    let mut cd = b"PK\x01\x02".to_vec();
    cd.extend_from_slice(&63u16.to_le_bytes()); // version made by
    fields(&mut cd);
    cd.extend_from_slice(&[0; 6]); // comment length, disk, internal attrs
    cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    cd.extend_from_slice(name.as_bytes());
    z.extend_from_slice(&cd);
    z.extend_from_slice(b"PK\x05\x06");
    z.extend_from_slice(&[0; 4]); // disk numbers
    z.extend_from_slice(&1u16.to_le_bytes());
    z.extend_from_slice(&1u16.to_le_bytes());
    z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    z.extend_from_slice(&cd_at.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

#[test]
fn eicar_in_a_ppmd_member_is_found() {
    let db = Scanner::builtin();
    let blob = zip_one("eicar.com", 98, &ppmd_member(eicar()), eicar());
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR in a PPMd ZIP member must be FOUND, got {other:?}"),
    }
}

/// A PPMd stream that does not decode leaves the member unexamined: never
/// clean. Its first four bytes all ones are a start value the range decoder
/// refuses. (A stream that only runs out is not this: its rest is absent.)
#[test]
fn undecodable_ppmd_member_is_not_clean() {
    let db = Scanner::builtin();
    let text = b"harmless text, harmless text, harmless text";
    let mut packed = ppmd_member(text);
    packed[2..6].fill(0xff);
    let blob = zip_one("text.txt", 98, &packed, text);
    let verdict = analyze(&db, &blob, &ScanOptions::default()).verdict;
    assert!(
        !matches!(verdict, Verdict::Clean),
        "a PPMd member exav could not decode must never be reported Clean"
    );
}
