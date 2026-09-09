//! ARC — the pre-ZIP SEA format, plus the PKARC/PAK variants.
//!
//! Worth having because The Unarchiver, 7-Zip and Microsoft's RecursiveExtractor
//! all still open one: exav's rule is the union of what a victim's tools open.
//! Before this, an `.arc` was not recognised at all and its members went
//! unscanned with nothing reported.
//!
//! Fixtures come from **`arc` 5.21q**, the original SEA-lineage tool, and one
//! from Microsoft's RecursiveExtractor test corpus (MIT). Listings were
//! cross-checked against **`nomarch`**, an independent decoder.
//!
//! The archive stores a CRC-16 of each member's uncompressed bytes, which exav
//! checks on every decode — so a fixture that decoded wrongly would be reported
//! unreadable and never reach the digest comparisons here.
//!
//! Regenerate with:
//! ```sh
//! arc a sample.arc eicar.com text.txt dle.bin   # stored + crunched (method 8)
//! arc as stored.arc eicar.com                   # -s suppresses compression
//! ```

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const TEXT: &str = "080d15586f0165e6fe26ccc32060051fb67344c54691e3bca8ea7871b2c5d23f";
const DLE: &str = "10fddcc6c3ef0721ffd392913aa7c2bc763ad13738add4105153ef276a20b39e";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/arc/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Arc,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

fn contents(name: &str) -> Vec<(String, String)> {
    let e = members(&fixture(name));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "{name}: nothing should be unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let mut got: Vec<(String, String)> = e
        .iter()
        .map(|x| (x.name.clone(), sha256_hex(&x.data)))
        .collect();
    got.sort();
    got
}

#[test]
fn stored_and_crunched_members_decode_to_their_originals() {
    // `dle.bin` is the one that matters: it holds literal 0x90 bytes, which is
    // the run-length escape, plus long runs — so it exercises both sides of the
    // `DLE n` / `DLE 00` rule that the crunched methods apply after LZW.
    let mut want = vec![
        ("dle.bin".to_string(), DLE.to_string()),
        ("eicar.com".to_string(), EICAR.to_string()),
        ("text.txt".to_string(), TEXT.to_string()),
    ];
    want.sort();
    assert_eq!(contents("sample.arc"), want);
}

#[test]
fn a_stored_only_archive_decodes() {
    assert_eq!(
        contents("stored.arc"),
        vec![("eicar.com".to_string(), EICAR.to_string())]
    );
}

#[test]
fn a_third_party_archive_decodes() {
    // From Microsoft's RecursiveExtractor corpus — a different writer, and one
    // that happens to NUL-pad the name field where `arc` leaves garbage there.
    let e = members(&fixture("microsoft_testdata.arc"));
    assert!(
        e.iter()
            .any(|x| x.name == "TestFile.txt" && !x.data.is_empty()),
        "expected TestFile.txt, got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
}

#[test]
fn detection_needs_more_than_the_two_byte_marker() {
    // `1A` plus a method byte is two bytes; on its own that is far too weak, and
    // a false positive would hand the file to the wrong extractor so its real
    // format never gets tried. Detection therefore requires a printable name and
    // a declared size that chains to the next header or the end marker.
    assert_eq!(detect(&fixture("sample.arc")), Some(Format::Arc));

    // Marker and a plausible method, but nothing else about it is an archive.
    let mut junk = vec![0xAAu8; 4096];
    junk[0] = 0x1A;
    junk[1] = 2;
    assert_ne!(detect(&junk), Some(Format::Arc));

    // A printable name, but the size points into the middle of nowhere.
    let mut fake = vec![0u8; 4096];
    fake[0] = 0x1A;
    fake[1] = 2;
    fake[2..11].copy_from_slice(b"thing.txt");
    fake[15..19].copy_from_slice(&3000u32.to_le_bytes());
    fake[3000 + 29] = 0x77;
    assert_ne!(detect(&fake), Some(Format::Arc));
}

#[test]
fn a_truncated_archive_yields_what_it_can_without_panicking() {
    let full = fixture("sample.arc");
    for n in [8, 29, 64, full.len() / 2, full.len() - 1] {
        let mut b = Budget::new(Limits::default());
        let _ = extract_each(
            Format::Arc,
            &full[..n],
            &mut b,
            &mut |_: Entry, _: &mut Budget| None::<()>,
        );
    }
}
