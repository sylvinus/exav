//! `Target:11` (Flash) signatures must run on SWF movies and nowhere else.
//!
//! 257 official signatures — 94 `.ldb` and 163 `.ndb` — key on target 11. They
//! loaded fine but never fired, because `target_ok` had no `FileType` to gate
//! them on and defaulted to "skip". That is a silent clean by omission: the
//! signature is in the database, the file is an SWF, and the scan returns `OK`.
//!
//! The gate has to be exact in both directions, so each case below was first
//! run through clamscan with a single-signature database to establish what
//! ClamAV does:
//!
//! * `FWS` (uncompressed) — FOUND. Uncompressed movies are still SWF, and the
//!   magic is the bare three bytes: a garbage version byte and a nonsense length
//!   field do not stop it typing as SWF.
//! * `CWS` (zlib) — FOUND, both because the container itself is typed SWF and
//!   because the inflated body is scanned.
//! * an untyped binary and a PE carrying the identical bytes — OK. A target-11
//!   signature must not reach content that merely contains the pattern.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};

/// A distinctive body, present verbatim in every fixture below. Only the file's
/// *type* differs between them, so any difference in verdict is attributable to
/// the target gate alone.
const BODY: &[u8] = b"exav-flash-target-probe-\x01\x02\x03-end";

fn scanner() -> Scanner {
    let hex: String = BODY.iter().map(|b| format!("{b:02x}")).collect();
    let mut loader = loader::Builder::new();
    loader.add_named_bytes(
        "t.ndb",
        format!("Test.Swf.Target11:11:*:{hex}\n").as_bytes(),
        true,
    );
    loader.build().expect("single-signature database")
}

fn swf(magic: &[u8; 3], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::from(*magic);
    v.push(9); // SWF version
    v.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn verdict(db: &Scanner, blob: &[u8]) -> Verdict {
    analyze(db, blob, &ScanOptions::default()).verdict
}

fn assert_found(db: &Scanner, blob: &[u8], what: &str) {
    match verdict(db, blob) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Test.Swf.Target11", "{what}")
        }
        other => panic!("{what}: a Target:11 signature must fire here, got {other:?}"),
    }
}

#[test]
fn an_uncompressed_movie_is_typed_flash() {
    let db = scanner();
    assert_found(&db, &swf(b"FWS", BODY), "FWS");
}

#[test]
fn a_garbage_header_after_the_magic_does_not_lose_the_type() {
    // clamscan still types these as SWF, so validating the header here would
    // cost detections rather than prevent false positives. A malformed movie is
    // exactly what a dropper ships.
    let db = scanner();
    let mut junk = Vec::from(*b"FWS");
    junk.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff]);
    junk.extend_from_slice(BODY);
    assert_found(&db, &junk, "FWS with a nonsense version and length");
}

#[test]
#[cfg(feature = "swf")]
fn a_compressed_movie_is_reached_through_its_inflated_body() {
    use std::io::Write;
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    // Pad so the payload cannot survive compression as a recognisable literal:
    // a match then proves the movie was actually inflated.
    let mut body = vec![0u8; 64];
    body.extend_from_slice(BODY);
    z.write_all(&body).unwrap();
    let deflated = z.finish().unwrap();
    let mut cws = Vec::from(*b"CWS");
    cws.push(9);
    cws.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    cws.extend_from_slice(&deflated);
    assert!(
        !cws.windows(BODY.len()).any(|w| w == BODY),
        "the compressed movie must not expose the payload in its own bytes, or \
         this test would pass on the raw container scan and prove nothing"
    );
    assert_found(&scanner(), &cws, "CWS");
}

#[test]
fn the_same_bytes_in_a_non_flash_file_do_not_fire() {
    let db = scanner();
    // Untyped binary: a leading NUL forces `Unknown` rather than `Text`.
    let mut blob = vec![0u8, 1, 2, 3];
    blob.extend_from_slice(BODY);
    assert!(
        matches!(verdict(&db, &blob), Verdict::Clean),
        "a Target:11 signature must not reach an untyped binary"
    );

    // And a PE, the type most likely to carry an embedded movie's bytes.
    let mut pe = Vec::from(*b"MZ\x90\x00\x00\x00\x00\x00");
    pe.extend_from_slice(BODY);
    assert!(
        matches!(verdict(&db, &pe), Verdict::Clean),
        "a Target:11 signature must not reach a PE"
    );
}
