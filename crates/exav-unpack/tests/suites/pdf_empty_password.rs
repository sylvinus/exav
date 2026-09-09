//! Encrypted PDFs that use the EMPTY user password (the overwhelming majority of
//! "encrypted" malicious PDFs — they encrypt only to obstruct scanners, and open
//! with no prompt) must be transparently decrypted and scanned, across every
//! standard-security revision: R3/R4 (RC4) and R6 (AES-256). No password supplied.
use exav_unpack::{extract, Budget, Format, Limits};

fn recovers_eicar(fixture: &str) -> bool {
    let p = format!(
        "{}/tests/fixtures/pdf/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    );
    let blob = exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut b = Budget::new(Limits::default());
    let entries = extract(Format::Pdf, &blob, &mut b).unwrap();
    entries
        .iter()
        .any(|e| e.data.windows(5).any(|w| w == b"EICAR"))
}

#[test]
fn empty_password_rc4_r3() {
    assert!(
        recovers_eicar("empty_rc4_r3.pdf"),
        "RC4 R3 empty-password PDF must decrypt"
    );
}

#[test]
fn empty_password_rc4_r4() {
    assert!(
        recovers_eicar("empty_rc4_r4.pdf"),
        "RC4 R4 empty-password PDF must decrypt"
    );
}

#[test]
fn empty_password_aesv3_r6() {
    assert!(
        recovers_eicar("empty_aesv3_r6.pdf"),
        "AES-256 R6 empty-password PDF must decrypt"
    );
}

/// A truncated/corrupt FlateDecode stream must still yield the bytes inflated
/// before the error — a payload in the recoverable prefix must not be discarded.
#[test]
fn truncated_flate_stream_is_salvaged() {
    assert!(
        recovers_eicar("truncated_flate.pdf"),
        "EICAR in the recoverable prefix of a truncated FlateDecode stream must be found"
    );
}
