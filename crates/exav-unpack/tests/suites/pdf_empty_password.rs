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

/// Written by qpdf with its default permissions, `/P -4`. Bit 12 of `/P` was
/// read as `/EncryptMetadata false`, which changes the key, so the empty
/// password never matched and the file came out `PASSWORD-PROTECTED`.
#[test]
fn empty_password_aesv2_r4() {
    assert!(
        recovers_eicar("empty_aesv2_r4.pdf"),
        "AES-128 R4 empty-password PDF must decrypt"
    );
}

#[test]
fn empty_password_aesv3_r6() {
    assert!(
        recovers_eicar("empty_aesv3_r6.pdf"),
        "AES-256 R6 empty-password PDF must decrypt"
    );
}

/// AES (R4 AES-128, R6 AES-256), from qpdf 12.2: `qpdf --encrypt "" "" 128
/// --use-aes=y` and `256`, the EICAR content stream deflated. The 16-byte IV
/// at the front of each encrypted stream is not data; kept, the stream does
/// not inflate.
#[test]
fn a_deflated_stream_decrypts_and_inflates_under_aes() {
    for f in ["eicar_qpdf_aesv2_r4.pdf", "eicar_qpdf_aesv3_r6.pdf"] {
        assert!(recovers_eicar(f), "{f}");
    }
}

/// The strings of an AES-encrypted PDF carry the IV in front of their
/// ciphertext too: an OpenAction's script and a link's URI come out as they
/// were written, nothing before them. qpdf 12.2, `--encrypt "" "" 128
/// --use-aes=y` and `256`.
#[test]
fn aes_encrypted_script_and_uri_strings_come_out_exact() {
    for f in ["qpdf_actions_aes128.pdf", "qpdf_actions_aes256.pdf"] {
        let p = format!("{}/tests/fixtures/pdf/{f}", env!("CARGO_MANIFEST_DIR"));
        let blob = std::fs::read(&p).unwrap();
        let entries = extract(Format::Pdf, &blob, &mut Budget::new(Limits::default())).unwrap();
        let get = |name: &str| {
            entries
                .iter()
                .find(|e| e.name == name)
                .map(|e| String::from_utf8_lossy(&e.data).into_owned())
                .unwrap_or_else(|| panic!("{f}: no {name}"))
        };
        assert_eq!(
            get("pdf-javascript"),
            "app.alert('exav-js-marker');\n",
            "{f}"
        );
        assert_eq!(get("pdf-uris"), "http://exav.invalid/landing\n", "{f}");
    }
}

/// RC4 with a 40-bit key (R2), the content stream in object `4 1`: its key is
/// the file key, the object number and the generation hashed, cut to 10
/// bytes. Encrypted per ISO 32000-1 7.6.3 by hand, as no writer keeps a
/// non-zero generation, and checked with `qpdf --decrypt`.
#[test]
fn rc4_40_decrypts_with_the_object_and_generation_key() {
    assert!(recovers_eicar("eicar_rc4_r2_gen1.pdf"));
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
