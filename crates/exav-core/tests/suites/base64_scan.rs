//! End-to-end test for the base64-embedded-executable scan: a text/script
//! carrier that stashes a PE as a base64 string (the PowerShell reflective-loader
//! pattern) is detected when — and only when — `decode_base64` is on.

use base64::Engine;
use exav_core::{analyze, ScanOptions, Scanner, Verdict};

// The standard EICAR test string — the built-in DB carries a signature for it.
// Assembled at runtime; see `exav_core::unpack::eicar` for why it is never a
// literal anywhere in this tree.
fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// A minimal but structurally valid PE (MZ + e_lfanew → `PE\0\0`) that embeds the
/// EICAR string, padded so its base64 encoding exceeds the scan's minimum run.
fn eicar_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
    pe[0x80..0x80 + eicar().len()].copy_from_slice(eicar());
    pe
}

fn script_with_base64(pe: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pe);
    format!(
        "# dropper\r\n$PEBytes = \"{b64}\"\r\nInvoke-ReflectivePEInjection -PEBytes $PEBytes\r\n"
    )
    .into_bytes()
}

#[test]
fn base64_embedded_pe_detected_by_default() {
    let db = Scanner::builtin();
    let blob = script_with_base64(&eicar_pe());
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => {
            assert!(
                signature.to_ascii_lowercase().contains("eicar"),
                "expected EICAR from the decoded PE, got {signature}"
            );
        }
        other => panic!("expected the base64-embedded PE to be detected, got {other:?}"),
    }
}

/// The `.sfp` allowlist applies to every object, a payload decoded out of
/// another included: the PE whose SHA-256 is on it is not reported, and the
/// carrier is then clean.
#[test]
fn an_allowlisted_decoded_payload_is_not_reported() {
    use sha2::{Digest, Sha256};
    // A multiple of 3 bytes, so its base64 ends on a whole group.
    let mut pe = eicar_pe();
    pe.resize(2049, 0);
    let sha: String = Sha256::digest(&pe).iter().map(|b| format!("{b:02x}")).collect();
    let mut b = exav_core::loader::Builder::new();
    b.add_named_bytes("x.sfp", format!("{sha}:{}:Allowed.Pe\n", pe.len()).as_bytes(), false);
    let db = b.build().unwrap();
    let blob = script_with_base64(&pe);
    let v = analyze(&db, &blob, &ScanOptions::default()).verdict;
    assert!(matches!(v, Verdict::Clean), "{v:?}");
    // The entry is what clears it.
    assert!(matches!(
        analyze(&Scanner::builtin(), &blob, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    ));
}

#[test]
fn base64_scan_off_leaves_it_clean() {
    // With decoding disabled (as under --clamav-compat / --no-base64) the base64
    // text is inert — the PE never materializes, so the script scans clean.
    let db = Scanner::builtin();
    let blob = script_with_base64(&eicar_pe());
    let mut opts = ScanOptions::default();
    opts.decode_base64 = false;
    assert!(
        matches!(analyze(&db, &blob, &opts).verdict, Verdict::Clean),
        "base64 scan disabled should leave the carrier clean"
    );
}
