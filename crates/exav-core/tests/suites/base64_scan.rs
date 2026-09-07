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

#[test]
fn base64_scan_off_leaves_it_clean() {
    // With decoding disabled (as under --clamav-compat / --no-base64) the base64
    // text is inert — the PE never materializes, so the script scans clean.
    let db = Scanner::builtin();
    let blob = script_with_base64(&eicar_pe());
    let opts = ScanOptions {
        decode_base64: false,
        ..ScanOptions::default()
    };
    assert!(
        matches!(analyze(&db, &blob, &opts).verdict, Verdict::Clean),
        "base64 scan disabled should leave the carrier clean"
    );
}
