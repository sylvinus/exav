//! End-to-end: the opt-in Authenticode heuristic flags a code-signed PE whose
//! embedded digest does not cover the file (tampered / appended-to after
//! signing), and stays silent unless the flag is set.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/authenticode/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// A `.crb` block-list entry for the signer certificate flags the signed PE by
/// name — no opt-in flag needed (it is signature-based, like a hash detection).
#[test]
fn crb_blocklist_flags_signed_pe() {
    // SHA-1 of the fixture cert's subject DN.
    let subj = "2c190fb742c4be7399e7706dd24610807dc9860c";
    let crb = format!("Malware.StolenCert;0;{subj};\n");
    let mut loader = exav_core::loader::Builder::new();
    loader.add_named_bytes("block.crb", crb.as_bytes(), true);
    let db = loader.build().expect("build db");

    let pe = fixture("signed_mismatch.exe");
    match analyze(&db, &pe, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Malware.StolenCert", "unexpected {signature}")
        }
        other => panic!("expected .crb cert-blocklist detection, got {other:?}"),
    }
}

/// A signed PE whose section runs past the end of the file, its signer on a
/// loaded `.crb` block-list: the check answers rather than panicking, and the
/// signer's certificate, which is in the file, is still found.
#[test]
fn a_signed_pe_whose_section_runs_past_the_file_is_still_checked() {
    let subj = "2c190fb742c4be7399e7706dd24610807dc9860c";
    let mut loader = exav_core::loader::Builder::new();
    loader.add_named_bytes(
        "block.crb",
        format!("Malware.StolenCert;0;{subj};\n").as_bytes(),
        true,
    );
    let db = loader.build().expect("build db");

    let mut pe = fixture("signed_mismatch.exe");
    let at = u32::from_le_bytes(pe[0x3c..0x40].try_into().unwrap()) as usize;
    let opt_len = u16::from_le_bytes(pe[at + 20..at + 22].try_into().unwrap()) as usize;
    let first = at + 24 + opt_len;
    // The first section's PointerToRawData, far past the end.
    pe[first + 20..first + 24].copy_from_slice(&0xE727_0000u32.to_le_bytes());
    match analyze(&db, &pe, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(signature, "Malware.StolenCert"),
        other => panic!("expected the block-listed signer, got {other:?}"),
    }
}

#[test]
fn broken_authenticode_flagged_only_when_opted_in() {
    let db = Scanner::builtin();
    let pe = fixture("signed_mismatch.exe");

    // Opt-in: the digest doesn't cover the file → HashMismatch.
    let mut opts = ScanOptions::default();
    opts.alert_broken_authenticode = true;
    match analyze(&db, &pe, &opts).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(
            signature, "Heuristics.Authenticode.HashMismatch",
            "unexpected signature {signature}"
        ),
        other => panic!("expected HashMismatch, got {other:?}"),
    }

    // Default (flag off): the heuristic must not fire.
    match analyze(&db, &pe, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } if signature.contains("Authenticode") => {
            panic!("Authenticode heuristic fired without the opt-in flag")
        }
        _ => {}
    }
}
