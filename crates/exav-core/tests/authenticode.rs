//! End-to-end: the opt-in Authenticode heuristic flags a code-signed PE whose
//! embedded digest does not cover the file (tampered / appended-to after
//! signing), and stays silent unless the flag is set.

use exav_core::{analyze, Database, ScanOptions, Verdict};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/authenticode/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// A `.crb` block-list entry for the signer certificate flags the signed PE by
/// name — no opt-in flag needed (it is signature-based, like a hash detection).
#[test]
fn crb_blocklist_flags_signed_pe() {
    // SHA-1 of the fixture cert's subject DN.
    let subj = "2c190fb742c4be7399e7706dd24610807dc9860c";
    let crb = format!("Malware.StolenCert;0;{subj};\n");
    let mut loader = exav_core::db::Loader::new();
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

#[test]
fn broken_authenticode_flagged_only_when_opted_in() {
    let db = Database::builtin();
    let pe = fixture("signed_mismatch.exe");

    // Opt-in: the digest doesn't cover the file → HashMismatch.
    let opts = ScanOptions {
        alert_broken_authenticode: true,
        ..ScanOptions::default()
    };
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
