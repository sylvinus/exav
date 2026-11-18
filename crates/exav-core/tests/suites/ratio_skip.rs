//! A member over the compression ratio is left out and the walk goes on.
//!
//! The ratio acts on a member whose output passes the object limit
//! (`max_buffer_bytes`); below it a member is held in memory and the memory
//! limits bound it. A member left out marks the scan partial with the reason,
//! and the members after it are still scanned.

use exav_core::{ScanOptions, Scanner, Verdict, analyze};
use std::io::Write;

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// A ZIP of deflated members, in order.
fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, body) in members {
        z.start_file(*name, deflated).unwrap();
        z.write_all(body).unwrap();
    }
    z.finish().unwrap().into_inner()
}

/// EICAR in a form the compressor codes, so that only the member has it.
fn coded_eicar() -> Vec<u8> {
    [eicar(), b"\n"].concat().repeat(64)
}

fn assert_eicar(v: Verdict) {
    match v {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR was not found: {other:?}"),
    }
}

/// A member over the ratio, past the object limit, does not end the walk: the
/// EICAR after it is found; and when nothing else matches the scan is
/// `LIMITS-EXCEEDED` for the ratio.
#[test]
fn a_member_over_the_ratio_does_not_hide_the_members_after_it() {
    let db = Scanner::builtin();
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 64 * 1024;
    // A member over the object limit is spilled, which is where the ratio is checked.
    opts.spill = Some(std::sync::Arc::new(
        exav_core::unpack::spill::MemSpill::new(),
    ));
    opts.limits.max_compression_ratio = 100;
    let zeros = vec![0u8; 1 << 20];

    let eicar_member = coded_eicar();
    let blob = zip_of(&[("zeros.bin", &zeros), ("eicar.txt", &eicar_member)]);
    assert!(
        !blob.windows(eicar().len()).any(|w| w == eicar()),
        "EICAR must be only in the member"
    );
    assert!(
        blob.len() * 100 < zeros.len(),
        "the first member must be a bomb"
    );
    assert_eicar(analyze(&db, &blob, &opts).verdict);

    let blob = zip_of(&[("zeros.bin", &zeros), ("plain.txt", b"nothing to see")]);
    match analyze(&db, &blob, &opts).verdict {
        Verdict::LimitsExceeded { reason } => {
            assert!(reason.contains("zeros.bin"), "{reason}");
            assert!(reason.contains("compression ratio"), "{reason}");
        }
        other => panic!("a member left out must not scan clean: {other:?}"),
    }
}

/// The parts of a split file, held to be joined when the archive ends, are
/// joined and scanned after a member over the ratio: EICAR cut across the two
/// parts is found.
#[test]
fn a_split_file_after_a_member_over_the_ratio_is_joined() {
    let db = Scanner::builtin();
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 64 * 1024;
    opts.spill = Some(std::sync::Arc::new(
        exav_core::unpack::spill::MemSpill::new(),
    ));
    opts.limits.max_compression_ratio = 100;
    let zeros = vec![0u8; 1 << 20];
    let mut payload = vec![b'.'; 2000];
    payload.extend_from_slice(eicar());
    payload.extend_from_slice(&[b'.'; 2000]);
    let cut = 2000 + eicar().len() / 2;
    let blob = zip_of(&[
        ("zeros.bin", &zeros),
        ("notes.bin.001", &payload[..cut]),
        ("notes.bin.002", &payload[cut..]),
    ]);
    assert_eicar(analyze(&db, &blob, &opts).verdict);
}

/// A container inside the archive whose own walk ends in a limit does not end
/// the archive's: the member after it is still scanned, and with nothing found
/// the inner limit is the archive's.
#[test]
fn a_nested_container_over_a_limit_does_not_hide_the_members_after_it() {
    let db = Scanner::builtin();
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 64 * 1024;
    opts.spill = Some(std::sync::Arc::new(
        exav_core::unpack::spill::MemSpill::new(),
    ));
    opts.limits.max_compression_ratio = 100;
    let zeros = vec![0u8; 1 << 20];
    let inner = zip_of(&[("zeros.bin", &zeros), ("plain.txt", b"nothing to see")]);
    let eicar_member = coded_eicar();
    let outer = zip_of(&[("inner.zip", &inner), ("eicar.txt", &eicar_member)]);
    assert_eicar(analyze(&db, &outer, &opts).verdict);
    let outer = zip_of(&[("inner.zip", &inner), ("plain.txt", b"nothing either")]);
    match analyze(&db, &outer, &opts).verdict {
        Verdict::LimitsExceeded { reason } => {
            assert!(reason.contains("compression ratio"), "{reason}")
        }
        other => panic!("a member left out must not scan clean: {other:?}"),
    }
}

/// A member past 1000:1 and past the 4 MiB the ratio used to start at, but
/// within the object limit, is held and scanned whole: no limit is reached
/// and the EICAR at its end is found.
#[test]
fn a_member_past_the_ratio_within_the_object_limit_is_scanned() {
    let db = Scanner::builtin();
    let mut body = vec![0u8; 8 << 20];
    body.extend_from_slice(&coded_eicar());
    let blob = zip_of(&[("big.bin", &body)]);
    assert!(
        blob.len() * 1000 < body.len(),
        "the member must be past 1000:1: {} bytes for {}",
        blob.len(),
        body.len()
    );
    assert_eicar(analyze(&db, &blob, &ScanOptions::default()).verdict);
}
