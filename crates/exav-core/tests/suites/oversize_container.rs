//! An oversize container is never clean, whichever entry point sees it.
//!
//! Past `deep_analysis_max` the structural walk does not run: the flat
//! pattern+hash core reads the bytes and that is all. For flat content that is
//! a complete scan and `Clean` is the truth. For a container it is not — the
//! members were never opened, so nothing that only structural parsing finds
//! could have fired, and reporting `Clean` is the never-a-silent-clean
//! invariant broken in the one case where the file is large enough to be worth
//! hiding something in.
//!
//! [`scan_path`] and [`scan_seekable`] reach that decision by separate routes —
//! one buffers from a `File`, the other from a `Read + Seek` that may be an
//! HTTP range source — and the daemon picks between them by verb. Two routes
//! and one rule, so the rule needs a test on both or they drift.

use exav_core::{loader, scan_path, scan_seekable, ScanOptions, Scanner, Verdict};
use std::io::Write;

fn scanner() -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", b"Zzz.Never:0:*:deadbeefdeadbeefdead\n", true);
    l.build().expect("build database")
}

/// A RAR header followed by padding. RAR is a container that is not walked off
/// a stream (its directory lives at the end), so it takes the buffer-or-refuse
/// path rather than the member-by-member one — which is the path under test.
/// The body is deliberately not a valid archive: the point is that exav refuses
/// *before* it would find that out.
fn oversize_rar() -> Vec<u8> {
    let mut v = b"Rar!\x1a\x07\x00".to_vec();
    v.resize(64 * 1024, 0);
    v
}

fn tiny_deep_analysis() -> ScanOptions {
    ScanOptions {
        deep_analysis_max: 4096,
        ..ScanOptions::default()
    }
}

#[test]
fn scan_seekable_refuses_an_oversize_container() {
    let db = scanner();
    let blob = oversize_rar();
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_deep_analysis()).expect("scan");
    match report.verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!(
            "an oversize RAR was never unpacked, so its members were never scanned. \
             Expected LIMITS-EXCEEDED, got {other:?} — which renders as OK."
        ),
    }
}

#[test]
fn scan_path_refuses_the_same_container() {
    let db = scanner();
    let dir =
        std::env::temp_dir().join(format!("exav-oversize-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("big.rar");
    std::fs::File::create(&path)
        .expect("create")
        .write_all(&oversize_rar())
        .expect("write");

    let report = scan_path(&db, &path, &tiny_deep_analysis()).expect("scan");
    let _ = std::fs::remove_dir_all(&dir);
    match report.verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("expected LIMITS-EXCEEDED from scan_path, got {other:?}"),
    }
}

#[test]
fn oversize_flat_content_stays_clean() {
    // The counterweight: the refusal above has to be about containers, not
    // about size. A large text file was fully examined by the flat core, and
    // downgrading it would make every big log file unscannable.
    let db = scanner();
    let blob = vec![b'a'; 64 * 1024];
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_deep_analysis()).expect("scan");
    match report.verdict {
        Verdict::Clean => {}
        other => panic!("flat content past the cap is fully scanned; got {other:?}"),
    }
}
