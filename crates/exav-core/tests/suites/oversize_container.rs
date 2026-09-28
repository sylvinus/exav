//! A file past `deep_analysis_max` is never clean, whichever entry point sees it.
//!
//! Past that size the full engine does not run: the streaming core reads the
//! bytes, and it matches literal signatures and whole-file hashes only. That is
//! not a complete scan of any file, and for a container the members were never
//! opened either, so reporting `Clean` would break the never-a-silent-clean
//! invariant in the one case where the file is large enough to be worth hiding
//! something in.
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
    let mut o = ScanOptions::default();
    o.deep_analysis_max = 4096;
    o
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

/// A ZIP is walked member by member at any size, but past the cap neither its
/// own bytes nor a member that large get the full engine. That is the same
/// size limit, and it is named as one.
#[test]
fn an_oversize_streamed_container_or_member_is_a_limit() {
    let db = scanner();
    let zip_of = |members: &[(String, Vec<u8>)]| {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in members {
            z.start_file(name.as_str(), stored).unwrap();
            z.write_all(body).unwrap();
        }
        z.finish().unwrap().into_inner()
    };
    let many_small: Vec<_> = (0..64)
        .map(|i| (format!("m{i}.txt"), vec![b'a'; 200]))
        .collect();
    let one_large = vec![("big.txt".to_string(), vec![b'a'; 64 * 1024])];
    let flat = vec![b'a'; 64 * 1024];
    for blob in [zip_of(&many_small), zip_of(&one_large), flat] {
        let size = blob.len() as u64;
        let report = scan_seekable(
            &db,
            std::io::Cursor::new(blob.clone()),
            size,
            &tiny_deep_analysis(),
        )
        .expect("scan");
        match report.verdict {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("--max-object-bytes"), "{reason}")
            }
            other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
        }
        // Under ClamAV's naming it is the size alert ClamAV raises.
        let mut alert = tiny_deep_analysis();
        alert.alert_exceeds_max = true;
        let report = scan_seekable(&db, std::io::Cursor::new(blob), size, &alert).expect("scan");
        match report.verdict {
            Verdict::Infected { signature, .. } => {
                assert_eq!(signature, "Heuristics.Limits.Exceeded.MaxFileSize")
            }
            other => panic!("expected the MaxFileSize alert, got {other:?}"),
        }
    }
}

#[test]
fn oversize_flat_content_is_a_limit_too() {
    // Flat content past the cap got the literal-and-hash pass only, so it is
    // not fully scanned either.
    let db = scanner();
    let blob = vec![b'a'; 64 * 1024];
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_deep_analysis()).expect("scan");
    match report.verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("flat content past the cap had a literal-only scan; got {other:?}"),
    }
}
