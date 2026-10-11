//! A file past `deep_analysis_max` is scanned in full, or reported as over the
//! size limit, whichever entry point sees it.
//!
//! Past that size the file is read through a block cache rather than held,
//! and everything that can run that way does. What cannot is named as the
//! size limit: a container whose format is read whole, and the parts of a
//! scan that need spill space when the host provides none.
//!
//! [`scan_path`] and [`scan_seekable`] reach that decision by separate routes —
//! one buffers from a `File`, the other from a `Read + Seek` that may be an
//! HTTP range source — and the daemon picks between them by verb. Two routes
//! and one rule, so the rule needs a test on both or they drift.

use exav_core::spill::{Spill, SpillReader, SpillWriter};
use exav_core::{loader, scan_path, scan_seekable, ScanOptions, Scanner, Verdict};
use std::io::Write;

/// Spill space held in memory.
struct MemSpill;

struct MemFile(Vec<u8>);

impl Spill for MemSpill {
    fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
        Ok(Box::new(MemFile(Vec::new())))
    }
}

impl SpillWriter for MemFile {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
        Ok(Box::new(std::io::Cursor::new(self.0)))
    }
}

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

/// A ZIP is walked member by member at any size, and past the cap its own
/// bytes get the full engine read through the cache. A member that large, or
/// text whose normalised views are that large, needs spill space: without it
/// that is the size limit, named as one, and with it the scan is complete.
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
        .map(|i| (format!("m{i}.bin"), vec![0u8; 200]))
        .collect();
    let many_small = zip_of(&many_small);
    let report = scan_seekable(
        &db,
        std::io::Cursor::new(many_small.clone()),
        many_small.len() as u64,
        &tiny_deep_analysis(),
    )
    .expect("scan");
    assert_eq!(
        report.verdict,
        Verdict::Clean,
        "every member and byte was scanned"
    );

    let one_large = vec![("big.txt".to_string(), vec![b'a'; 64 * 1024])];
    let flat = vec![b'a'; 64 * 1024];
    for blob in [zip_of(&one_large), flat] {
        let mut spilling = tiny_deep_analysis();
        spilling.spill = Some(std::sync::Arc::new(MemSpill));
        let report = scan_seekable(
            &db,
            std::io::Cursor::new(blob.clone()),
            blob.len() as u64,
            &spilling,
        )
        .expect("scan");
        assert_eq!(report.verdict, Verdict::Clean, "a spill completes the scan");
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

/// A DMG is walked off its source, decompressing only what the filesystem
/// reaches, so its files are scanned at any size.
#[cfg(feature = "all-formats")]
#[test]
fn an_oversize_disk_image_has_its_files_scanned() {
    let mut l = loader::Builder::new();
    // "hello hfs+", the one file on the image.
    l.add_named_bytes("t.ndb", b"Zzz.InDmg:0:*:68656c6c6f206866732b\n", true);
    let db = l.build().expect("build database");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/dmg/hfs_plus_udzo.dmg"
    );
    let blob = std::fs::read(path).unwrap();
    assert!(blob.len() > 4096);
    assert!(!blob.windows(10).any(|w| w == b"hello hfs+"), "compressed");
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_deep_analysis()).expect("scan");
    match report.verdict {
        Verdict::Infected { signature, .. } => assert_eq!(signature, "Zzz.InDmg"),
        other => panic!("expected the file on the image to be found, got {other:?}"),
    }
}

#[test]
fn oversize_flat_content_is_a_limit_too() {
    // Text past the cap has its normalised views made in spill space. With
    // none, those views were not scanned, so the file was not fully scanned.
    let db = scanner();
    let blob = vec![b'a'; 64 * 1024];
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_deep_analysis()).expect("scan");
    match report.verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("text past the cap had no views scanned; got {other:?}"),
    }
}
