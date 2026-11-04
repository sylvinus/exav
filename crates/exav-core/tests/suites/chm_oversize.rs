//! A CHM past `limits.max_buffer_bytes` has its files scanned, from the file as it
//! lies, whichever entry point reads it.
//!
//! The fixture's topic is LZX-compressed, so its marker is in no byte of the
//! file: only the decoded member holds it. The directory, the stored files and
//! the LZX frames are read through the block cache, one frame at a time.

use exav_core::{ScanOptions, Scanner, Verdict, loader, scan_path, scan_seekable};
use std::io::Cursor;

const MARKER: &[u8] = b"EXAV-LZX-OK";

fn chm() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/chm/benign-lzx.chm"
    );
    let blob = std::fs::read(path).unwrap();
    assert!(
        !blob.windows(MARKER.len()).any(|w| w == MARKER),
        "the marker must be inside compressed bytes"
    );
    blob
}

fn scanner(signature: &[u8]) -> Scanner {
    let hex: String = signature.iter().map(|b| format!("{b:02x}")).collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", format!("Zzz.InChm:0:*:{hex}\n").as_bytes(), true);
    l.build().expect("build database")
}

/// Under the file's size, over every member's.
fn small_object_limit() -> ScanOptions {
    let mut o = ScanOptions::default();
    o.limits.max_buffer_bytes = 8192;
    o
}

/// The verdicts of the two entry points; `tag` keeps the temporary files of
/// tests running together apart.
fn scan_both(db: &Scanner, blob: &[u8], tag: &str) -> Vec<Verdict> {
    let opts = small_object_limit();
    assert!(blob.len() as u64 > opts.limits.max_buffer_bytes);
    let seekable = scan_seekable(db, Cursor::new(blob.to_vec()), blob.len() as u64, &opts)
        .expect("scan")
        .verdict;
    let dir = std::env::temp_dir().join(format!("exav-chm-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("big.chm");
    std::fs::write(&path, blob).expect("write");
    let by_path = scan_path(db, &path, &opts).expect("scan").verdict;
    let _ = std::fs::remove_dir_all(&dir);
    vec![seekable, by_path]
}

/// Before the CHM reader took a source, a file past the limit was refused as
/// read whole: the member was never decoded, and the scan ended at the limit.
#[test]
fn a_file_of_an_oversize_chm_is_scanned() {
    let db = scanner(MARKER);
    for verdict in scan_both(&db, &chm(), "found") {
        match verdict {
            Verdict::Infected { signature, .. } => assert_eq!(signature, "Zzz.InChm"),
            other => panic!("the marker in the compressed topic was not found: {other:?}"),
        }
    }
}

/// With nothing to find, every file was read: the scan is complete, not
/// reported as over the size limit.
#[test]
fn an_oversize_chm_with_nothing_in_it_is_clean() {
    let db = scanner(b"never in this file");
    for verdict in scan_both(&db, &chm(), "clean") {
        assert_eq!(verdict, Verdict::Clean);
    }
}
