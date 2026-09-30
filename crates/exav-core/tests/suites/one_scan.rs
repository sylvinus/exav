//! A file path and the same bytes from any other source get one answer: both
//! entry points are the same scan, at every size threshold.

use std::io::Write;

use exav_core::{scan_path, scan_seekable, ScanOptions, Scanner, Verdict};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// The verdicts of `scan_path` and `scan_seekable` on `blob`.
fn both(blob: &[u8], opts: &ScanOptions) -> [(&'static str, Verdict); 2] {
    let db = Scanner::builtin();
    let dir = crate::tmpfile::TempDir::new().unwrap();
    let path = dir.path().join("input");
    std::fs::write(&path, blob).unwrap();
    let file = scan_path(&db, &path, opts).unwrap().verdict;
    let seekable = scan_seekable(&db, std::io::Cursor::new(blob), blob.len() as u64, opts)
        .unwrap()
        .verdict;
    [("scan_path", file), ("scan_seekable", seekable)]
}

fn zip_with(member: &[u8], comment: &str) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.set_comment(comment);
    z.start_file(
        "member.bin",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated),
    )
    .unwrap();
    z.write_all(member).unwrap();
    z.finish().unwrap().into_inner()
}

/// Over `--max-input-bytes` the first bytes get the whole scan, extraction
/// included: EICAR deflated inside a ZIP is not in the file's bytes, and only
/// extraction finds it.
#[test]
fn the_start_of_an_oversize_input_gets_the_whole_scan() {
    // Compressible text first, so the deflater codes EICAR rather than
    // storing it verbatim.
    let mut member = vec![b'a'; 4096];
    member.extend_from_slice(eicar());
    let zip = zip_with(&member, "");
    assert!(!zip.windows(eicar().len()).any(|w| w == eicar()));
    let mut blob = zip.clone();
    blob.extend(vec![0u8; 64 * 1024]);
    let mut opts = ScanOptions::default();
    opts.max_scan_size = Some(zip.len() as u64 + 512);
    for (entry, v) in both(&blob, &opts) {
        assert!(matches!(v, Verdict::Infected { .. }), "{entry}: {v:?}");
    }

    // A payload past the limit is not scanned, and the input is not clean.
    let mut blob = vec![b'.'; 64 * 1024];
    blob.extend_from_slice(eicar());
    opts.max_scan_size = Some(1024);
    for (entry, v) in both(&blob, &opts) {
        assert!(
            matches!(v, Verdict::LimitsExceeded { .. }),
            "{entry}: {v:?}"
        );
    }
}

/// A container over the deep-analysis limit is walked member by member, and
/// its own bytes get the constant-memory pass on every entry point.
#[test]
fn an_oversize_container_gets_the_same_passes_everywhere() {
    let mut member = Vec::new();
    for i in 0..4000u32 {
        member.extend_from_slice(format!("{i} clean line\n").as_bytes());
    }
    let comment = String::from_utf8(eicar().to_vec()).unwrap();
    let blob = zip_with(&member, &comment);
    let mut opts = ScanOptions::default();
    opts.deep_analysis_max = 4096;
    assert!(blob.len() > 4096);
    for (entry, v) in both(&blob, &opts) {
        assert!(matches!(v, Verdict::Infected { .. }), "{entry}: {v:?}");
    }

    // The counterweight: nothing in its bytes, and it is a limit, not clean.
    let blob = zip_with(&member, "");
    for (entry, v) in both(&blob, &opts) {
        assert!(
            matches!(v, Verdict::LimitsExceeded { .. }),
            "{entry}: {v:?}"
        );
    }
}
