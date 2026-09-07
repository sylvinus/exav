//! Containers with no ClamAV `CL_TYPE_*` of their own must still be extracted.
//!
//! The scanner normally reaches an extractor through the file's [`FileType`],
//! but a handful of formats — Unix `compress` and the disk images — have no
//! ClamAV type to map to and so are typed `Unknown`. Nothing then dispatches
//! them, and the file is reported clean on the strength of a raw pattern scan
//! that cannot see compressed content. That is a silent clean, the worst
//! failure mode a scanner has, and it is invisible in the unpack crate's own
//! tests because the extractors themselves work fine.
//!
//! Both fixtures hide the payload behind real compression: the EICAR string
//! appears nowhere in their bytes (asserted below), so a verdict of `Infected`
//! can only come from the container actually being opened.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn assert_found(name: &str) {
    let blob = fixture(name);
    assert!(
        !blob.windows(eicar().len()).any(|w| w == eicar()),
        "{name} must not expose the payload in its own bytes, or this test \
         would pass on the raw scan alone and prove nothing"
    );
    let db = Scanner::builtin();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "{name}: unexpected signature {signature}"
        ),
        other => panic!("{name}: the payload must be reached, got {other:?}"),
    }
}

#[test]
#[cfg(feature = "lzw")]
fn a_unix_compress_stream_is_decompressed_and_scanned() {
    // Produced by ncompress 5.0 (`compress -c`), not by any encoder of ours.
    assert_found("eicar.txt.Z");
}

#[test]
#[cfg(feature = "diskimage")]
fn a_compressed_qcow2_is_reconstructed_and_scanned() {
    // `qemu-img convert -c` — every cluster deflated.
    assert_found("compressed.qcow2");
}

#[test]
#[cfg(feature = "inno")]
fn an_installer_embedded_in_an_executable_is_not_reported_clean() {
    // The second shape of the same routing bug. An installer *is* an executable,
    // so `identify` answers `Pe` — correctly, the PE signature scan has to run —
    // and `unpack_format` has no mapping from an executable to a container. So
    // the extractor was never reached.
    //
    // Embedded-archive carving covers the case where the appended data is a
    // recognisable archive, but not where it is the installer's own format:
    // NSIS's compressed blocks and Inno Setup's chunked LZMA look like nothing
    // in particular, so nothing is carved and the file scans clean with every
    // packaged file unexamined. Verified against a real Inno Setup 6.2.2
    // installer, which reported `OK` before this.
    //
    // Synthetic here rather than a shipped installer: the routing is what is
    // under test, and a real one would mean committing a multi-megabyte binary.
    let mut pe = vec![0u8; 8192];
    pe[0..2].copy_from_slice(b"MZ");
    pe[4096..4102].copy_from_slice(b"rDlPtS");

    let db = Scanner::builtin();
    match analyze(&db, &pe, &ScanOptions::default()).verdict {
        Verdict::Unscannable { reason } => assert!(
            reason.to_lowercase().contains("inno"),
            "the reason should name what could not be read, got {reason:?}"
        ),
        other => {
            panic!("an installer whose payload exav cannot read must not be clean, got {other:?}")
        }
    }
}
