//! One payload, wrapped through twenty-six container formats in a row.
//!
//! Every other extractor test asks "does this format work?". This one asks the
//! question that matters at the seams: **does each format hand off to the next?**
//! A layer that decodes correctly but types its member wrongly, or emits it in a
//! shape the next handler will not take, breaks the chain — and a broken chain
//! looks exactly like a clean file.
//!
//! It earned its keep immediately: the first run came back `OK`. A compressed
//! QCOW2 cluster whose host offset happened to be **odd** was being read as the
//! "reads as zeroes" flag and silently zero-filled, so one cluster — the one
//! holding everything below it — became a hole. Nothing errored. See
//! `a_compressed_cluster_at_an_odd_host_offset_is_not_dropped` in
//! `exav-unpack/tests/diskimage.rs` for the narrow regression test.
//!
//! The chain, outermost first. Every layer was produced by that format's own
//! reference tool, never by this crate:
//!
//! ```text
//! uuencode -> QCOW2 -> MBR partition table -> VMDK -> VHD -> VHDX -> ISO 9660
//!   -> MIME email -> WIM (LZX) -> OLE2 -> XAR -> ar -> cpio -> CAB -> RAR5
//!   -> ARJ -> 7z -> tar -> compress (.Z) -> LZ4 -> zstd -> xz -> bzip2
//!   -> gzip -> lzip -> ZIP -> eicar.com
//! ```
//!
//! The bulky formats sit in the middle on purpose: a VHDX is nine megabytes of
//! mostly zeroes, and the QCOW2 layer above it compresses that back down, so the
//! whole twenty-six-layer fixture is thirteen kilobytes.
//!
//! Tools: `uuencode`(sharutils), `qemu-img`, `fdisk`(util-linux),
//! `genisoimage`, Python's `email` module, `wimcapture`(wimlib), `gsf`(libgsf),
//! `xar`, `ar`(binutils), `cpio`, `gcab`, official `rar` 7.23, `arj`, `7zz`
//! 25.01, `tar`, `compress`(ncompress 5.0), `lz4`, `zstd`, `xz`, `bzip2`,
//! `gzip`, `lzip`, `zip`(Info-ZIP). Rebuild with `scripts/make-matryoshka.sh`.
//!
//! Two things are asserted, and the second matters more than the first:
//!
//! 1. Given depth to work with, exav reaches the payload at the bottom.
//! 2. One level short of it, the verdict is `LimitsExceeded` — never `Clean`. A
//!    scanner that gives up quietly on a deeply nested archive has been evaded
//!    by nothing more than a shell loop.

use exav_core::unpack::Limits;
use exav_core::{analyze, ScanOptions, Scanner, Verdict};

/// Recursion levels needed to reach the payload. One less than this and exav
/// cannot get there; the fixture sits exactly at this depth so the boundary is
/// pinned rather than approximated.
const DEPTH: u32 = 25;

/// How many distinct container formats the chain passes through. One more than
/// `DEPTH`, because the outermost layer is the file's own type rather than a
/// level of recursion.
const FORMATS: u32 = 26;

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/matryoshka.uu",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn scan_at(max_recursion: u32) -> Verdict {
    let db = Scanner::builtin();
    let opts = ScanOptions {
        limits: Limits {
            max_recursion,
            ..Limits::default()
        },
        ..ScanOptions::default()
    };
    analyze(&db, &fixture(), &opts).verdict
}

#[test]
fn the_payload_under_twenty_six_formats_is_found() {
    match scan_at(DEPTH) {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!(
            "the chain broke somewhere in the {FORMATS} formats — every one must \
             hand its member to the next one's detector, got {other:?}"
        ),
    }
}

#[test]
fn one_level_short_of_the_payload_is_a_limit_not_a_clean_bill() {
    // exav cannot reach the bottom here, and that is fine. Saying "clean" would
    // not be: nesting is free to produce, so a quiet give-up is an evasion that
    // costs an attacker one shell loop.
    match scan_at(DEPTH - 1) {
        Verdict::LimitsExceeded { reason } => assert!(
            reason.to_lowercase().contains("recursion"),
            "the reason should name the limit that was hit, got {reason:?}"
        ),
        other => panic!("a chain deeper than the limit must report the limit, got {other:?}"),
    }
}

#[test]
fn no_depth_short_of_the_payload_ever_reads_as_clean() {
    // Samples across the chain rather than just testing the boundary: a layer
    // that quietly produced nothing would show up as `Clean` at its own depth
    // while the boundary case still looked right. Stepping rather than testing
    // every level keeps the runtime down — each deep scan re-expands the
    // nine-megabyte VHDX in the middle of the chain.
    for depth in (1..DEPTH).step_by(3) {
        let v = scan_at(depth);
        assert!(
            !matches!(v, Verdict::Clean),
            "at max_recursion={depth} the scan stopped inside the chain and \
             reported clean: {v:?}"
        );
    }
    assert!(
        matches!(scan_at(DEPTH), Verdict::Infected { .. }),
        "with room to recurse the payload must be reached"
    );
}
