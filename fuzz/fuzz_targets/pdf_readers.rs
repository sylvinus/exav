#![no_main]
//! The two readings of a PDF the scanner uses, one against the other: its
//! members (streams, scripts, link targets) come from exav-unpack's own reader,
//! its visible text from hayro-syntax. Both read each input, and a difference
//! that leaves something unscanned is a finding: hayro lists a stream
//! exav-unpack does not emit, reads a script or a link target exav-unpack's
//! members lack, or opens a file exav-unpack found no stream in.
//!
//! The other differences (a stream decoded to other bytes, an object only
//! exav-unpack reads, an unknown filter) are expected repair differences and
//! are recorded, file by file, by `crates/exav-unpack/tests/suites/
//! pdf_readers_diff.rs`, which shares the comparison. hayro is given a file
//! only when exav-unpack read it whole, as the scanner does. A panic inside
//! hayro is a finding here too, though the scanner contains it.
//!
//! Seeds: `scripts/fuzz-seeds.sh` (the `pdf_readers` directory, the PDFs of the
//! repository of at most 64 KiB). Run with `-max_len=65536`: hayro bounds
//! neither what a stream inflates to nor what an image declares, and the
//! comparison skips the image codecs and relies on the input's size for the
//! rest.
use exav_unpack::Limits;
use libfuzzer_sys::fuzz_target;

#[allow(dead_code)]
#[path = "../../crates/exav-unpack/tests/pdf_readers/mod.rs"]
mod pdf_readers;

fn tight_limits() -> Limits {
    let mut l = Limits::default();
    l.max_extracted_bytes = 1 << 20;
    l.max_members = 2000;
    l.max_compression_ratio = 100;
    l.max_buffer_bytes = 256 * 1024;
    l.max_scanned_bytes = 1 << 20;
    l.max_recursion = 2;
    l
}

fuzz_target!(|data: &[u8]| {
    let c = pdf_readers::compare(data, &tight_limits());
    if let Some(d) = c.differences.iter().find(|d| d.kind.is_miss()) {
        panic!("{:?}: {}", d.kind, d.detail);
    }
});
