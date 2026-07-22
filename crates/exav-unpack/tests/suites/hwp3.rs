//! HWP3 against a document a real Hangul Word Processor wrote.
//!
//! The unit tests in `formats/hwp3.rs` build documents to the same preamble
//! offsets they then check, so they can only prove the parser matches the layout
//! *as recorded*. This file is the external check: `testHWP_3.0.hwp` from the
//! Apache Tika test corpus (Apache-2.0, credited in NOTICE) was produced by the
//! application, not by exav, so it is the layout's own authority.
//!
//! What it pins is exactly what a scanner needs: the body is deflate-compressed,
//! so **without decompression a signature in the document can never match**. The
//! assertion is that real content comes out, not that exav's writer and reader
//! agree with each other.

#![cfg(feature = "hwp3")]

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

const REAL: &[u8] = include_bytes!("../fixtures/hwp3/tika_testHWP_3.0.hwp");

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    let mut out = Vec::new();
    let _ = extract_each::<()>(
        Format::Hwp3,
        blob,
        &mut budget,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None
        },
    );
    out
}

#[test]
fn a_real_document_is_recognised() {
    assert_eq!(exav_unpack::detect(REAL), Some(Format::Hwp3));
}

#[test]
fn a_real_documents_body_is_decompressed() {
    let m = members(REAL);
    assert_eq!(m.len(), 1, "expected one body member, got {m:?}");
    assert!(
        m[0].unsupported.is_none(),
        "the body must decode, not be reported: {:?}",
        m[0].unsupported
    );
    // The container is 9 KiB; the body inflates to ~45 KiB. A decoder that
    // sliced the preamble wrongly would either fail to inflate or produce
    // something far smaller, so the size is the assertion that the offsets are
    // right on a document exav did not write.
    assert!(
        m[0].data.len() > 40_000,
        "body inflated to only {} bytes from a {} byte file — the preamble \
         offsets are wrong",
        m[0].data.len(),
        REAL.len()
    );
}

#[test]
fn content_hidden_behind_the_compression_becomes_scannable() {
    // The reason for decoding HWP3 rather than reporting it: bytes that are
    // absent from the raw file are present after inflation. If this ever fails,
    // exav is back to scanning a compressed blob and calling it clean.
    let m = members(REAL);
    let body = &m[0].data;
    let mut found_in_body_only = 0usize;
    // Sixteen-byte windows from the middle of the body, looked for in the
    // original file. A compressed body means almost none of them appear.
    for chunk in body.chunks(16).skip(64).take(64) {
        if chunk.len() == 16 && !REAL.windows(16).any(|w| w == chunk) {
            found_in_body_only += 1;
        }
    }
    assert!(
        found_in_body_only > 32,
        "only {found_in_body_only}/64 sampled windows were absent from the raw \
         file — the body does not look compressed, so this fixture no longer \
         tests what it claims"
    );
}

#[test]
fn a_truncated_real_document_is_reported_never_clean() {
    for keep in [40usize, 200, 1100, 1200, 5000] {
        let m = members(&REAL[..keep.min(REAL.len())]);
        assert_eq!(m.len(), 1, "keep={keep}: {m:?}");
        assert!(
            m[0].unsupported.is_some() || !m[0].data.is_empty(),
            "keep={keep}: a truncated document must be reported or yield \
             content, never both empty and unexplained"
        );
    }
}
