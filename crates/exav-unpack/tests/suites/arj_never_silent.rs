//! ARJ enumeration must never drop members quietly.
//!
//! ARJ walks a chain of headers, so anything that ends the walk early hides
//! every member after it. Two cases were silent before: a member using a
//! compression method exav does not decode, and a malformed (or bad-CRC) header
//! terminating the chain.
//!
//! The fixtures are derived by mutating a real archive rather than hand-rolled,
//! so the surrounding structure stays valid and the test exercises the
//! path it claims to.

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

fn sample() -> Vec<u8> {
    let p = format!("{}/tests/fixtures/sample.arj", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// Collect every member the extractor emits, **including** those emitted before
/// a mid-way error. The scanner consumes entries through a visitor as they are
/// produced, so this mirrors what it actually sees; the convenience `extract()`
/// wrapper would discard them along with the error.
fn emitted(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Arj,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

/// Offset of the second `0x60 0xEA` header marker — i.e. the first *local* file
/// header, the main header being the first.
fn first_local_header(data: &[u8]) -> usize {
    let mut seen = 0;
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == 0x60 && data[i + 1] == 0xEA {
            seen += 1;
            if seen == 2 {
                return i;
            }
        }
    }
    panic!("no local header found in the sample");
}

#[test]
fn the_unmodified_sample_extracts_cleanly() {
    // Baseline: none of the reporting below may fire on a healthy archive.
    let e = emitted(&sample());
    assert!(!e.is_empty(), "the sample should yield members");
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a healthy archive must not report anything unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_unsupported_compression_method_is_reported_not_stepped_over() {
    // Byte 5 of the local header body is the compression method. 8 is not one
    // of the four ARJ methods exav decodes, but the member is still there and a
    // real extractor unpacks it — so it must surface rather than be skipped.
    let mut data = sample();
    let lh = first_local_header(&data);
    let method = lh + 4 + 5; // magic(2) + size(2) + offset of method in body
    data[method] = 8;

    let e = emitted(&data);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "an unsupported ARJ method must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_malformed_header_does_not_silently_hide_the_rest_of_the_archive() {
    // Damaging one header must not be a way to make the remainder of an archive
    // invisible: enumeration walks a chain, so anything that ends it early hides
    // every member behind it.
    let mut data = sample();
    let lh = first_local_header(&data);
    // Oversize the declared header length: the read fails its bounds/CRC check.
    data[lh + 2] = 0xFF;
    data[lh + 3] = 0x7F;

    let e = emitted(&data);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "a malformed header must surface as unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
