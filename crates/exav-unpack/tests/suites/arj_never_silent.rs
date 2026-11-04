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

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};

fn sample() -> Vec<u8> {
    let p = format!("{}/tests/fixtures/sample.arj", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
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

/// Offset of the second `0x60 0xEA` header marker, i.e. the first *local* file
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
    // real extractor unpacks it, so it must surface rather than be skipped.
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

/// The member is reported as a method not decoded, not as damage. The header
/// CRC-32 goes stale with the changed byte, which is read through by default.
#[test]
fn an_unsupported_compression_method_has_the_unsupported_kind() {
    use exav_unpack::tree::ReasonKind;
    let mut data = sample();
    let method = first_local_header(&data) + 4 + 5;
    data[method] = 5;

    let e = emitted(&data);
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].name, "payload.txt");
    assert!(e[0].data.is_empty(), "{e:?}");
    assert_eq!(e[0].unsupported, Some("unsupported ARJ compression method"));
    assert_eq!(e[0].reason_kind, Some(ReasonKind::Unsupported));
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

/// Where the CRC-32 of the main header and of the first file header are.
fn header_crcs(data: &[u8]) -> [usize; 2] {
    let size = |at: usize| usize::from(u16::from_le_bytes([data[at + 2], data[at + 3]]));
    let lh = first_local_header(data);
    [4 + size(0), lh + 4 + size(lh)]
}

/// What the members are, as the scanner would be handed them.
fn members(data: &[u8]) -> Vec<(String, Vec<u8>, Option<&'static str>)> {
    emitted(data)
        .into_iter()
        .map(|e| (e.name, e.data, e.unsupported))
        .collect()
}

/// A header whose CRC-32 is stale hides nothing: ClamAV does not look at it, and
/// flipping a byte of it must not be a way to keep an archive from being read.
#[test]
fn a_stale_header_crc_is_read_through() {
    let data = sample();
    let want = members(&data);
    assert!(want.iter().all(|m| m.2.is_none()) && !want.is_empty());
    for (what, at) in ["main", "file"].into_iter().zip(header_crcs(&data)) {
        let mut stale = data.clone();
        stale[at] ^= 0xFF;
        assert_eq!(members(&stale), want, "{what} header");
    }
}

/// With checksums verified, a stale header CRC-32 is damage again: the archive
/// is not read, or not past that header, and says so.
#[cfg(feature = "checksums")]
#[test]
fn a_stale_header_crc_is_damage_when_checksums_are_verified() {
    let data = sample();
    let [main, file] = header_crcs(&data);
    let verified = |blob: &[u8]| {
        let mut out = Vec::new();
        let mut b = Budget::new(Limits::default());
        b.set_verify_checksums(true);
        let r = extract_each(
            Format::Arj,
            blob,
            &mut b,
            &mut |e: Entry, _: &mut Budget| {
                out.push(e);
                None::<()>
            },
        );
        (r.is_ok(), out)
    };
    let mut stale = data.clone();
    stale[main] ^= 0xFF;
    assert!(!verified(&stale).0, "a stale main header CRC");
    let mut stale = data.clone();
    stale[file] ^= 0xFF;
    let (_, out) = verified(&stale);
    assert!(
        out.iter().any(|e| e.unsupported.is_some()),
        "a stale file header CRC"
    );
    assert!(out.iter().all(|e| e.data.is_empty()), "{out:?}");
}
