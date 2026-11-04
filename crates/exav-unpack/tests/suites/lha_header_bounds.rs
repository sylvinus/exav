//! An LHA header may not declare more bytes than the archive holds.
//!
//! The reader sizes its buffer from a header length field before reading what
//! that field describes, so a crafted header reserves gigabytes from an archive
//! of a few hundred bytes. That allocation is invisible to every layer exav
//! normally relies on: `Budget` counts what an extractor yields, and the
//! catch-unwind boundary does not catch an allocation, which aborts rather than
//! unwinding. The only place to stop it is before the reader is handed the
//! bytes.

use exav_unpack::{Budget, Format, Limits, extract};

/// The 143-byte archive that reserves ~3.2 GB. Its level-3 header states a
/// total of 0xFFFFFFDF, which cannot be true of a file this size.
///
/// The assertion is that extraction *fails*, not merely that it returns: a
/// reader that quietly yielded nothing would leave the scan free to call the
/// file clean, which is the outcome this whole layer exists to prevent.
#[test]
fn a_header_larger_than_the_archive_is_rejected() {
    let data = include_bytes!("../fixtures/lha_delharc_oom.lha");
    let mut budget = Budget::new(Limits::default());
    let err = extract(Format::Lha, data, &mut budget)
        .expect_err("a header declaring 4 GiB in a 143-byte file must be refused");
    assert!(
        err.is_corrupt(),
        "a header that cannot be true is malformed input, not a budget stop: {}",
        err.reason
    );
}

/// The same shape, reached through the fuzzer's other LHA finding: a header
/// whose arithmetic overflows. It must be refused by the same gate rather than
/// relying on the decoder to survive it.
#[test]
fn the_overflow_reproducers_do_not_reach_the_decoder_unchecked() {
    for data in [
        &include_bytes!("../fixtures/lha_delharc_overflow.lha")[..],
        &include_bytes!("../fixtures/lha_delharc_overflow_min.lha")[..],
    ] {
        let mut budget = Budget::new(Limits::default());
        // Either the bounds check refuses it or the decoder reports it; what
        // must never happen is a panic escaping, or a silent empty success.
        let _ = extract(Format::Lha, &data, &mut budget);
    }
}

/// The gate must only ever turn away the impossible. A header whose declared
/// size fits the buffer has to reach the decoder, so that a well-formed archive
/// is never refused by the check meant to catch a hostile one.
///
/// Levels 0 and 1 size their header with a single byte and so cannot
/// over-declare meaningfully; level 2 states a 16-bit total. All three are
/// built here with a total that fits, and none may be rejected by the gate.
#[test]
fn a_header_that_fits_still_reaches_the_decoder() {
    for level in [0u8, 1, 2] {
        let mut data = vec![0u8; 64];
        data[0] = 32; // level 0/1: header size byte, well inside 64
        data[1] = 0; // level 2 reads [0..2] as a u16 total = 32
        data[2..7].copy_from_slice(b"-lh0-");
        data[20] = level;
        let mut budget = Budget::new(Limits::default());
        if let Err(e) = extract(Format::Lha, &data, &mut budget) {
            assert!(
                !e.reason.contains("no archive carries"),
                "level {level}: the gate refused a header that fits: {}",
                e.reason
            );
        }
    }
}

/// A header reaching past the end of the bytes in hand must NOT be refused on
/// that ground alone.
///
/// This extractor is handed carved and embedded regions as well as whole files,
/// and there a genuine archive's header can describe more than the slice holds.
/// Refusing it would convert an archive that real extractors open into an
/// `Unscannable`, and a member nobody scanned is worth more to an attacker than
/// a member nobody could allocate, so over-declaring is only grounds for
/// refusal once the size passes what any archiver would ever write.
///
/// A level-3 header declaring 1 MiB inside a 64-byte slice is the shape that
/// must survive: far beyond the slice, nowhere near implausible.
#[test]
fn an_embedded_archive_that_over_declares_is_not_refused() {
    let mut data = vec![0u8; 64];
    data[0] = 4; // level 3 word size
    data[2..7].copy_from_slice(b"-lh0-");
    data[20] = 3;
    data[24..28].copy_from_slice(&(1u32 << 20).to_le_bytes()); // 1 MiB total
    let mut budget = Budget::new(Limits::default());
    if let Err(e) = extract(Format::Lha, &data, &mut budget) {
        assert!(
            !e.reason.contains("no archive carries"),
            "the gate refused a plausible header merely for exceeding the slice: {}",
            e.reason
        );
    }
}

/// A level-0 member of `method` holding `body`, as the format lays it out.
fn level0_member(method: &[u8; 5], name: &[u8], body: &[u8]) -> Vec<u8> {
    let mut h = method.to_vec();
    h.extend_from_slice(&(body.len() as u32).to_le_bytes()); // compressed size
    h.extend_from_slice(&(body.len() as u32).to_le_bytes()); // original size
    h.extend_from_slice(&[0; 4]); // time
    h.extend_from_slice(&[0x20, 0]); // attributes, level
    h.push(name.len() as u8);
    h.extend_from_slice(name);
    h.extend_from_slice(&[0, 0]); // file CRC-16
    let sum = h.iter().fold(0u8, |s, b| s.wrapping_add(*b));
    let mut out = vec![h.len() as u8, sum];
    out.extend_from_slice(&h);
    out.extend_from_slice(body);
    out.push(0); // end of archive
    out
}

/// A member of a method no decoder reads is reported as a method not decoded,
/// not as damage, and the walk reaches the end of the archive.
#[test]
fn an_unknown_method_is_reported_as_unsupported() {
    use exav_unpack::tree::ReasonKind;
    let data = level0_member(b"-lhz-", b"a.txt", b"payload");
    let entries = extract(Format::Lha, &data, &mut Budget::new(Limits::default())).unwrap();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].name, "a.txt");
    assert!(entries[0].data.is_empty(), "{entries:?}");
    assert_eq!(
        entries[0].unsupported,
        Some("unsupported LHA compression method")
    );
    assert_eq!(entries[0].reason_kind, Some(ReasonKind::Unsupported));
}
