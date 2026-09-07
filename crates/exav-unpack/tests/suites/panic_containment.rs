//! Hostile-input panic containment: a malformed container must never panic the
//! process. Third-party decoders can panic on crafted input, so `extract_each`
//! wraps format dispatch in a catch-unwind boundary that turns any such panic
//! into a clean `LimitHit`.

use exav_unpack::{extract, Budget, Format, Limits};

/// Regression for a fuzz-found crash: this 291-byte cabinet drove `cab-0.6.0`'s
/// `seek_to_uncompressed_offset` into an out-of-bounds index (`folder.rs:134`,
/// "len is 0 but the index is 0"). Patched via [patch.crates-io]; must not panic.
#[test]
fn malformed_cab_does_not_panic() {
    let data = include_bytes!("../fixtures/cab_folder_panic.cab");
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Cab, data, &mut budget);
}

/// Regression for fuzz-found crash (2026-06-30): 122-byte CAB with zero-length
/// folder data — same `folder.rs:134` OOB but different input shape.
#[test]
fn malformed_cab_zero_folder_does_not_panic() {
    let data = include_bytes!("../fixtures/cab_folder_panic2.cab");
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Cab, data, &mut budget);
}

/// Regression for fuzz-found crash (2026-06-30): CAB triggering underflow in
/// `FolderReader::read()` (`folder.rs:239`) — `current_offset_within_block`
/// exceeds `current_block_data.len()`. Patched cab returns 0 gracefully.
#[test]
fn malformed_cab_read_underflow_does_not_panic() {
    let data = include_bytes!("../fixtures/cab_read_underflow.cab");
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Cab, data, &mut budget);
}

/// Regression for a fuzz-found crash: a binary cpio (`0o070707`) header with a
/// `namesize` pointing far past EOF drove `data[data_start..data_end]` out of
/// range (cpio.rs:77, "range start 64286 out of range for slice of length
/// 3550"). Extraction must complete without panicking, on all three cpio
/// variants (the unclamped `data_start` bug was shared by bin/newc/odc).
#[test]
fn malformed_cpio_does_not_panic() {
    let data = include_bytes!("../fixtures/cpio_bin_oob.cpio");
    let mut budget = Budget::new(Limits::default());
    // Must return (Ok or Err) — never unwind.
    let _ = extract(Format::Cpio, data, &mut budget);
}

/// Regression for fuzz-found crashes: ISO9660 directory records whose
/// self-declared length is non-zero but shorter than the 33-byte fixed area
/// indexed `rec[2..32]` (iso.rs:54/57). Must not panic.
#[test]
fn malformed_iso_short_record_does_not_panic() {
    for data in [
        &include_bytes!("../fixtures/iso_short_record.iso")[..],
        &include_bytes!("../fixtures/iso_short_record2.iso")[..],
    ] {
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Iso, data, &mut budget);
    }
}

/// Regression for fuzz-found crashes: a UPX NRV2D/E stream whose gamma bit
/// sequence never terminates, doubling the gamma value until it overflows
/// `usize` (upx.rs nrv_gamma/nrv_gamma_de). Capped now; must not panic.
#[test]
fn malformed_upx_nrv_gamma_does_not_panic() {
    // Masked on disk: a fuzzer-built UPX'd i386 ELF matches ClamAV's generic
    // Mirai signature, so committed in the clear it gets this repository
    // quarantined on clone. See `exav_unpack::unmask_fixture`.
    let data =
        exav_unpack::unmask_fixture(include_bytes!("../fixtures/upx_nrv_gamma_overflow.upx.xor"));
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Upx, &data, &mut budget);
}

/// Regression for fuzz-found crash (2026-07-01): a truncated CAB with LZX
/// compressed data triggers an index-out-of-bounds in `lzxd`'s bitstream
/// reader (`bitstream.rs:37` — `self.buffer[1]` when buffer has 1 byte).
/// Must not panic; the `catch_unwind` boundary in `extract_each` turns it
/// into a clean `LimitHit`.
#[test]
fn cab_lzxd_bitstream_oob_does_not_panic() {
    let data = include_bytes!("../fixtures/cab_lzxd_bitstream_panic.cab");
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Cab, data, &mut budget);
}

/// Regression for fuzz-found crash (2026-07-01): a crafted LHA level-3 header
/// with a `first_header_len` that overflows when added to `parser.len`
/// (`delharc header/parser.rs:265`). Must not panic; caught by
/// `catch_unwind`.
#[test]
fn lha_delharc_overflow_does_not_panic() {
    // Two crafted headers that both drive delharc 0.6.1 into the same
    // `header/parser.rs:265` add-with-overflow (`parser.len as u32 +
    // first_header_len`) under overflow-checks. `_min` is the smaller (49-byte)
    // trigger, re-found by fuzzing 2026-07-02 and used for the upstream report
    // (see fixtures/DELHARC_UPSTREAM_REPRO.md). Both must be caught, not panic.
    for data in [
        &include_bytes!("../fixtures/lha_delharc_overflow.lha")[..],
        &include_bytes!("../fixtures/lha_delharc_overflow_min.lha")[..],
    ] {
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Lha, data, &mut budget);
    }
}

/// Same crafted LHA headers, but driven through the **streaming** API
/// (`stream_members`) — which has its own `catch_unwind` boundary. LHA is
/// stream-extractable, so the delharc panic must be contained here too.
#[test]
fn lha_delharc_overflow_stream_does_not_panic() {
    use exav_unpack::{stream_members, MemberMeta};
    use std::io::{Cursor, Read};
    for data in [
        &include_bytes!("../fixtures/lha_delharc_overflow.lha")[..],
        &include_bytes!("../fixtures/lha_delharc_overflow_min.lha")[..],
    ] {
        let mut budget = Budget::new(Limits::default());
        let mut visit =
            |_m: &MemberMeta, r: Option<&mut dyn Read>, _b: &mut Budget| -> Option<()> {
                if let Some(r) = r {
                    let mut sink = Vec::new();
                    let _ = r.read_to_end(&mut sink);
                }
                None
            };
        let _ = stream_members(Format::Lha, Cursor::new(data), &mut budget, &mut visit);
    }
}

/// A 143-byte LHA header that declares a huge extended-header length. delharc
/// bounds the read, so extraction must complete without a large allocation and
/// without panic.
#[test]
fn lha_delharc_oom_is_bounded() {
    let data = include_bytes!("../fixtures/lha_delharc_oom.lha");
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Lha, data, &mut budget);
}

/// The boundary itself, rather than the decoders behind it.
///
/// Every other test here uses an input that once panicked a particular decoder.
/// Those are real regressions and worth keeping, but they do not test
/// `extract_each`'s `catch_unwind`: fix all of those decoders and they keep
/// passing with the boundary deleted. This panics from inside the dispatch for
/// input nothing else produces, so the only thing that can turn it into a
/// `LimitHit` is the boundary.
///
/// What must come back is an ERROR. A panic swallowed into `Ok(vec![])` would
/// say the container holds nothing, which for a scanner is the one answer that
/// must never be wrong.
#[cfg(feature = "testing-faults")]
#[test]
fn an_arbitrary_decoder_panic_becomes_a_reported_limit() {
    let mut budget = Budget::new(Limits::default());
    let err = extract(Format::Zip, b"__exav_panic__", &mut budget)
        .expect_err("a panic was reported as a successful, empty extraction");
    assert!(
        err.to_string().to_lowercase().contains("panic"),
        "the limit does not say a panic caused it: {err}"
    );
    // Twice, because containment that survives one panic and not the next has
    // contained nothing — a scanner meets hostile input repeatedly, in one
    // process, and has to keep answering.
    let mut budget = Budget::new(Limits::default());
    assert!(
        extract(Format::Zip, b"__exav_panic__", &mut budget).is_err(),
        "the boundary did not hold a second time"
    );
}
