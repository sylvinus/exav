//! Hostile-input panic containment: a malformed container must never panic the
//! process. Third-party decoders can panic on crafted input, so `extract_each`
//! wraps format dispatch in a catch-unwind boundary that turns any such panic
//! into a clean `LimitHit`.

use exav_unpack::{extract, Budget, Format, Limits};

/// Regression for a fuzz-found crash: this 291-byte cabinet drove `cab-0.6.0`'s
/// `seek_to_uncompressed_offset` into an out-of-bounds index (`folder.rs:134`,
/// "len is 0 but the index is 0"). It must return an error, not panic/abort.
#[test]
fn malformed_cab_does_not_panic() {
    let data = include_bytes!("fixtures/cab_folder_panic.cab");
    let mut budget = Budget::new(Limits::default());
    // The call must return (Ok or Err), never unwind past here.
    let res = extract(Format::Cab, data, &mut budget);
    assert!(
        res.is_err(),
        "expected a contained error for the malformed cabinet, got {res:?}"
    );
}

/// Regression for a fuzz-found crash: a binary cpio (`0o070707`) header with a
/// `namesize` pointing far past EOF drove `data[data_start..data_end]` out of
/// range (cpio.rs:77, "range start 64286 out of range for slice of length
/// 3550"). Extraction must complete without panicking, on all three cpio
/// variants (the unclamped `data_start` bug was shared by bin/newc/odc).
#[test]
fn malformed_cpio_does_not_panic() {
    let data = include_bytes!("fixtures/cpio_bin_oob.cpio");
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
        &include_bytes!("fixtures/iso_short_record.iso")[..],
        &include_bytes!("fixtures/iso_short_record2.iso")[..],
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
    let data = include_bytes!("fixtures/upx_nrv_gamma_overflow.upx");
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Upx, data, &mut budget);
}
