//! xz streams with a check the decoder does not read (SHA-256, and the reserved
//! types) are decoded without it, as liblzma does. The fixtures are built by
//! `make.py` in `tests/fixtures/xz_checks/`; `xz -t` accepts them, with a
//! warning that the check is not verified for the reserved ones.

use exav_unpack::{Budget, Entry, Format, Limits, extract};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/xz_checks/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn members(blob: &[u8]) -> Vec<Entry> {
    extract(Format::Xz, &blob, &mut Budget::new(Limits::default())).unwrap()
}

#[test]
fn a_sha256_stream_is_decoded() {
    let m = members(&fixture("sha256.xz"));
    assert_eq!(m.len(), 1);
    assert!(m[0].unsupported.is_none(), "{:?}", m[0].unsupported);
    assert_eq!(m[0].data, fixture("plain.bin"));
}

#[test]
fn a_reserved_check_is_skipped() {
    for id in [2, 9, 12, 15] {
        let m = members(&fixture(&format!("reserved_{id}.xz")));
        assert!(
            m[0].unsupported.is_none(),
            "check {id}: {:?}",
            m[0].unsupported
        );
        assert_eq!(m[0].data, fixture("plain.bin"), "check {id}");
    }
}

/// Two such streams one after the other, with the zero padding the format
/// allows between them, decode to both.
#[test]
fn streams_in_a_row_are_all_decoded() {
    let one = fixture("reserved_9.xz");
    let blob = [&one[..], &[0u8; 8], &fixture("sha256.xz")].concat();
    let plain = fixture("plain.bin");
    assert_eq!(members(&blob)[0].data, [&plain[..], &plain].concat());
}

/// A stream cut short gives the data before the cut and is reported as one
/// with a check the decoder reads is.
#[test]
fn a_cut_stream_is_treated_as_a_cut_stream_is() {
    let cut = |name: &str, at: usize| {
        let blob = fixture(name);
        members(&blob[..blob.len() * at / 100])
    };
    for at in [20, 50, 80, 95] {
        let (read, rewritten) = (cut("crc32.xz", at), cut("reserved_12.xz", at));
        assert_eq!(
            read[0].unsupported, rewritten[0].unsupported,
            "cut at {at}%"
        );
        assert!(!rewritten[0].data.is_empty(), "cut at {at}%");
        assert!(
            fixture("plain.bin").starts_with(&rewritten[0].data),
            "cut at {at}%"
        );
    }
}
