//! CAB Quantum decompression, checked against `cabextract`/libmspack.
//!
//! Quantum is the one CAB codec ClamAV decodes that exav did not, which under
//! the drop-in-replacement rule made it a required capability rather than an
//! optional one. It also stays reachable for an attacker: **7-Zip decompresses
//! Quantum cabinets byte-exactly today**, so a victim opens the archive while a
//! scanner that skips the codec sees nothing.
//!
//! The fixture is libmspack's `mszip_lzx_qtm.cab` — three tiny members, one per
//! CAB codec, so it also guards MSZIP and LZX from regressions.
//!
//! **What this fixture does NOT cover**, and why the real validation lives
//! outside the repo: at 59 bytes the Quantum member never triggers a frequency
//! rescale, never triggers the periodic model reordering, and never wraps the
//! window. Those were covered by differential testing against
//! `cabextract` on 107 generated streams spanning every window size 10–21 with
//! outputs up to 11 KB — zero disagreements. Treat a pass here as "still
//! wired up", not as "the codec is correct".

use exav_unpack::{extract, Budget, Format, Limits};

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/cab/mszip_lzx_qtm.cab",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn members() -> Vec<(String, Vec<u8>)> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Cab, &fixture(), &mut budget)
        .expect("extract")
        .into_iter()
        .map(|e| (e.name, e.data))
        .collect()
}

/// All three codecs decode, and the Quantum member is byte-exact against the
/// bytes `cabextract` produces.
#[test]
fn decodes_quantum_mszip_and_lzx() {
    let m = members();
    assert_eq!(m.len(), 3, "expected one member per codec: {m:?}");

    let find = |needle: &str| {
        m.iter()
            .find(|(n, _)| n.contains(needle))
            .unwrap_or_else(|| panic!("no member matching {needle}: {m:?}"))
    };

    assert_eq!(
        find("qtm").1,
        b"If you can read this, the Quantum decompressor is working!\n",
        "Quantum output differs from the oracle's"
    );
    assert_eq!(
        find("mszip").1,
        b"If you can read this, the MSZIP decompressor is working!\n"
    );
    assert!(
        String::from_utf8_lossy(&find("lzx").1).contains("the LZX decompressor is working!"),
        "LZX output changed"
    );
}

/// Nothing is reported unsupported now that the codec is implemented — the
/// whole point of the exercise was to stop reporting `UNSCANNABLE` here.
#[test]
fn no_member_is_reported_unscannable() {
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Cab, &fixture(), &mut budget).expect("extract");
    let unsupported: Vec<_> = entries
        .iter()
        .filter(|e| e.unsupported.is_some())
        .map(|e| (&e.name, e.unsupported))
        .collect();
    assert!(
        unsupported.is_empty(),
        "codecs still reporting unsupported: {unsupported:?}"
    );
}
