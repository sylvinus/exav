//! A compound file (OLE2/CFB) whose directory red-black tree is malformed — e.g.
//! sibling entries whose names violate the required ordering — is rejected
//! outright by a strict CFB reader, so a naive implementation would report the
//! whole document "not fully scanned". Many real Office documents and OLE-based
//! malware carry exactly this defect. exav falls back to a lenient flat
//! directory walk that ignores the tree structure and recovers the stream
//! contents anyway, so embedded payloads can't hide behind a broken directory.

use exav_unpack::{extract, Budget, Format, Limits};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/ole/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn any_has_eicar(entries: &[exav_unpack::Entry]) -> bool {
    entries
        .iter()
        .any(|e| e.data.windows(EICAR.len()).any(|w| w == EICAR))
}

/// The fixture is a real compound file with two sibling streams whose names were
/// swapped, breaking the directory ordering invariant.
#[test]
fn strict_cfb_reader_rejects_the_fixture() {
    let blob = fixture("malformed_dir_order.ole");
    // The strict reader must fail — otherwise this test wouldn't exercise the
    // lenient fallback at all.
    let res = cfb::CompoundFile::open(std::io::Cursor::new(blob));
    assert!(
        res.is_err(),
        "fixture is supposed to be malformed; strict cfb reader accepted it"
    );
}

#[test]
#[cfg(feature = "ole")]
fn lenient_fallback_recovers_streams_from_malformed_directory() {
    let blob = fixture("malformed_dir_order.ole");
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Ole, &blob, &mut budget)
        .expect("lenient OLE fallback should recover streams, not error");
    assert!(
        any_has_eicar(&entries),
        "EICAR in a stream of a malformed compound file must still be recovered \
         via the lenient flat directory walk"
    );
}

/// A stream the lenient reader had to cut short must say so.
///
/// Both of its readers stop at the per-member cap and return a bare `Vec<u8>`.
/// Handing that back as a whole stream is the worst shape available: the head
/// is scanned and reads as complete, so a payload past the cap is neither
/// scanned nor mentioned, and the file can be called clean on the strength of
/// bytes nobody claimed were all of them.
#[test]
#[cfg(feature = "ole")]
fn a_stream_cut_short_by_the_budget_is_reported() {
    let blob = fixture("malformed_dir_order.ole");
    // Far below any real stream in the fixture, so every one is cut.
    let mut budget = Budget::new(Limits {
        max_buffer_bytes: 16,
        ..Limits::default()
    });
    let Ok(entries) = extract(Format::Ole, &blob, &mut budget) else {
        // Refusing outright is also acceptable: the scan is told something is
        // wrong either way. What must not happen is silent truncation.
        return;
    };
    assert!(
        entries.iter().any(|e| e.unsupported.is_some()),
        "streams were cut to 16 bytes and every entry came back looking complete: {:?}",
        entries
            .iter()
            .map(|e| (&e.name, e.data.len(), e.unsupported.is_some()))
            .collect::<Vec<_>>()
    );
}
