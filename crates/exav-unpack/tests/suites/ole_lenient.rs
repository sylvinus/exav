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

/// The lenient reader keeps each stream's path, from the directory tree. From
/// a live encrypted workbook: with bare names, the VBA project, found by its
/// `VBA` storage, was never assembled and its macros went unreported.
#[test]
#[cfg(feature = "ole")]
fn the_lenient_fallback_keeps_stream_paths() {
    use std::io::Write;
    let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    for path in ["/aaaa", "/bbbb"] {
        cf.create_stream(path).unwrap().write_all(b"x").unwrap();
    }
    cf.create_storage("/Store").unwrap();
    cf.create_stream("/Store/inner")
        .unwrap()
        .write_all(EICAR)
        .unwrap();
    let mut blob = cf.into_inner().into_inner();
    // Swap two siblings' names, which breaks the directory's ordering.
    let utf16 = |s: &str| {
        s.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    };
    let (a, b) = (utf16("aaaa"), utf16("bbbb"));
    let at = |n: &[u8], blob: &[u8]| blob.windows(n.len()).position(|w| w == n).unwrap();
    let (pa, pb) = (at(&a, &blob), at(&b, &blob));
    blob[pa..pa + 8].copy_from_slice(&b);
    blob[pb..pb + 8].copy_from_slice(&a);
    assert!(cfb::CompoundFile::open(std::io::Cursor::new(blob.clone())).is_err());

    let entries = extract(Format::Ole, &blob, &mut Budget::new(Limits::default())).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.name == "/Store/inner" && e.data == EICAR),
        "{:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

/// A workbook encrypted with a password exav does not have leaves the other
/// streams readable: Excel encrypts the `Workbook` stream alone, and the VBA
/// project beside it is in the clear. Reporting only the encrypted stream hid
/// the macros of live encrypted workbooks. Checked through the strict reader
/// and, with two sibling names swapped, the lenient one.
#[test]
#[cfg(feature = "ole")]
fn an_encrypted_workbook_leaves_its_other_streams_readable() {
    // BOF, then FilePass with an encryption type nothing implements.
    let mut workbook = vec![0x09, 0x08, 16, 0];
    workbook.extend_from_slice(&[0; 16]);
    workbook.extend_from_slice(&[0x2f, 0x00, 2, 0, 0x09, 0x00]);
    the_other_streams_stay_readable("/Workbook", &workbook);
}

/// The same for a Word document, which nothing decrypts: its FIB has
/// `fEncrypted` (bit 8 of the flags word at offset 10) set.
#[test]
#[cfg(feature = "ole")]
fn an_encrypted_word_document_leaves_its_other_streams_readable() {
    let fib = [0xec, 0xa5, 0xc1, 0x00, 0, 0, 0, 0, 0, 0, 0x00, 0x01];
    the_other_streams_stay_readable("/WordDocument", &fib);
}

#[cfg(feature = "ole")]
fn the_other_streams_stay_readable(stream: &str, encrypted: &[u8]) {
    use std::io::Write;
    let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    cf.create_stream(stream)
        .unwrap()
        .write_all(encrypted)
        .unwrap();
    for path in ["/aaaa", "/bbbb"] {
        cf.create_stream(path).unwrap().write_all(b"x").unwrap();
    }
    cf.create_storage("/_VBA_PROJECT_CUR").unwrap();
    cf.create_stream("/_VBA_PROJECT_CUR/PROJECT")
        .unwrap()
        .write_all(EICAR)
        .unwrap();
    let strict = cf.into_inner().into_inner();
    let mut lenient = strict.clone();
    let utf16 = |s: &str| {
        s.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    };
    let (a, b) = (utf16("aaaa"), utf16("bbbb"));
    let at = |n: &[u8], blob: &[u8]| blob.windows(n.len()).position(|w| w == n).unwrap();
    let (pa, pb) = (at(&a, &lenient), at(&b, &lenient));
    lenient[pa..pa + 8].copy_from_slice(&b);
    lenient[pb..pb + 8].copy_from_slice(&a);
    assert!(cfb::CompoundFile::open(std::io::Cursor::new(lenient.clone())).is_err());

    for blob in [strict, lenient] {
        let entries = extract(Format::Ole, &blob, &mut Budget::new(Limits::default())).unwrap();
        let names = || entries.iter().map(|e| &e.name).collect::<Vec<_>>();
        assert!(
            entries
                .iter()
                .any(|e| e.name == stream && e.encrypted && e.unsupported.is_some()),
            "{:?}",
            names()
        );
        assert!(any_has_eicar(&entries), "{:?}", names());
    }
}

/// A stream whose directory entry declares more than its sector chain holds
/// has nothing more in the file to read: it is not reported cut short, as a
/// stream over the budget is. From a live Word document, which came out
/// `UNSCANNABLE` for a 12 KB stream "over the per-member size budget".
#[test]
#[cfg(feature = "ole")]
fn a_stream_whose_chain_ends_early_is_not_reported_cut() {
    use std::io::Write;
    let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    cf.create_stream("/aaaa").unwrap().write_all(b"x").unwrap();
    cf.create_stream("/bbbb").unwrap().write_all(b"x").unwrap();
    cf.create_stream("/long")
        .unwrap()
        .write_all(&[b'L'; 5000])
        .unwrap();
    let mut blob = cf.into_inner().into_inner();
    let utf16 = |s: &str| {
        s.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    };
    let at = |n: &[u8], blob: &[u8]| blob.windows(n.len()).position(|w| w == n).unwrap();
    let (a, b) = (utf16("aaaa"), utf16("bbbb"));
    let (pa, pb) = (at(&a, &blob), at(&b, &blob));
    blob[pa..pa + 8].copy_from_slice(&b);
    blob[pb..pb + 8].copy_from_slice(&a);
    // The directory entry's size, at offset 120 of the entry, now claims more.
    let entry = at(&utf16("long"), &blob);
    blob[entry + 120..entry + 124].copy_from_slice(&9000u32.to_le_bytes());

    let entries = extract(Format::Ole, &blob, &mut Budget::new(Limits::default())).unwrap();
    let long: Vec<_> = entries.iter().filter(|e| e.name == "/long").collect();
    assert_eq!(long.len(), 1, "{entries:?}");
    assert!(long[0].unsupported.is_none());
    assert!(long[0].data.starts_with(&[b'L'; 5000]));
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
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 16;
    let mut budget = Budget::new(limits);
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
