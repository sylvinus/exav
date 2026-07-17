//! Regression: logical signatures scoped to an OOXML container
//! (`Container:CL_TYPE_OOXML_WORD`, e.g. ClamAV's `Doc.Downloader.Loda`) must
//! fire on the STREAMED container path — the path a `.docx` (a ZIP) actually
//! takes via the daemon and CLI. Two bugs suppressed the whole class: the
//! streamed path passed no container context to members, and it never probed the
//! ZIP's OOXML sub-type, so a member of `word/document.xml` was scanned as a
//! plain ZIP member and the `Container:`-scoped sig was skipped. A plain ZIP
//! carrying the same bytes must NOT fire (the constraint still discriminates).

use exav_core::{db, scan_seekable, ScanOptions, Verdict};
use std::io::Cursor;

/// The marker the logical signature keys on (appears in `word/document.xml`).
const MARKER: &[u8] = b"LODA_OOXML_CONTAINER_MARKER";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A logical sig scoped to an OOXML-Word container, matching `MARKER`.
fn db_with_ooxml_sig() -> exav_core::Database {
    let ldb = format!(
        "Doc.Downloader.LodaTest;Engine:0-255,Target:0,Container:CL_TYPE_OOXML_WORD;0;{}\n",
        hex(MARKER)
    );
    let mut loader = db::Loader::new();
    loader.add_named_bytes("t.ldb", ldb.as_bytes(), true);
    loader.build().expect("build db")
}

/// Build a minimal STORED (method 0) ZIP with a central directory + EOCD.
fn stored_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets = Vec::new();
    for (name, data) in members {
        offsets.push(out.len() as u32);
        let name = name.as_bytes();
        // Local file header.
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method = stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32 (not verified)
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed size
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(data);
    }
    for ((name, data), off) in members.iter().zip(&offsets) {
        let name = name.as_bytes();
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method = stored
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&0u32.to_le_bytes()); // crc32
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // csize
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // usize
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&off.to_le_bytes()); // LFH offset
        central.extend_from_slice(name);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&(members.len() as u16).to_le_bytes()); // entries this disk
    out.extend_from_slice(&(members.len() as u16).to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn word_doc(body: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(b"<?xml version=\"1.0\"?><document>");
    d.extend_from_slice(body);
    d.extend_from_slice(b"</document>");
    d
}

fn scan(zip: &[u8]) -> Verdict {
    let db = db_with_ooxml_sig();
    scan_seekable(
        &db,
        Cursor::new(zip),
        zip.len() as u64,
        &ScanOptions::default(),
    )
    .unwrap()
    .verdict
}

#[test]
fn ooxml_word_container_sig_fires_on_streamed_docx() {
    // A .docx is a ZIP whose part names type it CL_TYPE_OOXML_WORD.
    let zip = stored_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", &word_doc(MARKER)),
    ]);
    match scan(&zip) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Doc.Downloader.LodaTest")
        }
        other => panic!("expected OOXML-Word container detection, got {other:?}"),
    }
}

#[test]
fn same_bytes_in_plain_zip_do_not_fire() {
    // Identical marker bytes, but no OOXML part names -> plain CL_TYPE_ZIP, so the
    // Container:CL_TYPE_OOXML_WORD constraint must keep the sig from firing.
    let zip = stored_zip(&[("readme.txt", &word_doc(MARKER))]);
    assert!(
        !matches!(scan(&zip), Verdict::Infected { .. }),
        "an OOXML-scoped sig must not fire inside a plain ZIP"
    );
}
