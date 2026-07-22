//! The VBA macro SOURCE must reach the `vba_project` artifact — not merely a
//! header block describing that a module exists.
//!
//! Every other macro fixture in the tree stops at record 0x0019 (MODULENAME), so
//! `build_artifacts` is exercised only down the path where it finds a module and
//! finds no source for it. The branch this file covers is the one that carries
//! the payload: locating the module's own stream, skipping its performance cache,
//! and decompressing the MS-OVBA container holding the code.
//!
//! That decompressed text is what `Target:2` `Doc.*` signatures match against. A
//! regression in it is silent in the worst way — the artifact is still emitted
//! and the ContainsMacros heuristic still fires, while every macro-content
//! signature quietly matches nothing.

use exav_unpack::{extract, Budget, Format, Limits};
use std::io::Write;

/// An MS-OVBA CompressedContainer holding `payload` in one UNCOMPRESSED chunk.
///
/// [MS-OVBA] 2.4.1: a 0x01 signature byte, then chunks. The chunk header is a
/// u16 — bit 15 the compressed flag, bits 14..12 the chunk signature 0b011, bits
/// 11..0 the size minus one. An uncompressed chunk is as legal as a compressed
/// one and needs no compressor to produce, which is the only reason this fixture
/// is writable by hand.
fn ovba_container(payload: &[u8]) -> Vec<u8> {
    assert!(
        !payload.is_empty() && payload.len() <= 4096,
        "one raw chunk holds 1..=4096 bytes; got {}",
        payload.len()
    );
    let mut v = vec![0x01u8];
    let header: u16 = (0b011 << 12) | (payload.len() as u16 - 1);
    v.extend_from_slice(&header.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// A `dir` record: u16 id, u32 size, body.
fn record(id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

/// MODULESTREAMNAME (0x001A) is not a plain sized record: the size covers only
/// the MBCS name, and a reserved u16 plus a length-prefixed UTF-16 copy follow
/// it. Getting this wrong desynchronises every later record, so it is built
/// explicitly rather than through `record`.
fn module_stream_name(name: &str) -> Vec<u8> {
    let mut v = 0x001Au16.to_le_bytes().to_vec();
    v.extend_from_slice(&(name.len() as u32).to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(&0x0032u16.to_le_bytes()); // Reserved
    let utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    v.extend_from_slice(&utf16);
    v
}

/// A compound file carrying one complete VBA module: the `dir` stream describing
/// it and the module stream holding the code.
fn ole_with_a_real_module(source: &str, text_offset: usize) -> Vec<u8> {
    let mut dir = Vec::new();
    dir.extend_from_slice(&record(0x0004, b"VBAProject")); // PROJECTNAME
    dir.extend_from_slice(&record(0x0019, b"Module1")); // MODULENAME
    dir.extend_from_slice(&module_stream_name("Module1"));
    dir.extend_from_slice(&record(0x0031, &(text_offset as u32).to_le_bytes())); // MODULEOFFSET
    dir.extend_from_slice(&record(0x002B, &[])); // module terminator

    // The module stream opens with a performance cache the offset skips over.
    // Filling it with bytes that look nothing like the source keeps the
    // assertion honest: if the offset were ignored, this is what would land in
    // the artifact instead.
    let mut module = vec![0xCCu8; text_offset];
    module.extend_from_slice(&ovba_container(source.as_bytes()));

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut cf = cfb::CompoundFile::create(cursor).expect("create cfb");
    cf.create_storage("/VBA").expect("create /VBA");
    {
        let mut s = cf.create_stream("/VBA/dir").expect("create dir");
        s.write_all(&ovba_container(&dir)).expect("write dir");
        s.flush().expect("flush dir");
    }
    {
        let mut s = cf.create_stream("/VBA/Module1").expect("create module");
        s.write_all(&module).expect("write module");
        s.flush().expect("flush module");
    }
    cf.flush().expect("flush cfb");
    cf.into_inner().into_inner()
}

fn artifact<'a>(entries: &'a [exav_unpack::Entry], name: &str) -> &'a exav_unpack::Entry {
    entries.iter().find(|e| e.name == name).unwrap_or_else(|| {
        panic!(
            "no `{name}` artifact; got {:?}",
            entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        )
    })
}

#[test]
fn the_macro_source_reaches_the_vba_project_artifact() {
    const SOURCE: &str = "Attribute VB_Name = \"Module1\"\r\n\
                          Sub AutoOpen()\r\n\
                            Shell \"cmd.exe /c calc.exe\", vbHide\r\n\
                          End Sub\r\n";
    let blob = ole_with_a_real_module(SOURCE, 0x2A);
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Ole, &blob, &mut budget).expect("extract OLE");

    // The raw artifact preserves original case, so the source is compared against
    // it verbatim; the REM dump lowercases code and is checked separately below.
    let raw = String::from_utf8_lossy(&artifact(&entries, "vba_project_raw").data).into_owned();
    assert!(
        raw.contains("Shell") && raw.contains("calc.exe"),
        "the module's decompressed source must be present in vba_project_raw, got:\n{raw}"
    );
    assert!(
        !raw.contains('\u{FFFD}') && !raw.contains("\u{00CC}"),
        "the performance-cache filler before MODULEOFFSET leaked into the artifact:\n{raw}"
    );

    let dump = String::from_utf8_lossy(&artifact(&entries, "vba_project").data).into_owned();
    assert!(
        dump.contains("MODULESTREAMNAME: Module1"),
        "the REM dump must name the module stream it read, got:\n{dump}"
    );
    assert!(
        dump.to_ascii_lowercase().contains("calc.exe"),
        "the REM dump must carry the module source, got:\n{dump}"
    );
}

#[test]
fn a_module_whose_stream_is_absent_still_yields_a_project() {
    // The counterweight: the `dir` stream promises a module that is not there.
    // exav must still report the project rather than dropping it — a document
    // that declares macros is worth reporting even when the code is missing.
    let mut dir = Vec::new();
    dir.extend_from_slice(&record(0x0019, b"Ghost"));
    dir.extend_from_slice(&module_stream_name("Ghost"));
    dir.extend_from_slice(&record(0x0031, &0u32.to_le_bytes()));
    dir.extend_from_slice(&record(0x002B, &[]));

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut cf = cfb::CompoundFile::create(cursor).expect("create cfb");
    cf.create_storage("/VBA").expect("create /VBA");
    {
        let mut s = cf.create_stream("/VBA/dir").expect("create dir");
        s.write_all(&ovba_container(&dir)).expect("write dir");
        s.flush().expect("flush dir");
    }
    cf.flush().expect("flush cfb");
    let blob = cf.into_inner().into_inner();

    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Ole, &blob, &mut budget).expect("extract OLE");
    let dump = String::from_utf8_lossy(&artifact(&entries, "vba_project").data).into_owned();
    assert!(
        dump.contains("MODULENAME: Ghost"),
        "a module with no stream must still be described, got:\n{dump}"
    );
}

/// An `Ole10Native` stream carries an embedded-object header before the payload,
/// so the file dropped into the document starts partway in. Nothing looked past
/// that header and the sniffer only inspects offset 0, which made every embedded
/// executable or compound file invisible.
#[test]
fn an_ole10native_payload_is_carved_past_its_header() {
    const PAYLOAD: &[u8] = b"MALWARETEST-embedded-package-payload";

    let mut stream = Vec::new();
    stream.extend_from_slice(&0u32.to_le_bytes()); // total size (unused)
    stream.extend_from_slice(&2u16.to_le_bytes()); // flags
    stream.extend_from_slice(b"invoice.exe\0"); // label
    stream.extend_from_slice(b"C:\\Users\\x\\invoice.exe\0"); // original path
    stream.extend_from_slice(b"C:\\Temp\\invoice.exe\0"); // temp path
    stream.extend_from_slice(&(PAYLOAD.len() as u32).to_le_bytes());
    stream.extend_from_slice(PAYLOAD);

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut cf = cfb::CompoundFile::create(cursor).expect("create cfb");
    {
        let mut s = cf
            .create_stream("/\u{1}Ole10Native")
            .expect("create stream");
        s.write_all(&stream).expect("write");
        s.flush().expect("flush");
    }
    cf.flush().expect("flush cfb");
    let blob = cf.into_inner().into_inner();

    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Ole, &blob, &mut budget).expect("extract OLE");
    let carved = entries
        .iter()
        .find(|e| e.name.contains("Ole10Native-payload"))
        .unwrap_or_else(|| {
            panic!(
                "the embedded payload must be carved; got {:?}",
                entries.iter().map(|e| &e.name).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        carved.data, PAYLOAD,
        "the carve must start after the header, not at the stream start"
    );
}
