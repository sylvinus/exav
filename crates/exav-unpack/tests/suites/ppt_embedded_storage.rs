//! PowerPoint 97 keeps embedded objects in a *record tree* inside its single
//! `PowerPoint Document` stream, not in the compound file's directory. Emitting
//! the streams alone therefore stops at the container: a VBA project, or any
//! OLE object dropped onto a slide, is present and readable and never seen.
//!
//! Found by differential testing: three corpus documents where `clamd` reported
//! `Heuristics.OLE2.ContainsMacros.VBA` and exav reported nothing. Their CFB
//! directory holds five streams and no VBA storage — the macro project is a
//! 10,752-byte compound file deflated inside one record.
//!
//! The fixtures here are built rather than vendored, so each one isolates a
//! single property of the record walk.

use exav_unpack::{extract, Budget, Format, Limits};
use std::io::Write;

const MARKER: &[u8] = b"EMBEDDED-OBJECT-MARKER";

/// `RT_ExternalOleObjectStg`.
const EXT_OLE_OBJ_STG: u16 = 0x1011;

/// One PowerPoint record: `[verInstance:u16][type:u16][length:u32]` then body.
fn record(ver_instance: u16, rec_type: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ver_instance.to_le_bytes());
    v.extend_from_slice(&rec_type.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

/// A container record, whose body is more records.
fn container(rec_type: u16, body: &[u8]) -> Vec<u8> {
    record(0x000f, rec_type, body)
}

fn deflate(raw: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(raw).unwrap();
    e.finish().unwrap()
}

/// A compressed storage record: instance 1, `[uncompressed size][zlib]`.
fn compressed_storage(payload: &[u8]) -> Vec<u8> {
    let mut body = (payload.len() as u32).to_le_bytes().to_vec();
    body.extend_from_slice(&deflate(payload));
    record(0x0010, EXT_OLE_OBJ_STG, &body)
}

/// An uncompressed storage record: instance 0, the bytes as they are.
fn stored_storage(payload: &[u8]) -> Vec<u8> {
    record(0x0000, EXT_OLE_OBJ_STG, payload)
}

/// A compound file whose only stream is `PowerPoint Document`, holding `records`.
fn ppt_with(records: &[u8]) -> Vec<u8> {
    let mut comp = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    comp.create_stream("/PowerPoint Document")
        .unwrap()
        .write_all(records)
        .unwrap();
    comp.flush().unwrap();
    comp.into_inner().into_inner()
}

fn members(blob: &[u8]) -> Vec<exav_unpack::Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Ole, blob, &mut budget).expect("ppt extracts")
}

fn has_marker(entries: &[exav_unpack::Entry]) -> bool {
    entries
        .iter()
        .any(|e| e.data.windows(MARKER.len()).any(|w| w == MARKER))
}

/// The shape the corpus samples actually use: the storage record is nested
/// inside a container, and its payload is deflated.
#[test]
#[cfg(feature = "ole")]
fn a_deflated_object_nested_in_a_container_is_recovered() {
    let inner = container(0x03fa, &compressed_storage(MARKER));
    let entries = members(&ppt_with(&inner));
    assert!(
        has_marker(&entries),
        "embedded object not recovered; members: {:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

/// The uncompressed form of the same record.
#[test]
#[cfg(feature = "ole")]
fn a_stored_object_is_recovered() {
    let entries = members(&ppt_with(&stored_storage(MARKER)));
    assert!(has_marker(&entries), "stored object not recovered");
}

/// A container's body is more records, so the walk must step *into* it rather
/// than over it. Skipping containers would leave anything nested unreachable,
/// which is the whole defect this suite covers — so the fixture buries the
/// object three levels down.
#[test]
#[cfg(feature = "ole")]
fn the_walk_descends_through_nested_containers() {
    let deep = container(
        0x03e8,
        &container(0x03fa, &container(0x03ff, &compressed_storage(MARKER))),
    );
    assert!(
        has_marker(&members(&ppt_with(&deep))),
        "nested object missed"
    );
}

/// A record length is attacker-controlled. One that runs past the end of the
/// stream, or that is zero forever, must end the walk rather than loop or panic.
#[test]
#[cfg(feature = "ole")]
fn a_malformed_record_length_terminates_the_walk() {
    // Length far beyond the stream.
    let mut huge = Vec::new();
    huge.extend_from_slice(&0x0010u16.to_le_bytes());
    huge.extend_from_slice(&EXT_OLE_OBJ_STG.to_le_bytes());
    huge.extend_from_slice(&0xffff_fff0u32.to_le_bytes());
    huge.extend_from_slice(b"short");
    let _ = members(&ppt_with(&huge));

    // A run of zero-length records: the walk must still advance by the header.
    let zeros = record(0x0000, 0x0001, b"").repeat(4096);
    let _ = members(&ppt_with(&zeros));

    // Truncated header.
    let _ = members(&ppt_with(b"\x10\x00\x11"));
}

/// Deflate that stops early: the object is damaged, not absent, so whatever
/// decompressed is still handed over rather than dropped.
///
/// The tail is deliberately incompressible, so the encoder emits many blocks
/// and the marker at the front is complete well before the cut. A small,
/// highly compressible payload would be one block, and truncating that yields
/// nothing at all — which is correct behaviour, just not what this is testing.
#[test]
#[cfg(feature = "ole")]
fn a_truncated_deflate_stream_still_yields_what_it_decoded() {
    let mut payload = MARKER.to_vec();
    let mut x: u32 = 0x1234_5678;
    for _ in 0..(256 * 1024) {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        payload.push((x >> 16) as u8);
    }
    let full = deflate(&payload);
    let mut body = (payload.len() as u32).to_le_bytes().to_vec();
    body.extend_from_slice(&full[..full.len() / 2]);
    let entries = members(&ppt_with(&record(0x0010, EXT_OLE_OBJ_STG, &body)));
    assert!(
        has_marker(&entries),
        "a truncated object gave back nothing at all"
    );
}
