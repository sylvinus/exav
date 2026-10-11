//! Microsoft OneNote (`.one`) embedded-file extractor.
//!
//! A `.one` section file is a OneStore package; malware abuses it as a delivery
//! container, storing the real payload as an embedded file. Implemented from the
//! open Microsoft specifications **[MS-ONESTORE]** and **[MS-ONE]**:
//!
//! - A `.one` section file opens with the OneNote section GUID
//!   `{7B5C525E-D8C8-4DA7-AEB1-5378D02996D3}` ([MS-ONE] §2.3.1).
//! - Every embedded file is a **FileDataStoreObject** ([MS-ONESTORE] §2.7.6):
//!   the 16-byte GUID `{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}`, then
//!   `cbLength` (u64, the data size), `unused` (u32), `reserved` (u64), then
//!   `cbLength` bytes of the embedded file, then padding.
//!
//! GUIDs are stored in the usual mixed-endian in-memory layout (first three
//! fields little-endian). We locate each FileDataStoreObject by its GUID and
//! carve the declared bytes; `cbLength` is attacker-controlled, so it is clamped
//! to the bytes actually present — a hostile/truncated file cannot panic.

use crate::*;

/// OneNote section-file header GUID `{7B5C525E-D8C8-4DA7-AEB1-5378D02996D3}`
/// (in-memory mixed-endian byte order). Used for detection.
pub(crate) const ONENOTE_HEADER_GUID: [u8; 16] = [
    0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
];

/// FileDataStoreObject GUID `{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}` (in-memory
/// byte order) — the start marker of every embedded-file record.
const FILE_DATA_STORE_GUID: [u8; 16] = [
    0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC,
];

/// Bytes after the GUID before the data: `cbLength`(8) + `unused`(4) +
/// `reserved`(8). With the 16-byte GUID that is the 36-byte record header.
const POST_GUID_HEADER: usize = 8 + 4 + 8;

/// True if `data` opens with the OneNote section header GUID.
pub(crate) fn is_onenote(data: &[u8]) -> bool {
    data.starts_with(&ONENOTE_HEADER_GUID)
}

/// Walk a OneNote section, each embedded file streamed from where it lies.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let members = stream_offsets(src);
    crate::stream::stream_stored(&mut crate::source::Reader::new(src), budget, visit, members)
}

/// Every embedded-file record as `(name, offset, size)`, the payloads left in
/// place for the caller to stream. `cbLength` is clamped to the bytes present.
pub(crate) fn stream_offsets(src: &dyn crate::source::ByteSource) -> Vec<(String, u64, u64)> {
    let len = src.len();
    let mut out = Vec::new();
    let mut from = 0;
    let mut idx = 0;
    while let Some(guid_at) = src.find(&FILE_DATA_STORE_GUID, from, len) {
        from = guid_at + 1;
        let cb_at = guid_at + FILE_DATA_STORE_GUID.len();
        let data_start = cb_at + POST_GUID_HEADER;
        let cb = src.window(cb_at, 8);
        if cb.len() == 8 && data_start <= len {
            let declared =
                u64::from_le_bytes([cb[0], cb[1], cb[2], cb[3], cb[4], cb[5], cb[6], cb[7]]);
            let take = declared.min((len - data_start) as u64);
            if take > 0 {
                out.push((format!("onenote-embedded-{idx}"), data_start as u64, take));
            }
        }
        idx += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one FileDataStoreObject record (GUID + 20-byte header + payload).
    fn push_fds(out: &mut Vec<u8>, payload: &[u8]) {
        out.extend_from_slice(&FILE_DATA_STORE_GUID);
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(payload);
    }

    fn minimal_one(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ONENOTE_HEADER_GUID);
        out.extend_from_slice(b"\x00\x01 filler between header and object \xff");
        push_fds(&mut out, payload);
        out
    }

    #[test]
    fn detects_header_guid() {
        assert!(is_onenote(&minimal_one(b"x")));
        assert!(!is_onenote(b"not a onenote file at all........"));
    }

    #[test]
    fn extracts_one_embedded_file() {
        let blob = minimal_one(b"MALWARETEST");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::OneNote, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "onenote-embedded-0");
        assert_eq!(entries[0].data, b"MALWARETEST");
    }

    #[test]
    fn extracts_multiple() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&ONENOTE_HEADER_GUID);
        push_fds(&mut blob, b"AAA");
        blob.extend_from_slice(b"gap");
        push_fds(&mut blob, b"MALWARETEST");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::OneNote, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"AAA");
        assert_eq!(entries[1].data, b"MALWARETEST");
    }

    #[test]
    fn oversized_length_clamped_no_panic() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&ONENOTE_HEADER_GUID);
        blob.extend_from_slice(&FILE_DATA_STORE_GUID);
        blob.extend_from_slice(&u64::MAX.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u64.to_le_bytes());
        blob.extend_from_slice(b"only-a-few-bytes");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::OneNote, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"only-a-few-bytes");
    }

    #[test]
    fn truncated_header_no_panic() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&ONENOTE_HEADER_GUID);
        blob.extend_from_slice(&FILE_DATA_STORE_GUID);
        blob.extend_from_slice(&[0u8; 3]);
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::OneNote, &blob, &mut budget)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn no_object_yields_nothing() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&ONENOTE_HEADER_GUID);
        blob.extend_from_slice(b"a section with no embedded files");
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::OneNote, &blob, &mut budget)
            .unwrap()
            .is_empty());
    }
}
