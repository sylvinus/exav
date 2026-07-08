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

/// Read the `cbLength` (u64) that follows the GUID at `guid_at`, returning the
/// data start offset and the length clamped to `end` (the bytes available).
fn record_at(guid_at: usize, cb_source: &[u8], data_start: u64, end: u64) -> Option<(u64, u64)> {
    let cb_at = guid_at + FILE_DATA_STORE_GUID.len();
    let cb = cb_source.get(cb_at..cb_at + 8)?;
    if data_start > end {
        return None;
    }
    let declared = u64::from_le_bytes(cb.try_into().ok()?);
    let avail = end - data_start;
    let take = declared.min(avail);
    (take > 0).then_some((data_start, take))
}

/// Streaming variant: scan a bounded prefix for embedded-file records and return
/// each as `(name, offset, size)`; the (possibly large) payload is streamed by
/// the caller via seek+take.
pub(crate) fn stream_offsets<R: std::io::Read + std::io::Seek>(
    source: &mut R,
    max_buffer: u64,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    use std::io::SeekFrom;
    let file_len = source
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("onenote: {e}")))?;
    let scan = max_buffer.min(file_len) as usize;
    let mut prefix = vec![0u8; scan];
    if source.seek(SeekFrom::Start(0)).is_err() {
        return Ok(Vec::new());
    }
    let mut got = 0usize;
    while got < prefix.len() {
        match source.read(&mut prefix[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(_) => break,
        }
    }
    prefix.truncate(got);

    let mut out = Vec::new();
    for (idx, guid_at) in memchr::memmem::Finder::new(&FILE_DATA_STORE_GUID)
        .find_iter(&prefix)
        .enumerate()
    {
        let data_start = (guid_at + FILE_DATA_STORE_GUID.len() + POST_GUID_HEADER) as u64;
        if let Some((off, len)) = record_at(guid_at, &prefix, data_start, file_len) {
            out.push((format!("onenote-embedded-{idx}"), off, len));
        }
    }
    Ok(out)
}

pub(crate) fn extract_onenote<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    for (idx, guid_at) in memchr::memmem::Finder::new(&FILE_DATA_STORE_GUID)
        .find_iter(data)
        .enumerate()
    {
        let data_start = (guid_at + FILE_DATA_STORE_GUID.len() + POST_GUID_HEADER) as u64;
        let Some((off, len)) = record_at(guid_at, data, data_start, data.len() as u64) else {
            continue;
        };
        let (off, len) = (off as usize, len as usize);

        budget.count_entry()?;
        let cap = budget.reserve()?;
        if len as u64 > cap {
            return Err(LimitHit::new("onenote embedded file exceeds budget".to_string()));
        }
        let member = data[off..off + len].to_vec();
        budget.commit(member.len() as u64);
        if let Some(r) = visit(Entry::new(format!("onenote-embedded-{idx}"), member), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
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
        assert!(extract(Format::OneNote, &blob, &mut budget).unwrap().is_empty());
    }

    #[test]
    fn no_object_yields_nothing() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&ONENOTE_HEADER_GUID);
        blob.extend_from_slice(b"a section with no embedded files");
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::OneNote, &blob, &mut budget).unwrap().is_empty());
    }
}
