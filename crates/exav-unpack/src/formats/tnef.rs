//! TNEF (`winmail.dat`) attachment extractor.
//!
//! Implemented from the public **[MS-OXTNEF]** specification. TNEF is the
//! container Outlook/Exchange uses to carry message properties and file
//! attachments; malware hides its payload in the embedded attachment, so we
//! carve attachment attributes out for the engine to recurse into.
//!
//! Structure (little-endian): a `u32` signature `0x223E9F78`, a `u16` key, then a
//! sequence of attribute records — a `u8` level (`1` = message, `2` = attachment),
//! a `u32` whose low 16 bits are the attribute id and high 16 the type, a `u32`
//! length, `length` data bytes, and a `u16` checksum (not verified). We emit the
//! attachment-level attributes `attAttachData` (`0x800F`, the file bytes),
//! `attAttachTitle` (`0x8010`, the file name, used to name the next data record),
//! and `attAttachment` (`0x9005`, a MAPI blob that can wrap an OLE object).
//!
//! Every length is clamped to the bytes actually present, so hostile/truncated
//! input cannot panic or read out of bounds.

use crate::*;

/// Signature `0x223E9F78`, little-endian.
const TNEF_SIGNATURE_LE: [u8; 4] = [0x78, 0x9F, 0x3E, 0x22];

const LVL_ATTACHMENT: u8 = 0x02;
const ATT_ATTACHDATA: u16 = 0x800F;
const ATT_ATTACHTITLE: u16 = 0x8010;
const ATT_ATTACHMENT: u16 = 0x9005;

/// A NUL-terminated attachment title → `String` (lossy UTF-8).
fn attachment_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Streaming variant: walk the TLV records off a seekable source and return each
/// attachment payload as `(name, offset, size)`; titles are read to name them.
pub(crate) fn stream_offsets<R: std::io::Read + std::io::Seek>(
    source: &mut R,
    max_buffer: u64,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    use std::io::SeekFrom;
    let len = source
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("tnef: {e}")))?;
    let mut sig = [0u8; 6];
    if source
        .seek(SeekFrom::Start(0))
        .and_then(|_| source.read_exact(&mut sig))
        .is_err()
        || sig[0..4] != TNEF_SIGNATURE_LE
    {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut pos = 6u64;
    while pos < len {
        if source.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        let mut hdr = [0u8; 9]; // level(1) + type_and_id(4) + length(4)
        let mut got = 0;
        while got < 9 {
            match source.read(&mut hdr[got..]) {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(_) => break,
            }
        }
        if got < 9 || hdr[0] == 0 {
            break;
        }
        let level = hdr[0];
        let tag = (u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) & 0xFFFF) as u16;
        let length = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as u64;
        pos += 9;
        if length == 0 {
            continue;
        }
        let data_start = pos;
        let clamped = length.min(len - data_start);
        let truncated = clamped < length;
        if level == LVL_ATTACHMENT {
            match tag {
                ATT_ATTACHTITLE => {
                    let n = clamped.min(max_buffer) as usize;
                    let mut buf = vec![0u8; n];
                    if source.seek(SeekFrom::Start(data_start)).is_ok() {
                        let mut g = 0;
                        while g < buf.len() {
                            match source.read(&mut buf[g..]) {
                                Ok(0) => break,
                                Ok(k) => g += k,
                                Err(_) => break,
                            }
                        }
                        buf.truncate(g);
                    }
                    name = Some(attachment_name(&buf));
                }
                ATT_ATTACHDATA | ATT_ATTACHMENT => {
                    out.push((
                        name.clone().unwrap_or_else(|| "tnef-attachment".to_string()),
                        data_start,
                        clamped,
                    ));
                }
                _ => {}
            }
        }
        pos = data_start + clamped + 2; // skip data + checksum
        if truncated {
            break;
        }
    }
    Ok(out)
}

pub(crate) fn extract_tnef<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let len = data.len();
    if len < 6 || !data.starts_with(&TNEF_SIGNATURE_LE) {
        return Ok(None);
    }
    let le32 = |p: usize| u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
    let mut pos = 6usize; // signature + key
    let mut name: Option<String> = None;

    while pos < len {
        let level = data[pos];
        pos += 1;
        if level == 0 {
            break;
        }
        if pos + 8 > len {
            break;
        }
        let tag = (le32(pos) & 0xFFFF) as u16;
        let length = le32(pos + 4) as usize;
        pos += 8;
        if length == 0 {
            continue;
        }
        let data_start = pos;
        let clamped = length.min(len - data_start);
        let truncated = clamped < length;
        let record = &data[data_start..data_start + clamped];

        if level == LVL_ATTACHMENT {
            match tag {
                ATT_ATTACHTITLE => name = Some(attachment_name(record)),
                ATT_ATTACHDATA | ATT_ATTACHMENT => {
                    budget.count_entry()?;
                    let cap = budget.reserve()?;
                    if clamped as u64 > cap {
                        return Err(LimitHit::new("tnef attachment exceeds budget".to_string()));
                    }
                    let member_name = name.clone().unwrap_or_else(|| "tnef-attachment".to_string());
                    let bytes = record.to_vec();
                    budget.commit(bytes.len() as u64);
                    if let Some(r) = visit(Entry::new(member_name, bytes), budget) {
                        return Ok(Some(r));
                    }
                }
                _ => {}
            }
        }
        pos = (data_start + clamped).saturating_add(2);
        if truncated {
            break;
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_record(out: &mut Vec<u8>, tag: u16, payload: &[u8]) {
        out.push(LVL_ATTACHMENT);
        out.extend_from_slice(&(tag as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&0u16.to_le_bytes()); // checksum (ignored)
    }

    fn minimal_tnef() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TNEF_SIGNATURE_LE);
        out.extend_from_slice(&0x1234u16.to_le_bytes());
        push_record(&mut out, ATT_ATTACHTITLE, b"evil.exe\0");
        push_record(&mut out, ATT_ATTACHDATA, b"MALWARETEST");
        out
    }

    #[test]
    fn extracts_named_attachment() {
        let blob = minimal_tnef();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Tnef, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "evil.exe");
        assert_eq!(entries[0].data, b"MALWARETEST");
    }

    #[test]
    fn truncated_length_no_panic() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&TNEF_SIGNATURE_LE);
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.push(LVL_ATTACHMENT);
        blob.extend_from_slice(&(ATT_ATTACHDATA as u32).to_le_bytes());
        blob.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        blob.extend_from_slice(b"short");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Tnef, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"short");
    }

    #[test]
    fn non_tnef_yields_nothing() {
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Tnef, b"not a tnef file", &mut budget).unwrap().is_empty());
    }
}
