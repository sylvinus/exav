//! The BIFF record stream: from a compound file's "Workbook" or "Book"
//! stream, or a bare BIFF stream, as records, with the payload of the
//! CONTINUE records of the records that are continued joined to them.

use crate::formats::office::common::bytes::u16_at;
use crate::formats::office::common::cfb::{Compound, SIGNATURE};
use crate::formats::office::sheets::error::{Error, Result};

pub(crate) struct Rec {
    pub id: u16,
    /// Offset of the record header in the stream (BOUNDSHEET points there).
    pub pos: usize,
    pub data: Vec<u8>,
    /// Offsets in `data` where a CONTINUE record's payload starts.
    pub breaks: Vec<usize>,
}

pub(crate) const CONTINUE: u16 = 0x003C;
pub(crate) const BOF_IDS: [u16; 4] = [0x0809, 0x0409, 0x0209, 0x0009];

/// Records whose CONTINUE records carry the rest of their payload.
fn continued(id: u16) -> bool {
    matches!(
        id,
        0x00FC // SST
            | 0x01B6 // TXO
            | 0x00EB // MSODRAWINGGROUP
            | 0x00EC // MSODRAWING
            | 0x0018 // NAME
            | 0x0006 // FORMULA
            | 0x0221 // ARRAY
            | 0x04BC // SHRFMLA
            | 0x01B8 // HLINK
            | 0x01BE // DV
            | 0x01B1 // CF
            | 0x087A // CF12
            | 0x0023 // EXTERNNAME
            | 0x0017 // EXTERNSHEET
            | 0x01AE // SUPBOOK
            | 0x0207 // STRING
    )
}

/// The workbook stream.
pub(crate) fn open(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.starts_with(&SIGNATURE) {
        let c = Compound::open(bytes)
            .ok_or_else(|| Error::Malformed("unreadable compound file".into()))?;
        return match c.stream(&["Workbook", "Book"]) {
            Some(s) if s.len() >= 4 => Ok(s),
            _ => {
                if c.names()
                    .any(|n| n.eq_ignore_ascii_case("EncryptedPackage"))
                {
                    return Err(Error::NotFormat("an encrypted OOXML file".into()));
                }
                Err(Error::NotFormat("no Workbook stream".into()))
            }
        };
    }
    if bytes.len() >= 8 && BOF_IDS.contains(&u16_at(bytes, 0)) && u16_at(bytes, 2) as usize >= 4 {
        return Ok(bytes.to_vec());
    }
    Err(Error::NotFormat(
        "not a compound file nor a BIFF stream".into(),
    ))
}

pub(crate) fn records(stream: &[u8]) -> Vec<Rec> {
    let mut out: Vec<Rec> = Vec::new();
    let mut p = 0;
    while p + 4 <= stream.len() {
        let id = u16_at(stream, p);
        let len = u16_at(stream, p + 2) as usize;
        let end = (p + 4 + len).min(stream.len());
        let data = &stream[p + 4..end];
        if id == CONTINUE {
            if let Some(last) = out.last_mut() {
                if continued(last.id) {
                    last.breaks.push(last.data.len());
                    last.data.extend_from_slice(data);
                    p = end;
                    continue;
                }
            }
        }
        out.push(Rec {
            id,
            pos: p,
            data: data.to_vec(),
            breaks: vec![],
        });
        p = end;
    }
    out
}

/// BIFF version of a BOF record: 2, 3, 4, 5 or 8 (0 for no BOF).
pub(crate) fn bof_version(rec: &Rec) -> u8 {
    match rec.id {
        0x0009 => 2,
        0x0209 => 3,
        0x0409 => 4,
        0x0809 => match u16_at(&rec.data, 0) {
            0x0600 => 8,
            0x0500 | 0x0400 | 0x0300 | 0x0200 => 5,
            // Writers that leave the version out or write garbage: by length.
            _ if rec.data.len() >= 16 => 8,
            _ => 5,
        },
        _ => 0,
    }
}

/// BOF substream type: 0x05 globals, 0x10 worksheet, 0x20 chart, 0x40 macro
/// sheet, 0x100 workspace. BIFF2 to BIFF4 keep it at the same place.
pub(crate) fn bof_type(rec: &Rec) -> u16 {
    u16_at(&rec.data, 2)
}
