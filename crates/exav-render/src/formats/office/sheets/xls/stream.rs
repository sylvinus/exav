//! The BIFF record stream: a compound file's "Workbook" or "Book" stream, or
//! a bare BIFF stream, read as records by `exav_unpack::biff`.

use crate::formats::office::common::bytes::u16_at;
use crate::formats::office::sheets::error::{Error, Result};
use exav_unpack::cfb::{Compound, SIGNATURE};

pub(crate) use exav_unpack::biff::{BOF_IDS, Rec, bof_type, bof_version};

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

pub(crate) fn records(stream: &[u8]) -> Vec<Rec<'_>> {
    exav_unpack::biff::records(stream).collect()
}
