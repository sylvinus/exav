//! The BIFF record stream: a compound file's "Workbook" or "Book" stream, or
//! a bare BIFF stream, as records, with the payload of the CONTINUE records
//! of the records that are continued joined to them.

use crate::bytes::u16_at;
use std::borrow::Cow;

pub struct Rec<'a> {
    pub id: u16,
    /// Offset of the record header in the stream (BOUNDSHEET points there).
    pub pos: usize,
    /// Borrowed from the stream unless CONTINUE records were joined to it.
    pub data: Cow<'a, [u8]>,
    /// Offsets in `data` where a CONTINUE record's payload starts.
    pub breaks: Vec<usize>,
}

pub const CONTINUE: u16 = 0x003C;
/// The BOF record of BIFF8 and BIFF5, BIFF4, BIFF3 and BIFF2.
pub const BOF_IDS: [u16; 4] = [0x0809, 0x0409, 0x0209, 0x0009];

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

/// The records of `stream`, read as they are asked for: a stream of
/// four-byte records costs nothing until a reader keeps them. A record cut
/// short by the end of the stream keeps what is there.
pub fn records(stream: &[u8]) -> Records<'_> {
    Records { stream, p: 0 }
}

pub struct Records<'a> {
    stream: &'a [u8],
    p: usize,
}

impl Records<'_> {
    /// The header at `p`: (id, payload range), the payload cut at the end of the stream.
    fn header(&self, p: usize) -> Option<(u16, std::ops::Range<usize>)> {
        if p + 4 > self.stream.len() {
            return None;
        }
        let len = u16_at(self.stream, p + 2) as usize;
        Some((
            u16_at(self.stream, p),
            p + 4..(p + 4 + len).min(self.stream.len()),
        ))
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Rec<'a>;

    fn next(&mut self) -> Option<Rec<'a>> {
        let (id, range) = self.header(self.p)?;
        let pos = self.p;
        self.p = range.end;
        let mut data = Cow::Borrowed(&self.stream[range]);
        let mut breaks = vec![];
        if continued(id) {
            while let Some((CONTINUE, more)) = self.header(self.p) {
                breaks.push(data.len());
                data.to_mut().extend_from_slice(&self.stream[more.clone()]);
                self.p = more.end;
            }
        }
        Some(Rec {
            id,
            pos,
            data,
            breaks,
        })
    }
}

/// BIFF version of a BOF record: 2, 3, 4, 5 or 8 (0 for no BOF).
pub fn bof_version(rec: &Rec) -> u8 {
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
pub fn bof_type(rec: &Rec) -> u16 {
    u16_at(&rec.data, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u16, body: &[u8]) -> Vec<u8> {
        let mut v = id.to_le_bytes().to_vec();
        v.extend((body.len() as u16).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn continue_records_are_joined_to_the_records_that_take_them() {
        let mut s = rec(0x0006, b"ab");
        s.extend(rec(CONTINUE, b"cd"));
        s.extend(rec(0x0203, b"ef"));
        // A CONTINUE after a record that is not continued stands alone.
        s.extend(rec(CONTINUE, b"gh"));
        let r: Vec<_> = records(&s).collect();
        assert_eq!(r.len(), 3);
        assert_eq!(
            (r[0].data.as_ref(), r[0].breaks.as_slice()),
            (&b"abcd"[..], &[2][..])
        );
        assert!(matches!(r[1].data, Cow::Borrowed(_)));
        assert_eq!(r[2].id, CONTINUE);
    }

    #[test]
    fn a_record_cut_short_keeps_what_is_there() {
        let mut s = rec(0x0203, b"abcd");
        s.truncate(s.len() - 2);
        let r: Vec<_> = records(&s).collect();
        assert_eq!(r[0].data.as_ref(), b"ab");
    }
}
