//! Cell records of table tiles. Since 2019 a record is version 5: a type
//! byte, a field mask at byte 8, then the fields the mask names in mask
//! order (as numbers-parser's cell.py reads them, MIT). Older records
//! (versions 1 to 4) carry a value, a string or rich-text key and a format,
//! as SheetJS reads them (Apache-2.0); their style keys are not read.

/// Cell types of the type byte (0 is an empty cell).
pub const NUMBER: u8 = 2;
pub const TEXT: u8 = 3;
pub const DATE: u8 = 5;
pub const BOOL: u8 = 6;
pub const DURATION: u8 = 7;
pub const ERROR: u8 = 8;
pub const RICH: u8 = 9;
pub const CURRENCY: u8 = 10;

/// One record's fields; keys index the table's data lists.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Raw {
    pub kind: u8,
    pub decimal: Option<f64>,
    pub double: Option<f64>,
    /// Seconds since 2001-01-01.
    pub seconds: Option<f64>,
    pub string: Option<u32>,
    pub rich: Option<u32>,
    pub cell_style: Option<u32>,
    pub text_style: Option<u32>,
    pub formula: Option<u32>,
    pub formula_error: Option<u32>,
    pub number_format: Option<u32>,
    pub currency_format: Option<u32>,
    pub date_format: Option<u32>,
    pub duration_format: Option<u32>,
    pub text_format: Option<u32>,
    pub bool_format: Option<u32>,
    pub comment: Option<u32>,
}

impl Raw {
    /// The number the cell shows (dates as seconds, durations as seconds).
    pub fn number(&self) -> Option<f64> {
        match self.kind {
            NUMBER | CURRENCY => self.decimal.or(self.double),
            DATE => self.seconds,
            DURATION | BOOL => self.double,
            _ => None,
        }
    }

    /// The format key for the value the cell holds.
    pub fn format(&self) -> Option<u32> {
        match self.kind {
            NUMBER | CURRENCY => self.currency_format.or(self.number_format),
            DATE => self.date_format.or(self.number_format),
            DURATION => self.duration_format.or(self.number_format),
            TEXT | RICH => self.text_format,
            BOOL => self.bool_format,
            _ => None,
        }
    }
}

pub fn decode(b: &[u8]) -> Option<Raw> {
    match *b.first()? {
        5 => decode_v5(b),
        v @ 1..=4 => decode_old(b, v),
        _ => None,
    }
}

fn u32_at(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?))
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl Reader<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = u32_at(self.b, self.p)?;
        self.p += 4;
        Some(v)
    }
    fn f64(&mut self) -> Option<f64> {
        let v = self.b.get(self.p..self.p + 8)?;
        self.p += 8;
        Some(f64::from_le_bytes(v.try_into().ok()?))
    }
    fn skip(&mut self, n: usize) {
        self.p += n;
    }
}

fn decode_v5(b: &[u8]) -> Option<Raw> {
    let flags = u32_at(b, 8)?;
    let mut r = Reader { b, p: 12 };
    let mut c = Raw {
        kind: *b.get(1)?,
        ..Raw::default()
    };
    if flags & 0x1 != 0 {
        c.decimal = Some(decimal128(b.get(r.p..r.p + 16)?));
        r.skip(16);
    }
    if flags & 0x2 != 0 {
        c.double = Some(r.f64()?);
    }
    if flags & 0x4 != 0 {
        c.seconds = Some(r.f64()?);
    }
    // The 4-byte keys, in mask order.
    let keys: [(u32, Option<&mut Option<u32>>); 17] = [
        (0x8, Some(&mut c.string)),
        (0x10, Some(&mut c.rich)),
        (0x20, Some(&mut c.cell_style)),
        (0x40, Some(&mut c.text_style)),
        (0x80, None),
        (0x100, None),
        (0x200, Some(&mut c.formula)),
        (0x400, None),
        (0x800, Some(&mut c.formula_error)),
        (0x1000, None),
        (0x2000, Some(&mut c.number_format)),
        (0x4000, Some(&mut c.currency_format)),
        (0x8000, Some(&mut c.date_format)),
        (0x10000, Some(&mut c.duration_format)),
        (0x20000, Some(&mut c.text_format)),
        (0x40000, Some(&mut c.bool_format)),
        (0x80000, Some(&mut c.comment)),
    ];
    for (bit, slot) in keys {
        if flags & bit == 0 {
            continue;
        }
        let v = r.u32()?;
        if let Some(s) = slot {
            *s = Some(v);
        }
    }
    Some(c)
}

fn decode_old(b: &[u8], v: u8) -> Option<Raw> {
    let flags = u32_at(b, 4)?;
    let mut r = Reader {
        b,
        p: if v > 1 { 12 } else { 8 },
    };
    let mut c = Raw {
        kind: *b.get(if v >= 4 { 1 } else { 2 })?,
        ..Raw::default()
    };
    let mut format = None;
    if flags & 0x2 != 0 {
        format = Some(r.u32()?);
    }
    r.skip((flags & if v > 1 { 0xD8C } else { 0x18C }).count_ones() as usize * 4);
    if flags & 0x200 != 0 {
        c.rich = Some(r.u32()?);
    }
    r.skip((flags & if v > 1 { 0x3000 } else { 0x1000 }).count_ones() as usize * 4);
    if flags & 0x10 != 0 {
        c.string = Some(r.u32()?);
    }
    if flags & 0x20 != 0 {
        c.double = Some(r.f64()?);
    }
    if flags & 0x40 != 0 {
        c.seconds = Some(r.f64()?);
    }
    if v > 1 && (u32_at(b, 8)? >> 16) & 0xFF != 0 && format.is_none() {
        format = Some(r.u32()?);
    }
    c.number_format = format;
    if c.kind == NUMBER {
        c.decimal = c.double;
    }
    Some(c)
}

/// An IEEE 754 decimal128 in the binary integer encoding, as Numbers
/// stores it: a 14-bit exponent biased by 6176 and a 113-bit coefficient.
/// Parsed through its decimal text, so that the double is the nearest one.
pub fn decimal128(b: &[u8]) -> f64 {
    if b.len() < 16 {
        return 0.0;
    }
    let exp = ((i32::from(b[15] & 0x7F) << 7) | i32::from(b[14] >> 1)) - 6176;
    let mut m: u128 = u128::from(b[14] & 1);
    for &x in b[..14].iter().rev() {
        m = (m << 8) | u128::from(x);
    }
    let sign = if b[15] & 0x80 != 0 { "-" } else { "" };
    format!("{sign}{m}e{exp}").parse().unwrap_or(0.0)
}

/// The column records of one tile row: `offsets` are 16-bit, in units of
/// 4 bytes when `wide`, negative for an empty column.
pub fn row_cells<'a>(storage: &'a [u8], offsets: &[u8], wide: bool) -> Vec<(u32, &'a [u8])> {
    let starts: Vec<Option<usize>> = offsets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|o| {
            let v = i16::from_le_bytes(*o);
            (v >= 0).then(|| v as usize * if wide { 4 } else { 1 })
        })
        .collect();
    let mut out = vec![];
    for (col, s) in starts.iter().enumerate() {
        let Some(s) = *s else { continue };
        let end = starts[col + 1..]
            .iter()
            .flatten()
            .next()
            .copied()
            .unwrap_or(storage.len())
            .min(storage.len());
        if let Some(rec) = storage.get(s..end.max(s)) {
            out.push((col as u32, rec));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d128(m: u64, exp: i32, neg: bool) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&m.to_le_bytes());
        let e = (exp + 6176) as u32;
        b[14] |= ((e & 0x7F) << 1) as u8;
        b[15] |= (e >> 7) as u8;
        if neg {
            b[15] |= 0x80;
        }
        b
    }

    #[test]
    fn decimals() {
        assert_eq!(decimal128(&d128(12345, -2, false)), 123.45);
        assert_eq!(decimal128(&d128(1, 3, true)), -1000.0);
        assert_eq!(decimal128(&d128(0, 0, false)), 0.0);
        // 0.1 is the double nearest to 1e-1, not 1 * 0.1 computed.
        assert_eq!(decimal128(&d128(1, -1, false)), 0.1);
    }

    #[test]
    fn v5_fields_in_mask_order() {
        let mut b = vec![5u8, NUMBER, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(&(0x1u32 | 0x20 | 0x200 | 0x2000).to_le_bytes());
        b.extend_from_slice(&d128(42, 0, false));
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&9u32.to_le_bytes());
        b.extend_from_slice(&3u32.to_le_bytes());
        let c = decode(&b).unwrap();
        assert_eq!(c.number(), Some(42.0));
        assert_eq!(
            (c.cell_style, c.formula, c.number_format),
            (Some(7), Some(9), Some(3))
        );
        assert_eq!(c.format(), Some(3));
        // Truncated: refused, not misread.
        assert!(decode(&b[..b.len() - 2]).is_none());
    }

    #[test]
    fn offsets() {
        let storage = b"aaaabbbbbbbbcccc";
        // Columns 0, 2 and 3; column 1 empty.
        let offs: Vec<u8> = [0i16, -1, 1, 3]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let cells = row_cells(storage, &offs, true);
        assert_eq!(
            cells,
            vec![
                (0, &storage[0..4]),
                (2, &storage[4..12]),
                (3, &storage[12..16])
            ]
        );
        // An offset past the buffer is dropped.
        let offs: Vec<u8> = [0i16, 100].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(row_cells(storage, &offs, false).len(), 1);
    }
}
