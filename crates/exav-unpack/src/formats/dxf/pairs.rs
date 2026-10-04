//! Group code and value pairs, from ASCII or binary DXF.
//!
//! ASCII: a group code line, then a value line, each ended by CR LF, LF or
//! CR. Binary: after the 22-byte sentinel, a 2-byte little-endian group code
//! (1 byte before R14, with 255 escaping a 2-byte code) and a value whose
//! form the code decides: a NUL-terminated string, a 1-byte boolean, a 2-,
//! 4- or 8-byte integer, an 8-byte double, or a 1-byte length and that many
//! bytes for binary chunks (DXF reference, "Binary DXF Files" and "Group Code
//! Value Types").

/// What a binary DXF file starts with.
pub const BINARY_SENTINEL: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\0";

/// A value as the file gives it. ASCII values are text until a reader asks
/// for a number.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value<'a> {
    Text(&'a [u8]),
    Double(f64),
    Int(i64),
    Bytes(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tag<'a> {
    pub code: i32,
    pub value: Value<'a>,
}

fn trim(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    b.get(start..end).unwrap_or(&[])
}

fn parse_f64(b: &[u8]) -> Option<f64> {
    std::str::from_utf8(trim(b)).ok()?.parse::<f64>().ok()
}

fn parse_i64(b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(trim(b)).ok()?;
    if let Ok(v) = s.parse::<i64>() {
        return Some(v);
    }
    // Some writers put a real where an integer belongs ("1.0").
    let f = s.parse::<f64>().ok()?;
    (f.is_finite() && f.abs() < 9.0e18).then_some(f as i64)
}

impl<'a> Tag<'a> {
    /// The value as a double; 0 when it is not a number.
    pub fn f64(&self) -> f64 {
        match self.value {
            Value::Double(v) => v,
            Value::Int(v) => v as f64,
            Value::Text(t) => parse_f64(t).unwrap_or(0.0),
            Value::Bytes(_) => 0.0,
        }
    }

    /// The value as an integer; 0 when it is not a number.
    pub fn int(&self) -> i64 {
        match self.value {
            Value::Int(v) => v,
            Value::Double(v) if v.is_finite() && v.abs() < 9.0e18 => v as i64,
            Value::Double(_) => 0,
            Value::Text(t) => parse_i64(t).unwrap_or(0),
            Value::Bytes(_) => 0,
        }
    }

    pub fn i16(&self) -> i16 {
        let v = self.int();
        v.clamp(i16::MIN.into(), i16::MAX.into()) as i16
    }

    pub fn i32(&self) -> i32 {
        let v = self.int();
        v.clamp(i32::MIN.into(), i32::MAX.into()) as i32
    }

    pub fn bool(&self) -> bool {
        self.int() != 0
    }

    /// The raw bytes of a string value.
    pub fn bytes(&self) -> &'a [u8] {
        match self.value {
            Value::Text(t) | Value::Bytes(t) => t,
            _ => &[],
        }
    }

    /// A string value compared as ASCII, without trailing whitespace.
    pub fn is(&self, s: &str) -> bool {
        let b = self.bytes();
        let end = b
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map_or(0, |e| e + 1);
        b.get(..end)
            .is_some_and(|b| b.eq_ignore_ascii_case(s.as_bytes()))
    }

    /// Append a binary chunk's bytes (groups 310-319, 1004) to `out`: the
    /// bytes themselves in a binary file, the hexadecimal text decoded in an
    /// ASCII one. False when the text is not hexadecimal (what decoded before
    /// the fault is kept).
    pub fn chunk_into(&self, out: &mut Vec<u8>) -> bool {
        match self.value {
            Value::Bytes(b) => {
                out.extend_from_slice(b);
                true
            }
            Value::Text(t) => {
                let t = trim(t);
                let (pairs, rest) = t.as_chunks::<2>();
                for [h, l] in pairs {
                    let digit = |c: u8| char::from(c).to_digit(16);
                    match (digit(*h), digit(*l)) {
                        (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                        _ => return false,
                    }
                }
                rest.is_empty()
            }
            Value::Int(_) | Value::Double(_) => false,
        }
    }

    /// A handle: hexadecimal text, as groups 5, 105, 320-369, 390-399 and
    /// 480-481 hold them.
    pub fn handle(&self) -> u64 {
        match self.value {
            Value::Text(t) | Value::Bytes(t) => {
                let t = trim(t);
                if t.is_empty() || t.len() > 16 {
                    return 0;
                }
                std::str::from_utf8(t)
                    .ok()
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0)
            }
            Value::Int(v) => v as u64,
            Value::Double(_) => 0,
        }
    }
}

/// How the binary form stores a group code's value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Text,
    Double,
    I16,
    I32,
    I64,
    Bool,
    Chunk,
}

fn kind_of(code: i32) -> Option<Kind> {
    Some(match code {
        0..=9
        | 100..=102
        | 105
        | 300..=309
        | 320..=369
        | 390..=399
        | 410..=419
        | 430..=439
        | 470..=481
        | 999
        | 1000..=1003
        | 1005..=1009 => Kind::Text,
        310..=319 | 1004 => Kind::Chunk,
        10..=59 | 110..=149 | 210..=239 | 460..=469 | 1010..=1059 => Kind::Double,
        60..=79 | 170..=179 | 270..=289 | 370..=389 | 400..=409 | 1060..=1070 => Kind::I16,
        90..=99 | 420..=429 | 440..=459 | 1071 => Kind::I32,
        160..=169 => Kind::I64,
        290..=299 => Kind::Bool,
        _ => return None,
    })
}

/// The forms tried, in order, for a value whose code is not documented.
const UNKNOWN_FORMS: [Kind; 4] = [Kind::Double, Kind::I16, Kind::I32, Kind::Text];

/// Why tokenizing stopped before the end of the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Ran out of bytes mid-tag.
    Truncated,
    /// A group code that is not a number, or one the binary form cannot
    /// carry.
    BadCode(u64),
}

/// Group code and value pairs from a whole file.
pub struct Tags<'a> {
    data: &'a [u8],
    pos: usize,
    form: Form,
    /// Set once iteration ends early.
    pub stop: Option<Stop>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    Ascii,
    /// Binary with 2-byte group codes.
    Binary,
    /// Binary with 1-byte group codes (before R14).
    BinaryShort,
}

impl<'a> Tags<'a> {
    pub fn new(data: &'a [u8]) -> Tags<'a> {
        if let Some(rest) = data.strip_prefix(BINARY_SENTINEL) {
            // The first pair is 0 SECTION: a 1-byte code is followed by "S",
            // a 2-byte one by a second zero.
            let form = match rest.get(1) {
                Some(0) => Form::Binary,
                _ => Form::BinaryShort,
            };
            return Tags {
                data,
                pos: BINARY_SENTINEL.len(),
                form,
                stop: None,
            };
        }
        let pos = if data.starts_with(b"\xEF\xBB\xBF") {
            3
        } else {
            0
        };
        Tags {
            data,
            pos,
            form: Form::Ascii,
            stop: None,
        }
    }

    pub fn is_binary(&self) -> bool {
        self.form != Form::Ascii
    }

    /// Byte offset of the next pair.
    pub fn offset(&self) -> usize {
        self.pos
    }

    fn line(&mut self) -> Option<&'a [u8]> {
        let rest = self.data.get(self.pos..)?;
        if rest.is_empty() {
            return None;
        }
        let end = rest
            .iter()
            .position(|&c| c == b'\n' || c == b'\r')
            .unwrap_or(rest.len());
        let line = rest.get(..end)?;
        let mut next = end;
        match (rest.get(end), rest.get(end + 1)) {
            (Some(b'\r'), Some(b'\n')) => next += 2,
            (Some(_), _) => next += 1,
            (None, _) => {}
        }
        self.pos += next;
        Some(line)
    }

    fn next_ascii(&mut self) -> Option<Tag<'a>> {
        let code = loop {
            let start = self.pos;
            let code = trim(self.line()?);
            // A blank line between pairs is tolerated; anything else that is
            // not a number is not a group code.
            if code.is_empty() {
                continue;
            }
            match std::str::from_utf8(code)
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
            {
                Some(c) => break c,
                None => {
                    self.stop = Some(Stop::BadCode(start as u64));
                    return None;
                }
            }
        };
        let Some(value) = self.line() else {
            self.stop = Some(Stop::Truncated);
            return None;
        };
        Some(Tag {
            code,
            value: Value::Text(value),
        })
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let b = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }

    fn take_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// Bytes a value of this form takes at `pos`, if the data has them.
    fn value_len(&self, pos: usize, kind: Kind) -> Option<usize> {
        let rest = self.data.get(pos..)?;
        let n = match kind {
            Kind::Text => rest.iter().position(|&c| c == 0)? + 1,
            Kind::Chunk => usize::from(*rest.first()?) + 1,
            Kind::Double | Kind::I64 => 8,
            Kind::I32 => 4,
            Kind::I16 => 2,
            Kind::Bool => 1,
        };
        (n <= rest.len()).then_some(n)
    }

    /// A code and its value at `pos`, if the code is known: the position
    /// after them.
    fn known_pair(&self, pos: usize) -> Option<usize> {
        let (code, at) = match self.form {
            Form::BinaryShort => match *self.data.get(pos)? {
                255 => {
                    let b = self.data.get(pos + 1..pos + 3)?;
                    (
                        i32::from(i16::from_le_bytes([*b.first()?, *b.get(1)?])),
                        pos + 3,
                    )
                }
                c => (i32::from(c), pos + 1),
            },
            _ => {
                let b = self.data.get(pos..pos + 2)?;
                (
                    i32::from(i16::from_le_bytes([*b.first()?, *b.get(1)?])),
                    pos + 2,
                )
            }
        };
        let kind = kind_of(code)?;
        Some(at + self.value_len(at, kind)?)
    }

    /// Whether reading the value at the current position as `kind` leaves
    /// two known pairs after it, or the end of the data.
    fn plausible_after(&self, kind: Kind) -> bool {
        let Some(len) = self.value_len(self.pos, kind) else {
            return false;
        };
        let mut at = self.pos + len;
        for _ in 0..2 {
            if at >= self.data.len() {
                return true;
            }
            match self.known_pair(at) {
                Some(next) => at = next,
                None => return false,
            }
        }
        true
    }

    fn next_binary(&mut self) -> Option<Tag<'a>> {
        if self.pos >= self.data.len() {
            return None;
        }
        let code = match self.form {
            Form::BinaryShort => match self.take_array::<1>()? {
                [255] => i32::from(i16::from_le_bytes(self.take_array::<2>()?)),
                [c] => i32::from(c),
            },
            _ => i32::from(i16::from_le_bytes(self.take_array::<2>()?)),
        };
        let kind = match kind_of(code) {
            Some(k) => k,
            // A code outside the documented ranges (XRECORD data from ODA
            // carries 5001 and 5008, doubles in the ASCII form): its value's
            // size is not known. Take the first form after which the next two
            // pairs read with known codes.
            None => match UNKNOWN_FORMS.into_iter().find(|k| self.plausible_after(*k)) {
                Some(k) => k,
                None => {
                    self.stop = Some(Stop::BadCode(self.pos as u64));
                    return None;
                }
            },
        };
        let value = match kind {
            Kind::Text => {
                let rest = self.data.get(self.pos..)?;
                let end = rest.iter().position(|&c| c == 0)?;
                let s = self.take(end)?;
                self.pos += 1;
                Value::Text(s)
            }
            Kind::Chunk => {
                let [len] = self.take_array::<1>()?;
                Value::Bytes(self.take(usize::from(len))?)
            }
            Kind::Double => Value::Double(f64::from_le_bytes(self.take_array()?)),
            Kind::I16 => Value::Int(i16::from_le_bytes(self.take_array()?).into()),
            Kind::I32 => Value::Int(i32::from_le_bytes(self.take_array()?).into()),
            Kind::I64 => Value::Int(i64::from_le_bytes(self.take_array()?)),
            // R12 binary has no booleans; 290-299 do not occur there.
            Kind::Bool => {
                let [b] = self.take_array::<1>()?;
                Value::Int(b.into())
            }
        };
        Some(Tag { code, value })
    }
}

impl<'a> Iterator for Tags<'a> {
    type Item = Tag<'a>;

    fn next(&mut self) -> Option<Tag<'a>> {
        if self.stop.is_some() {
            return None;
        }
        let before = self.pos;
        let tag = match self.form {
            Form::Ascii => self.next_ascii(),
            Form::Binary | Form::BinaryShort => self.next_binary(),
        };
        // Bytes were left but no whole pair: the file is cut short. Trailing
        // blank lines in an ASCII file are not.
        if tag.is_none() && self.stop.is_none() && before < self.data.len() {
            let rest = self.data.get(before..).unwrap_or(&[]);
            if self.is_binary() || !rest.iter().all(u8::is_ascii_whitespace) {
                self.stop = Some(Stop::Truncated);
            }
        }
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(data: &[u8]) -> (Vec<(i32, Vec<u8>)>, Option<Stop>) {
        let mut t = Tags::new(data);
        let v = (&mut t)
            .map(|t| (t.code, t.bytes().to_vec()))
            .collect::<Vec<_>>();
        (v, t.stop)
    }

    #[test]
    fn ascii_line_ends_and_padding() {
        let (v, stop) = all(b"  0\r\nSECTION\n  2\rHEADER\r\n999\r\n comment \r\n");
        assert_eq!(
            v,
            vec![
                (0, b"SECTION".to_vec()),
                (2, b"HEADER".to_vec()),
                (999, b" comment ".to_vec())
            ]
        );
        assert_eq!(stop, None);
    }

    #[test]
    fn an_empty_value_line_is_a_value() {
        let (v, _) = all(b"1\n\n0\nEOF\n");
        assert_eq!(v, vec![(1, vec![]), (0, b"EOF".to_vec())]);
    }

    #[test]
    fn a_missing_value_is_truncation() {
        let (v, stop) = all(b"0\nSECTION\n2");
        assert_eq!(v.len(), 1);
        assert_eq!(stop, Some(Stop::Truncated));
    }

    #[test]
    fn binary_values_take_the_form_their_code_says() {
        let mut b = BINARY_SENTINEL.to_vec();
        b.extend_from_slice(&0i16.to_le_bytes());
        b.extend_from_slice(b"SECTION\0");
        b.extend_from_slice(&10i16.to_le_bytes());
        b.extend_from_slice(&1.5f64.to_le_bytes());
        b.extend_from_slice(&70i16.to_le_bytes());
        b.extend_from_slice(&(-3i16).to_le_bytes());
        b.extend_from_slice(&90i16.to_le_bytes());
        b.extend_from_slice(&70000i32.to_le_bytes());
        b.extend_from_slice(&290i16.to_le_bytes());
        b.push(1);
        b.extend_from_slice(&310i16.to_le_bytes());
        b.extend_from_slice(&[3, 0xAA, 0xBB, 0xCC]);
        let mut t = Tags::new(&b);
        assert!(t.is_binary());
        let tags: Vec<Tag> = (&mut t).collect();
        assert_eq!(t.stop, None);
        assert!(tags[0].is("SECTION"));
        assert_eq!(tags[1].f64(), 1.5);
        assert_eq!(tags[2].int(), -3);
        assert_eq!(tags[3].int(), 70000);
        assert!(tags[4].bool());
        assert_eq!(tags[5].bytes(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn binary_r12_codes_are_one_byte_with_an_escape() {
        let mut b = BINARY_SENTINEL.to_vec();
        b.push(0);
        b.extend_from_slice(b"SECTION\0");
        b.push(255);
        b.extend_from_slice(&1071i16.to_le_bytes());
        b.extend_from_slice(&999999i32.to_le_bytes());
        let tags: Vec<Tag> = Tags::new(&b).collect();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[1].code, 1071);
        assert_eq!(tags[1].int(), 999999);
    }

    /// ODA writes XRECORD data under 5001 and 5008, codes no range types;
    /// in its ASCII form the values are reals.
    #[test]
    fn an_undocumented_binary_code_is_read_by_what_follows_it() {
        let mut b = BINARY_SENTINEL.to_vec();
        b.extend_from_slice(&0i16.to_le_bytes());
        b.extend_from_slice(b"XRECORD\0");
        b.extend_from_slice(&280i16.to_le_bytes());
        b.extend_from_slice(&1i16.to_le_bytes());
        b.extend_from_slice(&5008i16.to_le_bytes());
        b.extend_from_slice(&90.000000000006f64.to_le_bytes());
        b.extend_from_slice(&0i16.to_le_bytes());
        b.extend_from_slice(b"XRECORD\0");
        b.extend_from_slice(&5i16.to_le_bytes());
        b.extend_from_slice(b"AB\0");
        let mut t = Tags::new(&b);
        let tags: Vec<Tag> = (&mut t).collect();
        assert_eq!(t.stop, None);
        assert_eq!(tags.len(), 5);
        assert_eq!(tags[2].code, 5008);
        assert_eq!(tags[2].f64(), 90.000000000006);
        assert!(tags[3].is("XRECORD"));
    }

    #[test]
    fn numbers_parse_from_text_leniently() {
        let t = Tag {
            code: 70,
            value: Value::Text(b"   1.0 "),
        };
        assert_eq!(t.int(), 1);
        let t = Tag {
            code: 5,
            value: Value::Text(b"1F"),
        };
        assert_eq!(t.handle(), 0x1F);
        let t = Tag {
            code: 40,
            value: Value::Text(b"nonsense"),
        };
        assert_eq!(t.f64(), 0.0);
    }
}
