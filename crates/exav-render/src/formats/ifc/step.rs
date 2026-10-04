//! ISO 10303-21 (STEP physical file) reading: the header's schema, and an
//! index of the DATA section's instances whose parameters are parsed when
//! asked for.
//!
//! Indexing is one pass over the bytes that only finds where each instance
//! starts and ends, so a 200 MB file costs 16 bytes per instance until its
//! geometry is needed.

use std::collections::HashMap;
use std::fmt;

/// Deepest nesting of lists a parameter may have.
const MAX_DEPTH: usize = 64;

/// A parameter value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    /// `$`
    Null,
    /// `*`, a value derived from others.
    Derived,
    Int(i64),
    Real(f64),
    /// The raw bytes between the quotes, escapes not decoded: see
    /// [`decode_string`].
    Str(&'a [u8]),
    /// `.NAME.` without its dots; also `.T.`, `.F.` and `.U.`.
    Enum(&'a [u8]),
    /// `#123`
    Ref(u32),
    /// The hex digits of `"0ABC"`.
    Binary(&'a [u8]),
    List(Vec<Value<'a>>),
    /// `IFCLABEL('x')`: a value given with its type.
    Typed(&'a [u8], Box<Value<'a>>),
}

impl<'a> Value<'a> {
    /// A number, through a typed value too.
    pub fn num(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Real(r) => Some(*r),
            Value::Typed(_, v) => v.num(),
            _ => None,
        }
    }

    pub fn int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Real(r) if r.fract() == 0.0 && r.abs() < 9e15 => Some(*r as i64),
            Value::Typed(_, v) => v.int(),
            _ => None,
        }
    }

    pub fn id(&self) -> Option<u32> {
        match self {
            Value::Ref(r) => Some(*r),
            _ => None,
        }
    }

    pub fn list(&self) -> Option<&[Value<'a>]> {
        match self {
            Value::List(l) => Some(l),
            Value::Typed(_, v) => v.list(),
            _ => None,
        }
    }

    pub fn enumeration(&self) -> Option<&'a [u8]> {
        match self {
            Value::Enum(e) => Some(e),
            Value::Typed(_, v) => v.enumeration(),
            _ => None,
        }
    }

    /// `.T.` is true, `.F.` false, anything else none.
    pub fn boolean(&self) -> Option<bool> {
        match self.enumeration() {
            Some(b"T") => Some(true),
            Some(b"F") => Some(false),
            _ => None,
        }
    }

    /// A string decoded (see [`decode_string`]), through a typed value too.
    pub fn text(&self) -> Option<String> {
        match self {
            Value::Str(s) => Some(decode_string(s)),
            Value::Typed(_, v) => v.text(),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null | Value::Derived)
    }
}

/// The schema `FILE_SCHEMA` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schema {
    Ifc2x3,
    Ifc4,
    Ifc4x3,
    /// Any other, read as IFC4.
    Other,
}

/// Why a file is not read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// It does not start with `ISO-10303-21;`.
    NotStep,
    /// No DATA section, or nothing in it.
    NoData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::NotStep => "not a STEP file",
            Error::NoData => "no instances in the file",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy)]
struct Entry {
    id: u32,
    /// Index into `types`; `COMPLEX` for an instance written as a list of
    /// partial records.
    ty: u32,
    /// The parameters, without their parentheses.
    start: u32,
    end: u32,
}

const COMPLEX: u32 = u32::MAX;

/// An indexed STEP file.
pub struct StepFile<'a> {
    data: &'a [u8],
    pub schema: Schema,
    entries: Vec<Entry>,
    /// Sorted (id, index) when the file's ids are not ascending.
    sorted: Option<Vec<(u32, u32)>>,
    types: Vec<Box<[u8]>>,
    /// Some instances could not be read, or the file ends early.
    pub damaged: bool,
}

impl<'a> StepFile<'a> {
    /// Indexes `data`. Fails only when it is not STEP or has no instance:
    /// a record that cannot be read is skipped and `damaged` set.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() > u32::MAX as usize {
            return Err(Error::NoData);
        }
        let mut s = Scanner { data, pos: 0 };
        // A UTF-8 byte order mark, then the magic.
        if s.rest().starts_with(b"\xEF\xBB\xBF") {
            s.pos = 3;
        }
        s.skip_space();
        if !s.rest().starts_with(b"ISO-10303-21;") {
            return Err(Error::NotStep);
        }
        let mut file = StepFile {
            data,
            schema: Schema::Other,
            entries: Vec::new(),
            sorted: None,
            types: Vec::new(),
            damaged: false,
        };
        let mut type_ids: HashMap<&'a [u8], u32> = HashMap::new();
        s.pos += 13;
        let mut in_data = false;
        loop {
            s.skip_space();
            if s.pos >= data.len() {
                file.damaged = true;
                break;
            }
            let rest = s.rest();
            if !in_data {
                if rest.starts_with(b"DATA") {
                    // `DATA;` or ISO 10303-21:2016 `DATA(...);`.
                    s.pos += 4;
                    s.skip_space();
                    if s.peek() == Some(b'(') && s.skip_balanced().is_none() {
                        file.damaged = true;
                        break;
                    }
                    s.skip_space();
                    if s.peek() == Some(b';') {
                        s.pos += 1;
                    }
                    in_data = true;
                } else if rest.starts_with(b"END-ISO-10303-21") {
                    break;
                } else if rest.starts_with(b"FILE_SCHEMA") {
                    s.pos += 11;
                    s.skip_space();
                    let start = s.pos;
                    if s.peek() != Some(b'(') || s.skip_balanced().is_none() {
                        file.damaged = true;
                        break;
                    }
                    file.schema = schema_of(&data[start + 1..s.pos - 1]);
                } else if !s.skip_statement() {
                    file.damaged = true;
                    break;
                }
                continue;
            }
            if rest.starts_with(b"ENDSEC") {
                s.pos += 6;
                s.skip_space();
                if s.peek() == Some(b';') {
                    s.pos += 1;
                }
                in_data = false;
                continue;
            }
            match s.instance() {
                Some((id, name, start, end)) => {
                    let ty = match name {
                        None => COMPLEX,
                        Some(n) => {
                            let next = file.types.len() as u32;
                            *type_ids.entry(n).or_insert_with(|| {
                                file.types.push(n.to_ascii_uppercase().into_boxed_slice());
                                next
                            })
                        }
                    };
                    file.entries.push(Entry {
                        id,
                        ty,
                        start: start as u32,
                        end: end as u32,
                    });
                }
                None => {
                    file.damaged = true;
                    if !s.skip_statement() {
                        break;
                    }
                }
            }
        }
        if file.entries.is_empty() {
            return Err(Error::NoData);
        }
        if file.entries.windows(2).any(|w| w[0].id >= w[1].id) {
            let mut sorted: Vec<(u32, u32)> = file
                .entries
                .iter()
                .enumerate()
                .map(|(i, e)| (e.id, i as u32))
                .collect();
            // Stable: the first of two instances with one id wins.
            sorted.sort_by_key(|&(id, _)| id);
            sorted.dedup_by_key(|&mut (id, _)| id);
            file.sorted = Some(sorted);
        }
        Ok(file)
    }

    /// Number of instances.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn index(&self, id: u32) -> Option<usize> {
        match &self.sorted {
            Some(s) => s
                .binary_search_by_key(&id, |&(i, _)| i)
                .ok()
                .map(|k| s[k].1 as usize),
            None => self.entries.binary_search_by_key(&id, |e| e.id).ok(),
        }
    }

    /// The instance numbers, in file order.
    pub fn ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries.iter().map(|e| e.id)
    }

    /// The upper-case type name of `#id`; empty for a complex instance.
    pub fn type_name(&self, id: u32) -> Option<&[u8]> {
        let e = self.entries[self.index(id)?];
        Some(if e.ty == COMPLEX {
            b""
        } else {
            &self.types[e.ty as usize]
        })
    }

    /// The instances of a type, in file order.
    pub fn of_type<'s>(&'s self, name: &'s [u8]) -> impl Iterator<Item = u32> + 's {
        let ty = self
            .types
            .iter()
            .position(|t| &t[..] == name)
            .map(|t| t as u32);
        self.entries
            .iter()
            .filter(move |e| Some(e.ty) == ty)
            .map(|e| e.id)
    }

    /// The parameters of `#id`, or `None` when there is no such instance or
    /// they do not parse.
    pub fn params(&self, id: u32) -> Option<Vec<Value<'a>>> {
        let e = self.entries[self.index(id)?];
        if e.ty == COMPLEX {
            return None;
        }
        parse_params(&self.data[e.start as usize..e.end as usize])
    }

    /// The type and parameters of `#id`.
    pub fn get(&self, id: u32) -> Option<(&[u8], Vec<Value<'a>>)> {
        let e = self.entries[self.index(id)?];
        if e.ty == COMPLEX {
            return None;
        }
        Some((
            &self.types[e.ty as usize],
            parse_params(&self.data[e.start as usize..e.end as usize])?,
        ))
    }

    /// The raw parameter text of `#id`, for a cheap look before parsing.
    pub fn raw(&self, id: u32) -> Option<&'a [u8]> {
        let e = self.entries[self.index(id)?];
        Some(&self.data[e.start as usize..e.end as usize])
    }
}

fn schema_of(params: &[u8]) -> Schema {
    let upper = params.to_ascii_uppercase();
    let has = |n: &[u8]| upper.windows(n.len()).any(|w| w == n);
    if has(b"IFC4X3") {
        Schema::Ifc4x3
    } else if has(b"IFC2X3") {
        Schema::Ifc2x3
    } else if has(b"IFC4") {
        Schema::Ifc4
    } else {
        Schema::Other
    }
}

struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Whitespace and `/* comments */`.
    fn skip_space(&mut self) {
        loop {
            match self.peek() {
                Some(b) if b.is_ascii_whitespace() => self.pos += 1,
                Some(b'/') if self.data.get(self.pos + 1) == Some(&b'*') => {
                    match find(&self.data[self.pos + 2..], b"*/") {
                        Some(i) => self.pos += 2 + i + 2,
                        None => self.pos = self.data.len(),
                    }
                }
                _ => return,
            }
        }
    }

    /// From `(` to after its `)`, over strings and comments. None at the
    /// end of the data.
    fn skip_balanced(&mut self) -> Option<()> {
        let mut depth = 0usize;
        while let Some(b) = self.peek() {
            match b {
                b'(' => {
                    depth += 1;
                    self.pos += 1;
                }
                b')' => {
                    self.pos += 1;
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(());
                    }
                }
                b'\'' => self.skip_string()?,
                b'"' => {
                    self.pos += 1;
                    let i = self.rest().iter().position(|&c| c == b'"')?;
                    self.pos += i + 1;
                }
                b'/' if self.data.get(self.pos + 1) == Some(&b'*') => self.skip_space(),
                b';' if depth > 0 => {
                    // A statement end inside parentheses: the record is
                    // broken; stop at it so the next one can be read.
                    return None;
                }
                _ => self.pos += 1,
            }
        }
        None
    }

    /// From `'` to after the closing one (`''` is a quote inside).
    fn skip_string(&mut self) -> Option<()> {
        self.pos += 1;
        loop {
            let i = self.rest().iter().position(|&c| c == b'\'')?;
            self.pos += i + 1;
            if self.peek() == Some(b'\'') {
                self.pos += 1;
            } else {
                return Some(());
            }
        }
    }

    /// To after the next `;` outside strings. False at the end of the data.
    fn skip_statement(&mut self) -> bool {
        while let Some(b) = self.peek() {
            match b {
                b';' => {
                    self.pos += 1;
                    return true;
                }
                b'\'' => {
                    if self.skip_string().is_none() {
                        return false;
                    }
                }
                _ => self.pos += 1,
            }
        }
        false
    }

    /// `#id = NAME(...);` or `#id = (A(...) B(...));`: the id, the name
    /// (none for the complex form) and the span of the parameters.
    fn instance(&mut self) -> Option<(u32, Option<&'a [u8]>, usize, usize)> {
        if self.peek() != Some(b'#') {
            return None;
        }
        self.pos += 1;
        let digits = self
            .rest()
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 || digits > 10 {
            return None;
        }
        let id: u64 = std::str::from_utf8(&self.rest()[..digits])
            .ok()?
            .parse()
            .ok()?;
        let id = u32::try_from(id).ok()?;
        self.pos += digits;
        self.skip_space();
        if self.peek() != Some(b'=') {
            return None;
        }
        self.pos += 1;
        self.skip_space();
        let name = if self.peek() == Some(b'(') {
            None
        } else {
            let n = self
                .rest()
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
                .count();
            if n == 0 {
                return None;
            }
            let name = &self.rest()[..n];
            self.pos += n;
            self.skip_space();
            if self.peek() != Some(b'(') {
                return None;
            }
            Some(name)
        };
        let open = self.pos;
        self.skip_balanced()?;
        let close = self.pos;
        self.skip_space();
        if self.peek() != Some(b';') {
            return None;
        }
        self.pos += 1;
        Some((id, name, open + 1, close - 1))
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parses a parameter list's inside (`a, (b, c), 'd'`).
pub fn parse_params(src: &[u8]) -> Option<Vec<Value<'_>>> {
    let mut p = Parser { src, pos: 0 };
    let mut out = Vec::new();
    p.space();
    if p.pos >= src.len() {
        return Some(out);
    }
    loop {
        out.push(p.value(0)?);
        p.space();
        match p.peek() {
            Some(b',') => {
                p.pos += 1;
                p.space();
            }
            None => return Some(out),
            _ => return None,
        }
    }
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn space(&mut self) {
        loop {
            match self.peek() {
                Some(b) if b.is_ascii_whitespace() => self.pos += 1,
                Some(b'/') if self.src.get(self.pos + 1) == Some(&b'*') => {
                    match find(&self.src[self.pos + 2..], b"*/") {
                        Some(i) => self.pos += 2 + i + 2,
                        None => self.pos = self.src.len(),
                    }
                }
                _ => return,
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value<'a>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let b = self.peek()?;
        match b {
            b'$' => {
                self.pos += 1;
                Some(Value::Null)
            }
            b'*' => {
                self.pos += 1;
                Some(Value::Derived)
            }
            b'#' => {
                self.pos += 1;
                let n = self.src[self.pos..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
                if n == 0 || n > 10 {
                    return None;
                }
                let id: u64 = std::str::from_utf8(&self.src[self.pos..self.pos + n])
                    .ok()?
                    .parse()
                    .ok()?;
                self.pos += n;
                Some(Value::Ref(u32::try_from(id).ok()?))
            }
            b'\'' => {
                let start = self.pos + 1;
                self.pos += 1;
                loop {
                    let i = self.src[self.pos..].iter().position(|&c| c == b'\'')?;
                    self.pos += i + 1;
                    if self.peek() == Some(b'\'') {
                        self.pos += 1;
                    } else {
                        return Some(Value::Str(&self.src[start..self.pos - 1]));
                    }
                }
            }
            b'"' => {
                let start = self.pos + 1;
                let i = self.src[start..].iter().position(|&c| c == b'"')?;
                self.pos = start + i + 1;
                let hex = &self.src[start..start + i];
                hex.iter()
                    .all(u8::is_ascii_hexdigit)
                    .then_some(Value::Binary(hex))
            }
            b'.' if self
                .src
                .get(self.pos + 1)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') =>
            {
                let start = self.pos + 1;
                let i = self.src[start..].iter().position(|&c| c == b'.')?;
                let name = &self.src[start..start + i];
                if !name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_') {
                    return None;
                }
                self.pos = start + i + 1;
                Some(Value::Enum(name))
            }
            b'(' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.space();
                if self.peek() == Some(b')') {
                    self.pos += 1;
                    return Some(Value::List(items));
                }
                loop {
                    self.space();
                    items.push(self.value(depth + 1)?);
                    self.space();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b')' => {
                            self.pos += 1;
                            return Some(Value::List(items));
                        }
                        _ => return None,
                    }
                }
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                let start = self.pos;
                let n = self.src[start..]
                    .iter()
                    .take_while(|c| {
                        c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.' | b'e' | b'E')
                    })
                    .count();
                let text = std::str::from_utf8(&self.src[start..start + n]).ok()?;
                self.pos += n;
                let is_real = text.bytes().any(|c| matches!(c, b'.' | b'e' | b'E'));
                if !is_real {
                    if let Ok(i) = text.parse::<i64>() {
                        return Some(Value::Int(i));
                    }
                }
                // `1.E5` is STEP; Rust wants a digit after the point.
                let r = text.parse::<f64>().ok().or_else(|| {
                    text.replacen(".E", ".0E", 1)
                        .replacen(".e", ".0e", 1)
                        .parse()
                        .ok()
                })?;
                r.is_finite().then_some(Value::Real(r))
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let n = self.src[self.pos..]
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                    .count();
                let name = &self.src[self.pos..self.pos + n];
                self.pos += n;
                self.space();
                if self.peek() != Some(b'(') {
                    return None;
                }
                self.pos += 1;
                self.space();
                let inner = if self.peek() == Some(b')') {
                    Value::List(Vec::new())
                } else {
                    self.value(depth + 1)?
                };
                self.space();
                if self.peek() != Some(b')') {
                    return None;
                }
                self.pos += 1;
                Some(Value::Typed(name, Box::new(inner)))
            }
            _ => None,
        }
    }
}

/// Decodes a STEP string's escapes (ISO 10303-21, 6.4.3): `''` is a quote,
/// `\\` a backslash, `\S\c` the ISO 8859-1 character `c` + 128, `\X\hh` the
/// ISO 8859-1 character `hh`, `\X2\hhhh..\X0\` UTF-16 code units and
/// `\X4\hhhhhhhh..\X0\` code points; `\P?\` (code page) is dropped. Other
/// bytes are read as UTF-8, which some writers emit, with invalid
/// sequences replaced.
pub fn decode_string(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut plain: Vec<u8> = Vec::new();
    let flush = |plain: &mut Vec<u8>, out: &mut String| {
        if !plain.is_empty() {
            out.push_str(&String::from_utf8_lossy(plain));
            plain.clear();
        }
    };
    let hex =
        |s: &[u8]| -> Option<u32> { u32::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok() };
    let mut i = 0;
    while i < raw.len() {
        let rest = &raw[i..];
        if rest.starts_with(b"''") {
            plain.push(b'\'');
            i += 2;
        } else if rest.starts_with(b"\\\\") {
            plain.push(b'\\');
            i += 2;
        } else if rest.starts_with(b"\\S\\") && rest.len() >= 4 {
            flush(&mut plain, &mut out);
            out.push(char::from(rest[3].wrapping_add(128)));
            i += 4;
        } else if rest.starts_with(b"\\X\\") && rest.len() >= 5 && hex(&rest[3..5]).is_some() {
            flush(&mut plain, &mut out);
            out.push(char::from(hex(&rest[3..5]).unwrap_or(0x3f) as u8));
            i += 5;
        } else if rest.starts_with(b"\\X2\\") || rest.starts_with(b"\\X4\\") {
            let width = if rest[2] == b'2' { 4 } else { 8 };
            let body = &rest[4..];
            let end = find(body, b"\\X0\\").unwrap_or(body.len());
            flush(&mut plain, &mut out);
            let units: Vec<u32> = body[..end].chunks(width).filter_map(hex).collect();
            if width == 4 {
                let units: Vec<u16> = units.into_iter().map(|u| u as u16).collect();
                out.push_str(&String::from_utf16_lossy(&units));
            } else {
                out.extend(
                    units
                        .into_iter()
                        .map(|u| char::from_u32(u).unwrap_or('\u{fffd}')),
                );
            }
            i += 4 + end + if end < body.len() { 4 } else { 0 };
        } else if rest.starts_with(b"\\P") && rest.len() >= 4 && rest[3] == b'\\' {
            i += 4;
        } else {
            plain.push(raw[i]);
            i += 1;
        }
    }
    flush(&mut plain, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(data: &str) -> String {
        format!("ISO-10303-21;\nHEADER;\nFILE_DESCRIPTION((''),'2;1');\nFILE_NAME('a','',(''),(''),'','','');\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n{data}\nENDSEC;\nEND-ISO-10303-21;\n")
    }

    #[test]
    fn values_of_every_kind() {
        let src =
            file("#1=IFCX($,*,12,-3.5E-2,1.,'it''s',.T.,#77,\"0FF\",(1,(2,3)),IFCLABEL('x'),());");
        let f = StepFile::parse(src.as_bytes()).unwrap();
        assert_eq!(f.schema, Schema::Ifc4);
        let (ty, p) = f.get(1).unwrap();
        assert_eq!(ty, b"IFCX");
        assert_eq!(p[0], Value::Null);
        assert_eq!(p[1], Value::Derived);
        assert_eq!(p[2], Value::Int(12));
        assert_eq!(p[3], Value::Real(-0.035));
        assert_eq!(p[4], Value::Real(1.0));
        assert_eq!(p[5].text().unwrap(), "it's");
        assert_eq!(p[6].boolean(), Some(true));
        assert_eq!(p[7], Value::Ref(77));
        assert_eq!(p[8], Value::Binary(b"0FF"));
        assert_eq!(
            p[9],
            Value::List(vec![
                Value::Int(1),
                Value::List(vec![Value::Int(2), Value::Int(3)])
            ])
        );
        assert_eq!(p[10], Value::Typed(b"IFCLABEL", Box::new(Value::Str(b"x"))));
        assert_eq!(p[11], Value::List(vec![]));
    }

    #[test]
    fn reals_written_with_a_bare_point_and_exponent() {
        assert_eq!(
            parse_params(b"1.E5, -2.e-1, .5").unwrap(),
            vec![Value::Real(1e5), Value::Real(-0.2), Value::Real(0.5)]
        );
    }

    #[test]
    fn string_escapes() {
        assert_eq!(decode_string(b"caf\\X\\E9"), "café");
        assert_eq!(decode_string(b"\\X2\\00E9006C00E8\\X0\\ve"), "élève");
        assert_eq!(decode_string(b"\\X4\\0001F600\\X0\\"), "\u{1F600}");
        assert_eq!(decode_string(b"\\S\\i"), "é");
        assert_eq!(decode_string(b"a\\\\b''c"), "a\\b'c");
        assert_eq!(decode_string(b"\\PA\\x"), "x");
        assert_eq!(decode_string("déjà".as_bytes()), "déjà");
    }

    #[test]
    fn comments_strings_and_semicolons_inside_records() {
        let src = file("/* c ; ) */ #1 = IFCA('a;b)', /* x */ 2) ;\n#2=IFCB((3));");
        let f = StepFile::parse(src.as_bytes()).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(
            f.params(1).unwrap(),
            vec![Value::Str(b"a;b)"), Value::Int(2)]
        );
        assert_eq!(f.params(2).unwrap(), vec![Value::List(vec![Value::Int(3)])]);
    }

    #[test]
    fn complex_instances_are_indexed_but_have_no_params() {
        let src = file("#1=(IFCA(1)IFCB(2));#2=IFCC(#1);");
        let f = StepFile::parse(src.as_bytes()).unwrap();
        assert_eq!(f.type_name(1), Some(&b""[..]));
        assert!(f.params(1).is_none());
        assert_eq!(f.params(2).unwrap(), vec![Value::Ref(1)]);
    }

    #[test]
    fn ids_out_of_order_are_found() {
        let src = file("#5=IFCA(5);#2=IFCA(2);#9=IFCA(9);#2=IFCA(22);");
        let f = StepFile::parse(src.as_bytes()).unwrap();
        assert_eq!(f.params(2).unwrap(), vec![Value::Int(2)]);
        assert_eq!(f.params(9).unwrap(), vec![Value::Int(9)]);
        assert!(f.params(3).is_none());
    }

    #[test]
    fn damaged_files_fail_fast_or_keep_what_they_can() {
        assert_eq!(StepFile::parse(b"PK\x03\x04").err(), Some(Error::NotStep));
        assert_eq!(
            StepFile::parse(b"ISO-10303-21;HEADER;ENDSEC;").err(),
            Some(Error::NoData)
        );
        // Cut in the middle of a record.
        let full = file("#1=IFCA(1);#2=IFCB('abc");
        let cut = &full.as_bytes()[..full.find("'abc").unwrap() + 3];
        let f = StepFile::parse(cut).unwrap();
        assert!(f.damaged);
        assert_eq!(f.len(), 1);
        // A broken record between good ones.
        let broken = file("#1=IFCA(1);#2=IFCB(1,;#3 IFCC();#4=IFCD(4);");
        let f = StepFile::parse(broken.as_bytes()).unwrap();
        assert!(f.damaged);
        assert_eq!(f.ids().collect::<Vec<_>>(), vec![1, 4]);
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = format!("{}1{}", "(".repeat(100), ")".repeat(100));
        assert!(parse_params(deep.as_bytes()).is_none());
        let ok = format!("{}1{}", "(".repeat(10), ")".repeat(10));
        assert!(parse_params(ok.as_bytes()).is_some());
    }

    #[test]
    fn schema_names() {
        assert_eq!(schema_of(b"('IFC2X3')"), Schema::Ifc2x3);
        assert_eq!(schema_of(b"('IFC4X3_ADD2')"), Schema::Ifc4x3);
        assert_eq!(schema_of(b"('IFC4')"), Schema::Ifc4);
        assert_eq!(schema_of(b"('CONFIG_CONTROL_DESIGN')"), Schema::Other);
    }
}
