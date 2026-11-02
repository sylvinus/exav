//! A JSON reader for glTF's document: bounded in depth and in size, the
//! only thing it does. Numbers are `f64`; a duplicate key keeps its first
//! value on lookup.

/// Nesting deeper than this is refused: glTF's own never passes ten.
const MAX_DEPTH: usize = 64;

/// Values (of every kind) a document may hold. Each takes tens of bytes,
/// while a bare `1,` takes two of the file.
const MAX_VALUES: usize = 2_000_000;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn array(&self) -> &[Value] {
        match self {
            Value::Arr(items) => items,
            _ => &[],
        }
    }

    pub fn str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            _ => None,
        }
    }

    /// A whole number from 0 to 2^53.
    pub fn usize(&self) -> Option<usize> {
        let n = self.f64()?;
        (n >= 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_992.0).then_some(n as usize)
    }

    /// Exactly `n` numbers.
    pub fn numbers(&self, n: usize) -> Option<Vec<f64>> {
        let items = match self {
            Value::Arr(items) if items.len() == n => items,
            _ => return None,
        };
        items.iter().map(Value::f64).collect()
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value, &'static str> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut p = Parser {
        b: bytes,
        at: 0,
        values: 0,
    };
    let v = p.value(0)?;
    p.space();
    if p.at != p.b.len() {
        return Err("data after the document");
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    at: usize,
    values: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while matches!(self.b.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Result<Value, &'static str> {
        if self.b[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(v)
        } else {
            Err("bad literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, &'static str> {
        if depth > MAX_DEPTH {
            return Err("nested too deep");
        }
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err("too many values");
        }
        self.space();
        match self.b.get(self.at).ok_or("unexpected end")? {
            b'{' => {
                self.at += 1;
                let mut members = Vec::new();
                self.space();
                if self.b.get(self.at) == Some(&b'}') {
                    self.at += 1;
                    return Ok(Value::Obj(members));
                }
                loop {
                    self.space();
                    if self.b.get(self.at) != Some(&b'"') {
                        return Err("expected a key");
                    }
                    let key = self.string()?;
                    self.space();
                    if self.b.get(self.at) != Some(&b':') {
                        return Err("expected a colon");
                    }
                    self.at += 1;
                    members.push((key, self.value(depth + 1)?));
                    self.space();
                    match self.b.get(self.at) {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Value::Obj(members));
                        }
                        _ => return Err("expected a comma or a brace"),
                    }
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                self.space();
                if self.b.get(self.at) == Some(&b']') {
                    self.at += 1;
                    return Ok(Value::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.space();
                    match self.b.get(self.at) {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Value::Arr(items));
                        }
                        _ => return Err("expected a comma or a bracket"),
                    }
                }
            }
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => {
                let start = self.at;
                while matches!(
                    self.b.get(self.at),
                    Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                ) {
                    self.at += 1;
                }
                let n: f64 = std::str::from_utf8(&self.b[start..self.at])
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or("bad number")?;
                if n.is_finite() {
                    Ok(Value::Num(n))
                } else {
                    Err("number out of range")
                }
            }
            _ => Err("unexpected character"),
        }
    }

    /// A string; `at` is on its opening quote.
    fn string(&mut self) -> Result<String, &'static str> {
        self.at += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.at).ok_or("unterminated string")?;
            self.at += 1;
            match c {
                b'"' => return String::from_utf8(out).map_err(|_| "string is not UTF-8"),
                0..=0x1f => return Err("control character in a string"),
                b'\\' => {
                    let e = *self.b.get(self.at).ok_or("unterminated string")?;
                    self.at += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut unit = self.hex4()?;
                            if (0xd800..0xdc00).contains(&unit)
                                && self.b[self.at..].starts_with(b"\\u")
                            {
                                let save = self.at;
                                self.at += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    unit = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.at = save;
                                }
                            }
                            let ch = char::from_u32(unit).unwrap_or('\u{fffd}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err("bad escape"),
                    }
                }
                _ => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, &'static str> {
        let digits = self.b.get(self.at..self.at + 4).ok_or("bad escape")?;
        let mut n = 0;
        for &d in digits {
            n = n * 16 + (d as char).to_digit(16).ok_or("bad escape")?;
        }
        self.at += 4;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_it_is_given() {
        let v =
            parse(br#" {"a":[1,-2.5e1,true,null],"b":{"c":"x\u00e9\ud83d\ude00\n"}} "#).unwrap();
        assert_eq!(v.get("a").unwrap().array()[1], Value::Num(-25.0));
        assert_eq!(
            v.get("b").unwrap().get("c").unwrap().str(),
            Some("x\u{e9}\u{1f600}\n")
        );
    }

    #[test]
    fn refuses_what_is_not_json_without_panicking() {
        for bad in [
            &b""[..],
            b"{",
            b"[1,]",
            b"{\"a\" 1}",
            b"\"abc",
            b"\"\\x\"",
            b"1e999",
            b"[1] 2",
            b"\"\\u12\"",
            b"nul",
            b"tru",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = "[".repeat(10_000);
        assert!(parse(deep.as_bytes()).is_err());
    }
}
