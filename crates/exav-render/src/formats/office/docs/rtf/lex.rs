//! The RTF tokenizer: groups, control words and symbols, and runs of text.

#[derive(Debug, PartialEq, Eq)]
pub enum Tok<'a> {
    Open,
    Close,
    /// A control word and its parameter.
    Word(&'a str, Option<i32>),
    /// `\'hh`.
    Hex(u8),
    /// A control symbol other than `\'`: `\~`, `\-`, `\_`, `\*`, `\\`, ...
    Sym(u8),
    /// Plain bytes.
    Text(&'a [u8]),
}

pub struct Lexer<'a> {
    pub d: &'a [u8],
    pub p: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Lexer { d, p: 0 }
    }

    pub fn next_tok(&mut self) -> Option<Tok<'a>> {
        loop {
            let c = *self.d.get(self.p)?;
            match c {
                b'{' => {
                    self.p += 1;
                    return Some(Tok::Open);
                }
                b'}' => {
                    self.p += 1;
                    return Some(Tok::Close);
                }
                b'\r' | b'\n' => {
                    self.p += 1;
                    continue;
                }
                b'\\' => return Some(self.control()),
                _ => {
                    let s = self.p;
                    while let Some(&c) = self.d.get(self.p) {
                        if matches!(c, b'{' | b'}' | b'\\' | b'\r' | b'\n') {
                            break;
                        }
                        self.p += 1;
                    }
                    return Some(Tok::Text(&self.d[s..self.p]));
                }
            }
        }
    }

    fn control(&mut self) -> Tok<'a> {
        self.p += 1;
        let Some(&c) = self.d.get(self.p) else {
            return Tok::Text(&[]);
        };
        if c.is_ascii_alphabetic() {
            let s = self.p;
            while self.d.get(self.p).is_some_and(|c| c.is_ascii_alphabetic()) && self.p - s < 32 {
                self.p += 1;
            }
            let name = std::str::from_utf8(&self.d[s..self.p]).unwrap_or("");
            let mut param = None;
            let neg = self.d.get(self.p) == Some(&b'-');
            let ds = if neg { self.p + 1 } else { self.p };
            let mut e = ds;
            while self.d.get(e).is_some_and(|c| c.is_ascii_digit()) && e - ds < 11 {
                e += 1;
            }
            if e > ds {
                let v: i64 = std::str::from_utf8(&self.d[ds..e])
                    .ok()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0);
                let v = if neg { -v } else { v };
                // Parameters are small in any real document; the bound keeps
                // the arithmetic on them from overflowing.
                param = Some(v.clamp(-100_000_000, 100_000_000) as i32);
                self.p = e;
            }
            // One space after a control word belongs to it.
            if self.d.get(self.p) == Some(&b' ') {
                self.p += 1;
            }
            return Tok::Word(name, param);
        }
        self.p += 1;
        if c == b'\'' {
            let h = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16));
            let hi = h(self.d.get(self.p));
            let lo = h(self.d.get(self.p + 1));
            return match (hi, lo) {
                (Some(a), Some(b)) => {
                    self.p += 2;
                    Tok::Hex((a * 16 + b) as u8)
                }
                _ => Tok::Hex(0),
            };
        }
        if c == b'\r' || c == b'\n' {
            // A backslash before a line break is a paragraph end.
            return Tok::Word("par", None);
        }
        Tok::Sym(c)
    }

    /// Skips the bytes standing for the `n` characters after `\uN`.
    pub fn skip_fallback(&mut self, n: u32) {
        for _ in 0..n {
            match self.d.get(self.p) {
                Some(b'\\') if self.d.get(self.p + 1) == Some(&b'\'') => self.p += 4,
                Some(b'\\' | b'{' | b'}' | b'\r' | b'\n') | None => break,
                Some(_) => self.p += 1,
            }
        }
        self.p = self.p.min(self.d.len());
    }

    /// The `n` raw bytes after `\binN`.
    pub fn take_bin(&mut self, n: usize) -> &'a [u8] {
        let e = self.p.saturating_add(n).min(self.d.len());
        let s = &self.d[self.p..e];
        self.p = e;
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(s: &[u8]) -> Vec<Tok<'_>> {
        let mut l = Lexer::new(s);
        let mut v = vec![];
        while let Some(t) = l.next_tok() {
            v.push(t);
        }
        v
    }

    #[test]
    fn words_parameters_and_text() {
        let t = all(b"{\\rtf1\\ansi\\fs-24 Hi\\'e9\\~x\\u-3913 ?}");
        assert_eq!(
            t,
            vec![
                Tok::Open,
                Tok::Word("rtf", Some(1)),
                Tok::Word("ansi", None),
                Tok::Word("fs", Some(-24)),
                Tok::Text(b"Hi"),
                Tok::Hex(0xE9),
                Tok::Sym(b'~'),
                Tok::Text(b"x"),
                Tok::Word("u", Some(-3913)),
                Tok::Text(b"?"),
                Tok::Close,
            ]
        );
    }

    #[test]
    fn line_breaks_are_ignored_and_a_slash_before_one_is_a_paragraph() {
        assert_eq!(all(b"a\r\nb"), vec![Tok::Text(b"a"), Tok::Text(b"b")]);
        assert_eq!(all(b"\\\nx"), vec![Tok::Word("par", None), Tok::Text(b"x")]);
    }

    #[test]
    fn fallback_characters_are_skipped() {
        let mut l = Lexer::new(b"\\u233\\'e9z");
        assert_eq!(l.next_tok(), Some(Tok::Word("u", Some(233))));
        l.skip_fallback(1);
        assert_eq!(l.next_tok(), Some(Tok::Text(b"z")));
    }
}
