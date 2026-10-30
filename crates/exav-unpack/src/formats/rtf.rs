//! RTF: the tokenizer of the format, and the extractor of the objects it
//! embeds.
//!
//! Implemented from the public **Microsoft Rich Text Format (RTF) Specification**
//! (v1.9.1). An RTF file is a tree of brace-delimited groups containing control
//! words (`\word` + optional signed number + one optional delimiting space) and
//! control symbols (`\` + a single non-letter). The [`Lexer`] reads it, for the
//! scanner and for exav-render's converter alike: what one sees as a control
//! word, a group or text, so does the other.
//!
//! An embedded OLE object is carried as ASCII hex inside an `\objdata`
//! destination (RTF §"Objects"); malware hides droppers there (an OLE2/VBA
//! document or a raw PE). The extractor collects the hex bytes of every
//! `\objdata`/`\datastore` destination and emits the decoded object so the
//! engine can recurse into it.
//!
//! Hex digits inside the destination may be split across lines and interleaved
//! with control words; only `[0-9a-fA-F]` of the text between them is decoded
//! (so the letters of a control word are not misread as hex), up to the `}`
//! that closes the destination. Every read is bounds-checked; truncated or
//! hostile RTF cannot panic (an unterminated group runs to EOF, an odd
//! trailing nibble is dropped).

use crate::*;

/// One token of an RTF file.
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

/// The tokens of an RTF file, one at a time. Line breaks between tokens are
/// not tokens; a backslash before one is a paragraph end.
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

/// Numeric value of an ASCII hex digit, else `None`.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode the hex payload of the destination whose data begins where `lex`
/// stands, up to the `}` that closes it. Returns the decoded bytes and the
/// offset of that `}` (or EOF).
fn decode_object(lex: &mut Lexer<'_>) -> (Vec<u8>, usize) {
    let mut depth = 1i32;
    let mut hi: Option<u8> = None;
    let mut out = Vec::new();
    loop {
        let at = lex.p;
        match lex.next_tok() {
            None => return (out, lex.d.len()),
            Some(Tok::Open) => depth += 1,
            Some(Tok::Close) => {
                depth -= 1;
                if depth == 0 {
                    return (out, at);
                }
            }
            Some(Tok::Text(text)) => {
                for v in text.iter().filter_map(|&b| hex_nibble(b)) {
                    match hi.take() {
                        None => hi = Some(v),
                        Some(h) => out.push((h << 4) | v),
                    }
                }
            }
            // Control words and symbols hold no digits of the object.
            Some(_) => {}
        }
    }
}

pub(crate) fn extract_rtf<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !data.starts_with(b"{\\rtf") {
        return Ok(None);
    }
    let mut lex = Lexer::new(data);
    let mut index = 0usize;
    while let Some(tok) = lex.next_tok() {
        // `\binN` is not honored: its bytes are read as the groups and words
        // they could be, so an object in them is found whichever way a reader
        // takes them.
        if !matches!(tok, Tok::Word("objdata" | "datastore", _)) {
            continue;
        }
        let start = lex.p;
        let (bytes, end) = decode_object(&mut lex);
        let hex = data.get(start..end).unwrap_or(&[]);
        if bytes.is_empty() {
            continue;
        }
        // Hex digits are case-insensitive by definition, so a signature
        // written against this destination's hex TEXT should match whichever
        // case the writer chose: an uppercase destination is also offered
        // lowercased. Only then: a lowercase one is identical to bytes the
        // raw scan has covered, so copying it would cost memory for nothing.
        index += 1;
        if hex.iter().any(|b| b.is_ascii_uppercase()) {
            budget.count_entry()?;
            let cap = budget.reserve()?;
            if hex.len() as u64 <= cap {
                budget.commit(hex.len() as u64);
                let folded = hex.to_ascii_lowercase();
                if let Some(r) = visit(
                    Entry::new(format!("rtf-objdata-hex-{index}"), folded),
                    budget,
                ) {
                    return Ok(Some(r));
                }
            }
        }
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if bytes.len() as u64 > cap {
            return Err(LimitHit::new("rtf object exceeds budget".to_string()));
        }
        budget.commit(bytes.len() as u64);
        if let Some(r) = visit(Entry::new(format!("rtf-object-{index}"), bytes), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

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

    #[test]
    fn extracts_single_object() {
        let payload = b"MALWARETEST-inside-rtf-object";
        let rtf = format!(
            "{{\\rtf1\\ansi {{\\object\\objemb{{\\objdata {}}}}}}}",
            hex(payload)
        );
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, &rtf.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "rtf-object-1");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn hex_split_with_control_words() {
        let mut payload = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        payload.extend_from_slice(b"MALWARETEST");
        let h = hex(&payload);
        let (a, b) = h.split_at(10);
        let rtf = format!("{{\\rtf1{{\\object{{\\objdata\n{a}\r\n\\par {b}\n}}}}}}");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, &rtf.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn uppercase_hex_also_reaches_the_matcher_as_lowercase() {
        // Hex digits are case-insensitive by definition, so a signature written
        // against a destination's hex TEXT must match whichever case the writer
        // used. Without this, catching the uppercase variant relied on exav
        // lowercasing any pure-ASCII file it types as text — a rule that changes
        // matching for EVERY signature on a whole class of files, and that flips
        // on a single NUL byte.
        let payload = b"MALWARETEST-upper";
        let rtf = format!(
            "{{\\rtf1{{\\object{{\\objdata {}}}}}}}",
            hex(payload).to_uppercase()
        );
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, &rtf.as_bytes(), &mut budget).unwrap();
        let folded = entries
            .iter()
            .find(|e| e.name == "rtf-objdata-hex-1")
            .expect("an uppercase destination must also be offered lowercased");
        assert_eq!(folded.data, hex(payload).as_bytes());
        // The decoded object is unaffected either way.
        assert!(entries.iter().any(|e| e.data == payload));
    }

    #[test]
    fn lowercase_hex_is_not_duplicated() {
        // Already lowercase: identical to bytes the raw scan covers, so copying
        // it would cost memory for nothing.
        let payload = b"MALWARETEST-lower";
        let rtf = format!("{{\\rtf1{{\\object{{\\objdata {}}}}}}}", hex(payload));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, &rtf.as_bytes(), &mut budget).unwrap();
        assert!(
            entries
                .iter()
                .all(|e| !e.name.starts_with("rtf-objdata-hex"))
        );
    }

    #[test]
    fn extracts_multiple() {
        let (p1, p2) = (b"FIRST-MALWARETEST", b"SECOND-DROPPER");
        let rtf = format!(
            "{{\\rtf1 {{\\object{{\\objdata {}}}}} text {{\\object{{\\objdata {}}}}}}}",
            hex(p1),
            hex(p2)
        );
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, &rtf.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, p1);
        assert_eq!(entries[1].data, p2);
    }

    #[test]
    fn odd_nibble_dropped() {
        let rtf = b"{\\rtf1{\\object{\\objdata 4142434}}}";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, rtf, &mut budget).unwrap();
        assert_eq!(entries[0].data, b"ABC");
    }

    #[test]
    fn truncated_no_panic() {
        let rtf = b"{\\rtf1{\\object{\\objdata 4d414c5741524554455354";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, rtf, &mut budget).unwrap();
        assert_eq!(entries[0].data, b"MALWARETEST");
    }

    #[test]
    fn empty_and_nonrtf() {
        let mut budget = Budget::new(Limits::default());
        assert!(
            extract(Format::Rtf, b"{\\rtf1{\\object{\\objdata }}}", &mut budget)
                .unwrap()
                .is_empty()
        );
        assert!(
            extract(Format::Rtf, b"not rtf", &mut budget)
                .unwrap()
                .is_empty()
        );
    }

    /// The destination ends at its own closing brace, whatever groups open
    /// inside it, and an object a `\bin` run seems to hide is still found.
    #[test]
    fn nested_groups_and_bin_runs() {
        let payload = b"NESTED-MALWARETEST";
        let h = hex(payload);
        let (a, b) = h.split_at(8);
        let rtf = format!("{{\\rtf1{{\\objdata {a}{{\\*\\x}}{b}}}more}}");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, &rtf.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries[0].data, payload);
        let rtf = format!("{{\\rtf1\\bin4 abcd{{\\objdata {h}}}}}");
        let entries = extract(Format::Rtf, &rtf.as_bytes(), &mut budget).unwrap();
        assert!(entries.iter().any(|e| e.data == payload));
    }
}
