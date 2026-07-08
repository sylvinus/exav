pub(crate) struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token {
    Null,
    True,
    False,
    Integer(i64),
    Real(f64),
    Name(String),
    String(Vec<u8>),
    DictStart,  // <<
    DictEnd,    // >>
    ArrayStart, // [
    ArrayEnd,   // ]
    Obj,
    EndObj,
    Stream,
    EndStream,
    R, // indirect reference "R" keyword
    Eof,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Lexer { data, pos: 0 }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    pub(crate) fn data(&self) -> &'a [u8] {
        self.data
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' | b'\x00' => self.pos += 1,
                b'%' => {
                    // PDF comment: skip to end of line
                    self.pos += 1;
                    while self.pos < self.data.len()
                        && self.data[self.pos] != b'\n'
                        && self.data[self.pos] != b'\r'
                    {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    pub(crate) fn next_token(&mut self) -> Token {
        loop {
            self.skip_whitespace();
            if self.pos >= self.data.len() {
                return Token::Eof;
            }
            let ch = self.data[self.pos];
            match ch {
                b'<' => {
                    if self.pos + 1 < self.data.len() && self.data[self.pos + 1] == b'<' {
                        self.pos += 2;
                        return Token::DictStart;
                    }
                    self.pos += 1;
                    return Token::String(self.read_hex_string());
                }
                b'>' => {
                    if self.pos + 1 < self.data.len() && self.data[self.pos + 1] == b'>' {
                        self.pos += 2;
                        return Token::DictEnd;
                    }
                    // stray > — skip and retry
                    self.pos += 1;
                    continue;
                }
                b'[' => {
                    self.pos += 1;
                    return Token::ArrayStart;
                }
                b']' => {
                    self.pos += 1;
                    return Token::ArrayEnd;
                }
                b'(' => {
                    self.pos += 1;
                    return Token::String(self.read_literal_string());
                }
                b'/' => {
                    self.pos += 1;
                    return Token::Name(self.read_name());
                }
                b'-' | b'+' | b'0'..=b'9' => {
                    return self.read_number();
                }
                b'n' if self.starts_with(b"null") => {
                    self.pos += 4;
                    return Token::Null;
                }
                b't' if self.starts_with(b"true") => {
                    self.pos += 4;
                    return Token::True;
                }
                b'f' if self.starts_with(b"false") => {
                    self.pos += 5;
                    return Token::False;
                }
                b'o' if self.starts_with(b"obj") => {
                    self.pos += 3;
                    return Token::Obj;
                }
                b'e' if self.starts_with(b"endobj") => {
                    self.pos += 6;
                    return Token::EndObj;
                }
                b's' if self.starts_with(b"stream") => {
                    self.pos += 6;
                    if self.pos < self.data.len() && self.data[self.pos] == b'\r' {
                        self.pos += 1;
                    }
                    if self.pos < self.data.len() && self.data[self.pos] == b'\n' {
                        self.pos += 1;
                    }
                    return Token::Stream;
                }
                b'e' if self.starts_with(b"endstream") => {
                    self.pos += 9;
                    return Token::EndStream;
                }
                b'R' => {
                    self.pos += 1;
                    return Token::R;
                }
                _ => {
                    // skip unknown byte and retry
                    self.pos += 1;
                    continue;
                }
            }
        }
    }

    fn starts_with(&self, s: &[u8]) -> bool {
        self.data[self.pos..].starts_with(s)
    }

    fn read_hex_string(&mut self) -> Vec<u8> {
        let mut hex = Vec::new();
        while self.pos < self.data.len() && self.data[self.pos] != b'>' {
            let ch = self.data[self.pos];
            if ch.is_ascii_hexdigit() {
                hex.push(ch);
            }
            self.pos += 1;
        }
        if self.pos < self.data.len() {
            self.pos += 1; // skip >
        }
        // Convert hex pairs to bytes
        let mut result = Vec::with_capacity(hex.len() / 2);
        for pair in hex.chunks(2) {
            if pair.len() == 2 {
                if let Ok(b) = u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("0"), 16) {
                    result.push(b);
                }
            } else if pair.len() == 1 {
                if let Ok(b) = u8::from_str_radix(&format!("{}0", char::from(pair[0])), 16) {
                    result.push(b);
                }
            }
        }
        result
    }

    fn read_literal_string(&mut self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut depth = 1u32;
        while self.pos < self.data.len() && depth > 0 {
            let ch = self.data[self.pos];
            match ch {
                b'(' => {
                    depth += 1;
                    result.push(ch);
                    self.pos += 1;
                }
                b')' => {
                    depth -= 1;
                    if depth > 0 {
                        result.push(ch);
                    }
                    self.pos += 1;
                }
                b'\\' => {
                    self.pos += 1;
                    if self.pos < self.data.len() {
                        match self.data[self.pos] {
                            b'n' => result.push(b'\n'),
                            b'r' => result.push(b'\r'),
                            b't' => result.push(b'\t'),
                            b'\\' => result.push(b'\\'),
                            b'(' => result.push(b'('),
                            b')' => result.push(b')'),
                            b'\r' => {
                                // PDF spec §7.4.2: \CR, \CR+LF, \LF all produce nothing (line continuation)
                                if self.pos + 1 < self.data.len()
                                    && self.data[self.pos + 1] == b'\n'
                                {
                                    self.pos += 1; // skip LF after CR
                                }
                            }
                            b'\n' => {
                                // PDF spec §7.4.2: \LF produces nothing (line continuation)
                            }
                            d @ b'0'..=b'7' => {
                                let mut octal = (d - b'0') as u16;
                                for _ in 0..2 {
                                    self.pos += 1;
                                    if self.pos < self.data.len() {
                                        if let Some(o) = self.data[self.pos].checked_sub(b'0') {
                                            if o <= 7 {
                                                octal = octal * 8 + o as u16;
                                            } else {
                                                break;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                result.push(octal as u8);
                            }
                            other => result.push(other),
                        }
                        self.pos += 1;
                    }
                }
                _ => {
                    result.push(ch);
                    self.pos += 1;
                }
            }
        }
        result
    }

    fn read_name(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b'<' | b'>' | b'/' | b'[' | b']'
                | b'{' | b'}' | b'%' | 0 => break,
                _ => self.pos += 1,
            }
        }
        // Decode #XX escapes
        let raw = &self.data[start..self.pos];
        let mut name = String::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'#' && i + 2 < raw.len() {
                if let Ok(b) =
                    u8::from_str_radix(std::str::from_utf8(&raw[i + 1..i + 3]).unwrap_or("0"), 16)
                {
                    name.push(b as char);
                    i += 3;
                    continue;
                }
            }
            name.push(raw[i] as char);
            i += 1;
        }
        name
    }

    fn read_number(&mut self) -> Token {
        let start = self.pos;
        let mut has_dot = false;
        if self.data[self.pos] == b'-' || self.data[self.pos] == b'+' {
            self.pos += 1;
        }
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b'0'..=b'9' => self.pos += 1,
                b'.' if !has_dot => {
                    has_dot = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let s = std::str::from_utf8(&self.data[start..self.pos]).unwrap_or("0");
        if has_dot {
            s.parse::<f64>()
                .map(Token::Real)
                .unwrap_or(Token::Real(0.0))
        } else {
            s.parse::<i64>()
                .map(Token::Integer)
                .unwrap_or(Token::Integer(0))
        }
    }

    /// Quick scan: find the next `N G obj` pattern starting from current position.
    /// Returns (obj_number, gen_number, offset_of_first_byte_after_obj_keyword) or None.
    pub(crate) fn find_next_obj(&mut self) -> Option<(u32, u32, usize)> {
        while self.pos < self.data.len() {
            self.skip_whitespace();
            if self.pos >= self.data.len() {
                return None;
            }
            // Try to read: number number obj
            let saved = self.pos;
            if let Token::Integer(n) = self.read_number() {
                if n >= 0 {
                    self.skip_whitespace();
                    if self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
                        // This might be the generation number
                        let gen_start = self.pos;
                        while self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
                            self.pos += 1;
                        }
                        let gen: u32 = std::str::from_utf8(&self.data[gen_start..self.pos])
                            .unwrap_or("0")
                            .parse()
                            .unwrap_or(0);
                        self.skip_whitespace();
                        if self.starts_with(b"obj") {
                            self.pos += 3;
                            return Some((n as u32, gen, self.pos));
                        }
                    }
                }
            }
            self.pos = saved;
            // Skip forward looking for digit
            self.pos += 1;
        }
        None
    }
}
