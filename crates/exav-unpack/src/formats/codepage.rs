//! AutoCAD drawing strings to UTF-8.
//!
//! Before 2007 a drawing is in the code page `$DWGCODEPAGE` names, and
//! characters outside it are written as `\U+XXXX` (a UTF-16 code unit) or
//! `\M+nXXXX` (a double-byte character of an Asian code page: `n` 1
//! Shift-JIS, 2 Big5, 3 Wansung, 4 Johab, 5 GB 2312). From 2007 on the file
//! is UTF-8, though writers still use the escapes. Both are decoded here, in
//! every version: they encode characters, unlike `%%` codes and MTEXT
//! formatting, which are left to the renderer.

use std::borrow::Cow;

use encoding_rs::Encoding;

/// How a drawing's strings are decoded.
#[derive(Clone, Copy, Debug)]
pub struct Decoder(Kind);

#[derive(Clone, Copy, Debug)]
enum Kind {
    Utf8,
    Legacy(&'static Encoding),
    /// No header said: UTF-8 where the bytes are, Windows-1252 otherwise.
    Guess,
}

impl Default for Decoder {
    /// Windows-1252, AutoCAD's default code page.
    fn default() -> Self {
        Decoder(Kind::Legacy(encoding_rs::WINDOWS_1252))
    }
}

impl Decoder {
    /// UTF-8, as every 2007 and later drawing is.
    pub const UTF8: Decoder = Decoder(Kind::Utf8);
    /// For a file whose header names neither version nor code page: UTF-8
    /// where the bytes are valid UTF-8, Windows-1252 otherwise.
    pub const GUESS: Decoder = Decoder(Kind::Guess);

    /// A string already in Unicode (a 2007 and later DWG's UTF-16), its
    /// `\U+XXXX` and `\M+nXXXX` escapes decoded as [`Decoder::decode`]
    /// decodes them.
    pub fn unescape(s: &str) -> Cow<'_, str> {
        unescape(s)
    }

    /// The decoder for a code page name as `$DWGCODEPAGE` holds it
    /// (`ANSI_1252`, `ANSI_932`...); `None` for a name this reader does not
    /// have. An empty or `UNDEFINED` name is Windows-1252.
    pub fn for_code_page(name: &str) -> Option<Decoder> {
        code_page(name).map(|c| match c {
            CodePage::Utf8 => Decoder(Kind::Utf8),
            CodePage::Legacy(e) => Decoder(Kind::Legacy(e)),
        })
    }

    /// The decoder for a drawing's `$ACADVER` and `$DWGCODEPAGE` (empty when
    /// absent), and whether its code page was one this reader has: from
    /// AC1021 (2007) on, UTF-8; before, the code page, Windows-1252 when it is
    /// unknown.
    pub fn for_drawing(acadver: &str, code_page: &str) -> (Decoder, bool) {
        let acadver = acadver.trim();
        if acadver.starts_with("AC") && acadver >= "AC1021" {
            return (Decoder::UTF8, true);
        }
        if acadver.is_empty() && code_page.trim().is_empty() {
            return (Decoder::GUESS, true);
        }
        match Decoder::for_code_page(code_page) {
            Some(d) => (d, true),
            None => (Decoder::default(), false),
        }
    }

    /// The string `bytes` hold, escapes decoded.
    pub fn decode(&self, bytes: &[u8]) -> String {
        let raw: Cow<'_, str> = match self.0 {
            Kind::Utf8 => String::from_utf8_lossy(bytes),
            Kind::Legacy(e) => e.decode_without_bom_handling(bytes).0,
            Kind::Guess => match std::str::from_utf8(bytes) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => {
                    encoding_rs::WINDOWS_1252
                        .decode_without_bom_handling(bytes)
                        .0
                }
            },
        };
        match unescape(&raw) {
            Cow::Borrowed(_) => raw.into_owned(),
            Cow::Owned(s) => s,
        }
    }
}

enum CodePage {
    Utf8,
    Legacy(&'static Encoding),
}

/// AutoCAD's code page names, as `$DWGCODEPAGE` holds them.
fn code_page(name: &str) -> Option<CodePage> {
    use encoding_rs as e;
    let upper = name.trim().to_ascii_uppercase();
    let enc = match upper.as_str() {
        "" | "UNDEFINED" | "ANSI_1252" | "ISO8859-1" | "ISO8859_1" | "ASCII" => e::WINDOWS_1252,
        "UTF8" | "UTF-8" => return Some(CodePage::Utf8),
        "ANSI_874" => e::WINDOWS_874,
        "ANSI_932" | "DOS932" | "SHIFT_JIS" => e::SHIFT_JIS,
        "ANSI_936" | "GB2312" => e::GBK,
        "ANSI_949" | "KSC5601" => e::EUC_KR,
        "ANSI_950" | "BIG5" => e::BIG5,
        "ANSI_1250" => e::WINDOWS_1250,
        "ANSI_1251" => e::WINDOWS_1251,
        "ANSI_1253" => e::WINDOWS_1253,
        "ANSI_1254" => e::WINDOWS_1254,
        "ANSI_1255" => e::WINDOWS_1255,
        "ANSI_1256" => e::WINDOWS_1256,
        "ANSI_1257" => e::WINDOWS_1257,
        "ANSI_1258" => e::WINDOWS_1258,
        "DOS866" => e::IBM866,
        // The ODA converter's name for it.
        "MACINTOSH" | "MAC-ROMAN" => e::MACINTOSH,
        "ISO8859-2" => e::ISO_8859_2,
        "ISO8859-3" => e::ISO_8859_3,
        "ISO8859-4" => e::ISO_8859_4,
        "ISO8859-5" => e::ISO_8859_5,
        "ISO8859-6" => e::ISO_8859_6,
        "ISO8859-7" => e::ISO_8859_7,
        "ISO8859-8" => e::ISO_8859_8,
        "ISO8859-9" => e::WINDOWS_1254,
        "ISO8859-10" => e::ISO_8859_10,
        _ => return None,
    };
    Some(CodePage::Legacy(enc))
}

fn hex_value(digits: &[u8]) -> Option<u32> {
    let mut v = 0u32;
    for d in digits {
        v = v.checked_mul(16)? + char::from(*d).to_digit(16)?;
    }
    Some(v)
}

/// The UTF-16 code unit of a `\U+XXXX` escape at the start of `s`.
fn unicode_escape(s: &[u8]) -> Option<u32> {
    match s {
        [b'\\', b'U' | b'u', b'+', a, b, c, d, ..] => hex_value(&[*a, *b, *c, *d]),
        _ => None,
    }
}

/// The character of a `\M+nXXXX` escape at the start of `s`.
fn mif_escape(s: &[u8]) -> Option<char> {
    let [b'\\', b'M' | b'm', b'+', n, a, b, c, d, ..] = s else {
        return None;
    };
    let encoding = match n {
        b'1' => encoding_rs::SHIFT_JIS,
        b'2' => encoding_rs::BIG5,
        b'3' => encoding_rs::EUC_KR,
        b'5' => encoding_rs::GBK,
        // 4 is Johab, which encoding_rs does not have.
        _ => return None,
    };
    let v = hex_value(&[*a, *b, *c, *d])?;
    let pair = [(v >> 8) as u8, v as u8];
    let bytes = if pair[0] == 0 { &pair[1..] } else { &pair[..] };
    let (text, _, bad) = encoding.decode(bytes);
    let mut chars = text.chars();
    match (bad, chars.next(), chars.next()) {
        (false, Some(c), None) => Some(c),
        _ => None,
    }
}

/// Replace `\U+XXXX` and `\M+nXXXX` escapes. An escape that does not decode
/// is left as written.
pub(crate) fn unescape(s: &str) -> Cow<'_, str> {
    if !s.contains("\\U+") && !s.contains("\\u+") && !s.contains("\\M+") && !s.contains("\\m+") {
        return Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut copied = 0;
    while let Some(rest) = bytes.get(i..) {
        if rest.first() != Some(&b'\\') {
            if rest.is_empty() {
                break;
            }
            i += 1;
            continue;
        }
        let decoded: Option<(char, usize)> = if let Some(unit) = unicode_escape(rest) {
            match unit {
                0xD800..=0xDBFF => {
                    // A high surrogate needs its low half in the next escape.
                    rest.get(7..)
                        .and_then(unicode_escape)
                        .filter(|low| (0xDC00..=0xDFFF).contains(low))
                        .and_then(|low| {
                            char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))
                        })
                        .map(|c| (c, 14))
                }
                _ => char::from_u32(unit).map(|c| (c, 7)),
            }
        } else {
            mif_escape(rest).map(|c| (c, 8))
        };
        match decoded {
            Some((c, len)) => {
                out.push_str(s.get(copied..i).unwrap_or(""));
                out.push(c);
                i += len;
                copied = i;
            }
            None => i += 1,
        }
    }
    if copied == 0 {
        return Cow::Borrowed(s);
    }
    out.push_str(s.get(copied..).unwrap_or(""));
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_escapes_decode_in_any_case_and_bad_ones_stay() {
        assert_eq!(unescape(r"caf\U+00E9"), "café");
        assert_eq!(unescape(r"\U+4e2d\U+0416"), "中Ж");
        assert_eq!(unescape(r"\u+0041x"), "Ax");
        assert_eq!(unescape(r"\U+D83D\U+DE00"), "\u{1F600}");
        assert_eq!(unescape(r"\U+D83D alone"), r"\U+D83D alone");
        assert_eq!(unescape(r"\U+12"), r"\U+12");
        assert_eq!(unescape(r"\U+zzzz"), r"\U+zzzz");
        assert_eq!(unescape(r"\P\U+0041"), r"\PA");
    }

    #[test]
    fn mif_escapes_decode_through_their_code_page() {
        // Shift-JIS 0x93FA is 日, GB 2312 0xD6D0 is 中.
        assert_eq!(unescape(r"\M+193FA"), "日");
        assert_eq!(unescape(r"\M+5D6D0"), "中");
        assert_eq!(unescape(r"\M+493FA"), r"\M+493FA");
    }

    #[test]
    fn a_code_page_decodes_high_bytes() {
        let (d, known) = Decoder::for_drawing("AC1015", "ANSI_1251");
        assert!(known);
        assert_eq!(d.decode(b"\xc6"), "Ж");
        let (d, known) = Decoder::for_drawing("AC1015", "dos437");
        assert!(!known);
        assert_eq!(d.decode(b"\xe9"), "é");
    }

    #[test]
    fn from_2007_strings_are_utf8_whatever_the_code_page() {
        let (d, known) = Decoder::for_drawing("AC1021", "ANSI_1251");
        assert!(known);
        assert_eq!(d.decode("Ж".as_bytes()), "Ж");
        // No header at all: UTF-8 if it is, else Windows-1252.
        let (d, _) = Decoder::for_drawing("", "");
        assert_eq!(d.decode("Ж".as_bytes()), "Ж");
        assert_eq!(d.decode(b"\xe9"), "é");
    }
}
