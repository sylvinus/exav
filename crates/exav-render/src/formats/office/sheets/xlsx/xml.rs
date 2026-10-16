//! XML text helpers.

use crate::formats::office::sheets::model::Rgb;
use std::fmt::Write as _;

/// Appends `s` escaped for XML text or an attribute value. Characters XML
/// 1.0 cannot hold are written as SpreadsheetML's `_xHHHH_` escapes, and a
/// literal `_xHHHH_` has its underscore escaped so that it reads back as
/// written. Lone surrogates cannot occur in a `str`.
pub fn esc_into(o: &mut String, s: &str) {
    let b = s.as_bytes();
    let mut start = 0;
    for (at, c) in s.char_indices() {
        let rep: Option<&str> = match c {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '"' => Some("&quot;"),
            '\t' | '\n' | '\r' => None,
            '_' if b.len() >= at + 7
                && b[at + 1] == b'x'
                && b[at + 2..at + 6].iter().all(u8::is_ascii_hexdigit)
                && b[at + 6] == b'_' =>
            {
                Some("_x005F_")
            }
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => {
                o.push_str(&s[start..at]);
                let _ = write!(o, "_x{:04X}_", c as u32);
                start = at + c.len_utf8();
                continue;
            }
            _ => None,
        };
        if let Some(r) = rep {
            o.push_str(&s[start..at]);
            o.push_str(r);
            start = at + c.len_utf8();
        }
    }
    o.push_str(&s[start..]);
}

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    esc_into(&mut o, s);
    o
}

/// ARGB as SpreadsheetML writes it.
pub fn argb(c: Rgb) -> String {
    format!("FF{:06X}", c & 0xFF_FFFF)
}

/// RGB as DrawingML writes it.
pub fn rgb(c: Rgb) -> String {
    format!("{:06X}", c & 0xFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::esc;

    #[test]
    fn escapes() {
        assert_eq!(esc("a<b & \"c\""), "a&lt;b &amp; &quot;c&quot;");
        assert_eq!(esc("x\u{1}y"), "x_x0001_y");
        assert_eq!(esc("_x0041_"), "_x005F_x0041_");
        assert_eq!(esc("tab\tok_x"), "tab\tok_x");
        assert_eq!(esc("été"), "été");
    }
}
