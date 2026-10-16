//! Escaping for the XML parts a converter writes.

/// Appends `s` escaped for XML text or an attribute value. Characters XML
/// 1.0 cannot hold are dropped.
pub fn esc_into(o: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\t' | '\n' | '\r' => o.push(c),
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => {}
            c => o.push(c),
        }
    }
}

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    esc_into(&mut o, s);
    o
}

/// RGB as six hex digits.
pub fn hex(c: u32) -> String {
    format!("{:06X}", c & 0xFF_FFFF)
}

pub const XML_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_drops_what_xml_cannot_hold() {
        assert_eq!(esc("a<b & \"c\""), "a&lt;b &amp; &quot;c&quot;");
        assert_eq!(esc("x\u{1}y\u{FFFF}\u{FFFE}\u{1F}"), "xy");
        assert_eq!(esc("tab\tok"), "tab\tok");
        assert_eq!(hex(0x12ABCDEF), "ABCDEF");
    }
}
