//! Text documents in other encodings than UTF-8, to UTF-8: SpreadsheetML in
//! the encoding its XML declaration names (HTML is `exav_unpack::html::decode`).

use std::borrow::Cow;

/// How far into a document its encoding is looked for.
const HEAD: usize = 1024;

/// UTF-16 by its byte order mark, or by the `<` of a document without one.
fn utf16(b: &[u8]) -> Option<&'static encoding_rs::Encoding> {
    match b {
        [0xFF, 0xFE, ..] | [b'<', 0, b'?' | b'!' | b'h' | b'H', 0, ..] => {
            Some(encoding_rs::UTF_16LE)
        }
        [0xFE, 0xFF, ..] | [0, b'<', 0, b'?' | b'!' | b'h' | b'H', ..] => {
            Some(encoding_rs::UTF_16BE)
        }
        _ => None,
    }
}

/// UTF-16 cut after an odd byte: the half unit dropped.
fn even<'a>(b: &'a [u8], enc: &'static encoding_rs::Encoding) -> &'a [u8] {
    if (enc == encoding_rs::UTF_16LE || enc == encoding_rs::UTF_16BE) && b.len() % 2 == 1 {
        &b[..b.len() - 1]
    } else {
        b
    }
}

fn decode<'a>(b: &'a [u8], enc: &'static encoding_rs::Encoding) -> Cow<'a, [u8]> {
    let b = even(b, enc);
    match enc.decode_with_bom_removal(b).0 {
        Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
        Cow::Owned(s) => Cow::Owned(s.into_bytes()),
    }
}

/// The value of `name="..."` (or `'...'`, or bare) in `head`, any case.
fn attr_value(head: &str, name: &str) -> Option<String> {
    let lower = head.to_ascii_lowercase();
    let mut from = 0;
    while let Some(p) = lower[from..].find(name) {
        let mut i = from + p + name.len();
        from = i;
        let b = lower.as_bytes();
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if b.get(i) != Some(&b'=') {
            continue;
        }
        i += 1;
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let quote = b.get(i).copied().filter(|q| matches!(q, b'"' | b'\''));
        if quote.is_some() {
            i += 1;
        }
        let start = i;
        while i < b.len() && !matches!(b[i], b'"' | b'\'' | b' ' | b'>' | b';' | b'/') {
            i += 1;
        }
        if i > start {
            return Some(lower[start..i].to_string());
        }
    }
    None
}

/// An XML document as UTF-8: its BOM's encoding, else its declaration's.
pub fn xml_utf8(b: &[u8]) -> Cow<'_, [u8]> {
    if let Some(enc) = utf16(b) {
        return decode(b, enc);
    }
    if let Some(rest) = b.strip_prefix(b"\xEF\xBB\xBF") {
        return Cow::Borrowed(rest);
    }
    let head = String::from_utf8_lossy(&b[..b.len().min(HEAD)]);
    let decl = head
        .split("?>")
        .next()
        .filter(|_| head.starts_with("<?xml"))
        .unwrap_or("");
    match attr_value(decl, "encoding").and_then(|l| encoding_rs::Encoding::for_label(l.as_bytes()))
    {
        Some(enc) if enc != encoding_rs::UTF_8 => decode(b, enc),
        _ => Cow::Borrowed(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml() {
        let latin = b"<?xml version=\"1.0\" encoding=\"windows-1251\"?><a>\xC0</a>";
        assert_eq!(
            std::str::from_utf8(&xml_utf8(latin)).unwrap(),
            "<?xml version=\"1.0\" encoding=\"windows-1251\"?><a>\u{410}</a>"
        );
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<a>é</a>".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(&*xml_utf8(&utf16), "<a>é</a>".as_bytes());
        assert_eq!(&*xml_utf8(b"\xEF\xBB\xBF<a/>"), b"<a/>");
        assert_eq!(
            &*xml_utf8(b"<a encoding='latin1'>\xE9</a>"),
            b"<a encoding='latin1'>\xE9</a>"
        );
    }
}
