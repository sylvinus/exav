//! Content normalisation for `Target:3` (HTML), `Target:4` (mail) and
//! `Target:7` (ASCII / normalised) signatures, which are evaluated against
//! a canonicalised stream rather than raw bytes. Without this, signatures
//! written against normalised HTML/text never match.
//!
//! This is a pragmatic normaliser (lowercase, entity-decode, comment-strip,
//! whitespace-collapse), close to but not byte-identical with the reference
//! `cli_html_normalise`; it recovers the bulk of normalised-content matches.

/// Cheap heuristic: is the content textual enough to be worth normalising?
/// True when the first chunk is overwhelmingly printable ASCII / whitespace.
pub fn is_textual(data: &[u8]) -> bool {
    let head = &data[..data.len().min(8192)];
    if head.is_empty() {
        return false;
    }
    let mut printable = 0usize;
    for &b in head {
        if b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b) {
            printable += 1;
        }
    }
    printable * 100 / head.len() >= 90
}

/// Decode an HTML entity body (the text between `&` and `;`) into bytes.
fn decode_entity(body: &[u8], out: &mut Vec<u8>) {
    let push_char = |cp: u32, out: &mut Vec<u8>| {
        if let Some(c) = char::from_u32(cp) {
            // The normalised stream is lowercased throughout, so a decoded
            // letter entity (e.g. `&#x41;` -> 'A') is lowercased too.
            let c = c.to_ascii_lowercase();
            let mut b = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
        }
    };
    if let Some(num) = body.strip_prefix(b"#") {
        let cp = if let Some(hex) = num.strip_prefix(b"x").or_else(|| num.strip_prefix(b"X")) {
            u32::from_str_radix(&String::from_utf8_lossy(hex), 16).ok()
        } else {
            String::from_utf8_lossy(num).parse::<u32>().ok()
        };
        if let Some(cp) = cp {
            push_char(cp, out);
            return;
        }
    } else {
        // Lowercased already by the caller, so match lowercase names.
        let named: &[(&[u8], &[u8])] = &[
            (b"amp", b"&"),
            (b"lt", b"<"),
            (b"gt", b">"),
            (b"quot", b"\""),
            (b"apos", b"'"),
            (b"nbsp", b" "),
            (b"tab", b"\t"),
            (b"newline", b"\n"),
        ];
        for (n, v) in named {
            if body == *n {
                out.extend_from_slice(v);
                return;
            }
        }
    }
    // Unknown entity: keep it verbatim so a signature written against the raw
    // entity still has a chance.
    out.push(b'&');
    out.extend_from_slice(body);
    out.push(b';');
}

/// Normalise HTML-ish content: lowercase ASCII, strip `<!-- -->` comments,
/// decode entities, and collapse runs of whitespace to a single space.
pub fn html(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let mut last_ws = false;
    while i < data.len() {
        // Strip HTML comments.
        if data[i..].starts_with(b"<!--") {
            if let Some(end) = find(&data[i + 4..], b"-->") {
                i += 4 + end + 3;
                continue;
            }
            break; // unterminated comment: drop the rest
        }
        let b = data[i];
        if b.is_ascii_whitespace() {
            if !last_ws {
                out.push(b' ');
                last_ws = true;
            }
            i += 1;
            continue;
        }
        last_ws = false;
        if b == b'&' {
            // Entity: read up to ';' within a small bound.
            if let Some(semi) = data[i + 1..].iter().take(32).position(|&c| c == b';') {
                let body: Vec<u8> = data[i + 1..i + 1 + semi]
                    .iter()
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                decode_entity(&body, &mut out);
                i += 1 + semi + 1;
                continue;
            }
        }
        out.push(b.to_ascii_lowercase());
        i += 1;
    }
    out
}

/// Normalise plain text: lowercase ASCII and collapse whitespace runs.
pub fn text(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut last_ws = false;
    for &b in data {
        if b.is_ascii_whitespace() {
            if !last_ws {
                out.push(b' ');
                last_ws = true;
            }
        } else {
            out.push(b.to_ascii_lowercase());
            last_ws = false;
        }
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_lowercases_decodes_and_collapses() {
        let got = html(b"<A   HREF>Pay&amp;Day&#33;\n<!--junk-->X&#x41;</A>");
        let s = String::from_utf8(got).unwrap();
        assert_eq!(s, "<a href>pay&day! xa</a>");
    }

    #[test]
    fn text_lowercases_and_collapses_whitespace() {
        assert_eq!(text(b"Hello\t\n  WORLD"), b"hello world");
    }

    #[test]
    fn textual_heuristic() {
        assert!(is_textual(b"<html><body>hi</body></html>"));
        assert!(!is_textual(&[0u8, 1, 2, 3, 0xff, 0xfe, 0, 0, 0, 0]));
    }
}
