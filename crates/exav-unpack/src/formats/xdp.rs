//! Adobe XDP (XML Data Package): an XML wrapper carrying a base64-encoded PDF.
//!
//! A malicious PDF is frequently smuggled inside an `.xdp`: the bytes live in one
//! or more `<chunk>…</chunk>` elements under `<pdf>` (itself under the `<xdp>`
//! root). We concatenate every chunk's base64 payload, decode it, and emit the
//! reconstructed PDF as a single member for the engine to recurse into.
//!
//! Parsing is a plain byte scan, fully bounds-checked so truncated/hostile
//! input cannot panic. A chunk's character references are read, as an XML
//! reader does; CDATA sections and comments in a chunk are not.
//!
//! The format is also found by a string in a text ([`looks_like_xdp`]): a text
//! whose root is not an XDP's and whose chunks are not base64 has no PDF, and
//! is only a text.

use crate::*;
use base64::Engine;

/// Whether `data` names XDP's tags anywhere in its first 64 KiB: `<pdf` and
/// `<chunk`, or `<xdp`.
pub(crate) fn looks_like_xdp(data: &[u8]) -> bool {
    let head = &data[..data.len().min(65536)];
    let has = |needle: &[u8]| memchr::memmem::find(head, needle).is_some();
    (has(b"<pdf") && has(b"<chunk")) || has(b"<xdp")
}

/// Whether `data` holds the root element of an Adobe XDP, `<xdp:xdp`, in its
/// first 64 KiB: the namespaced tag every XDP an Adobe tool writes opens with.
/// A bare `<xdp` is a string in a text.
pub(crate) fn has_adobe_root(data: &[u8]) -> bool {
    let head = &data[..data.len().min(65536)];
    memchr::memmem::find(head, b"<xdp:xdp").is_some()
}

/// Whether the root element of `data`, past the XML declaration, processing
/// instructions, comments and a doctype, is `xdp` under any prefix.
fn root_is_xdp(data: &[u8]) -> bool {
    let head = &data[..data.len().min(65536)];
    let mut rest = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    loop {
        rest = rest.trim_ascii_start();
        let close: &[u8] = if rest.starts_with(b"<?") {
            b"?>"
        } else if rest.starts_with(b"<!--") {
            b"-->"
        } else if rest.starts_with(b"<!") {
            b">"
        } else {
            break;
        };
        let Some(at) = memchr::memmem::find(&rest[2..], close) else {
            return false;
        };
        rest = &rest[2 + at + close.len()..];
    }
    let Some(tag) = rest.strip_prefix(b"<") else {
        return false;
    };
    let end = tag
        .iter()
        .position(|&b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
        .unwrap_or(tag.len());
    let name = &tag[..end];
    name.rsplit(|&b| b == b':').next() == Some(b"xdp")
}

/// Appends the text of a chunk's body to `out`, as the base64 decoder reads
/// it: character references resolved, whitespace dropped. A reference that
/// is not to an ASCII character is kept as written, which does not decode.
fn chunk_text(body: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'&'
            && let Some((c, len)) = char_ref(&body[i..])
        {
            if !c.is_ascii_whitespace() {
                out.push(c);
            }
            i += len;
            continue;
        }
        if !body[i].is_ascii_whitespace() {
            out.push(body[i]);
        }
        i += 1;
    }
}

fn is_base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

/// The ASCII character of the character reference `s` starts with
/// (`&#65;`, `&#x41;`), and its length.
fn char_ref(s: &[u8]) -> Option<(u8, usize)> {
    let rest = s.strip_prefix(b"&#")?;
    let (digits, radix) = match rest.strip_prefix(b"x") {
        Some(hex) => (hex, 16),
        None => (rest, 10),
    };
    let n = digits
        .iter()
        .take_while(|&&b| char::from(b).is_digit(radix))
        .count();
    if digits.get(n) != Some(&b';') {
        return None;
    }
    let text = std::str::from_utf8(&digits[..n]).ok()?;
    let c = u8::try_from(u32::from_str_radix(text, radix).ok()?).ok()?;
    c.is_ascii().then_some((c, s.len() - digits.len() + n + 1))
}

pub(crate) fn extract_xdp(data: &[u8], budget: &mut Budget, visit: Sink) -> crate::Extracted {
    let rooted = root_is_xdp(data);
    // Collect the base64 text of every <chunk>…</chunk>.
    let mut b64: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        // Find the next "<chunk" start tag.
        let Some(rel) = memchr::memmem::find(&data[pos..], b"<chunk") else {
            break;
        };
        let tag_start = pos + rel;
        // The chunk body begins after the '>' that closes the opening tag.
        let Some(gt) = memchr::memchr(b'>', &data[tag_start.min(data.len())..]) else {
            break;
        };
        let body_start = (tag_start + gt + 1).min(data.len());
        // The body ends at the next "</chunk" (or EOF for a truncated doc).
        let body_end = memchr::memmem::find(&data[body_start..], b"</chunk")
            .map(|r| body_start + r)
            .unwrap_or(data.len());
        let from = b64.len();
        chunk_text(&data[body_start..body_end], &mut b64);
        if !rooted && !b64[from..].iter().all(|&b| is_base64(b)) {
            return Ok(None);
        }
        // Bound the accumulated base64 so an XDP bomb can't blow past the budget
        // before we decode (4 base64 chars -> 3 bytes).
        let cap_peek = budget
            .limits
            .max_buffer_bytes
            .min(budget.limits.max_extracted_bytes);
        if b64.len() as u64 > cap_peek.saturating_mul(2).saturating_add(64) {
            return Err(LimitHit::new(
                "xdp: embedded PDF exceeds budget".to_string(),
            ));
        }
        pos = body_end.saturating_add(7).min(data.len()); // past "</chunk"
    }

    if b64.is_empty() {
        return Ok(None);
    }

    let decoded = base64::engine::general_purpose::STANDARD.decode(&b64);
    if decoded.is_err() && !rooted {
        return Ok(None);
    }
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let out = decoded.map_err(|e| LimitHit::corrupt(format!("xdp base64: {e}")))?;
    if out.len() as u64 > cap {
        return Err(LimitHit::new(
            "xdp: embedded PDF exceeds budget".to_string(),
        ));
    }
    budget.commit(out.len() as u64);
    if let Some(r) = visit(Entry::new("embedded.pdf".to_string(), out), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_single_chunk_roundtrip() {
        let pdf = b"%PDF-1.4 MALWARETEST body \nendobj\n%%EOF";
        let b64 = base64::engine::general_purpose::STANDARD.encode(pdf);
        let xdp = format!(
            "<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">\
             <pdf xmlns=\"http://ns.adobe.com/xdp/pdf/\"><document><chunk>{b64}</chunk>\
             </document></pdf></xdp:xdp>"
        )
        .into_bytes();
        assert!(looks_like_xdp(&xdp));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xdp, &xdp, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "embedded.pdf");
        assert_eq!(entries[0].data, pdf);
    }

    #[test]
    fn xdp_multi_chunk_concatenated() {
        // Two chunks whose base64 concatenates to the full PDF (whitespace and
        // newlines between/within chunks must be ignored).
        let pdf = b"%PDF-1.5 MALWARETEST split across chunks";
        let full = base64::engine::general_purpose::STANDARD.encode(pdf);
        let (a, b) = full.split_at(full.len() / 2);
        let xdp = format!("<xdp><pdf><chunk>\n  {a}\n</chunk><chunk>{b}\n</chunk></pdf></xdp>")
            .into_bytes();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xdp, &xdp, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, pdf);
    }

    #[test]
    fn character_references_in_a_chunk_are_read() {
        let pdf = b"%PDF-1.4 MALWARETEST with escaped line ends";
        let b64 = base64::engine::general_purpose::STANDARD.encode(pdf);
        let (a, b) = b64.split_at(8);
        let a = format!("&#{};&#x{:x};{}", a.as_bytes()[0], a.as_bytes()[1], &a[2..]);
        let xdp = format!(
            "<?xml version=\"1.0\"?>\n<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">\
             <pdf><document><chunk>{a}&#10;&#xD;&#x0a;{b}&#13;</chunk></document></pdf></xdp:xdp>"
        );
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xdp, &xdp.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, pdf);
    }

    #[test]
    fn a_text_that_names_the_tags_is_only_a_text() {
        for text in [
            &b"let s = \"<xdp><pdf><chunk>{b64}</chunk></pdf></xdp>\";\n"[..],
            b"// <pdf> holds a <chunk>, and the root is <xdp:xdp ...>.\n",
            b"notes\n<pdf><chunk>QUJD</chunk> and <chunk>&#x2603;</chunk>\n",
            b"an unclosed <xdp><pdf><chunk>QUJ",
        ] {
            let mut budget = Budget::new(Limits::default());
            let entries = extract(Format::Xdp, &text, &mut budget);
            assert!(entries.unwrap().is_empty(), "{}", text.escape_ascii());
        }
        // Before the budget: the rest of a long text is not a chunk.
        let small = Limits {
            max_buffer_bytes: 16,
            ..Limits::default()
        };
        let long = [&b"<pdf><chunk>"[..], &b"a text, not base64. ".repeat(10)].concat();
        let mut budget = Budget::new(small);
        assert!(extract(Format::Xdp, &long, &mut budget).unwrap().is_empty());
    }

    #[test]
    fn an_xdp_whose_chunk_does_not_decode_is_corrupt() {
        for xdp in [
            &b"<?xml version=\"1.0\"?><!-- <a> --><?xfa generator=\"x\"?>\n\
               <xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><pdf><chunk>{b64}</chunk>"[..],
            b"\xEF\xBB\xBF<x:xdp xmlns:x=\"http://ns.adobe.com/xdp/\"><pdf><chunk>QUJD&#xE9;</chunk>",
            b"<xdp><pdf><chunk>QUJ\n", // no closing tag
        ] {
            let mut budget = Budget::new(Limits::default());
            let hit = extract(Format::Xdp, &xdp, &mut budget).unwrap_err();
            assert_eq!(hit.kind, LimitKind::Corrupt, "{}", xdp.escape_ascii());
        }
    }

    #[test]
    fn truncated_chunk_does_not_panic() {
        let xdp = b"<xdp><pdf><chunk>QUJD".to_vec(); // no closing tag
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Xdp, &xdp, &mut budget);
    }
}
