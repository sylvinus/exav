//! Textual content canonicalisation for normalised signature matching.
//!
//! `Target:3` (HTML) and `Target:7` (text) signatures are authored against
//! *canonicalised* content rather than raw bytes (`Target:4`, mail, matches the
//! raw bytes; see `target_ok` in `engine`), so that a
//! single pattern matches regardless of letter case, HTML entity encoding,
//! comment insertion or whitespace padding used to evade it. This module is a
//! clean-room implementation driven by that interoperability requirement:
//!
//! * [`is_textual`] — cheap gate: is a buffer worth normalising at all?
//! * [`html`]       — decode HTML entities, lowercase, collapse whitespace.
//! * [`text`]       — lowercase, drop control bytes, collapse whitespace.
//! * [`javascript`] — strip comments (quote-aware), lowercase, collapse whitespace.
//!
//! None of these interpret attacker-controlled sizes; they walk the input once
//! and can't panic on any byte sequence.

use crate::byte_source::{Bytes, Indexed};

/// Fraction (percent) of sampled bytes that must be "text-like" for a buffer to
/// be treated as textual, and the NUL-byte ceiling above which it's binary.
const TEXT_PERCENT: usize = 90;
/// Bytes of an object's start [`is_textual`] looks at.
pub(crate) const SAMPLE: usize = 8192;

/// Heuristic: does this buffer look like text worth running normalised
/// signatures over? Empty input is not textual; a buffer with more than ~1% NUL
/// bytes, or fewer than `TEXT_PERCENT`% printable/whitespace/high bytes in its
/// leading sample, is treated as binary.
pub fn is_textual(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = &data[..data.len().min(SAMPLE)];
    let mut text = 0usize;
    let mut nul = 0usize;
    for &b in sample {
        match b {
            0 => nul += 1,
            b'\t' | b'\n' | b'\r' | 0x0c => text += 1,
            0x20..=0x7e => text += 1,
            0x80..=0xff => text += 1, // UTF-8/extended: treat as text-ish
            _ => {}                   // other control bytes: neither
        }
    }
    if nul.saturating_mul(100) > sample.len() {
        return false;
    }
    text.saturating_mul(100) >= sample.len().saturating_mul(TEXT_PERCENT)
}

/// Lowercase an ASCII letter, leave everything else unchanged.
#[inline]
fn lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// Where a normaliser writes its view: memory, or a spill for an object too
/// large to hold.
pub(crate) trait Out {
    fn push(&mut self, b: u8);
    fn last(&self) -> Option<u8>;
}

impl Out for Vec<u8> {
    #[inline]
    fn push(&mut self, b: u8) {
        Vec::push(self, b);
    }
    fn last(&self) -> Option<u8> {
        self.as_slice().last().copied()
    }
}

/// Append `b`, collapsing any run of ASCII whitespace to a single space.
#[inline]
fn push_collapsed<O: Out>(out: &mut O, b: u8, prev_ws: &mut bool) {
    if b.is_ascii_whitespace() {
        if !*prev_ws {
            out.push(b' ');
            *prev_ws = true;
        }
    } else {
        out.push(b);
        *prev_ws = false;
    }
}

/// Normalise HTML: decode entities, lowercase, collapse whitespace. Tags are
/// preserved (so `Target:3` signatures written against markup still match).
pub fn html(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    html_into(&mut Indexed(data), &mut out);
    out
}

/// [`html`] from any object into any [`Out`].
pub(crate) fn html_into<B: Bytes, O: Out>(data: &mut B, out: &mut O) {
    let mut prev_ws = false;
    let mut i = 0usize;
    let n = data.len();
    while i < n {
        let (b, next) = decode_entity_at(data, i);
        push_collapsed(out, lower(b), &mut prev_ws);
        i = next;
    }
}

/// Normalise plain text: lowercase, drop control bytes, collapse whitespace.
pub fn text(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    text_into(&mut Indexed(data), &mut out);
    out
}

/// [`text`] from any object into any [`Out`].
pub(crate) fn text_into<B: Bytes, O: Out>(data: &mut B, out: &mut O) {
    let mut prev_ws = false;
    for i in 0..data.len() {
        let b = data.at(i);
        if b.is_ascii_whitespace() {
            push_collapsed(out, b, &mut prev_ws);
        } else if b >= 0x20 {
            out.push(lower(b));
            prev_ws = false;
        }
    }
}

/// A JavaScript identifier byte (letters, digits, `_`, `$`).
#[inline]
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Normalise script/JavaScript: strip comments (respecting string literals),
/// lowercase, and remove whitespace between tokens — keeping a single space only
/// between two identifier characters so tokens don't merge. Defeats the classic
/// comment-and-case obfuscation of `eval(unescape(...))`-style loaders (a comment
/// between `eval(` and `unescape(` must not leave a separating space).
pub fn javascript(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    javascript_into(&mut Indexed(data), &mut out);
    out
}

/// [`javascript`] from any object into any [`Out`].
pub(crate) fn javascript_into<B: Bytes, O: Out>(data: &mut B, out: &mut O) {
    let mut pending_ws = false;
    strip_comments(data, &mut |b| {
        if b.is_ascii_whitespace() {
            pending_ws = true;
            return;
        }
        let c = lower(b);
        if pending_ws {
            pending_ws = false;
            if let Some(last) = out.last() {
                if is_word(last) && is_word(c) {
                    out.push(b' ');
                }
            }
        }
        out.push(c);
    });
}

/// The byte an HTML character reference at `i` decodes to, and where the text
/// after it starts: numeric decimal (`&#105;`), numeric hex (`&#x69;`/`&#X69;`)
/// and the handful of named entities. Only well-formed, terminated references
/// decode; anything else is the byte at `i` itself.
#[inline]
fn decode_entity_at<B: Bytes>(data: &mut B, i: usize) -> (u8, usize) {
    let b = data.at(i);
    if b != b'&' {
        return (b, i + 1);
    }
    // Find the terminating ';' within a short window (entities are short).
    let limit = (i + 12).min(data.len());
    let window = data.range(i + 1, limit);
    let Some(p) = window.iter().position(|&b| b == b';') else {
        return (b'&', i + 1);
    };
    match decode_reference(&window[..p]) {
        Some(decoded) => (decoded, i + 1 + p + 1),
        None => (b'&', i + 1),
    }
}

/// Decode the inside of one `&…;` reference to a single byte, if recognised.
fn decode_reference(body: &[u8]) -> Option<u8> {
    if body.is_empty() {
        return None;
    }
    if body[0] == b'#' {
        let (radix, digits) = match body.get(1) {
            Some(b'x') | Some(b'X') => (16u32, &body[2..]),
            _ => (10u32, &body[1..]),
        };
        if digits.is_empty() {
            return None;
        }
        let mut value: u32 = 0;
        for &d in digits {
            let v = (d as char).to_digit(radix)?;
            value = value.checked_mul(radix)?.checked_add(v)?;
            if value > 0x10_FFFF {
                return None;
            }
        }
        // We normalise to bytes; keep the low byte of the code point.
        return Some((value & 0xFF) as u8);
    }
    match body.to_ascii_lowercase().as_slice() {
        b"lt" => Some(b'<'),
        b"gt" => Some(b'>'),
        b"amp" => Some(b'&'),
        b"quot" => Some(b'"'),
        b"apos" => Some(b'\''),
        b"nbsp" => Some(b' '),
        _ => None,
    }
}

/// Remove `/* … */` and `// …` comments, treating them as inert inside string
/// literals (`'…'`, `"…"`, `` `…` ``) so a comment marker in a string survives.
/// Each byte kept goes to `out`.
fn strip_comments<B: Bytes, F: FnMut(u8)>(data: &mut B, out: &mut F) {
    let n = data.len();
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < n {
        let b = data.at(i);
        if let Some(q) = quote {
            out(b);
            if b == b'\\' && i + 1 < n {
                out(data.at(i + 1)); // keep the escaped char intact
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quote = Some(b);
                out(b);
                i += 1;
            }
            b'/' if i + 1 < n && data.at(i + 1) == b'*' => {
                i += 2;
                while i + 1 < n && !(data.at(i) == b'*' && data.at(i + 1) == b'/') {
                    i += 1;
                }
                i = (i + 2).min(n);
                out(b' '); // comment becomes a token separator
            }
            b'/' if i + 1 < n && data.at(i + 1) == b'/' => {
                i += 2;
                while i < n && data.at(i) != b'\n' {
                    i += 1;
                }
            }
            _ => {
                out(b);
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textual_gate() {
        assert!(is_textual(b"plain ascii text file\n"));
        assert!(is_textual("café — unicode".as_bytes()));
        assert!(!is_textual(b""));
        assert!(!is_textual(&[0u8; 64]));
        let mut binary = vec![0u8; 200];
        binary[..20].fill(b'A');
        assert!(!is_textual(&binary));
    }

    #[test]
    fn html_lowercases_decodes_and_collapses() {
        let raw = b"<SCRIPT>EV&#x69;L</SCRIPT>   and\n\tmore <b>HTML</b>";
        let out = html(raw);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("<script>evil"), "got: {s}");
        assert!(s.contains(" and more "), "whitespace not collapsed: {s}");
    }

    #[test]
    fn html_decimal_and_named_entities() {
        let out = html(b"A&#105;&amp;&lt;B&gt;");
        assert_eq!(out, b"ai&<b>");
    }

    #[test]
    fn malformed_entities_pass_through() {
        // Unterminated / empty / non-entity ampersands are copied verbatim.
        let out = html(b"a & b &# &#;");
        let s = String::from_utf8_lossy(&out);
        assert!(s.starts_with("a & b"));
    }

    #[test]
    fn javascript_strips_comments_and_lowercases() {
        let raw = b"EVAL(/* c */unescape('%61'))";
        let out = javascript(raw);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("eval("), "got: {s}");
        assert!(s.contains("unescape("), "got: {s}");
    }

    #[test]
    fn javascript_line_comment_and_string_marker() {
        let raw = b"x = 1; // kill\nvar u = \"/*not_a_comment*/\";";
        let out = javascript(raw);
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("kill"), "line comment survived: {s}");
        // The `/*`…`*/` inside the string literal must not be stripped as a comment.
        assert!(s.contains("/*not_a_comment*/"), "string content lost: {s}");
        assert!(s.contains("var u"), "identifier spacing lost: {s}");
    }

    #[test]
    fn text_drops_controls_and_lowercases() {
        let out = text(b"Hello\x00\x01World\t\tGoodbye");
        assert_eq!(out, b"helloworld goodbye");
    }

    /// The normalisers as they were, over a slice in two passes.
    mod before {
        use super::super::{decode_reference, is_word, lower};

        fn collapse(out: &mut Vec<u8>, b: u8, prev_ws: &mut bool) {
            if b.is_ascii_whitespace() {
                if !*prev_ws {
                    out.push(b' ');
                    *prev_ws = true;
                }
            } else {
                out.push(b);
                *prev_ws = false;
            }
        }

        pub fn html(data: &[u8]) -> Vec<u8> {
            let mut decoded = Vec::new();
            let mut i = 0usize;
            let n = data.len();
            while i < n {
                if data[i] != b'&' {
                    decoded.push(data[i]);
                    i += 1;
                    continue;
                }
                let limit = (i + 12).min(n);
                let semi = data[i + 1..limit].iter().position(|&b| b == b';').map(|p| i + 1 + p);
                match semi.and_then(|s| decode_reference(&data[i + 1..s]).map(|d| (d, s))) {
                    Some((d, s)) => {
                        decoded.push(d);
                        i = s + 1;
                    }
                    None => {
                        decoded.push(b'&');
                        i += 1;
                    }
                }
            }
            let mut out = Vec::new();
            let mut prev_ws = false;
            for &b in &decoded {
                collapse(&mut out, lower(b), &mut prev_ws);
            }
            out
        }

        pub fn text(data: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            let mut prev_ws = false;
            for &b in data {
                if b.is_ascii_whitespace() {
                    collapse(&mut out, b, &mut prev_ws);
                } else if b >= 0x20 {
                    out.push(lower(b));
                    prev_ws = false;
                }
            }
            out
        }

        pub fn javascript(data: &[u8]) -> Vec<u8> {
            let mut stripped = Vec::new();
            let n = data.len();
            let mut i = 0usize;
            let mut quote: Option<u8> = None;
            while i < n {
                let b = data[i];
                if let Some(q) = quote {
                    stripped.push(b);
                    if b == b'\\' && i + 1 < n {
                        stripped.push(data[i + 1]);
                        i += 2;
                        continue;
                    }
                    if b == q {
                        quote = None;
                    }
                    i += 1;
                    continue;
                }
                match b {
                    b'\'' | b'"' | b'`' => {
                        quote = Some(b);
                        stripped.push(b);
                        i += 1;
                    }
                    b'/' if i + 1 < n && data[i + 1] == b'*' => {
                        i += 2;
                        while i + 1 < n && !(data[i] == b'*' && data[i + 1] == b'/') {
                            i += 1;
                        }
                        i = (i + 2).min(n);
                        stripped.push(b' ');
                    }
                    b'/' if i + 1 < n && data[i + 1] == b'/' => {
                        i += 2;
                        while i < n && data[i] != b'\n' {
                            i += 1;
                        }
                    }
                    _ => {
                        stripped.push(b);
                        i += 1;
                    }
                }
            }
            let mut out: Vec<u8> = Vec::new();
            let mut pending_ws = false;
            for &b in &stripped {
                if b.is_ascii_whitespace() {
                    pending_ws = true;
                    continue;
                }
                let c = lower(b);
                if pending_ws {
                    pending_ws = false;
                    if let Some(&last) = out.last() {
                        if is_word(last) && is_word(c) {
                            out.push(b' ');
                        }
                    }
                }
                out.push(c);
            }
            out
        }
    }

    #[test]
    fn references_at_the_edge_of_the_window_decode_as_they_did() {
        for s in [
            &b"a&#000000065;b"[..],
            b"a&#0000000065;b",
            b"&#x00000041;",
            b"&#x000000041;",
            b"&AMP;&amp&#;&#x;&",
        ] {
            assert_eq!(html(s), before::html(s), "{:?}", String::from_utf8_lossy(s));
        }
        assert_eq!(html(b"a&#000000065;b"), b"aab");
    }

    #[test]
    fn the_views_are_what_they_were_from_memory_or_read_in_blocks() {
        use crate::byte_source::{BlockCache, Stepper, CHUNK};
        let alphabet = b"&#;x6aA9lgt amp;\t\n/*'\"`\\\x01Zq_$";
        let mut state = 0x853C_49E6_748F_EA9Bu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..400 {
            let len = if round < 390 { (next() % 64) as usize } else { 3 * CHUNK + (next() % 100) as usize };
            let data: Vec<u8> = (0..len).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            let what = String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned();
            assert_eq!(html(&data), before::html(&data), "html {what:?}");
            assert_eq!(text(&data), before::text(&data), "text {what:?}");
            assert_eq!(javascript(&data), before::javascript(&data), "javascript {what:?}");
            let cache = BlockCache::with_sizes(std::io::Cursor::new(data.clone()), 7, 56).unwrap();
            let mut got = Vec::new();
            html_into(&mut Stepper::new(&cache), &mut got);
            assert_eq!(got, html(&data), "html read in blocks, {what:?}");
            got.clear();
            text_into(&mut Stepper::new(&cache), &mut got);
            assert_eq!(got, text(&data), "text read in blocks, {what:?}");
            got.clear();
            javascript_into(&mut Stepper::new(&cache), &mut got);
            assert_eq!(got, javascript(&data), "javascript read in blocks, {what:?}");
        }
    }
}
