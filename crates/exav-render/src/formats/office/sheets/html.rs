//! HTML tables, as Excel saves a worksheet "as Web Page" (Microsoft Office
//! HTML and XML Reference, Office 2000) and as other programs export
//! spreadsheets: each table's cells, with Excel's `x:num`, `x:str`,
//! `x:bool`, `x:err` and `x:fmla` attributes, the `mso-` CSS properties
//! and the CSS of `<style>` blocks and `style` attributes, `colspan` and
//! `rowspan` as merges, `<col>` widths and `<tr>` heights.
//!
//! Data only: scripts, frames, images and links to other files are not
//! followed; nothing is fetched. The tokenizer is bounded like the XML
//! readers: elements, attributes, nesting and text.

use crate::formats::office::sheets::css;
use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use std::collections::HashSet;

const MAX_TOKENS: usize = 20_000_000;
const MAX_ATTRS: usize = 256;
const MAX_DEPTH: usize = 256;
/// Characters of one cell's text.
const MAX_CELL_TEXT: usize = 32_767;

// ------------------------------------------------------------ tokenizer

#[derive(Debug, PartialEq)]
pub(crate) enum Token {
    Start {
        name: String,
        attrs: Vec<(String, String)>,
        closed: bool,
    },
    End(String),
    Text(String),
    Comment(String),
}

/// HTML 4's named character references (the Latin-1 set and the common
/// symbols), sorted.
const ENTITIES: &[(&str, char)] = &[
    ("AElig", 'Æ'),
    ("Aacute", 'Á'),
    ("Acirc", 'Â'),
    ("Agrave", 'À'),
    ("Aring", 'Å'),
    ("Atilde", 'Ã'),
    ("Auml", 'Ä'),
    ("Ccedil", 'Ç'),
    ("Dagger", '‡'),
    ("ETH", 'Ð'),
    ("Eacute", 'É'),
    ("Ecirc", 'Ê'),
    ("Egrave", 'È'),
    ("Euml", 'Ë'),
    ("Iacute", 'Í'),
    ("Icirc", 'Î'),
    ("Igrave", 'Ì'),
    ("Iuml", 'Ï'),
    ("Ntilde", 'Ñ'),
    ("OElig", 'Œ'),
    ("Oacute", 'Ó'),
    ("Ocirc", 'Ô'),
    ("Ograve", 'Ò'),
    ("Oslash", 'Ø'),
    ("Otilde", 'Õ'),
    ("Ouml", 'Ö'),
    ("Scaron", 'Š'),
    ("THORN", 'Þ'),
    ("Uacute", 'Ú'),
    ("Ucirc", 'Û'),
    ("Ugrave", 'Ù'),
    ("Uuml", 'Ü'),
    ("Yacute", 'Ý'),
    ("Yuml", 'Ÿ'),
    ("aacute", 'á'),
    ("acirc", 'â'),
    ("acute", '´'),
    ("aelig", 'æ'),
    ("agrave", 'à'),
    ("amp", '&'),
    ("apos", '\''),
    ("aring", 'å'),
    ("atilde", 'ã'),
    ("auml", 'ä'),
    ("bdquo", '„'),
    ("brvbar", '¦'),
    ("bull", '•'),
    ("ccedil", 'ç'),
    ("cedil", '¸'),
    ("cent", '¢'),
    ("circ", 'ˆ'),
    ("copy", '©'),
    ("curren", '¤'),
    ("dagger", '†'),
    ("deg", '°'),
    ("divide", '÷'),
    ("eacute", 'é'),
    ("ecirc", 'ê'),
    ("egrave", 'è'),
    ("emsp", '\u{2003}'),
    ("ensp", '\u{2002}'),
    ("eth", 'ð'),
    ("euml", 'ë'),
    ("euro", '€'),
    ("frac12", '½'),
    ("frac14", '¼'),
    ("frac34", '¾'),
    ("gt", '>'),
    ("hellip", '…'),
    ("iacute", 'í'),
    ("icirc", 'î'),
    ("iexcl", '¡'),
    ("igrave", 'ì'),
    ("iquest", '¿'),
    ("iuml", 'ï'),
    ("laquo", '«'),
    ("ldquo", '“'),
    ("lsaquo", '‹'),
    ("lsquo", '‘'),
    ("lt", '<'),
    ("macr", '¯'),
    ("mdash", '—'),
    ("micro", 'µ'),
    ("middot", '·'),
    ("nbsp", '\u{A0}'),
    ("ndash", '–'),
    ("not", '¬'),
    ("ntilde", 'ñ'),
    ("oacute", 'ó'),
    ("ocirc", 'ô'),
    ("oelig", 'œ'),
    ("ograve", 'ò'),
    ("ordf", 'ª'),
    ("ordm", 'º'),
    ("oslash", 'ø'),
    ("otilde", 'õ'),
    ("ouml", 'ö'),
    ("para", '¶'),
    ("permil", '‰'),
    ("plusmn", '±'),
    ("pound", '£'),
    ("quot", '"'),
    ("raquo", '»'),
    ("rdquo", '”'),
    ("reg", '®'),
    ("rsaquo", '›'),
    ("rsquo", '’'),
    ("sbquo", '‚'),
    ("scaron", 'š'),
    ("sect", '§'),
    ("shy", '\u{AD}'),
    ("sup1", '¹'),
    ("sup2", '²'),
    ("sup3", '³'),
    ("szlig", 'ß'),
    ("thinsp", '\u{2009}'),
    ("thorn", 'þ'),
    ("tilde", '˜'),
    ("times", '×'),
    ("trade", '™'),
    ("uacute", 'ú'),
    ("ucirc", 'û'),
    ("ugrave", 'ù'),
    ("uml", '¨'),
    ("uuml", 'ü'),
    ("yacute", 'ý'),
    ("yen", '¥'),
    ("yuml", 'ÿ'),
];

/// Text with its character references resolved.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let end = rest[1..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '#'))
            .map_or(rest.len(), |e| e + 1);
        let name = &rest[1..end];
        let semi = rest[end..].starts_with(';');
        let c = if let Some(num) = name.strip_prefix('#') {
            let v = match num.strip_prefix(['x', 'X']) {
                Some(h) => u32::from_str_radix(h, 16).ok(),
                None => num.parse::<u32>().ok(),
            };
            // Windows-1252's C1 range, as browsers read it.
            v.map(|v| match v {
                0x80 => 0x20AC,
                0x91 => 0x2018,
                0x92 => 0x2019,
                0x93 => 0x201C,
                0x94 => 0x201D,
                0x96 => 0x2013,
                0x97 => 0x2014,
                v => v,
            })
            .and_then(char::from_u32)
            .filter(|c| *c != '\0')
        } else {
            ENTITIES
                .binary_search_by_key(&name, |e| e.0)
                .ok()
                .map(|i| ENTITIES[i].1)
        };
        match c {
            Some(c) if name.len() > 1 || semi => {
                out.push(c);
                rest = &rest[end + usize::from(semi)..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Elements whose content is text up to their end tag.
const RAW: &[&str] = &[
    "script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript",
];

pub(crate) fn tokenize(s: &str) -> Result<Vec<Token>> {
    let mut out = vec![];
    let b = s.as_bytes();
    let mut i = 0;
    let mut text_start = 0;
    let lower = |a: usize, z: usize| s[a..z].to_ascii_lowercase();
    macro_rules! push {
        ($t:expr) => {{
            if out.len() >= MAX_TOKENS {
                return Err(Error::TooLarge("HTML elements"));
            }
            out.push($t);
        }};
    }
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        let flush = |out: &mut Vec<Token>, from: usize, to: usize| {
            if to > from {
                out.push(Token::Text(unescape(&s[from..to])));
            }
        };
        if s[i..].starts_with("<!--") {
            flush(&mut out, text_start, i);
            let end = s[i + 4..].find("-->").map_or(b.len(), |e| i + 4 + e);
            push!(Token::Comment(s[i + 4..end].to_string()));
            i = (end + 3).min(b.len());
            text_start = i;
            continue;
        }
        if s[i..].starts_with("<![if") {
            // Downlevel-revealed conditional markup: what Excel writes for
            // browsers (`!supportTabStrip`, `!vml`, `supportMisalignedColumns`
            // and the like) is not what Excel reads.
            flush(&mut out, text_start, i);
            let end = s[i..].find('>').map_or(b.len(), |e| i + e + 1);
            let cond = s.get(i + 5..end).unwrap_or("").to_ascii_lowercase();
            i = end;
            if cond.contains('!') || cond.contains("support") {
                let mut depth = 1;
                while depth > 0 && i < b.len() {
                    let next_if = s[i..].find("<![if").map(|p| i + p);
                    let next_end = s[i..].find("<![endif]>").map(|p| i + p);
                    match (next_if, next_end) {
                        (Some(a), Some(e)) if a < e => {
                            depth += 1;
                            i = a + 5;
                        }
                        (_, Some(e)) => {
                            depth -= 1;
                            i = e + 10;
                        }
                        _ => i = b.len(),
                    }
                }
            }
            text_start = i;
            continue;
        }
        if s[i..].starts_with("<!") || s[i..].starts_with("<?") {
            // Doctype, processing instructions, `<![endif]>`.
            flush(&mut out, text_start, i);
            i = s[i..].find('>').map_or(b.len(), |e| i + e + 1);
            text_start = i;
            continue;
        }
        let close = b.get(i + 1) == Some(&b'/');
        let ns = i + 1 + usize::from(close);
        let mut j = ns;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || matches!(b[j], b':' | b'-' | b'_')) {
            j += 1;
        }
        if j == ns || !b[ns].is_ascii_alphabetic() {
            // A "<" that starts no tag is text.
            i += 1;
            continue;
        }
        flush(&mut out, text_start, i);
        let name = lower(ns, j);
        // Attributes.
        let mut attrs = vec![];
        let mut k = j;
        let mut closed = false;
        loop {
            while k < b.len() && (b[k].is_ascii_whitespace() || b[k] == b'/') {
                if b[k] == b'/' {
                    closed = true;
                }
                k += 1;
            }
            if k >= b.len() || b[k] == b'>' {
                break;
            }
            closed = false;
            let a = k;
            while k < b.len() && !b[k].is_ascii_whitespace() && !matches!(b[k], b'=' | b'>' | b'/')
            {
                k += 1;
            }
            let key = lower(a, k);
            while k < b.len() && b[k].is_ascii_whitespace() {
                k += 1;
            }
            let mut value = String::new();
            if b.get(k) == Some(&b'=') {
                k += 1;
                while k < b.len() && b[k].is_ascii_whitespace() {
                    k += 1;
                }
                match b.get(k) {
                    Some(&q @ (b'"' | b'\'')) => {
                        let v = k + 1;
                        let e = s[v..].find(char::from(q)).map_or(b.len(), |e| v + e);
                        value = unescape(&s[v..e]);
                        k = (e + 1).min(b.len());
                    }
                    _ => {
                        let v = k;
                        while k < b.len() && !b[k].is_ascii_whitespace() && b[k] != b'>' {
                            k += 1;
                        }
                        value = unescape(&s[v..k]);
                    }
                }
            }
            if a == k {
                k += 1;
                continue;
            }
            if attrs.len() < MAX_ATTRS && !key.is_empty() {
                attrs.push((key, value));
            }
        }
        i = (k + 1).min(b.len());
        text_start = i;
        if close {
            push!(Token::End(name));
            continue;
        }
        let raw = RAW.contains(&name.as_str()) && !closed;
        push!(Token::Start {
            name: name.clone(),
            attrs,
            closed
        });
        if raw {
            let end_tag = format!("</{name}");
            let rest = s[i..].to_ascii_lowercase();
            let e = rest.find(&end_tag).map_or(b.len(), |e| i + e);
            if name == "style" || name == "title" {
                push!(Token::Text(if name == "title" {
                    unescape(&s[i..e])
                } else {
                    s[i..e].to_string()
                }));
            }
            push!(Token::End(name));
            i = s[e..].find('>').map_or(b.len(), |g| e + g + 1);
            text_start = i;
        }
    }
    if text_start < b.len() {
        out.push(Token::Text(unescape(&s[text_start..])));
    }
    Ok(out)
}

pub(crate) fn get<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs.iter().find(|a| a.0 == key).map(|a| a.1.as_str())
}

// ------------------------------------------------------------------ CSS

/// A style sheet: the declarations of each simple selector (`td`,
/// `.xl65`, `td.xl65`), in source order.
#[derive(Default)]
pub(crate) struct Sheet {
    rules: Vec<(String, Vec<(String, String)>)>,
}

impl Sheet {
    pub(crate) fn add(&mut self, css_text: &str) {
        // Comments out, the HTML comment markers Excel wraps it in too.
        let mut t = String::with_capacity(css_text.len());
        let mut rest = css_text;
        while let Some(p) = rest.find("/*") {
            t.push_str(&rest[..p]);
            rest = rest[p + 2..]
                .find("*/")
                .map_or("", |e| &rest[p + 2 + e + 2..]);
        }
        t.push_str(rest);
        let t = t.replace("<!--", " ").replace("-->", " ");
        let mut rest = t.as_str();
        while let Some(open) = rest.find('{') {
            let Some(close) = rest[open..].find('}').map(|c| open + c) else {
                break;
            };
            let decls = css::declarations(&rest[open + 1..close]);
            for sel in rest[..open].split(',') {
                let sel = sel.trim().to_ascii_lowercase();
                if !sel.is_empty() && !sel.starts_with('@') && self.rules.len() < 1 << 16 {
                    self.rules.push((sel, decls.clone()));
                }
            }
            rest = &rest[close + 1..];
        }
    }

    /// Declarations for an element of `tag` and `classes`: the element's
    /// rules, then its classes', each in source order. A class naming
    /// `mso-style-parent` gets that style's declarations under its own.
    pub(crate) fn lookup(&self, tag: &str, classes: &[&str], out: &mut Vec<(String, String)>) {
        for (sel, decls) in &self.rules {
            if sel == tag {
                out.extend(decls.iter().cloned());
            }
        }
        for cls in classes {
            let cls = cls.to_ascii_lowercase();
            let dot = format!(".{cls}");
            let tagged = format!("{tag}.{cls}");
            for (sel, decls) in &self.rules {
                if *sel == dot || *sel == tagged {
                    if let Some(parent) = decls
                        .iter()
                        .find(|d| d.0 == "mso-style-parent")
                        .map(|d| d.1.trim().to_ascii_lowercase())
                    {
                        if parent != cls {
                            let p = format!(".{parent}");
                            for (s2, d2) in &self.rules {
                                if *s2 == p {
                                    out.extend(d2.iter().cloned());
                                }
                            }
                        }
                    }
                    out.extend(decls.iter().cloned());
                }
            }
        }
    }
}

/// CSS string escapes (`\0022`, `\@`) resolved, its quotes off.
fn css_string(v: &str) -> String {
    let v = v.trim();
    let v = v
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
        .unwrap_or(v);
    let mut out = String::new();
    let mut chars = v.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let mut hex = String::new();
        while hex.len() < 6 && chars.peek().is_some_and(char::is_ascii_hexdigit) {
            hex.push(chars.next().unwrap_or('0'));
        }
        if hex.is_empty() {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            if chars.peek() == Some(&' ') {
                chars.next();
            }
            if let Some(ch) = u32::from_str_radix(&hex, 16)
                .ok()
                .and_then(char::from_u32)
                .filter(|c| *c != '\0')
            {
                out.push(ch);
            }
        }
    }
    out
}

/// A number format from `mso-number-format`: Excel's escapes kept as
/// format escapes, its named formats resolved.
fn number_format(v: &str) -> String {
    let f = css_string(v);
    if let Some(n) = crate::formats::office::sheets::xmlss::named_format(&f) {
        return n.to_string();
    }
    f.chars().take(255).collect()
}

/// `mso-pattern`'s pattern names as XLSX's.
fn mso_pattern(p: &str) -> Option<&'static str> {
    Some(match p {
        "gray-75" => "darkGray",
        "gray-50" => "mediumGray",
        "gray-25" => "lightGray",
        "gray-125" => "gray125",
        "gray-0625" => "gray0625",
        "horz-stripe" => "darkHorizontal",
        "vert-stripe" => "darkVertical",
        "reverse-diag-stripe" => "darkUp",
        "diag-stripe" => "darkDown",
        "diag-cross" => "darkGrid",
        "thick-diag-cross" => "darkTrellis",
        "thin-horz-stripe" => "lightHorizontal",
        "thin-vert-stripe" => "lightVertical",
        "thin-reverse-diag-stripe" => "lightUp",
        "thin-diag-stripe" => "lightDown",
        "thin-horz-cross" => "lightGrid",
        "thin-diag-cross" => "lightTrellis",
        _ => return None,
    })
}

/// What a declaration list says of a cell's style, over `st`.
fn apply(st: &mut Style, decls: &[(String, String)], ignore: &mut HashSet<String>) {
    let mut background = None;
    let mut pattern = None;
    for (k, v) in decls {
        let v = v.trim();
        let low = v.to_ascii_lowercase();
        match k.as_str() {
            "mso-number-format" => st.numfmt = number_format(v),
            "text-align" => {
                st.align.horizontal = match low.as_str() {
                    "left" => Some("left"),
                    "center" => Some("center"),
                    "right" => Some("right"),
                    "justify" => Some("justify"),
                    "fill" => Some("fill"),
                    "center-across" | "centeracross" => Some("centerContinuous"),
                    "distributed" => Some("distributed"),
                    _ => None,
                };
            }
            "vertical-align" => match low.as_str() {
                "super" => st.font.vert_align = Some("superscript"),
                "sub" => st.font.vert_align = Some("subscript"),
                _ => {
                    st.align.vertical = match low.as_str() {
                        "top" => Some("top"),
                        "middle" | "center" => Some("center"),
                        "justify" => Some("justify"),
                        "distributed" => Some("distributed"),
                        _ => None,
                    };
                }
            },
            "mso-text-control" => match low.as_str() {
                "shrinktofit" => st.align.shrink = true,
                "wrap" => st.align.wrap = true,
                _ => {}
            },
            "border-style" => {
                // Excel's line styles CSS has no name for, after the
                // shorthand that gave the width and colour.
                let name = match low.as_str() {
                    "hairline" => Some("hair"),
                    "dash-dot" | "dot-dash" => Some("dashDot"),
                    "dash-dot-dot" | "dot-dot-dash" => Some("dashDotDot"),
                    "slanted-dash-dot" => Some("slantDashDot"),
                    _ => None,
                };
                if let Some(n) = name {
                    for e in [
                        &mut st.border.top,
                        &mut st.border.right,
                        &mut st.border.bottom,
                        &mut st.border.left,
                    ] {
                        if let Some(old) = e.style {
                            let wide = old.starts_with("medium") || old == "thick";
                            e.style = Some(match (n, wide) {
                                ("dashDot", true) => "mediumDashDot",
                                ("dashDotDot", true) => "mediumDashDotDot",
                                _ => n,
                            });
                        }
                    }
                }
            }
            "white-space" => {
                st.align.wrap = matches!(low.as_str(), "normal" | "pre-wrap" | "pre-line")
            }
            "font-weight" => {
                st.font.bold =
                    low == "bold" || low == "bolder" || low.parse::<u32>().is_ok_and(|w| w >= 600)
            }
            "font-style" => st.font.italic = low == "italic" || low == "oblique",
            "font-size" => {
                if let Some(pt) = css::length_pt(&low, "px").filter(|p| *p > 0.0) {
                    st.font.size_centipt = (pt * 100.0).round().clamp(100.0, 40_000.0) as u32;
                }
            }
            "font-family" => {
                let first = v
                    .split(',')
                    .map(|f| f.trim().trim_matches(['"', '\'']).trim())
                    .find(|f| {
                        !f.is_empty()
                            && !matches!(
                                f.to_ascii_lowercase().as_str(),
                                "sans-serif"
                                    | "serif"
                                    | "monospace"
                                    | "cursive"
                                    | "fantasy"
                                    | "system-ui"
                            )
                    });
                if let Some(f) = first {
                    st.font.name = f.chars().take(64).collect();
                }
            }
            "color" => {
                if let Some(c) = css::color(v) {
                    st.font.color = c.filter(|&c| c != 0);
                }
            }
            "text-decoration" | "text-decoration-line" => {
                st.font.underline = low
                    .contains("underline")
                    .then_some(st.font.underline.unwrap_or("single"));
                st.font.strike = low.contains("line-through");
            }
            "text-underline-style" | "mso-text-underline" => {
                st.font.underline = match low.as_str() {
                    "double" => Some("double"),
                    "single-accounting" => Some("singleAccounting"),
                    "double-accounting" => Some("doubleAccounting"),
                    "none" => None,
                    _ => Some("single"),
                };
            }
            "vertical-align-text" | "mso-text-raise" => {}
            "background" | "background-color" => {
                if let Some(c) = low.split_whitespace().find_map(css::color) {
                    background = Some(c);
                }
            }
            "mso-pattern" => pattern = Some(low.clone()),
            "border" => {
                let e = css::border(v);
                st.border.top = e.clone();
                st.border.right = e.clone();
                st.border.bottom = e.clone();
                st.border.left = e;
            }
            "border-top" => st.border.top = css::border(v),
            "border-right" => st.border.right = css::border(v),
            "border-bottom" => st.border.bottom = css::border(v),
            "border-left" => st.border.left = css::border(v),
            "mso-diagonal-down" | "mso-diagonal-up" => {
                let e = css::border(v);
                if e.style.is_some() {
                    if k.ends_with("down") {
                        st.border.diag_down = true;
                    } else {
                        st.border.diag_up = true;
                    }
                    st.border.diagonal = e;
                }
            }
            "mso-rotate" => {
                if let Ok(r) = low.parse::<f64>() {
                    let r = r.round().clamp(-90.0, 90.0) as i32;
                    st.align.rotation = if r < 0 { (90 - r) as u8 } else { r as u8 };
                }
            }
            "layout-flow" if low.contains("vertical") => st.align.rotation = 255,
            "mso-char-indent-count" => {
                if let Ok(n) = low.parse::<f64>() {
                    st.align.indent = n.clamp(0.0, 250.0) as u8;
                }
            }
            "mso-protection" => {
                st.locked = !low.contains("unlocked");
                st.hidden = low.contains("hidden");
            }
            "mso-ignore" => {
                for w in low.split_whitespace() {
                    ignore.insert(w.to_string());
                }
            }
            _ => {}
        }
    }
    let pat = pattern
        .as_deref()
        .and_then(|p| p.split_whitespace().nth(1))
        .unwrap_or("none");
    match (background, pat) {
        (Some(None), _) => st.fill = Fill::NONE,
        (Some(Some(bg)), "none" | "solid") => st.fill = Fill::solid(bg),
        (bg, p) => {
            if let Some(kind) = mso_pattern(p) {
                let fg = pattern
                    .as_deref()
                    .and_then(|p| p.split_whitespace().next())
                    .and_then(css::color)
                    .flatten()
                    .or(Some(0));
                st.fill = Fill {
                    pattern: kind,
                    fg,
                    bg: bg.flatten().or(match &st.fill {
                        f if f.pattern == "solid" => f.fg,
                        _ => None,
                    }),
                };
            }
        }
    }
}

// --------------------------------------------------------------- tables

/// A cell's text as runs of one font each.
#[derive(Default)]
struct Runs {
    runs: Vec<Run>,
    len: usize,
    /// The text's last character is white space (or none was written).
    space: bool,
}

impl Runs {
    fn push(&mut self, t: &str, font: &Font, pre: bool) {
        for c in t.chars() {
            if self.len >= MAX_CELL_TEXT {
                return;
            }
            let c = if c == '\u{A0}' { ' ' } else { c };
            let ws = c.is_whitespace() && !pre;
            if ws {
                if self.space {
                    continue;
                }
                self.space = true;
            } else {
                self.space = c == '\n';
            }
            let c = if ws { ' ' } else { c };
            match self.runs.last_mut() {
                Some(r) if r.font.as_ref() == Some(font) => r.text.push(c),
                _ => self.runs.push(Run {
                    text: c.to_string(),
                    font: Some(font.clone()),
                }),
            }
            self.len += 1;
        }
    }

    fn newline(&mut self, font: &Font) {
        if let Some(r) = self.runs.last_mut() {
            while r.text.ends_with(' ') {
                r.text.pop();
            }
        }
        if self.len > 0 {
            self.space = false;
            self.push("\n", font, true);
            self.space = true;
        }
    }

    fn text(&self) -> String {
        self.runs
            .iter()
            .map(|r| r.text.as_str())
            .collect::<String>()
            .trim_matches([' ', '\n'])
            .to_string()
    }
}

struct CellOut {
    row: u32,
    col: u32,
    rows: u32,
    cols: u32,
    merge: bool,
    style: Style,
    runs: Runs,
    attrs: Vec<(String, String)>,
    link: Option<String>,
    header: bool,
    /// Text after line breaks that start a new cell, a row down each.
    below: Vec<Runs>,
}

/// A table's rows, read from its tokens.
#[derive(Default)]
struct Table {
    cells: Vec<CellOut>,
    rows: Vec<(u32, Option<f64>, bool)>,
    cols: Vec<(u32, u32, Option<Width>, bool)>,
    /// Text cells by default (`x:str` on the table).
    strings: bool,
    /// The decimal and thousands separators of cells without `x:num`.
    seps: (char, char),
    height: u32,
    /// The table's `<caption>`, a row above it.
    caption: Option<Runs>,
    /// Lines around cells (the `border` attribute).
    ruled: bool,
}

/// What a page puts on the sheet, top to bottom: tables, and the text
/// around them a row each in the first column.
enum Block {
    Table(Table),
    Text(Runs),
}

/// `mso-displayed-decimal-separator` and its thousands twin, `.` and `,`
/// unless they say otherwise.
fn separators(d: &[(String, String)]) -> (char, char) {
    let one = |k: &str, def: char| {
        d.iter()
            .rev()
            .find(|x| x.0 == k)
            .and_then(|x| css_string(&x.1).chars().next())
            .unwrap_or(def)
    };
    (
        one("mso-displayed-decimal-separator", '.'),
        one("mso-displayed-thousand-separator", ','),
    )
}

/// Parses `s` as a number the way a cell's text reads as one: an optional
/// sign or parentheses, a currency sign, digits with thousands
/// separators, decimals and a percent sign. The value and the format
/// that shows it so.
fn parse_number(s: &str, seps: (char, char)) -> Option<(f64, Option<&'static str>)> {
    // To "1,234.5" form: other separators than these two are not a number's.
    let (dec, thou) = seps;
    if s.chars()
        .any(|c| matches!(c, '.' | ',') && c != dec && c != thou)
    {
        return None;
    }
    let mut t: String = s
        .trim()
        .chars()
        .filter(|c| !matches!(c, '\u{A0}' | ' ') || thou == *c)
        .map(|c| {
            if c == thou {
                ','
            } else if c == dec {
                '.'
            } else {
                c
            }
        })
        .collect();
    if t.is_empty() || t.len() > 64 {
        return None;
    }
    let mut neg = false;
    if t.starts_with('(') && t.ends_with(')') {
        neg = true;
        t = t[1..t.len() - 1].to_string();
    }
    if let Some(r) = t.strip_prefix('-') {
        neg = !neg;
        t = r.to_string();
    } else if let Some(r) = t.strip_prefix('+') {
        t = r.to_string();
    }
    let currency = t.starts_with('$');
    let t = t.trim_start_matches('$');
    let percent = t.ends_with('%');
    let t = t.trim_end_matches('%');
    let grouped = t.contains(',');
    if grouped {
        // Groups of three after the first.
        let int = t.split('.').next().unwrap_or("");
        let mut groups = int.split(',');
        let first = groups.next().unwrap_or("");
        if first.is_empty() || first.len() > 3 || !groups.all(|g| g.len() == 3) {
            return None;
        }
    }
    let plain = t.replace(',', "");
    if plain.is_empty()
        || !plain
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
        || !plain.starts_with(|c: char| c.is_ascii_digit() || c == '.')
    {
        return None;
    }
    let mut v: f64 = plain.parse().ok().filter(|v: &f64| v.is_finite())?;
    if neg {
        v = -v;
    }
    let decimals = plain
        .split_once('.')
        .is_some_and(|(_, d)| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()));
    let fmt = match (percent, currency, grouped, decimals) {
        (true, _, _, true) => Some("0.00%"),
        (true, _, _, false) => Some("0%"),
        (_, true, _, _) => Some("\"$\"#,##0.00_);\\(\"$\"#,##0.00\\)"),
        (_, _, true, true) => Some("#,##0.00"),
        (_, _, true, false) => Some("#,##0"),
        _ => None,
    };
    if percent {
        v /= 100.0;
    }
    Some((v, fmt))
}

/// Excel's settings in the `<xml>` of a conditional comment: the sheet's
/// name, frozen panes, grid lines.
#[derive(Default)]
struct Options {
    names: Vec<String>,
    freeze: Option<(u32, u32)>,
    no_grid: bool,
    sources: bool,
    date1904: bool,
}

fn options(c: &str, o: &mut Options) {
    let text_of = |tag: &str| -> Vec<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut out = vec![];
        let mut rest = c;
        while let Some(p) = rest.find(&open) {
            let v = &rest[p + open.len()..];
            let e = v.find(&close).unwrap_or(v.len());
            out.push(unescape(v[..e].trim()));
            rest = &v[e..];
            if out.len() > 4096 {
                break;
            }
        }
        out
    };
    o.names.extend(text_of("x:Name"));
    if c.contains("<x:FreezePanes") {
        let n = |t: &str| {
            text_of(t)
                .first()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0)
        };
        let (r, c2) = (
            n("x:SplitHorizontal").min(MAX_ROW),
            n("x:SplitVertical").min(MAX_COL),
        );
        if r > 0 || c2 > 0 {
            o.freeze = Some((r, c2));
        }
    }
    o.no_grid |= c.contains("<x:DoNotDisplayGridlines");
    o.sources |= c.contains("<x:WorksheetSource");
    o.date1904 |= c.contains("<x:1904Date");
}

pub(crate) fn read(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    budget.alloc(bytes.len() as u64 * 6)?;
    let text = crate::formats::office::sheets::textenc::html_utf8(bytes);
    let tokens = tokenize(&text)?;
    if !tokens.iter().any(|t| matches!(t, Token::Start { name, .. } if matches!(name.as_str(), "html" | "table" | "body" | "head" | "td" | "tr"))) {
        return Err(Error::NotFormat("not an HTML document".into()));
    }

    // Style sheets and Excel's settings first: they may follow the body.
    let mut sheet_css = Sheet::default();
    let mut opts = Options::default();
    let mut frames = false;
    for (k, t) in tokens.iter().enumerate() {
        match t {
            Token::Start { name, .. } if name == "style" => {
                if let Some(Token::Text(c)) = tokens.get(k + 1) {
                    sheet_css.add(c);
                }
            }
            Token::Start { name, .. } if name == "frameset" || name == "frame" => frames = true,
            Token::Comment(c) if c.trim_start().starts_with("[if") => options(c, &mut opts),
            _ => {}
        }
    }

    // The base style: Excel's `td` and `.style0` rules over its defaults,
    // a browser's for other pages.
    let excel = tokens.iter().any(
        |t| matches!(t, Token::Start { attrs, .. } if attrs.iter().any(|a| a.0.starts_with("x:"))),
    ) || sheet_css
        .rules
        .iter()
        .any(|r| r.1.iter().any(|d| d.0.starts_with("mso-")));
    let mut base = Style {
        font: Font {
            name: if excel {
                "Arial".into()
            } else {
                "Times New Roman".into()
            },
            size_centipt: if excel { 1000 } else { 1200 },
            ..Font::default()
        },
        ..Style::default()
    };
    {
        let mut d = vec![];
        sheet_css.lookup("body", &[], &mut d);
        sheet_css.lookup("table", &[], &mut d);
        sheet_css.lookup("td", &["style0"], &mut d);
        apply(&mut base, &d, &mut HashSet::new());
        base.align.wrap = d
            .iter()
            .rev()
            .find(|x| x.0 == "white-space")
            .is_some_and(|x| matches!(x.1.trim(), "normal" | "pre-wrap"));
    }

    let blocks = build_tables(&tokens, &sheet_css, &base, budget)?;
    let tables = blocks
        .iter()
        .filter(|b| matches!(b, Block::Table(_)))
        .count();
    if tables == 0 {
        if frames || opts.sources {
            return Err(Error::Unsupported(
                "an Excel web page whose sheets are separate files".into(),
            ));
        }
        return Err(Error::NotFormat("an HTML page without tables".into()));
    }

    let mut wb = Workbook::new(base.clone());
    wb.date1904 = opts.date1904;
    // The name Excel stored; a page's title is not a sheet's name.
    let name = opts
        .names
        .first()
        .cloned()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Sheet1".into());
    let mut sheet = crate::formats::office::sheets::model::Sheet::new(
        crate::formats::office::sheets::xlsx::sheet_names(std::iter::once(name.as_str())).remove(0),
    );
    if let Some(f) = opts.freeze {
        sheet.freeze = Some(f);
    }
    if opts.no_grid {
        sheet.show_grid = false;
    }
    let digit =
        (crate::formats::office::sheets::fonts::digit_twips(&base.font.name, base.font.size_pt())
            / 15.0)
            .round()
            .max(1.0);
    // Tables and text rows one under another, from A1.
    let mut top = 0u32;
    for b in &blocks {
        if top > MAX_ROW {
            break;
        }
        let t = match b {
            Block::Table(t) => t,
            Block::Text(runs) => {
                let text = runs.text();
                if !text.is_empty() {
                    let (value, style) = match text_value(runs, &base.font, text) {
                        Value::Rich(r) if r.len() == 1 => {
                            let st = Style {
                                font: r[0].font.clone().unwrap_or_else(|| base.font.clone()),
                                ..base.clone()
                            };
                            (Value::text(r[0].text.clone()), wb.styles.add(st))
                        }
                        v => (v, 0),
                    };
                    budget.cell(value.text_len())?;
                    sheet.cells.insert(
                        (top, 0),
                        Cell {
                            value,
                            formula: None,
                            style,
                        },
                    );
                    top += 1;
                }
                continue;
            }
        };
        if let Some(cap) = &t.caption {
            let text = cap.text();
            if !text.is_empty() {
                budget.cell(text.len())?;
                sheet.cells.insert(
                    (top, 0),
                    Cell {
                        value: Value::text(text),
                        formula: None,
                        style: 0,
                    },
                );
                top = top.saturating_add(1);
            }
        }
        // Text after line breaks that start new cells, where those are free.
        let mut below: Vec<((u32, u32), Value, u32)> = vec![];
        for &(first, last, w, hidden) in &t.cols {
            if !sheet
                .cols
                .iter()
                .any(|c| c.first <= last && first <= c.last)
            {
                sheet.cols.push(ColInfo {
                    first,
                    last,
                    width: w.map(|w| w.width(digit)),
                    hidden,
                    style: None,
                    outline: 0,
                });
            }
        }
        for &(r, h, hidden) in &t.rows {
            let r = top.saturating_add(r);
            if r <= MAX_ROW && (h.is_some() || hidden) {
                sheet.rows.insert(
                    r,
                    RowInfo {
                        height: h.map(|h| h.min(409.0)),
                        custom_height: h.is_some(),
                        hidden,
                        style: None,
                        outline: 0,
                    },
                );
            }
        }
        for c in &t.cells {
            let r = top.saturating_add(c.row);
            if r > MAX_ROW || c.col > MAX_COL {
                continue;
            }
            let (value, formula, extra) = cell_value(c, t.strings, t.seps);
            let mut st = c.style.clone();
            if let Some(f) = extra {
                if st.numfmt == "General" {
                    st.numfmt = f.to_string();
                }
            }
            if c.header {
                st.font.bold = true;
                st.align.horizontal = st.align.horizontal.or(Some("center"));
            }
            if matches!(&value, Value::Text(t) if t.contains('\n')) {
                st.align.wrap = true;
            }
            let value = match value {
                // A single run in another font than the cell's: the cell's.
                Value::Rich(runs) if runs.len() == 1 => {
                    if let Some(f) = &runs[0].font {
                        st.font = f.clone();
                    }
                    Value::text(runs[0].text.clone())
                }
                v => v,
            };
            // Spans merge, but for columns Excel marks mso-ignore:colspan.
            let r2 = r.saturating_add(c.rows - 1).min(MAX_ROW);
            let c2 = if c.merge {
                c.col.saturating_add(c.cols - 1).min(MAX_COL)
            } else {
                c.col
            };
            if r2 > r || c2 > c.col {
                sheet.merges.push(Range {
                    r1: r,
                    c1: c.col,
                    r2,
                    c2,
                });
            }
            if let Some(href) = &c.link {
                let link = Hyperlink {
                    range: Range::cell(r, c.col),
                    url: (!href.starts_with('#') && safe_url(href)).then(|| href.clone()),
                    location: href.strip_prefix('#').map(str::to_string),
                    tooltip: None,
                    display: None,
                };
                if link.url.is_some() || link.location.is_some() {
                    sheet.hyperlinks.push(link);
                }
            }
            let style = wb.styles.add(st);
            for (k, runs) in c.below.iter().enumerate() {
                let text = runs.text();
                let rr = r.saturating_add(k as u32 + 1);
                if !text.is_empty() && rr <= MAX_ROW {
                    below.push(((rr, c.col), Value::text(text), style));
                }
            }
            // An unmerged run of cells (mso-ignore:colspan): each formatted.
            if !c.merge && c.cols > 1 && style != 0 {
                for dc in 1..c.cols.min(MAX_COL - c.col + 1) {
                    if let std::collections::btree_map::Entry::Vacant(e) =
                        sheet.cells.entry((r, c.col + dc))
                    {
                        budget.cell(0)?;
                        e.insert(Cell::styled(style));
                    }
                }
            }
            if matches!(value, Value::Empty) && formula.is_none() && style == 0 {
                continue;
            }
            budget.cell(value.text_len() + formula.as_ref().map_or(0, |f| f.len()))?;
            sheet.cells.insert(
                (r, c.col),
                Cell {
                    value,
                    formula,
                    style,
                },
            );
        }
        let mut grown = top.saturating_add(t.height);
        for (at, value, style) in below {
            if sheet.cells.get(&at).is_none_or(|c| c.value == Value::Empty) {
                budget.cell(value.text_len())?;
                sheet.cells.insert(
                    at,
                    Cell {
                        value,
                        formula: None,
                        style,
                    },
                );
                grown = grown.max(at.0 + 1);
            }
        }
        top = grown;
    }
    if tokens.iter().any(|t| match t {
        Token::Start { name, .. } => name == "img",
        // Excel's pictures, in VML for Office alone.
        Token::Comment(c) => c.contains("v:imagedata"),
        _ => false,
    }) {
        wb.warn("pictures are not converted");
    }
    wb.sheets.push(sheet);
    Ok(wb)
}

/// A column's width as a page gives it.
#[derive(Clone, Copy)]
enum Width {
    /// `mso-width-alt`: 1/256 of the default font's digit, padding in,
    /// as XLSX counts widths.
    Alt(f64),
    Pt(f64),
}

impl Width {
    fn width(self, digit: f64) -> f64 {
        match self {
            Width::Alt(w) => (w / 256.0).clamp(0.0, 255.0),
            Width::Pt(pt) => crate::formats::office::sheets::xmlss::width_chars(pt, digit),
        }
    }
}

/// A cell's value and formula from its text and Excel's attributes, and
/// the format a number read from its text implies.
fn cell_value(
    c: &CellOut,
    strings: bool,
    seps: (char, char),
) -> (Value, Option<Box<str>>, Option<&'static str>) {
    let text = c.runs.text();
    let formula = get(&c.attrs, "x:fmla")
        .map(|f| f.trim().trim_start_matches('=').to_string())
        .filter(|f| !f.is_empty())
        .map(String::into_boxed_str);
    if let Some(b) = get(&c.attrs, "x:bool") {
        let v = if b.is_empty() { text.as_str() } else { b };
        return (
            Value::Bool(v.eq_ignore_ascii_case("true") || v == "1"),
            formula,
            None,
        );
    }
    if let Some(e) = get(&c.attrs, "x:err") {
        let v = if e.is_empty() { text.as_str() } else { e };
        return (
            Value::Error(CellError::parse(v).unwrap_or(CellError::Value)),
            formula,
            None,
        );
    }
    if let Some(n) = get(&c.attrs, "x:num") {
        if let Ok(v) = n.trim().parse::<f64>() {
            if v.is_finite() {
                return (Value::Number(v), formula, None);
            }
        }
        if let Some((v, f)) = parse_number(&text, seps) {
            return (Value::Number(v), formula, f);
        }
    }
    if let Some(s) = get(&c.attrs, "x:str") {
        if !s.is_empty() {
            // The value with the apostrophe that forces text in Excel.
            return (
                Value::text(s.strip_prefix('\'').unwrap_or(s)),
                formula,
                None,
            );
        }
        return (text_value(&c.runs, &c.style.font, text), formula, None);
    }
    if text.is_empty() {
        return (Value::Empty, formula, None);
    }
    if !strings && c.style.numfmt != "@" {
        if let Some((v, f)) = parse_number(&text, seps) {
            return (Value::Number(v), formula, f);
        }
    }
    (text_value(&c.runs, &c.style.font, text), formula, None)
}

fn text_value(r: &Runs, font: &Font, text: String) -> Value {
    let mut runs: Vec<Run> = r
        .runs
        .iter()
        .filter(|r| !r.text.is_empty())
        .cloned()
        .collect();
    if runs.len() > 1 {
        // The text trimmed as `text` is.
        if let Some(f) = runs.first_mut() {
            f.text = f.text.trim_start_matches([' ', '\n']).to_string();
        }
        if let Some(l) = runs.last_mut() {
            l.text = l.text.trim_end_matches([' ', '\n']).to_string();
        }
        runs.retain(|r| !r.text.is_empty());
        if runs.len() > 1 && runs.windows(2).any(|w| w[0].font != w[1].font) {
            return Value::Rich(runs.into());
        }
    }
    if runs.len() == 1 && runs[0].font.as_ref() != Some(font) {
        return Value::Rich(
            vec![Run {
                text,
                font: runs[0].font.clone(),
            }]
            .into(),
        );
    }
    Value::text(text)
}

/// The element names that end a cell, a row or a table when they start.
const CELL_ENDERS: &[&str] = &["td", "th", "tr", "tbody", "thead", "tfoot"];

struct Open {
    table: Table,
    /// Cells taken by row spans: (row, col) to the row they free after.
    taken: HashSet<(u32, u32)>,
    row: Option<u32>,
    next_row: u32,
    col: u32,
    row_style: Vec<(String, String)>,
    cell: Option<CellOut>,
    /// Columns described so far by `<col>`.
    col_cursor: u32,
    /// Inside the table's `<caption>`.
    in_caption: bool,
}

/// Elements whose content is not data: scripts, frames, the head's title
/// and styles (read apart). The tokenizer closes each of them.
const SKIPPED: &[&str] = &[
    "script", "noscript", "iframe", "noframes", "noembed", "title", "style", "textarea", "xmp",
];

/// Elements that start a new line of text.
const BLOCKS: &[&str] = &[
    "p",
    "div",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "dl",
    "dt",
    "dd",
    "pre",
    "blockquote",
    "hr",
    "address",
    "center",
    "form",
    "fieldset",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "aside",
    "body",
    "caption",
];

fn flush_text(loose: &mut Runs, done: &mut Vec<Block>) {
    if !loose.text().is_empty() && done.len() < 1 << 20 {
        done.push(Block::Text(std::mem::replace(
            loose,
            Runs {
                space: true,
                ..Runs::default()
            },
        )));
    } else {
        *loose = Runs {
            space: true,
            ..Runs::default()
        };
    }
}

fn build_tables(
    tokens: &[Token],
    css_sheet: &Sheet,
    base: &Style,
    budget: &mut Budget,
) -> Result<Vec<Block>> {
    let mut done: Vec<Block> = vec![];
    let mut stack: Vec<Open> = vec![];
    // The font of inline formatting inside the current cell, or of the
    // text outside tables.
    let mut fonts: Vec<(String, Font)> = vec![];
    let mut loose = Runs {
        space: true,
        ..Runs::default()
    };
    let mut link: Option<String> = None;
    let mut pre = 0u32;
    let mut skip = 0u32;
    // Excel's comment lists, after the table: `div`s nested in one.
    let mut comment_divs = 0u32;
    for t in tokens {
        match t {
            Token::Start {
                name,
                attrs,
                closed,
            } => {
                let n = name.as_str();
                if SKIPPED.contains(&n) && !closed {
                    skip += 1;
                    continue;
                }
                if skip > 0 {
                    continue;
                }
                if comment_divs > 0 {
                    if n == "div" && !closed {
                        comment_divs += 1;
                    }
                    continue;
                }
                if n == "div"
                    && get(attrs, "style").is_some_and(|s| s.contains("mso-element:comment"))
                    && !closed
                {
                    comment_divs = 1;
                    continue;
                }
                if stack.is_empty() && BLOCKS.contains(&n) {
                    flush_text(&mut loose, &mut done);
                }
                if stack.is_empty() && n == "br" {
                    flush_text(&mut loose, &mut done);
                }
                if fonts.is_empty() && stack.last().is_none_or(|o| o.cell.is_none()) {
                    fonts.push((String::new(), base.font.clone()));
                }
                match n {
                    "table" => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(Error::Malformed("tables nested too deep".into()));
                        }
                        if stack.is_empty() {
                            flush_text(&mut loose, &mut done);
                        }
                        let strings = get(attrs, "x:str").is_some();
                        let mut d = vec![];
                        css_sheet.lookup("table", &classes(attrs), &mut d);
                        if let Some(s) = get(attrs, "style") {
                            d.extend(css::declarations(s));
                        }
                        let seps = separators(&d);
                        let ruled = get(attrs, "border").is_some_and(|b| {
                            b.trim().is_empty() || b.trim().parse::<f64>().is_ok_and(|w| w > 0.0)
                        });
                        stack.push(Open {
                            table: Table {
                                strings,
                                seps,
                                ruled,
                                ..Table::default()
                            },
                            taken: HashSet::new(),
                            row: None,
                            next_row: 0,
                            col: 0,
                            row_style: vec![],
                            cell: None,
                            col_cursor: 0,
                            in_caption: false,
                        });
                    }
                    "caption" => {
                        if let Some(o) = stack.last_mut() {
                            finish_cell(o, &mut fonts, &mut link, budget)?;
                            o.in_caption = true;
                            o.table.caption.get_or_insert(Runs {
                                space: true,
                                ..Runs::default()
                            });
                            fonts.push((String::new(), base.font.clone()));
                        }
                    }
                    "col" if stack.last().is_some_and(|o| o.row.is_none()) => {
                        let o = stack.last_mut().unwrap_or_else(|| unreachable!());
                        let span = get(attrs, "span")
                            .and_then(|s| s.trim().parse::<u32>().ok())
                            .unwrap_or(1)
                            .clamp(1, MAX_COL + 1);
                        let mut d = vec![];
                        if let Some(s) = get(attrs, "style") {
                            d = css::declarations(s);
                        }
                        // Excel's own width unit first, then its `width`
                        // attribute (whole pixels), then the CSS width
                        // (those pixels rounded to points).
                        let alt = d
                            .iter()
                            .rev()
                            .find(|x| x.0 == "mso-width-alt")
                            .and_then(|x| x.1.trim().parse::<f64>().ok())
                            .filter(|v| v.is_finite() && *v >= 0.0);
                        let w = alt.map(Width::Alt).or_else(|| {
                            get(attrs, "width")
                                .and_then(|w| css::length_pt(w, "px"))
                                .or_else(|| {
                                    d.iter()
                                        .rev()
                                        .find(|x| x.0 == "width")
                                        .and_then(|x| css::length_pt(&x.1, "px"))
                                })
                                .filter(|w| *w >= 0.0)
                                .map(Width::Pt)
                        });
                        let hidden = d.iter().any(|x| x.0 == "display" && x.1.trim() == "none");
                        let first = o.col_cursor.min(MAX_COL);
                        let last = o.col_cursor.saturating_add(span - 1).min(MAX_COL);
                        o.col_cursor = last.saturating_add(1);
                        if (w.is_some() || hidden) && o.table.cols.len() < 1 << 14 {
                            o.table.cols.push((first, last, w, hidden));
                        }
                    }
                    "tr" => {
                        let Some(o) = stack.last_mut() else { continue };
                        finish_cell(o, &mut fonts, &mut link, budget)?;
                        let r = o.next_row;
                        o.row = Some(r);
                        o.col = 0;
                        let mut d = vec![];
                        css_sheet.lookup("tr", &classes(attrs), &mut d);
                        if let Some(s) = get(attrs, "style") {
                            d.extend(css::declarations(s));
                        }
                        // One row for several empty ones, its height theirs.
                        let n = d
                            .iter()
                            .rev()
                            .find(|x| x.0 == "mso-xlrowspan")
                            .and_then(|x| x.1.trim().parse::<u32>().ok())
                            .unwrap_or(1)
                            .clamp(1, 1 << 20);
                        o.next_row = r.saturating_add(n);
                        let h = d
                            .iter()
                            .rev()
                            .find(|x| x.0 == "height")
                            .and_then(|x| css::length_pt(&x.1, "px"))
                            .or_else(|| get(attrs, "height").and_then(|h| css::length_pt(h, "px")))
                            .map(|h| h / f64::from(n));
                        let hidden = d.iter().any(|x| x.0 == "display" && x.1.trim() == "none");
                        if (h.is_some() || hidden) && o.table.rows.len() < 1 << 20 {
                            budget.alloc(32 * u64::from(n))?;
                            for k in 0..n {
                                o.table.rows.push((r.saturating_add(k), h, hidden));
                            }
                        }
                        o.table.height = o.table.height.max(o.next_row);
                        o.row_style = d
                            .into_iter()
                            .filter(|x| x.0 != "height" && x.0 != "display")
                            .collect();
                        if let Some(a) = get(attrs, "align") {
                            o.row_style.push(("text-align".into(), a.to_string()));
                        }
                        if let Some(a) = get(attrs, "valign") {
                            o.row_style.push(("vertical-align".into(), a.to_string()));
                        }
                    }
                    "td" | "th" => {
                        let Some(o) = stack.last_mut() else { continue };
                        finish_cell(o, &mut fonts, &mut link, budget)?;
                        let r = match o.row {
                            Some(r) => r,
                            None => {
                                let r = o.next_row;
                                o.row = Some(r);
                                o.next_row = r.saturating_add(1);
                                o.col = 0;
                                r
                            }
                        };
                        let mut c = o.col;
                        while o.taken.contains(&(r, c)) && c < MAX_COL {
                            c += 1;
                        }
                        let span = |k: &str| {
                            get(attrs, k)
                                .and_then(|s| s.trim().parse::<u32>().ok())
                                .unwrap_or(1)
                                .clamp(1, 65_534)
                        };
                        let (rows, cols) = (span("rowspan"), span("colspan"));
                        // The cell's style: the sheet's rules, the row's,
                        // the element's attributes, its own style.
                        let mut d = vec![];
                        css_sheet.lookup(n, &classes(attrs), &mut d);
                        let mut own = o.row_style.clone();
                        // Office ignores `bgcolor`.
                        for (attr, prop) in [("align", "text-align"), ("valign", "vertical-align")]
                        {
                            if let Some(v) = get(attrs, attr) {
                                own.push((prop.into(), v.to_string()));
                            }
                        }
                        if get(attrs, "nowrap").is_some() {
                            own.push(("white-space".into(), "nowrap".into()));
                        }
                        d.splice(0..0, own);
                        if let Some(s) = get(attrs, "style") {
                            d.extend(css::declarations(s));
                        }
                        let mut st = base.clone();
                        if o.table.ruled {
                            let thin = Edge {
                                style: Some("thin"),
                                color: None,
                            };
                            st.border = Border {
                                top: thin.clone(),
                                right: thin.clone(),
                                bottom: thin.clone(),
                                left: thin,
                                ..Border::default()
                            };
                        }
                        let mut ignore = HashSet::new();
                        apply(&mut st, &d, &mut ignore);
                        let merge_cols = !ignore.contains("colspan");
                        let merge_rows = !ignore.contains("rowspan");
                        let (rows, cols) = (if merge_rows { rows } else { 1 }, cols);
                        // The columns a row-spanning cell takes below.
                        if rows > 1 {
                            budget.alloc(u64::from(rows) * u64::from(cols) * 16)?;
                            for dr in 1..rows {
                                for dc in 0..cols {
                                    o.taken.insert((r.saturating_add(dr), c.saturating_add(dc)));
                                }
                            }
                        }
                        o.col = c.saturating_add(cols);
                        o.table.height = o.table.height.max(r.saturating_add(rows));
                        fonts.clear();
                        fonts.push((String::new(), st.font.clone()));
                        o.in_caption = false;
                        o.cell = Some(CellOut {
                            row: r,
                            col: c,
                            rows,
                            cols,
                            merge: merge_cols,
                            style: st,
                            runs: Runs {
                                space: true,
                                ..Runs::default()
                            },
                            attrs: attrs.clone(),
                            link: None,
                            header: n == "th" && !excel_cell(attrs),
                            below: vec![],
                        });
                    }
                    "br" => {
                        // In the cell (`mso-data-placement:same-cell`, which
                        // Excel's style sheets set for all), else the start
                        // of a new cell a row down.
                        let mut d = vec![];
                        css_sheet.lookup("br", &classes(attrs), &mut d);
                        if let Some(s) = get(attrs, "style") {
                            d.extend(css::declarations(s));
                        }
                        let same = d
                            .iter()
                            .rev()
                            .find(|x| x.0 == "mso-data-placement")
                            .is_some_and(|x| x.1.trim() == "same-cell");
                        if let (Some(o), Some((_, f))) = (stack.last_mut(), fonts.last()) {
                            if let Some(cell) = &mut o.cell {
                                if same || cell.below.len() >= 1024 {
                                    cell.runs.newline(f);
                                } else {
                                    cell.below.push(Runs {
                                        space: true,
                                        ..Runs::default()
                                    });
                                }
                            }
                        }
                    }
                    "p" | "div" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                        if let (Some(o), Some((_, f))) = (stack.last_mut(), fonts.last()) {
                            if let Some(cell) = &mut o.cell {
                                if cell.runs.len > 0 {
                                    cell.runs.newline(f);
                                }
                            }
                        }
                        if n.starts_with('h') {
                            push_font(&mut fonts, n, |f| f.bold = true);
                        }
                    }
                    "pre" => pre += 1,
                    "b" | "strong" => push_font(&mut fonts, n, |f| f.bold = true),
                    "i" | "em" | "cite" | "var" => push_font(&mut fonts, n, |f| f.italic = true),
                    "u" | "ins" => push_font(&mut fonts, n, |f| f.underline = Some("single")),
                    "s" | "strike" | "del" => push_font(&mut fonts, n, |f| f.strike = true),
                    "sub" => push_font(&mut fonts, n, |f| f.vert_align = Some("subscript")),
                    "sup" => push_font(&mut fonts, n, |f| f.vert_align = Some("superscript")),
                    "font" | "span" | "a" => {
                        let style_decls: Vec<(String, String)> = get(attrs, "style")
                            .map(css::declarations)
                            .unwrap_or_default();
                        let color = get(attrs, "color").map(str::to_string);
                        let face = get(attrs, "face").map(str::to_string);
                        let size = get(attrs, "size").and_then(|s| s.trim().parse::<i32>().ok());
                        let class_decls = {
                            let mut d = vec![];
                            css_sheet.lookup(n, &classes(attrs), &mut d);
                            d
                        };
                        if n == "a" {
                            if let Some(h) = get(attrs, "href") {
                                link = Some(h.trim().to_string());
                            }
                        }
                        if !closed {
                            push_font(&mut fonts, n, |f| {
                                let mut st = Style {
                                    font: f.clone(),
                                    ..Style::default()
                                };
                                apply(&mut st, &class_decls, &mut HashSet::new());
                                apply(&mut st, &style_decls, &mut HashSet::new());
                                *f = st.font;
                                if let Some(c) = color.as_deref().and_then(css::color) {
                                    f.color = c.filter(|&c| c != 0);
                                }
                                if let Some(face) = &face {
                                    if let Some(first) = face
                                        .split(',')
                                        .next()
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                    {
                                        f.name = first.chars().take(64).collect();
                                    }
                                }
                                if let Some(s) = size {
                                    // HTML's font sizes 1 to 7.
                                    const PT: [u32; 7] = [750, 1000, 1200, 1350, 1800, 2400, 3600];
                                    f.size_centipt = PT[(s.clamp(1, 7) - 1) as usize];
                                }
                            });
                        }
                    }
                    _ => {}
                }
            }
            Token::End(name) => {
                let n = name.as_str();
                if SKIPPED.contains(&n) {
                    skip = skip.saturating_sub(1);
                    continue;
                }
                if skip > 0 {
                    continue;
                }
                if comment_divs > 0 {
                    if n == "div" {
                        comment_divs -= 1;
                    }
                    continue;
                }
                if stack.is_empty() && BLOCKS.contains(&n) {
                    flush_text(&mut loose, &mut done);
                }
                match n {
                    "table" => {
                        if let Some(mut o) = stack.pop() {
                            finish_cell(&mut o, &mut fonts, &mut link, budget)?;
                            match stack.last_mut().and_then(|p| p.cell.as_mut()) {
                                // A table in a cell: its text, row by row.
                                Some(cell) => {
                                    let f = cell.style.font.clone();
                                    let mut rows: Vec<&CellOut> = o.table.cells.iter().collect();
                                    rows.sort_by_key(|c| (c.row, c.col));
                                    let mut last = None;
                                    for c in rows {
                                        if last.is_some() && last != Some(c.row) {
                                            cell.runs.newline(&f);
                                        } else if last.is_some() {
                                            cell.runs.push(" ", &f, false);
                                        }
                                        cell.runs.push(&c.runs.text(), &f, false);
                                        last = Some(c.row);
                                    }
                                }
                                None => done.push(Block::Table(o.table)),
                            }
                        }
                    }
                    "td" | "th" | "tr" => {
                        if let Some(o) = stack.last_mut() {
                            finish_cell(o, &mut fonts, &mut link, budget)?;
                            if n == "tr" {
                                o.row = None;
                            }
                        }
                    }
                    "caption" => {
                        if let Some(o) = stack.last_mut() {
                            o.in_caption = false;
                        }
                    }
                    "pre" => pre = pre.saturating_sub(1),
                    "a" => {
                        pop_font(&mut fonts, n);
                    }
                    "p" | "div" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "b"
                    | "strong" | "i" | "em" | "cite" | "var" | "u" | "ins" | "s" | "strike"
                    | "del" | "sub" | "sup" | "font" | "span" => {
                        pop_font(&mut fonts, n);
                    }
                    _ if CELL_ENDERS.contains(&n) => {}
                    _ => {}
                }
            }
            Token::Text(s) => {
                if skip > 0 || comment_divs > 0 {
                    continue;
                }
                if stack.is_empty() {
                    if fonts.is_empty() {
                        fonts.push((String::new(), base.font.clone()));
                    }
                    if let Some((_, f)) = fonts.last() {
                        loose.push(s, f, pre > 0);
                    }
                    continue;
                }
                if let (Some(o), Some((_, f))) = (stack.last_mut(), fonts.last()) {
                    if let Some(cell) = &mut o.cell {
                        if let Some(l) = link.take() {
                            cell.link.get_or_insert(l);
                        }
                        match cell.below.last_mut() {
                            Some(b) => b.push(s, f, pre > 0),
                            None => cell.runs.push(s, f, pre > 0),
                        }
                    } else if o.in_caption {
                        if let Some(c) = &mut o.table.caption {
                            c.push(s, f, pre > 0);
                        }
                    }
                }
            }
            Token::Comment(_) => {}
        }
    }
    // Tables left open at the end.
    while let Some(mut o) = stack.pop() {
        finish_cell(&mut o, &mut fonts, &mut link, budget)?;
        if stack.is_empty() {
            done.push(Block::Table(o.table));
        }
    }
    flush_text(&mut loose, &mut done);
    Ok(done)
}

/// Whether a cell carries Excel's attributes: its `th` is then no header.
fn excel_cell(attrs: &[(String, String)]) -> bool {
    attrs.iter().any(|a| a.0.starts_with("x:"))
}

fn classes(attrs: &[(String, String)]) -> Vec<&str> {
    get(attrs, "class")
        .map(|c| c.split_whitespace().take(16).collect())
        .unwrap_or_default()
}

fn push_font(fonts: &mut Vec<(String, Font)>, tag: &str, f: impl FnOnce(&mut Font)) {
    if fonts.is_empty() || fonts.len() > MAX_DEPTH {
        return;
    }
    let mut font = fonts.last().map(|x| x.1.clone()).unwrap_or_default();
    f(&mut font);
    fonts.push((tag.to_string(), font));
}

fn pop_font(fonts: &mut Vec<(String, Font)>, tag: &str) {
    if let Some(p) = fonts.iter().rposition(|x| x.0 == tag) {
        if p > 0 {
            fonts.truncate(p);
        }
    }
}

fn finish_cell(
    o: &mut Open,
    fonts: &mut Vec<(String, Font)>,
    link: &mut Option<String>,
    budget: &mut Budget,
) -> Result<()> {
    if let Some(cell) = o.cell.take() {
        if o.table.cells.len() >= 1 << 22 {
            return Err(Error::TooLarge("cells"));
        }
        budget.alloc(cell.runs.len as u64 + 256)?;
        o.table.cells.push(cell);
    }
    fonts.clear();
    *link = None;
    Ok(())
}

#[cfg(test)]
mod tests;
