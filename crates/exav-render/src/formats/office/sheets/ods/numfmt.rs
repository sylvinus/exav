//! ODF data styles (number:*-style) to Excel number format codes.

use crate::formats::office::common::xml::Node;
use std::collections::HashMap;

/// Windows language identifiers of currency symbols' locales, as Excel
/// writes them in `[$€-407]`.
fn lcid(lang: Option<&str>, country: Option<&str>) -> Option<u32> {
    let l = lang?.to_ascii_lowercase();
    let c = country.unwrap_or("").to_ascii_uppercase();
    Some(match (l.as_str(), c.as_str()) {
        ("en", "US") => 0x409,
        ("en", "GB") => 0x809,
        ("en", "AU") => 0xC09,
        ("en", "CA") => 0x1009,
        ("en", "IN") => 0x4009,
        ("en", "IE") => 0x1809,
        ("de", "DE") => 0x407,
        ("de", "AT") => 0xC07,
        ("de", "CH") => 0x807,
        ("fr", "FR") => 0x40C,
        ("fr", "BE") => 0x80C,
        ("fr", "CH") => 0x100C,
        ("fr", "CA") => 0xC0C,
        ("es", "ES") => 0xC0A,
        ("es", "MX") => 0x80A,
        ("it", "IT") => 0x410,
        ("nl", "NL") => 0x413,
        ("nl", "BE") => 0x813,
        ("pt", "BR") => 0x416,
        ("pt", "PT") => 0x816,
        ("pl", "PL") => 0x415,
        ("cs", "CZ") => 0x405,
        ("hu", "HU") => 0x40E,
        ("sk", "SK") => 0x41B,
        ("sl", "SI") => 0x424,
        ("ru", "RU") => 0x419,
        ("ja", "JP") => 0x411,
        ("zh", "CN") => 0x804,
        ("zh", "TW") => 0x404,
        ("ko", "KR") => 0x412,
        ("sv", "SE") => 0x41D,
        ("da", "DK") => 0x406,
        ("fi", "FI") => 0x40B,
        ("nb", "NO") | ("no", "NO") => 0x414,
        ("tr", "TR") => 0x41F,
        ("el", "GR") => 0x408,
        ("ga", "IE") => 0x83C,
        _ => return None,
    })
}

/// A literal in a format code: single safe characters bare or escaped,
/// others quoted.
fn lit(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    if s.chars()
        .all(|c| matches!(c, '-' | '/' | ':' | '.' | ' ' | '(' | ')' | '$' | '+'))
    {
        return s
            .chars()
            .map(|c| {
                if c == ' ' || c == '-' {
                    format!("\\{c}")
                } else {
                    c.to_string()
                }
            })
            .collect();
    }
    if s.chars().count() == 1 {
        return format!("\\{s}");
    }
    format!("\"{}\"", s.replace('"', "\\\""))
}

fn usize_attr(n: &Node, k: &str) -> Option<usize> {
    n.attr(k)
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.min(30))
}

fn number_part(n: &Node, fraction: bool) -> String {
    let dec = usize_attr(n, "number:decimal-places").unwrap_or(0);
    let min_dec = usize_attr(n, "number:min-decimal-places")
        .or_else(|| usize_attr(n, "loext:min-decimal-places"))
        .unwrap_or(dec);
    let min_int =
        usize_attr(n, "number:min-integer-digits").unwrap_or(if fraction { 0 } else { 1 });
    let grouping = n.attr("number:grouping") == Some("true");
    let mut s = if grouping {
        let width = min_int.max(4);
        let mut s = String::new();
        for i in 0..width {
            if i > 0 && (width - i).is_multiple_of(3) {
                s.push(',');
            }
            s.push(if i >= width - min_int { '0' } else { '#' });
        }
        s
    } else if min_int == 0 {
        "#".to_string()
    } else {
        "0".repeat(min_int)
    };
    if dec > 0 {
        s.push('.');
        s += &"0".repeat(min_dec.min(dec));
        s += &"#".repeat(dec.saturating_sub(min_dec));
    }
    if let Some(f) = n
        .attr("number:display-factor")
        .and_then(|v| v.parse::<f64>().ok())
    {
        let mut k = f;
        let mut guard = 0;
        while k >= 1000.0 && guard < 10 {
            s.push(',');
            k /= 1000.0;
            guard += 1;
        }
    }
    s
}

fn text(n: &Node) -> String {
    n.own_text()
}

/// The format code of a data style's own section, without its maps.
fn section(st: &Node) -> String {
    let mut out = String::new();
    if let Some(c) = st
        .child("style:text-properties")
        .and_then(|tp| tp.attr("fo:color"))
    {
        out += match c.to_ascii_lowercase().as_str() {
            "#ff0000" => "[RED]",
            "#0000ff" => "[BLUE]",
            "#00ff00" => "[GREEN]",
            "#000000" => "[BLACK]",
            "#ffffff" => "[WHITE]",
            "#ffff00" => "[YELLOW]",
            "#ff00ff" => "[MAGENTA]",
            "#00ffff" => "[CYAN]",
            _ => "",
        };
    }
    let kind = st.name.as_str();
    let is_time = kind == "number:time-style";
    let overflow = st.attr("number:truncate-on-overflow") == Some("false");
    let mut first_time_unit = true;
    let parts = st
        .nodes()
        .filter(|x| x.name != "style:text-properties" && x.name != "style:map")
        .count();
    for n in st.nodes() {
        match n.name.as_str() {
            // A bare number without decimals is General.
            "number:number"
                if kind == "number:number-style"
                    && n.attr("number:decimal-places").is_none()
                    && n.attr("number:grouping") != Some("true")
                    && n.attr("number:min-integer-digits").is_none_or(|v| v == "1")
                    && parts == 1 =>
            {
                out += "General"
            }
            "number:number" => out += &number_part(n, false),
            "number:scientific-number" => {
                out += &number_part(n, false);
                out += "E+";
                out += &"0".repeat(usize_attr(n, "number:min-exponent-digits").unwrap_or(2));
            }
            "number:fraction" => {
                let num = usize_attr(n, "number:min-numerator-digits").unwrap_or(1);
                let den = usize_attr(n, "number:min-denominator-digits").unwrap_or(1);
                if let Some(m) = usize_attr(n, "number:min-integer-digits") {
                    out += if m == 0 { "#" } else { "0" };
                    out.push(' ');
                }
                out += &"?".repeat(num);
                out.push('/');
                match n.attr("number:denominator-value") {
                    Some(d) if d.chars().all(|c| c.is_ascii_digit()) && d.len() < 10 => out += d,
                    _ => out += &"?".repeat(den),
                }
            }
            "number:currency-symbol" => {
                let sym = text(n);
                match lcid(n.attr("number:language"), n.attr("number:country")) {
                    Some(id) => out += &format!("[${}-{:X}]", sym, id),
                    None => out += &lit(&sym),
                }
            }
            "number:text" | "loext:text" => {
                let t = text(n);
                // A percentage's sign scales the value: it stays bare.
                if kind == "number:percentage-style" && t.contains('%') {
                    let (a, b) = t.split_once('%').unwrap_or((&t, ""));
                    out += &lit(a);
                    out.push('%');
                    out += &lit(b);
                } else {
                    out += &lit(&t);
                }
            }
            "number:text-content" => out.push('@'),
            "number:fill-character" | "loext:fill-character" => {
                out.push('*');
                out.push(text(n).chars().next().unwrap_or(' '));
            }
            "number:day" => {
                out += if n.attr("number:style") == Some("long") {
                    "dd"
                } else {
                    "d"
                }
            }
            "number:month" => {
                let long = n.attr("number:style") == Some("long");
                out += match (n.attr("number:textual") == Some("true"), long) {
                    (true, true) => "mmmm",
                    (true, false) => "mmm",
                    (false, true) => "mm",
                    _ => "m",
                }
            }
            "number:year" => {
                out += if n.attr("number:style") == Some("long") {
                    "yyyy"
                } else {
                    "yy"
                }
            }
            "number:day-of-week" => {
                out += if n.attr("number:style") == Some("long") {
                    "dddd"
                } else {
                    "ddd"
                }
            }
            "number:era" => {
                out += if n.attr("number:style") == Some("long") {
                    "gggg"
                } else {
                    "g"
                }
            }
            "number:quarter" => {
                out += if n.attr("number:style") == Some("long") {
                    "\"Q\"Q"
                } else {
                    "Q"
                }
            }
            "number:week-of-year" => out += "WW",
            "number:hours" | "number:minutes" => {
                let long = n.attr("number:style") == Some("long");
                let unit = match (n.name.as_str(), long) {
                    ("number:hours", true) => "hh",
                    ("number:hours", false) => "h",
                    (_, true) => "mm",
                    _ => "m",
                };
                if is_time && overflow && first_time_unit {
                    out += &format!("[{unit}]");
                } else {
                    out += unit;
                }
                first_time_unit = false;
            }
            "number:seconds" => {
                out += if n.attr("number:style") == Some("long") {
                    "ss"
                } else {
                    "s"
                };
                let d = usize_attr(n, "number:decimal-places").unwrap_or(0);
                if d > 0 {
                    out.push('.');
                    out += &"0".repeat(d);
                }
                first_time_unit = false;
            }
            "number:am-pm" => out += "AM/PM",
            "number:boolean" => out += "\"TRUE\";\"TRUE\";\"FALSE\"",
            _ => {}
        }
    }
    if kind == "number:percentage-style" && !out.contains('%') {
        out.push('%');
    }
    if kind == "number:text-style" && !out.contains('@') {
        out.push('@');
    }
    out
}

/// Every data style of a document, by name, as a format code.
pub fn collect(roots: &[&Node]) -> HashMap<String, String> {
    let mut raw: HashMap<String, &Node> = HashMap::new();
    for r in roots {
        for n in r.nodes() {
            if n.name.starts_with("number:")
                && n.name.ends_with("-style")
                && let Some(name) = n.attr("style:name")
            {
                raw.insert(name.to_string(), n);
            }
        }
    }
    raw.iter()
        .map(|(name, n)| (name.clone(), code(n, &raw, 0)))
        .collect()
}

fn code(n: &Node, raw: &HashMap<String, &Node>, depth: u32) -> String {
    let own = section(n);
    let own = if own.is_empty() {
        "General".to_string()
    } else {
        own
    };
    let maps: Vec<(&str, &str)> = n
        .all("style:map")
        .filter_map(|m| {
            Some((
                m.attr("style:condition")?,
                m.attr("style:apply-style-name")?,
            ))
        })
        .collect();
    if maps.is_empty() || depth > 3 {
        return own;
    }
    // Maps on the sign are Excel's positive, negative and zero sections;
    // other conditions keep their brackets.
    let (mut pos, mut neg, mut zero, mut custom) = (None, None, None, vec![]);
    for (cond, target) in maps.iter().take(3) {
        let Some(t) = raw.get(*target) else { continue };
        let c = code(t, raw, depth + 1);
        match cond.replace("value()", "").replace(' ', "").as_str() {
            ">0" | ">=0" => pos = Some(c),
            "<0" => neg = Some(c),
            "=0" => zero = Some(c),
            other => custom.push(format!("[{other}]{c}")),
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if custom.is_empty() {
        match (pos, neg, zero) {
            (Some(p), Some(n), Some(z)) => parts.extend([p, n, z, own]),
            (Some(p), Some(n), None) => parts.extend([p, n, own]),
            (Some(p), None, Some(z)) => parts.extend([p, own.clone(), z]),
            (Some(p), None, None) => parts.extend([p, own]),
            (None, Some(n), z) => {
                parts.extend([own.clone(), n]);
                parts.extend(z);
            }
            (None, None, Some(z)) => parts.extend([own.clone(), own, z]),
            (None, None, None) => parts.push(own),
        }
    } else {
        parts.extend(custom);
        parts.push(own);
    }
    parts.join(";")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::common::xml::{parse, within};

    fn fmt(xml: &str) -> String {
        let doc = parse(format!(r#"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0">{xml}</office:styles>"#).as_bytes(), &mut within(1 << 20)).unwrap();
        collect(&[&doc]).remove("N1").unwrap()
    }

    #[test]
    fn formats() {
        assert_eq!(
            fmt(
                r#"<number:number-style style:name="N1"><number:number number:decimal-places="2" number:min-integer-digits="1" number:grouping="true"/></number:number-style>"#
            ),
            "#,##0.00"
        );
        assert_eq!(
            fmt(
                r#"<number:date-style style:name="N1"><number:day number:style="long"/><number:text>.</number:text><number:month number:style="long"/><number:text>.</number:text><number:year/></number:date-style>"#
            ),
            "dd.mm.yy"
        );
        assert_eq!(
            fmt(
                r#"<number:time-style style:name="N1" number:truncate-on-overflow="false"><number:hours/><number:text>:</number:text><number:minutes number:style="long"/></number:time-style>"#
            ),
            "[h]:mm"
        );
        assert_eq!(
            fmt(
                r#"<number:percentage-style style:name="N1"><number:number number:decimal-places="1" number:min-integer-digits="1"/><number:text>%</number:text></number:percentage-style>"#
            ),
            "0.0%"
        );
    }
}
