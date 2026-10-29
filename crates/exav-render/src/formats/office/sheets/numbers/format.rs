//! Numbers cell formats (TSK.FormatStructArchive) to XLSX format codes.
//!
//! FormatStructArchive fields: format_type 1, decimal_places 2 (253 for
//! automatic), currency_code 3, negative_style 4 (0 minus, 1 red, 2
//! parentheses, 3 red parentheses), show_thousands_separator 5,
//! use_accounting_style 6, duration_style 7 (0 compact, 1 short, 2 long),
//! base 8, base_places 9, fraction_accuracy 11, date_time_format 14 (an
//! ICU pattern),
//! duration_unit_largest 15 and duration_unit_smallest 16 (1 week, 2 day,
//! 4 hour, 8 minute, 16 second, 32 millisecond), custom_format_string 18,
//! scale_factor 19, num_nonspace_integer_digits 29,
//! num_nonspace_decimal_digits 30, use_automatic_duration_units 40,
//! custom_uid 41, bool_true_string 44, bool_false_string 45.

use super::proto::Msg;

pub const DECIMAL: u32 = 256;
pub const CURRENCY: u32 = 257;
pub const PERCENT: u32 = 258;
pub const SCIENTIFIC: u32 = 259;
pub const TEXT: u32 = 260;
pub const DATE: u32 = 261;
pub const FRACTION: u32 = 262;
pub const DURATION: u32 = 268;
pub const BASE: u32 = 269;
pub const CUSTOM_NUMBER: u32 = 270;
pub const CUSTOM_TEXT: u32 = 271;
pub const CUSTOM_DATE: u32 = 272;
pub const CUSTOM_CURRENCY: u32 = 274;

const AUTO_DECIMALS: u64 = 253;

/// For a date format without a pattern.
pub const DEFAULT_DATE: &str = "yyyy-mm-dd hh:mm:ss";

/// A format's XLSX code for a cell holding `value` (automatic decimals
/// depend on it); `None` for General. Custom formats are resolved by the
/// caller and passed as `custom`.
pub fn code(f: Msg, custom: Option<Msg>, value: Option<f64>) -> Option<String> {
    let kind = f.uint(1).unwrap_or(0) as u32;
    match kind {
        DECIMAL if general(f) => None,
        DECIMAL => Some(decimal(f, value, "")),
        PERCENT => Some(decimal(f, value.map(|v| v * 100.0), "%")),
        CURRENCY => {
            let sym = symbol(&f.string(3).unwrap_or_default());
            let body = decimal(f, value, "");
            let lit = format!("\"{}\"", sym.replace('"', ""));
            if f.boolean(6).unwrap_or(false) {
                // Accounting: the symbol at the left edge, the number at the right.
                let pos = body.split(';').next().unwrap_or("0");
                return Some(format!("{lit}* {pos};{lit}* ({pos})"));
            }
            if !body.contains(';') {
                // A plain minus follows the symbol.
                return Some(format!("{lit}{body};{lit}-{body}"));
            }
            Some(
                body.split(';')
                    .map(|s| prefix_number(s, &lit))
                    .collect::<Vec<_>>()
                    .join(";"),
            )
        }
        SCIENTIFIC => {
            let d = f
                .uint(2)
                .filter(|&d| d < AUTO_DECIMALS)
                .unwrap_or(2)
                .min(15) as usize;
            Some(format!("0{}E+00", dots(d, '0')))
        }
        TEXT => Some("@".into()),
        DATE => date(&f.string(14).unwrap_or_default()).or_else(|| Some(DEFAULT_DATE.into())),
        FRACTION => Some(fraction(f.uint(11).unwrap_or(0xFFFF_FFFD) as u32)),
        // Other bases than 10 have no XLSX code.
        BASE if f.uint(8) == Some(10) => {
            Some("0".repeat(f.uint(9).unwrap_or(1).clamp(1, 30) as usize))
        }
        DURATION => Some(duration(f, value)),
        CUSTOM_NUMBER | CUSTOM_CURRENCY => custom_number(custom.unwrap_or(f), f),
        CUSTOM_DATE => {
            let c = custom.unwrap_or(f);
            date(&c.string(18).or_else(|| c.string(14)).unwrap_or_default())
                .or_else(|| Some(DEFAULT_DATE.into()))
        }
        CUSTOM_TEXT => custom_text(&custom.unwrap_or(f).string(18).unwrap_or_default()),
        _ => None,
    }
}

fn dots(n: usize, c: char) -> String {
    if n == 0 {
        String::new()
    } else {
        format!(".{}", c.to_string().repeat(n))
    }
}

/// Decimals a number shows when its format has automatic decimals: those
/// of its shortest text, at most 10.
fn auto_decimals(v: f64) -> usize {
    let s = crate::formats::office::sheets::numtext::shortest(v.abs());
    if s.contains('e') {
        return 10;
    }
    s.split_once('.').map_or(0, |(_, d)| d.len().min(10))
}

/// A DECIMAL format that shows numbers as General does: automatic
/// decimals, no separators, a plain minus.
fn general(f: Msg) -> bool {
    f.uint(2).unwrap_or(AUTO_DECIMALS) >= AUTO_DECIMALS
        && !f.boolean(5).unwrap_or(false)
        && f.uint(4).unwrap_or(0) == 0
}

/// DECIMAL, PERCENT and the number of CURRENCY: `suffix` follows each
/// section.
fn decimal(f: Msg, value: Option<f64>, suffix: &str) -> String {
    let places = f.uint(2).unwrap_or(AUTO_DECIMALS);
    let d = if places >= AUTO_DECIMALS {
        value.map_or(0, auto_decimals)
    } else {
        places.min(30) as usize
    };
    let int = if f.boolean(5).unwrap_or(false) {
        "#,##0"
    } else {
        "0"
    };
    let pos = format!("{int}{}{suffix}", dots(d, '0'));
    match f.uint(4).unwrap_or(0) {
        1 => format!("{pos};[Red]{pos}"),
        2 => format!("{pos};({pos})"),
        3 => format!("{pos};[Red]({pos})"),
        _ => pos,
    }
}

/// `lit` before the number of a section, after its colour.
fn prefix_number(section: &str, lit: &str) -> String {
    let (color, rest) = match section.strip_prefix("[Red]") {
        Some(r) => ("[Red]", r),
        None => ("", section),
    };
    match rest.strip_prefix('(') {
        Some(r) => format!("{color}({lit}{r}"),
        None => format!("{color}{lit}{rest}"),
    }
}

/// The symbol of an ISO 4217 code as English-locale Numbers shows it.
fn symbol(code: &str) -> String {
    const SYMBOLS: &[(&str, &str)] = &[
        ("AUD", "A$"),
        ("BRL", "R$"),
        ("CAD", "CA$"),
        ("CHF", "CHF "),
        ("CNY", "CN¥"),
        ("EUR", "€"),
        ("GBP", "£"),
        ("HKD", "HK$"),
        ("ILS", "₪"),
        ("INR", "₹"),
        ("JPY", "JP¥"),
        ("KRW", "₩"),
        ("MXN", "MX$"),
        ("NZD", "NZ$"),
        ("PHP", "₱"),
        ("THB", "฿"),
        ("TWD", "NT$"),
        ("USD", "$"),
        ("VND", "₫"),
        ("XAF", "FCFA "),
        ("XCD", "EC$"),
        ("XOF", "CFA "),
    ];
    match SYMBOLS.iter().find(|s| s.0 == code) {
        Some(s) => s.1.to_string(),
        None if code.is_empty() => "$".into(),
        None => format!("{code} "),
    }
}

fn fraction(accuracy: u32) -> String {
    match accuracy {
        0xFFFF_FFFF => "# ?/?".into(),
        0xFFFF_FFFE => "# ??/??".into(),
        0xFFFF_FFFD => "# ???/???".into(),
        d @ 1..=99_999 => format!("# ?/{d}"),
        _ => "# ???/???".into(),
    }
}

/// DURATION: the value is converted to days by the caller; the code shows
/// the units the format names, from the largest down to the smallest.
fn duration(f: Msg, value: Option<f64>) -> String {
    let (mut largest, mut smallest) = (
        f.uint(15).unwrap_or(4) as u32,
        f.uint(16).unwrap_or(16) as u32,
    );
    if f.boolean(40).unwrap_or(false) {
        (largest, smallest) = auto_units(value.unwrap_or(0.0) * 86_400.0);
    }
    let compact = f.uint(7).unwrap_or(0) == 0;
    let long = f.uint(7) == Some(2);
    // Excel has no weeks, counts whole days only as a rounded number and
    // milliseconds only as a fraction of the seconds: weeks show as days,
    // days followed by smaller units as hours, milliseconds after seconds.
    let ms = smallest >= 32;
    let largest = largest.min(16);
    let smallest = smallest.min(16).max(largest.max(2));
    let largest = if smallest > 2 { largest.max(4) } else { 2 };
    // Compact durations pad minutes and seconds to two digits, unless one
    // unit shows alone.
    let pad = compact && (smallest > largest || ms);
    let mut out = String::new();
    for unit in [2u32, 4, 8, 16] {
        if unit < largest || unit > smallest {
            continue;
        }
        let first = out.is_empty();
        let tok = match (unit, first, pad || (unit == 16 && ms)) {
            (2, _, _) => "0",
            (4, true, _) => "[h]",
            (8, true, true) => "[mm]",
            (8, true, false) => "[m]",
            (16, true, true) => "[ss]",
            (16, true, false) => "[s]",
            (4, false, _) => "h",
            (8, false, true) => "mm",
            (8, false, false) => "m",
            (16, false, true) => "ss",
            _ => "s",
        };
        if !first {
            out.push(if compact { ':' } else { ' ' });
        }
        out.push_str(tok);
        if unit == 16 && ms {
            out.push_str(".000");
        }
        if !compact {
            let i = [2, 4, 8, 16].iter().position(|&u| u == unit).unwrap_or(0);
            out.push_str(if long {
                ["\" days\"", "\" hours\"", "\" minutes\"", "\" seconds\""][i]
            } else {
                ["\"d\"", "\"h\"", "\"m\"", "\"s\""][i]
            });
        }
    }
    out
}

/// The units numbers-parser's notes say automatic durations show.
fn auto_units(secs: f64) -> (u32, u32) {
    if secs == 0.0 {
        return (2, 2);
    }
    // To the millisecond: the seconds come back from days.
    let a = (secs.abs() * 1000.0).round() / 1000.0;
    let largest = if a >= 604_800.0 {
        1
    } else if a >= 86_400.0 {
        2
    } else if a >= 3600.0 {
        4
    } else if a >= 60.0 {
        8
    } else if a >= 1.0 {
        16
    } else {
        32
    };
    let smallest = if a.fract() != 0.0 {
        32
    } else if a % 60.0 != 0.0 {
        16
    } else if a % 3600.0 != 0.0 {
        8
    } else if a % 86_400.0 != 0.0 {
        4
    } else {
        2
    };
    (largest, smallest.max(largest))
}

/// An ICU date pattern to an XLSX date code.
pub fn date(p: &str) -> Option<String> {
    let chars: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            // 'literal', '' for a quote.
            if chars.get(i + 1) == Some(&'\'') {
                out.push_str("\\'");
                i += 2;
                continue;
            }
            let mut lit = String::new();
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        lit.push('\'');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                lit.push(chars[i]);
                i += 1;
            }
            if !lit.is_empty() {
                out.push('"');
                out.push_str(&lit.replace('"', ""));
                out.push('"');
            }
            continue;
        }
        if !c.is_ascii_alphabetic() {
            match c {
                ' ' | '-' | '/' | ':' | ',' | '.' | '(' | ')' => out.push(c),
                '"' => {}
                _ => {
                    out.push('\\');
                    out.push(c);
                }
            }
            i += 1;
            continue;
        }
        let mut n = 1;
        while chars.get(i + n) == Some(&c) {
            n += 1;
        }
        i += n;
        let tok: &str = match (c, n) {
            ('y' | 'Y' | 'u', 2) => "yy",
            ('y' | 'Y' | 'u', _) => "yyyy",
            ('M' | 'L', 1) => "m",
            ('M' | 'L', 2) => "mm",
            ('M' | 'L', 3) => "mmm",
            ('M' | 'L', 4) => "mmmm",
            ('M' | 'L', _) => "mmmmm",
            ('d', 1) => "d",
            ('d', _) => "dd",
            ('E' | 'c' | 'e', 1..=3) => "ddd",
            ('E' | 'c' | 'e', _) => "dddd",
            ('H' | 'k', 1) => "h",
            ('H' | 'k', _) => "hh",
            ('h' | 'K', 1) => "h",
            ('h' | 'K', _) => "hh",
            ('m', 1) => "m",
            ('m', _) => "mm",
            ('s', 1) => "s",
            ('s', _) => "ss",
            ('S', k) => {
                // Fractions of a second follow the seconds.
                if !out.ends_with('.') {
                    out.push('.');
                }
                out.push_str(&"0".repeat(k.min(3)));
                continue;
            }
            ('a', _) => "AM/PM",
            ('G', _) => "\"AD\"",
            ('Q' | 'q', _) => continue,
            _ => continue,
        };
        out.push_str(tok);
    }
    let out = out.trim().to_string();
    (!out.is_empty()).then_some(out)
}

/// A custom number format: its pattern with Numbers' digit padding and
/// quoting, made XLSX's.
fn custom_number(c: Msg, outer: Msg) -> Option<String> {
    let pattern = c.string(18)?;
    let thousands = c.boolean(5).unwrap_or(false);
    let int_zero = c.uint(29).unwrap_or(0) > 0;
    let dec_zero = c.uint(30).unwrap_or(0) > 0;
    let currency = c
        .string(3)
        .filter(|s| !s.is_empty())
        .or_else(|| outer.string(3).filter(|s| !s.is_empty()));
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut in_dec = false;
    let mut first_int: Option<char> = None;
    let mut first_dec: Option<char> = None;
    while i < chars.len() {
        let ch = chars[i];
        match ch {
            '\'' => {
                let mut lit = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    lit.push(chars[i]);
                    i += 1;
                }
                if lit.is_empty() && chars.get(i) == Some(&'\'') {
                    lit.push('\'');
                }
                out.push('"');
                out.push_str(&lit.replace('"', ""));
                out.push('"');
            }
            '#' | '0' => {
                let lead = if in_dec {
                    *first_dec.get_or_insert(ch)
                } else {
                    *first_int.get_or_insert(ch)
                };
                let pad = if in_dec { dec_zero } else { int_zero };
                out.push(match (lead, ch, pad) {
                    ('#', c, _) => c,
                    (_, _, true) => '0',
                    _ => '?',
                });
            }
            '.' => {
                in_dec = true;
                out.push('.');
            }
            ',' => {
                if thousands {
                    out.push(',');
                }
            }
            '%' => out.push('%'),
            'E' if chars.get(i + 1) == Some(&'+') => {
                out.push_str("E+");
                i += 1;
            }
            '\u{a4}' => {
                let s = symbol(currency.as_deref().unwrap_or("USD"));
                out.push('"');
                out.push_str(&s.replace('"', ""));
                out.push('"');
            }
            ' ' | '-' | '(' | ')' | '/' | ':' | '$' | '+' => out.push(ch),
            '"' => {}
            _ => {
                out.push('\\');
                out.push(ch);
            }
        }
        i += 1;
    }
    if !out.chars().any(|c| matches!(c, '0' | '#' | '?')) {
        // A pattern without digits shows the text alone.
        return Some(format!("{out};{out};{out}"));
    }
    if thousands
        && !out.contains(',')
        && let Some(p) = out.find(['0', '#', '?'])
    {
        out.insert_str(p, "#,##");
    }
    Some(out)
}

/// A custom text format: the text placeholder (U+E421) becomes `@`.
fn custom_text(p: &str) -> Option<String> {
    if p.is_empty() {
        return Some("@".into());
    }
    let mut out = String::new();
    let mut lit = String::new();
    let flush = |lit: &mut String, out: &mut String| {
        if !lit.is_empty() {
            out.push('"');
            out.push_str(&lit.replace('"', ""));
            out.push('"');
            lit.clear();
        }
    };
    for c in p.chars() {
        if c == '\u{e421}' {
            flush(&mut lit, &mut out);
            out.push('@');
        } else {
            lit.push(c);
        }
    }
    flush(&mut lit, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::proto::Msg;
    use super::super::proto::write::W;
    use super::*;

    fn fmt(w: W, v: Option<f64>) -> Option<String> {
        code(Msg(&w.0), None, v)
    }

    #[test]
    fn numbers() {
        let d = W::default().uint(1, 256);
        assert_eq!(fmt(d.clone().uint(2, 253), Some(1.5)), None);
        assert_eq!(
            fmt(d.clone().uint(2, 2).uint(5, 1), None).as_deref(),
            Some("#,##0.00")
        );
        assert_eq!(
            fmt(d.clone().uint(2, 1).uint(4, 3), None).as_deref(),
            Some("0.0;[Red](0.0)")
        );
        assert_eq!(
            fmt(d.clone().uint(2, 253).uint(5, 1), Some(1234.125)).as_deref(),
            Some("#,##0.000")
        );
        let p = W::default().uint(1, 258).uint(2, 253);
        assert_eq!(fmt(p, Some(0.125)).as_deref(), Some("0.0%"));
        let c = W::default()
            .uint(1, 257)
            .uint(2, 2)
            .bytes(3, b"EUR")
            .uint(4, 2);
        assert_eq!(fmt(c, None).as_deref(), Some("\"€\"0.00;(\"€\"0.00)"));
        assert_eq!(
            fmt(W::default().uint(1, 262).uint(11, 4), None).as_deref(),
            Some("# ?/4")
        );
    }

    #[test]
    fn dates() {
        assert_eq!(date("dd/MM/yyyy").as_deref(), Some("dd/mm/yyyy"));
        assert_eq!(
            date("EEEE, MMMM d, y 'at' h:mm a").as_deref(),
            Some("dddd, mmmm d, yyyy \"at\" h:mm AM/PM")
        );
        assert_eq!(date("HH:mm:ss.SSS").as_deref(), Some("hh:mm:ss.000"));
    }

    #[test]
    fn durations() {
        let f = W::default()
            .uint(1, 268)
            .uint(7, 0)
            .uint(15, 4)
            .uint(16, 16);
        assert_eq!(fmt(f, Some(1.0)).as_deref(), Some("[h]:mm:ss"));
        let f = W::default().uint(1, 268).uint(7, 1).uint(15, 8).uint(16, 8);
        assert_eq!(fmt(f, None).as_deref(), Some("[m]\"m\""));
        // Days followed by hours: hours from the start.
        let f = W::default().uint(1, 268).uint(7, 1).uint(15, 2).uint(16, 4);
        assert_eq!(fmt(f, None).as_deref(), Some("[h]\"h\""));
        // Automatic units: 90 seconds (in days) show minutes and seconds.
        let f = W::default().uint(1, 268).uint(7, 0).uint(40, 1);
        assert_eq!(fmt(f, Some(90.0 / 86_400.0)).as_deref(), Some("[mm]:ss"));
        let f = W::default()
            .uint(1, 268)
            .uint(7, 2)
            .uint(15, 16)
            .uint(16, 32);
        assert_eq!(fmt(f, None).as_deref(), Some("[ss].000\" seconds\""));
    }

    #[test]
    fn custom() {
        let f = W::default()
            .uint(1, 270)
            .bytes(18, "#,##0.00 'units'".as_bytes())
            .uint(5, 1)
            .uint(29, 1)
            .uint(30, 2);
        assert_eq!(fmt(f, None).as_deref(), Some("#,##0.00 \"units\""));
        let f = W::default()
            .uint(1, 271)
            .bytes(18, "Name: \u{e421}".as_bytes());
        assert_eq!(fmt(f, None).as_deref(), Some("\"Name: \"@"));
    }
}
