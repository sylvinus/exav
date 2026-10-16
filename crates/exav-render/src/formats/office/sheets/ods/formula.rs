//! OpenFormula (ODF 1.2 part 2) to Excel A1 formula syntax.
//!
//! References `[.A1]`, `[$Sheet2.A1:.B2]`, `['My sheet'.A1]` become `A1`,
//! `Sheet2!A1:B2`, `'My sheet'!A1`; `;` separates arguments, `~` is the
//! union operator and `!` the intersection; array constants use `;` and `|`.

use crate::formats::office::sheets::xls::formula::{quote_external, quote_sheet};

/// Function names that differ between OpenFormula and Excel.
const RENAME: &[(&str, &str)] = &[
    ("CEILING.XCL", "CEILING"),
    ("FLOOR.XCL", "FLOOR"),
    ("COM.MICROSOFT.CEILING.MATH", "_xlfn.CEILING.MATH"),
    ("COM.MICROSOFT.FLOOR.MATH", "_xlfn.FLOOR.MATH"),
    ("CHISQDIST", "_xlfn.CHISQ.DIST"),
    ("CHISQINV", "_xlfn.CHISQ.INV"),
    ("LEGACY.CHIDIST", "CHIDIST"),
    ("LEGACY.CHIINV", "CHIINV"),
    ("LEGACY.CHITEST", "CHITEST"),
    ("LEGACY.FDIST", "FDIST"),
    ("LEGACY.FINV", "FINV"),
    ("LEGACY.FTEST", "FTEST"),
    ("LEGACY.NORMSDIST", "NORMSDIST"),
    ("LEGACY.NORMSINV", "NORMSINV"),
    ("LEGACY.TDIST", "TDIST"),
    ("LEGACY.TINV", "TINV"),
    ("MULTIPLE.OPERATIONS", "TABLE"),
    ("FORMULA", "_xlfn.FORMULATEXT"),
];

/// Functions Excel 2010 and later added: `_xlfn.` in XLSX. OpenFormula
/// files name them with `COM.MICROSOFT.` or plainly.
pub(crate) const XLFN: &[&str] = &[
    "AGGREGATE",
    "BETA.DIST",
    "BETA.INV",
    "BINOM.DIST",
    "BINOM.INV",
    "BINOM.DIST.RANGE",
    "BITAND",
    "BITLSHIFT",
    "BITOR",
    "BITRSHIFT",
    "BITXOR",
    "CEILING.MATH",
    "CEILING.PRECISE",
    "CHISQ.DIST",
    "CHISQ.DIST.RT",
    "CHISQ.INV",
    "CHISQ.INV.RT",
    "CHISQ.TEST",
    "COMBINA",
    "CONCAT",
    "CONFIDENCE.NORM",
    "CONFIDENCE.T",
    "COT",
    "COTH",
    "COVARIANCE.P",
    "COVARIANCE.S",
    "CSC",
    "CSCH",
    "DAYS",
    "DECIMAL",
    "ERF.PRECISE",
    "ERFC.PRECISE",
    "EXPON.DIST",
    "F.DIST",
    "F.DIST.RT",
    "F.INV",
    "F.INV.RT",
    "F.TEST",
    "FILTERXML",
    "FLOOR.MATH",
    "FLOOR.PRECISE",
    "FORECAST.ETS",
    "FORECAST.ETS.CONFINT",
    "FORECAST.ETS.SEASONALITY",
    "FORECAST.ETS.STAT",
    "FORECAST.LINEAR",
    "FORMULATEXT",
    "GAMMA",
    "GAMMA.DIST",
    "GAMMA.INV",
    "GAMMALN.PRECISE",
    "GAUSS",
    "HYPGEOM.DIST",
    "IFNA",
    "IFS",
    "IMCOSH",
    "IMCOT",
    "IMCSC",
    "IMCSCH",
    "IMSEC",
    "IMSECH",
    "IMSINH",
    "IMTAN",
    "ISFORMULA",
    "ISOWEEKNUM",
    "LOGNORM.DIST",
    "LOGNORM.INV",
    "MAXIFS",
    "MINIFS",
    "MODE.MULT",
    "MODE.SNGL",
    "MUNIT",
    "NEGBINOM.DIST",
    "NETWORKDAYS.INTL",
    "NORM.DIST",
    "NORM.INV",
    "NORM.S.DIST",
    "NORM.S.INV",
    "NUMBERVALUE",
    "PDURATION",
    "PERCENTILE.EXC",
    "PERCENTILE.INC",
    "PERCENTRANK.EXC",
    "PERCENTRANK.INC",
    "PERMUTATIONA",
    "PHI",
    "POISSON.DIST",
    "QUARTILE.EXC",
    "QUARTILE.INC",
    "RANK.AVG",
    "RANK.EQ",
    "RRI",
    "SEC",
    "SECH",
    "SHEET",
    "SHEETS",
    "SKEW.P",
    "STDEV.P",
    "STDEV.S",
    "SWITCH",
    "T.DIST",
    "T.DIST.2T",
    "T.DIST.RT",
    "T.INV",
    "T.INV.2T",
    "T.TEST",
    "TEXTJOIN",
    "UNICHAR",
    "UNICODE",
    "VAR.P",
    "VAR.S",
    "WEBSERVICE",
    "WEIBULL.DIST",
    "WORKDAY.INTL",
    "XOR",
    "Z.TEST",
    "ACOT",
    "ACOTH",
    "ARABIC",
    "BASE",
    "ENCODEURL",
    "XLOOKUP",
    "XMATCH",
    "SORT",
    "SORTBY",
    "FILTER",
    "UNIQUE",
    "SEQUENCE",
    "RANDARRAY",
    "LET",
];

/// Formula text past this length is not converted.
const MAX_LEN: usize = 65_536;

/// Converts formulas, numbering the external documents they name as
/// externalLink parts are numbered.
#[derive(Default)]
pub struct Converter {
    external: Vec<String>,
}

#[derive(Debug, PartialEq, Clone)]
enum T {
    Ref(String),
    Str(String),
    Num(String),
    Func(String),
    Name(String),
    Op(String),
    Open,
    Close,
    Sep,
    ArrOpen,
    ArrClose,
    ArrCol,
    ArrRow,
    Space,
}

/// One part of a reference: its sheet, if any, and its cell, column or row.
fn ref_part(s: &str) -> (Option<String>, String) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('.') {
        return (None, rest.to_string());
    }
    let t = s.strip_prefix('$').unwrap_or(s);
    if let Some(q) = t.strip_prefix('\'') {
        // Quoted: up to the closing quote that is not doubled.
        let mut name = String::new();
        let mut it = q.char_indices().peekable();
        let mut end = q.len();
        while let Some((i, c)) = it.next() {
            if c == '\'' {
                if it.peek().map(|x| x.1) == Some('\'') {
                    it.next();
                    name.push('\'');
                    continue;
                }
                end = i + 1;
                break;
            }
            name.push(c);
        }
        let rest = &q[end.min(q.len())..];
        return match rest
            .strip_prefix('#')
            .and_then(|r| r.rfind('.').map(|d| (r, d)))
        {
            // 'document'#$Sheet.A1: another document's sheet.
            Some((r, d)) => (Some(format!("{name}#{}", &r[..d])), r[d + 1..].to_string()),
            None => (Some(name), rest.trim_start_matches('.').to_string()),
        };
    }
    match t.rfind('.') {
        Some(dot) => (Some(t[..dot].to_string()), t[dot + 1..].to_string()),
        None => (None, t.to_string()),
    }
}

impl Converter {
    fn external_index(&mut self, doc: &str) -> usize {
        match self.external.iter().position(|d| d == doc) {
            Some(i) => i + 1,
            None => {
                self.external.push(doc.to_string());
                self.external.len()
            }
        }
    }

    /// `[...]` reference contents to Excel text.
    fn convert_ref(&mut self, inner: &str) -> String {
        let inner = inner.trim();
        if inner.contains("#REF!") {
            return "#REF!".into();
        }
        let mut parts = vec![];
        let mut cur = String::new();
        let mut q = false;
        for c in inner.chars() {
            match c {
                '\'' => {
                    q = !q;
                    cur.push(c);
                }
                ':' if !q => parts.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
        parts.push(cur);
        let conv: Vec<(Option<String>, String)> =
            parts.iter().take(2).map(|p| ref_part(p)).collect();
        let (s1, c1) = &conv[0];
        let mut out = String::new();
        if let Some(s) = s1 {
            if let Some((doc, sheet)) = s.split_once('#') {
                let sheet = sheet.trim_start_matches('$');
                let n = self.external_index(doc.trim_matches('\''));
                out += &format!("{}!{c1}", quote_external(n, sheet));
                if let Some((_, c2)) = conv.get(1) {
                    out.push(':');
                    out += c2;
                }
                return out;
            }
            out += &quote_sheet(s);
            if let Some((Some(s2), _)) = conv.get(1) {
                if s2 != s {
                    // Sheet1:Sheet3!A1, quoted whole when either name needs it.
                    out = if quote_sheet(s) == *s && quote_sheet(s2) == *s2 {
                        format!("{s}:{s2}")
                    } else {
                        format!("'{}:{}'", s.replace('\'', "''"), s2.replace('\'', "''"))
                    };
                }
            }
            out.push('!');
        }
        out += c1;
        if let Some((_, c2)) = conv.get(1) {
            out.push(':');
            out += c2;
        }
        out
    }

    fn tokenize(&mut self, f: &str) -> Option<Vec<T>> {
        let ch: Vec<char> = f.chars().collect();
        let mut i = 0;
        let mut out = vec![];
        while i < ch.len() {
            let c = ch[i];
            match c {
                ' ' | '\n' | '\r' | '\t' => {
                    out.push(T::Space);
                    i += 1;
                }
                '"' => {
                    let mut s = String::new();
                    i += 1;
                    loop {
                        if i >= ch.len() {
                            return None;
                        }
                        if ch[i] == '"' {
                            if i + 1 < ch.len() && ch[i + 1] == '"' {
                                s.push('"');
                                i += 2;
                                continue;
                            }
                            i += 1;
                            break;
                        }
                        s.push(ch[i]);
                        i += 1;
                    }
                    out.push(T::Str(s));
                }
                '[' => {
                    let mut depth = 0;
                    let mut s = String::new();
                    i += 1;
                    let mut q = false;
                    while i < ch.len() {
                        let d = ch[i];
                        if d == '\'' {
                            q = !q;
                        }
                        if !q && d == '[' {
                            depth += 1;
                        }
                        if !q && d == ']' {
                            if depth == 0 {
                                break;
                            }
                            depth -= 1;
                        }
                        s.push(d);
                        i += 1;
                    }
                    i += 1;
                    out.push(T::Ref(self.convert_ref(&s)));
                }
                '(' => {
                    out.push(T::Open);
                    i += 1;
                }
                ')' => {
                    out.push(T::Close);
                    i += 1;
                }
                ';' => {
                    out.push(if in_array(&out) { T::ArrCol } else { T::Sep });
                    i += 1;
                }
                '|' => {
                    out.push(T::ArrRow);
                    i += 1;
                }
                '{' => {
                    out.push(T::ArrOpen);
                    i += 1;
                }
                '}' => {
                    out.push(T::ArrClose);
                    i += 1;
                }
                '~' => {
                    out.push(T::Op(",".into()));
                    i += 1;
                }
                '!' => {
                    out.push(T::Op(" ".into()));
                    i += 1;
                }
                '<' | '>' | '=' => {
                    let mut s = c.to_string();
                    if i + 1 < ch.len() && (ch[i + 1] == '=' || (c == '<' && ch[i + 1] == '>')) {
                        s.push(ch[i + 1]);
                        i += 1;
                    }
                    out.push(T::Op(s));
                    i += 1;
                }
                '+' | '-' | '*' | '/' | '^' | '&' | '%' => {
                    out.push(T::Op(c.to_string()));
                    i += 1;
                }
                '#' => {
                    let mut s = String::new();
                    while i < ch.len() && !matches!(ch[i], ';' | ')' | ' ' | ',' | '}' | '|') {
                        s.push(ch[i]);
                        i += 1;
                        if s.ends_with('!') || s.ends_with('?') || s == "#N/A" {
                            break;
                        }
                    }
                    out.push(T::Name(s));
                }
                c if c.is_ascii_digit()
                    || (c == '.' && i + 1 < ch.len() && ch[i + 1].is_ascii_digit()) =>
                {
                    let mut s = String::new();
                    while i < ch.len() && (ch[i].is_ascii_digit() || ch[i] == '.') {
                        s.push(ch[i]);
                        i += 1;
                    }
                    if i + 1 < ch.len()
                        && (ch[i] == 'E' || ch[i] == 'e')
                        && (ch[i + 1].is_ascii_digit() || ch[i + 1] == '+' || ch[i + 1] == '-')
                    {
                        s.push('E');
                        i += 1;
                        if ch[i] == '+' || ch[i] == '-' {
                            s.push(ch[i]);
                            i += 1;
                        }
                        while i < ch.len() && ch[i].is_ascii_digit() {
                            s.push(ch[i]);
                            i += 1;
                        }
                    }
                    out.push(T::Num(s));
                }
                '\'' => {
                    let mut s = String::from("'");
                    i += 1;
                    while i < ch.len() {
                        s.push(ch[i]);
                        i += 1;
                        if ch[i - 1] == '\'' {
                            break;
                        }
                    }
                    out.push(T::Name(s));
                }
                c if c.is_alphanumeric() || c == '_' || c == '$' || c == '\\' => {
                    let mut s = String::new();
                    while i < ch.len()
                        && (ch[i].is_alphanumeric() || matches!(ch[i], '_' | '.' | '$' | '\\'))
                    {
                        s.push(ch[i]);
                        i += 1;
                    }
                    let mut j = i;
                    while j < ch.len() && ch[j] == ' ' {
                        j += 1;
                    }
                    if j < ch.len() && ch[j] == '(' {
                        out.push(T::Func(s));
                        i = j;
                    } else {
                        out.push(T::Name(s));
                    }
                }
                _ => {
                    out.push(T::Name(c.to_string()));
                    i += 1;
                }
            }
        }
        Some(out)
    }

    /// Converts `f` (with or without its `of:=` prefix). `None` for a
    /// formula in another syntax this does not read.
    pub fn convert(&mut self, f: &str) -> Option<String> {
        if f.len() > MAX_LEN {
            return None;
        }
        let body = if let Some(b) = f.strip_prefix("of:") {
            b
        } else if let Some(b) = f.strip_prefix("oooc:") {
            b
        } else if let Some(b) = f.strip_prefix("msoxl:") {
            return Some(b.trim_start_matches('=').to_string());
        } else if f
            .find(':')
            .is_some_and(|c| f.find('=').is_none_or(|e| c < e))
        {
            return None;
        } else {
            f
        };
        let body = body.trim_start();
        let body = body.strip_prefix('=').unwrap_or(body);
        let toks = self.tokenize(body)?;
        let mut out = String::new();
        for (k, t) in toks.iter().enumerate() {
            match t {
                T::Ref(r) => out += r,
                T::Str(s) => {
                    out.push('"');
                    out += &s.replace('"', "\"\"");
                    out.push('"');
                }
                T::Num(n) => out += n,
                T::Func(n) => out += &func_name(n),
                T::Name(n) => out += n,
                T::Op(o) => out += o,
                T::Open => out.push('('),
                T::Close => out.push(')'),
                T::Sep | T::ArrCol => out.push(','),
                T::ArrOpen => out.push('{'),
                T::ArrClose => out.push('}'),
                T::ArrRow => out.push(';'),
                T::Space => {
                    // A space between two operands is an intersection in Excel's
                    // syntax: kept only there.
                    let prev = toks[..k].iter().rev().find(|t| **t != T::Space);
                    let next = toks[k + 1..].iter().find(|t| **t != T::Space);
                    if matches!(prev, Some(T::Ref(_) | T::Name(_)))
                        && matches!(next, Some(T::Ref(_) | T::Name(_)))
                    {
                        out.push(' ');
                    }
                }
            }
        }
        Some(out)
    }
}

fn in_array(toks: &[T]) -> bool {
    let mut depth = 0i32;
    for t in toks.iter().rev() {
        match t {
            T::ArrClose => depth += 1,
            T::ArrOpen => {
                if depth == 0 {
                    return true;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    false
}

fn func_name(n: &str) -> String {
    let up = n.to_ascii_uppercase();
    if let Some(&(_, to)) = RENAME.iter().find(|(f, _)| *f == up) {
        return to.to_string();
    }
    let bare = up.strip_prefix("COM.MICROSOFT.").unwrap_or(&up);
    if XLFN.contains(&bare) {
        return format!("_xlfn.{bare}");
    }
    // The application's own functions keep their names, as future functions.
    if up.starts_with("ORG.OPENOFFICE.") || up.starts_with("ORG.LIBREOFFICE.") {
        return format!("_xlfn.{up}");
    }
    if up.starts_with("COM.SUN.STAR.") {
        return n.to_string();
    }
    bare.to_string()
}

#[cfg(test)]
mod tests {
    use super::Converter;

    #[test]
    fn refs() {
        let mut c = Converter::default();
        assert_eq!(c.convert("of:=SUM([.A1:.B2])").unwrap(), "SUM(A1:B2)");
        assert_eq!(c.convert("of:=[$Sheet2.$A$1]+1").unwrap(), "Sheet2!$A$1+1");
        assert_eq!(c.convert("of:=['My sheet'.A1];").unwrap(), "'My sheet'!A1,");
        assert_eq!(
            c.convert("of:=IF([.A1]>1;\"a\";\"b\")").unwrap(),
            "IF(A1>1,\"a\",\"b\")"
        );
        assert_eq!(c.convert("of:={1;2|3;4}").unwrap(), "{1,2;3,4}");
        assert_eq!(c.convert("of:=[.A1:.A3]~[.C1]").unwrap(), "A1:A3,C1");
        assert_eq!(
            c.convert("of:=[Sheet1.A1:Sheet3.B2]").unwrap(),
            "Sheet1:Sheet3!A1:B2"
        );
        assert_eq!(c.convert("of:=TRUE()").unwrap(), "TRUE()");
        assert_eq!(
            c.convert("of:=['file:///a.ods'#$Sheet1.A1]").unwrap(),
            "[1]Sheet1!A1"
        );
        assert_eq!(
            c.convert("of:=['file:///b.ods'#$Sheet1.A1]+['file:///a.ods'#$S.B2]")
                .unwrap(),
            "[2]Sheet1!A1+[1]S!B2"
        );
        assert!(c.convert("of:=\"unterminated").is_none());
    }
}
