//! R1C1 formulas, as SpreadsheetML and SYLK store them, to A1 syntax.
//!
//! `R2C3` is row 2, column 3; `R[-1]C[2]` is relative to the cell holding
//! the formula; a missing number (`RC`) is the cell's own row or column.
//! `R2` alone is a whole row, `C3` a whole column. Relative references
//! past the sheet's edge wrap around, as Excel's do.

use crate::formats::office::sheets::model::{col_name, MAX_COL, MAX_ROW};

const MAX_LEN: usize = 16_384;

/// One axis of a reference: absolute (0-based) or an offset.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Part {
    Abs(u32),
    Rel(i64),
}

impl Part {
    fn resolve(self, at: u32, max: u32) -> (u32, bool) {
        match self {
            Part::Abs(n) => (n, true),
            Part::Rel(d) => {
                let span = i64::from(max) + 1;
                ((i64::from(at) + d).rem_euclid(span) as u32, false)
            }
        }
    }
}

/// A parsed `R..C..`, `R..` or `C..`.
#[derive(Clone, Copy, PartialEq, Debug)]
struct Ref {
    row: Option<Part>,
    col: Option<Part>,
}

/// Reads an axis after its letter: `5`, `[-2]` or nothing (offset 0).
fn axis(s: &[char], i: &mut usize, max: u32) -> Option<Part> {
    if s.get(*i) == Some(&'[') {
        let start = *i + 1;
        let mut j = start;
        if s.get(j) == Some(&'-') || s.get(j) == Some(&'+') {
            j += 1;
        }
        while j < s.len() && s[j].is_ascii_digit() {
            j += 1;
        }
        if s.get(j) != Some(&']') || j == start || j - start > 9 {
            return None;
        }
        let v: i64 = s[start..j].iter().collect::<String>().parse().ok()?;
        *i = j + 1;
        return Some(Part::Rel(v));
    }
    let start = *i;
    while *i < s.len() && s[*i].is_ascii_digit() {
        *i += 1;
    }
    if *i == start {
        return Some(Part::Rel(0));
    }
    if *i - start > 9 {
        return None;
    }
    let v: u32 = s[start..*i].iter().collect::<String>().parse().ok()?;
    (v >= 1 && v - 1 <= max).then(|| Part::Abs(v - 1))
}

/// A reference at `s[*i..]`, case-insensitive, not followed by a name
/// character; `*i` moves past it.
fn reference(s: &[char], i: &mut usize) -> Option<Ref> {
    let mut j = *i;
    let mut r = Ref {
        row: None,
        col: None,
    };
    if matches!(s.get(j), Some('R' | 'r')) {
        j += 1;
        r.row = Some(axis(s, &mut j, MAX_ROW)?);
    }
    if matches!(s.get(j), Some('C' | 'c')) {
        j += 1;
        r.col = Some(axis(s, &mut j, MAX_COL)?);
    }
    if r.row.is_none() && r.col.is_none() {
        return None;
    }
    if s.get(j)
        .is_some_and(|&c| c.is_alphanumeric() || matches!(c, '_' | '.' | '(' | '\\'))
    {
        return None;
    }
    *i = j;
    Some(r)
}

fn cell_text(row: Part, col: Part, at: (u32, u32)) -> String {
    let (r, ra) = row.resolve(at.0, MAX_ROW);
    let (c, ca) = col.resolve(at.1, MAX_COL);
    format!(
        "{}{}{}{}",
        if ca { "$" } else { "" },
        col_name(c),
        if ra { "$" } else { "" },
        u64::from(r) + 1
    )
}

fn row_text(p: Part, at: u32) -> String {
    let (r, a) = p.resolve(at, MAX_ROW);
    format!("{}{}", if a { "$" } else { "" }, u64::from(r) + 1)
}

fn col_text(p: Part, at: u32) -> String {
    let (c, a) = p.resolve(at, MAX_COL);
    format!("{}{}", if a { "$" } else { "" }, col_name(c))
}

/// `a` alone, or `a:b`, in A1 syntax; `None` when they do not pair.
fn ref_text(a: Ref, b: Option<Ref>, at: (u32, u32)) -> Option<String> {
    let single = b.is_none();
    let b = b.unwrap_or(a);
    Some(match (a.row, a.col, b.row, b.col) {
        (Some(r1), Some(c1), Some(r2), Some(c2)) => {
            let one = cell_text(r1, c1, at);
            if single {
                one
            } else {
                format!("{one}:{}", cell_text(r2, c2, at))
            }
        }
        (Some(r1), None, Some(r2), None) => {
            format!("{}:{}", row_text(r1, at.0), row_text(r2, at.0))
        }
        (None, Some(c1), None, Some(c2)) => {
            format!("{}:{}", col_text(c1, at.1), col_text(c2, at.1))
        }
        _ => return None,
    })
}

/// `formula` (with or without its `=`) in A1 syntax, for the cell at
/// 0-based `at` (row, column); `None` when it cannot be read.
pub fn to_a1(formula: &str, at: (u32, u32)) -> Option<String> {
    let f = formula.trim();
    let f = f.strip_prefix('=').unwrap_or(f);
    let s: Vec<char> = f.chars().take(MAX_LEN + 1).collect();
    if s.len() > MAX_LEN {
        return None;
    }
    let mut out = String::with_capacity(f.len() + 8);
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        match c {
            '"' | '\'' => {
                // A string, or a quoted sheet name: copied as is.
                let start = i;
                i += 1;
                while i < s.len() {
                    if s[i] == c {
                        if s.get(i + 1) == Some(&c) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i = (i + 1).min(s.len());
                out.extend(&s[start..i]);
            }
            '[' => {
                // An external workbook's name.
                let start = i;
                while i < s.len() && s[i] != ']' {
                    i += 1;
                }
                i = (i + 1).min(s.len());
                out.extend(&s[start..i]);
            }
            _ if c.is_alphabetic() || c == '_' || c == '\\' => {
                // A name or a reference: references only where a name
                // could not continue one already begun.
                let mut j = i;
                if let Some(a) = reference(&s, &mut j) {
                    let mut b = None;
                    if s.get(j) == Some(&':') {
                        let mut k = j + 1;
                        if let Some(r) = reference(&s, &mut k) {
                            b = Some(r);
                            j = k;
                        }
                    }
                    out.push_str(&ref_text(a, b, at)?);
                    i = j;
                    continue;
                }
                while i < s.len()
                    && (s[i].is_alphanumeric() || matches!(s[i], '_' | '.' | '\\' | '?'))
                {
                    out.push(s[i]);
                    i += 1;
                }
            }
            _ if c.is_ascii_digit() => {
                // A number, with its exponent; also keeps "1E5" from
                // reading as a name.
                while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == '.') {
                    let e = matches!(s[i], 'e' | 'E');
                    out.push(s[i]);
                    i += 1;
                    if e && matches!(s.get(i), Some('+' | '-')) {
                        out.push(s[i]);
                        i += 1;
                    }
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    (!out.trim().is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::to_a1;

    #[test]
    fn references() {
        let at = (4, 2); // C5
        assert_eq!(to_a1("=R1C1", at).as_deref(), Some("$A$1"));
        assert_eq!(to_a1("=RC", at).as_deref(), Some("C5"));
        assert_eq!(to_a1("=R[-1]C[2]+R2C[-1]", at).as_deref(), Some("E4+B$2"));
        assert_eq!(
            to_a1("=SUM(R1C1:R[-1]C)", at).as_deref(),
            Some("SUM($A$1:C4)")
        );
        // Whole rows and columns.
        assert_eq!(to_a1("=SUM(R2:R[1])", at).as_deref(), Some("SUM($2:6)"));
        assert_eq!(
            to_a1("=SUM(C[-1])+C3", at).as_deref(),
            Some("SUM(B:B)+$C:$C")
        );
        // Lower case, and wrapping past the edge.
        assert_eq!(to_a1("=r[-6]c[-3]", at).as_deref(), Some("XFD1048575"));
    }

    #[test]
    fn what_is_not_a_reference() {
        let at = (0, 0);
        assert_eq!(
            to_a1("=ROUND(Rate*R1C2,2)&\"R1C1\"&'R2 C2'!R1C1", at).as_deref(),
            Some("ROUND(Rate*$B$1,2)&\"R1C1\"&'R2 C2'!$A$1")
        );
        assert_eq!(to_a1("=RC2", at).as_deref(), Some("$B1"));
        assert_eq!(to_a1("=R1C1E", at).as_deref(), Some("R1C1E"));
        assert_eq!(
            to_a1("=1E+5+COUNT(C1R)", at).as_deref(),
            Some("1E+5+COUNT(C1R)")
        );
        assert_eq!(
            to_a1("=[Book1.xls]Sheet1!R1C1", at).as_deref(),
            Some("[Book1.xls]Sheet1!$A$1")
        );
        // No row 0: a name, which Excel will not find.
        assert_eq!(to_a1("=R0C1", at).as_deref(), Some("R0C1"));
        assert_eq!(to_a1("=", at), None);
    }
}
