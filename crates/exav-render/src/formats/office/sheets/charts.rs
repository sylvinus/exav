//! Chart caches: the values of the cells a series refers to, written beside
//! the reference as XLSX readers draw from them.

use crate::formats::office::sheets::model::*;

/// "Sheet1!$A$1:$B$3", "'My sheet'!A1" or "A1:B3" to (sheet, range).
pub(crate) fn parse_ref(f: &str) -> Option<(Option<String>, Range)> {
    let f = f.trim().trim_start_matches('=');
    let (sheet, area) = match f.rfind('!') {
        Some(i) => {
            let s = &f[..i];
            let s = match s.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
                Some(q) => q.replace("''", "'"),
                None => s.to_string(),
            };
            if s.starts_with('[') {
                return None;
            }
            (Some(s), &f[i + 1..])
        }
        None => (None, f),
    };
    let mut parts = area.split(':');
    let a = parse_cell(parts.next()?)?;
    let b = match parts.next() {
        Some(p) => parse_cell(p)?,
        None => a,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((
        sheet,
        Range {
            r1: a.0.min(b.0),
            c1: a.1.min(b.1),
            r2: a.0.max(b.0),
            c2: a.1.max(b.1),
        },
    ))
}

fn values(wb: &Workbook, here: usize, f: &str) -> Option<Vec<Value>> {
    let (sheet, r) = parse_ref(f)?;
    if r.area() > 100_000 {
        return None;
    }
    let sh = match sheet {
        Some(n) => wb.sheets.iter().find(|s| s.name.eq_ignore_ascii_case(&n))?,
        None => wb.sheets.get(here)?,
    };
    let mut out = Vec::with_capacity(r.area() as usize);
    for row in r.r1..=r.r2 {
        for col in r.c1..=r.c2 {
            out.push(
                sh.cells
                    .get(&(row, col))
                    .map_or(Value::Empty, |c| c.value.clone()),
            );
        }
    }
    Some(out)
}

fn nums(v: Vec<Value>) -> Vec<Option<f64>> {
    v.into_iter()
        .map(|v| {
            if let Value::Number(n) = v {
                Some(n)
            } else {
                None
            }
        })
        .collect()
}

/// Fills the caches of every series that has a reference and no values.
pub(crate) fn fill(wb: &mut Workbook) {
    let mut updates: Vec<(usize, usize, usize, ChartSeries)> = vec![];
    for (si, sh) in wb.sheets.iter().enumerate() {
        for (ci, ch) in sh.charts.iter().enumerate() {
            for (k, s) in ch.series.iter().enumerate() {
                let mut s = s.clone();
                let mut changed = false;
                if s.vals.is_empty() {
                    if let Some(v) = s.val_ref.as_deref().and_then(|f| values(wb, si, f)) {
                        s.vals = nums(v);
                        changed = true;
                    }
                }
                if s.sizes.is_empty() {
                    if let Some(v) = s.size_ref.as_deref().and_then(|f| values(wb, si, f)) {
                        s.sizes = nums(v);
                        changed = true;
                    }
                }
                let empty_cats =
                    s.cats.is_empty() && s.cat_nums.as_ref().is_none_or(|c| c.is_empty());
                if empty_cats {
                    if let Some(v) = s.cat_ref.as_deref().and_then(|f| values(wb, si, f)) {
                        let numeric = matches!(ch.kind, ChartKind::Scatter | ChartKind::Bubble)
                            || s.cat_nums.is_some();
                        if numeric {
                            s.cat_nums = Some(nums(v));
                        } else {
                            s.cats = v.into_iter().map(|x| x.display()).collect();
                        }
                        changed = true;
                    }
                }
                if s.name.is_none() {
                    if let Some(v) = s.name_ref.as_deref().and_then(|f| values(wb, si, f)) {
                        s.name = Some(v.iter().map(Value::display).collect::<Vec<_>>().join(" "));
                        changed = true;
                    }
                }
                if changed {
                    updates.push((si, ci, k, s));
                }
            }
        }
    }
    for (si, ci, k, s) in updates {
        wb.sheets[si].charts[ci].series[k] = s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        assert_eq!(
            parse_ref("Sheet1!$B$2:$B$5"),
            Some((
                Some("Sheet1".into()),
                Range {
                    r1: 1,
                    c1: 1,
                    r2: 4,
                    c2: 1
                }
            ))
        );
        assert_eq!(
            parse_ref("'It''s'!A1"),
            Some((Some("It's".into()), Range::cell(0, 0)))
        );
        assert_eq!(parse_ref("[1]S!A1"), None);
        assert_eq!(parse_ref("(A1,B2)"), None);
    }
}
