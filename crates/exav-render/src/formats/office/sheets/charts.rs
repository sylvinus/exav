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

/// What a cached value takes written as XML, beside its text: the point, its
/// index and its value element.
pub(crate) const XML_PER_POINT: usize = 48;

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

/// Fills the caches of every series that has a reference and no values. Each
/// series gets a copy of the cells it refers to, however many series refer to
/// the same ones: what the copies take is told to `charge`, and `false` comes
/// back when it refuses.
pub(crate) fn fill(wb: &mut Workbook, charge: &mut dyn FnMut(u64) -> bool) -> bool {
    let mut updates: Vec<(usize, usize, usize, ChartSeries)> = vec![];
    for (si, sh) in wb.sheets.iter().enumerate() {
        for (ci, ch) in sh.charts.iter().enumerate() {
            for (k, s) in ch.series.iter().enumerate() {
                let mut s = s.clone();
                let mut changed = false;
                let mut held = 0usize;
                // Values written out as XML, which is `XML_PER_POINT` a point
                // and the text of each.
                let mut points = 0usize;
                let mut text = 0usize;
                if s.vals.is_empty()
                    && let Some(v) = s.val_ref.as_deref().and_then(|f| values(wb, si, f))
                {
                    s.vals = nums(v);
                    held += s.vals.len() * size_of::<Option<f64>>();
                    points += s.vals.len();
                    changed = true;
                }
                if s.sizes.is_empty()
                    && let Some(v) = s.size_ref.as_deref().and_then(|f| values(wb, si, f))
                {
                    s.sizes = nums(v);
                    held += s.sizes.len() * size_of::<Option<f64>>();
                    points += s.sizes.len();
                    changed = true;
                }
                let empty_cats =
                    s.cats.is_empty() && s.cat_nums.as_ref().is_none_or(|c| c.is_empty());
                if empty_cats && let Some(v) = s.cat_ref.as_deref().and_then(|f| values(wb, si, f))
                {
                    let numeric = matches!(ch.kind, ChartKind::Scatter | ChartKind::Bubble)
                        || s.cat_nums.is_some();
                    if numeric {
                        let n = nums(v);
                        held += n.len() * size_of::<Option<f64>>();
                        points += n.len();
                        s.cat_nums = Some(n);
                    } else {
                        s.cats = v.into_iter().map(|x| x.display()).collect();
                        held += s
                            .cats
                            .iter()
                            .map(|c| size_of::<String>() + c.len())
                            .sum::<usize>();
                        points += s.cats.len();
                        text += s.cats.iter().map(String::len).sum::<usize>();
                    }
                    changed = true;
                }
                if s.name.is_none()
                    && let Some(v) = s.name_ref.as_deref().and_then(|f| values(wb, si, f))
                {
                    let name = v.iter().map(Value::display).collect::<Vec<_>>().join(" ");
                    held += name.len();
                    s.name = Some(name);
                    changed = true;
                }
                if changed {
                    if !charge((held + points * XML_PER_POINT + text) as u64) {
                        return false;
                    }
                    updates.push((si, ci, k, s));
                }
            }
        }
    }
    for (si, ci, k, s) in updates {
        wb.sheets[si].charts[ci].series[k] = s;
    }
    true
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
