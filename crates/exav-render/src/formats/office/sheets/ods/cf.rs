//! Conditional formats (calcext:conditional-formats, and the style:map of
//! older documents) and content validations.

use super::formula::Converter;
use super::styles::parse_color;
use super::{Doc, parse_addr, parse_range_addr, text_of};
use crate::formats::office::common::xml::Node;
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;

pub(crate) fn split_args(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut q = false;
    for c in s.chars() {
        match c {
            '"' => {
                q = !q;
                cur.push(c)
            }
            '(' | '[' if !q => {
                depth += 1;
                cur.push(c)
            }
            ')' | ']' if !q => {
                depth -= 1;
                cur.push(c)
            }
            ';' | ',' if !q && depth == 0 => out.push(std::mem::take(&mut cur).trim().to_string()),
            _ => cur.push(c),
        }
        if out.len() > 4096 {
            break;
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn split_op(r: &str) -> (&'static str, &str) {
    let r = r.trim();
    for (p, op) in [
        (">=", "greaterThanOrEqual"),
        ("<=", "lessThanOrEqual"),
        ("!=", "notEqual"),
        ("<>", "notEqual"),
        (">", "greaterThan"),
        ("<", "lessThan"),
        ("=", "equal"),
    ] {
        if let Some(v) = r.strip_prefix(p) {
            return (op, v.trim());
        }
    }
    ("equal", r)
}

fn conv(fc: &mut Converter, s: &str) -> Option<String> {
    fc.convert(&format!("of:={}", s.trim()))
}

fn list_formula(inner: &str, fc: &mut Converter) -> Option<String> {
    let items = split_args(inner);
    if !items.is_empty() && items.iter().all(|i| i.starts_with('"')) {
        let vals: Vec<String> = items
            .iter()
            .map(|i| i.trim_matches('"').replace("\"\"", "\""))
            .collect();
        Some(format!("\"{}\"", vals.join(",")))
    } else {
        conv(fc, inner)
    }
}

pub(crate) fn read_validation(v: &Node, fc: &mut Converter) -> Option<Validation> {
    let cond = v.attr("table:condition")?;
    let cond = cond
        .strip_prefix("of:")
        .or(cond.strip_prefix("oooc:"))
        .unwrap_or(cond);
    let message = |n: &Node| -> Option<String> {
        Some(
            n.all("text:p")
                .map(|p| {
                    let mut s = String::new();
                    text_of(p, &mut s);
                    s
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .filter(|s| !s.is_empty())
    };
    let mut val = Validation {
        allow_blank: v.attr("table:allow-empty-cell") != Some("false"),
        hide_dropdown: v.attr("table:display-list") == Some("none"),
        error_style: "stop",
        operator: "between",
        ..Default::default()
    };
    if let Some(h) = v.child("table:help-message") {
        val.show_input = h.attr("table:display") == Some("true");
        val.prompt_title = h.attr("table:title").map(str::to_string);
        val.prompt = message(h);
    }
    if let Some(e) = v.child("table:error-message") {
        val.show_error = e.attr("table:display") == Some("true");
        val.error_title = e.attr("table:title").map(str::to_string);
        val.error = message(e);
        val.error_style = match e.attr("table:message-type") {
            Some("warning") => "warning",
            Some("information") => "information",
            _ => "stop",
        };
    }
    let (kind, rest) = if let Some(r) = cond.strip_prefix("cell-content-is-whole-number() and ") {
        ("whole", r)
    } else if let Some(r) = cond.strip_prefix("cell-content-is-decimal-number() and ") {
        ("decimal", r)
    } else if let Some(r) = cond.strip_prefix("cell-content-is-date() and ") {
        ("date", r)
    } else if let Some(r) = cond.strip_prefix("cell-content-is-time() and ") {
        ("time", r)
    } else if let Some(r) = cond.strip_prefix("cell-content-is-in-list(") {
        val.kind = "list";
        val.formula1 = list_formula(r.strip_suffix(')').unwrap_or(r), fc);
        return Some(val);
    } else if let Some(r) = cond.strip_prefix("cell-content-text-length") {
        ("textLength", r)
    } else {
        let r = cond.strip_prefix("is-true-formula(")?;
        val.kind = "custom";
        val.formula1 = conv(fc, r.strip_suffix(')').unwrap_or(r));
        return Some(val);
    };
    val.kind = kind;
    let rest = rest.trim();
    let mut args = |s: &str| -> Vec<String> {
        split_args(s)
            .into_iter()
            .filter_map(|a| conv(fc, &a))
            .collect()
    };
    if let Some(r) = rest
        .strip_prefix("cell-content-is-between(")
        .or(rest.strip_prefix("()-is-between("))
        .or(rest.strip_prefix("-is-between("))
    {
        let a = args(r.strip_suffix(')').unwrap_or(r));
        val.formula1 = a.first().cloned();
        val.formula2 = a.get(1).cloned();
    } else if let Some(r) = rest
        .strip_prefix("cell-content-is-not-between(")
        .or(rest.strip_prefix("()-is-not-between("))
        .or(rest.strip_prefix("-is-not-between("))
    {
        val.operator = "notBetween";
        let a = args(r.strip_suffix(')').unwrap_or(r));
        val.formula1 = a.first().cloned();
        val.formula2 = a.get(1).cloned();
    } else {
        let r = rest
            .strip_prefix("cell-content()")
            .or(rest.strip_prefix("()"))
            .unwrap_or(rest);
        let (op, v) = split_op(r);
        val.operator = op;
        val.formula1 = conv(fc, v);
    }
    Some(val)
}

/// A formula relative to `base` (A1 when absent) made relative to `target`,
/// the top left cell of the range, where XLSX evaluates it.
fn rebase(f: &str, base: Option<(u32, u32)>, target: (u32, u32)) -> String {
    let base = base.unwrap_or((0, 0));
    let dr = i64::from(target.0) - i64::from(base.0);
    let dc = i64::from(target.1) - i64::from(base.1);
    if dr == 0 && dc == 0 {
        return f.to_string();
    }
    shift_refs(f, dr, dc)
}

/// Moves the relative parts of the A1 references in `f` by (dr, dc).
pub(crate) fn shift_refs(f: &str, dr: i64, dc: i64) -> String {
    let ch: Vec<char> = f.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < ch.len() {
        let c = ch[i];
        if c == '"' || c == '\'' {
            // A string or a quoted sheet name, copied as it is.
            let q = c;
            out.push(c);
            i += 1;
            while i < ch.len() {
                out.push(ch[i]);
                if ch[i] == q {
                    if i + 1 < ch.len() && ch[i + 1] == q {
                        out.push(q);
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        let prev_word =
            i > 0 && (ch[i - 1].is_alphanumeric() || ch[i - 1] == '_' || ch[i - 1] == '.');
        if (c == '$' || c.is_ascii_alphabetic()) && !prev_word {
            let mut j = i;
            let cabs = ch[j] == '$';
            if cabs {
                j += 1;
            }
            let cs = j;
            while j < ch.len() && ch[j].is_ascii_alphabetic() {
                j += 1;
            }
            let col: String = ch[cs..j].iter().collect();
            let rabs = j < ch.len() && ch[j] == '$';
            if rabs {
                j += 1;
            }
            let rs = j;
            while j < ch.len() && ch[j].is_ascii_digit() {
                j += 1;
            }
            let row: String = ch[rs..j].iter().collect();
            let next_word = j < ch.len()
                && (ch[j].is_alphanumeric() || ch[j] == '_' || ch[j] == '(' || ch[j] == '.');
            if (1..=3).contains(&col.len())
                && !row.is_empty()
                && !next_word
                && let Some((r, cc)) = parse_cell(&format!("{col}{row}"))
            {
                let r2 = if rabs {
                    i64::from(r)
                } else {
                    (i64::from(r) + dr).rem_euclid(i64::from(MAX_ROW) + 1)
                };
                let c2 = if cabs {
                    i64::from(cc)
                } else {
                    (i64::from(cc) + dc).rem_euclid(i64::from(MAX_COL) + 1)
                };
                out += &format!(
                    "{}{}{}{}",
                    if cabs { "$" } else { "" },
                    col_name(c2 as u32),
                    if rabs { "$" } else { "" },
                    r2 + 1
                );
                i = j;
                continue;
            }
            let mut k = i;
            while k < ch.len()
                && (ch[k].is_alphanumeric() || ch[k] == '_' || ch[k] == '$' || ch[k] == '.')
            {
                out.push(ch[k]);
                k += 1;
            }
            i = k.max(i + 1);
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn cfvo(e: &Node, fc: &mut Converter, tl: (u32, u32)) -> Cfvo {
    let kind = match e.attr("calcext:type").unwrap_or("number") {
        "minimum" | "auto-minimum" => "min",
        "maximum" | "auto-maximum" => "max",
        "percentile" => "percentile",
        "percent" => "percent",
        "formula" => "formula",
        _ => "num",
    };
    let v = e
        .attr("calcext:value")
        .map(str::to_string)
        .filter(|_| kind != "min" && kind != "max");
    let val = match (kind, v) {
        ("formula", Some(f)) => fc
            .convert(&format!(
                "of:{}",
                if f.starts_with('=') {
                    f
                } else {
                    format!("={f}")
                }
            ))
            .map(|f| rebase(&f, None, tl)),
        (_, v) => v,
    };
    Cfvo { kind, val }
}

fn rule(kind: CfKind, dxf: Option<Dxf>) -> CfRule {
    CfRule {
        kind,
        dxf,
        stop: false,
        priority: 0,
    }
}

fn condition_rule(v: &str, dxf: Dxf, fc: &mut Converter, tl: (u32, u32)) -> Option<CfRule> {
    let call = |name: &str| -> Option<Vec<String>> {
        let r = v.strip_prefix(name)?.strip_prefix('(')?;
        Some(split_args(r.strip_suffix(')')?))
    };
    if let Some(a) = call("between") {
        return Some(rule(
            CfKind::CellIs {
                operator: "between",
                formulas: a.iter().filter_map(|x| conv(fc, x)).collect(),
            },
            Some(dxf),
        ));
    }
    if let Some(a) = call("not-between") {
        return Some(rule(
            CfKind::CellIs {
                operator: "notBetween",
                formulas: a.iter().filter_map(|x| conv(fc, x)).collect(),
            },
            Some(dxf),
        ));
    }
    if let Some(a) = call("formula-is") {
        return Some(rule(
            CfKind::Expression {
                formula: conv(fc, a.first()?)?,
            },
            Some(dxf),
        ));
    }
    let other = |kind: &'static str,
                 attrs: Vec<(&'static str, String)>,
                 formulas: Vec<String>,
                 dxf: Dxf| {
        Some(rule(
            CfKind::Other {
                kind,
                attrs,
                formulas,
            },
            Some(dxf),
        ))
    };
    match v.trim_end_matches("()").trim_end_matches('(') {
        "duplicate" => return other("duplicateValues", vec![], vec![], dxf),
        "unique" => return other("uniqueValues", vec![], vec![], dxf),
        "above-average" => return other("aboveAverage", vec![], vec![], dxf),
        "below-average" => {
            return other(
                "aboveAverage",
                vec![("aboveAverage", "0".into())],
                vec![],
                dxf,
            );
        }
        "above-equal-average" => {
            return other(
                "aboveAverage",
                vec![("equalAverage", "1".into())],
                vec![],
                dxf,
            );
        }
        "below-equal-average" => {
            return other(
                "aboveAverage",
                vec![("aboveAverage", "0".into()), ("equalAverage", "1".into())],
                vec![],
                dxf,
            );
        }
        "is-error" => {
            return other(
                "containsErrors",
                vec![],
                vec![format!("ISERROR({})", cell_ref(tl.0, tl.1))],
                dxf,
            );
        }
        "is-no-error" => {
            return other(
                "notContainsErrors",
                vec![],
                vec![format!("NOT(ISERROR({}))", cell_ref(tl.0, tl.1))],
                dxf,
            );
        }
        _ => {}
    }
    for (name, top, pct) in [
        ("top-elements", true, false),
        ("bottom-elements", false, false),
        ("top-percent", true, true),
        ("bottom-percent", false, true),
    ] {
        if let Some(a) = call(name) {
            let mut attrs = vec![("rank", a.first().cloned().unwrap_or_else(|| "10".into()))];
            if !top {
                attrs.push(("bottom", "1".into()));
            }
            if pct {
                attrs.push(("percent", "1".into()));
            }
            return other("top10", attrs, vec![], dxf);
        }
    }
    for (name, kind, op) in [
        ("begins-with", "beginsWith", "beginsWith"),
        ("ends-with", "endsWith", "endsWith"),
        ("contains-text", "containsText", "containsText"),
        ("not-contains-text", "notContainsText", "notContains"),
    ] {
        if let Some(a) = call(name) {
            let lit = a.first()?.clone();
            let text = lit.trim_matches('"').replace("\"\"", "\"");
            let cell = cell_ref(tl.0, tl.1);
            let f = match kind {
                "beginsWith" => format!("LEFT({cell},LEN({lit}))={lit}"),
                "endsWith" => format!("RIGHT({cell},LEN({lit}))={lit}"),
                "containsText" => format!("NOT(ISERROR(SEARCH({lit},{cell})))"),
                _ => format!("ISERROR(SEARCH({lit},{cell}))"),
            };
            return other(
                kind,
                vec![("operator", op.into()), ("text", text)],
                vec![f],
                dxf,
            );
        }
    }
    let (op, val) = split_op(v);
    if val.is_empty() {
        return None;
    }
    Some(rule(
        CfKind::CellIs {
            operator: op,
            formulas: vec![conv(fc, val)?],
        },
        Some(dxf),
    ))
}

fn read_cond_format(cf: &Node, doc: &mut Doc) -> Option<CondFormat> {
    let addr = cf.attr("calcext:target-range-address")?;
    let ranges: Vec<Range> = super::split_ranges(addr)
        .take(1024)
        .filter_map(|a| parse_range_addr(a).map(|x| x.1))
        .collect();
    let tl = ranges.iter().map(|r| (r.r1, r.c1)).min()?;
    let mut rules = vec![];
    for c in cf.nodes().take(1024) {
        match c.name.as_str() {
            "calcext:condition" => {
                let v = c.attr("calcext:value").unwrap_or("");
                let dxf = c
                    .attr("calcext:apply-style-name")
                    .map(|s| doc.st.dxf(s, false))
                    .unwrap_or_default();
                if let Some(r) = condition_rule(v, dxf, &mut doc.fc, tl) {
                    rules.push(r);
                }
            }
            "calcext:color-scale" => {
                let mut cfvos = vec![];
                let mut colors = vec![];
                for e in c.all("calcext:color-scale-entry").take(3) {
                    cfvos.push(cfvo(e, &mut doc.fc, tl));
                    colors.push(
                        e.attr("calcext:color")
                            .and_then(parse_color)
                            .flatten()
                            .unwrap_or(0),
                    );
                }
                if cfvos.len() >= 2 {
                    rules.push(rule(CfKind::ColorScale { cfvos, colors }, None));
                }
            }
            "calcext:data-bar" => {
                let entries: Vec<&Node> = c.all("calcext:formatting-entry").collect();
                let min = entries.first().map_or(
                    Cfvo {
                        kind: "min",
                        val: None,
                    },
                    |e| cfvo(e, &mut doc.fc, tl),
                );
                let max = entries.get(1).map_or(
                    Cfvo {
                        kind: "max",
                        val: None,
                    },
                    |e| cfvo(e, &mut doc.fc, tl),
                );
                let color = c
                    .attr("calcext:positive-color")
                    .and_then(parse_color)
                    .flatten()
                    .unwrap_or(0x638EC6);
                rules.push(rule(CfKind::DataBar { min, max, color }, None));
            }
            "calcext:date-is" => {
                let dxf = c
                    .attr("calcext:style")
                    .map(|s| doc.st.dxf(s, false))
                    .unwrap_or_default();
                let period = match c.attr("calcext:date").unwrap_or("today") {
                    "yesterday" => "yesterday",
                    "tomorrow" => "tomorrow",
                    "last-7-days" => "last7Days",
                    "this-week" => "thisWeek",
                    "last-week" => "lastWeek",
                    "next-week" => "nextWeek",
                    "this-month" => "thisMonth",
                    "last-month" => "lastMonth",
                    "next-month" => "nextMonth",
                    _ => "today",
                };
                rules.push(rule(
                    CfKind::Other {
                        kind: "timePeriod",
                        attrs: vec![("timePeriod", period.into())],
                        formulas: vec![],
                    },
                    Some(dxf),
                ));
            }
            "calcext:icon-set" => {
                let set = c
                    .attr("calcext:icon-set-type")
                    .unwrap_or("3Arrows")
                    .to_string();
                let cfvos = c
                    .all("calcext:formatting-entry")
                    .take(5)
                    .map(|e| cfvo(e, &mut doc.fc, tl))
                    .collect();
                rules.push(rule(
                    CfKind::IconSet {
                        set,
                        cfvos,
                        reverse: false,
                        show_value: c.attr("calcext:show-value") != Some("false"),
                    },
                    None,
                ));
            }
            _ => {}
        }
    }
    (!rules.is_empty()).then_some(CondFormat { ranges, rules })
}

/// Older documents' conditions on cell styles: each style with maps is a
/// conditional format over the cells that have it.
/// Conditions of cell styles (style:map), over the cells of each style the
/// table reader noted (`Doc::note_maps`).
fn read_style_maps(sheet: &mut Sheet, doc: &mut Doc, by_style: HashMap<String, Vec<(u32, u32)>>) {
    let mut names: Vec<String> = by_style.keys().cloned().collect();
    names.sort();
    for name in names {
        let maps = doc
            .st
            .defs
            .get(&name)
            .map(|d| d.maps.clone())
            .unwrap_or_default();
        let cells = &by_style[&name];
        let ranges = column_runs(cells);
        let tl = ranges.iter().map(|r| (r.r1, r.c1)).min().unwrap_or((0, 0));
        let mut rules = vec![];
        for (cond, apply, base) in maps {
            let dxf = doc.st.dxf(&apply, true);
            let base = base.as_deref().and_then(parse_addr).map(|a| (a.1, a.2));
            let c = cond.trim();
            let between = |r: &str, fc: &mut Converter| -> Vec<String> {
                split_args(r.strip_suffix(')').unwrap_or(r))
                    .iter()
                    .filter_map(|x| conv(fc, x))
                    .map(|f| rebase(&f, base, tl))
                    .collect()
            };
            let kind = if let Some(r) = c.strip_prefix("cell-content-is-between(") {
                Some(CfKind::CellIs {
                    operator: "between",
                    formulas: between(r, &mut doc.fc),
                })
            } else if let Some(r) = c.strip_prefix("cell-content-is-not-between(") {
                Some(CfKind::CellIs {
                    operator: "notBetween",
                    formulas: between(r, &mut doc.fc),
                })
            } else if let Some(r) = c.strip_prefix("is-true-formula(") {
                conv(&mut doc.fc, r.strip_suffix(')').unwrap_or(r)).map(|f| CfKind::Expression {
                    formula: rebase(&f, base, tl),
                })
            } else if let Some(r) = c.strip_prefix("cell-content()") {
                let (op, v) = split_op(r);
                conv(&mut doc.fc, v).map(|f| CfKind::CellIs {
                    operator: op,
                    formulas: vec![rebase(&f, base, tl)],
                })
            } else {
                None
            };
            if let Some(k) = kind {
                rules.push(rule(k, Some(dxf)));
            }
        }
        if !rules.is_empty() {
            sheet.cond_formats.push(CondFormat { ranges, rules });
        }
    }
}

/// Single cells joined into column runs.
fn column_runs(cells: &[(u32, u32)]) -> Vec<Range> {
    let mut v: Vec<(u32, u32)> = cells.to_vec();
    v.sort_by_key(|&(r, c)| (c, r));
    let mut out: Vec<Range> = vec![];
    for (r, c) in v {
        if let Some(l) = out.last_mut()
            && l.c1 == c
            && l.r2 + 1 == r
        {
            l.r2 = r;
            continue;
        }
        out.push(Range::cell(r, c));
    }
    out
}

pub(crate) fn read_table_cfs(t: &Node, doc: &mut Doc, _wb: &mut Workbook, sheet: &mut Sheet) {
    let mapped = std::mem::take(&mut doc.map_cells);
    match t.child("calcext:conditional-formats") {
        Some(cfs) => {
            for cf in cfs.all("calcext:conditional-format").take(4096) {
                if let Some(c) = read_cond_format(cf, doc) {
                    // The same rules over the same cells again change nothing.
                    if !sheet
                        .cond_formats
                        .iter()
                        .any(|x| x.ranges == c.ranges && x.rules == c.rules)
                    {
                        sheet.cond_formats.push(c);
                    }
                }
            }
        }
        None => read_style_maps(sheet, doc, mapped),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shifting_references() {
        assert_eq!(
            shift_refs("A1+$B$2+B$3+\"A1\"+'S A1'!C4", 1, 2),
            "C2+$B$2+D$3+\"A1\"+'S A1'!E5"
        );
        assert_eq!(shift_refs("SUM(A1)", 0, 1), "SUM(B1)");
        assert_eq!(shift_refs("LOG10(A1)", 1, 0), "LOG10(A2)");
    }
}
