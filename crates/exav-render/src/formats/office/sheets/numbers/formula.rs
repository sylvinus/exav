//! Formulas: TSCE.ASTNodeArrayArchive (AST_node 1), a postfix array of
//! nodes, to Excel syntax. Node fields: AST_node_type 1,
//! AST_function_node_index 2, AST_function_node_numArgs 3,
//! AST_number_node_number 4, AST_boolean_node_boolean 5,
//! AST_string_node_string 6, AST_date_node_dateNum 7,
//! AST_duration_node_unitNum 8, AST_duration_node_unit 9,
//! AST_token_node_boolean 10, AST_array_node_numCol 11 and numRow 12,
//! AST_list_node_numArgs 13, AST_unknown_function_node_string 17 and
//! numArgs 18, AST_column 26 (column 1, absolute 2), AST_row 27 (row 1,
//! absolute 2), AST_cross_table_reference_extra_info 28 (table_id 1),
//! AST_sticky_bits 33 (begin row 1, begin column 2, end row 3, end column 4
//! absolute), AST_colon_tract 40 (relative_column 1, relative_row 2,
//! absolute_column 3, absolute_row 4, each range_begin 1 and range_end 2),
//! AST_number_node_decimal_low 42 and high 43.

use super::functions::FUNCTIONS;
use super::proto::Msg;
use crate::formats::office::sheets::model::col_name;
use std::collections::HashMap;

/// What a reference needs to know of a table.
#[derive(Clone, Debug, Default)]
pub struct TableDims {
    /// The XLSX sheet name.
    pub name: String,
    pub rows: u32,
    pub cols: u32,
    pub header_rows: u32,
    pub header_cols: u32,
    pub footer_rows: u32,
}

pub struct Refs<'a> {
    pub tables: &'a [TableDims],
    /// Table UUIDs, as cross-table references name them, to tables.
    pub by_uuid: &'a HashMap<u128, usize>,
    pub host: usize,
}

/// A CFUUIDArchive (uuid_w0 2 to uuid_w3 5).
pub fn cfuuid(m: Msg) -> Option<u128> {
    let w = |n| m.uint(n).map(|v| u128::from(v as u32));
    Some(w(5)? << 96 | w(4)? << 64 | w(3)? << 32 | w(2)?)
}

/// A TSP.UUID (lower 1, upper 2).
pub fn uuid(m: Msg) -> Option<u128> {
    Some(u128::from(m.uint(2)?) << 64 | u128::from(m.uint(1)?))
}

// Excel operator precedence, higher binds tighter.
const P_CMP: u8 = 1;
const P_CONCAT: u8 = 2;
const P_ADD: u8 = 3;
const P_MUL: u8 = 4;
const P_POW: u8 = 5;
const P_PERCENT: u8 = 6;
const P_NEG: u8 = 7;
const P_ATOM: u8 = 9;

struct Item {
    text: String,
    prec: u8,
}

const MAX_TEXT: usize = 16_384;
const MAX_NODES: usize = 1 << 16;

/// The formula of the cell at `row`, `col` of the host table; `None` when
/// it uses what Excel cannot say.
pub fn convert(ast: Msg, cx: &Refs, row: u32, col: u32) -> Option<String> {
    let mut st: Vec<Item> = vec![];
    for node in ast.msgs(1).take(MAX_NODES) {
        let kind = node.uint(1)?;
        match kind {
            1..=12 => {
                let (op, p) = match kind {
                    1 => ("+", P_ADD),
                    2 => ("-", P_ADD),
                    3 => ("*", P_MUL),
                    4 => ("/", P_MUL),
                    5 => ("^", P_POW),
                    6 => ("&", P_CONCAT),
                    7 => (">", P_CMP),
                    8 => (">=", P_CMP),
                    9 => ("<", P_CMP),
                    10 => ("<=", P_CMP),
                    11 => ("=", P_CMP),
                    _ => ("<>", P_CMP),
                };
                let b = st.pop()?;
                let a = st.pop()?;
                let l = wrap(a, p, false);
                let r = wrap(b, p, true);
                st.push(Item {
                    text: format!("{l}{op}{r}"),
                    prec: p,
                });
            }
            13 => {
                let a = st.pop()?;
                st.push(Item {
                    text: format!("-{}", wrap(a, P_NEG, false)),
                    prec: P_NEG,
                });
            }
            14 => {
                let a = st.pop()?;
                st.push(Item {
                    text: format!("+{}", wrap(a, P_NEG, false)),
                    prec: P_NEG,
                });
            }
            15 => {
                let a = st.pop()?;
                st.push(Item {
                    text: format!("{}%", wrap(a, P_PERCENT, false)),
                    prec: P_PERCENT,
                });
            }
            16 | 31 => {
                let n = if kind == 16 {
                    node.uint(3)?
                } else {
                    node.uint(18)?
                } as usize;
                let name = if kind == 16 {
                    let idx = node.uint(2)?;
                    let i = FUNCTIONS
                        .binary_search_by_key(&idx, |f| u64::from(f.0))
                        .ok()?;
                    excel_function(FUNCTIONS[i].1)
                } else {
                    node.string(17)?.to_ascii_uppercase()
                };
                if n > st.len() {
                    return None;
                }
                let args: Vec<String> = st
                    .split_off(st.len() - n)
                    .into_iter()
                    .map(|a| a.text)
                    .collect();
                st.push(Item {
                    text: format!("{name}({})", args.join(",")),
                    prec: P_ATOM,
                });
            }
            17 => {
                let v = number(node)?;
                st.push(Item {
                    text: crate::formats::office::sheets::numtext::shortest(v),
                    prec: if v < 0.0 { P_NEG } else { P_ATOM },
                });
            }
            18 | 23 => {
                let b = node
                    .boolean(if kind == 18 { 5 } else { 10 })
                    .unwrap_or(false);
                st.push(atom(if b { "TRUE" } else { "FALSE" }.into()));
            }
            19 => {
                let s = node.string(6).unwrap_or_default();
                st.push(atom(format!("\"{}\"", s.replace('"', "\"\""))));
            }
            20 => st.push(atom(date(node.double(7)?))),
            21 => st.push(atom(crate::formats::office::sheets::numtext::shortest(
                duration_days(node)?,
            ))),
            22 => st.push(atom(String::new())),
            24 => {
                let (cols, rows) = (node.uint(11)? as usize, node.uint(12)? as usize);
                let n = cols.checked_mul(rows)?;
                if n > st.len() || n == 0 {
                    return None;
                }
                let cells: Vec<String> = st
                    .split_off(st.len() - n)
                    .into_iter()
                    .map(|a| a.text)
                    .collect();
                let rows: Vec<String> = cells.chunks(cols).map(|r| r.join(",")).collect();
                st.push(atom(format!("{{{}}}", rows.join(";"))));
            }
            25 => {
                let n = node.uint(13)? as usize;
                if n > st.len() {
                    return None;
                }
                let args: Vec<String> = st
                    .split_off(st.len() - n)
                    .into_iter()
                    .map(|a| a.text)
                    .collect();
                st.push(atom(format!("({})", args.join(","))));
            }
            29 | 45 => {
                let b = st.pop()?;
                let a = st.pop()?;
                st.push(atom(join_range(&a.text, &b.text)));
            }
            30 | 46 => st.push(atom("#REF!".into())),
            32..=35 => {}
            36 | 67 => st.push(atom(reference(node, cx, row, col)?)),
            69 => {
                let b = st.pop()?;
                let a = st.pop()?;
                st.push(atom(format!("{} {}", a.text, b.text)));
            }
            70 => {
                let a = st.pop()?;
                st.push(atom(format!("{}#", a.text)));
            }
            _ => return None,
        }
        if st.last().is_some_and(|i| i.text.len() > MAX_TEXT) {
            return None;
        }
    }
    let out = st.pop()?;
    st.is_empty().then_some(out.text)
}

fn atom(text: String) -> Item {
    Item { text, prec: P_ATOM }
}

/// An operand in parentheses when its operator binds looser than `p` (or
/// as loose, on the right of a left-associative operator).
fn wrap(a: Item, p: u8, right: bool) -> String {
    if a.prec < p || (right && a.prec == p) {
        format!("({})", a.text)
    } else {
        a.text
    }
}

fn excel_function(name: &str) -> String {
    if crate::formats::office::sheets::ods::formula::XLFN.contains(&name) {
        format!("_xlfn.{name}")
    } else {
        name.to_string()
    }
}

/// A number node: its decimal when it has one, else its double.
fn number(node: Msg) -> Option<f64> {
    match (node.uint(42), node.uint(43)) {
        (Some(lo), Some(0x3040_0000_0000_0000)) => Some(lo as f64),
        (Some(lo), Some(hi)) => {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&lo.to_le_bytes());
            b[8..].copy_from_slice(&hi.to_le_bytes());
            Some(super::cells::decimal128(&b))
        }
        _ => node.double(4),
    }
}

/// A date literal, seconds since 2001-01-01, as DATE (and TIME).
fn date(secs: f64) -> String {
    if !secs.is_finite() {
        return "#VALUE!".into();
    }
    let days = (secs / 86_400.0).floor();
    let (y, m, d) = civil(days as i64 + 11_323);
    let rest = (secs - days * 86_400.0).round() as i64;
    if rest == 0 {
        format!("DATE({y},{m},{d})")
    } else {
        format!(
            "DATE({y},{m},{d})+TIME({},{},{})",
            rest / 3600,
            rest / 60 % 60,
            rest % 60
        )
    }
}

/// Days since 1970-01-01 to a civil date (H. Hinnant's algorithm).
fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A duration literal in days: unitNum 8 of unit 9 (1 week, 2 day, 4 hour,
/// 8 minute, 16 second, 32 millisecond).
fn duration_days(node: Msg) -> Option<f64> {
    let n = node.double(8)?;
    let per = match node.int(9)? {
        1 => 7.0,
        2 => 1.0,
        4 => 1.0 / 24.0,
        8 => 1.0 / 1440.0,
        16 => 1.0 / 86_400.0,
        32 => 1.0 / 86_400_000.0,
        _ => return None,
    };
    Some(n * per)
}

/// `S!A1` and `S!B2` to `S!A1:B2`.
fn join_range(a: &str, b: &str) -> String {
    match (a.rsplit_once('!'), b.rsplit_once('!')) {
        (Some((sa, ra)), Some((sb, rb))) if sa == sb => format!("{sa}!{ra}:{rb}"),
        _ => format!("{a}:{b}"),
    }
}

const WHOLE_ROWS: u64 = 0x7FFF_FFFF;
const WHOLE_COLS: u64 = 0x7FFF;

/// A cell or range reference node.
fn reference(node: Msg, cx: &Refs, row: u32, col: u32) -> Option<String> {
    let target = match node.msg(28) {
        Some(x) => {
            let id = cfuuid(x.msg(1)?)?;
            match cx.by_uuid.get(&id) {
                Some(&t) => t,
                None => return Some("#REF!".into()),
            }
        }
        None => cx.host,
    };
    let t = cx.tables.get(target)?;
    let (r0, c0) = (i64::from(row), i64::from(col));
    // (row1, col1, row2, col2, absolute flags), `None` for a whole row or
    // column side.
    let (r1, c1, r2, c2, abs) = if let Some(tract) = node.msg(40) {
        let sticky = node.msg(33).unwrap_or_default();
        let ab = [1, 2, 3, 4].map(|n| sticky.boolean(n).unwrap_or(false));
        let first = |field: u32| tract.msgs(field).next();
        let side = |abs: bool,
                    rel_f: u32,
                    abs_f: u32,
                    origin: i64,
                    end: bool,
                    whole: u64|
         -> Option<Option<i64>> {
            let pick = |m: Msg| if end { m.int(2).or(m.int(1)) } else { m.int(1) };
            if abs {
                return Some(first(abs_f).and_then(pick).map(|v| v as u32 as i64));
            }
            match first(rel_f) {
                Some(m) => Some(pick(m).map(|v| origin + i64::from(v as i32))),
                None => match first(abs_f).and_then(pick) {
                    Some(v) if v as u64 & 0xFFFF_FFFF == whole => Some(None),
                    Some(v) => Some(Some(v as u32 as i64)),
                    None => Some(None),
                },
            }
        };
        let r1 = side(ab[0], 2, 4, r0, false, WHOLE_ROWS)?;
        let r2 = side(ab[2], 2, 4, r0, true, WHOLE_ROWS)?;
        let c1 = side(ab[1], 1, 3, c0, false, WHOLE_COLS)?;
        let c2 = side(ab[3], 1, 3, c0, true, WHOLE_COLS)?;
        let whole = |v: Option<i64>, w: u64| v.filter(|&x| x as u64 != w);
        (
            whole(r1, WHOLE_ROWS),
            whole(c1, WHOLE_COLS),
            whole(r2, WHOLE_ROWS),
            whole(c2, WHOLE_COLS),
            ab,
        )
    } else {
        let rm = node.msg(27);
        let cm = node.msg(26);
        let one = |m: Option<Msg>, origin: i64| -> Option<(Option<i64>, bool)> {
            match m {
                None => Some((None, false)),
                Some(m) => {
                    let v = m.sint(1).unwrap_or(0);
                    let a = m.boolean(2).unwrap_or(false);
                    Some((Some(if a { v } else { origin + v }), a))
                }
            }
        };
        let (r, ra) = one(rm, r0)?;
        let (c, ca) = one(cm, c0)?;
        (r, c, r, c, [ra, ca, ra, ca])
    };
    let body_rows = (
        t.header_rows,
        t.rows.saturating_sub(t.footer_rows).saturating_sub(1),
    );
    let body_cols = (t.header_cols, t.cols.saturating_sub(1));
    // Whole columns cover the body rows of the table, whole rows its body
    // columns, as in Numbers.
    let (r1, r2, rows_abs) = match (r1, r2) {
        (None, None) if body_rows.0 <= body_rows.1 => {
            (i64::from(body_rows.0), i64::from(body_rows.1), true)
        }
        (None, None) => (0, i64::from(t.rows.saturating_sub(1)), true),
        (a, b) => (a.or(b)?, b.or(a)?, false),
    };
    let (c1, c2, cols_abs) = match (c1, c2) {
        (None, None) if body_cols.0 <= body_cols.1 => {
            (i64::from(body_cols.0), i64::from(body_cols.1), true)
        }
        (None, None) => (0, i64::from(t.cols.saturating_sub(1)), true),
        (a, b) => (a.or(b)?, b.or(a)?, false),
    };
    let ok = |v: i64, max: u32| (0..=i64::from(max)).contains(&v);
    if !ok(r1, crate::formats::office::sheets::model::MAX_ROW)
        || !ok(r2, crate::formats::office::sheets::model::MAX_ROW)
        || !ok(c1, crate::formats::office::sheets::model::MAX_COL)
        || !ok(c2, crate::formats::office::sheets::model::MAX_COL)
    {
        return Some("#REF!".into());
    }
    let cell = |r: i64, c: i64, ra: bool, ca: bool| {
        format!(
            "{}{}{}{}",
            if ca { "$" } else { "" },
            col_name(c as u32),
            if ra { "$" } else { "" },
            r + 1
        )
    };
    let a = cell(r1, c1, abs[0] || rows_abs, abs[1] || cols_abs);
    let text = if (r1, c1) == (r2, c2) {
        a
    } else {
        format!(
            "{a}:{}",
            cell(r2, c2, abs[2] || rows_abs, abs[3] || cols_abs)
        )
    };
    Some(if target == cx.host {
        text
    } else {
        format!(
            "{}!{text}",
            crate::formats::office::sheets::xls::formula::quote_sheet(&t.name)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::super::proto::write::W;
    use super::*;

    fn node(kind: u64) -> W {
        W::default().uint(1, kind)
    }

    fn num(v: f64) -> W {
        node(17).double(4, v)
    }

    fn cell(r: i64, c: i64, abs: bool) -> W {
        node(36)
            .msg(27, W::default().sint(1, r).uint(2, abs as u64))
            .msg(26, W::default().sint(1, c).uint(2, abs as u64))
    }

    fn run(
        nodes: Vec<W>,
        tables: &[TableDims],
        by_uuid: &HashMap<u128, usize>,
        at: (u32, u32),
    ) -> Option<String> {
        let mut ast = W::default();
        for n in nodes {
            ast = ast.msg(1, n);
        }
        convert(
            Msg(&ast.0),
            &Refs {
                tables,
                by_uuid,
                host: 0,
            },
            at.0,
            at.1,
        )
    }

    fn table(name: &str) -> TableDims {
        TableDims {
            name: name.into(),
            rows: 10,
            cols: 5,
            header_rows: 1,
            header_cols: 1,
            footer_rows: 0,
        }
    }

    #[test]
    fn operators_keep_their_grouping() {
        let t = [table("T")];
        let m = HashMap::new();
        // (1+2)*3, as postfix 1 2 + 3 *.
        assert_eq!(
            run(
                vec![num(1.0), num(2.0), node(1), num(3.0), node(3)],
                &t,
                &m,
                (0, 0)
            )
            .as_deref(),
            Some("(1+2)*3")
        );
        // 1-(2-3).
        assert_eq!(
            run(
                vec![num(1.0), num(2.0), num(3.0), node(2), node(2)],
                &t,
                &m,
                (0, 0)
            )
            .as_deref(),
            Some("1-(2-3)")
        );
        // -(2^2) and (-2)^2.
        assert_eq!(
            run(vec![num(2.0), num(2.0), node(5), node(13)], &t, &m, (0, 0)).as_deref(),
            Some("-(2^2)")
        );
        assert_eq!(
            run(vec![num(2.0), node(13), num(2.0), node(5)], &t, &m, (0, 0)).as_deref(),
            Some("-2^2")
        );
        // SUM(1,2): function index 168 is SUM.
        let sum = FUNCTIONS.iter().find(|f| f.1 == "SUM").unwrap().0;
        assert_eq!(
            run(
                vec![num(1.0), num(2.0), node(16).uint(2, sum.into()).uint(3, 2)],
                &t,
                &m,
                (0, 0)
            )
            .as_deref(),
            Some("SUM(1,2)")
        );
        // A stack left with two items is refused.
        assert_eq!(run(vec![num(1.0), num(2.0)], &t, &m, (0, 0)), None);
    }

    #[test]
    fn references() {
        let t = [table("T"), table("Sheet 2 - T")];
        let mut m = HashMap::new();
        m.insert(7u128 << 96 | 1, 1);
        // Relative to the host cell (2, 1): one row up, same column.
        assert_eq!(
            run(vec![cell(-1, 0, false)], &t, &m, (2, 1)).as_deref(),
            Some("B2")
        );
        assert_eq!(
            run(vec![cell(0, 2, true)], &t, &m, (2, 1)).as_deref(),
            Some("$C$1")
        );
        let xt = W::default().msg(1, W::default().uint(2, 1).uint(3, 0).uint(4, 0).uint(5, 7));
        assert_eq!(
            run(vec![cell(3, 3, true).msg(28, xt.clone())], &t, &m, (0, 0)).as_deref(),
            Some("'Sheet 2 - T'!$D$4")
        );
        // An unknown table.
        let bad = W::default().msg(1, W::default().uint(2, 9).uint(3, 0).uint(4, 0).uint(5, 0));
        assert_eq!(
            run(vec![cell(0, 0, true).msg(28, bad)], &t, &m, (0, 0)).as_deref(),
            Some("#REF!")
        );
        // Whole column B of T: its body rows, 2 to 10.
        let tract = W::default()
            .msg(3, W::default().uint(1, 1).uint(2, 1))
            .msg(4, W::default().uint(1, 0x7FFF_FFFF).uint(2, 0x7FFF_FFFF));
        let sticky = W::default().uint(1, 0).uint(2, 1).uint(3, 0).uint(4, 1);
        assert_eq!(
            run(
                vec![node(67).msg(40, tract).msg(33, sticky)],
                &t,
                &m,
                (0, 0)
            )
            .as_deref(),
            Some("$B$2:$B$10")
        );
    }

    #[test]
    fn literals() {
        let t = [table("T")];
        let m = HashMap::new();
        // 2001-01-02 12:00.
        assert_eq!(
            run(
                vec![node(20).double(7, 86_400.0 + 43_200.0)],
                &t,
                &m,
                (0, 0)
            )
            .as_deref(),
            Some("DATE(2001,1,2)+TIME(12,0,0)")
        );
        assert_eq!(
            run(vec![node(19).bytes(6, b"a\"b")], &t, &m, (0, 0)).as_deref(),
            Some("\"a\"\"b\"")
        );
        assert_eq!(
            run(
                vec![node(17).uint(42, 5).uint(43, 0x3040_0000_0000_0000)],
                &t,
                &m,
                (0, 0)
            )
            .as_deref(),
            Some("5")
        );
    }
}
