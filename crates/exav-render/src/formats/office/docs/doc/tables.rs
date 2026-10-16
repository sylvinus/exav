//! Table rows ([MS-DOC] 2.4.3): the modifiers of a row mark define its cells.

use super::props::{brc, brc80, colorref, shd, shd80};
use super::sprm::{parse, Prl};
use crate::formats::office::common::bytes::{u16_at, Cur};
use crate::formats::office::docs::grid::{self, CellIn, RowIn};
use crate::formats::office::docs::model::*;

#[derive(Clone, Debug, Default)]
pub struct Tc {
    /// 0 none, 1 merged into the cell before, 2 or 3 first of a merged set.
    pub merge_h: u8,
    /// 0 none, 1 merged with the cell above, 3 first of a merged set.
    pub merge_v: u8,
    pub v_align: u8,
    pub text_flow: u8,
    pub fit_text: bool,
    pub no_wrap: bool,
    pub width: Option<Width>,
    /// top, left, bottom, right: `None` inherits, `Some(None)` is no border.
    pub borders: [Option<Option<Border>>; 4],
    pub shading: Option<Shading>,
    pub margins: Margins,
}

#[derive(Clone, Debug, Default)]
pub struct Tap {
    /// Positions of the cell edges, twips from the margin.
    pub edges: Vec<i32>,
    pub tcs: Vec<Tc>,
    pub borders: TableBorders,
    pub height: Option<i32>,
    pub header: bool,
    pub cant_split: bool,
    pub jc: Option<Jc>,
    pub gap_half: Option<i32>,
    pub left: Option<i32>,
    pub width: Option<Width>,
    pub bidi: bool,
    pub margins: Margins,
    pub spacing: Option<i32>,
    pub width_before: Option<Width>,
    pub width_after: Option<Width>,
    pub style: Option<u16>,
}

fn fts(f: u8, w: u16) -> Option<Width> {
    match f {
        0 => Some(Width::Auto),
        2 => Some(Width::Pct(i32::from(w))),
        3 => Some(Width::Twips(i32::from(w))),
        _ => None,
    }
}

fn tc80(b: &[u8]) -> Tc {
    let g = u16_at(b, 0);
    let mut tc = Tc {
        merge_h: (g & 3) as u8,
        text_flow: ((g >> 2) & 7) as u8,
        merge_v: ((g >> 5) & 3) as u8,
        v_align: ((g >> 7) & 3) as u8,
        fit_text: g & 0x1000 != 0,
        no_wrap: g & 0x2000 != 0,
        width: fts(((g >> 9) & 7) as u8, u16_at(b, 2)),
        ..Tc::default()
    };
    for i in 0..4 {
        let v = b.get(4 + 4 * i..8 + 4 * i).unwrap_or(&[0; 4]);
        tc.borders[i] = if v == [0, 0, 0, 0] {
            None
        } else if v == [0xFF; 4] {
            Some(None)
        } else {
            Some(brc80(v))
        };
    }
    tc
}

fn itc(tap: &mut Tap, first: usize, lim: usize, f: impl Fn(&mut Tc)) {
    for i in first..lim.min(tap.tcs.len()) {
        f(&mut tap.tcs[i]);
    }
}

fn apply_brcs(tc: &mut Tc, which: u8, b: Option<Border>, nil: bool) {
    let v = if nil { Some(None) } else { Some(b) };
    for (bit, k) in [(1u8, 0usize), (2, 1), (4, 2), (8, 3)] {
        if which & bit != 0 {
            tc.borders[k] = v.clone();
        }
    }
}

fn border_set(tap: &mut Tap, which: u8, b: Option<Border>) {
    // Bits for the inside lines apply to the table.
    if which & 0x10 != 0 {
        tap.borders.inside_h = b.clone();
    }
    if which & 0x20 != 0 {
        tap.borders.inside_v = b;
    }
}

fn margins_of(grf: u8, w: i32, m: &mut Margins) {
    if grf & 1 != 0 {
        m.top = Some(w);
    }
    if grf & 2 != 0 {
        m.left = Some(w);
    }
    if grf & 4 != 0 {
        m.bottom = Some(w);
    }
    if grf & 8 != 0 {
        m.right = Some(w);
    }
}

/// The table properties a row mark's modifiers describe.
pub fn parse_tap(grpprl: &[u8]) -> Tap {
    let mut t = Tap::default();
    for p in parse(grpprl) {
        if p.sgc() != super::sprm::SGC_TABLE {
            continue;
        }
        apply(&mut t, &p);
    }
    t
}

fn tbl_borders(t: &mut Tap, v: &[u8], size: usize, f: fn(&[u8]) -> Option<Border>) {
    let get = |i: usize| v.get(i * size..(i + 1) * size).and_then(f);
    t.borders.top = get(0);
    t.borders.left = get(1);
    t.borders.bottom = get(2);
    t.borders.right = get(3);
    t.borders.inside_h = get(4);
    t.borders.inside_v = get(5);
}

fn apply(t: &mut Tap, p: &Prl) {
    match p.op {
        0xD608 => {
            let v = p.var();
            let n = usize::from(v.first().copied().unwrap_or(0)).min(63);
            t.edges = (0..=n)
                .map(|i| i32::from(u16_at(v, 1 + 2 * i) as i16))
                .collect();
            let base = 1 + 2 * (n + 1);
            t.tcs = (0..n)
                .map(|i| {
                    let s = base + 20 * i;
                    match v.get(s..s + 20) {
                        Some(b) => tc80(b),
                        None => Tc::default(),
                    }
                })
                .collect();
        }
        0xD605 => tbl_borders(t, p.var(), 4, brc80),
        0xD613 => tbl_borders(t, p.var(), 8, brc),
        0xD609 | 0xD612 | 0xD616 | 0xD60C | 0xD670 | 0xD671 | 0xD672 => {
            let start = match p.op {
                0xD616 | 0xD671 => 22,
                0xD60C | 0xD672 => 44,
                _ => 0,
            };
            let v = p.var();
            let size = if p.op == 0xD609 { 2 } else { 10 };
            for (k, c) in v.chunks_exact(size).enumerate() {
                let sh = if size == 2 {
                    shd80(u16_at(c, 0))
                } else {
                    shd(c)
                };
                if let Some(tc) = t.tcs.get_mut(start + k) {
                    tc.shading = sh;
                }
            }
        }
        0xD62D | 0xD62E => {
            let v = p.var();
            if let [a, b, rest @ ..] = v {
                let sh = shd(rest);
                itc(t, usize::from(*a), usize::from(*b), |c| {
                    c.shading = sh.clone()
                });
            }
        }
        0xD62F => {
            let v = p.var();
            if let [a, b, which, rest @ ..] = v {
                let bd = brc(rest);
                let nil = rest.len() >= 8 && rest[4..8] == [0xFF; 4];
                let (which, bd2) = (*which, bd.clone());
                itc(t, usize::from(*a), usize::from(*b), |c| {
                    apply_brcs(c, which, bd2.clone(), nil)
                });
                border_set(t, which, bd);
            }
        }
        0xD620 => {
            let v = p.var();
            if let [a, b, which, rest @ ..] = v {
                let bd = brc80(rest);
                let nil = rest.len() >= 4 && rest[..4] == [0xFF; 4];
                let (which, bd2) = (*which, bd.clone());
                itc(t, usize::from(*a), usize::from(*b), |c| {
                    apply_brcs(c, which, bd2.clone(), nil)
                });
                border_set(t, which, bd);
            }
        }
        0xD62B => {
            if let [i, f, ..] = p.var() {
                let f = *f;
                itc(t, usize::from(*i), usize::from(*i) + 1, |c| c.merge_v = f);
            }
        }
        0xD62C => {
            if let [a, b, va, ..] = p.var() {
                let va = *va;
                itc(t, usize::from(*a), usize::from(*b), |c| c.v_align = va);
            }
        }
        0xD635 => {
            if let [a, b, f, w0, w1, ..] = p.var() {
                let w = fts(*f, u16::from_le_bytes([*w0, *w1]));
                itc(t, usize::from(*a), usize::from(*b), |c| c.width = w);
            }
        }
        0xD639 => {
            if let [a, b, ..] = p.var() {
                itc(t, usize::from(*a), usize::from(*b), |c| c.no_wrap = true);
            }
        }
        0xD632 | 0xD634 => {
            if let [a, b, grf, _f, w0, w1, ..] = p.var() {
                let w = i32::from(u16::from_le_bytes([*w0, *w1]));
                if p.op == 0xD634 {
                    margins_of(*grf, w, &mut t.margins);
                } else {
                    let grf = *grf;
                    itc(t, usize::from(*a), usize::from(*b), |c| {
                        margins_of(grf, w, &mut c.margins)
                    });
                }
            }
        }
        0xD633 => {
            if let [_, _, _, _, w0, w1, ..] = p.var() {
                t.spacing = Some(i32::from(u16::from_le_bytes([*w0, *w1])));
            }
        }
        0x9407 => {
            let v = i32::from(p.i16());
            t.height = (v != 0).then_some(v);
        }
        0x3404 => t.header = p.u8() & 1 != 0,
        0x3403 | 0x3466 => t.cant_split = p.u8() & 1 != 0,
        0x5400 | 0x548A => {
            t.jc = Some(match p.u16() {
                1 => Jc::Center,
                2 => Jc::Right,
                _ => Jc::Left,
            })
        }
        0x9601 => t.left = Some(i32::from(p.i16())),
        0x9602 => t.gap_half = Some(i32::from(p.i16())),
        0xF614 => {
            if let [f, w0, w1, ..] = p.val {
                t.width = fts(*f, u16::from_le_bytes([*w0, *w1]));
            }
        }
        0xF617 => {
            if let [f, w0, w1, ..] = p.val {
                t.width_before = fts(*f, u16::from_le_bytes([*w0, *w1]));
            }
        }
        0xF618 => {
            if let [f, w0, w1, ..] = p.val {
                t.width_after = fts(*f, u16::from_le_bytes([*w0, *w1]));
            }
        }
        0x560B | 0x5664 => t.bidi = p.u16() & 1 != 0,
        0x563A => t.style = Some(p.u16()),
        0x7621 => {
            // sprmTInsert: itcFirst, ctc, dxaCol.
            let mut c = Cur::new(p.val);
            let first = usize::from(c.u8());
            let n = usize::from(c.u8());
            let dxa = i32::from(c.u16());
            if first <= t.tcs.len() && n > 0 && t.tcs.len() + n <= 63 {
                if t.edges.is_empty() {
                    t.edges.push(0);
                }
                for k in 0..n {
                    t.tcs.insert(first + k, Tc::default());
                }
                // Shift the edges after the inserted cells.
                let at = first.min(t.edges.len() - 1);
                let base = t.edges[at];
                for e in t.edges.iter_mut().skip(at + 1) {
                    *e += dxa * n as i32;
                }
                for k in 0..n {
                    t.edges.insert(at + 1 + k, base + dxa * (k as i32 + 1));
                }
                t.edges.truncate(t.tcs.len() + 1);
            }
        }
        0x5622 => {
            if let [a, b, ..] = p.val {
                let (a, b) = (usize::from(*a), usize::from(*b).min(t.tcs.len()));
                if a < b && b - a < t.tcs.len() {
                    let w: i32 =
                        t.edges.get(b).copied().unwrap_or(0) - t.edges.get(a).copied().unwrap_or(0);
                    t.tcs.drain(a..b);
                    if a < t.edges.len() {
                        t.edges.drain(a + 1..(b + 1).min(t.edges.len()));
                        for e in t.edges.iter_mut().skip(a + 1) {
                            *e -= w;
                        }
                    }
                }
            }
        }
        0x7623 => {
            if let [a, b, w0, w1, ..] = p.val {
                let w = i32::from(u16::from_le_bytes([*w0, *w1]));
                let (a, b) = (usize::from(*a), usize::from(*b).min(t.tcs.len()));
                for i in a..b {
                    if i + 1 < t.edges.len() {
                        let delta = (t.edges[i] + w) - t.edges[i + 1];
                        for e in t.edges.iter_mut().skip(i + 1) {
                            *e += delta;
                        }
                    }
                }
            }
        }
        0x5624 => {
            if let [a, b, ..] = p.val {
                let (a, b) = (usize::from(*a), usize::from(*b).min(t.tcs.len()));
                for i in a..b {
                    t.tcs[i].merge_h = if i == a { 2 } else { 1 };
                }
            }
        }
        0x5625 => {
            if let [a, b, ..] = p.val {
                let (a, b) = (usize::from(*a), usize::from(*b).min(t.tcs.len()));
                for i in a..b {
                    t.tcs[i].merge_h = 0;
                }
            }
        }
        0xD60A | 0xD62A => {}
        _ => {
            let _ = colorref;
        }
    }
}

/// A table from its rows: the cell edges of every row make up the grid; a
/// cell spans the grid columns between its edges.
pub fn build(rows: Vec<(Tap, Vec<Vec<Block>>)>) -> Table {
    let mut props = TableProps::default();
    if let Some((t, _)) = rows.first() {
        let gap = t.gap_half.unwrap_or(108);
        props.cell_margins = Margins {
            top: None,
            left: Some(gap),
            bottom: None,
            right: Some(gap),
        };
        props.borders = t.borders.clone();
        props.jc = t.jc;
        props.bidi = t.bidi;
        props.cell_spacing = t.spacing.filter(|s| *s > 0);
        props.indent = Some(t.edges.first().copied().unwrap_or(0) + gap);
        props.width = t.width.filter(|w| *w != Width::Auto);
    }
    let mut rows_in = vec![];
    for (tap, contents) in rows {
        let mut row = RowIn {
            edges: tap.edges.clone(),
            props: RowProps::default(),
            cells: vec![],
        };
        row.props.height = tap.height.map(i32::abs);
        row.props.height_exact = tap.height.is_some_and(|h| h < 0);
        row.props.header = tap.header;
        row.props.cant_split = tap.cant_split;
        let n = tap.tcs.len().min(tap.edges.len().saturating_sub(1));
        let mut contents = contents.into_iter();
        for k in 0..n {
            let tc = &tap.tcs[k];
            let content = contents.next().unwrap_or_default();
            let mut cp = CellProps {
                v_merge: match tc.merge_v {
                    3 => VMerge::Restart,
                    1 => VMerge::Continue,
                    _ => VMerge::None,
                },
                shading: tc.shading.clone(),
                v_align: match tc.v_align {
                    1 => Some(VAlign::Center),
                    2 => Some(VAlign::Bottom),
                    _ => None,
                },
                no_wrap: tc.no_wrap,
                fit_text: tc.fit_text,
                margins: tc.margins.clone(),
                ..CellProps::default()
            };
            cp.text_direction = match tc.text_flow {
                1 => Some("tbRl"),
                3 => Some("btLr"),
                _ => None,
            };
            for (slot, b) in [
                (&mut cp.borders.top, &tc.borders[0]),
                (&mut cp.borders.left, &tc.borders[1]),
                (&mut cp.borders.bottom, &tc.borders[2]),
                (&mut cp.borders.right, &tc.borders[3]),
            ] {
                *slot = match b {
                    None => None,
                    Some(Some(b)) => Some(b.clone()),
                    Some(None) => Some(Border {
                        style: "nil",
                        size: 0,
                        space: 0,
                        color: Color::Auto,
                        shadow: false,
                    }),
                };
            }
            row.cells.push(CellIn {
                props: cp,
                content,
                merged_left: tc.merge_h == 1,
            });
        }
        // Content past the cells goes into the last one.
        let extra: Vec<Vec<Block>> = contents.collect();
        if let Some(last) = row.cells.last_mut() {
            for e in extra {
                last.content.extend(e);
            }
        }
        rows_in.push(row);
    }
    grid::build(rows_in, props)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def_table(edges: &[i16], tcs: &[[u8; 20]]) -> Vec<u8> {
        let n = edges.len() - 1;
        let mut body = vec![n as u8];
        for e in edges {
            body.extend_from_slice(&e.to_le_bytes());
        }
        for t in tcs {
            body.extend_from_slice(t);
        }
        let mut g = vec![0x08, 0xD6];
        g.extend_from_slice(&((body.len() + 1) as u16).to_le_bytes());
        g.extend_from_slice(&body);
        g
    }

    #[test]
    fn cell_edges_and_merges() {
        let mut first = [0u8; 20];
        first[0] = 2; // first of a merged set
        let mut second = [0u8; 20];
        second[0] = 1;
        let g = def_table(&[0, 1000, 2000, 3000], &[first, second, [0; 20]]);
        let t = parse_tap(&g);
        assert_eq!(t.edges, vec![0, 1000, 2000, 3000]);
        assert_eq!(t.tcs.len(), 3);
        assert_eq!((t.tcs[0].merge_h, t.tcs[1].merge_h), (2, 1));
    }

    #[test]
    fn shading_in_the_two_byte_form() {
        let mut g = def_table(&[0, 1000, 2000], &[[0; 20], [0; 20]]);
        // sprmTDefTableShd80: the first cell none, the second a yellow
        // background (colour 8 is white over 7, yellow, with no pattern).
        g.extend_from_slice(&[0x09, 0xD6, 4, 0xFF, 0xFF, 0x08 | 7 << 5, 0]);
        let t = parse_tap(&g);
        assert!(t.tcs[0].shading.is_none());
        let s = t.tcs[1].shading.as_ref().unwrap();
        assert_eq!(s.fill, Some(Color::Rgb(0xFFFF00)));
    }

    #[test]
    fn row_height_header_and_shading() {
        let mut g = def_table(&[0, 1000, 2000], &[[0; 20], [0; 20]]);
        // exact 300 (negative), header row, shading of the second cell.
        g.extend_from_slice(&[0x07, 0x94, 0xD4, 0xFE, 0x04, 0x34, 1]);
        g.extend_from_slice(&[0x12, 0xD6, 20]);
        // The first cell has no shading (automatic colours, no pattern); the
        // second a solid pattern of red.
        g.extend_from_slice(&[0, 0, 0, 0xFF, 0, 0, 0, 0xFF, 0, 0]);
        g.extend_from_slice(&[0xFF, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0, 1, 0]);
        let t = parse_tap(&g);
        assert_eq!(t.height, Some(-300));
        assert!(t.header);
        assert!(t.tcs[0].shading.is_none());
        assert!(t.tcs[1].shading.is_some());
    }
}
