//! Tables ([ODF 1.2] 9): columns, rows, cells and their spans.

use super::{Odt, props};
use crate::formats::office::common::odf::{self, Props};
use crate::formats::office::common::xml::Node;
use crate::formats::office::docs::error::Result;
use crate::formats::office::docs::model::*;

const MAX_COLUMNS: usize = 1024;
const MAX_REPEAT_ROWS: usize = 1 << 12;

struct Col {
    width: Option<i32>,
    rel: Option<f64>,
    style: Option<String>,
}

fn collect_rows<'a>(n: &'a Node, header: bool, out: &mut Vec<(&'a Node, bool)>) {
    for c in n.nodes() {
        match c.name.as_str() {
            "table:table-row" => out.push((c, header)),
            "table:table-header-rows" => collect_rows(c, true, out),
            "table:table-rows" | "table:table-row-group" => collect_rows(c, header, out),
            _ => {}
        }
    }
}

fn collect_cols<'a>(n: &'a Node, out: &mut Vec<&'a Node>) {
    for c in n.nodes() {
        match c.name.as_str() {
            "table:table-column" => out.push(c),
            "table:table-columns" | "table:table-header-columns" | "table:table-column-group" => {
                collect_cols(c, out)
            }
            _ => {}
        }
    }
}

fn repeat(n: &Node, key: &str, max: usize) -> usize {
    n.attr(key)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, max)
}

impl Odt<'_> {
    pub(crate) fn table(&mut self, n: &Node) -> Result<Option<Table>> {
        if self.depth > 16 {
            return Ok(None);
        }
        let ap = n
            .attr("table:style-name")
            .map(|s| self.apply("table", s))
            .unwrap_or_default();
        let tp: &Props = &ap.props;
        // Columns.
        let mut cols: Vec<Col> = vec![];
        let mut nodes = vec![];
        collect_cols(n, &mut nodes);
        for c in nodes {
            let r = repeat(c, "table:number-columns-repeated", MAX_COLUMNS);
            let style = c
                .attr("table:style-name")
                .map(|s| self.apply("table-column", s));
            let width = style
                .as_ref()
                .and_then(|s| s.props.twips("table-column/style:column-width"));
            let rel = style.as_ref().and_then(|s| {
                s.props
                    .get("table-column/style:rel-column-width")
                    .and_then(|v| v.trim_end_matches('*').parse::<f64>().ok())
            });
            let default_style = c.attr("table:default-cell-style-name").map(str::to_string);
            for _ in 0..r {
                if cols.len() >= MAX_COLUMNS {
                    break;
                }
                cols.push(Col {
                    width,
                    rel,
                    style: default_style.clone(),
                });
            }
        }
        let table_width = tp.twips("table/style:width").or_else(|| {
            tp.get("table/style:rel-width")
                .and_then(odf::percent)
                .map(|p| (p * 9000.0) as i32)
        });
        let total = table_width.unwrap_or(9000);
        let abs_sum: i32 = cols.iter().filter_map(|c| c.width).sum();
        let rel_sum: f64 = cols
            .iter()
            .filter(|c| c.width.is_none())
            .filter_map(|c| c.rel)
            .sum();
        let unspec = cols
            .iter()
            .filter(|c| c.width.is_none() && c.rel.is_none())
            .count();
        let mut grid: Vec<i32> = vec![];
        for c in &cols {
            let w = match (c.width, c.rel) {
                (Some(w), _) => w,
                (None, Some(r)) if rel_sum > 0.0 => {
                    ((total - abs_sum).max(0) as f64 * r / rel_sum) as i32
                }
                _ => ((total - abs_sum).max(0) / unspec.max(1) as i32).max(100),
            };
            grid.push(w.max(1));
        }
        // Rows.
        let mut rows = vec![];
        collect_rows(n, false, &mut rows);
        let mut table = Table::default();
        table.props.fixed_layout = true;
        table.props.width = Some(
            table_width
                .map(Width::Twips)
                .unwrap_or(Width::Twips(grid.iter().sum())),
        );
        if let Some(pc) = tp.get("table/style:rel-width").and_then(odf::percent) {
            table.props.width = Some(Width::Pct((pc * 5000.0) as i32));
        }
        table.props.jc = match tp.get("table/table:align") {
            Some("center") => Some(Jc::Center),
            Some("right") => Some(Jc::Right),
            _ => None,
        };
        if let Some(l) = tp.twips("table/fo:margin-left") {
            table.props.indent = Some(l);
        }
        if tp
            .get("table/style:writing-mode")
            .is_some_and(|w| w.starts_with("rl"))
        {
            table.props.bidi = true;
        }
        table.props.shading = tp
            .get("table/fo:background-color")
            .and_then(odf::color)
            .map(|c| Shading::fill(Color::Rgb(c)));
        // Cell margins default to none in ODF: the cells carry their padding.
        table.props.cell_margins = Margins {
            top: Some(0),
            left: Some(0),
            bottom: Some(0),
            right: Some(0),
        };
        let ncols = grid.len().max(1);
        table.grid = if grid.is_empty() {
            vec![9000]
        } else {
            grid.clone()
        };
        // Spans going down: (rows left, first column, columns).
        let mut down: Vec<(usize, usize, usize)> = vec![(0, 0, 0); ncols + 1];
        self.depth += 1;
        let mut res = Ok(());
        'rows: for (rn, header) in rows {
            let times = repeat(rn, "table:number-rows-repeated", MAX_REPEAT_ROWS);
            let rap = rn
                .attr("table:style-name")
                .map(|s| self.apply("table-row", s))
                .unwrap_or_default();
            for _ in 0..times {
                let active = down.clone();
                let mut row = Row::default();
                row.props.header = header;
                if let Some(h) = rap.props.twips("table-row/style:row-height") {
                    row.props.height = Some(h);
                    row.props.height_exact = true;
                } else if let Some(h) = rap.props.twips("table-row/style:min-row-height") {
                    row.props.height = Some(h);
                }
                if rap.props.get("table-row/fo:keep-together") == Some("always") {
                    row.props.cant_split = true;
                }
                let mut col = 0usize;
                let mut covered_left = 0usize;
                for cell in rn.nodes() {
                    let covered = cell.name == "table:covered-table-cell";
                    if cell.name != "table:table-cell" && !covered {
                        continue;
                    }
                    let rep_cols = repeat(cell, "table:number-columns-repeated", MAX_COLUMNS);
                    for _ in 0..rep_cols.min(MAX_COLUMNS.saturating_sub(col).max(1)) {
                        if col >= MAX_COLUMNS {
                            break;
                        }
                        if col + 1 >= down.len() {
                            down.resize(col + 2, (0, 0, 0));
                        }
                        let span = repeat(cell, "table:number-columns-spanned", MAX_COLUMNS);
                        let rspan = repeat(cell, "table:number-rows-spanned", MAX_REPEAT_ROWS);
                        if covered_left > 0 {
                            // Covered by the cell before it in this row.
                            covered_left -= 1;
                            col += 1;
                            continue;
                        }
                        if covered {
                            // Covered by a cell above: the first column of the
                            // block continues the merge, the others are part of it.
                            let (left, first, w) = active[col.min(active.len() - 1)];
                            if left > 0 && first == col {
                                let mut c = Cell::default();
                                c.props.v_merge = VMerge::Continue;
                                c.props.grid_span = w as u32;
                                c.props.width = Some(Width::Twips(
                                    (col..col + w).filter_map(|i| table.grid.get(i)).sum(),
                                ));
                                c.content = vec![Block::Para(Para::default())];
                                self.b.cell()?;
                                row.cells.push(c);
                            }
                            col += 1;
                            continue;
                        }
                        self.b.cell()?;
                        let c = self.cell(cell, &cols, col, span, rspan, &table.grid)?;
                        covered_left = span - 1;
                        if rspan > 1 {
                            for slot in down.iter_mut().skip(col).take(span) {
                                *slot = (rspan - 1, col, span);
                            }
                        }
                        row.cells.push(c);
                        col += 1;
                    }
                }
                // The spans that continued through this row are one row nearer
                // their end.
                for (i, a) in active.iter().enumerate() {
                    if a.0 > 0 && i < down.len() {
                        down[i] = (a.0 - 1, a.1, a.2);
                    }
                }
                if row.cells.is_empty() {
                    continue;
                }
                table.rows.push(row);
                if table.rows.len() as u64 > self.b.limits.max_cells {
                    res = Err(crate::formats::office::docs::error::Error::TooLarge(
                        "table rows",
                    ));
                    break 'rows;
                }
            }
        }
        self.depth -= 1;
        res?;
        if table.rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(table))
    }

    fn cell(
        &mut self,
        n: &Node,
        cols: &[Col],
        col: usize,
        span: usize,
        rspan: usize,
        grid: &[i32],
    ) -> Result<Cell> {
        let style = n
            .attr("table:style-name")
            .map(str::to_string)
            .or_else(|| cols.get(col).and_then(|c| c.style.clone()));
        let ap = style
            .as_deref()
            .map(|s| self.apply("table-cell", s))
            .unwrap_or_default();
        let p = &ap.props;
        let mut cp = CellProps {
            grid_span: span as u32,
            v_merge: if rspan > 1 {
                VMerge::Restart
            } else {
                VMerge::None
            },
            width: Some(Width::Twips(
                (col..col + span).filter_map(|i| grid.get(i)).sum(),
            )),
            ..CellProps::default()
        };
        for (name, slot) in [
            ("top", &mut cp.borders.top),
            ("left", &mut cp.borders.left),
            ("bottom", &mut cp.borders.bottom),
            ("right", &mut cp.borders.right),
        ] {
            if let Some(b) = props::side(p, "table-cell", name) {
                *slot = Some(b.unwrap_or(Border {
                    style: "nil",
                    size: 0,
                    space: 0,
                    color: Color::Auto,
                    shadow: false,
                }));
            }
        }
        if let Some(c) = p.get("table-cell/fo:background-color").and_then(odf::color) {
            cp.shading = Some(Shading::fill(Color::Rgb(c)));
        }
        cp.v_align = match p.get("table-cell/style:vertical-align") {
            Some("middle") => Some(VAlign::Center),
            Some("bottom") => Some(VAlign::Bottom),
            Some("top") => Some(VAlign::Top),
            _ => None,
        };
        for (side, slot) in [
            ("top", &mut cp.margins.top),
            ("left", &mut cp.margins.left),
            ("bottom", &mut cp.margins.bottom),
            ("right", &mut cp.margins.right),
        ] {
            let v = p
                .twips(&format!("table-cell/fo:padding-{side}"))
                .or_else(|| p.twips("table-cell/fo:padding"));
            *slot = Some(v.unwrap_or(0));
        }
        match p.get("table-cell/style:rotation-angle") {
            Some("90") => cp.text_direction = Some("btLr"),
            Some("270") => cp.text_direction = Some("tbRl"),
            _ => {}
        }
        if p.get("table-cell/style:writing-mode") == Some("tb-rl") {
            cp.text_direction = Some("tbRl");
        }
        let content = self.blocks(n)?;
        Ok(Cell {
            props: cp,
            content: if content.is_empty() {
                vec![Block::Para(Para::default())]
            } else {
                content
            },
        })
    }
}
