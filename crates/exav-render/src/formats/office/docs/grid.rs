//! Tables whose rows give their own cell edges (DOC, RTF, Word 2003 XML): the
//! edges of all rows make up the grid, and a cell spans the grid columns
//! between its edges.

use crate::formats::office::docs::model::*;

const TOL: i32 = 3;

/// A cell of a row as its reader found it.
pub struct CellIn {
    pub props: CellProps,
    pub content: Vec<Block>,
    /// Merged into the cell before it (its edge is joined to that cell).
    pub merged_left: bool,
}

/// A row: the cell edges in twips (one more than cells), and the cells.
pub struct RowIn {
    pub edges: Vec<i32>,
    pub props: RowProps,
    pub cells: Vec<CellIn>,
}

fn nearest(grid: &[i32], x: i32) -> usize {
    let mut best = 0usize;
    for (i, g) in grid.iter().enumerate() {
        if (g - x).abs() < (grid[best] - x).abs() {
            best = i;
        }
    }
    best
}

/// The table made of `rows`, with `props` for the whole table.
pub fn build(rows: Vec<RowIn>, mut props: TableProps) -> Table {
    let mut all: Vec<i32> = rows.iter().flat_map(|r| r.edges.iter().copied()).collect();
    all.sort_unstable();
    let mut grid: Vec<i32> = vec![];
    for x in all {
        if grid.last().is_none_or(|l| x - l > TOL) {
            grid.push(x);
        }
    }
    if grid.len() < 2 {
        grid = vec![0, 1];
    }
    props.fixed_layout = true;
    if props.width.is_none() {
        props.width = Some(Width::Twips(grid[grid.len() - 1] - grid[0]));
    }
    let m = grid.len() - 1;
    let mut table = Table {
        props,
        grid: grid.array_windows().map(|[a, b]| b - a).collect(),
        rows: vec![],
    };
    for r in rows {
        let mut row = Row {
            props: r.props,
            cells: vec![],
        };
        let mut placed: Vec<(usize, usize, Cell)> = vec![];
        for (k, c) in r.cells.into_iter().enumerate() {
            let (Some(&le), Some(&re)) = (r.edges.get(k), r.edges.get(k + 1)) else {
                // A cell with no edges: its content joins the last cell.
                if let Some(last) = placed.last_mut() {
                    last.2.content.extend(c.content);
                }
                continue;
            };
            let (l, rr) = (nearest(&grid, le), nearest(&grid, re));
            if c.merged_left
                && let Some(prev) = placed.last_mut()
            {
                prev.1 = rr.max(prev.1);
                continue;
            }
            let mut cell = Cell {
                props: c.props,
                content: if c.content.is_empty() {
                    vec![Block::Para(Para::default())]
                } else {
                    c.content
                },
            };
            cell.props.width = Some(Width::Twips((re - le).max(0)));
            placed.push((l, rr, cell));
        }
        if placed.is_empty() {
            continue;
        }
        let first = placed[0].0;
        row.props.grid_before = first as u32;
        if first > 0 {
            row.props.width_before = Some(Width::Twips(grid[first] - grid[0]));
        }
        let last = placed[placed.len() - 1].1;
        row.props.grid_after = m.saturating_sub(last) as u32;
        if last < m {
            row.props.width_after = Some(Width::Twips(grid[m] - grid[last]));
        }
        for (l, rr, mut c) in placed {
            c.props.grid_span = rr.saturating_sub(l).max(1) as u32;
            row.cells.push(c);
        }
        table.rows.push(row);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(merged_left: bool) -> CellIn {
        CellIn {
            props: CellProps::default(),
            content: vec![],
            merged_left,
        }
    }

    #[test]
    fn edges_make_the_grid_and_spans() {
        let rows = vec![
            RowIn {
                edges: vec![0, 1000, 2000],
                props: RowProps::default(),
                cells: vec![cell(false), cell(false)],
            },
            RowIn {
                edges: vec![0, 1000, 1500, 2000],
                props: RowProps::default(),
                cells: vec![cell(false), cell(false), cell(false)],
            },
            // The second and third cells are one.
            RowIn {
                edges: vec![0, 1000, 1500, 2000],
                props: RowProps::default(),
                cells: vec![cell(false), cell(false), cell(true)],
            },
        ];
        let t = build(rows, TableProps::default());
        assert_eq!(t.grid, vec![1000, 500, 500]);
        assert_eq!(t.rows[0].cells[1].props.grid_span, 2);
        assert_eq!(t.rows[1].cells.len(), 3);
        assert_eq!(t.rows[2].cells.len(), 2);
        assert_eq!(t.rows[2].cells[1].props.grid_span, 2);
    }

    #[test]
    fn a_row_that_starts_late_has_grid_before() {
        let rows = vec![
            RowIn {
                edges: vec![0, 1000, 2000],
                props: RowProps::default(),
                cells: vec![cell(false), cell(false)],
            },
            RowIn {
                edges: vec![1000, 2000],
                props: RowProps::default(),
                cells: vec![cell(false)],
            },
        ];
        let t = build(rows, TableProps::default());
        assert_eq!(t.rows[1].props.grid_before, 1);
        assert_eq!(t.rows[1].props.width_before, Some(Width::Twips(1000)));
    }
}
