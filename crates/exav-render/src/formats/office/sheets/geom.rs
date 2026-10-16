//! Where cells are on the sheet, in pixels at 96 dpi as an XLSX reader lays
//! them out: for anchors given in absolute positions (ODS frames, grouped
//! shapes) and for the absolute positions DrawingML shapes repeat.

use crate::formats::office::sheets::model::*;

pub const EMU_PER_PX: f64 = 9525.0;

/// Column width in characters to pixels, for a maximum digit width of 7
/// pixels (ECMA-376 part 1, 18.3.1.13).
pub fn chars_to_px(w: f64) -> f64 {
    ((256.0 * w + (128.0f64 / 7.0).trunc()) / 256.0 * 7.0)
        .trunc()
        .max(0.0)
}

pub fn col_px(sh: &Sheet, col: u32) -> f64 {
    match sh.col_info(col) {
        Some(c) if c.hidden => 0.0,
        Some(c) => chars_to_px(c.width.or(sh.default_col_width).unwrap_or(8.43)),
        None => chars_to_px(sh.default_col_width.unwrap_or(8.43)),
    }
}

pub fn row_px(sh: &Sheet, row: u32) -> f64 {
    match sh.rows.get(&row) {
        Some(r) if r.hidden => 0.0,
        Some(r) => r.height.unwrap_or(sh.default_row_height) * 96.0 / 72.0,
        None => sh.default_row_height * 96.0 / 72.0,
    }
}

/// Left and top edges of columns and rows, in pixels, up to a bound.
pub struct Grid {
    left: Vec<f64>,
    top: Vec<f64>,
}

impl Grid {
    /// Edges up to column `mc` and row `mr` (clipped to the sheet).
    pub fn new(sh: &Sheet, mc: u32, mr: u32) -> Grid {
        let mc = mc.min(MAX_COL) + 1;
        let mr = mr.min(MAX_ROW) + 1;
        let mut left = Vec::with_capacity(mc as usize + 1);
        let mut x = 0.0;
        for c in 0..=mc {
            left.push(x);
            x += col_px(sh, c);
        }
        let mut top = Vec::with_capacity(mr as usize + 1);
        let mut y = 0.0;
        let default = sh.default_row_height * 96.0 / 72.0;
        let mut it = sh.rows.range(..=mr).peekable();
        for r in 0..=mr {
            top.push(y);
            y += match it.peek() {
                Some((&k, _)) if k == r => {
                    it.next();
                    row_px(sh, r)
                }
                _ => default,
            };
        }
        Grid { left, top }
    }

    /// Edges covering the anchors.
    pub fn for_anchors(sh: &Sheet, anchors: impl Iterator<Item = Anchor>) -> Grid {
        let (mut mc, mut mr) = (0u32, 0u32);
        for a in anchors {
            mc = mc.max(a.from.0).max(a.to.0);
            mr = mr.max(a.from.1).max(a.to.1);
        }
        Grid::new(sh, mc, mr)
    }

    pub fn x(&self, sh: &Sheet, col: u32, frac: i64) -> f64 {
        let c = col.min(self.left.len() as u32 - 1);
        self.left[c as usize] + frac as f64 / 1e6 * col_px(sh, c)
    }

    pub fn y(&self, sh: &Sheet, row: u32, frac: i64) -> f64 {
        let r = row.min(self.top.len() as u32 - 1);
        self.top[r as usize] + frac as f64 / 1e6 * row_px(sh, r)
    }

    /// The cell holding pixel position (x, y), and the offsets in it.
    pub fn locate(&self, sh: &Sheet, x: f64, y: f64) -> (u32, u32, i64, i64) {
        let c = self
            .left
            .partition_point(|&l| l <= x)
            .saturating_sub(1)
            .min(self.left.len() - 2);
        let r = self
            .top
            .partition_point(|&t| t <= y)
            .saturating_sub(1)
            .min(self.top.len() - 2);
        let frac = |off: f64, size: f64| {
            if size > 0.0 {
                ((off / size) * 1e6).clamp(0.0, 1e6) as i64
            } else {
                0
            }
        };
        let (c, r) = (c as u32, r as u32);
        (
            c,
            r,
            frac(x - self.left[c as usize], col_px(sh, c)),
            frac(y - self.top[r as usize], row_px(sh, r)),
        )
    }

    /// The anchor of a rectangle in pixels.
    pub fn anchor(&self, sh: &Sheet, x0: f64, y0: f64, x1: f64, y1: f64) -> Anchor {
        Anchor {
            from: self.locate(sh, x0.min(x1), y0.min(y1)),
            to: self.locate(sh, x0.max(x1), y0.max(y1)),
        }
    }
}
