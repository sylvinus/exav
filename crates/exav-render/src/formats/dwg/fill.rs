//! Even-odd polygon filling by horizontal band decomposition.
//!
//! Hatch boundaries are awkward: several loops, islands inside islands, loops
//! that touch or self-intersect. Ear clipping needs one simple ring, so islands
//! have to be bridged in, and on real drawings that bridging sometimes fails
//! and the clip stalls, leaving wedges of the region unfilled.
//!
//! Splitting the region into horizontal bands at every vertex sidesteps all of
//! it. Inside a band no edge starts or ends, so the left-to-right order of the
//! edges crossing it is fixed, and pairing them off under the even-odd rule
//! gives trapezoids that tile the region exactly. It costs more triangles than
//! ear clipping and cannot fail.

/// How a hatch treats the regions inside its islands.
///
/// DWG stores this per hatch and it is not cosmetic: a rooflight band drawn as
/// an island containing a second island fills that inner island again under
/// `Normal`, but stays blank under `Outer`. Assuming `Normal` everywhere puts
/// tile hatching back inside the glazing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IslandStyle {
    /// Odd parity: alternate with nesting depth.
    Normal,
    /// Only the region between the outer boundary and its first islands.
    Outer,
    /// Everything inside the outer boundary, islands included.
    Ignore,
}

impl IslandStyle {
    /// Is a region at this nesting depth drawn? Depth 0 is outside everything.
    #[inline]
    pub fn fills(self, depth: usize) -> bool {
        match self {
            IslandStyle::Normal => depth % 2 == 1,
            IslandStyle::Outer => depth == 1,
            IslandStyle::Ignore => depth >= 1,
        }
    }
}

/// One boundary edge, normalised so `y0 < y1`. Horizontal edges are dropped:
/// they never bound a band.
#[derive(Clone, Copy)]
struct Edge {
    x0: f64,
    y0: f64,
    x1: f64,
    y1: f64,
    /// Which boundary loop this edge came from, for nesting depth.
    loop_id: u32,
}

impl Edge {
    #[inline]
    fn x_at(&self, y: f64) -> f64 {
        let t = (y - self.y0) / (self.y1 - self.y0);
        self.x0 + (self.x1 - self.x0) * t
    }
}

/// Guard against a pathological boundary generating unbounded geometry.
const MAX_TRIANGLES: usize = 200_000;

/// Pair tests the self-intersection sweep may do before giving up.
///
/// Reached only by a boundary whose edges all span the same heights, which is
/// not a shape any drawing tool produces; a real one clears in a fraction of
/// this. Stopping early costs the crossings past that point, the same way
/// skipping the scan entirely used to cost all of them.
const MAX_INTERSECTION_TESTS: usize = 4_000_000;

/// Heights where two edges cross away from a shared vertex.
///
/// Band decomposition assumes the left-to-right order of edges is fixed across
/// a band, which holds only if no two edges cross inside it. Boundaries are
/// allowed to self-intersect (the format even has a flag for it), so those
/// crossings have to become band boundaries too.
///
/// Swept in y order against an active list rather than tested pairwise: a
/// boundary is normally a curve, so only a handful of edges overlap any given
/// height and the sweep stays near linear. The pairwise version was quadratic
/// and had to be skipped above 256 edges, which left every crossing in a large
/// boundary unhandled.
fn intersection_heights(edges: &[Edge]) -> Vec<f64> {
    let mut ys = Vec::new();
    let mut order: Vec<usize> = (0..edges.len()).collect();
    order.sort_by(|&a, &b| {
        edges[a]
            .y0
            .partial_cmp(&edges[b].y0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut active: Vec<usize> = Vec::new();
    let mut tests = 0usize;
    for &i in &order {
        let a = &edges[i];
        // Everything that ended below this edge starts can never cross it.
        active.retain(|&j| edges[j].y1 > a.y0);

        for &j in &active {
            let b = &edges[j];
            tests += 1;
            if tests > MAX_INTERSECTION_TESTS {
                return ys;
            }
            if b.y0 >= a.y1 {
                continue;
            }
            let (ax, ay) = (a.x1 - a.x0, a.y1 - a.y0);
            let (bx, by) = (b.x1 - b.x0, b.y1 - b.y0);
            let denom = ax * by - ay * bx;
            if denom.abs() < 1e-12 {
                continue;
            }
            let dx = b.x0 - a.x0;
            let dy = b.y0 - a.y0;
            let t = (dx * by - dy * bx) / denom;
            let u = (dx * ay - dy * ax) / denom;
            // Strictly interior to both, so shared endpoints are not reported.
            if t > 1e-9 && t < 1.0 - 1e-9 && u > 1e-9 && u < 1.0 - 1e-9 {
                ys.push(a.y0 + ay * t);
            }
        }
        active.push(i);
    }
    ys
}

#[cfg(test)]
mod self_intersection {
    use super::*;

    fn area(tris: &[[f64; 2]]) -> f64 {
        tris.chunks(3)
            .map(|t| {
                ((t[1][0] - t[0][0]) * (t[2][1] - t[0][1])
                    - (t[2][0] - t[0][0]) * (t[1][1] - t[0][1]))
                    .abs()
                    / 2.0
            })
            .sum()
    }

    /// A bow tie: two triangles meeting where the long edges cross at (5,5).
    fn bow_tie() -> Vec<[f64; 2]> {
        vec![[0.0, 0.0], [10.0, 10.0], [10.0, 0.0], [0.0, 10.0]]
    }

    /// A comb far off to one side, purely to push the edge count up.
    fn comb(teeth: usize) -> Vec<[f64; 2]> {
        let mut out = vec![[100.0, 0.0]];
        for i in 0..teeth {
            let x = 100.0 + i as f64 * 0.1;
            out.push([x, 1.0]);
            out.push([x + 0.05, 0.0]);
        }
        out.push([100.0 + teeth as f64 * 0.1, 0.0]);
        out
    }

    #[test]
    fn a_crossing_is_found_however_many_edges_the_region_has() {
        // Two triangles meeting at (5,5), each 10 wide and 5 tall: 25 + 25. A
        // crossing treated as if it were not there fills the whole quad, 100.
        let alone = area(&fill_even_odd(&[bow_tie()]));
        assert!((alone - 50.0).abs() < 0.5, "bow tie alone: {alone}");

        // The same bow tie in a region whose edge count is past where the scan
        // used to give up. Its crossing still has to be found.
        let noise = comb(200);
        let apart = alone + area(&fill_even_odd(std::slice::from_ref(&noise)));
        let together = area(&fill_even_odd(&[bow_tie(), noise]));
        assert!(
            (together - apart).abs() < 0.5,
            "with 400 more edges the fill came to {together}, not {apart}"
        );
    }
}

fn collect_edges(loops: &[Vec<[f64; 2]>]) -> Vec<Edge> {
    let mut edges = Vec::new();
    for (id, l) in loops.iter().enumerate() {
        if l.len() < 3 {
            continue;
        }
        for i in 0..l.len() {
            let a = l[i];
            let b = l[(i + 1) % l.len()];
            if !(a[0].is_finite() && a[1].is_finite() && b[0].is_finite() && b[1].is_finite()) {
                continue;
            }
            if a[1] == b[1] {
                continue;
            }
            let (p, q) = if a[1] < b[1] { (a, b) } else { (b, a) };
            edges.push(Edge {
                x0: p[0],
                y0: p[1],
                x1: q[0],
                y1: q[1],
                loop_id: id as u32,
            });
        }
    }
    edges
}

/// Triangulate the interior of a set of closed loops under the even-odd rule.
pub fn fill_even_odd(loops: &[Vec<[f64; 2]>]) -> Vec<[f64; 2]> {
    fill_region(loops, IslandStyle::Normal)
}

/// Triangulate the interior of a set of closed loops under a given island style.
///
/// Returns flat triangle corners. Loop orientation does not matter.
pub fn fill_region(loops: &[Vec<[f64; 2]>], style: IslandStyle) -> Vec<[f64; 2]> {
    let edges = collect_edges(loops);
    if edges.is_empty() {
        return Vec::new();
    }

    // Band boundaries: every vertex height, so no edge begins or ends inside a
    // band and the crossing order stays fixed across it.
    let mut ys: Vec<f64> = Vec::with_capacity(edges.len() * 2);
    for e in &edges {
        ys.push(e.y0);
        ys.push(e.y1);
    }
    ys.extend(intersection_heights(&edges));
    ys.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    ys.dedup_by(|a, b| (*a - *b).abs() < 1e-9);
    if ys.len() < 2 {
        return Vec::new();
    }

    let mut out: Vec<[f64; 2]> = Vec::new();
    let mut crossings: Vec<(f64, usize)> = Vec::new();
    let mut inside_loops: Vec<bool> = Vec::new();

    for w in ys.windows(2) {
        let (ya, yb) = (w[0], w[1]);
        if yb - ya < 1e-12 {
            continue;
        }
        let mid = (ya + yb) * 0.5;

        crossings.clear();
        for (i, e) in edges.iter().enumerate() {
            // Half-open in y, so a vertex shared by two edges is counted once.
            if e.y0 <= mid && e.y1 > mid {
                crossings.push((e.x_at(mid), i));
            }
        }
        if crossings.len() < 2 {
            continue;
        }
        crossings.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        // Walk left to right, tracking which loops we are inside. The count is
        // the nesting depth, which is what the island style is defined on;
        // plain crossing parity only answers the `Normal` case.
        inside_loops.clear();
        inside_loops.resize(loops.len(), false);
        let mut depth = 0usize;

        for k in 0..crossings.len().saturating_sub(1) {
            let id = edges[crossings[k].1].loop_id as usize;
            if inside_loops[id] {
                inside_loops[id] = false;
                depth -= 1;
            } else {
                inside_loops[id] = true;
                depth += 1;
            }
            if !style.fills(depth) {
                continue;
            }

            let left = &edges[crossings[k].1];
            let right = &edges[crossings[k + 1].1];

            let la = left.x_at(ya);
            let lb = left.x_at(yb);
            let ra = right.x_at(ya);
            let rb = right.x_at(yb);

            // Degenerate slivers contribute nothing and only cost fill rate.
            if (ra - la).abs() > 1e-12 || (rb - lb).abs() > 1e-12 {
                out.push([la, ya]);
                out.push([ra, ya]);
                out.push([rb, yb]);

                out.push([la, ya]);
                out.push([rb, yb]);
                out.push([lb, yb]);
            }

            if out.len() / 3 > MAX_TRIANGLES {
                return out;
            }
        }
    }

    out
}

#[cfg(test)]
pub(crate) mod tests_shapes {
    pub fn area(tris: &[[f64; 2]]) -> f64 {
        tris.chunks(3)
            .filter(|t| t.len() == 3)
            .map(|t| {
                ((t[1][0] - t[0][0]) * (t[2][1] - t[0][1])
                    - (t[2][0] - t[0][0]) * (t[1][1] - t[0][1]))
                    .abs()
                    / 2.0
            })
            .sum()
    }

    pub fn square(x: f64, y: f64, s: f64) -> Vec<[f64; 2]> {
        vec![[x, y], [x + s, y], [x + s, y + s], [x, y + s]]
    }

    pub fn circle(cx: f64, cy: f64, r: f64, n: usize) -> Vec<[f64; 2]> {
        (0..n)
            .map(|i| {
                let a = std::f64::consts::TAU * i as f64 / n as f64;
                [cx + r * a.cos(), cy + r * a.sin()]
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_shapes::*;
    use super::*;

    #[test]
    fn a_square_fills_exactly() {
        let t = fill_even_odd(&[square(0.0, 0.0, 10.0)]);
        assert!((area(&t) - 100.0).abs() < 1e-9, "area {}", area(&t));
    }

    #[test]
    fn winding_does_not_matter() {
        let cw: Vec<[f64; 2]> = square(0.0, 0.0, 10.0).into_iter().rev().collect();
        assert!((area(&fill_even_odd(&[cw])) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn an_island_is_cut_out() {
        let t = fill_even_odd(&[square(0.0, 0.0, 10.0), square(4.0, 4.0, 2.0)]);
        assert!((area(&t) - 96.0).abs() < 1e-9, "area {}", area(&t));
    }

    #[test]
    fn an_island_inside_an_island_is_filled_again() {
        let t = fill_even_odd(&[
            square(0.0, 0.0, 20.0),
            square(2.0, 2.0, 16.0),
            square(6.0, 6.0, 8.0),
        ]);
        // 400 - 256 + 64
        assert!((area(&t) - 208.0).abs() < 1e-9, "area {}", area(&t));
    }

    #[test]
    fn disjoint_regions_both_fill() {
        let t = fill_even_odd(&[square(0.0, 0.0, 10.0), square(50.0, 0.0, 4.0)]);
        assert!((area(&t) - 116.0).abs() < 1e-9, "area {}", area(&t));
    }

    #[test]
    fn a_concave_shape_fills_exactly() {
        // L-shape of area 3.
        let l = vec![
            [0.0, 0.0],
            [2.0, 0.0],
            [2.0, 1.0],
            [1.0, 1.0],
            [1.0, 2.0],
            [0.0, 2.0],
        ];
        assert!((area(&fill_even_odd(&[l])) - 3.0).abs() < 1e-9);
    }

    #[test]
    fn a_round_island_in_a_round_region_is_cut() {
        let outer = circle(0.0, 0.0, 50.0, 128);
        let inner = circle(0.0, 0.0, 10.0, 64);
        let got = area(&fill_even_odd(&[outer.clone(), inner.clone()]));
        // Compare against the polygons' own areas, not the ideal circles.
        let shoelace = |p: &Vec<[f64; 2]>| {
            let mut s = 0.0;
            for i in 0..p.len() {
                let a = p[i];
                let b = p[(i + 1) % p.len()];
                s += a[0] * b[1] - b[0] * a[1];
            }
            (s / 2.0).abs()
        };
        let expected = shoelace(&outer) - shoelace(&inner);
        assert!(
            (got - expected).abs() / expected < 1e-9,
            "got {got} expected {expected}"
        );
    }

    #[test]
    fn a_self_intersecting_bowtie_uses_the_even_odd_rule() {
        // Both lobes are inside an odd number of crossings, so both fill.
        let bow = vec![[0.0, 0.0], [2.0, 2.0], [2.0, 0.0], [0.0, 2.0]];
        let got = area(&fill_even_odd(&[bow]));
        assert!((got - 2.0).abs() < 1e-9, "area {got}");
    }

    #[test]
    fn a_horizontal_sliver_does_not_break_parity() {
        // Horizontal edges are dropped; the shape must still fill correctly.
        let p = vec![
            [0.0, 0.0],
            [10.0, 0.0],
            [10.0, 5.0],
            [5.0, 5.0],
            [5.0, 10.0],
            [0.0, 10.0],
        ];
        assert!((area(&fill_even_odd(&[p])) - 75.0).abs() < 1e-9);
    }

    #[test]
    fn degenerate_input_is_empty() {
        assert!(fill_even_odd(&[]).is_empty());
        assert!(fill_even_odd(&[vec![[0.0, 0.0], [1.0, 1.0]]]).is_empty());
        // A zero-height loop has no bands.
        assert!(fill_even_odd(&[vec![[0.0, 0.0], [5.0, 0.0], [2.0, 0.0]]]).is_empty());
    }

    #[test]
    fn touching_loops_do_not_double_fill() {
        // Two squares sharing an edge fill their union once, not twice.
        let t = fill_even_odd(&[square(0.0, 0.0, 10.0), square(10.0, 0.0, 10.0)]);
        assert!((area(&t) - 200.0).abs() < 1e-6, "area {}", area(&t));
    }
}

#[cfg(test)]
mod island_styles {
    use super::tests_shapes::*;
    use super::*;

    /// Outer boundary, an island, and a second island inside that one.
    fn nested() -> Vec<Vec<[f64; 2]>> {
        vec![
            square(0.0, 0.0, 20.0),
            square(2.0, 2.0, 16.0),
            square(6.0, 6.0, 8.0),
        ]
    }

    #[test]
    fn normal_alternates_with_depth() {
        // 400 - 256 + 64
        let a = area(&fill_region(&nested(), IslandStyle::Normal));
        assert!((a - 208.0).abs() < 1e-9, "area {a}");
    }

    #[test]
    fn outer_fills_only_down_to_the_first_island() {
        // The rooflight case: everything inside the island stays blank, however
        // it is subdivided. 400 - 256.
        let a = area(&fill_region(&nested(), IslandStyle::Outer));
        assert!((a - 144.0).abs() < 1e-9, "area {a}");
    }

    #[test]
    fn ignore_fills_the_whole_outer_boundary() {
        let a = area(&fill_region(&nested(), IslandStyle::Ignore));
        assert!((a - 400.0).abs() < 1e-9, "area {a}");
    }

    #[test]
    fn the_styles_agree_when_there_are_no_islands() {
        let one = vec![square(0.0, 0.0, 10.0)];
        for style in [IslandStyle::Normal, IslandStyle::Outer, IslandStyle::Ignore] {
            let a = area(&fill_region(&one, style));
            assert!((a - 100.0).abs() < 1e-9, "{style:?} gave {a}");
        }
    }

    #[test]
    fn outer_still_cuts_a_single_island() {
        let loops = vec![square(0.0, 0.0, 10.0), square(4.0, 4.0, 2.0)];
        let a = area(&fill_region(&loops, IslandStyle::Outer));
        assert!((a - 96.0).abs() < 1e-9, "area {a}");
    }

    #[test]
    fn disjoint_regions_are_all_outermost() {
        // Two separate loops are both at depth 1, so Outer keeps both.
        let loops = vec![square(0.0, 0.0, 10.0), square(50.0, 0.0, 4.0)];
        let a = area(&fill_region(&loops, IslandStyle::Outer));
        assert!((a - 116.0).abs() < 1e-9, "area {a}");
    }
}
