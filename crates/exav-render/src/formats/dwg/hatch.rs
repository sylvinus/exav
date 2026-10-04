//! Hatch region solving: island nesting, solid fills and pattern lines.
//!
//! AutoCAD does not draw a hatch's boundary paths. They are bookkeeping, and
//! the visible edge almost always belongs to separate geometry that is drawn in
//! its own right. Stroking them produces lines that are not in the drawing, and
//! for a hatch bounded by a large circle that shows up as a circle spanning the
//! sheet. So nothing here emits boundary strokes; a hatch contributes its fill
//! or its pattern, and nothing else.

use super::fill::IslandStyle;

/// Upper bound on segments generated for one hatch, so a tiny pattern scale
/// over a huge region cannot lock up the tessellator.
const MAX_PATTERN_SEGMENTS: usize = 40_000;

/// One closed boundary loop, already flattened to points.
pub type Loop = Vec<[f64; 2]>;

/// Ray-cast point-in-polygon, crossing rule.
pub fn point_in_loop(p: [f64; 2], poly: &[[f64; 2]]) -> bool {
    let mut inside = false;
    let n = poly.len();
    for i in 0..n {
        let a = poly[i];
        let b = poly[(i + 1) % n];
        if (a[1] > p[1]) != (b[1] > p[1]) {
            let t = (p[1] - a[1]) / (b[1] - a[1]);
            if p[0] < a[0] + t * (b[0] - a[0]) {
                inside = !inside;
            }
        }
    }
    inside
}

fn representative(poly: &[[f64; 2]]) -> [f64; 2] {
    // A vertex lies on the boundary, which is ambiguous for containment tests.
    // The centroid of the first three vertices is interior for any sane loop.
    if poly.len() >= 3 {
        [
            (poly[0][0] + poly[1][0] + poly[2][0]) / 3.0,
            (poly[0][1] + poly[1][1] + poly[2][1]) / 3.0,
        ]
    } else {
        poly.first().copied().unwrap_or([0.0, 0.0])
    }
}

/// Nesting depth of every loop: 0 for outermost, 1 for an island, and so on.
///
/// This is the "Normal" hatch style, AutoCAD's default: fill alternates with
/// depth, so an island inside an island is filled again.
pub fn nesting_depths(loops: &[Loop]) -> Vec<usize> {
    loops
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let p = representative(l);
            loops
                .iter()
                .enumerate()
                .filter(|(j, other)| *j != i && other.len() >= 3 && point_in_loop(p, other))
                .count()
        })
        .collect()
}

/// Split loops into filled regions, each with the islands cut out of it.
#[cfg(test)]
pub fn solve_regions(loops: &[Loop]) -> Vec<(Loop, Vec<Loop>)> {
    let depths = nesting_depths(loops);
    let mut out = Vec::new();

    for (i, l) in loops.iter().enumerate() {
        if l.len() < 3 || !depths[i].is_multiple_of(2) {
            continue;
        }
        // Islands are the loops one level deeper that sit inside this one.
        let holes: Vec<Loop> = loops
            .iter()
            .enumerate()
            .filter(|(j, h)| {
                *j != i
                    && h.len() >= 3
                    && depths[*j] == depths[i] + 1
                    && point_in_loop(representative(h), l)
            })
            .map(|(_, h)| h.clone())
            .collect();
        out.push((l.clone(), holes));
    }

    out
}

/// A pattern line family, as stored on the hatch entity.
#[derive(Clone, Debug)]
pub struct PatternLine {
    pub angle: f64,
    pub base: [f64; 2],
    /// Offset from one line in the family to the next.
    pub offset: [f64; 2],
    /// Signed run lengths: positive draws, negative skips, zero is a dot.
    pub dashes: Vec<f64>,
}

fn bbox(loops: &[Loop]) -> Option<[f64; 4]> {
    let mut b = [f64::MAX, f64::MAX, f64::MIN, f64::MIN];
    let mut any = false;
    for l in loops {
        for p in l {
            if !p[0].is_finite() || !p[1].is_finite() {
                continue;
            }
            any = true;
            b[0] = b[0].min(p[0]);
            b[1] = b[1].min(p[1]);
            b[2] = b[2].max(p[0]);
            b[3] = b[3].max(p[1]);
        }
    }
    if any {
        Some(b)
    } else {
        None
    }
}

/// Parameters along `u` where a line through `origin` crosses the loops,
/// each tagged with the loop it belongs to so nesting depth can be tracked.
fn crossings(origin: [f64; 2], u: [f64; 2], loops: &[Loop]) -> Vec<(f64, usize)> {
    // Perpendicular, so a crossing is a sign change of the normal distance.
    let n = [-u[1], u[0]];
    let mut ts = Vec::new();

    for (loop_id, l) in loops.iter().enumerate() {
        let count = l.len();
        if count < 3 {
            continue;
        }
        for i in 0..count {
            let a = l[i];
            let b = l[(i + 1) % count];
            let da = (a[0] - origin[0]) * n[0] + (a[1] - origin[1]) * n[1];
            let db = (b[0] - origin[0]) * n[0] + (b[1] - origin[1]) * n[1];

            // Half-open rule: an edge counts when it leaves the closed side for
            // the open one. A vertex lying exactly on the scan line then counts
            // once for a genuine crossing and twice (so, not at all, for
            // parity) where the boundary merely grazes the line. Comparing the
            // two signs directly instead miscounts every graze, which lets the
            // hatch leak across an island boundary.
            let crosses = (da <= 0.0 && db > 0.0) || (db <= 0.0 && da > 0.0);
            if !crosses {
                continue;
            }
            let denom = da - db;
            if denom.abs() < 1e-12 {
                continue;
            }
            let s = da / denom;
            let x = a[0] + s * (b[0] - a[0]);
            let y = a[1] + s * (b[1] - a[1]);
            ts.push(((x - origin[0]) * u[0] + (y - origin[1]) * u[1], loop_id));
        }
    }

    ts.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    ts
}

/// Cut a span into dashes, appending drawn pieces as (t_start, t_end).
fn apply_dashes(t0: f64, t1: f64, dashes: &[f64], out: &mut Vec<(f64, f64)>) {
    let period: f64 = dashes.iter().map(|d| d.abs().max(1e-9)).sum();
    if dashes.is_empty() || !(period > 1e-9) {
        out.push((t0, t1));
        return;
    }

    if !t0.is_finite() || !t1.is_finite() {
        return;
    }
    // Anchor the dash phase to the pattern origin so adjacent lines line up.
    let first = (t0 / period).floor() * period;
    // Counted rather than compared: far from the origin, adding a fine period
    // can leave the cycle where it was, and the loop would never end. A span
    // of more cycles than can be drawn reads as a solid line.
    let cycles = ((t1 - first) / period).ceil();
    if !(cycles <= MAX_PATTERN_SEGMENTS as f64) {
        out.push((t0, t1));
        return;
    }
    for k in 0..cycles.max(0.0) as usize {
        let cycle_start = first + k as f64 * period;
        let mut t = cycle_start;
        for d in dashes {
            let len = d.abs().max(1e-9);
            let seg_end = t + len;
            if *d >= 0.0 {
                let s = t.max(t0);
                let e = seg_end.min(t1);
                if e > s {
                    out.push((s, e));
                }
            }
            t = seg_end;
            if t > t1 {
                break;
            }
        }
        if out.len() > MAX_PATTERN_SEGMENTS {
            return;
        }
    }
}

/// Smallest spacing across a pattern's line families, in drawing units.
///
/// Drives the sub-pixel fade; see `encode_fade_spacing`.
pub fn min_spacing(lines: &[PatternLine]) -> f64 {
    let mut best = f64::MAX;
    for line in lines {
        let (sin_a, cos_a) = line.angle.sin_cos();
        let step = (line.offset[0] * -sin_a + line.offset[1] * cos_a).abs();
        if step.is_finite() && step > 1e-9 {
            best = best.min(step);
        }
    }
    if best == f64::MAX {
        0.0
    } else {
        best
    }
}

/// Generate the drawn segments of a hatch pattern, clipped to the region.
///
/// Returns `(segments, truncated)`; `truncated` means the segment cap was hit
/// and the pattern is incomplete.
pub fn pattern_segments(
    loops: &[Loop],
    lines: &[PatternLine],
    style: IslandStyle,
) -> (Vec<[[f64; 2]; 2]>, bool) {
    let Some(b) = bbox(loops) else {
        return (Vec::new(), false);
    };
    let mut out: Vec<[[f64; 2]; 2]> = Vec::new();
    let mut inside_loops: Vec<bool> = Vec::new();

    // ANSI32 and friends declare two families that differ only in base point.
    // Where a file repeats a family outright, drawing it twice doubles the ink
    // for no visual gain, and once the lines are faded it actually darkens them.
    let mut seen: Vec<&PatternLine> = Vec::new();
    let mut unique: Vec<&PatternLine> = Vec::new();
    for l in lines {
        let dup = seen.iter().any(|p| {
            (p.angle - l.angle).abs() < 1e-12
                && (p.base[0] - l.base[0]).abs() < 1e-9
                && (p.base[1] - l.base[1]).abs() < 1e-9
                && (p.offset[0] - l.offset[0]).abs() < 1e-12
                && (p.offset[1] - l.offset[1]).abs() < 1e-12
                && p.dashes == l.dashes
        });
        if !dup {
            seen.push(l);
            unique.push(l);
        }
    }

    for line in unique {
        let (sin_a, cos_a) = line.angle.sin_cos();
        let u = [cos_a, sin_a];
        let n = [-sin_a, cos_a];

        // Spacing is the offset's component across the line direction. Without
        // it every line in the family would sit on top of the last.
        let step = line.offset[0] * n[0] + line.offset[1] * n[1];
        if !step.is_finite() || step.abs() < 1e-9 {
            continue;
        }

        // Cover the region's extent measured across the lines.
        let corners = [[b[0], b[1]], [b[2], b[1]], [b[0], b[3]], [b[2], b[3]]];
        let base_n = line.base[0] * n[0] + line.base[1] * n[1];
        let mut lo = f64::MAX;
        let mut hi = f64::MIN;
        for c in corners {
            let d = (c[0] * n[0] + c[1] * n[1]) - base_n;
            lo = lo.min(d);
            hi = hi.max(d);
        }

        let k0 = (lo / step).floor() as i64;
        let k1 = (hi / step).ceil() as i64;
        let (k0, k1) = if k0 <= k1 { (k0, k1) } else { (k1, k0) };
        // Saturating: an extent at the edge of f64 casts to the ends of i64.
        if k1.saturating_sub(k0) as u64 > MAX_PATTERN_SEGMENTS as u64 {
            return (out, true);
        }

        for k in k0..=k1 {
            let origin = [
                line.base[0] + k as f64 * line.offset[0],
                line.base[1] + k as f64 * line.offset[1],
            ];
            let ts = crossings(origin, u, loops);
            // Walk the crossings tracking which loops we are inside, so the
            // island style decides each span rather than plain parity.
            inside_loops.clear();
            inside_loops.resize(loops.len(), false);
            let mut depth = 0usize;
            let mut spans: Vec<(f64, f64)> = Vec::new();
            for i in 0..ts.len().saturating_sub(1) {
                let id = ts[i].1;
                if inside_loops[id] {
                    inside_loops[id] = false;
                    depth -= 1;
                } else {
                    inside_loops[id] = true;
                    depth += 1;
                }
                if style.fills(depth) && ts[i + 1].0 > ts[i].0 {
                    spans.push((ts[i].0, ts[i + 1].0));
                }
            }

            for (t0, t1) in spans {
                let mut pieces = Vec::new();
                apply_dashes(t0, t1, &line.dashes, &mut pieces);
                for (s, e) in pieces {
                    out.push([
                        [origin[0] + u[0] * s, origin[1] + u[1] * s],
                        [origin[0] + u[0] * e, origin[1] + u[1] * e],
                    ]);
                    if out.len() >= MAX_PATTERN_SEGMENTS {
                        return (out, true);
                    }
                }
            }
        }
    }

    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn square(x: f64, y: f64, s: f64) -> Loop {
        vec![[x, y], [x + s, y], [x + s, y + s], [x, y + s]]
    }

    #[test]
    fn containment_is_correct_for_a_square() {
        let sq = square(0.0, 0.0, 10.0);
        assert!(point_in_loop([5.0, 5.0], &sq));
        assert!(!point_in_loop([15.0, 5.0], &sq));
        assert!(!point_in_loop([-1.0, 5.0], &sq));
    }

    #[test]
    fn a_lone_loop_is_depth_zero() {
        assert_eq!(nesting_depths(&[square(0.0, 0.0, 10.0)]), vec![0]);
    }

    #[test]
    fn an_island_is_depth_one() {
        let loops = vec![square(0.0, 0.0, 10.0), square(3.0, 3.0, 2.0)];
        assert_eq!(nesting_depths(&loops), vec![0, 1]);
    }

    #[test]
    fn an_island_inside_an_island_is_depth_two() {
        let loops = vec![
            square(0.0, 0.0, 20.0),
            square(2.0, 2.0, 10.0),
            square(4.0, 4.0, 2.0),
        ];
        assert_eq!(nesting_depths(&loops), vec![0, 1, 2]);
    }

    #[test]
    fn regions_pair_each_outer_with_its_own_islands() {
        // Two separate regions, one island each; the islands must not swap.
        let loops = vec![
            square(0.0, 0.0, 10.0),
            square(2.0, 2.0, 2.0),
            square(50.0, 0.0, 10.0),
            square(52.0, 2.0, 2.0),
        ];
        let regions = solve_regions(&loops);
        assert_eq!(regions.len(), 2);
        for (outer, holes) in &regions {
            assert_eq!(holes.len(), 1);
            assert!(point_in_loop(representative(&holes[0]), outer));
        }
    }

    #[test]
    fn a_depth_two_island_is_filled_again() {
        let loops = vec![
            square(0.0, 0.0, 20.0),
            square(2.0, 2.0, 10.0),
            square(4.0, 4.0, 2.0),
        ];
        let regions = solve_regions(&loops);
        // Outer and the innermost both fill; the middle ring is the hole.
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn horizontal_pattern_covers_the_square() {
        let sq = square(0.0, 0.0, 10.0);
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [0.0, 1.0],
            dashes: vec![],
        };
        let (segs, truncated) = pattern_segments(&[sq], &[line], IslandStyle::Normal);
        assert!(!truncated);
        // One line per unit of height, spanning the full width each.
        assert!(segs.len() >= 9 && segs.len() <= 12, "got {}", segs.len());
        for s in &segs {
            assert!(
                (s[0][1] - s[1][1]).abs() < 1e-9,
                "line must stay horizontal"
            );
            assert!(
                (s[0][0] - 0.0).abs() < 1e-6,
                "should start at the left edge"
            );
            assert!(
                (s[1][0] - 10.0).abs() < 1e-6,
                "should end at the right edge"
            );
        }
    }

    #[test]
    fn pattern_skips_the_island() {
        let loops = vec![square(0.0, 0.0, 10.0), square(4.0, 4.0, 2.0)];
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [0.0, 1.0],
            dashes: vec![],
        };
        let (segs, _) = pattern_segments(&loops, &[line], IslandStyle::Normal);
        // A line at y=5 crosses the island, so it must come out as two pieces.
        let at5: Vec<_> = segs
            .iter()
            .filter(|s| (s[0][1] - 5.0).abs() < 1e-6)
            .collect();
        assert_eq!(at5.len(), 2, "island should split the line");
        let covered: f64 = at5.iter().map(|s| (s[1][0] - s[0][0]).abs()).sum();
        assert!(
            (covered - 8.0).abs() < 1e-6,
            "covered {covered}, island is 2 wide"
        );
    }

    #[test]
    fn angled_pattern_stays_at_its_angle() {
        let sq = square(0.0, 0.0, 10.0);
        let a = std::f64::consts::FRAC_PI_4;
        let line = PatternLine {
            angle: a,
            base: [0.0, 0.0],
            offset: [-a.sin(), a.cos()],
            dashes: vec![],
        };
        let (segs, _) = pattern_segments(&[sq], &[line], IslandStyle::Normal);
        assert!(!segs.is_empty());
        for s in &segs {
            let dx = s[1][0] - s[0][0];
            let dy = s[1][1] - s[0][1];
            if dx.abs() < 1e-9 && dy.abs() < 1e-9 {
                continue;
            }
            assert!((dy.atan2(dx) - a).abs() < 1e-6, "segment off-angle");
        }
    }

    #[test]
    fn dashes_break_the_line_up() {
        let sq = square(0.0, 0.0, 10.0);
        let solid = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [0.0, 5.0],
            dashes: vec![],
        };
        let dashed = PatternLine {
            dashes: vec![1.0, -1.0],
            ..solid.clone()
        };
        let (a, _) = pattern_segments(std::slice::from_ref(&sq), &[solid], IslandStyle::Normal);
        let (b, _) = pattern_segments(&[sq], &[dashed], IslandStyle::Normal);
        assert!(b.len() > a.len(), "dashed should emit more, shorter pieces");
        let drawn: f64 = b.iter().map(|s| (s[1][0] - s[0][0]).abs()).sum();
        let full: f64 = a.iter().map(|s| (s[1][0] - s[0][0]).abs()).sum();
        // Half on, half off.
        assert!(
            (drawn - full / 2.0).abs() < full * 0.15,
            "drawn {drawn} of {full}"
        );
    }

    #[test]
    fn a_degenerate_offset_is_skipped_not_looped_forever() {
        let sq = square(0.0, 0.0, 10.0);
        // Offset parallel to the line direction: the family never advances.
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [1.0, 0.0],
            dashes: vec![],
        };
        let (segs, truncated) = pattern_segments(&[sq], &[line], IslandStyle::Normal);
        assert!(segs.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn a_tiny_spacing_over_a_big_region_truncates_rather_than_hanging() {
        let big = square(0.0, 0.0, 1e6);
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [0.0, 1e-3],
            dashes: vec![],
        };
        let (segs, truncated) = pattern_segments(&[big], &[line], IslandStyle::Normal);
        assert!(truncated, "should report truncation");
        assert!(segs.len() <= MAX_PATTERN_SEGMENTS + 1);
    }

    /// Far from the origin a fine period stops moving the cycle forward: at
    /// 1e20 a float's step is 16384, and the loop ran forever without
    /// drawing anything that would have stopped it.
    #[test]
    fn a_fine_dash_far_from_the_origin_is_drawn_solid_at_once() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            apply_dashes(1e20, 1e20 + 1e6, &[1e-3, -1e-3], &mut out);
            let _ = tx.send(out);
        });
        let out = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("did not return within 5 s");
        assert_eq!(out, vec![(1e20, 1e20 + 1e6)]);
    }

    #[test]
    fn dashes_start_on_the_pattern_origin() {
        let mut out = Vec::new();
        apply_dashes(0.5, 6.0, &[1.0, -1.0], &mut out);
        // Cycles start at 0, 2, 4: the first dash is cut by the span's start.
        assert_eq!(out, vec![(0.5, 1.0), (2.0, 3.0), (4.0, 5.0)]);
    }

    /// An extent at the edge of the float range: its line indices cast to the
    /// ends of i64, and their difference overflowed.
    #[test]
    fn a_hatch_as_wide_as_a_float_truncates_rather_than_overflowing() {
        let huge = square(-1e308, -1e308, 1.7e308);
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [0.0, 1.0],
            dashes: vec![],
        };
        let (segs, truncated) = pattern_segments(&[huge], &[line], IslandStyle::Normal);
        assert!(truncated);
        assert!(segs.len() <= MAX_PATTERN_SEGMENTS + 1);
    }

    #[test]
    fn empty_input_is_handled() {
        assert!(pattern_segments(&[], &[], IslandStyle::Normal).0.is_empty());
        assert!(solve_regions(&[]).is_empty());
    }
}

#[cfg(test)]
mod island_invariant {
    use super::*;

    /// Under the even-odd rule a point is inside the hatched region when an odd
    /// number of loops contain it. A drawn segment whose midpoint sits inside an
    /// even number of loops is therefore covering an island.
    fn violations(loops: &[Loop], lines: &[PatternLine]) -> usize {
        let (segs, _) = pattern_segments(loops, lines, IslandStyle::Normal);
        segs.iter()
            .filter(|s| {
                let mid = [(s[0][0] + s[1][0]) / 2.0, (s[0][1] + s[1][1]) / 2.0];
                let inside = loops.iter().filter(|l| point_in_loop(mid, l)).count();
                inside % 2 == 0
            })
            .count()
    }

    fn circle(cx: f64, cy: f64, r: f64, n: usize) -> Loop {
        (0..n)
            .map(|i| {
                let a = std::f64::consts::TAU * i as f64 / n as f64;
                [cx + r * a.cos(), cy + r * a.sin()]
            })
            .collect()
    }

    #[test]
    fn a_round_island_is_left_blank() {
        // The shape on the roofs: a big facet with a circular vent in it.
        let outer = vec![[0.0, 0.0], [1000.0, 0.0], [1000.0, 800.0], [0.0, 800.0]];
        let island = circle(500.0, 400.0, 120.0, 64);
        let line = PatternLine {
            angle: 0.6,
            base: [0.0, 0.0],
            offset: [-0.6_f64.sin() * 40.0, 0.6_f64.cos() * 40.0],
            dashes: vec![],
        };
        assert_eq!(violations(&[outer, island], &[line]), 0);
    }

    #[test]
    fn two_islands_are_both_left_blank() {
        let outer = vec![[0.0, 0.0], [1000.0, 0.0], [1000.0, 800.0], [0.0, 800.0]];
        let a = circle(300.0, 400.0, 90.0, 48);
        let b = circle(700.0, 300.0, 70.0, 48);
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [0.0, 25.0],
            dashes: vec![],
        };
        assert_eq!(violations(&[outer, a, b], &[line]), 0);
    }

    #[test]
    fn an_island_inside_an_island_is_hatched_again() {
        let outer = vec![[0.0, 0.0], [1000.0, 0.0], [1000.0, 1000.0], [0.0, 1000.0]];
        let island = circle(500.0, 500.0, 300.0, 64);
        let inner = circle(500.0, 500.0, 100.0, 48);
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 0.0],
            offset: [0.0, 25.0],
            dashes: vec![],
        };
        let loops = vec![outer, island, inner];
        assert_eq!(violations(&loops, std::slice::from_ref(&line)), 0);
        // And the innermost region must actually get hatched: it sits inside
        // all three loops, so the even-odd rule says it is filled again.
        let (segs, _) = pattern_segments(&loops, &[line], IslandStyle::Normal);
        let inner_hits = segs
            .iter()
            .filter(|s| {
                let mid = [(s[0][0] + s[1][0]) / 2.0, (s[0][1] + s[1][1]) / 2.0];
                point_in_loop(mid, &loops[2])
            })
            .count();
        assert!(inner_hits > 0, "innermost region should be hatched");
    }

    #[test]
    fn an_island_touching_the_pattern_angle_is_still_respected() {
        // Lines exactly parallel to an island edge are the fragile case for
        // parity counting.
        let outer = vec![[0.0, 0.0], [1000.0, 0.0], [1000.0, 800.0], [0.0, 800.0]];
        let island = vec![
            [400.0, 375.0],
            [600.0, 375.0],
            [600.0, 425.0],
            [400.0, 425.0],
        ];
        let line = PatternLine {
            angle: 0.0,
            base: [0.0, 375.0],
            offset: [0.0, 25.0],
            dashes: vec![],
        };
        assert_eq!(violations(&[outer, island], &[line]), 0);
    }
}
