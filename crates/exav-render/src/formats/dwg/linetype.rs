//! Linetype patterns: turning a polyline into its drawn dashes.
//!
//! A DWG linetype is a repeating run of signed lengths in drawing units:
//! positive draws, negative skips, zero is a dot. The phase runs along the
//! whole polyline rather than restarting at each vertex, which is what keeps a
//! dashed outline looking continuous around its corners.

/// Above this many dashes on one polyline, fall back to a solid line. A tiny
/// linetype scale over a long polyline would otherwise generate millions of
/// segments for something that reads as solid anyway.
const MAX_DASHES: usize = 20_000;

/// Text carried by one element of a complex linetype.
///
/// A linetype like GAZ draws its dashes and stamps "GAS" into the gaps at every
/// repetition. Without this the line is drawn as plain dashes and the label
/// that says what the pipe carries is missing.
#[derive(Clone, Debug)]
pub struct Label {
    /// Index into `runs` of the element that carries the text.
    pub run: usize,
    pub text: String,
    /// Text height in drawing units.
    pub height: f64,
    /// Offset from the element's position: along the line, then across it.
    pub offset: [f64; 2],
    pub rotation: f64,
    /// Rotation is world-absolute rather than relative to the line.
    pub absolute_rotation: bool,
    /// The face the label's text style resolves to. These are usually stroke
    /// fonts, since a linetype that stamps a symbol along a line is drawn from
    /// an SHX shape file.
    pub face: super::font::Face,
}

/// One placed copy of a label, in drawing coordinates.
pub struct Placement {
    pub x: f64,
    pub y: f64,
    pub angle: f64,
    /// Index into the pattern's `labels`.
    pub label: usize,
}

/// A resolved pattern: signed run lengths, already scaled to drawing units.
#[derive(Clone, Debug, Default)]
pub struct Pattern {
    pub runs: Vec<f64>,
    pub total: f64,
    pub labels: Vec<Label>,
}

impl Pattern {
    /// Build from raw element lengths, or None when the result draws solid.
    #[cfg(test)]
    pub fn new(elements: &[f64], scale: f64) -> Option<Pattern> {
        Pattern::with_labels(elements, &[], scale)
    }

    /// Build a complex linetype, whose elements can stamp text along the line.
    ///
    /// The labels' heights and offsets scale with the pattern, the way AutoCAD
    /// scales them.
    pub fn with_labels(elements: &[f64], labels: &[Label], scale: f64) -> Option<Pattern> {
        if elements.is_empty() || !scale.is_finite() || scale <= 0.0 {
            return None;
        }
        let runs: Vec<f64> = elements.iter().map(|e| e * scale).collect();
        let total: f64 = runs.iter().map(|r| r.abs()).sum();
        if !total.is_finite() || total <= 1e-9 {
            return None;
        }
        // A pattern with no gaps is a solid line with extra steps, unless it
        // stamps something along the way.
        if labels.is_empty() && runs.iter().all(|r| *r > 0.0) {
            return None;
        }
        let labels = labels
            .iter()
            .map(|l| Label {
                height: l.height * scale,
                offset: [l.offset[0] * scale, l.offset[1] * scale],
                ..l.clone()
            })
            .collect();
        Some(Pattern {
            runs,
            total,
            labels,
        })
    }
}

#[cfg(test)]
fn polyline_length(pts: &[[f64; 2]], closed: bool) -> f64 {
    let mut total = 0.0;
    for w in pts.windows(2) {
        total += ((w[1][0] - w[0][0]).powi(2) + (w[1][1] - w[0][1]).powi(2)).sqrt();
    }
    if closed && pts.len() > 2 {
        let a = pts[pts.len() - 1];
        let b = pts[0];
        total += ((b[0] - a[0]).powi(2) + (b[1] - a[1]).powi(2)).sqrt();
    }
    total
}

/// Whether a run of `len` would need more than `MAX_DASHES` dashes. In `f64`:
/// an infinite length, cast to `usize` and multiplied, overflows.
fn too_fine(len: f64, pattern: &Pattern) -> bool {
    !((len / pattern.total).ceil() * pattern.runs.len() as f64 <= MAX_DASHES as f64)
}

/// The drawn intervals along a polyline of length `len`, in arc-length.
///
/// A zero-length run is a dot and comes back as a zero-width interval, which
/// the renderer draws as a round cap.
fn drawn_intervals(len: f64, pattern: &Pattern) -> Option<Vec<(f64, f64)>> {
    // NaN included: a polyline with a non-finite vertex draws nothing.
    if !(len > 0.0) {
        return Some(Vec::new());
    }
    if too_fine(len, pattern) {
        return None;
    }

    let mut out = Vec::new();
    let mut s = 0.0;
    while s < len {
        for run in &pattern.runs {
            if *run > 0.0 {
                let e = (s + run).min(len);
                if e > s {
                    out.push((s, e));
                }
                s += run;
            } else if *run < 0.0 {
                s += -run;
            } else {
                // A dot: no length, but it still marks the line.
                out.push((s, s));
            }
            if s >= len {
                break;
            }
        }
    }
    Some(out)
}

/// Point at arc-length `s` along the polyline, plus the segment index.
fn point_at(pts: &[[f64; 2]], cum: &[f64], s: f64) -> [f64; 2] {
    // cum[i] is the arc-length at pts[i].
    let mut lo = 0usize;
    let mut hi = cum.len() - 1;
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if cum[mid] <= s {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let seg = cum[hi] - cum[lo];
    let t = if seg.abs() < 1e-12 {
        0.0
    } else {
        (s - cum[lo]) / seg
    };
    [
        pts[lo][0] + (pts[hi][0] - pts[lo][0]) * t,
        pts[lo][1] + (pts[hi][1] - pts[lo][1]) * t,
    ]
}

/// Split a polyline into the segments the linetype actually draws.
///
/// Returns None when the pattern would draw solid, so the caller can take its
/// cheaper path rather than round-tripping every segment through here.
pub fn dash_polyline(
    pts: &[[f64; 2]],
    closed: bool,
    pattern: &Pattern,
) -> Option<Vec<[[f64; 2]; 2]>> {
    if pts.len() < 2 {
        return Some(Vec::new());
    }

    // Work on an explicitly closed copy so the phase carries round the seam.
    let Some((path, cum)) = arc_lengths(pts, closed) else {
        return Some(Vec::new());
    };
    let len = cum[cum.len() - 1];

    let intervals = drawn_intervals(len, pattern)?;

    let mut out = Vec::with_capacity(intervals.len());
    for (s0, s1) in intervals {
        // Emit each drawn interval following the polyline's own vertices, so a
        // dash spanning a corner bends with it instead of cutting across.
        let mut prev = point_at(&path, &cum, s0);
        // The vertices past `s0`: found by search, as a scan from the start
        // for every dash is quadratic in a long polyline.
        let first = cum.partition_point(|&c| c <= s0);
        for i in first..path.len() {
            if cum[i] >= s1 {
                break;
            }
            out.push([prev, path[i]]);
            prev = path[i];
        }
        let end = point_at(&path, &cum, s1);
        out.push([prev, end]);
    }
    Some(out)
}

/// Where each copy of the pattern's embedded text lands along a polyline.
///
/// The phase is the same walk the dashes use, so a label sits in the gap its
/// definition puts it in rather than drifting against the dashes.
pub fn dash_labels(pts: &[[f64; 2]], closed: bool, pattern: &Pattern) -> Vec<Placement> {
    let mut out = Vec::new();
    if pattern.labels.is_empty() || pts.len() < 2 {
        return out;
    }
    let Some((path, cum)) = arc_lengths(pts, closed) else {
        return out;
    };
    let len = cum[cum.len() - 1];

    // Same guard as the dashes: a pattern this fine reads as a solid line.
    if too_fine(len, pattern) {
        return out;
    }

    let mut s = 0.0;
    while s < len {
        for (i, run) in pattern.runs.iter().enumerate() {
            for (li, label) in pattern.labels.iter().enumerate() {
                if label.run != i {
                    continue;
                }
                let at = s + label.offset[0];
                if at < 0.0 || at > len {
                    continue;
                }
                let p = point_at(&path, &cum, at);
                let angle = tangent_at(&path, &cum, at);
                let (sin_a, cos_a) = angle.sin_cos();
                out.push(Placement {
                    // The across-the-line offset follows the line's own normal.
                    x: p[0] - label.offset[1] * sin_a,
                    y: p[1] + label.offset[1] * cos_a,
                    angle: if label.absolute_rotation {
                        label.rotation
                    } else {
                        angle + label.rotation
                    },
                    label: li,
                });
            }
            s += run.abs();
            if s >= len {
                break;
            }
        }
        // A pattern of nothing but dots would never advance.
        if pattern.total <= 1e-12 {
            break;
        }
    }
    out
}

/// Direction of the polyline at arc-length `s`.
fn tangent_at(pts: &[[f64; 2]], cum: &[f64], s: f64) -> f64 {
    let mut i = 0usize;
    while i + 2 < cum.len() && cum[i + 1] <= s {
        i += 1;
    }
    let d = [pts[i + 1][0] - pts[i][0], pts[i + 1][1] - pts[i][1]];
    if d[0].abs() < 1e-12 && d[1].abs() < 1e-12 {
        0.0
    } else {
        d[1].atan2(d[0])
    }
}

/// The polyline closed if it needs to be, with the arc-length at each vertex.
fn arc_lengths(pts: &[[f64; 2]], closed: bool) -> Option<(Vec<[f64; 2]>, Vec<f64>)> {
    let mut path: Vec<[f64; 2]> = pts.to_vec();
    if closed && pts.len() > 2 {
        path.push(pts[0]);
    }
    let mut cum = Vec::with_capacity(path.len());
    let mut acc = 0.0;
    cum.push(0.0);
    for w in path.windows(2) {
        acc += ((w[1][0] - w[0][0]).powi(2) + (w[1][1] - w[0][1]).powi(2)).sqrt();
        cum.push(acc);
    }
    (acc > 1e-12).then_some((path, cum))
}

/// Total drawn length, for tests.
#[cfg(test)]
pub fn drawn_length(segments: &[[[f64; 2]; 2]]) -> f64 {
    segments
        .iter()
        .map(|s| ((s[1][0] - s[0][0]).powi(2) + (s[1][1] - s[0][1]).powi(2)).sqrt())
        .sum()
}

#[cfg(test)]
mod embedded_text {
    use super::*;

    /// A gas-main linetype, as site plans have: a dash, then a gap holding
    /// "GAS".
    fn gaz(scale: f64) -> Pattern {
        Pattern::with_labels(
            &[10.0, -5.0],
            &[Label {
                run: 1,
                text: "GAS".to_string(),
                height: 2.54,
                offset: [-2.54, -1.27],
                rotation: 0.0,
                absolute_rotation: false,
                face: super::super::font::Face::Stroke,
            }],
            scale,
        )
        .unwrap()
    }

    #[test]
    fn the_text_repeats_with_the_pattern() {
        let p = gaz(1.0);
        // 100 units at 15 per repetition: six or seven labels.
        let places = dash_labels(&[[0.0, 0.0], [100.0, 0.0]], false, &p);
        assert!(
            places.len() >= 6 && places.len() <= 7,
            "{} labels",
            places.len()
        );

        // Evenly spaced, one period apart.
        for w in places.windows(2) {
            assert!(
                (w[1].x - w[0].x - 15.0).abs() < 1e-6,
                "{} to {}",
                w[0].x,
                w[1].x
            );
        }
    }

    #[test]
    fn the_offsets_place_it_along_and_across_the_line() {
        let places = dash_labels(&[[0.0, 0.0], [100.0, 0.0]], false, &gaz(1.0));
        let first = &places[0];
        // The dash runs 0..10, so the gap starts at 10 and the label sits
        // 2.54 back along it and 1.27 below it.
        assert!((first.x - (10.0 - 2.54)).abs() < 1e-6, "x {}", first.x);
        assert!((first.y - -1.27).abs() < 1e-6, "y {}", first.y);
        assert!(first.angle.abs() < 1e-9, "angle {}", first.angle);
    }

    #[test]
    fn everything_scales_with_the_linetype_scale() {
        let p = gaz(2.0);
        assert!((p.labels[0].height - 5.08).abs() < 1e-9);
        let places = dash_labels(&[[0.0, 0.0], [200.0, 0.0]], false, &p);
        assert!(
            (places[0].x - (20.0 - 5.08)).abs() < 1e-6,
            "x {}",
            places[0].x
        );
    }

    #[test]
    fn the_text_turns_with_the_line() {
        // Straight up: the label rotates a quarter turn with it.
        let places = dash_labels(&[[0.0, 0.0], [0.0, 100.0]], false, &gaz(1.0));
        assert!(!places.is_empty());
        assert!(
            (places[0].angle - std::f64::consts::FRAC_PI_2).abs() < 1e-9,
            "angle {}",
            places[0].angle
        );
        // And the across-the-line offset now moves it in x.
        assert!((places[0].x - 1.27).abs() < 1e-6, "x {}", places[0].x);
    }

    #[test]
    fn a_pattern_without_labels_places_nothing() {
        let p = Pattern::new(&[5.0, -5.0], 1.0).unwrap();
        assert!(dash_labels(&[[0.0, 0.0], [100.0, 0.0]], false, &p).is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(len: f64) -> Vec<[f64; 2]> {
        vec![[0.0, 0.0], [len, 0.0]]
    }

    /// Two finite vertices a float's range apart make an infinite length;
    /// the dash count guard cast it to `usize` and multiplied, which overflowed.
    #[test]
    fn a_line_too_long_to_measure_is_drawn_solid() {
        let p = Pattern::new(&[1.0, -1.0], 1.0).unwrap();
        let pts = [[-1e308, 0.0], [1e308, 0.0]];
        assert!(dash_polyline(&pts, false, &p).is_none());
        let label = Label {
            run: 1,
            text: "X".to_string(),
            height: 1.0,
            offset: [0.0, 0.0],
            rotation: 0.0,
            absolute_rotation: false,
            face: super::super::font::Face::Stroke,
        };
        let labelled = Pattern::with_labels(&[1.0, -1.0], &[label], 1.0).unwrap();
        assert!(dash_labels(&pts, false, &labelled).is_empty());
    }

    /// Each dash looked for its vertices from the start of the polyline, so
    /// the dashes of a polyline of a million vertices took minutes. The
    /// bound is wide: the pass is a few milliseconds.
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "timing")]
    fn the_dashes_of_a_long_polyline_do_not_each_scan_all_its_vertices() {
        let pts: Vec<[f64; 2]> = (0..=1_000_000).map(|i| [f64::from(i), 0.0]).collect();
        let p = Pattern::new(&[50.0, -50.0], 1.0).unwrap();
        let t = std::time::Instant::now();
        let dashes = dash_polyline(&pts, false, &p).unwrap();
        assert!(t.elapsed().as_millis() < 400, "took {:?}", t.elapsed());
        // 10,000 dashes of 50 unit segments each.
        assert_eq!(dashes.len(), 10_000 * 50);
        assert_eq!(dashes[0], [[0.0, 0.0], [1.0, 0.0]]);
        assert_eq!(
            dashes[dashes.len() - 1],
            [[999_949.0, 0.0], [999_950.0, 0.0]]
        );
    }

    #[test]
    fn an_all_dash_pattern_is_treated_as_solid() {
        assert!(Pattern::new(&[1.0, 2.0], 1.0).is_none());
    }

    #[test]
    fn an_empty_or_zero_scale_pattern_is_solid() {
        assert!(Pattern::new(&[], 1.0).is_none());
        assert!(Pattern::new(&[1.0, -1.0], 0.0).is_none());
        assert!(Pattern::new(&[0.0], 1.0).is_none());
    }

    #[test]
    fn a_half_on_half_off_pattern_draws_half_the_length() {
        let p = Pattern::new(&[5.0, -5.0], 1.0).unwrap();
        let segs = dash_polyline(&line(100.0), false, &p).unwrap();
        let drawn = drawn_length(&segs);
        assert!((drawn - 50.0).abs() < 1e-6, "drawn {drawn} of 100");
        assert_eq!(segs.len(), 10);
    }

    #[test]
    fn the_scale_stretches_the_pattern() {
        let p = Pattern::new(&[5.0, -5.0], 2.0).unwrap();
        let segs = dash_polyline(&line(100.0), false, &p).unwrap();
        // Dashes are twice as long, so half as many of them.
        assert_eq!(segs.len(), 5);
        assert!((drawn_length(&segs) - 50.0).abs() < 1e-6);
    }

    #[test]
    fn dashes_start_at_the_beginning_of_the_line() {
        let p = Pattern::new(&[2.0, -3.0], 1.0).unwrap();
        let segs = dash_polyline(&line(20.0), false, &p).unwrap();
        assert_eq!(segs[0][0], [0.0, 0.0]);
        assert!((segs[0][1][0] - 2.0).abs() < 1e-9);
    }

    #[test]
    fn the_last_dash_is_clipped_to_the_line_end() {
        let p = Pattern::new(&[8.0, -1.0], 1.0).unwrap();
        let segs = dash_polyline(&line(10.0), false, &p).unwrap();
        let last = segs.last().unwrap();
        let far = last[0][0].max(last[1][0]);
        assert!(far <= 10.0 + 1e-9, "dash ran past the end to {far}");
    }

    #[test]
    fn the_phase_carries_across_a_corner() {
        // An L: the dash pattern must not restart at the bend.
        let pts = vec![[0.0, 0.0], [10.0, 0.0], [10.0, 10.0]];
        let p = Pattern::new(&[3.0, -3.0], 1.0).unwrap();
        let segs = dash_polyline(&pts, false, &p).unwrap();
        let drawn = drawn_length(&segs);
        // 20 units of path, half drawn, within one partial dash.
        assert!((drawn - 10.0).abs() < 3.0, "drawn {drawn} of 20");
        // A dash crossing the corner must bend, not cut the corner.
        for s in &segs {
            let straight = s[0][0] <= 10.0 + 1e-9 && s[1][0] <= 10.0 + 1e-9;
            assert!(straight, "segment left the path: {s:?}");
        }
    }

    #[test]
    fn a_dash_spanning_a_corner_is_split_at_the_vertex() {
        let pts = vec![[0.0, 0.0], [5.0, 0.0], [5.0, 5.0]];
        // One long dash covering the whole path.
        let p = Pattern::new(&[100.0, -1.0], 1.0).unwrap();
        let segs = dash_polyline(&pts, false, &p).unwrap();
        // Two collinear runs, so the corner survives.
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0][1], [5.0, 0.0]);
    }

    #[test]
    fn a_closed_polyline_dashes_round_the_seam() {
        let square = vec![[0.0, 0.0], [10.0, 0.0], [10.0, 10.0], [0.0, 10.0]];
        let p = Pattern::new(&[2.0, -2.0], 1.0).unwrap();
        let segs = dash_polyline(&square, true, &p).unwrap();
        // Perimeter 40, half drawn.
        assert!((drawn_length(&segs) - 20.0).abs() < 1.0);
        // The closing edge must be represented.
        let on_closing = segs.iter().any(|s| s[0][0] < 1e-6 && s[1][0] < 1e-6);
        assert!(on_closing, "closing edge missing");
    }

    #[test]
    fn a_dot_is_emitted_as_a_zero_length_segment() {
        let p = Pattern::new(&[5.0, -5.0, 0.0, -5.0], 1.0).unwrap();
        let segs = dash_polyline(&line(60.0), false, &p).unwrap();
        let dots = segs.iter().filter(|s| s[0] == s[1]).count();
        assert!(dots >= 3, "expected dots, found {dots}");
    }

    #[test]
    fn an_absurdly_fine_pattern_falls_back_to_solid() {
        let p = Pattern::new(&[1.0, -1.0], 1e-6).unwrap();
        assert!(
            dash_polyline(&line(1e6), false, &p).is_none(),
            "should refuse rather than emit millions of dashes"
        );
    }

    #[test]
    fn degenerate_geometry_is_handled() {
        let p = Pattern::new(&[1.0, -1.0], 1.0).unwrap();
        assert!(dash_polyline(&[], false, &p).unwrap().is_empty());
        assert!(dash_polyline(&[[0.0, 0.0]], false, &p).unwrap().is_empty());
        // Zero-length path.
        assert!(dash_polyline(&[[1.0, 1.0], [1.0, 1.0]], false, &p)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn drawn_segments_stay_on_the_original_path() {
        let pts = vec![[0.0, 0.0], [10.0, 0.0], [10.0, 10.0], [20.0, 10.0]];
        let p = Pattern::new(&[1.5, -1.0], 1.0).unwrap();
        let segs = dash_polyline(&pts, false, &p).unwrap();
        // Every emitted point must lie on one of the three legs.
        for s in &segs {
            for q in s {
                let on_a = q[1].abs() < 1e-6 && q[0] >= -1e-6 && q[0] <= 10.0 + 1e-6;
                let on_b = (q[0] - 10.0).abs() < 1e-6 && q[1] >= -1e-6 && q[1] <= 10.0 + 1e-6;
                let on_c = (q[1] - 10.0).abs() < 1e-6 && q[0] >= 10.0 - 1e-6 && q[0] <= 20.0 + 1e-6;
                assert!(on_a || on_b || on_c, "point {q:?} left the path");
            }
        }
        assert!((polyline_length(&pts, false) - 30.0).abs() < 1e-9);
    }
}
