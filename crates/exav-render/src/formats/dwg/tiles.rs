//! Spatial buckets, so the renderer can skip geometry that is off screen.
//!
//! Measured on a site plan: a view of the middle tenth of the drawing holds
//! 3.4% of its 2.17M strokes, and the other 96.6% are still fed through the
//! vertex shader every frame to be discarded after the fact. Sorting the
//! buffers into buckets and recording where each one starts lets the renderer
//! issue draw calls only for the buckets a view touches.
//!
//! Three properties of the rest of the system make this safe, and each is a
//! constraint on what this module may do:
//!
//! 1. **Draw order survives reordering**, because it travels per instance in
//!    `order` and is resolved by the depth buffer rather than by the sequence
//!    of draw calls. This is what makes spatial sorting possible at all.
//! 2. **Opaque geometry must still be drawn before any translucent geometry**,
//!    globally, not per bucket. The opaque pass writes depth and the
//!    translucent pass only tests it; interleaving them by bucket would let a
//!    later bucket's opaque geometry paint over an earlier bucket's
//!    translucent. So the buffer is partitioned first and bucketed within each
//!    half, and the renderer keeps its two passes.
//! 3. **A bucket's contents can reach outside it.** A long line belongs to one
//!    bucket but crosses many, so each bucket records the true bounding box of
//!    what it holds rather than its own grid square. The renderer tests that.
//!
//! What this module does *not* do is decide that geometry is too small to
//! matter. 97% of strokes are sub-pixel when the sheet is fitted, and they
//! still deposit the ink that makes a hatched area read as grey; dropping them
//! is a different operation with a different correctness argument.

/// One bucket: a contiguous run of the buffer, and the box it covers.
///
/// The box stays in f64 world coordinates until it is encoded. Narrowing it
/// first and subtracting the origin afterwards loses the box entirely on a
/// drawing sited far from zero (a site plan in national grid coordinates can
/// sit at x = 38,985,257, where an f32 step is about two units), while the
/// vertex buffer subtracts then narrows. The two have to agree or a tile stops containing its contents.
#[derive(Clone, Copy, Debug)]
pub struct Tile {
    /// First element, counted in strokes or in fill vertices.
    pub start: u32,
    pub count: u32,
    pub min_x: f64,
    pub min_y: f64,
    pub max_x: f64,
    pub max_y: f64,
}

/// Bytes one tile occupies in the wire format: `u32 start, count | f32 box[4]`.
pub const TILE_BYTES: usize = 24;

/// Buckets across the wider side of the drawing.
///
/// A view of a tenth of the drawing then touches about a hundred of them, which
/// is fine granularity against a few thousand draw calls in the worst case.
/// Finer buckets cull more but cost more draw calls; this is the knee for the
/// drawings measured.
const GRID: usize = 48;

/// Assign each element to a bucket and report the permutation that sorts them.
///
/// `key` gives an element's representative point. Elements are bucketed by
/// which grid square that point falls in, which keeps the work linear; a long
/// line lands in one bucket and simply widens that bucket's box.
///
/// Returns the sorted order and the tile table. `extent` is the drawing's
/// bounding box; a degenerate one puts everything in a single bucket, which is
/// correct and costs nothing.
pub fn bucket<T, K, B>(items: &[T], extent: [f64; 4], key: K, bounds: B) -> (Vec<u32>, Vec<Tile>)
where
    K: Fn(&T) -> [f64; 2],
    B: Fn(&T) -> [f64; 4],
{
    if items.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let (w, h) = (extent[2] - extent[0], extent[3] - extent[1]);
    let span = w.max(h);
    // One bucket when the drawing has no extent to divide, or when it is so
    // small that dividing it would be noise.
    let cells = if span.is_finite() && span > 0.0 {
        GRID
    } else {
        1
    };
    let step = if cells > 1 {
        span / cells as f64
    } else {
        f64::INFINITY
    };

    let index_of = |p: [f64; 2]| -> usize {
        if cells == 1 {
            return 0;
        }
        let cx = (((p[0] - extent[0]) / step) as isize).clamp(0, cells as isize - 1) as usize;
        let cy = (((p[1] - extent[1]) / step) as isize).clamp(0, cells as isize - 1) as usize;
        cy * cells + cx
    };

    // Counting sort: one pass to size the buckets, one to place into them.
    let bucket_count = cells * cells;
    let mut counts = vec![0u32; bucket_count + 1];
    let mut of: Vec<u32> = Vec::with_capacity(items.len());
    for it in items {
        let b = index_of(key(it));
        of.push(b as u32);
        counts[b + 1] += 1;
    }
    for i in 0..bucket_count {
        counts[i + 1] += counts[i];
    }

    let starts = counts.clone();
    let mut cursor = counts;
    let mut order = vec![0u32; items.len()];
    for (i, b) in of.iter().enumerate() {
        let slot = &mut cursor[*b as usize];
        order[*slot as usize] = i as u32;
        *slot += 1;
    }

    // One tile per non-empty bucket, carrying the true box of its contents
    // rather than its grid square, because a line can reach well outside it.
    let mut tiles = Vec::new();
    for b in 0..bucket_count {
        let (s, e) = (starts[b] as usize, starts[b + 1] as usize);
        if s == e {
            continue;
        }
        let mut bb = [f64::MAX, f64::MAX, f64::MIN, f64::MIN];
        for i in &order[s..e] {
            let r = bounds(&items[*i as usize]);
            bb[0] = bb[0].min(r[0]);
            bb[1] = bb[1].min(r[1]);
            bb[2] = bb[2].max(r[2]);
            bb[3] = bb[3].max(r[3]);
        }
        tiles.push(Tile {
            start: s as u32,
            count: (e - s) as u32,
            min_x: bb[0],
            min_y: bb[1],
            max_x: bb[2],
            max_y: bb[3],
        });
    }

    (order, tiles)
}

/// Narrowing to f32 must never shrink a box, so the bounds are nudged outward
/// by an ulp or so. A box a hair too large draws a tile that was not quite
/// needed; a box a hair too small drops geometry that was on screen.
fn narrow_down(v: f64) -> f32 {
    let f = v as f32;
    f - (f.abs() * f32::EPSILON + f32::MIN_POSITIVE)
}

fn narrow_up(v: f64) -> f32 {
    let f = v as f32;
    f + (f.abs() * f32::EPSILON + f32::MIN_POSITIVE)
}

/// Serialise a tile table, with the boxes relative to `origin`.
///
/// The origin is subtracted before narrowing, exactly as the vertex buffers do
/// it, because the drawings this runs on sit millions of units from zero.
pub fn encode(tiles: &[Tile], origin: [f64; 2]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tiles.len() * TILE_BYTES);
    for t in tiles {
        out.extend_from_slice(&t.start.to_le_bytes());
        out.extend_from_slice(&t.count.to_le_bytes());
        out.extend_from_slice(&narrow_down(t.min_x - origin[0]).to_le_bytes());
        out.extend_from_slice(&narrow_down(t.min_y - origin[1]).to_le_bytes());
        out.extend_from_slice(&narrow_up(t.max_x - origin[0]).to_le_bytes());
        out.extend_from_slice(&narrow_up(t.max_y - origin[1]).to_le_bytes());
    }
    debug_assert_eq!(out.len(), tiles.len() * TILE_BYTES);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Points on a line, so the expected bucketing is easy to state.
    fn points(n: usize) -> Vec<[f64; 2]> {
        (0..n).map(|i| [i as f64, 0.0]).collect()
    }

    fn bucket_points(pts: &[[f64; 2]], extent: [f64; 4]) -> (Vec<u32>, Vec<Tile>) {
        bucket(pts, extent, |p| *p, |p| [p[0], p[1], p[0], p[1]])
    }

    #[test]
    fn empty_input_makes_no_tiles() {
        let (order, tiles) = bucket_points(&[], [0.0, 0.0, 1.0, 1.0]);
        assert!(order.is_empty() && tiles.is_empty());
    }

    /// Every element must appear exactly once, or geometry would be dropped or
    /// drawn twice.
    #[test]
    fn the_permutation_is_a_permutation() {
        let pts = points(1000);
        let (order, _) = bucket_points(&pts, [0.0, -1.0, 999.0, 1.0]);
        assert_eq!(order.len(), pts.len());
        let mut seen = vec![false; pts.len()];
        for i in &order {
            assert!(!seen[*i as usize], "element {i} appears twice");
            seen[*i as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    /// The tiles must tile the buffer: contiguous, in order, covering all of it.
    #[test]
    fn tiles_cover_the_buffer_without_gaps_or_overlap() {
        let pts = points(1000);
        let (order, tiles) = bucket_points(&pts, [0.0, -1.0, 999.0, 1.0]);
        assert!(
            tiles.len() > 1,
            "a spread-out drawing should use many tiles"
        );
        let mut at = 0u32;
        for t in &tiles {
            assert_eq!(t.start, at, "tile starts must be contiguous");
            assert!(t.count > 0, "an empty tile should not be recorded");
            at += t.count;
        }
        assert_eq!(at as usize, order.len());
    }

    /// A tile's box must contain everything in it, because that box is the
    /// only thing the renderer tests before skipping the whole run.
    #[test]
    fn a_tile_box_contains_its_contents() {
        let pts = points(500);
        let (order, tiles) = bucket_points(&pts, [0.0, -1.0, 499.0, 1.0]);
        for t in &tiles {
            for i in &order[t.start as usize..(t.start + t.count) as usize] {
                let p = pts[*i as usize];
                assert!(
                    p[0] >= t.min_x && p[0] <= t.max_x,
                    "{p:?} outside tile x {}..{}",
                    t.min_x,
                    t.max_x
                );
                assert!(p[1] >= t.min_y && p[1] <= t.max_y);
            }
        }
    }

    /// The case the per-tile box exists for: one element reaches far outside
    /// its own grid square, so the square is not what the renderer may test.
    #[test]
    fn a_long_element_widens_its_tile_rather_than_escaping_it() {
        // Ten short segments near the origin, and one spanning the drawing.
        let mut segs: Vec<[f64; 4]> = (0..10)
            .map(|i| [i as f64, 0.0, i as f64 + 0.5, 0.0])
            .collect();
        segs.push([0.0, 0.0, 1000.0, 1000.0]);
        let (order, tiles) = bucket(
            &segs,
            [0.0, 0.0, 1000.0, 1000.0],
            |s| [(s[0] + s[2]) / 2.0, (s[1] + s[3]) / 2.0],
            |s| {
                [
                    s[0].min(s[2]),
                    s[1].min(s[3]),
                    s[0].max(s[2]),
                    s[1].max(s[3]),
                ]
            },
        );
        // Whichever tile holds the long one must have a box that covers it.
        let long_at = order.iter().position(|i| *i == 10).unwrap() as u32;
        let t = tiles
            .iter()
            .find(|t| long_at >= t.start && long_at < t.start + t.count)
            .expect("the long segment is in some tile");
        assert!(
            t.max_x >= 1000.0 && t.max_y >= 1000.0,
            "tile box {t:?} does not cover it"
        );
    }

    /// A drawing with no extent still has to render, in one bucket.
    #[test]
    fn a_degenerate_extent_makes_a_single_tile() {
        let pts = vec![[5.0, 5.0]; 10];
        for extent in [[5.0, 5.0, 5.0, 5.0], [0.0, 0.0, f64::NAN, 1.0]] {
            let (order, tiles) = bucket_points(&pts, extent);
            assert_eq!(order.len(), 10);
            assert_eq!(tiles.len(), 1, "extent {extent:?}");
            assert_eq!(tiles[0].count, 10);
        }
    }

    /// Points outside the stated extent must still land somewhere, not index
    /// out of the grid.
    #[test]
    fn points_outside_the_extent_are_clamped_in() {
        let pts = vec![[-1e9, -1e9], [1e9, 1e9], [0.0, 0.0]];
        let (order, tiles) = bucket_points(&pts, [0.0, 0.0, 10.0, 10.0]);
        assert_eq!(order.len(), 3);
        assert_eq!(tiles.iter().map(|t| t.count).sum::<u32>(), 3);
    }

    #[test]
    fn encode_writes_the_documented_stride_relative_to_the_origin() {
        let tiles = vec![Tile {
            start: 7,
            count: 3,
            min_x: 100.0,
            min_y: 200.0,
            max_x: 110.0,
            max_y: 220.0,
        }];
        let bytes = encode(&tiles, [100.0, 200.0]);
        let f = |o: usize| f32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        assert_eq!(bytes.len(), TILE_BYTES);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 3);
        // Nudged outward, so the encoded box still contains the original.
        assert!(f(8) <= 0.0 && f(8) > -1e-6, "min x {}", f(8));
        assert!(f(12) <= 0.0 && f(12) > -1e-6, "min y {}", f(12));
        assert!(f(16) >= 10.0 && f(16) < 10.0 + 1e-5, "max x {}", f(16));
        assert!(f(20) >= 20.0 && f(20) < 20.0 + 1e-5, "max y {}", f(20));
    }

    /// Narrowing to f32 must never shrink a box. A drawing sited millions of
    /// units from the origin is where this bites: the origin has to come off
    /// before the narrowing, exactly as the vertex buffers do it, or the box
    /// loses all its precision and stops containing its contents.
    #[test]
    fn encoding_a_box_never_shrinks_it() {
        // A site plan's origin in national grid coordinates, where an f32 step
        // is about two units.
        let origin = [38_985_257.044_716_63, -5_624_989.275_250_534];
        let mut checked = 0;
        for k in 0..200 {
            let dx = k as f64 * 0.37;
            let t = Tile {
                start: 0,
                count: 1,
                min_x: origin[0] + dx,
                min_y: origin[1] - dx,
                max_x: origin[0] + dx + 1.0 / 3.0,
                max_y: origin[1] - dx + 7.0 / 9.0,
            };
            let b = encode(&[t], origin);
            let f = |o: usize| f32::from_le_bytes(b[o..o + 4].try_into().unwrap());
            // What the vertex buffer would store for the same corners.
            let vmin = [(t.min_x - origin[0]) as f32, (t.min_y - origin[1]) as f32];
            let vmax = [(t.max_x - origin[0]) as f32, (t.max_y - origin[1]) as f32];
            assert!(f(8) <= vmin[0], "min x {} > vertex {}", f(8), vmin[0]);
            assert!(f(12) <= vmin[1], "min y {} > vertex {}", f(12), vmin[1]);
            assert!(f(16) >= vmax[0], "max x {} < vertex {}", f(16), vmax[0]);
            assert!(f(20) >= vmax[1], "max y {} < vertex {}", f(20), vmax[1]);
            checked += 1;
        }
        assert_eq!(checked, 200);
    }
}
