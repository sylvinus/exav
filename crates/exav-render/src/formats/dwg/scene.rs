//! Scene accumulation and the wire format handed to WebGL.
//!
//! Geometry is accumulated in f64 so a drawing in survey coordinates keeps its
//! precision, then re-emitted as f32 relative to a per-drawing origin. See
//! DESIGN.md section 4.4.

/// 2D affine transform, applied as the block/insert stack is walked.
///
/// x' = a*x + c*y + e
/// y' = b*x + d*y + f
#[derive(Clone, Copy, Debug)]
pub struct Affine {
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
    pub e: f64,
    pub f: f64,
}

impl Affine {
    pub const IDENTITY: Affine = Affine {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        e: 0.0,
        f: 0.0,
    };

    pub fn new(tx: f64, ty: f64, sx: f64, sy: f64, rot: f64) -> Affine {
        let (sin_r, cos_r) = rot.sin_cos();
        Affine {
            a: sx * cos_r,
            b: sx * sin_r,
            c: -sy * sin_r,
            d: sy * cos_r,
            e: tx,
            f: ty,
        }
    }

    /// `self` applied after `inner`, i.e. the child transform composed into the parent.
    pub fn mul(&self, inner: &Affine) -> Affine {
        Affine {
            a: self.a * inner.a + self.c * inner.b,
            b: self.b * inner.a + self.d * inner.b,
            c: self.a * inner.c + self.c * inner.d,
            d: self.b * inner.c + self.d * inner.d,
            e: self.a * inner.e + self.c * inner.f + self.e,
            f: self.b * inner.e + self.d * inner.f + self.f,
        }
    }

    #[inline]
    pub fn apply(&self, x: f64, y: f64) -> [f64; 2] {
        [
            self.a * x + self.c * y + self.e,
            self.b * x + self.d * y + self.f,
        ]
    }

    /// Object coordinates to world, for an entity with the given extrusion.
    ///
    /// This is the DXF Arbitrary Axis Algorithm, projected onto the XY plane.
    /// Entities stored in OCS (arcs, circles, polylines, text, inserts, hatches)
    /// keep their coordinates in a frame defined by their extrusion vector, and
    /// an extrusion of (0,0,-1) mirrors the X axis. Ignoring it puts such an
    /// entity the same distance the *other* side of the origin, which is how a
    /// block sitting at x=16613 ends up drawn at x=-16613.
    ///
    /// `elevation` is the entity's height along its own normal.
    pub fn from_extrusion(nx: f64, ny: f64, nz: f64, elevation: f64) -> Affine {
        let len = (nx * nx + ny * ny + nz * nz).sqrt();
        if !len.is_finite() || len < 1e-12 {
            return Affine::IDENTITY;
        }
        let (nx, ny, nz) = (nx / len, ny / len, nz / len);

        // The overwhelmingly common case; skip the algebra.
        if nz > 0.0 && nx.abs() < 1e-12 && ny.abs() < 1e-12 {
            return Affine::IDENTITY;
        }

        // Pick the reference axis the way the spec does, avoiding a degenerate
        // cross product when the normal is close to world Z.
        let cross = |a: [f64; 3], b: [f64; 3]| {
            [
                a[1] * b[2] - a[2] * b[1],
                a[2] * b[0] - a[0] * b[2],
                a[0] * b[1] - a[1] * b[0],
            ]
        };
        let norm = |v: [f64; 3]| {
            let l = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt();
            if l < 1e-12 {
                [1.0, 0.0, 0.0]
            } else {
                [v[0] / l, v[1] / l, v[2] / l]
            }
        };

        let n = [nx, ny, nz];
        let ax = if nx.abs() < 1.0 / 64.0 && ny.abs() < 1.0 / 64.0 {
            cross([0.0, 1.0, 0.0], n)
        } else {
            cross([0.0, 0.0, 1.0], n)
        };
        let ax = norm(ax);
        let ay = norm(cross(n, ax));

        Affine {
            a: ax[0],
            b: ax[1],
            c: ay[0],
            d: ay[1],
            e: elevation * nx,
            f: elevation * ny,
        }
    }

    /// Mean absolute scale, used to keep lineweight sane through scaled blocks.
    pub fn scale_magnitude(&self) -> f64 {
        let sx = (self.a * self.a + self.b * self.b).sqrt();
        let sy = (self.c * self.c + self.d * self.d).sqrt();
        ((sx + sy) / 2.0).max(1e-12)
    }
}

/// One line segment, pre-transform-applied, still in drawing coordinates.
#[derive(Clone, Copy)]
pub struct Stroke {
    pub x0: f64,
    pub y0: f64,
    pub x1: f64,
    pub y1: f64,
    pub rgba: u32,
    /// layer index (16 bits) | lineweight in 1/100 mm (8 bits) | flags (8 bits)
    pub attr: u32,
    /// Position in the drawing's draw order. See `Scene::order`.
    pub order: u32,
}

/// One triangle corner.
#[derive(Clone, Copy)]
pub struct FillVertex {
    pub x: f64,
    pub y: f64,
    pub rgba: u32,
    pub attr: u32,
    pub order: u32,
}

pub const STROKE_BYTES: usize = 28;
pub const FILL_BYTES: usize = 20;

/// Fill flag: paint the viewer's background colour instead of the vertex's.
///
/// A WIPEOUT masks whatever lies beneath it, and what it masks to is the
/// background, which the tessellator does not know. The renderer substitutes it.
pub const FILL_FLAG_BACKGROUND: u8 = 1;

/// Flag: this colour is AutoCAD's colour 7, so it flips with the background.
///
/// Colour 7 means "white or black, whichever contrasts". A true colour that
/// happens to be white does not: a solid white hatch is a mask the author drew
/// to blank what lies under it, and flipping that one to black paints a black
/// box over the sheet.
pub const FLAG_CONTRAST: u8 = 0x80;

/// Encode a feature spacing into the low 7 bits of the flags field.
///
/// Hatch pattern lines are drawn at a one-pixel minimum width like any other
/// hairline. Once the pattern's spacing falls below a pixel, those lines
/// overlap and saturate to solid black, while a plot of the same drawing shows
/// a light grey: on paper the line is far thinner than the gap between lines.
/// Recording the spacing lets the shader fade the lines back to the tone they
/// should average out to. 0 means "do not fade".
#[inline]
pub fn encode_fade_spacing(spacing: f64) -> u8 {
    if !spacing.is_finite() || spacing <= 1.0 {
        return 0;
    }
    // Logarithmic, eight steps to the octave, which covers millimetres through
    // to tens of metres in the seven bits left beside the contrast flag.
    let code = (spacing.log2() * 8.0).round();
    code.clamp(1.0, 127.0) as u8
}

#[inline]
pub fn pack_attr(layer: u16, lineweight: u8, flags: u8) -> u32 {
    (layer as u32) | ((lineweight as u32) << 16) | ((flags as u32) << 24)
}

#[inline]
pub fn pack_rgba(r: u8, g: u8, b: u8, a: u8) -> u32 {
    // Little-endian u32 so the GPU reads it as a UNSIGNED_BYTE RGBA vec4.
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16) | ((a as u32) << 24)
}

/// A position in the scene's buffers, taken before a viewport is drawn.
#[derive(Clone, Copy)]
pub struct Mark {
    strokes: usize,
    fills: usize,
    texts: usize,
}

impl Mark {
    pub fn strokes(&self) -> usize {
        self.strokes
    }
}

#[derive(Default)]
pub struct Scene {
    pub strokes: Vec<Stroke>,
    pub fills: Vec<FillVertex>,
    pub texts: Vec<super::text::TextRun>,
    /// Draw order counter. AutoCAD paints entities in this sequence, and later
    /// entities cover earlier ones: a small solid fill placed over a hatch is
    /// how a roof vent masks the tiles beneath it. Without it a viewer that
    /// batches all fills before all strokes draws the hatch back on top.
    pub order: u32,
    min_x: f64,
    min_y: f64,
    max_x: f64,
    max_y: f64,
}

impl Scene {
    pub fn new() -> Scene {
        Scene {
            strokes: Vec::new(),
            fills: Vec::new(),
            texts: Vec::new(),
            order: 0,
            min_x: f64::INFINITY,
            min_y: f64::INFINITY,
            max_x: f64::NEG_INFINITY,
            max_y: f64::NEG_INFINITY,
        }
    }

    /// Record a text run. Only the anchor grows the extents: the rendered width
    /// depends on font metrics the renderer has and this side does not.
    pub fn push_text(&mut self, run: super::text::TextRun) {
        if !(run.x.is_finite() && run.y.is_finite() && run.height.is_finite()) {
            return;
        }
        if run.text.is_empty() {
            return;
        }
        self.grow(run.x, run.y);
        self.texts.push(run);
    }

    #[inline]
    fn grow(&mut self, x: f64, y: f64) {
        if x < self.min_x {
            self.min_x = x;
        }
        if y < self.min_y {
            self.min_y = y;
        }
        if x > self.max_x {
            self.max_x = x;
        }
        if y > self.max_y {
            self.max_y = y;
        }
    }

    pub fn push_stroke(&mut self, x0: f64, y0: f64, x1: f64, y1: f64, rgba: u32, attr: u32) {
        if !(x0.is_finite() && y0.is_finite() && x1.is_finite() && y1.is_finite()) {
            return;
        }
        self.grow(x0, y0);
        self.grow(x1, y1);
        let order = self.order;
        self.strokes.push(Stroke {
            x0,
            y0,
            x1,
            y1,
            rgba,
            attr,
            order,
        });
    }

    /// Push a flattened polyline as a run of segments.
    pub fn push_polyline(&mut self, pts: &[[f64; 2]], closed: bool, rgba: u32, attr: u32) {
        if pts.len() < 2 {
            return;
        }
        for w in pts.windows(2) {
            self.push_stroke(w[0][0], w[0][1], w[1][0], w[1][1], rgba, attr);
        }
        if closed {
            let a = pts[pts.len() - 1];
            let b = pts[0];
            self.push_stroke(a[0], a[1], b[0], b[1], rgba, attr);
        }
    }

    pub fn push_triangle(
        &mut self,
        p0: [f64; 2],
        p1: [f64; 2],
        p2: [f64; 2],
        rgba: u32,
        attr: u32,
    ) {
        for p in [p0, p1, p2] {
            if !(p[0].is_finite() && p[1].is_finite()) {
                return;
            }
        }
        let order = self.order;
        for p in [p0, p1, p2] {
            self.grow(p[0], p[1]);
            self.fills.push(FillVertex {
                x: p[0],
                y: p[1],
                rgba,
                attr,
                order,
            });
        }
    }

    /// A triangle whose corners carry their own colours, for gradient fills.
    pub fn push_triangle_shaded(&mut self, pts: [[f64; 2]; 3], rgba: [u32; 3], attr: u32) {
        for p in pts {
            if !(p[0].is_finite() && p[1].is_finite()) {
                return;
            }
        }
        let order = self.order;
        for (p, rgba) in pts.iter().zip(rgba) {
            self.grow(p[0], p[1]);
            self.fills.push(FillVertex {
                x: p[0],
                y: p[1],
                rgba,
                attr,
                order,
            });
        }
    }

    pub fn is_empty(&self) -> bool {
        self.strokes.is_empty() && self.fills.is_empty() && self.texts.is_empty()
    }

    /// Where each buffer currently ends, for a later `clip_since`.
    pub fn mark(&self) -> Mark {
        Mark {
            strokes: self.strokes.len(),
            fills: self.fills.len(),
            texts: self.texts.len(),
        }
    }

    /// Cut everything pushed since `mark` down to the clip shape.
    ///
    /// Viewport contents are tessellated first and clipped after, because an
    /// entity's position is only known once its transform has been applied.
    /// Extents are left stale on purpose: they are recomputed once the whole
    /// layout is built, by which point the discarded geometry is gone.
    pub fn clip_since(&mut self, mark: Mark, shape: &super::clip::ClipShape) {
        let mut spans = Vec::new();
        let mut kept: Vec<Stroke> = Vec::new();
        for s in self.strokes.drain(mark.strokes..) {
            let (a, b) = ([s.x0, s.y0], [s.x1, s.y1]);
            if a == b {
                // A POINT entity: a zero-length stroke has no span to clip.
                if shape.contains(a) {
                    kept.push(s);
                }
                continue;
            }
            shape.clip_segment(a, b, &mut spans);
            for (t0, t1) in spans.iter().copied() {
                kept.push(Stroke {
                    x0: a[0] + (b[0] - a[0]) * t0,
                    y0: a[1] + (b[1] - a[1]) * t0,
                    x1: a[0] + (b[0] - a[0]) * t1,
                    y1: a[1] + (b[1] - a[1]) * t1,
                    ..s
                });
            }
        }
        self.strokes.extend(kept);

        let mut tris = Vec::new();
        let mut kept_fills: Vec<FillVertex> = Vec::new();
        let tail: Vec<FillVertex> = self.fills.drain(mark.fills..).collect();
        for t in tail.as_chunks::<3>().0 {
            let tri = [[t[0].x, t[0].y], [t[1].x, t[1].y], [t[2].x, t[2].y]];
            shape.clip_triangle(tri, &mut tris);
            for piece in tris.iter() {
                for (i, p) in piece.iter().enumerate() {
                    kept_fills.push(FillVertex {
                        x: p[0],
                        y: p[1],
                        ..t[i]
                    });
                }
            }
        }
        self.fills.extend(kept_fills);

        // A run is kept or dropped whole: its rendered width lives on the other
        // side of the worker boundary, so there is no box here to cut against.
        let tail: Vec<super::text::TextRun> = self.texts.drain(mark.texts..).collect();
        self.texts
            .extend(tail.into_iter().filter(|r| shape.contains([r.x, r.y])));
    }

    /// Declare the extents instead of deriving them from the geometry.
    ///
    /// A paper-space tab is framed by its sheet, not by its contents: drawings
    /// routinely park something off the page, and one image 13,000 units away
    /// would otherwise shrink the sheet to a speck when the view is fitted.
    pub fn set_extents(&mut self, min: [f64; 2], max: [f64; 2]) {
        if !(max[0] > min[0] && max[1] > min[1]) {
            return;
        }
        self.min_x = min[0];
        self.min_y = min[1];
        self.max_x = max[0];
        self.max_y = max[1];
    }

    /// Rebuild the extents from what is actually in the buffers.
    pub fn recompute_extents(&mut self) {
        self.min_x = f64::INFINITY;
        self.min_y = f64::INFINITY;
        self.max_x = f64::NEG_INFINITY;
        self.max_y = f64::NEG_INFINITY;
        let points: Vec<[f64; 2]> = self
            .strokes
            .iter()
            .flat_map(|s| [[s.x0, s.y0], [s.x1, s.y1]])
            .chain(self.fills.iter().map(|v| [v.x, v.y]))
            .chain(self.texts.iter().map(|r| [r.x, r.y]))
            .collect();
        for p in points {
            self.grow(p[0], p[1]);
        }
    }

    /// Highest draw-order value used, for normalising depth.
    pub fn max_order(&self) -> u32 {
        self.order
    }

    /// Text records plus the UTF-8 string blob they index into.
    pub fn text_buffers(&self) -> (Vec<u8>, Vec<u8>) {
        super::text::encode(&self.texts, self.origin())
    }

    /// Centre of the drawing extents, used as the f32 origin.
    pub fn origin(&self) -> [f64; 2] {
        if self.is_empty() || !self.min_x.is_finite() {
            return [0.0, 0.0];
        }
        [
            (self.min_x + self.max_x) / 2.0,
            (self.min_y + self.max_y) / 2.0,
        ]
    }

    /// Extents relative to `origin()`: [min_x, min_y, max_x, max_y].
    pub fn extents_local(&self) -> [f32; 4] {
        if self.is_empty() || !self.min_x.is_finite() {
            return [0.0, 0.0, 0.0, 0.0];
        }
        let o = self.origin();
        [
            (self.min_x - o[0]) as f32,
            (self.min_y - o[1]) as f32,
            (self.max_x - o[0]) as f32,
            (self.max_y - o[1]) as f32,
        ]
    }

    /// The drawing's extent in world coordinates, for bucketing.
    fn world_extent(&self) -> [f64; 4] {
        [self.min_x, self.min_y, self.max_x, self.max_y]
    }

    /// Interleaved stroke instance buffer, `STROKE_BYTES` per segment.
    ///
    /// Opaque segments come first, then translucent ones, and each half is
    /// sorted into spatial buckets so the renderer can skip what a view does
    /// not touch. The halves stay whole: the opaque pass writes depth and the
    /// translucent pass only tests it, so interleaving them by bucket would let
    /// one bucket's opaque geometry paint over another's translucent.
    pub fn stroke_buffer(&self) -> Vec<u8> {
        let o = self.origin();
        let mut out = Vec::with_capacity(self.strokes.len() * STROKE_BYTES);
        for half in self.stroke_halves() {
            let (order, _) = self.bucket_strokes(&half);
            for i in order {
                let s = half[i as usize];
                out.extend_from_slice(&((s.x0 - o[0]) as f32).to_le_bytes());
                out.extend_from_slice(&((s.y0 - o[1]) as f32).to_le_bytes());
                out.extend_from_slice(&((s.x1 - o[0]) as f32).to_le_bytes());
                out.extend_from_slice(&((s.y1 - o[1]) as f32).to_le_bytes());
                out.extend_from_slice(&s.rgba.to_le_bytes());
                out.extend_from_slice(&s.attr.to_le_bytes());
                out.extend_from_slice(&s.order.to_le_bytes());
            }
        }
        out
    }

    /// Interleaved fill vertex buffer, `FILL_BYTES` per vertex.
    pub fn fill_buffer(&self) -> Vec<u8> {
        let o = self.origin();
        let mut out = Vec::with_capacity(self.fills.len() * FILL_BYTES);
        for half in self.fill_halves() {
            let (order, _) = self.bucket_fills(&half);
            for i in order {
                for v in half[i as usize] {
                    out.extend_from_slice(&((v.x - o[0]) as f32).to_le_bytes());
                    out.extend_from_slice(&((v.y - o[1]) as f32).to_le_bytes());
                    out.extend_from_slice(&v.rgba.to_le_bytes());
                    out.extend_from_slice(&v.attr.to_le_bytes());
                    out.extend_from_slice(&v.order.to_le_bytes());
                }
            }
        }
        out
    }

    /// Strokes split into the opaque half and the translucent half, in that
    /// order. Both buffer emission and the tile table walk this, so they cannot
    /// disagree about what went where.
    fn stroke_halves(&self) -> [Vec<Stroke>; 2] {
        let (a, b): (Vec<Stroke>, Vec<Stroke>) =
            self.strokes.iter().partition(|s| is_opaque(s.rgba));
        [a, b]
    }

    /// The same for fills, kept as whole triangles. A gradient gives its
    /// corners different colours but the same alpha, so one corner decides.
    fn fill_halves(&self) -> [Vec<[FillVertex; 3]>; 2] {
        let tris: Vec<[FillVertex; 3]> = self.fills.as_chunks::<3>().0.to_vec();
        let (a, b): (Vec<_>, Vec<_>) = tris.into_iter().partition(|t| is_opaque(t[0].rgba));
        [a, b]
    }

    fn bucket_strokes(&self, half: &[Stroke]) -> (Vec<u32>, Vec<super::tiles::Tile>) {
        super::tiles::bucket(
            half,
            self.world_extent(),
            |s| [(s.x0 + s.x1) / 2.0, (s.y0 + s.y1) / 2.0],
            |s| {
                [
                    s.x0.min(s.x1),
                    s.y0.min(s.y1),
                    s.x0.max(s.x1),
                    s.y0.max(s.y1),
                ]
            },
        )
    }

    fn bucket_fills(&self, half: &[[FillVertex; 3]]) -> (Vec<u32>, Vec<super::tiles::Tile>) {
        super::tiles::bucket(
            half,
            self.world_extent(),
            |t| {
                [
                    (t[0].x + t[1].x + t[2].x) / 3.0,
                    (t[0].y + t[1].y + t[2].y) / 3.0,
                ]
            },
            |t| {
                [
                    t[0].x.min(t[1].x).min(t[2].x),
                    t[0].y.min(t[1].y).min(t[2].y),
                    t[0].x.max(t[1].x).max(t[2].x),
                    t[0].y.max(t[1].y).max(t[2].y),
                ]
            },
        )
    }

    /// Tile table for `stroke_buffer`, counted in strokes. The translucent
    /// half's tiles are offset past the opaque half, so a start index addresses
    /// the whole buffer.
    pub fn stroke_tiles(&self) -> Vec<u8> {
        let halves = self.stroke_halves();
        let mut tiles = Vec::new();
        let mut base = 0u32;
        for half in &halves {
            let (_, mut t) = self.bucket_strokes(half);
            for tile in &mut t {
                tile.start += base;
            }
            base += half.len() as u32;
            tiles.extend(t);
        }
        super::tiles::encode(&tiles, self.origin())
    }

    /// Tile table for `fill_buffer`, counted in vertices, so it can be handed
    /// straight to `drawArrays`.
    pub fn fill_tiles(&self) -> Vec<u8> {
        let halves = self.fill_halves();
        let mut tiles = Vec::new();
        let mut base = 0u32;
        for half in &halves {
            let (_, mut t) = self.bucket_fills(half);
            for tile in &mut t {
                tile.start = base + tile.start * 3;
                tile.count *= 3;
            }
            base += half.len() as u32 * 3;
            tiles.extend(t);
        }
        super::tiles::encode(&tiles, self.origin())
    }

    /// Where the translucent tiles begin, as an index into the tile table.
    pub fn opaque_stroke_tiles(&self) -> usize {
        self.bucket_strokes(&self.stroke_halves()[0]).1.len()
    }

    pub fn opaque_fill_tiles(&self) -> usize {
        self.bucket_fills(&self.fill_halves()[0]).1.len()
    }

    /// How many leading strokes of `stroke_buffer` are opaque.
    pub fn opaque_strokes(&self) -> usize {
        self.strokes.iter().filter(|s| is_opaque(s.rgba)).count()
    }

    /// How many leading vertices of `fill_buffer` are opaque.
    pub fn opaque_fills(&self) -> usize {
        self.fills
            .as_chunks::<3>()
            .0
            .iter()
            .filter(|t| is_opaque(t[0].rgba))
            .count()
            * 3
    }
}

/// Fully opaque geometry can write depth; translucent geometry cannot.
///
/// The draw order is resolved through the depth buffer, so a translucent
/// entity that writes depth rejects everything drawn behind it afterwards
/// instead of letting it blend through. Splitting the buffers lets the
/// renderer draw the translucent tail with depth writes off.
#[inline]
fn is_opaque(rgba: u32) -> bool {
    rgba >> 24 == 255
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_transform_is_a_no_op() {
        let p = Affine::IDENTITY.apply(3.0, -7.0);
        assert_eq!(p, [3.0, -7.0]);
    }

    #[test]
    fn rotation_then_translation_composes_in_the_right_order() {
        // Rotate 90deg CCW about the origin, then move to (10, 0).
        let t = Affine::new(10.0, 0.0, 1.0, 1.0, std::f64::consts::FRAC_PI_2);
        let p = t.apply(1.0, 0.0);
        assert!((p[0] - 10.0).abs() < 1e-9, "{p:?}");
        assert!((p[1] - 1.0).abs() < 1e-9, "{p:?}");
    }

    #[test]
    fn nested_transforms_multiply() {
        let outer = Affine::new(10.0, 0.0, 2.0, 2.0, 0.0);
        let inner = Affine::new(1.0, 1.0, 1.0, 1.0, 0.0);
        let combined = outer.mul(&inner);
        // Inner moves (0,0) to (1,1); outer scales by 2 and shifts x by 10.
        let p = combined.apply(0.0, 0.0);
        assert!((p[0] - 12.0).abs() < 1e-9, "{p:?}");
        assert!((p[1] - 2.0).abs() < 1e-9, "{p:?}");
    }

    #[test]
    fn scale_magnitude_tracks_nesting() {
        let a = Affine::new(0.0, 0.0, 3.0, 3.0, 0.0);
        let b = Affine::new(0.0, 0.0, 2.0, 2.0, 0.0);
        assert!((a.mul(&b).scale_magnitude() - 6.0).abs() < 1e-9);
    }

    #[test]
    fn attr_packing_round_trips() {
        let a = pack_attr(1234, 211, 0x5A);
        assert_eq!(a & 0xFFFF, 1234);
        assert_eq!((a >> 16) & 0xFF, 211);
        assert_eq!((a >> 24) & 0xFF, 0x5A);
    }

    #[test]
    fn declared_extents_frame_the_sheet_not_the_strays() {
        let mut s = Scene::new();
        s.push_stroke(0.0, 0.0, 420.0, 297.0, 0, 0);
        // A logo parked well off the page, as real layouts have.
        s.push_stroke(-13291.0, -2963.0, -13285.0, -2962.0, 0, 0);
        assert!(s.extents_local()[0] < -6000.0, "{:?}", s.extents_local());

        s.set_extents([0.0, 0.0], [420.0, 297.0]);
        assert_eq!(s.origin(), [210.0, 148.5]);
        assert_eq!(s.extents_local(), [-210.0, -148.5, 210.0, 148.5]);

        // An empty or inverted sheet is ignored rather than believed.
        s.set_extents([10.0, 10.0], [10.0, 10.0]);
        assert_eq!(s.extents_local(), [-210.0, -148.5, 210.0, 148.5]);
    }

    #[test]
    fn buffers_put_translucent_geometry_last() {
        let mut s = Scene::new();
        let clear = pack_rgba(255, 0, 0, 128);
        let solid = pack_rgba(0, 0, 255, 255);
        s.push_stroke(0.0, 0.0, 1.0, 0.0, clear, 0);
        s.push_stroke(0.0, 1.0, 1.0, 1.0, solid, 0);
        s.push_triangle([0.0, 0.0], [1.0, 0.0], [0.0, 1.0], clear, 0);
        s.push_triangle([2.0, 0.0], [3.0, 0.0], [2.0, 1.0], solid, 0);

        assert_eq!(s.opaque_strokes(), 1);
        assert_eq!(s.opaque_fills(), 3);

        // The opaque one comes first in the buffer whatever order it arrived in.
        let buf = s.stroke_buffer();
        let first_rgba = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        assert_eq!(first_rgba, solid);
        let fills = s.fill_buffer();
        let first_fill_rgba = u32::from_le_bytes(fills[8..12].try_into().unwrap());
        assert_eq!(first_fill_rgba, solid);
    }

    #[test]
    fn the_contrast_flag_and_the_fade_code_share_one_byte() {
        // Both live in the flags byte, so a hatch on colour 7 has to carry its
        // spacing and its flip without either eating the other.
        for spacing in [1.5f64, 16.0, 500.0, 50_000.0] {
            let fade = encode_fade_spacing(spacing);
            assert!(
                fade > 0 && fade < FLAG_CONTRAST,
                "spacing {spacing} gave {fade}"
            );

            let a = pack_attr(7, 25, fade | FLAG_CONTRAST);
            assert_eq!((a >> 24) as u8 & 0x7F, fade);
            assert!((a >> 24) as u8 & FLAG_CONTRAST != 0);
            assert_eq!(a & 0xFFFF, 7);
            assert_eq!((a >> 16) & 0xFF, 25);
        }
        assert_eq!(encode_fade_spacing(0.5), 0);
    }

    #[test]
    fn the_fade_code_still_resolves_a_useful_spacing_range() {
        // Seven bits, eight steps to the octave: a millimetre up to tens of
        // metres, which is every hatch spacing a drawing uses.
        let decode = |code: u8| (code as f64 / 8.0).exp2();
        for spacing in [2.0f64, 40.0, 5000.0] {
            let back = decode(encode_fade_spacing(spacing));
            assert!(
                (back / spacing - 1.0).abs() < 0.05,
                "{spacing} came back as {back}"
            );
        }
    }

    #[test]
    fn rgba_packs_little_endian() {
        let c = pack_rgba(0x11, 0x22, 0x33, 0xFF);
        assert_eq!(c.to_le_bytes(), [0x11, 0x22, 0x33, 0xFF]);
    }

    #[test]
    fn origin_recentres_large_coordinates() {
        let mut s = Scene::new();
        // Survey-style coordinates well past f32's 7 digits of precision.
        s.push_stroke(6_500_000.0, 1_200_000.0, 6_500_001.0, 1_200_000.0, 0, 0);
        let o = s.origin();
        assert!((o[0] - 6_500_000.5).abs() < 1e-6);

        let buf = s.stroke_buffer();
        let x0 = f32::from_le_bytes(buf[0..4].try_into().unwrap());
        let x1 = f32::from_le_bytes(buf[8..12].try_into().unwrap());
        // Relative coordinates keep the 1-unit separation intact.
        assert!((x1 - x0 - 1.0).abs() < 1e-4, "x0 {x0} x1 {x1}");
    }

    #[test]
    fn raw_f32_would_have_lost_that_separation() {
        // Guards the premise of the test above: the origin shift is doing work.
        let a = 6_500_000.0f64 as f32;
        let b = 6_500_000.06f64 as f32;
        assert_eq!(
            a, b,
            "f32 should collapse these, making the origin shift necessary"
        );
    }

    #[test]
    fn buffers_have_the_documented_stride() {
        let mut s = Scene::new();
        s.push_stroke(0.0, 0.0, 1.0, 1.0, 0, 0);
        s.push_triangle([0.0, 0.0], [1.0, 0.0], [0.0, 1.0], 0, 0);
        assert_eq!(s.stroke_buffer().len(), STROKE_BYTES);
        assert_eq!(s.fill_buffer().len(), 3 * FILL_BYTES);
    }

    #[test]
    fn non_finite_geometry_is_dropped() {
        let mut s = Scene::new();
        s.push_stroke(f64::NAN, 0.0, 1.0, 1.0, 0, 0);
        s.push_stroke(0.0, f64::INFINITY, 1.0, 1.0, 0, 0);
        assert!(s.strokes.is_empty());
        // And extents stay clean.
        assert_eq!(s.extents_local(), [0.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn closed_polyline_emits_the_closing_segment() {
        let mut s = Scene::new();
        let pts = [[0.0, 0.0], [1.0, 0.0], [1.0, 1.0]];
        s.push_polyline(&pts, true, 0, 0);
        assert_eq!(s.strokes.len(), 3);
        let last = s.strokes.last().unwrap();
        assert_eq!((last.x0, last.y0, last.x1, last.y1), (1.0, 1.0, 0.0, 0.0));
    }
}

#[cfg(test)]
mod extrusion_tests {
    use super::*;

    #[test]
    fn the_default_extrusion_is_the_identity() {
        let m = Affine::from_extrusion(0.0, 0.0, 1.0, 0.0);
        assert_eq!(m.apply(7.0, -3.0), [7.0, -3.0]);
    }

    #[test]
    fn a_negative_z_extrusion_mirrors_x_and_keeps_y() {
        // The case that placed a block 33000 units from where it belonged.
        let m = Affine::from_extrusion(0.0, 0.0, -1.0, 0.0);
        let p = m.apply(16613.0, -2724.0);
        assert!(
            (p[0] + 16613.0).abs() < 1e-6,
            "x should mirror, got {}",
            p[0]
        );
        assert!(
            (p[1] + 2724.0).abs() < 1e-6,
            "y should be unchanged, got {}",
            p[1]
        );
    }

    #[test]
    fn mirroring_is_its_own_inverse() {
        let m = Affine::from_extrusion(0.0, 0.0, -1.0, 0.0);
        let p = m.apply(5.0, 9.0);
        let q = m.apply(p[0], p[1]);
        assert!((q[0] - 5.0).abs() < 1e-9 && (q[1] - 9.0).abs() < 1e-9);
    }

    #[test]
    fn an_unnormalised_extrusion_is_normalised_first() {
        let m = Affine::from_extrusion(0.0, 0.0, -42.0, 0.0);
        let p = m.apply(3.0, 4.0);
        assert!((p[0] + 3.0).abs() < 1e-9, "{p:?}");
        assert!((p[1] - 4.0).abs() < 1e-9, "{p:?}");
    }

    #[test]
    fn a_degenerate_extrusion_falls_back_to_the_identity() {
        let m = Affine::from_extrusion(0.0, 0.0, 0.0, 0.0);
        assert_eq!(m.apply(2.0, 3.0), [2.0, 3.0]);
        let m = Affine::from_extrusion(f64::NAN, 0.0, 1.0, 0.0);
        assert_eq!(m.apply(2.0, 3.0), [2.0, 3.0]);
    }

    #[test]
    fn the_axes_stay_orthonormal_for_a_tilted_extrusion() {
        let m = Affine::from_extrusion(0.3, -0.5, 0.81, 0.0);
        // Columns are the projections of two orthonormal 3D axes, so each has
        // length at most one and they cannot both collapse.
        let la = (m.a * m.a + m.b * m.b).sqrt();
        let lb = (m.c * m.c + m.d * m.d).sqrt();
        assert!(la <= 1.0 + 1e-9 && lb <= 1.0 + 1e-9, "{la} {lb}");
        assert!(la > 0.1 && lb > 0.1, "axes collapsed: {la} {lb}");
    }

    #[test]
    fn elevation_shifts_along_the_normal() {
        // Straight up: elevation moves along world Z, so XY is untouched.
        let m = Affine::from_extrusion(0.0, 0.0, 1.0, 12.0);
        assert_eq!(m.apply(1.0, 1.0), [1.0, 1.0]);

        // Tilted: elevation now has an in-plane component.
        let m = Affine::from_extrusion(1.0, 0.0, 0.0, 5.0);
        let p = m.apply(0.0, 0.0);
        assert!((p[0] - 5.0).abs() < 1e-9, "{p:?}");
    }

    #[test]
    fn clipping_keeps_the_part_of_a_viewport_inside_the_window() {
        let mut s = Scene::new();
        s.push_stroke(-100.0, -100.0, -90.0, -90.0, 0, 0); // before the mark
        let mark = s.mark();
        s.push_stroke(-50.0, 5.0, 50.0, 5.0, 0, 0); // crosses the window
        s.push_stroke(1.0, 1.0, 2.0, 2.0, 0, 0); // inside
        s.push_stroke(80.0, 80.0, 90.0, 90.0, 0, 0); // outside
        s.push_triangle([-20.0, -20.0], [20.0, -20.0], [0.0, 20.0], 0, 0);

        s.clip_since(
            mark,
            &super::super::clip::ClipShape::rect([0.0, 0.0], 20.0, 20.0),
        );

        // The stroke from before the mark is untouched, the crossing one is cut
        // to the window's width, the inside one survives, the outside one goes.
        assert_eq!(s.strokes.len(), 3, "kept {}", s.strokes.len());
        assert_eq!([s.strokes[0].x0, s.strokes[0].y0], [-100.0, -100.0]);
        assert!((s.strokes[1].x0 + 10.0).abs() < 1e-9, "{}", s.strokes[1].x0);
        assert!((s.strokes[1].x1 - 10.0).abs() < 1e-9, "{}", s.strokes[1].x1);
        assert!(
            !s.fills.is_empty(),
            "the triangle was clipped away entirely"
        );
        assert!(s.fills.len().is_multiple_of(3));
    }

    #[test]
    fn a_mirrored_extrusion_composes_with_a_block_transform() {
        // Reproduces the real failure: block content at x=16613, extrusion
        // flipped, inserted at x=9120. Correct result is 9120 - 16613.
        let ocs = Affine::from_extrusion(0.0, 0.0, -1.0, 0.0);
        let insert = Affine::new(9120.0, 123.0, 1.0, 1.0, 0.0);
        let combined = insert.mul(&ocs);
        let p = combined.apply(16613.0, -2724.0);
        assert!((p[0] - (9120.0 - 16613.0)).abs() < 1e-6, "{p:?}");
        assert!((p[1] - (123.0 - 2724.0)).abs() < 1e-6, "{p:?}");
    }
}
