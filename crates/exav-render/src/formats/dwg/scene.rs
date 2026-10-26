//! Scene accumulation and the wire format handed to WebGL.
//!
//! Geometry is accumulated in f64 so a drawing in survey coordinates keeps its
//! precision, then re-emitted as f32 relative to a per-drawing origin. See
//! DESIGN.md section 4.4.

use super::tiles::Tile;

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

    /// A text plane in world coordinates, as an MTEXT has it: its X axis (a
    /// vector, not necessarily unit) and its normal. The Y axis is the normal
    /// crossed with X, so a normal of -Z mirrors the text. The map takes the
    /// text's own (along, up) to the plan view, with `origin` as its corner.
    /// `None` when the axes are not a plane.
    pub fn from_plane(x_axis: [f64; 3], normal: [f64; 3], origin: [f64; 2]) -> Option<Affine> {
        let unit = |v: [f64; 3]| {
            let l = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt();
            (l.is_finite() && l > 1e-12).then(|| v.map(|c| c / l))
        };
        let x = unit(x_axis)?;
        let n = unit(normal)?;
        let y = unit([
            n[1] * x[2] - n[2] * x[1],
            n[2] * x[0] - n[0] * x[2],
            n[0] * x[1] - n[1] * x[0],
        ])?;
        Some(Affine {
            a: x[0],
            b: x[1],
            c: y[0],
            d: y[1],
            e: origin[0],
            f: origin[1],
        })
    }

    /// Mean absolute scale, used to keep lineweight sane through scaled blocks.
    pub fn scale_magnitude(&self) -> f64 {
        let sx = (self.a * self.a + self.b * self.b).sqrt();
        let sy = (self.c * self.c + self.d * self.d).sqrt();
        ((sx + sy) / 2.0).max(1e-12)
    }
}

/// One line segment, or circular arc, pre-transform-applied, still in drawing
/// coordinates.
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
    /// 0 for a line; for an arc from the first point to the second, the tan
    /// of a quarter of its sweep, positive counter-clockwise (DXF's bulge),
    /// at most [`MAX_ARC_BULGE`]: the renderer draws it exactly at any zoom.
    pub bulge: f32,
}

/// The largest bulge a stroke carries, a quarter turn's: an arc stroke then
/// lies within the box of its ends widened by a fifth of its chord, and
/// within its sector the shader's test is two cross products.
pub const MAX_ARC_BULGE: f64 = 0.414_213_562_373_095_1;

impl Stroke {
    /// How far an arc stroke's curve stands off its chord, at most.
    pub fn sagitta(&self) -> f64 {
        (self.bulge.abs() as f64) * (self.x1 - self.x0).hypot(self.y1 - self.y0) / 2.0
    }

    /// The stroke as straight segments: itself, or its arc in `n` pieces.
    pub fn flatten(&self, n: usize) -> Vec<[[f64; 2]; 2]> {
        let (a, b) = ([self.x0, self.y0], [self.x1, self.y1]);
        if self.bulge == 0.0 {
            return vec![[a, b]];
        }
        let pts = super::curves::bulge_points(a, b, self.bulge as f64, n);
        pts.windows(2).map(|w| [w[0], w[1]]).collect()
    }
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

pub const STROKE_BYTES: usize = 32;
pub const FILL_BYTES: usize = 20;

/// Fill flag: paint the viewer's background colour instead of the vertex's.
///
/// A WIPEOUT masks whatever lies beneath it, and what it masks to is the
/// background, which the tessellator does not know. The renderer substitutes it.
pub const FILL_FLAG_BACKGROUND: u8 = 1;

/// The lineweight code of a fill's edge, a stroke of no width whose fringe is
/// the fill's anti-aliasing (`shaders.ts`). Lineweights stop at 211.
pub const FILL_EDGE: u8 = 255;

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
    if !spacing.is_finite() || spacing <= 0.0 {
        return 0;
    }
    // Logarithmic, five steps to the octave from 2^-9: in the seven bits left
    // beside the contrast flag, 0.002 to 86,000 units, a pattern a few
    // millimetres apart in a drawing in metres to one metres apart in a
    // drawing in millimetres. `spacingFade` in shaders.ts decodes it.
    let code = ((spacing.log2() + FADE_OCTAVES_BELOW_ONE) * FADE_STEPS_PER_OCTAVE).round();
    code.clamp(1.0, 127.0) as u8
}

/// Octaves below a unit `encode_fade_spacing` reaches, and its steps per
/// octave.
const FADE_OCTAVES_BELOW_ONE: f64 = 9.0;
const FADE_STEPS_PER_OCTAVE: f64 = 5.0;

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
    /// Clip regions as triangles, a text run's `clip` indexing them from 1.
    pub clips: Vec<Vec<[[f64; 2]; 3]>>,
    /// Draw order counter. AutoCAD paints entities in this sequence, and later
    /// entities cover earlier ones: a small solid fill placed over a hatch is
    /// how a roof vent masks the tiles beneath it. Without it a viewer that
    /// batches all fills before all strokes draws the hatch back on top.
    pub order: u32,
    /// Fill vertices `edge_fills` has outlined.
    edged: usize,
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
            clips: Vec::new(),
            order: 0,
            edged: 0,
            min_x: f64::INFINITY,
            min_y: f64::INFINITY,
            max_x: f64::NEG_INFINITY,
            max_y: f64::NEG_INFINITY,
        }
    }

    /// Record a text run. Only the anchor grows the extents: the rendered width
    /// depends on font metrics the renderer has and this side does not.
    pub fn push_text(&mut self, run: super::text::TextRun) {
        if ![run.x, run.y, run.u[0], run.u[1], run.v[0], run.v[1]]
            .iter()
            .all(|c| c.is_finite())
        {
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
            bulge: 0.0,
        });
    }

    /// Push a circular arc as arc strokes of at most a quarter turn each:
    /// centre, radius, start angle and signed sweep (positive
    /// counter-clockwise), in drawing coordinates.
    #[allow(clippy::too_many_arguments)]
    pub fn push_arc(
        &mut self,
        cx: f64,
        cy: f64,
        r: f64,
        start: f64,
        sweep: f64,
        rgba: u32,
        attr: u32,
    ) {
        if ![cx, cy, r, start, sweep].iter().all(|v| v.is_finite()) || r <= 0.0 || sweep == 0.0 {
            return;
        }
        let n = (sweep.abs() / std::f64::consts::FRAC_PI_2).ceil().max(1.0) as usize;
        let step = sweep / n as f64;
        let bulge = (step / 4.0).tan() as f32;
        debug_assert!(f64::from(bulge.abs()) <= MAX_ARC_BULGE + 1e-6);
        let at = |a: f64| [cx + r * a.cos(), cy + r * a.sin()];
        // The extents: the arc's ends and the quadrant points it passes.
        let (lo, hi) = if sweep > 0.0 {
            (start, start + sweep)
        } else {
            (start + sweep, start)
        };
        let first = (lo / std::f64::consts::FRAC_PI_2).ceil() as i64;
        let last = (hi / std::f64::consts::FRAC_PI_2).floor() as i64;
        for k in first..=last.min(first + 4) {
            let p = at(k as f64 * std::f64::consts::FRAC_PI_2);
            self.grow(p[0], p[1]);
        }
        let order = self.order;
        for i in 0..n {
            let (a, b) = (
                at(start + step * i as f64),
                at(start + step * (i + 1) as f64),
            );
            self.grow(a[0], a[1]);
            self.grow(b[0], b[1]);
            self.strokes.push(Stroke {
                x0: a[0],
                y0: a[1],
                x1: b[0],
                y1: b[1],
                rgba,
                attr,
                order,
                bulge,
            });
        }
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
    /// Outline the opaque fills of one colour pushed since the last call with
    /// `FILL_EDGE` strokes, whose fringe anti-aliases the fill's edge: drawn
    /// at the fill's depth, each is hidden where the fill is and shows only
    /// outside it. An edge two triangles share is left out; a translucent,
    /// shaded or background fill is not outlined.
    pub fn edge_fills(&mut self) {
        let from = self.edged.min(self.fills.len());
        self.edged = self.fills.len();
        let tris = self.fills[from..].as_chunks::<3>().0;
        if tris.is_empty() {
            return;
        }
        let key = |a: &FillVertex, b: &FillVertex| {
            let (pa, pb) = (
                [a.x.to_bits(), a.y.to_bits()],
                [b.x.to_bits(), b.y.to_bits()],
            );
            let (lo, hi) = if pa <= pb { (pa, pb) } else { (pb, pa) };
            (a.rgba, a.attr, a.order, lo, hi)
        };
        let mut edges = Vec::new();
        let mut uses: std::collections::HashMap<_, u32> = std::collections::HashMap::new();
        for t in tris {
            let one_colour = t[1].rgba == t[0].rgba && t[2].rgba == t[0].rgba;
            let opaque = t[0].rgba >> 24 == 255;
            let background = (t[0].attr >> 24) as u8 & FILL_FLAG_BACKGROUND != 0;
            if !one_colour || !opaque || background {
                continue;
            }
            for (a, b) in [(&t[0], &t[1]), (&t[1], &t[2]), (&t[2], &t[0])] {
                *uses.entry(key(a, b)).or_insert(0) += 1;
                edges.push((*a, *b));
            }
        }
        for (a, b) in edges {
            if uses[&key(&a, &b)] != 1 {
                continue;
            }
            let attr = (a.attr & 0xFFFF)
                | u32::from(FILL_EDGE) << 16
                | (a.attr & (u32::from(FLAG_CONTRAST) << 24));
            self.strokes.push(Stroke {
                x0: a.x,
                y0: a.y,
                x1: b.x,
                y1: b.y,
                rgba: a.rgba,
                attr,
                order: a.order,
                bulge: 0.0,
            });
        }
    }

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
            // An arc wholly inside stays one; one crossing the edge is cut as
            // the straight pieces of its curve.
            if s.bulge != 0.0 {
                let [x0, y0, x1, y1] = stroke_box(&s);
                if [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]
                    .iter()
                    .all(|&c| shape.contains(c))
                {
                    kept.push(s);
                    continue;
                }
            }
            for [a, b] in s.flatten(16) {
                shape.clip_segment(a, b, &mut spans);
                for (t0, t1) in spans.iter().copied() {
                    kept.push(Stroke {
                        x0: a[0] + (b[0] - a[0]) * t0,
                        y0: a[1] + (b[1] - a[1]) * t0,
                        x1: a[0] + (b[0] - a[0]) * t1,
                        y1: a[1] + (b[1] - a[1]) * t1,
                        bulge: 0.0,
                        ..s
                    });
                }
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
        // Outlined before they were cut, and the outlines cut with the
        // strokes.
        self.edged = self.fills.len();

        // A run's glyphs are laid out on the other side of the worker
        // boundary, so it cannot be cut here: one that may cross the shape's
        // edge is drawn through a clip region, which the renderer masks it
        // with. One wholly outside is dropped, one wholly inside is left be.
        let tail: Vec<super::text::TextRun> = self.texts.drain(mark.texts..).collect();
        let (min, max) = shape.bounds();
        let mut regions: std::collections::HashMap<u16, Option<u16>> = Default::default();
        for mut r in tail {
            let reach = text_reach(&r);
            if r.x + reach < min[0]
                || r.x - reach > max[0]
                || r.y + reach < min[1]
                || r.y - reach > max[1]
            {
                continue;
            }
            let corners = [
                [r.x - reach, r.y - reach],
                [r.x + reach, r.y - reach],
                [r.x + reach, r.y + reach],
                [r.x - reach, r.y + reach],
            ];
            if !corners.iter().all(|c| shape.contains(*c)) {
                let region = *regions
                    .entry(r.clip)
                    .or_insert_with(|| self.clip_region(r.clip, shape));
                match region {
                    Some(id) => r.clip = id,
                    // Nothing of the earlier region is inside this one.
                    None => continue,
                }
            }
            self.texts.push(r);
        }
    }

    /// A new clip region: the shape, or the part of region `within` it, as
    /// its id; None when that is empty, or when ids have run out (the run is
    /// then kept or dropped by its anchor, as before regions).
    fn clip_region(&mut self, within: u16, shape: &super::clip::ClipShape) -> Option<u16> {
        let triangles = if within == 0 {
            shape.triangles()
        } else {
            let mut out = Vec::new();
            let mut piece = Vec::new();
            for t in self
                .clips
                .get(within as usize - 1)
                .cloned()
                .unwrap_or_default()
            {
                shape.clip_triangle(t, &mut piece);
                out.extend_from_slice(&piece);
            }
            out
        };
        if triangles.is_empty() || self.clips.len() >= u16::MAX as usize {
            return None;
        }
        self.clips.push(triangles);
        Some(self.clips.len() as u16)
    }

    /// The clip regions as the renderer takes them: for each, a `u32`
    /// triangle count, then `f32 x, y` for each corner, relative to
    /// `origin()`.
    pub fn clip_buffer(&self) -> Vec<u8> {
        let o = self.origin();
        let mut out = Vec::new();
        for region in &self.clips {
            out.extend_from_slice(&(region.len() as u32).to_le_bytes());
            for p in region.iter().flatten() {
                out.extend_from_slice(&((p[0] - o[0]) as f32).to_le_bytes());
                out.extend_from_slice(&((p[1] - o[1]) as f32).to_le_bytes());
            }
        }
        out
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

    /// Narrow the extents to where the drawing is when a few strays lie far
    /// off it (a point left at the origin of a drawing in national grid
    /// coordinates): the f32 origin, the fitted view and the culling grid
    /// then serve the drawing, not the empty space between it and them,
    /// which cost it centimetres of precision and showed it as a speck.
    /// The core is what lies between the 0.5th and 99.5th percentiles on
    /// each axis, with a margin; the strays are still drawn.
    pub fn focus_on_core(&mut self) {
        let points = self.strokes.len() * 2 + self.fills.len() + self.texts.len();
        if points < 200 || !self.min_x.is_finite() {
            return;
        }
        let stride = (points / 50_000).max(1);
        let all = self
            .strokes
            .iter()
            .flat_map(|s| [[s.x0, s.y0], [s.x1, s.y1]])
            .chain(self.fills.iter().map(|v| [v.x, v.y]))
            .chain(self.texts.iter().map(|r| [r.x, r.y]));
        let (mut xs, mut ys): (Vec<f64>, Vec<f64>) =
            all.step_by(stride).map(|p| (p[0], p[1])).unzip();
        let span = |v: &mut Vec<f64>| -> (f64, f64) {
            let n = v.len();
            let (lo, hi) = (n / 200, (n - 1) - n / 200);
            let a = *v.select_nth_unstable_by(lo, f64::total_cmp).1;
            let b = *v.select_nth_unstable_by(hi, f64::total_cmp).1;
            (a, b)
        };
        let ((x0, x1), (y0, y1)) = (span(&mut xs), span(&mut ys));
        let margin = (x1 - x0).max(y1 - y0) * 0.25;
        let core = [x0 - margin, y0 - margin, x1 + margin, y1 + margin];
        let (full_w, full_h) = (self.max_x - self.min_x, self.max_y - self.min_y);
        let (core_w, core_h) = (core[2] - core[0], core[3] - core[1]);
        if !(core_w > 0.0 && core_h > 0.0) || (full_w <= 4.0 * core_w && full_h <= 4.0 * core_h) {
            return;
        }
        self.min_x = self.min_x.max(core[0]);
        self.min_y = self.min_y.max(core[1]);
        self.max_x = self.max_x.min(core[2]);
        self.max_y = self.max_y.min(core[3]);
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

    /// The geometry as the renderer takes it (see [`Buffers`]).
    ///
    /// Opaque geometry comes first, sorted into spatial buckets so the
    /// renderer can skip what a view does not touch, then translucent
    /// geometry in draw order: blending is drawn in order, and the opaque
    /// pass must be done before any of it, so the halves stay whole.
    ///
    /// It takes the strokes and fills out of the scene as it encodes them,
    /// so each list is freed once its bytes are made: read the origin, the
    /// extents, the text and the clip regions first.
    pub fn buffers(&mut self) -> Buffers {
        let o = self.origin();
        // Indices rather than copies: a stroke is 48 bytes, its index 4.
        let [opaque_strokes, strokes] = self.stroke_halves();
        let [opaque_fills, fills] = self.fill_halves();
        let (stroke_order, mut stroke_tiles) = self.bucket_strokes(&opaque_strokes);
        let (fill_order, mut fill_tiles) = self.bucket_fills(&opaque_fills);
        let translucent = self.translucent(&strokes, &fills);

        let mut stroke_bytes = Vec::with_capacity(self.strokes.len() * STROKE_BYTES);
        let ordered = stroke_order
            .iter()
            .map(|&i| opaque_strokes[i as usize])
            .chain(strokes.iter().copied());
        for s in ordered.map(|i| &self.strokes[i as usize]) {
            stroke_bytes.extend_from_slice(&((s.x0 - o[0]) as f32).to_le_bytes());
            stroke_bytes.extend_from_slice(&((s.y0 - o[1]) as f32).to_le_bytes());
            stroke_bytes.extend_from_slice(&((s.x1 - o[0]) as f32).to_le_bytes());
            stroke_bytes.extend_from_slice(&((s.y1 - o[1]) as f32).to_le_bytes());
            stroke_bytes.extend_from_slice(&s.rgba.to_le_bytes());
            stroke_bytes.extend_from_slice(&s.attr.to_le_bytes());
            stroke_bytes.extend_from_slice(&s.order.to_le_bytes());
            stroke_bytes.extend_from_slice(&s.bulge.to_le_bytes());
        }
        drop((stroke_order, strokes));
        self.strokes = Vec::new();
        let mut fill_bytes = Vec::with_capacity(self.fills.len() * FILL_BYTES);
        let ordered = fill_order
            .iter()
            .map(|&i| opaque_fills[i as usize])
            .chain(fills.iter().copied());
        for t in ordered {
            for v in &self.fills[t as usize * 3..t as usize * 3 + 3] {
                fill_bytes.extend_from_slice(&((v.x - o[0]) as f32).to_le_bytes());
                fill_bytes.extend_from_slice(&((v.y - o[1]) as f32).to_le_bytes());
                fill_bytes.extend_from_slice(&v.rgba.to_le_bytes());
                fill_bytes.extend_from_slice(&v.attr.to_le_bytes());
                fill_bytes.extend_from_slice(&v.order.to_le_bytes());
            }
        }
        drop((fill_order, fills));
        self.fills = Vec::new();

        // Tiles count strokes, and fill vertices (for drawArrays); the
        // translucent ones start past the opaque half.
        for tile in &mut fill_tiles {
            tile.start *= 3;
            tile.count *= 3;
        }
        let (opaque_stroke_tiles, opaque_fill_tiles) = (stroke_tiles.len(), fill_tiles.len());
        for mut tile in translucent.strokes {
            tile.start += opaque_strokes.len() as u32;
            stroke_tiles.push(tile);
        }
        for mut tile in translucent.fills {
            tile.start = (opaque_fills.len() as u32 + tile.start) * 3;
            tile.count *= 3;
            fill_tiles.push(tile);
        }
        let mut runs = Vec::with_capacity(translucent.runs.len() * 12);
        for (fill, from, to) in translucent.runs {
            let base = if fill {
                opaque_fill_tiles
            } else {
                opaque_stroke_tiles
            } as u32;
            runs.extend_from_slice(&u32::from(fill).to_le_bytes());
            runs.extend_from_slice(&(base + from).to_le_bytes());
            runs.extend_from_slice(&(base + to).to_le_bytes());
        }

        Buffers {
            strokes: stroke_bytes,
            fills: fill_bytes,
            opaque_strokes: opaque_strokes.len(),
            opaque_fills: opaque_fills.len() * 3,
            stroke_tiles: super::tiles::encode(&stroke_tiles, o),
            fill_tiles: super::tiles::encode(&fill_tiles, o),
            opaque_stroke_tiles,
            opaque_fill_tiles,
            translucent_runs: runs,
        }
    }

    /// The strokes of the opaque half and of the translucent half, by
    /// index, the translucent one in draw order. Both buffer emission and
    /// the tile table walk this, so they cannot disagree about what went
    /// where.
    fn stroke_halves(&self) -> [Vec<u32>; 2] {
        let all = 0..self.strokes.len() as u32;
        let (a, mut b): (Vec<u32>, Vec<u32>) =
            all.partition(|&i| is_opaque(self.strokes[i as usize].rgba));
        b.sort_by_key(|&i| self.strokes[i as usize].order);
        [a, b]
    }

    /// The same for fills, by triangle. A gradient gives its corners
    /// different colours but the same alpha, so one corner decides.
    fn fill_halves(&self) -> [Vec<u32>; 2] {
        let all = 0..(self.fills.len() / 3) as u32;
        let (a, mut b): (Vec<u32>, Vec<u32>) =
            all.partition(|&t| is_opaque(self.fills[t as usize * 3].rgba));
        b.sort_by_key(|&t| self.fills[t as usize * 3].order);
        [a, b]
    }

    fn triangle(&self, t: u32) -> &[FillVertex; 3] {
        let at = t as usize * 3;
        self.fills[at..at + 3].try_into().expect("three vertices")
    }

    /// The translucent halves' tiles, and the order to draw them in. A tile
    /// is a run of the half in draw order, so it is no spatial bucket, but
    /// neighbours in draw order are often neighbours on the sheet too. Fills
    /// and strokes interleave by draw order, a run of tiles of one kind at a
    /// time; past [`MAX_TRANSLUCENT_RUNS`] runs, the fills then the strokes.
    fn translucent(&self, strokes: &[u32], fills: &[u32]) -> Translucent {
        let stroke = |i: u32| &self.strokes[i as usize];
        let mut t = Translucent::default();
        let (mut i, mut j) = (0, 0);
        while i < strokes.len() || j < fills.len() {
            let fill = match (strokes.get(i), fills.get(j)) {
                (Some(&s), Some(&f)) => self.triangle(f)[0].order <= stroke(s).order,
                (None, _) => true,
                (Some(_), None) => false,
            };
            if fill {
                t.push(true, j, fill_box(self.triangle(fills[j])));
                j += 1;
            } else {
                t.push(false, i, stroke_box(stroke(strokes[i])));
                i += 1;
            }
        }
        if t.runs.len() > MAX_TRANSLUCENT_RUNS {
            t = Translucent::default();
            for (j, &f) in fills.iter().enumerate() {
                t.push(true, j, fill_box(self.triangle(f)));
            }
            for (i, &s) in strokes.iter().enumerate() {
                t.push(false, i, stroke_box(stroke(s)));
            }
        }
        t
    }

    fn bucket_strokes(&self, half: &[u32]) -> (Vec<u32>, Vec<Tile>) {
        let stroke = |i: &u32| &self.strokes[*i as usize];
        super::tiles::bucket(
            half,
            self.world_extent(),
            |i| {
                let s = stroke(i);
                [(s.x0 + s.x1) / 2.0, (s.y0 + s.y1) / 2.0]
            },
            |i| stroke_box(stroke(i)),
        )
    }

    fn bucket_fills(&self, half: &[u32]) -> (Vec<u32>, Vec<Tile>) {
        super::tiles::bucket(
            half,
            self.world_extent(),
            |&i| {
                let t = self.triangle(i);
                [
                    (t[0].x + t[1].x + t[2].x) / 3.0,
                    (t[0].y + t[1].y + t[2].y) / 3.0,
                ]
            },
            |&i| fill_box(self.triangle(i)),
        )
    }
}

/// What [`Scene::buffers`] hands the renderer; see [`super::Drawing`].
pub struct Buffers {
    pub strokes: Vec<u8>,
    pub fills: Vec<u8>,
    pub opaque_strokes: usize,
    pub opaque_fills: usize,
    pub stroke_tiles: Vec<u8>,
    pub fill_tiles: Vec<u8>,
    pub opaque_stroke_tiles: usize,
    pub opaque_fill_tiles: usize,
    pub translucent_runs: Vec<u8>,
}

/// Elements in one tile of a translucent half.
const TRANSLUCENT_TILE: u32 = 4096;
/// Most runs the translucent pass alternates fills and strokes in, each a
/// few draw calls.
const MAX_TRANSLUCENT_RUNS: usize = 1024;

/// The translucent halves' tiles, `start` and `count` in elements of the
/// half, and the runs of tiles to draw: (fills, first tile, end tile).
#[derive(Default)]
struct Translucent {
    strokes: Vec<Tile>,
    fills: Vec<Tile>,
    runs: Vec<(bool, u32, u32)>,
}

impl Translucent {
    /// Element `index` of a half, next in draw order.
    fn push(&mut self, fill: bool, index: usize, b: [f64; 4]) {
        let tiles = if fill {
            &mut self.fills
        } else {
            &mut self.strokes
        };
        let same_run = self.runs.last().is_some_and(|r| r.0 == fill);
        if let Some(t) = tiles
            .last_mut()
            .filter(|t| same_run && t.count < TRANSLUCENT_TILE)
        {
            t.count += 1;
            t.min_x = t.min_x.min(b[0]);
            t.min_y = t.min_y.min(b[1]);
            t.max_x = t.max_x.max(b[2]);
            t.max_y = t.max_y.max(b[3]);
            return;
        }
        tiles.push(Tile {
            start: index as u32,
            count: 1,
            min_x: b[0],
            min_y: b[1],
            max_x: b[2],
            max_y: b[3],
        });
        let n = tiles.len() as u32;
        match self.runs.last_mut() {
            Some(r) if same_run => r.2 = n,
            _ => self.runs.push((fill, n - 1, n)),
        }
    }
}

fn stroke_box(s: &Stroke) -> [f64; 4] {
    let h = s.sagitta();
    [
        s.x0.min(s.x1) - h,
        s.y0.min(s.y1) - h,
        s.x0.max(s.x1) + h,
        s.y0.max(s.y1) + h,
    ]
}

fn fill_box(t: &[FillVertex; 3]) -> [f64; 4] {
    [
        t[0].x.min(t[1].x).min(t[2].x),
        t[0].y.min(t[1].y).min(t[2].y),
        t[0].x.max(t[1].x).max(t[2].x),
        t[0].y.max(t[1].y).max(t[2].y),
    ]
}

/// How far from its anchor a run can reach, whatever its alignment and
/// rotation: every character an em wide, which no bundled face exceeds, and
/// a line's height.
fn text_reach(r: &super::text::TextRun) -> f64 {
    let chars = r.text.chars().count() as f64;
    r.unit() * (chars + 1.0)
}

/// Fully opaque geometry can be drawn in any order, the depth buffer
/// deciding what covers what; translucent geometry blends over what is
/// already drawn, so it comes after, in draw order.
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

        let b = s.buffers();
        assert_eq!(b.opaque_strokes, 1);
        assert_eq!(b.opaque_fills, 3);

        // The opaque one comes first in the buffer whatever order it arrived in.
        let first_rgba = u32::from_le_bytes(b.strokes[16..20].try_into().unwrap());
        assert_eq!(first_rgba, solid);
        let first_fill_rgba = u32::from_le_bytes(b.fills[8..12].try_into().unwrap());
        assert_eq!(first_fill_rgba, solid);
    }

    fn u32s(b: &[u8]) -> Vec<u32> {
        b.as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect()
    }

    /// An opaque fill is outlined by edges of no width, which anti-alias it:
    /// a square of two triangles by its four sides, not their diagonal. A
    /// translucent fill and a background one are not.
    #[test]
    fn opaque_fills_are_outlined_for_their_edges() {
        let mut s = Scene::new();
        let red = pack_rgba(255, 0, 0, 255);
        let attr = pack_attr(3, 25, FLAG_CONTRAST);
        s.push_triangle([0.0, 0.0], [1.0, 0.0], [1.0, 1.0], red, attr);
        s.push_triangle([0.0, 0.0], [1.0, 1.0], [0.0, 1.0], red, attr);
        s.edge_fills();
        assert_eq!(s.strokes.len(), 4);
        for k in &s.strokes {
            assert_eq!(k.attr, pack_attr(3, FILL_EDGE, FLAG_CONTRAST));
            assert_eq!(k.rgba, red);
            assert!(k.x0 == k.x1 || k.y0 == k.y1, "a side, not the diagonal");
        }
        // Each fill once: a second call outlines nothing more.
        s.edge_fills();
        assert_eq!(s.strokes.len(), 4);
        s.push_triangle(
            [5.0, 0.0],
            [6.0, 0.0],
            [6.0, 1.0],
            pack_rgba(255, 0, 0, 128),
            attr,
        );
        s.push_triangle(
            [7.0, 0.0],
            [8.0, 0.0],
            [8.0, 1.0],
            red,
            pack_attr(3, 25, FILL_FLAG_BACKGROUND),
        );
        s.edge_fills();
        assert_eq!(s.strokes.len(), 4);
    }

    /// Translucent geometry is drawn in draw order, fills and strokes
    /// interleaved, wherever it was pushed from.
    #[test]
    fn translucent_geometry_keeps_draw_order() {
        let mut s = Scene::new();
        let clear = pack_rgba(255, 0, 0, 128);
        for (order, fill) in [(3, false), (1, true), (2, false), (4, true), (0, false)] {
            s.order = order;
            if fill {
                s.push_triangle([0.0, 0.0], [1.0, 0.0], [0.0, 1.0], clear, 0);
            } else {
                s.push_stroke(0.0, 0.0, 1.0, 0.0, clear, 0);
            }
        }
        // An opaque stroke elsewhere gives the stroke table a bucket first.
        s.order = 9;
        s.push_stroke(50.0, 50.0, 60.0, 50.0, pack_rgba(0, 0, 0, 255), 0);
        let b = s.buffers();
        let orders: Vec<u32> = b
            .strokes
            .chunks(STROKE_BYTES)
            .map(|c| u32s(&c[24..28])[0])
            .collect();
        assert_eq!(orders, [9, 0, 2, 3]);
        // Strokes 0, fill 1, strokes 2 and 3, fill 4: stroke tiles from 1
        // (past the opaque bucket), fill tiles from 0.
        assert_eq!(
            u32s(&b.translucent_runs),
            [0, 1, 2, 1, 0, 1, 0, 2, 3, 1, 1, 2]
        );
        let tiles = u32s(&b.stroke_tiles);
        let starts: Vec<u32> = tiles.chunks(6).map(|t| t[0]).collect();
        let counts: Vec<u32> = tiles.chunks(6).map(|t| t[1]).collect();
        assert_eq!((starts, counts), (vec![0, 1, 2], vec![1, 1, 2]));
    }

    /// Past the most runs, the fills then the strokes.
    #[test]
    fn translucent_runs_have_a_ceiling() {
        let mut s = Scene::new();
        let clear = pack_rgba(255, 0, 0, 128);
        for i in 0..MAX_TRANSLUCENT_RUNS as u32 {
            s.order = 2 * i;
            s.push_triangle([0.0, 0.0], [1.0, 0.0], [0.0, 1.0], clear, 0);
            s.order = 2 * i + 1;
            s.push_stroke(0.0, 0.0, 1.0, 0.0, clear, 0);
        }
        let runs = u32s(&s.buffers().translucent_runs);
        assert_eq!(runs, [1, 0, 1, 0, 0, 1]);
    }

    #[test]
    fn the_contrast_flag_and_the_fade_code_share_one_byte() {
        // Both live in the flags byte, so a hatch on colour 7 has to carry its
        // spacing and its flip without either eating the other.
        for spacing in [0.01, 0.5, 1.5f64, 16.0, 500.0, 50_000.0] {
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
        assert_eq!(encode_fade_spacing(0.0), 0);
    }

    #[test]
    fn the_fade_code_still_resolves_a_useful_spacing_range() {
        // Seven bits, five steps to the octave from 2^-9: a pattern
        // millimetres apart in metres, or metres apart in millimetres.
        let decode = |code: u8| (code as f64 / 5.0 - 9.0).exp2();
        for spacing in [0.003f64, 0.05, 0.5, 2.0, 40.0, 5000.0, 80_000.0] {
            let back = decode(encode_fade_spacing(spacing));
            assert!(
                (back / spacing - 1.0).abs() < 0.075,
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

        let buf = s.buffers().strokes;
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

    /// A circle is four quarter arcs, its extents its own box exactly; an
    /// arc inside a clip stays one, one across it is cut along its curve.
    #[test]
    fn arcs_are_strokes_of_a_quarter_turn() {
        let mut s = Scene::new();
        s.push_arc(10.0, 0.0, 2.0, 0.0, std::f64::consts::TAU, 0, 0);
        assert_eq!(s.strokes.len(), 4);
        let quarter = (std::f64::consts::PI / 8.0).tan() as f32;
        assert!(s.strokes.iter().all(|k| (k.bulge - quarter).abs() < 1e-6));
        let o = s.origin();
        assert_eq!(
            s.extents_local().map(|v| (v * 1e4).round() / 1e4),
            [-2.0, -2.0, 2.0, 2.0]
        );
        assert_eq!(o, [10.0, 0.0]);
        // The encoding carries the bulge last.
        let b = s.buffers();
        let at = STROKE_BYTES - 4;
        assert_eq!(
            f32::from_le_bytes(b.strokes[at..at + 4].try_into().unwrap()),
            quarter
        );

        let mut s = Scene::new();
        s.push_arc(0.0, 0.0, 1.0, 0.0, std::f64::consts::FRAC_PI_2, 0, 0);
        let mark = Mark {
            strokes: 0,
            fills: 0,
            texts: 0,
        };
        s.clip_since(
            mark,
            &super::super::clip::ClipShape::rect([0.0, 0.0], 10.0, 10.0),
        );
        assert_eq!(s.strokes.len(), 1, "inside: still one arc");
        s.clip_since(
            mark,
            &super::super::clip::ClipShape::rect([1.0, 0.0], 1.0, 10.0),
        );
        assert!(
            s.strokes.len() > 1
                && s.strokes
                    .iter()
                    .all(|k| k.bulge == 0.0 && k.x0 >= 0.5 - 1e-9)
        );
        // On the curve, to the flattening's sagitta.
        assert!(s
            .strokes
            .iter()
            .all(|k| (k.x0.hypot(k.y0) - 1.0).abs() < 2e-3));
    }

    #[test]
    fn buffers_have_the_documented_stride() {
        let mut s = Scene::new();
        s.push_stroke(0.0, 0.0, 1.0, 1.0, 0, 0);
        s.push_triangle([0.0, 0.0], [1.0, 0.0], [0.0, 1.0], 0, 0);
        let b = s.buffers();
        assert_eq!(b.strokes.len(), STROKE_BYTES);
        assert_eq!(b.fills.len(), 3 * FILL_BYTES);
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
