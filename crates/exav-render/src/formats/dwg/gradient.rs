//! Gradient hatch fills.
//!
//! A gradient hatch is filled with the same band decomposition as a solid one;
//! only the colour differs, and it is evaluated per vertex. For the linear
//! family that is exact, because the colour varies linearly across the region
//! and so does interpolation across a triangle. For the round family it is an
//! approximation that follows the bands.

use super::palette::Palette;
use super::scene::pack_rgba;

/// Shape of the colour ramp, as AutoCAD names them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    Linear,
    Cylinder,
    Spherical,
    Curved,
}

pub struct Gradient {
    shape: Shape,
    /// `INV...` variants run the ramp the other way.
    inverted: bool,
    /// Direction of the ramp, as a unit vector.
    dir: [f64; 2],
    shift: f64,
    from: [u8; 3],
    to: [u8; 3],
    alpha: u8,
    /// Region centre and half-size, filled in once the loops are known.
    center: [f64; 2],
    half: [f64; 2],
    radius: f64,
}

impl Gradient {
    /// Build from a hatch's gradient record, or None when it is not a gradient.
    ///
    /// `entity_rgba` stands in when the record carries fewer than two colours,
    /// which is how a single-colour gradient with no stored tint reads. An
    /// indexed stop resolves through `palette`, as every indexed colour does.
    pub fn new(g: &crate::cad::Gradient, entity_rgba: u32, palette: Palette) -> Option<Gradient> {
        if g.kind == 0 {
            return None;
        }
        let name = g.name.to_ascii_uppercase();
        let inverted = name.starts_with("INV");
        let base = name.trim_start_matches("INV");
        let shape = match base {
            "CYLINDER" => Shape::Cylinder,
            "SPHERICAL" | "HEMISPHERICAL" => Shape::Spherical,
            "CURVED" => Shape::Curved,
            // LINEAR, and anything a later AutoCAD invents.
            _ => Shape::Linear,
        };

        let entity = [
            (entity_rgba & 0xFF) as u8,
            ((entity_rgba >> 8) & 0xFF) as u8,
            ((entity_rgba >> 16) & 0xFF) as u8,
        ];
        let mut stops: Vec<(f64, [u8; 3])> = g
            .colors
            .iter()
            .filter_map(|(value, color)| {
                let (r, gg, b) = match *color {
                    crate::cad::Color::Rgb(r, g, b) => (r, g, b),
                    crate::cad::Color::Index(i) if i > 0 => palette.rgb(i),
                    _ => return None,
                };
                Some((*value, [r, gg, b]))
            })
            .collect();
        stops.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let (from, to) = match stops.len() {
            0 => (entity, tint(entity, g.tint)),
            1 => (stops[0].1, tint(stops[0].1, g.tint)),
            _ => (stops[0].1, stops[stops.len() - 1].1),
        };

        let (sin_a, cos_a) = g.angle.sin_cos();
        Some(Gradient {
            shape,
            inverted,
            dir: [cos_a, sin_a],
            shift: if g.shift.is_finite() {
                g.shift.clamp(0.0, 1.0)
            } else {
                0.0
            },
            from,
            to,
            alpha: (entity_rgba >> 24) as u8,
            center: [0.0, 0.0],
            half: [1.0, 1.0],
            radius: 1.0,
        })
    }

    /// Fit the ramp to the region it fills. AutoCAD scales a gradient to the
    /// hatch's own extent, not to the drawing.
    pub fn fit(&mut self, loops: &[Vec<[f64; 2]>]) {
        let mut min = [f64::INFINITY; 2];
        let mut max = [f64::NEG_INFINITY; 2];
        for l in loops {
            for p in l {
                min[0] = min[0].min(p[0]);
                min[1] = min[1].min(p[1]);
                max[0] = max[0].max(p[0]);
                max[1] = max[1].max(p[1]);
            }
        }
        if !min[0].is_finite() || !max[0].is_finite() {
            return;
        }
        self.center = [(min[0] + max[0]) / 2.0, (min[1] + max[1]) / 2.0];
        self.half = [
            ((max[0] - min[0]) / 2.0).max(1e-9),
            ((max[1] - min[1]) / 2.0).max(1e-9),
        ];
        // The span the ramp covers along its own direction.
        self.radius = (self.half[0] * self.dir[0]).abs() + (self.half[1] * self.dir[1]).abs();
        self.radius = self.radius.max(1e-9);
    }

    /// Longest triangle edge that still follows the ramp, or infinity when the
    /// ramp is linear.
    ///
    /// Colours are interpolated across a triangle, which reproduces a linear
    /// ramp exactly however few triangles the region decomposes into. A curved
    /// ramp does not: a rectangle comes out of the band decomposition as two
    /// triangles, and a cylinder sampled at four corners loses the bright band
    /// down its middle entirely.
    pub fn max_edge(&self) -> f64 {
        match self.shape {
            Shape::Linear => f64::INFINITY,
            _ => (self.radius / 12.0).max(1e-9),
        }
    }

    /// Colour at one point of the region.
    pub fn color_at(&self, x: f64, y: f64) -> u32 {
        let dx = x - self.center[0];
        let dy = y - self.center[1];

        let t = match self.shape {
            Shape::Linear | Shape::Curved => {
                // -1..1 along the ramp direction, mapped to 0..1.
                let along = (dx * self.dir[0] + dy * self.dir[1]) / self.radius;
                let u = (along + 1.0) / 2.0;
                if self.shape == Shape::Curved {
                    // Eased rather than straight, which is what sets CURVED
                    // apart from LINEAR.
                    let u = u.clamp(0.0, 1.0);
                    u * u * (3.0 - 2.0 * u)
                } else {
                    u
                }
            }
            Shape::Cylinder => {
                // Lit from the middle: the second colour peaks at the centre
                // line and falls off to the first at both edges.
                let along = (dx * self.dir[0] + dy * self.dir[1]) / self.radius;
                1.0 - along.abs()
            }
            Shape::Spherical => {
                let nx = dx / self.half[0];
                let ny = dy / self.half[1];
                1.0 - (nx * nx + ny * ny).sqrt()
            }
        };

        // DXF 461 is not an offset: every gradient has a shifted and an
        // unshifted definition, and the value blends between them. It is the
        // "Centered" box in AutoCAD's dialog and is 0 or 1 in practice. The
        // shifted definition moves the ramp on by half its span, which is what
        // makes the result look lit from one side rather than the middle.
        let t = t.clamp(0.0, 1.0);
        let t = t + (((t + 0.5).fract()) - t) * self.shift;
        let t = if self.inverted { 1.0 - t } else { t };
        let mix = |a: u8, b: u8| {
            (a as f64 + (b as f64 - a as f64) * t)
                .round()
                .clamp(0.0, 255.0) as u8
        };
        pack_rgba(
            mix(self.from[0], self.to[0]),
            mix(self.from[1], self.to[1]),
            mix(self.from[2], self.to[2]),
            self.alpha,
        )
    }
}

/// Split a triangle until no edge is longer than `max_edge`.
///
/// Each step halves every edge into four similar triangles, so `max_depth`
/// bounds the output at 4^max_depth pieces for one input triangle. The caller
/// sets it from how many triangles the region already has, which keeps a
/// gradient over a complicated boundary from exploding.
pub fn subdivide(tri: [[f64; 2]; 3], max_edge: f64, max_depth: u32, out: &mut Vec<[[f64; 2]; 3]>) {
    fn go(
        t: [[f64; 2]; 3],
        max_edge: f64,
        depth: u32,
        max_depth: u32,
        out: &mut Vec<[[f64; 2]; 3]>,
    ) {
        let edge = |a: [f64; 2], b: [f64; 2]| (b[0] - a[0]).hypot(b[1] - a[1]);
        let longest = edge(t[0], t[1]).max(edge(t[1], t[2])).max(edge(t[2], t[0]));
        if depth >= max_depth || longest <= max_edge {
            out.push(t);
            return;
        }
        let mid = |a: [f64; 2], b: [f64; 2]| [(a[0] + b[0]) / 2.0, (a[1] + b[1]) / 2.0];
        let (m01, m12, m20) = (mid(t[0], t[1]), mid(t[1], t[2]), mid(t[2], t[0]));
        for piece in [
            [t[0], m01, m20],
            [m01, t[1], m12],
            [m20, m12, t[2]],
            [m01, m12, m20],
        ] {
            go(piece, max_edge, depth + 1, max_depth, out);
        }
    }
    go(tri, max_edge, 0, max_depth, out);
}

/// How deep a gradient over `triangles` source triangles may subdivide, so the
/// whole hatch stays under `MAX_GRADIENT_TRIANGLES`.
pub fn depth_for(triangles: usize) -> u32 {
    let mut depth = 0;
    while depth < 6 && triangles * 4usize.pow(depth + 1) <= MAX_GRADIENT_TRIANGLES {
        depth += 1;
    }
    depth
}

/// Triangle budget for one gradient hatch. A gradient is a background wash, so
/// it is never worth more geometry than the drawing it sits behind.
const MAX_GRADIENT_TRIANGLES: usize = 8192;

/// A single-colour gradient runs from the colour to a tinted version of it.
/// AutoCAD's tint slider blends toward white.
fn tint(c: [u8; 3], amount: f64) -> [u8; 3] {
    let k = if amount.is_finite() {
        amount.clamp(0.0, 1.0)
    } else {
        0.5
    };
    let f = |v: u8| (v as f64 + (255.0 - v as f64) * k).round() as u8;
    [f(c[0]), f(c[1]), f(c[2])]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cad::Color;

    /// A two-colour gradient, blue to yellow.
    fn blue_to_yellow(name: &str, angle: f64) -> crate::cad::Gradient {
        crate::cad::Gradient {
            kind: 1,
            angle,
            shift: 0.0,
            single_color: false,
            tint: 1.0,
            colors: vec![(0.0, Color::Rgb(0, 0, 255)), (1.0, Color::Rgb(255, 255, 0))],
            name: name.to_string(),
        }
    }

    fn square() -> Vec<Vec<[f64; 2]>> {
        vec![vec![[0.0, 0.0], [10.0, 0.0], [10.0, 10.0], [0.0, 10.0]]]
    }

    #[test]
    fn a_linear_gradient_runs_between_its_two_colours() {
        let mut g =
            Gradient::new(&blue_to_yellow("LINEAR", 0.0), 0xFF000000, Palette::Light).unwrap();
        g.fit(&square());

        let left = g.color_at(0.0, 5.0);
        let right = g.color_at(10.0, 5.0);
        assert_eq!(left & 0x00FFFFFF, 0x00FF0000, "left end should be blue");
        assert_eq!(right & 0x00FFFFFF, 0x0000FFFF, "right end should be yellow");

        // Halfway is halfway.
        let mid = g.color_at(5.0, 5.0);
        let r = mid & 0xFF;
        assert!((r as i32 - 128).abs() <= 2, "mid red {r}");
    }

    #[test]
    fn a_linear_gradient_is_flat_across_its_own_direction() {
        let mut g =
            Gradient::new(&blue_to_yellow("LINEAR", 0.0), 0xFF000000, Palette::Light).unwrap();
        g.fit(&square());
        assert_eq!(g.color_at(3.0, 0.0), g.color_at(3.0, 10.0));
    }

    #[test]
    fn inverting_swaps_the_ends() {
        let mut plain =
            Gradient::new(&blue_to_yellow("CYLINDER", 0.0), 0xFF000000, Palette::Light).unwrap();
        let mut inv = Gradient::new(
            &blue_to_yellow("INVCYLINDER", 0.0),
            0xFF000000,
            Palette::Light,
        )
        .unwrap();
        plain.fit(&square());
        inv.fit(&square());
        // A cylinder peaks in the middle, so inverting bottoms out there.
        assert_eq!(plain.color_at(5.0, 5.0) & 0x00FFFFFF, 0x0000FFFF);
        assert_eq!(inv.color_at(5.0, 5.0) & 0x00FFFFFF, 0x00FF0000);
    }

    #[test]
    fn a_spherical_gradient_peaks_at_the_centre() {
        let mut g = Gradient::new(
            &blue_to_yellow("SPHERICAL", 0.0),
            0xFF000000,
            Palette::Light,
        )
        .unwrap();
        g.fit(&square());
        assert_eq!(g.color_at(5.0, 5.0) & 0x00FFFFFF, 0x0000FFFF);
        assert_eq!(g.color_at(0.0, 5.0) & 0x00FFFFFF, 0x00FF0000);
    }

    #[test]
    fn a_curved_ramp_is_subdivided_and_a_linear_one_is_not() {
        let mut linear =
            Gradient::new(&blue_to_yellow("LINEAR", 0.0), 0xFF000000, Palette::Light).unwrap();
        let mut cyl =
            Gradient::new(&blue_to_yellow("CYLINDER", 0.0), 0xFF000000, Palette::Light).unwrap();
        linear.fit(&square());
        cyl.fit(&square());

        let tri = [[0.0, 0.0], [10.0, 0.0], [0.0, 10.0]];
        let mut out = Vec::new();
        subdivide(tri, linear.max_edge(), 6, &mut out);
        assert_eq!(out.len(), 1, "a linear ramp needs no subdivision");

        out.clear();
        subdivide(tri, cyl.max_edge(), 6, &mut out);
        assert!(out.len() > 16, "curved ramp split into {}", out.len());
        // Area is conserved: the pieces cover the original exactly.
        let area = |t: &[[f64; 2]; 3]| {
            ((t[1][0] - t[0][0]) * (t[2][1] - t[0][1]) - (t[2][0] - t[0][0]) * (t[1][1] - t[0][1]))
                .abs()
                / 2.0
        };
        let total: f64 = out.iter().map(area).sum();
        assert!((total - 50.0).abs() < 1e-6, "area {total}");
    }

    #[test]
    fn the_subdivision_budget_shrinks_as_the_region_gets_busier() {
        // One triangle can go deep; a thousand cannot.
        assert!(depth_for(1) >= 5);
        assert_eq!(depth_for(4096), 0);
        for n in [1usize, 7, 64, 500, 5000] {
            assert!(n * 4usize.pow(depth_for(n)) <= 8192 || depth_for(n) == 0);
        }
    }

    #[test]
    fn shift_blends_between_the_two_definitions() {
        let mut plain =
            Gradient::new(&blue_to_yellow("LINEAR", 0.0), 0xFF000000, Palette::Light).unwrap();
        plain.fit(&square());

        let mut shifted_pattern = blue_to_yellow("LINEAR", 0.0);
        shifted_pattern.shift = 1.0;
        let mut shifted = Gradient::new(&shifted_pattern, 0xFF000000, Palette::Light).unwrap();
        shifted.fit(&square());

        // Unshifted runs blue at the left edge to yellow at the right.
        assert_eq!(plain.color_at(0.0, 5.0) & 0x00FFFFFF, 0x00FF0000);
        assert_eq!(plain.color_at(10.0, 5.0) & 0x00FFFFFF, 0x0000FFFF);

        // Shifted by half a span, the middle of the run is where the colours
        // change over instead of the ends.
        let mid = shifted.color_at(5.0, 5.0);
        assert!(
            (mid & 0xFF) < 0x20 || (mid & 0xFF) > 0xE0,
            "middle {:06x} should be near one end of the ramp",
            mid & 0x00FFFFFF
        );
        // And it is not the same picture as the unshifted one.
        assert_ne!(plain.color_at(2.5, 5.0), shifted.color_at(2.5, 5.0));
    }

    #[test]
    fn a_hatch_without_a_gradient_makes_none() {
        let mut p = blue_to_yellow("LINEAR", 0.0);
        p.kind = 0;
        assert!(Gradient::new(&p, 0xFF000000, Palette::Light).is_none());
    }

    /// An indexed stop is the colour the background's palette gives it, as
    /// every other indexed colour is: index 8 is a different grey on paper and
    /// on a dark ground.
    #[test]
    fn an_indexed_stop_reads_through_the_palette() {
        let mut p = blue_to_yellow("LINEAR", 0.0);
        p.colors[0].1 = Color::Index(8);
        for (palette, grey) in [(Palette::Light, 65u32), (Palette::Dark, 128)] {
            let mut g = Gradient::new(&p, 0xFF000000, palette).unwrap();
            g.fit(&square());
            assert_eq!(
                g.color_at(0.0, 5.0) & 0x00FF_FFFF,
                grey | grey << 8 | grey << 16,
                "{palette:?}"
            );
        }
    }

    #[test]
    fn transparency_carries_through_to_the_ramp() {
        let mut g =
            Gradient::new(&blue_to_yellow("LINEAR", 0.0), 0x80000000, Palette::Light).unwrap();
        g.fit(&square());
        assert_eq!(g.color_at(5.0, 5.0) >> 24, 0x80);
    }
}
