//! Vectors and affine transforms in `f64`.

pub type V3 = [f64; 3];
pub type V2 = [f64; 2];

pub(crate) use crate::formats::mesh::{cross, dot, sub};

pub fn add(a: V3, b: V3) -> V3 {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
}

pub fn scale(a: V3, s: f64) -> V3 {
    [a[0] * s, a[1] * s, a[2] * s]
}

pub fn len(a: V3) -> f64 {
    dot(a, a).sqrt()
}

/// The unit vector, or `None` for a zero or non-finite one.
pub fn unit(a: V3) -> Option<V3> {
    let l = len(a);
    (l > 1e-12 && l.is_finite()).then(|| scale(a, 1.0 / l))
}

pub fn lerp(a: V3, b: V3, t: f64) -> V3 {
    [
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
    ]
}

/// A vector perpendicular to `a`.
pub fn any_perpendicular(a: V3) -> V3 {
    let t = if a[0].abs() < 0.9 {
        [1.0, 0.0, 0.0]
    } else {
        [0.0, 1.0, 0.0]
    };
    unit(cross(a, t)).unwrap_or([0.0, 0.0, 1.0])
}

/// An affine transform: `p' = M p + t`, M's columns being the images of the
/// axes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Xf {
    /// Columns: x axis, y axis, z axis, translation.
    pub c: [V3; 4],
}

impl Xf {
    pub const IDENTITY: Xf = Xf {
        c: [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            [0.0, 0.0, 1.0],
            [0.0, 0.0, 0.0],
        ],
    };

    pub fn new(x: V3, y: V3, z: V3, t: V3) -> Xf {
        Xf { c: [x, y, z, t] }
    }

    pub fn translation(t: V3) -> Xf {
        Xf {
            c: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0], t],
        }
    }

    pub fn scaling(s: f64) -> Xf {
        Xf {
            c: [[s, 0.0, 0.0], [0.0, s, 0.0], [0.0, 0.0, s], [0.0; 3]],
        }
    }

    pub fn point(&self, p: V3) -> V3 {
        let c = &self.c;
        [
            c[0][0] * p[0] + c[1][0] * p[1] + c[2][0] * p[2] + c[3][0],
            c[0][1] * p[0] + c[1][1] * p[1] + c[2][1] * p[2] + c[3][1],
            c[0][2] * p[0] + c[1][2] * p[1] + c[2][2] * p[2] + c[3][2],
        ]
    }

    pub fn vector(&self, p: V3) -> V3 {
        let c = &self.c;
        [
            c[0][0] * p[0] + c[1][0] * p[1] + c[2][0] * p[2],
            c[0][1] * p[0] + c[1][1] * p[1] + c[2][1] * p[2],
            c[0][2] * p[0] + c[1][2] * p[1] + c[2][2] * p[2],
        ]
    }

    /// `self` after `o`: `(self * o)(p) = self(o(p))`.
    pub fn mul(&self, o: &Xf) -> Xf {
        Xf {
            c: [
                self.vector(o.c[0]),
                self.vector(o.c[1]),
                self.vector(o.c[2]),
                self.point(o.c[3]),
            ],
        }
    }

    pub fn det(&self) -> f64 {
        dot(self.c[0], cross(self.c[1], self.c[2]))
    }

    pub fn inverse(&self) -> Option<Xf> {
        let d = self.det();
        if !d.is_finite() || d.abs() <= 1e-300 {
            return None;
        }
        let [a, b, c, t] = self.c;
        // Rows of the inverse are the cross products over the determinant.
        let r0 = scale(cross(b, c), 1.0 / d);
        let r1 = scale(cross(c, a), 1.0 / d);
        let r2 = scale(cross(a, b), 1.0 / d);
        let m = Xf {
            c: [
                [r0[0], r1[0], r2[0]],
                [r0[1], r1[1], r2[1]],
                [r0[2], r1[2], r2[2]],
                [0.0; 3],
            ],
        };
        let nt = m.vector(t);
        Some(Xf {
            c: [m.c[0], m.c[1], m.c[2], [-nt[0], -nt[1], -nt[2]]],
        })
    }

    pub fn is_finite(&self) -> bool {
        self.c.iter().flatten().all(|v| v.is_finite())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_undoes() {
        let x = Xf::new(
            [0.0, 2.0, 0.0],
            [-1.0, 0.0, 0.0],
            [0.0, 0.0, 3.0],
            [5.0, -1.0, 2.0],
        );
        let i = x.inverse().unwrap();
        let p = [1.5, -2.0, 0.25];
        let q = i.point(x.point(p));
        assert!(len(sub(p, q)) < 1e-12);
        assert!(Xf::scaling(0.0).inverse().is_none());
    }
}
