//! Boolean operations on closed triangle meshes with binary space
//! partitioning trees (Naylor, Amanatides and Thibault, "Merging BSP trees
//! yields polyhedral set operations", SIGGRAPH 1990): each operand's
//! polygons are clipped by the other's tree. Trees live in an arena and are
//! walked without recursion; the work is bounded, and an operation past
//! its bound is given up (`None`), so that the caller draws the first
//! operand as it is.

use super::math::{cross, dot, lerp, sub, unit, V3};

/// Most polygon placements (into a tree or through one) per operation.
const WORK: usize = 30_000_000;
/// Operands larger than this, in triangles, are not combined.
pub const MAX_TRIANGLES: usize = 60_000;

#[derive(Debug, Clone, Copy)]
struct Plane {
    n: V3,
    w: f64,
}

impl Plane {
    fn flip(&mut self) {
        self.n = [-self.n[0], -self.n[1], -self.n[2]];
        self.w = -self.w;
    }
}

/// A convex polygon and which input mesh it came from.
#[derive(Debug, Clone)]
pub struct Poly {
    v: Vec<V3>,
    plane: Plane,
    pub tag: u32,
}

impl Poly {
    pub fn triangle(a: V3, b: V3, c: V3, tag: u32) -> Option<Poly> {
        let n = unit(cross(sub(b, a), sub(c, a)))?;
        Some(Poly {
            v: vec![a, b, c],
            plane: Plane { n, w: dot(n, a) },
            tag,
        })
    }

    fn flip(&mut self) {
        self.v.reverse();
        self.plane.flip();
    }

    pub fn vertices(&self) -> &[V3] {
        &self.v
    }
}

const NONE: u32 = u32::MAX;

struct Node {
    plane: Option<Plane>,
    front: u32,
    back: u32,
    polys: Vec<Poly>,
}

struct Tree {
    nodes: Vec<Node>,
}

struct Ctx {
    eps: f64,
    work: usize,
}

impl Ctx {
    fn spend(&mut self, n: usize) -> Option<()> {
        self.work += n;
        (self.work <= WORK).then_some(())
    }
}

const COPLANAR: u8 = 0;
const FRONT: u8 = 1;
const BACK: u8 = 2;

/// Sorts `poly` against `plane` into the four lists; a coplanar polygon
/// goes to `co_front` or `co_back` by its facing.
fn split(
    plane: &Plane,
    poly: Poly,
    eps: f64,
    co_front: &mut Vec<Poly>,
    co_back: &mut Vec<Poly>,
    front: &mut Vec<Poly>,
    back: &mut Vec<Poly>,
) {
    let mut kind = COPLANAR;
    let types: Vec<u8> = poly
        .v
        .iter()
        .map(|&p| {
            let t = dot(plane.n, p) - plane.w;
            let k = if t < -eps {
                BACK
            } else if t > eps {
                FRONT
            } else {
                COPLANAR
            };
            kind |= k;
            k
        })
        .collect();
    match kind {
        COPLANAR => {
            if dot(plane.n, poly.plane.n) > 0.0 {
                co_front.push(poly)
            } else {
                co_back.push(poly)
            }
        }
        FRONT => front.push(poly),
        BACK => back.push(poly),
        _ => {
            let n = poly.v.len();
            let mut f = Vec::with_capacity(n + 1);
            let mut b = Vec::with_capacity(n + 1);
            for i in 0..n {
                let j = (i + 1) % n;
                let (ti, tj) = (types[i], types[j]);
                let (vi, vj) = (poly.v[i], poly.v[j]);
                if ti != BACK {
                    f.push(vi);
                }
                if ti != FRONT {
                    b.push(vi);
                }
                if (ti | tj) == FRONT | BACK {
                    let d = dot(plane.n, sub(vj, vi));
                    let t = if d != 0.0 {
                        (plane.w - dot(plane.n, vi)) / d
                    } else {
                        0.5
                    };
                    let v = lerp(vi, vj, t.clamp(0.0, 1.0));
                    f.push(v);
                    b.push(v);
                }
            }
            if f.len() >= 3 {
                front.push(Poly {
                    v: f,
                    plane: poly.plane,
                    tag: poly.tag,
                });
            }
            if b.len() >= 3 {
                back.push(Poly {
                    v: b,
                    plane: poly.plane,
                    tag: poly.tag,
                });
            }
        }
    }
}

impl Tree {
    fn new(polys: Vec<Poly>, cx: &mut Ctx) -> Option<Tree> {
        let mut t = Tree {
            nodes: vec![Node {
                plane: None,
                front: NONE,
                back: NONE,
                polys: Vec::new(),
            }],
        };
        t.build(polys, cx)?;
        Some(t)
    }

    fn add_node(&mut self) -> u32 {
        self.nodes.push(Node {
            plane: None,
            front: NONE,
            back: NONE,
            polys: Vec::new(),
        });
        (self.nodes.len() - 1) as u32
    }

    fn build(&mut self, polys: Vec<Poly>, cx: &mut Ctx) -> Option<()> {
        let mut stack = vec![(0u32, polys)];
        while let Some((id, polys)) = stack.pop() {
            if polys.is_empty() {
                continue;
            }
            cx.spend(polys.len())?;
            let node = &mut self.nodes[id as usize];
            let plane = *node.plane.get_or_insert(polys[0].plane);
            let (mut f, mut b) = (Vec::new(), Vec::new());
            let mut co = std::mem::take(&mut node.polys);
            let mut co_back = Vec::new();
            for p in polys {
                split(&plane, p, cx.eps, &mut co, &mut co_back, &mut f, &mut b);
            }
            co.append(&mut co_back);
            self.nodes[id as usize].polys = co;
            if !f.is_empty() {
                let child = match self.nodes[id as usize].front {
                    NONE => {
                        let c = self.add_node();
                        self.nodes[id as usize].front = c;
                        c
                    }
                    c => c,
                };
                stack.push((child, f));
            }
            if !b.is_empty() {
                let child = match self.nodes[id as usize].back {
                    NONE => {
                        let c = self.add_node();
                        self.nodes[id as usize].back = c;
                        c
                    }
                    c => c,
                };
                stack.push((child, b));
            }
        }
        Some(())
    }

    /// Solid becomes empty space and the reverse.
    fn invert(&mut self) {
        for n in &mut self.nodes {
            for p in &mut n.polys {
                p.flip();
            }
            if let Some(pl) = &mut n.plane {
                pl.flip();
            }
            std::mem::swap(&mut n.front, &mut n.back);
        }
    }

    /// The parts of `polys` outside this tree's solid.
    fn clip_polys(&self, polys: Vec<Poly>, cx: &mut Ctx) -> Option<Vec<Poly>> {
        let mut out = Vec::new();
        let mut stack = vec![(0u32, polys)];
        while let Some((id, polys)) = stack.pop() {
            cx.spend(polys.len())?;
            let node = &self.nodes[id as usize];
            let Some(plane) = node.plane else {
                out.extend(polys);
                continue;
            };
            let (mut f, mut b) = (Vec::new(), Vec::new());
            let (mut cf, mut cb) = (Vec::new(), Vec::new());
            for p in polys {
                split(&plane, p, cx.eps, &mut cf, &mut cb, &mut f, &mut b);
            }
            f.append(&mut cf);
            b.append(&mut cb);
            if node.front != NONE {
                stack.push((node.front, f));
            } else {
                out.extend(f);
            }
            if node.back != NONE {
                stack.push((node.back, b));
            }
        }
        Some(out)
    }

    /// Removes from this tree the polygons inside `other`'s solid.
    fn clip_to(&mut self, other: &Tree, cx: &mut Ctx) -> Option<()> {
        for i in 0..self.nodes.len() {
            let polys = std::mem::take(&mut self.nodes[i].polys);
            self.nodes[i].polys = other.clip_polys(polys, cx)?;
        }
        Some(())
    }

    fn all(self) -> Vec<Poly> {
        self.nodes.into_iter().flat_map(|n| n.polys).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Union,
    Difference,
    Intersection,
}

fn bounds(p: &[Poly]) -> Option<(V3, V3)> {
    let mut lo = [f64::INFINITY; 3];
    let mut hi = [f64::NEG_INFINITY; 3];
    for v in p.iter().flat_map(|p| &p.v) {
        for k in 0..3 {
            lo[k] = lo[k].min(v[k]);
            hi[k] = hi[k].max(v[k]);
        }
    }
    (lo[0] <= hi[0]).then_some((lo, hi))
}

/// `a op b`. `None` when the work bound is reached.
pub fn combine(op: Op, a: Vec<Poly>, b: Vec<Poly>) -> Option<Vec<Poly>> {
    let (Some(ba), Some(bb)) = (bounds(&a), bounds(&b)) else {
        return Some(match op {
            Op::Union => a.into_iter().chain(b).collect(),
            Op::Difference => a,
            Op::Intersection => Vec::new(),
        });
    };
    let size = (0..3)
        .map(|k| ba.1[k].max(bb.1[k]) - ba.0[k].min(bb.0[k]))
        .fold(0.0f64, f64::max);
    let eps = (size * 1e-7).max(1e-12);
    let apart = (0..3).any(|k| ba.1[k] < bb.0[k] - eps || bb.1[k] < ba.0[k] - eps);
    if apart {
        return Some(match op {
            Op::Union => a.into_iter().chain(b).collect(),
            Op::Difference => a,
            Op::Intersection => Vec::new(),
        });
    }
    let mut cx = Ctx { eps, work: 0 };
    let mut ta = Tree::new(a, &mut cx)?;
    let mut tb = Tree::new(b, &mut cx)?;
    match op {
        Op::Union => {
            ta.clip_to(&tb, &mut cx)?;
            tb.clip_to(&ta, &mut cx)?;
            tb.invert();
            tb.clip_to(&ta, &mut cx)?;
            tb.invert();
            ta.build(tb.all(), &mut cx)?;
            Some(ta.all())
        }
        Op::Difference => {
            ta.invert();
            ta.clip_to(&tb, &mut cx)?;
            tb.clip_to(&ta, &mut cx)?;
            tb.invert();
            tb.clip_to(&ta, &mut cx)?;
            tb.invert();
            ta.build(tb.all(), &mut cx)?;
            ta.invert();
            Some(ta.all())
        }
        Op::Intersection => {
            ta.invert();
            tb.clip_to(&ta, &mut cx)?;
            tb.invert();
            ta.clip_to(&tb, &mut cx)?;
            tb.clip_to(&ta, &mut cx)?;
            ta.build(tb.all(), &mut cx)?;
            ta.invert();
            Some(ta.all())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bx(lo: V3, hi: V3) -> Vec<Poly> {
        let c = |i: usize| {
            [
                if i & 1 == 0 { lo[0] } else { hi[0] },
                if i & 2 == 0 { lo[1] } else { hi[1] },
                if i & 4 == 0 { lo[2] } else { hi[2] },
            ]
        };
        let quads = [
            [0, 2, 3, 1],
            [4, 5, 7, 6],
            [0, 1, 5, 4],
            [2, 6, 7, 3],
            [0, 4, 6, 2],
            [1, 3, 7, 5],
        ];
        let mut out = Vec::new();
        for q in quads {
            out.push(Poly::triangle(c(q[0]), c(q[1]), c(q[2]), 0).unwrap());
            out.push(Poly::triangle(c(q[0]), c(q[2]), c(q[3]), 0).unwrap());
        }
        out
    }

    /// Signed volume by the divergence theorem.
    fn volume(p: &[Poly]) -> f64 {
        p.iter()
            .map(|p| {
                (1..p.v.len() - 1)
                    .map(|k| dot(p.v[0], cross(p.v[k], p.v[k + 1])) / 6.0)
                    .sum::<f64>()
            })
            .sum()
    }

    #[test]
    fn the_box_is_outward() {
        assert!((volume(&bx([0.0; 3], [1.0, 2.0, 3.0])) - 6.0).abs() < 1e-12);
    }

    #[test]
    fn a_hole_through_a_wall() {
        let wall = bx([0.0, 0.0, 0.0], [4.0, 0.3, 3.0]);
        let hole = bx([1.0, -1.0, 1.0], [2.0, 1.0, 2.0]);
        let r = combine(Op::Difference, wall, hole).unwrap();
        assert!((volume(&r) - (4.0 * 0.3 * 3.0 - 0.3)).abs() < 1e-9);
    }

    #[test]
    fn union_and_intersection_of_overlapping_boxes() {
        let a = bx([0.0; 3], [2.0; 3]);
        let b = bx([1.0; 3], [3.0; 3]);
        let u = combine(Op::Union, a.clone(), b.clone()).unwrap();
        assert!((volume(&u) - 15.0).abs() < 1e-9);
        let i = combine(Op::Intersection, a, b).unwrap();
        assert!((volume(&i) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn disjoint_operands_are_not_split() {
        let a = bx([0.0; 3], [1.0; 3]);
        let b = bx([5.0; 3], [6.0; 3]);
        assert_eq!(
            combine(Op::Difference, a.clone(), b).unwrap().len(),
            a.len()
        );
    }
}
