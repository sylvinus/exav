//! Representations and representation items: choosing a product's body,
//! mapped items, booleans and half-spaces, and the dispatch to each kind of
//! geometry.

use std::rc::Rc;

use super::csg::{self, Op, Poly};
use super::math::{self, cross, dot, sub, unit, Xf, V3};
use super::step::Value;
use super::{is, Color, Mesh, Piece, Reader, MAX_DEPTH};

/// Representation identifiers that are not the body: axes, footprints,
/// boxes, 2D plan symbols and the like.
const NOT_BODY: &[&str] = &[
    "axis",
    "footprint",
    "box",
    "annotation",
    "profile",
    "reference",
    "clearance",
    "cog",
    "lighting",
    "survey",
    "plan",
    "outline",
];

/// Representation types that hold no surface.
const NOT_SURFACE: &[&str] = &[
    "curve",
    "curve2d",
    "curve3d",
    "geometriccurveset",
    "annotation2d",
    "boundingbox",
    "point",
    "pointcloud",
];

/// Items that are not surfaces, skipped without a warning.
const NOT_DRAWN: &[&[u8]] = &[
    b"IFCPOLYLINE",
    b"IFCINDEXEDPOLYCURVE",
    b"IFCCOMPOSITECURVE",
    b"IFCTRIMMEDCURVE",
    b"IFCCIRCLE",
    b"IFCELLIPSE",
    b"IFCLINE",
    b"IFCBSPLINECURVEWITHKNOTS",
    b"IFCRATIONALBSPLINECURVEWITHKNOTS",
    b"IFCCARTESIANPOINT",
    b"IFCCARTESIANPOINTLIST2D",
    b"IFCCARTESIANPOINTLIST3D",
    b"IFCGEOMETRICSET",
    b"IFCGEOMETRICCURVESET",
    b"IFCTEXTLITERAL",
    b"IFCTEXTLITERALWITHEXTENT",
    b"IFCANNOTATIONFILLAREA",
    b"IFCHALFSPACESOLID",
    b"IFCPOLYGONALBOUNDEDHALFSPACE",
    b"IFCBOXEDHALFSPACE",
    b"IFCBOUNDINGBOX",
    b"IFCAXIS2PLACEMENT2D",
    b"IFCAXIS2PLACEMENT3D",
    b"IFCALIGNMENTCURVE",
    b"IFCGRADIENTCURVE",
    b"IFCSEGMENTEDREFERENCECURVE",
    b"IFCOFFSETCURVEBYDISTANCES",
    b"IFCPOLYLOOP",
    b"IFCEDGECURVE",
];

const HALF_SPACES: &[&[u8]] = &[
    b"IFCHALFSPACESOLID",
    b"IFCPOLYGONALBOUNDEDHALFSPACE",
    b"IFCBOXEDHALFSPACE",
];

fn ids(v: Option<&Value>) -> Vec<u32> {
    match v {
        Some(Value::Ref(r)) => vec![*r],
        Some(v) => v
            .list()
            .map(|l| l.iter().filter_map(Value::id).collect())
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

impl<'a> Reader<'a> {
    /// A product's body, in its object coordinates.
    pub fn product(&mut self, shape: u32) -> Vec<Piece> {
        let Some(p) = self.f.params(shape) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for rep in self.body_representations(&ids(p.get(2))) {
            let Some(rp) = self.f.params(rep) else {
                continue;
            };
            for item in ids(rp.get(3)) {
                match self.item(item, 0, None) {
                    Some(mut v) => out.append(&mut v),
                    None => self.warnings.invalid = self.warnings.invalid.saturating_add(1),
                }
            }
        }
        out
    }

    /// The body representations: those named `Body`, else the fallbacks,
    /// else any that is neither auxiliary nor curves.
    fn body_representations(&self, reps: &[u32]) -> Vec<u32> {
        let info: Vec<(u32, String, String)> = reps
            .iter()
            .filter_map(|&r| {
                let (ty, p) = self.get(r)?;
                if !is(
                    ty,
                    &[b"IFCSHAPEREPRESENTATION", b"IFCTOPOLOGYREPRESENTATION"],
                ) {
                    return None;
                }
                let name = p
                    .get(1)
                    .and_then(Value::text)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let kind = p
                    .get(2)
                    .and_then(Value::text)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                Some((r, name, kind))
            })
            .collect();
        for wanted in [&["body"][..], &["facetation", "body-fallback"][..]] {
            let found: Vec<u32> = info
                .iter()
                .filter(|(_, n, _)| wanted.contains(&n.as_str()))
                .map(|(r, _, _)| *r)
                .collect();
            if !found.is_empty() {
                return found;
            }
        }
        info.iter()
            .filter(|(_, n, k)| {
                !NOT_BODY.contains(&n.as_str()) && !NOT_SURFACE.contains(&k.as_str())
            })
            .map(|(r, _, _)| *r)
            .collect()
    }

    /// An opening's body, in model coordinates (before the length unit).
    pub fn opening(&mut self, id: u32) -> Option<Vec<Piece>> {
        let p = self.f.params(id)?;
        let world = match p.get(5).and_then(Value::id) {
            Some(pl) => self.placement(pl)?,
            None => Xf::IDENTITY,
        };
        let shape = p.get(6)?.id()?;
        let mut pieces = self.product(shape);
        for piece in &mut pieces {
            piece.mesh.transform(&world);
        }
        Some(pieces)
    }

    /// `pieces` minus `cutters`, each closed piece on its own.
    pub fn subtract(&mut self, pieces: Vec<Piece>, cutters: Vec<Piece>) -> Vec<Piece> {
        if cutters.is_empty() {
            return pieces;
        }
        self.combine(Op::Difference, pieces, cutters)
    }

    /// One representation item, coloured by its own style or else by
    /// `inherited`. `None` when its data is unusable.
    pub fn item(&mut self, id: u32, depth: u32, inherited: Option<Color>) -> Option<Vec<Piece>> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.visit()?;
        let (ty, p) = self.get(id)?;
        let color = self.item_color(id).or(inherited);
        let solid = |mesh: Mesh| {
            vec![Piece {
                color,
                mesh,
                solid: true,
            }]
        };
        let surface = |mesh: Mesh| {
            vec![Piece {
                color,
                mesh,
                solid: false,
            }]
        };
        let out = match ty {
            b"IFCEXTRUDEDAREASOLID" | b"IFCEXTRUDEDAREASOLIDTAPERED" => {
                let (m, closed) = self.extruded(&p, ty == b"IFCEXTRUDEDAREASOLIDTAPERED", depth)?;
                vec![Piece {
                    color,
                    mesh: m,
                    solid: closed,
                }]
            }
            b"IFCREVOLVEDAREASOLID" | b"IFCREVOLVEDAREASOLIDTAPERED" => {
                solid(self.revolved(&p, depth)?)
            }
            b"IFCSWEPTDISKSOLID" | b"IFCSWEPTDISKSOLIDPOLYGONAL" => {
                solid(self.swept_disk(&p, depth)?)
            }
            b"IFCSURFACECURVESWEPTAREASOLID"
            | b"IFCFIXEDREFERENCESWEPTAREASOLID"
            | b"IFCDIRECTRIXCURVESWEPTAREASOLID" => solid(self.swept_area(ty, &p, depth)?),
            b"IFCTRIANGULATEDFACESET" | b"IFCTRIANGULATEDIRREGULARNETWORK" => {
                let closed = p.get(2).and_then(Value::boolean) == Some(true);
                let m = self.triangulated_face_set(&p)?;
                vec![Piece {
                    color,
                    mesh: m,
                    solid: closed,
                }]
            }
            b"IFCPOLYGONALFACESET" => {
                let closed = p.get(1).and_then(Value::boolean) == Some(true);
                let m = self.polygonal_face_set(&p)?;
                vec![Piece {
                    color,
                    mesh: m,
                    solid: closed,
                }]
            }
            b"IFCFACETEDBREP"
            | b"IFCFACETEDBREPWITHVOIDS"
            | b"IFCADVANCEDBREP"
            | b"IFCADVANCEDBREPWITHVOIDS" => {
                let mut m = self.shell(p.first()?.id()?, depth)?;
                m.orient_outward();
                for v in ids(p.get(1)) {
                    let mut void = self.shell(v, depth)?;
                    // Inward: a void's volume counts against the solid.
                    void.orient_outward();
                    for t in &mut void.t {
                        t.swap(1, 2);
                    }
                    m.append(&void);
                }
                solid(m)
            }
            b"IFCSHELLBASEDSURFACEMODEL" | b"IFCFACEBASEDSURFACEMODEL" => {
                let mut m = Mesh::default();
                for s in ids(p.first()) {
                    m.append(&self.shell(s, depth)?);
                }
                surface(m)
            }
            b"IFCCURVEBOUNDEDPLANE" => surface(self.curve_bounded_plane(&p, depth)?),
            b"IFCBOOLEANRESULT" | b"IFCBOOLEANCLIPPINGRESULT" => {
                let op = match p.first()?.enumeration()? {
                    b"DIFFERENCE" => Op::Difference,
                    b"UNION" => Op::Union,
                    b"INTERSECTION" => Op::Intersection,
                    _ => return None,
                };
                self.boolean(op, p.get(1)?.id()?, p.get(2)?.id()?, depth, color)?
            }
            b"IFCCSGSOLID" => self.item(p.first()?.id()?, depth + 1, color)?,
            b"IFCBLOCK"
            | b"IFCRECTANGULARPYRAMID"
            | b"IFCRIGHTCIRCULARCONE"
            | b"IFCRIGHTCIRCULARCYLINDER"
            | b"IFCSPHERE" => solid(self.primitive(ty, &p)?),
            b"IFCMAPPEDITEM" => self.mapped(&p, depth, color)?,
            _ if is(ty, NOT_DRAWN) => Vec::new(),
            _ => {
                self.unsupported(ty);
                Vec::new()
            }
        };
        let triangles: usize = out.iter().map(|p| p.mesh.t.len()).sum();
        self.spend(triangles)?;
        Some(out)
    }

    fn mapped(&mut self, p: &[Value], depth: u32, color: Option<Color>) -> Option<Vec<Piece>> {
        let map = p.first()?.id()?;
        let target = self.operator(p.get(1)?.id()?)?;
        let source = match self.maps.get(&map) {
            Some(s) => Rc::clone(s),
            None => {
                let mp = self.f.params(map)?;
                let origin = self.axis2(mp.first()?.id()?)?;
                let rp = self.f.params(mp.get(1)?.id()?)?;
                let mut pieces = Vec::new();
                for item in ids(rp.get(3)) {
                    match self.item(item, depth + 1, None) {
                        Some(mut v) => pieces.append(&mut v),
                        None => self.warnings.invalid = self.warnings.invalid.saturating_add(1),
                    }
                }
                for piece in &mut pieces {
                    piece.mesh.transform(&origin);
                }
                let s = Rc::new(pieces);
                self.maps.insert(map, Rc::clone(&s));
                s
            }
        };
        let mut out = Vec::with_capacity(source.len());
        for piece in source.iter() {
            let mut piece = piece.clone();
            piece.color = piece.color.or(color);
            piece.mesh.transform(&target);
            out.push(piece);
        }
        Some(out)
    }

    /// A boolean operand: an item, or a half-space bounded around `near`.
    fn boolean(
        &mut self,
        op: Op,
        first: u32,
        second: u32,
        depth: u32,
        color: Option<Color>,
    ) -> Option<Vec<Piece>> {
        let a = self.item(first, depth + 1, color)?;
        let (ty, _) = self.get(second)?;
        let b = if is(ty, HALF_SPACES) {
            let mut all = Mesh::default();
            for piece in &a {
                all.append(&piece.mesh);
            }
            let Some(near) = all.bounds() else {
                return Some(a);
            };
            match self.half_space(second, near, depth) {
                Some(m) => vec![Piece {
                    color,
                    mesh: m,
                    solid: true,
                }],
                None => {
                    self.warnings.invalid = self.warnings.invalid.saturating_add(1);
                    return Some(a);
                }
            }
        } else {
            self.item(second, depth + 1, color)?
        };
        Some(self.combine(op, a, b))
    }

    /// `a op b` on closed pieces; given up (counted, and `a` kept) when an
    /// operand is open or too large, or the work bound is reached.
    pub fn combine(&mut self, op: Op, a: Vec<Piece>, b: Vec<Piece>) -> Vec<Piece> {
        if a.is_empty() || b.is_empty() {
            return match op {
                Op::Union => a.into_iter().chain(b).collect(),
                Op::Difference => a,
                Op::Intersection => Vec::new(),
            };
        }
        let size: usize = a.iter().chain(&b).map(|p| p.mesh.t.len()).sum();
        let closed = b.iter().all(|p| p.solid) && a.iter().any(|p| p.solid);
        if !closed || size > csg::MAX_TRIANGLES {
            self.warnings.booleans_skipped = self.warnings.booleans_skipped.saturating_add(1);
            return if op == Op::Union {
                a.into_iter().chain(b).collect()
            } else {
                a
            };
        }
        // Open pieces of `a` are kept as they are.
        let (solids, mut open): (Vec<Piece>, Vec<Piece>) = a.into_iter().partition(|p| p.solid);
        let polys = |pieces: &[Piece], base: u32| -> Vec<Poly> {
            let mut out = Vec::new();
            for (k, piece) in pieces.iter().enumerate() {
                let m = &piece.mesh;
                for t in &m.t {
                    let (Some(&x), Some(&y), Some(&z)) = (
                        m.p.get(t[0] as usize),
                        m.p.get(t[1] as usize),
                        m.p.get(t[2] as usize),
                    ) else {
                        continue;
                    };
                    if let Some(poly) = Poly::triangle(x, y, z, base + k as u32) {
                        out.push(poly);
                    }
                }
            }
            out
        };
        let pa = polys(&solids, 0);
        let pb = polys(&b, solids.len() as u32);
        let Some(result) = csg::combine(op, pa, pb) else {
            self.warnings.booleans_skipped = self.warnings.booleans_skipped.saturating_add(1);
            let mut out = solids;
            if op == Op::Union {
                out.extend(b);
            }
            out.append(&mut open);
            return out;
        };
        // Faces from `b` take `a`'s colour, except in a union.
        let colors: Vec<Option<Color>> = solids
            .iter()
            .map(|p| p.color)
            .chain(b.iter().map(|p| {
                if op == Op::Union {
                    p.color
                } else {
                    solids[0].color
                }
            }))
            .collect();
        let mut meshes: Vec<Mesh> = vec![Mesh::default(); colors.len()];
        for poly in result {
            let Some(m) = meshes.get_mut(poly.tag as usize) else {
                continue;
            };
            let v = poly.vertices();
            let base = m.p.len() as u32;
            m.p.extend_from_slice(v);
            for k in 1..v.len().saturating_sub(1) {
                m.t.push([base, base + k as u32, base + k as u32 + 1]);
            }
        }
        let mut out: Vec<Piece> = Vec::new();
        for (k, mesh) in meshes.into_iter().enumerate() {
            if mesh.t.is_empty() {
                continue;
            }
            // Pieces of one colour merge, so that they weld when shaded.
            match out.iter_mut().find(|p| p.color == colors[k]) {
                Some(p) => p.mesh.append(&mesh),
                None => out.push(Piece {
                    color: colors[k],
                    mesh,
                    solid: true,
                }),
            }
        }
        out.append(&mut open);
        out
    }

    /// A half-space as a closed solid large enough to cover `near`:
    /// `IfcHalfSpaceSolid` (and `IfcBoxedHalfSpace`, whose box only helps
    /// computing) clipped from a box around `near`, `IfcPolygonalBoundedHalfSpace`
    /// that intersected with the prism of its boundary.
    fn half_space(&mut self, id: u32, near: (V3, V3), depth: u32) -> Option<Mesh> {
        let (ty, p) = self.get(id)?;
        let (pty, pp) = self.get(p.first()?.id()?)?;
        if pty != b"IFCPLANE" {
            self.unsupported(pty);
            return None;
        }
        let plane = self.axis2(pp.first()?.id()?)?;
        let o = plane.c[3];
        let n = unit(plane.c[2])?;
        // TRUE: the material is on the side the normal points away from.
        let agree = p.get(1).and_then(Value::boolean).unwrap_or(true);
        let inside = if agree { math::scale(n, -1.0) } else { n };
        let centre = math::lerp(near.0, near.1, 0.5);
        let radius = math::len(sub(near.1, near.0)).max(1e-6) * 2.0;
        let mut solid = clipped_box(centre, radius, o, inside);
        if ty == b"IFCPOLYGONALBOUNDEDHALFSPACE" {
            let position = self.axis2(p.get(2)?.id()?)?;
            let boundary = self.curve(p.get(3)?.id()?, depth + 1)?;
            let local = position.inverse()?.point(centre);
            let reach = local[2].abs() + radius;
            let loop2: Vec<math::V2> = boundary.iter().map(|q| [q[0], q[1]]).collect();
            let mut prism = super::solids::prism(&[(loop2, Vec::new())], -reach, reach)?;
            prism.transform(&position);
            let a = to_polys(&prism, 0);
            let b = to_polys(&solid, 0);
            let r = csg::combine(Op::Intersection, a, b)?;
            solid = Mesh::default();
            for poly in r {
                let v = poly.vertices();
                let base = solid.p.len() as u32;
                solid.p.extend_from_slice(v);
                for k in 1..v.len().saturating_sub(1) {
                    solid.t.push([base, base + k as u32, base + k as u32 + 1]);
                }
            }
        }
        Some(solid)
    }
}

fn to_polys(m: &Mesh, tag: u32) -> Vec<Poly> {
    m.t.iter()
        .filter_map(|t| {
            Poly::triangle(
                *m.p.get(t[0] as usize)?,
                *m.p.get(t[1] as usize)?,
                *m.p.get(t[2] as usize)?,
                tag,
            )
        })
        .collect()
}

/// The part of the cube of half-size `r` around `c` on the side of the
/// plane through `o` that `inside` points to.
fn clipped_box(c: V3, r: f64, o: V3, inside: V3) -> Mesh {
    let corner = |i: usize| {
        [
            c[0] + if i & 1 == 0 { -r } else { r },
            c[1] + if i & 2 == 0 { -r } else { r },
            c[2] + if i & 4 == 0 { -r } else { r },
        ]
    };
    let faces = [
        [0, 2, 3, 1],
        [4, 5, 7, 6],
        [0, 1, 5, 4],
        [2, 6, 7, 3],
        [0, 4, 6, 2],
        [1, 3, 7, 5],
    ];
    let side = |p: V3| dot(inside, sub(p, o));
    let mut m = Mesh::default();
    let mut cut: Vec<V3> = Vec::new();
    for f in faces {
        let poly: Vec<V3> = f.iter().map(|&i| corner(i)).collect();
        let mut kept: Vec<V3> = Vec::new();
        for i in 0..poly.len() {
            let (a, b) = (poly[i], poly[(i + 1) % poly.len()]);
            let (sa, sb) = (side(a), side(b));
            if sa >= 0.0 {
                kept.push(a);
            }
            if (sa >= 0.0) != (sb >= 0.0) {
                let t = sa / (sa - sb);
                let q = math::lerp(a, b, t);
                kept.push(q);
                cut.push(q);
            }
        }
        if kept.len() >= 3 {
            let base = m.p.len() as u32;
            m.p.extend_from_slice(&kept);
            for k in 1..kept.len() - 1 {
                m.t.push([base, base + k as u32, base + k as u32 + 1]);
            }
        }
    }
    // The cap: the cut points around their centre, facing out of the
    // material.
    if cut.len() >= 3 {
        let mid = cut.iter().fold([0.0; 3], |s, p| math::add(s, *p));
        let mid = math::scale(mid, 1.0 / cut.len() as f64);
        let u = math::any_perpendicular(inside);
        let v = cross(inside, u);
        cut.sort_by(|a, b| {
            let (da, db) = (sub(*a, mid), sub(*b, mid));
            let aa = dot(da, v).atan2(dot(da, u));
            let ab = dot(db, v).atan2(dot(db, u));
            aa.partial_cmp(&ab).unwrap_or(std::cmp::Ordering::Equal)
        });
        cut.dedup_by(|a, b| math::len(sub(*a, *b)) < r * 1e-9);
        if cut.len() >= 3 {
            let base = m.p.len() as u32;
            m.p.extend_from_slice(&cut);
            // Counter-clockwise about `inside`: turned to face out.
            for k in 1..cut.len() - 1 {
                m.t.push([base, base + k as u32 + 1, base + k as u32]);
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_box_cut_in_half() {
        let m = clipped_box([0.0; 3], 1.0, [0.0, 0.0, 0.25], [0.0, 0.0, -1.0]);
        // z from -1 to 0.25 over a 2 x 2 base.
        assert!((m.volume6() / 6.0 - 2.0 * 2.0 * 1.25).abs() < 1e-9);
    }
}
