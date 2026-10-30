//! Representations and representation items: choosing a product's body,
//! mapped items, booleans and half-spaces, and the dispatch to each kind of
//! geometry.

use std::rc::Rc;

use super::csg::{self, Op, Poly};
use super::math::{self, V3, Xf, cross, dot, sub, unit};
use super::step::Value;
use super::{Color, MAX_DEPTH, Mesh, Piece, Reader, is};

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
                let declared = p.get(2).and_then(Value::boolean);
                let mut m = self.triangulated_face_set(&p)?;
                let closed = closed_or_found(&mut m, declared);
                vec![Piece {
                    color,
                    mesh: m,
                    solid: closed,
                }]
            }
            b"IFCPOLYGONALFACESET" => {
                let declared = p.get(1).and_then(Value::boolean);
                let mut m = self.polygonal_face_set(&p)?;
                let closed = closed_or_found(&mut m, declared);
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
                // Faces written the wrong way round are common in a shell.
                m.orient_consistently();
                for v in ids(p.get(1)) {
                    let mut void = self.shell(v, depth)?;
                    // Inward: a void's volume counts against the solid.
                    void.orient_consistently();
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

/// Whether a face set is a solid: as it says, and where it says nothing (the
/// attribute is optional, and Bonsai and others leave it out) as its edges
/// show, each shared by two faces. A solid has its faces turned outward.
fn closed_or_found(m: &mut Mesh, declared: Option<bool>) -> bool {
    let closed = declared.unwrap_or_else(|| m.is_closed());
    if closed {
        m.orient_consistently();
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cube(lo: f64, hi: f64) -> Mesh {
        let p = |x: f64, y: f64, z: f64| [x, y, z];
        Mesh {
            p: vec![
                p(lo, lo, lo),
                p(hi, lo, lo),
                p(hi, hi, lo),
                p(lo, hi, lo),
                p(lo, lo, hi),
                p(hi, lo, hi),
                p(hi, hi, hi),
                p(lo, hi, hi),
            ],
            // Outward.
            t: vec![
                [0, 2, 1],
                [0, 3, 2],
                [4, 5, 6],
                [4, 6, 7],
                [0, 1, 5],
                [0, 5, 4],
                [1, 2, 6],
                [1, 6, 5],
                [2, 3, 7],
                [2, 7, 6],
                [3, 0, 4],
                [3, 4, 7],
            ],
        }
    }

    #[test]
    fn a_shell_with_faces_the_wrong_way_round_is_turned_outward() {
        let mut m = cube(1.0, 3.0);
        assert!((m.volume6() / 6.0 - 8.0).abs() < 1e-9);
        // The bottom face written the other way: the volume is wrong, and
        // turning all of it does not help.
        m.t[0].swap(1, 2);
        m.t[1].swap(1, 2);
        m.orient_outward();
        assert!((m.volume6() / 6.0 - 8.0).abs() > 1.0);
        m.orient_consistently();
        assert!((m.volume6() / 6.0 - 8.0).abs() < 1e-9);
        // A closed piece written inside out, beside one that is not.
        let mut two = cube(0.0, 1.0);
        let mut inside_out = cube(5.0, 6.0);
        for t in &mut inside_out.t {
            t.swap(1, 2);
        }
        two.append(&inside_out);
        two.orient_consistently();
        assert!((two.volume6() / 6.0 - 2.0).abs() < 1e-9);
    }

    #[test]
    fn a_surface_that_is_not_closed_keeps_its_first_triangle_s_side() {
        let mut m = Mesh {
            p: vec![[0.0; 3], [1.0, 0.0, 0.0], [1.0, 1.0, 0.0], [0.0, 1.0, 0.0]],
            t: vec![[0, 1, 2], [0, 2, 3]],
        };
        // The second triangle turned: both are given the first one's.
        m.t[1].swap(1, 2);
        m.orient_consistently();
        assert_eq!(m.t, vec![[0, 1, 2], [0, 2, 3]]);
    }

    #[test]
    fn a_wall_of_a_shell_with_a_face_turned_is_cut_by_its_opening() {
        // 5 x 0.25 x 3.3 from z 0.2, with a window opening 2.2 wide from z 1.7
        // to 3.2, both shells with their faces written as a sloppy exporter
        // does, not all outward.
        let src = "ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n\
#1=IFCWALL('a',$,'w',$,$,#93,#7,$,$);\n\
#6=IFCSHAPEREPRESENTATION(#100,'Body','BRep',(#8));\n#7=IFCPRODUCTDEFINITIONSHAPE($,$,(#6));\n\
#8=IFCFACETEDBREP(#9);\n#9=IFCCLOSEDSHELL((#18,#21,#24,#27,#30,#33));\n\
#10=IFCCARTESIANPOINT((0.,0.,0.2));\n#11=IFCCARTESIANPOINT((5.,0.,0.2));\n#12=IFCCARTESIANPOINT((5.,0.25,0.2));\n#13=IFCCARTESIANPOINT((0.,0.25,0.2));\n\
#14=IFCCARTESIANPOINT((0.,0.,3.5));\n#15=IFCCARTESIANPOINT((5.,0.,3.5));\n#16=IFCCARTESIANPOINT((5.,0.25,3.5));\n#17=IFCCARTESIANPOINT((0.,0.25,3.5));\n\
#18=IFCFACE((#19));\n#19=IFCFACEOUTERBOUND(#20,.T.);\n#20=IFCPOLYLOOP((#10,#11,#12,#13));\n\
#21=IFCFACE((#22));\n#22=IFCFACEOUTERBOUND(#23,.T.);\n#23=IFCPOLYLOOP((#14,#15,#16,#17));\n\
#24=IFCFACE((#25));\n#25=IFCFACEOUTERBOUND(#26,.T.);\n#26=IFCPOLYLOOP((#10,#11,#15,#14));\n\
#27=IFCFACE((#28));\n#28=IFCFACEOUTERBOUND(#29,.T.);\n#29=IFCPOLYLOOP((#11,#12,#16,#15));\n\
#30=IFCFACE((#31));\n#31=IFCFACEOUTERBOUND(#32,.T.);\n#32=IFCPOLYLOOP((#12,#13,#17,#16));\n\
#33=IFCFACE((#34));\n#34=IFCFACEOUTERBOUND(#35,.T.);\n#35=IFCPOLYLOOP((#13,#10,#14,#17));\n\
#39=IFCOPENINGELEMENT('b',$,$,$,$,#93,#41,$,$);\n#40=IFCSHAPEREPRESENTATION(#100,'Body','BRep',(#42));\n#41=IFCPRODUCTDEFINITIONSHAPE($,$,(#40));\n\
#42=IFCFACETEDBREP(#43);\n#43=IFCCLOSEDSHELL((#52,#55,#58,#61,#64,#67));\n\
#44=IFCCARTESIANPOINT((0.3,0.,1.7));\n#45=IFCCARTESIANPOINT((2.5,0.,1.7));\n#46=IFCCARTESIANPOINT((2.5,0.25,1.7));\n#47=IFCCARTESIANPOINT((0.3,0.25,1.7));\n\
#48=IFCCARTESIANPOINT((0.3,0.,3.2));\n#49=IFCCARTESIANPOINT((2.5,0.,3.2));\n#50=IFCCARTESIANPOINT((2.5,0.25,3.2));\n#51=IFCCARTESIANPOINT((0.3,0.25,3.2));\n\
#52=IFCFACE((#53));\n#53=IFCFACEOUTERBOUND(#54,.T.);\n#54=IFCPOLYLOOP((#44,#45,#46,#47));\n\
#55=IFCFACE((#56));\n#56=IFCFACEOUTERBOUND(#57,.T.);\n#57=IFCPOLYLOOP((#48,#49,#50,#51));\n\
#58=IFCFACE((#59));\n#59=IFCFACEOUTERBOUND(#60,.T.);\n#60=IFCPOLYLOOP((#44,#45,#49,#48));\n\
#61=IFCFACE((#62));\n#62=IFCFACEOUTERBOUND(#63,.T.);\n#63=IFCPOLYLOOP((#45,#46,#50,#49));\n\
#64=IFCFACE((#65));\n#65=IFCFACEOUTERBOUND(#66,.T.);\n#66=IFCPOLYLOOP((#46,#47,#51,#50));\n\
#67=IFCFACE((#68));\n#68=IFCFACEOUTERBOUND(#69,.T.);\n#69=IFCPOLYLOOP((#47,#44,#48,#51));\n\
#70=IFCRELVOIDSELEMENT('c',$,$,$,#1,#39);\n\
#79=IFCAXIS2PLACEMENT3D(#80,#81,#82);\n#80=IFCCARTESIANPOINT((0.,0.,0.));\n#81=IFCDIRECTION((0.,0.,1.));\n#82=IFCDIRECTION((1.,0.,0.));\n\
#93=IFCLOCALPLACEMENT($,#79);\n#98=IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.);\n#99=IFCUNITASSIGNMENT((#98));\n\
#100=IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,0.00001,#79,$);\n#71=IFCPROJECT('p',$,$,$,$,$,$,(#100),#99);\n\
ENDSEC;\nEND-ISO-10303-21;\n";
        let scene = crate::ifc::read(src.as_bytes(), &crate::ifc::Limits::default()).unwrap();
        let (lo, hi) = {
            let b = scene.bounds.unwrap();
            let o = scene.origin;
            (
                [0, 1, 2].map(|k| o[k] + f64::from(b[0][k])),
                [0, 1, 2].map(|k| o[k] + f64::from(b[1][k])),
            )
        };
        // The wall still reaches its foot (0.2) and head (3.5).
        assert!(
            (lo[2] - 0.2).abs() < 1e-4 && (hi[2] - 3.5).abs() < 1e-4,
            "{lo:?} {hi:?}"
        );
        assert_eq!(scene.warnings.booleans_skipped, 0);
    }

    #[test]
    fn an_opening_that_does_not_say_it_is_closed_is_cut_when_its_edges_show_it_is() {
        // A 5 x 0.25 x 3 wall with a window hole 1 x 0.5 x 1 through it, the
        // hole a polygonal face set whose Closed attribute is left out.
        let src = "ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n\
#1=IFCWALL('a',$,'w',$,$,#93,#7,$,$);\n#7=IFCPRODUCTDEFINITIONSHAPE($,$,(#6));\n\
#6=IFCSHAPEREPRESENTATION(#100,'Body','SweptSolid',(#8));\n\
#8=IFCEXTRUDEDAREASOLID(#9,#79,#81,3.);\n#9=IFCRECTANGLEPROFILEDEF(.AREA.,$,#10,5.,0.25);\n\
#10=IFCAXIS2PLACEMENT2D(#11,$);\n#11=IFCCARTESIANPOINT((2.5,0.125));\n\
#39=IFCOPENINGELEMENT('b',$,$,$,$,#93,#41,$,$);\n#41=IFCPRODUCTDEFINITIONSHAPE($,$,(#40));\n\
#40=IFCSHAPEREPRESENTATION(#100,'Body','Tessellation',(#42));\n\
#42=IFCPOLYGONALFACESET(#43,$,(#51,#52,#53,#54,#55,#56),$);\n\
#43=IFCCARTESIANPOINTLIST3D(((1.,-0.1,1.),(2.,-0.1,1.),(2.,0.4,1.),(1.,0.4,1.),(1.,-0.1,2.),(2.,-0.1,2.),(2.,0.4,2.),(1.,0.4,2.)));\n\
#51=IFCINDEXEDPOLYGONALFACE((1,4,3,2));\n#52=IFCINDEXEDPOLYGONALFACE((5,6,7,8));\n\
#53=IFCINDEXEDPOLYGONALFACE((1,2,6,5));\n#54=IFCINDEXEDPOLYGONALFACE((2,3,7,6));\n\
#55=IFCINDEXEDPOLYGONALFACE((3,4,8,7));\n#56=IFCINDEXEDPOLYGONALFACE((4,1,5,8));\n\
#70=IFCRELVOIDSELEMENT('c',$,$,$,#1,#39);\n\
#79=IFCAXIS2PLACEMENT3D(#80,#81,#82);\n#80=IFCCARTESIANPOINT((0.,0.,0.));\n#81=IFCDIRECTION((0.,0.,1.));\n#82=IFCDIRECTION((1.,0.,0.));\n\
#93=IFCLOCALPLACEMENT($,#79);\n#98=IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.);\n#99=IFCUNITASSIGNMENT((#98));\n\
#100=IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,0.00001,#79,$);\n#71=IFCPROJECT('p',$,$,$,$,$,$,(#100),#99);\n\
ENDSEC;\nEND-ISO-10303-21;\n";
        let scene = crate::ifc::read(src.as_bytes(), &crate::ifc::Limits::default()).unwrap();
        assert_eq!(scene.warnings.booleans_skipped, 0);
        // A box is 12 triangles: with the hole through it, more.
        assert!(scene.triangles() > 12, "{}", scene.triangles());
    }

    #[test]
    fn a_box_cut_in_half() {
        let m = clipped_box([0.0; 3], 1.0, [0.0, 0.0, 0.25], [0.0, 0.0, -1.0]);
        // z from -1 to 0.25 over a 2 x 2 base.
        assert!((m.volume6() / 6.0 - 2.0 * 2.0 * 1.25).abs() < 1e-9);
    }
}
