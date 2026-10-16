//! Solids and surfaces: swept areas (extruded, revolved, along a
//! directrix), swept disks, tessellated face sets, face-based shells and
//! B-reps, bounded planes and CSG primitives.

use std::f64::consts::TAU;

use super::curves::{segments, SEGMENTS_PER_TURN};
use super::math::{add, any_perpendicular, cross, dot, len, scale, sub, unit, Xf, V2, V3};
use super::profiles::Profile;
use super::step::Value;
use super::triangulate::{triangulate, triangulate_3d};
use super::{is, Mesh, Reader};

/// Most triangles one swept or sampled item may have before it is made.
const MAX_ITEM_TRIANGLES: usize = 4_000_000;

/// Rotates `p` about the line through `a` along the unit `d` (right-handed).
fn rotate(p: V3, a: V3, d: V3, t: f64) -> V3 {
    let v = sub(p, a);
    let (c, s) = (t.cos(), t.sin());
    let r = add(
        add(scale(v, c), scale(cross(d, v), s)),
        scale(d, dot(d, v) * (1.0 - c)),
    );
    add(a, r)
}

/// Loops of an area in order: the outer one, then the holes.
fn loops(area: &(Vec<V2>, Vec<Vec<V2>>)) -> impl Iterator<Item = &Vec<V2>> {
    std::iter::once(&area.0).chain(area.1.iter())
}

/// Triangles of an area's cap, as indices into its loops' points in order.
fn cap(area: &(Vec<V2>, Vec<Vec<V2>>)) -> Vec<[u32; 3]> {
    let pts: Vec<V2> = loops(area).flatten().copied().collect();
    let mut next = 0u32;
    let mut idx = |n: usize| {
        let r: Vec<u32> = (next..next + n as u32).collect();
        next += n as u32;
        r
    };
    let outer = idx(area.0.len());
    let holes: Vec<Vec<u32>> = area.1.iter().map(|h| idx(h.len())).collect();
    triangulate(&pts, &outer, &holes)
}

/// Joins ring `a` to ring `b` (each the area's loop points in order) with
/// side quads, plus caps when asked.
fn sweep_area(m: &mut Mesh, area: &(Vec<V2>, Vec<Vec<V2>>), rings: &[Vec<V3>], caps: bool) {
    let n: usize = loops(area).map(Vec::len).sum();
    let base = m.p.len() as u32;
    for r in rings {
        m.p.extend_from_slice(r);
    }
    for k in 0..rings.len().saturating_sub(1) {
        let (r0, r1) = (base + (k * n) as u32, base + ((k + 1) * n) as u32);
        let mut start = 0u32;
        for l in loops(area) {
            let len = l.len() as u32;
            for i in 0..len {
                let (a, b) = (start + i, start + (i + 1) % len);
                m.t.push([r0 + a, r0 + b, r1 + b]);
                m.t.push([r0 + a, r1 + b, r1 + a]);
            }
            start += len;
        }
    }
    if caps && rings.len() >= 2 {
        let tris = cap(area);
        let last = base + ((rings.len() - 1) * n) as u32;
        for t in &tris {
            m.t.push([base + t[0], base + t[2], base + t[1]]);
            m.t.push([last + t[0], last + t[1], last + t[2]]);
        }
    }
}

/// Open curves swept: a ribbon between consecutive rings.
fn sweep_open(m: &mut Mesh, rings: &[Vec<V3>]) {
    let Some(n) = rings.first().map(Vec::len) else {
        return;
    };
    let base = m.p.len() as u32;
    for r in rings {
        m.p.extend_from_slice(r);
    }
    for k in 0..rings.len().saturating_sub(1) {
        let (r0, r1) = (base + (k * n) as u32, base + ((k + 1) * n) as u32);
        for i in 0..n.saturating_sub(1) as u32 {
            m.t.push([r0 + i, r0 + i + 1, r1 + i + 1]);
            m.t.push([r0 + i, r1 + i + 1, r1 + i]);
        }
    }
}

fn lift(l: &[V2]) -> Vec<V3> {
    l.iter().map(|p| [p[0], p[1], 0.0]).collect()
}

/// The areas of `profile` extruded by `v`; `end` is the shape at the far
/// end when it matches the start one loop for loop.
pub fn extrude(profile: &Profile, v: V3, end: Option<&Profile>) -> Mesh {
    let mut m = Mesh::default();
    for (i, area) in profile.areas.iter().enumerate() {
        let start: Vec<V3> = loops(area).flat_map(|l| lift(l)).collect();
        let far = end
            .and_then(|e| e.areas.get(i))
            .filter(|e| {
                e.1.len() == area.1.len() && loops(e).map(Vec::len).eq(loops(area).map(Vec::len))
            })
            .unwrap_or(area);
        let top: Vec<V3> = loops(far)
            .flat_map(|l| lift(l))
            .map(|p| add(p, v))
            .collect();
        sweep_area(&mut m, area, &[start, top], true);
    }
    for c in &profile.open {
        let a = lift(c);
        let b: Vec<V3> = a.iter().map(|p| add(*p, v)).collect();
        sweep_open(&mut m, &[a, b]);
    }
    m
}

/// Closed areas extruded along z from `z0` to `z1`.
pub fn prism(areas: &[(Vec<V2>, Vec<Vec<V2>>)], z0: f64, z1: f64) -> Option<Mesh> {
    let mut profile = Profile::default();
    for (o, h) in areas {
        let mut outer = o.clone();
        while outer.len() > 1 && outer.first() == outer.last() {
            outer.pop();
        }
        if outer.len() < 3 {
            continue;
        }
        let a: f64 = (0..outer.len())
            .map(|i| {
                outer[i][0] * outer[(i + 1) % outer.len()][1]
                    - outer[(i + 1) % outer.len()][0] * outer[i][1]
            })
            .sum();
        if a < 0.0 {
            outer.reverse();
        }
        profile.areas.push((outer, h.clone()));
    }
    if profile.areas.is_empty() {
        return None;
    }
    let mut m = extrude(&profile, [0.0, 0.0, z1 - z0], None);
    m.transform(&Xf::translation([0.0, 0.0, z0]));
    m.orient_outward();
    Some(m)
}

impl<'a> Reader<'a> {
    pub(super) fn budget(&self, n: usize) -> Option<()> {
        (n <= MAX_ITEM_TRIANGLES && n <= self.work).then_some(())
    }

    /// `IfcExtrudedAreaSolid` (and `Tapered`); whether it is closed.
    pub fn extruded(&mut self, p: &[Value], tapered: bool, depth: u32) -> Option<(Mesh, bool)> {
        let profile = self.profile(p.first()?.id()?, depth + 1)?;
        let pos = self.axis2_or_identity(p.get(1))?;
        let dir = self.direction(p.get(2)?.id()?)?;
        let d = p.get(3)?.num()?;
        if !(d.is_finite() && d != 0.0) || dir[2].abs() < 1e-9 {
            return None;
        }
        let end = if tapered {
            p.get(4)
                .and_then(Value::id)
                .and_then(|e| self.profile(e, depth + 1))
        } else {
            None
        };
        let points: usize = profile
            .areas
            .iter()
            .flat_map(loops)
            .map(Vec::len)
            .sum::<usize>()
            + profile.open.iter().map(Vec::len).sum::<usize>();
        self.budget(points.saturating_mul(4))?;
        let mut m = extrude(&profile, scale(dir, d), end.as_ref());
        m.transform(&pos);
        let closed = profile.open.is_empty();
        if closed {
            m.orient_outward();
        }
        Some((m, closed))
    }

    /// `IfcRevolvedAreaSolid` (a tapered one revolves its start profile
    /// into its end one).
    pub fn revolved(&mut self, p: &[Value], depth: u32) -> Option<Mesh> {
        let profile = self.profile(p.first()?.id()?, depth + 1)?;
        let pos = self.axis2_or_identity(p.get(1))?;
        let ap = self.f.params(p.get(2)?.id()?)?;
        let a = self.point(ap.first()?.id()?)?;
        let d = ap
            .get(1)
            .and_then(Value::id)
            .and_then(|d| self.direction(d))
            .unwrap_or([0.0, 0.0, 1.0]);
        let angle = p.get(3)?.num()? * self.angle;
        if !angle.is_finite() || angle.abs() < 1e-9 {
            return None;
        }
        let end = p
            .get(4)
            .and_then(Value::id)
            .and_then(|e| self.profile(e, depth + 1));
        let full = angle.abs() >= TAU - 1e-6;
        let angle = angle.clamp(-TAU, TAU);
        let n = segments(angle);
        let points: usize = profile
            .areas
            .iter()
            .flat_map(loops)
            .map(Vec::len)
            .sum::<usize>()
            + profile.open.iter().map(Vec::len).sum::<usize>();
        self.budget(points.saturating_mul(2).saturating_mul(n.saturating_add(1)))?;
        let mut m = Mesh::default();
        let ring_at = |shape: &[V2], far: &[V2], k: usize| -> Vec<V3> {
            let f = k as f64 / n as f64;
            shape
                .iter()
                .zip(far)
                .map(|(s, e)| {
                    rotate(
                        [s[0] + (e[0] - s[0]) * f, s[1] + (e[1] - s[1]) * f, 0.0],
                        a,
                        d,
                        angle * f,
                    )
                })
                .collect()
        };
        for (i, area) in profile.areas.iter().enumerate() {
            let start: Vec<V2> = loops(area).flatten().copied().collect();
            let far: Vec<V2> = end
                .as_ref()
                .and_then(|e| e.areas.get(i))
                .map(|e| loops(e).flatten().copied().collect::<Vec<V2>>())
                .filter(|f| f.len() == start.len())
                .unwrap_or_else(|| start.clone());
            let mut rings: Vec<Vec<V3>> = (0..=n).map(|k| ring_at(&start, &far, k)).collect();
            if full {
                // The last ring is the first: closed round.
                rings[n] = rings[0].clone();
            }
            sweep_area(&mut m, area, &rings, !full);
        }
        for c in &profile.open {
            let rings: Vec<Vec<V3>> = (0..=n).map(|k| ring_at(c, c, k)).collect();
            sweep_open(&mut m, &rings);
        }
        m.transform(&pos);
        m.orient_outward();
        Some(m)
    }

    /// `IfcSweptDiskSolid`: a circle (with a hole for `InnerRadius`) along
    /// the directrix, its frame carried without twist.
    pub fn swept_disk(&mut self, p: &[Value], depth: u32) -> Option<Mesh> {
        let path = self.directrix(p.first()?.id()?, p.get(3), p.get(4), depth)?;
        let r = p.get(1)?.num().filter(|r| *r > 0.0 && r.is_finite())?;
        let inner = p
            .get(2)
            .and_then(Value::num)
            .filter(|ri| *ri > 0.0 && *ri < r);
        let n = SEGMENTS_PER_TURN as usize / 2;
        let circle = |r: f64| -> Vec<V2> {
            (0..n)
                .map(|k| {
                    [
                        r * (TAU * k as f64 / n as f64).cos(),
                        r * (TAU * k as f64 / n as f64).sin(),
                    ]
                })
                .collect()
        };
        let mut hole = inner.map(circle).map(|mut h| {
            h.reverse();
            h
        });
        let profile = Profile {
            areas: vec![(circle(r), hole.take().into_iter().collect())],
            open: Vec::new(),
        };
        self.sweep(&profile, &path, Frames::Transported)
    }

    /// `IfcSurfaceCurveSweptAreaSolid` (the profile's x along the
    /// reference plane's normal) and `IfcFixedReferenceSweptAreaSolid` (x
    /// along the fixed direction).
    pub fn swept_area(&mut self, ty: &[u8], p: &[Value], depth: u32) -> Option<Mesh> {
        let profile = self.profile(p.first()?.id()?, depth + 1)?;
        let pos = self.axis2_or_identity(p.get(1))?;
        let path = self.directrix(p.get(2)?.id()?, p.get(3), p.get(4), depth)?;
        let frames = match ty {
            b"IFCSURFACECURVESWEPTAREASOLID" => {
                let s = p.get(5)?.id()?;
                let (sty, sp) = self.get(s)?;
                if sty == b"IFCPLANE" {
                    Frames::Fixed(self.axis2(sp.first()?.id()?)?.c[2])
                } else {
                    self.unsupported(sty);
                    Frames::Transported
                }
            }
            b"IFCFIXEDREFERENCESWEPTAREASOLID" => Frames::Fixed(self.direction(p.get(5)?.id()?)?),
            _ => Frames::Transported,
        };
        let mut m = self.sweep(&profile, &path, frames)?;
        m.transform(&pos);
        Some(m)
    }

    /// `profile` along `path`, mitred at its corners.
    fn sweep(&mut self, profile: &Profile, path: &[V3], frames: Frames) -> Option<Mesh> {
        let mut pts: Vec<V3> = Vec::with_capacity(path.len());
        for &q in path {
            if pts
                .last()
                .is_none_or(|l| len(sub(q, *l)) > 1e-9 * (1.0 + len(q)))
            {
                pts.push(q);
            }
        }
        if pts.len() < 2 {
            return None;
        }
        let ring_len: usize = profile
            .areas
            .iter()
            .flat_map(loops)
            .map(Vec::len)
            .sum::<usize>()
            + profile.open.iter().map(Vec::len).sum::<usize>();
        self.budget(ring_len.saturating_mul(2).saturating_mul(pts.len()))?;
        let dirs: Vec<V3> = pts
            .windows(2)
            .map(|w| unit(sub(w[1], w[0])))
            .collect::<Option<_>>()?;
        // The profile's x axis on each segment.
        let mut xs: Vec<V3> = Vec::with_capacity(dirs.len());
        for (i, &s) in dirs.iter().enumerate() {
            let x = match frames {
                Frames::Fixed(f) => unit(sub(f, scale(s, dot(f, s)))),
                Frames::Transported => None,
            };
            let x = x.unwrap_or_else(|| match xs.last() {
                Some(&prev) => {
                    let t0 = dirs[i - 1];
                    let axis = cross(t0, s);
                    let carried = match unit(axis) {
                        Some(ax) => rotate(prev, [0.0; 3], ax, dot(t0, s).clamp(-1.0, 1.0).acos()),
                        None => prev,
                    };
                    unit(sub(carried, scale(s, dot(carried, s))))
                        .unwrap_or_else(|| any_perpendicular(s))
                }
                None => any_perpendicular(s),
            });
            xs.push(x);
        }
        let ring = |shape: &[V2], i: usize| -> Vec<V3> {
            let seg = i.min(dirs.len() - 1);
            // At a corner, the incoming segment's frame, pushed along it
            // onto the plane halfway between the two segments.
            let seg = if i > 0 && i < pts.len() - 1 {
                i - 1
            } else {
                seg
            };
            let (s, x) = (dirs[seg], xs[seg]);
            let y = cross(s, x);
            let miter = (i > 0 && i < pts.len() - 1)
                .then(|| unit(add(dirs[i - 1], dirs[i])))
                .flatten()
                .filter(|m| dot(s, *m) > 0.05);
            shape
                .iter()
                .map(|q| {
                    let w = add(pts[i], add(scale(x, q[0]), scale(y, q[1])));
                    match miter {
                        Some(m) => add(w, scale(s, dot(sub(pts[i], w), m) / dot(s, m))),
                        None => w,
                    }
                })
                .collect()
        };
        let mut m = Mesh::default();
        for area in &profile.areas {
            let shape: Vec<V2> = loops(area).flatten().copied().collect();
            let rings: Vec<Vec<V3>> = (0..pts.len()).map(|i| ring(&shape, i)).collect();
            sweep_area(&mut m, area, &rings, true);
        }
        for c in &profile.open {
            let rings: Vec<Vec<V3>> = (0..pts.len()).map(|i| ring(c, i)).collect();
            sweep_open(&mut m, &rings);
        }
        m.orient_outward();
        Some(m)
    }

    /// `IfcTriangulatedFaceSet`: one-based indices, through `PnIndex` when
    /// given.
    pub fn triangulated_face_set(&mut self, p: &[Value]) -> Option<Mesh> {
        let coords = self.point_list(p.first()?.id()?)?;
        let pn = self.pn_index(p.get(4))?;
        let mut m = Mesh {
            p: coords,
            t: Vec::new(),
        };
        let tris = p.get(3)?.list()?;
        self.budget(tris.len())?;
        for t in tris {
            let l = t.list()?;
            if l.len() != 3 {
                continue;
            }
            let i = [
                index(&l[0], &pn, m.p.len())?,
                index(&l[1], &pn, m.p.len())?,
                index(&l[2], &pn, m.p.len())?,
            ];
            m.t.push(i);
        }
        Some(m)
    }

    /// `PnIndex`. Files written to the IFC4 drafts have a list of index
    /// triples (normal indices) in its place, which is ignored.
    fn pn_index(&self, v: Option<&Value>) -> Option<Option<Vec<usize>>> {
        match v.and_then(Value::list) {
            Some(l) if l.first().is_some_and(|i| i.int().is_some()) => Some(Some(
                l.iter()
                    .map(|i| usize::try_from(i.int()?).ok())
                    .collect::<Option<_>>()?,
            )),
            _ => Some(None),
        }
    }

    /// `IfcPolygonalFaceSet`.
    pub fn polygonal_face_set(&mut self, p: &[Value]) -> Option<Mesh> {
        let coords = self.point_list(p.first()?.id()?)?;
        let pn = self.pn_index(p.get(3))?;
        let n = coords.len();
        let mut m = Mesh {
            p: coords,
            t: Vec::new(),
        };
        let faces = p.get(2)?.list()?;
        for f in faces.iter().filter_map(Value::id) {
            let (fty, fp) = self.get(f)?;
            let mut lps: Vec<Vec<u32>> = vec![fp
                .first()?
                .list()?
                .iter()
                .map(|i| index(i, &pn, n))
                .collect::<Option<_>>()?];
            if fty == b"IFCINDEXEDPOLYGONALFACEWITHVOIDS" {
                for h in fp.get(1)?.list()? {
                    lps.push(
                        h.list()?
                            .iter()
                            .map(|i| index(i, &pn, n))
                            .collect::<Option<_>>()?,
                    );
                }
            }
            let tris = triangulate_3d(&m.p, &lps);
            self.spend(tris.len())?;
            m.t.extend(tris);
        }
        Some(m)
    }

    /// The faces of an `IfcClosedShell`, `IfcOpenShell` or
    /// `IfcConnectedFaceSet`.
    pub fn shell(&mut self, id: u32, depth: u32) -> Option<Mesh> {
        let (ty, p) = self.get(id)?;
        if !is(
            ty,
            &[b"IFCCLOSEDSHELL", b"IFCOPENSHELL", b"IFCCONNECTEDFACESET"],
        ) {
            self.unsupported(ty);
            return Some(Mesh::default());
        }
        let mut m = Mesh::default();
        // Points shared by faces are made once.
        let mut points: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        for f in p.first()?.list()?.iter().filter_map(Value::id) {
            let Some((fty, fp)) = self.get(f) else {
                self.warnings.invalid = self.warnings.invalid.saturating_add(1);
                continue;
            };
            if fty == b"IFCADVANCEDFACE" || fty == b"IFCFACESURFACE" {
                if let Some(face) = self.surface_face(&fp, depth) {
                    self.spend(face.t.len())?;
                    m.append(&face);
                    continue;
                }
            }
            let Some(bounds) = fp.first().and_then(Value::list) else {
                continue;
            };
            let mut lps: Vec<Vec<u32>> = Vec::new();
            for b in bounds.iter().filter_map(Value::id) {
                let Some((bty, bp)) = self.get(b) else {
                    continue;
                };
                let Some(lp) = bp.first().and_then(Value::id) else {
                    continue;
                };
                let forward = bp.get(1).and_then(Value::boolean).unwrap_or(true);
                let Some((lty, lpp)) = self.get(lp) else {
                    continue;
                };
                let mut ring: Vec<u32> = match lty {
                    b"IFCPOLYLOOP" => {
                        let Some(list) = lpp.first().and_then(Value::list) else {
                            continue;
                        };
                        let mut ring = Vec::with_capacity(list.len());
                        for pid in list.iter().filter_map(Value::id) {
                            let i = match points.get(&pid) {
                                Some(&i) => i,
                                None => {
                                    let Some(q) = self.point(pid) else { continue };
                                    m.p.push(q);
                                    let i = (m.p.len() - 1) as u32;
                                    points.insert(pid, i);
                                    i
                                }
                            };
                            ring.push(i);
                        }
                        ring
                    }
                    b"IFCEDGELOOP" => {
                        let Some(pts) = self.edge_loop(&lpp, depth) else {
                            self.warnings.invalid = self.warnings.invalid.saturating_add(1);
                            continue;
                        };
                        let base = m.p.len() as u32;
                        m.p.extend_from_slice(&pts);
                        (base..base + pts.len() as u32).collect()
                    }
                    _ => continue,
                };
                if !forward {
                    ring.reverse();
                }
                if bty == b"IFCFACEOUTERBOUND" {
                    lps.insert(0, ring);
                } else {
                    lps.push(ring);
                }
            }
            if lps.is_empty() {
                continue;
            }
            let tris = triangulate_3d(&m.p, &lps);
            self.spend(tris.len())?;
            m.t.extend(tris);
        }
        Some(m)
    }

    /// The points of an `IfcEdgeLoop`, each edge's curve sampled between
    /// its vertices.
    pub(super) fn edge_loop(&mut self, p: &[Value], depth: u32) -> Option<Vec<V3>> {
        self.edge_loop_checked(p, depth).map(|(pts, _)| pts)
    }

    /// [`edge_loop`](Self::edge_loop), and whether each edge starts where
    /// the one before it ends and the last ends where the first starts
    /// (some writers flag the edges of a loop the wrong way round).
    pub(super) fn edge_loop_checked(&mut self, p: &[Value], depth: u32) -> Option<(Vec<V3>, bool)> {
        let mut out: Vec<V3> = Vec::new();
        let mut connected = true;
        for oe in p.first()?.list()?.iter().filter_map(Value::id) {
            let (oty, op) = self.get(oe)?;
            let (edge, forward) = if oty == b"IFCORIENTEDEDGE" {
                (
                    op.get(2)?.id()?,
                    op.get(3).and_then(Value::boolean).unwrap_or(true),
                )
            } else {
                (oe, true)
            };
            let ep = self.f.params(edge)?;
            let vertex = |r: &Self, v: Option<&Value>| -> Option<V3> {
                r.point(r.f.params(v?.id()?)?.first()?.id()?)
            };
            let (a, b) = (vertex(self, ep.first())?, vertex(self, ep.get(1))?);
            let same = ep.get(3).and_then(Value::boolean).unwrap_or(true);
            let mut pts = match ep.get(2).and_then(Value::id) {
                Some(g) if !matches!(self.get(g).map(|x| x.0), Some(b"IFCLINE")) => {
                    match self.curve(g, depth + 1) {
                        Some(c) => between(&c, a, b, same),
                        None => vec![a, b],
                    }
                }
                _ => vec![a, b],
            };
            if !forward {
                pts.reverse();
            }
            let tol = 1e-9 * (1.0 + len(pts[0]));
            let skip = out.last().is_some_and(|l| len(sub(*l, pts[0])) <= tol);
            if let Some(l) = out.last() {
                connected &= len(sub(*l, pts[0])) <= 1e-6 * (1.0 + len(pts[0]));
            }
            // Points are charged as they are made: a loop that lists the
            // same long edge many times is not free.
            self.charge(pts.len() / 8 + 1)?;
            out.extend(pts.into_iter().skip(skip as usize));
        }
        if let (Some(first), Some(last)) = (out.first(), out.last()) {
            connected &= len(sub(*first, *last)) <= 1e-6 * (1.0 + len(*first));
        }
        while out.len() > 1 && len(sub(out[0], out[out.len() - 1])) <= 1e-9 * (1.0 + len(out[0])) {
            out.pop();
        }
        (out.len() >= 3).then_some((out, connected))
    }

    /// `IfcCurveBoundedPlane`: boundaries in the plane's (u, v).
    pub fn curve_bounded_plane(&mut self, p: &[Value], depth: u32) -> Option<Mesh> {
        let (sty, sp) = self.get(p.first()?.id()?)?;
        if sty != b"IFCPLANE" {
            self.unsupported(sty);
            return None;
        }
        let pos = self.axis2(sp.first()?.id()?)?;
        let outer = self.curve(p.get(1)?.id()?, depth + 1)?;
        let mut flat: Vec<V2> = outer.iter().map(|q| [q[0], q[1]]).collect();
        let outer_idx: Vec<u32> = (0..flat.len() as u32).collect();
        let mut holes = Vec::new();
        for h in p
            .get(2)
            .and_then(Value::list)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::id)
        {
            let Some(c) = self.curve(h, depth + 1) else {
                continue;
            };
            let base = flat.len() as u32;
            flat.extend(c.iter().map(|q| [q[0], q[1]]));
            holes.push((base..flat.len() as u32).collect::<Vec<u32>>());
        }
        let t = triangulate(&flat, &outer_idx, &holes);
        Some(Mesh {
            p: flat.iter().map(|q| pos.point([q[0], q[1], 0.0])).collect(),
            t,
        })
    }

    /// CSG primitives, in their `Position`.
    pub fn primitive(&mut self, ty: &[u8], p: &[Value]) -> Option<Mesh> {
        let pos = self.axis2(p.first()?.id()?)?;
        let num = |i: usize| {
            p.get(i)
                .and_then(Value::num)
                .filter(|v| *v > 0.0 && v.is_finite())
        };
        let mut m = match ty {
            b"IFCBLOCK" => {
                let (x, y, z) = (num(1)?, num(2)?, num(3)?);
                let profile = Profile {
                    areas: vec![(vec![[0.0, 0.0], [x, 0.0], [x, y], [0.0, y]], Vec::new())],
                    open: Vec::new(),
                };
                extrude(&profile, [0.0, 0.0, z], None)
            }
            b"IFCRECTANGULARPYRAMID" => {
                let (x, y, h) = (num(1)?, num(2)?, num(3)?);
                let apex = [x / 2.0, y / 2.0, h];
                let b = [[0.0, 0.0, 0.0], [x, 0.0, 0.0], [x, y, 0.0], [0.0, y, 0.0]];
                let mut m = Mesh {
                    p: b.to_vec(),
                    t: vec![[0, 2, 1], [0, 3, 2]],
                };
                m.p.push(apex);
                for k in 0..4u32 {
                    m.t.push([k, (k + 1) % 4, 4]);
                }
                m
            }
            b"IFCRIGHTCIRCULARCONE" | b"IFCRIGHTCIRCULARCYLINDER" => {
                let h = num(1)?;
                let r = num(2)?;
                let n = SEGMENTS_PER_TURN as usize;
                let ring: Vec<V2> = (0..n)
                    .map(|k| {
                        [
                            r * (TAU * k as f64 / n as f64).cos(),
                            r * (TAU * k as f64 / n as f64).sin(),
                        ]
                    })
                    .collect();
                if ty == b"IFCRIGHTCIRCULARCYLINDER" {
                    extrude(
                        &Profile {
                            areas: vec![(ring, Vec::new())],
                            open: Vec::new(),
                        },
                        [0.0, 0.0, h],
                        None,
                    )
                } else {
                    let mut m = Mesh {
                        p: ring.iter().map(|q| [q[0], q[1], 0.0]).collect(),
                        t: Vec::new(),
                    };
                    m.p.push([0.0, 0.0, h]);
                    m.p.push([0.0, 0.0, 0.0]);
                    let (apex, centre) = (n as u32, n as u32 + 1);
                    for k in 0..n as u32 {
                        let j = (k + 1) % n as u32;
                        m.t.push([k, j, apex]);
                        m.t.push([j, k, centre]);
                    }
                    m
                }
            }
            b"IFCSPHERE" => {
                let r = num(1)?;
                let (rings, segs) = (SEGMENTS_PER_TURN as usize / 2, SEGMENTS_PER_TURN as usize);
                let mut m = Mesh::default();
                for i in 0..=rings {
                    let phi = std::f64::consts::PI * i as f64 / rings as f64;
                    for j in 0..segs {
                        let th = TAU * j as f64 / segs as f64;
                        m.p.push([
                            r * phi.sin() * th.cos(),
                            r * phi.sin() * th.sin(),
                            r * phi.cos(),
                        ]);
                    }
                }
                for i in 0..rings as u32 {
                    for j in 0..segs as u32 {
                        let (a, b) = (i * segs as u32 + j, i * segs as u32 + (j + 1) % segs as u32);
                        let (c, d) = (a + segs as u32, b + segs as u32);
                        m.t.push([a, c, d]);
                        m.t.push([a, d, b]);
                    }
                }
                m
            }
            _ => return None,
        };
        m.transform(&pos);
        m.orient_outward();
        Some(m)
    }
}

/// How a sweep turns its profile.
#[derive(Clone, Copy)]
enum Frames {
    /// The profile's x axis as close to this direction as the tangent
    /// allows.
    Fixed(V3),
    /// Carried along without twist (rotation minimising).
    Transported,
}

/// A one-based index, through `pn` when given, checked against `n`.
fn index(v: &Value, pn: &Option<Vec<usize>>, n: usize) -> Option<u32> {
    let i = usize::try_from(v.int()?).ok()?.checked_sub(1)?;
    let i = match pn {
        Some(pn) => pn.get(i)?.checked_sub(1)?,
        None => i,
    };
    (i < n).then_some(i as u32)
}

/// The part of a sampled curve from the sample nearest `a` to the one
/// nearest `b`, forwards (or backwards when `!same`), round the end for a
/// closed curve; its ends replaced by `a` and `b`.
fn between(c: &[V3], a: V3, b: V3, same: bool) -> Vec<V3> {
    let near = |q: V3| {
        (0..c.len())
            .min_by(|&i, &j| {
                len(sub(c[i], q))
                    .partial_cmp(&len(sub(c[j], q)))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(0)
    };
    let closed = c.len() > 2 && len(sub(c[0], c[c.len() - 1])) <= 1e-9 * (1.0 + len(c[0]));
    let n = if closed { c.len() - 1 } else { c.len() };
    if n == 0 {
        return vec![a, b];
    }
    let (ia, ib) = (near(a) % n, near(b) % n);
    let mut out = vec![a];
    let step = |i: usize| if same { (i + 1) % n } else { (i + n - 1) % n };
    let mut i = ia;
    let mut guard = 0;
    while i != ib && guard <= n {
        i = step(i);
        if !closed && ((same && i == 0) || (!same && i == n - 1)) {
            break;
        }
        if i != ib {
            out.push(c[i]);
        }
        guard += 1;
    }
    out.push(b);
    // A closed edge (one vertex at both ends) goes all the way round.
    if ia == ib && closed && len(sub(a, b)) <= 1e-9 * (1.0 + len(a)) {
        out = std::iter::once(a)
            .chain((1..n).map(|k| c[if same { (ia + k) % n } else { (ia + n - k) % n }]))
            .chain(std::iter::once(b))
            .collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_extruded_square_with_a_hole() {
        let profile = Profile {
            areas: vec![(
                vec![[0.0, 0.0], [4.0, 0.0], [4.0, 4.0], [0.0, 4.0]],
                vec![vec![[1.0, 1.0], [1.0, 3.0], [3.0, 3.0], [3.0, 1.0]]],
            )],
            open: Vec::new(),
        };
        let m = extrude(&profile, [0.0, 0.0, 2.0], None);
        assert!((m.volume6() / 6.0 - 24.0).abs() < 1e-9);
        // Extruded slanted: the same volume (Cavalieri).
        let m = extrude(&profile, [1.0, 0.5, 2.0], None);
        assert!((m.volume6() / 6.0 - 24.0).abs() < 1e-9);
    }

    #[test]
    fn rotation_is_right_handed() {
        let q = rotate(
            [1.0, 0.0, 0.0],
            [0.0; 3],
            [0.0, 0.0, 1.0],
            std::f64::consts::FRAC_PI_2,
        );
        assert!(len(sub(q, [0.0, 1.0, 0.0])) < 1e-12);
    }

    #[test]
    fn a_sampled_circle_cut_between_two_points() {
        let n = 8;
        let c: Vec<V3> = (0..=n)
            .map(|k| {
                let t = TAU * (k % n) as f64 / n as f64;
                [t.cos(), t.sin(), 0.0]
            })
            .collect();
        let half = between(&c, [1.0, 0.0, 0.0], [-1.0, 0.0, 0.0], true);
        assert!(half.iter().all(|p| p[1] >= -1e-12));
        assert_eq!(half.len(), 5);
        let other = between(&c, [1.0, 0.0, 0.0], [-1.0, 0.0, 0.0], false);
        assert!(other.iter().all(|p| p[1] <= 1e-12));
    }
}
