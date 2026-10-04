//! Proxy graphics as plain entities (lines, polylines, texts, fills), drawn
//! where the custom entity is, by the rules of the entities beside it.
//!
//! The pieces start with the entity's own layer, colour, linetype and
//! lineweight; the stream's traits change them for the pieces after. As
//! the ODA converter resolves them when it writes a stream again for a DWG
//! (its own drawing code making graphics that draw the same), ByBlock is
//! the block the entity is in (colour 7 in model space), not the entity,
//! and ByLayer on layer 0 is layer 0's colour in model space, not the
//! entity's layer's. (Its R12 output, an anonymous block inserted with the
//! entity's properties, has both the other way.) Points go through the
//! transforms pushed, then lose their Z as every other entity's do.

use std::f64::consts::TAU;

use crate::cad::{
    ArcKind, Drawing as CadDrawing, Entity, EntityKind, Linetype, LwPolyline, Plane, Polyline,
    ProxyEllipse, ProxyGraphics, ProxyItem, ProxyMesh, ProxyShell, ProxyText, Ray, Text, Vec3,
    Vertex,
};

use super::curves;
use super::tessellate::expand_bulges;

/// What a stream item becomes.
pub(super) struct Piece {
    /// Drawn as a block's entity would be; for a fill, its properties.
    pub entity: Entity,
    /// Closed loops in world XY to fill, even-odd, instead of drawing
    /// `entity`.
    pub fill: Option<Vec<Vec<[f64; 2]>>>,
}

/// A 4x4 matrix, row after row, applied to points as columns.
type Matrix = [f64; 16];

const IDENTITY: Matrix = [
    1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
];

fn mul(a: &Matrix, b: &Matrix) -> Matrix {
    let mut m = [0.0; 16];
    for r in 0..4 {
        for c in 0..4 {
            m[r * 4 + c] = (0..4).map(|k| a[r * 4 + k] * b[k * 4 + c]).sum();
        }
    }
    m
}

fn apply(m: &Matrix, p: Vec3) -> Vec3 {
    let w = m[12] * p.x + m[13] * p.y + m[14] * p.z + m[15];
    let w = if w.abs() > 1e-12 { w } else { 1.0 };
    Vec3::new(
        (m[0] * p.x + m[1] * p.y + m[2] * p.z + m[3]) / w,
        (m[4] * p.x + m[5] * p.y + m[6] * p.z + m[7]) / w,
        (m[8] * p.x + m[9] * p.y + m[10] * p.z + m[11]) / w,
    )
}

/// A direction through the matrix, without its translation.
fn turn(m: &Matrix, v: Vec3) -> Vec3 {
    Vec3::new(
        m[0] * v.x + m[1] * v.y + m[2] * v.z,
        m[4] * v.x + m[5] * v.y + m[6] * v.z,
        m[8] * v.x + m[9] * v.y + m[10] * v.z,
    )
}

fn sub(a: Vec3, b: Vec3) -> Vec3 {
    Vec3::new(a.x - b.x, a.y - b.y, a.z - b.z)
}

fn add(a: Vec3, b: Vec3) -> Vec3 {
    Vec3::new(a.x + b.x, a.y + b.y, a.z + b.z)
}

fn scale(a: Vec3, s: f64) -> Vec3 {
    Vec3::new(a.x * s, a.y * s, a.z * s)
}

fn dot(a: Vec3, b: Vec3) -> f64 {
    a.x * b.x + a.y * b.y + a.z * b.z
}

fn cross(a: Vec3, b: Vec3) -> Vec3 {
    Vec3::new(
        a.y * b.z - a.z * b.y,
        a.z * b.x - a.x * b.z,
        a.x * b.y - a.y * b.x,
    )
}

fn unit(a: Vec3) -> Option<Vec3> {
    let l = dot(a, a).sqrt();
    (l.is_finite() && l > 1e-12).then(|| scale(a, 1.0 / l))
}

/// The X and Y axes of the plane of normal `n`, by the arbitrary axis
/// algorithm (DXF reference, Object Coordinate Systems).
fn axes(n: Vec3) -> (Vec3, Vec3) {
    let n = unit(n).unwrap_or(Vec3::Z);
    let ax = if n.x.abs() < 1.0 / 64.0 && n.y.abs() < 1.0 / 64.0 {
        cross(Vec3::new(0.0, 1.0, 0.0), n)
    } else {
        cross(Vec3::Z, n)
    };
    let ax = unit(ax).unwrap_or(Vec3::new(1.0, 0.0, 0.0));
    let ay = unit(cross(n, ax)).unwrap_or(Vec3::new(0.0, 1.0, 0.0));
    (ax, ay)
}

/// The circle through three points: centre, radius and the normal that
/// turns from the first to the second to the third counterclockwise.
fn circle3(p: &[Vec3; 3]) -> Option<(Vec3, f64, Vec3)> {
    let (a, b) = (sub(p[1], p[0]), sub(p[2], p[0]));
    let n = cross(a, b);
    let nn = dot(n, n);
    if !(nn > 1e-24) {
        return None;
    }
    // Circumcentre: p0 + ((|a|^2 b - |b|^2 a) x n) / (2 |n|^2).
    let num = cross(sub(scale(b, dot(a, a)), scale(a, dot(b, b))), n);
    let center = add(p[0], scale(num, 0.5 / nn));
    let radius = dot(sub(p[0], center), sub(p[0], center)).sqrt();
    Some((center, radius, scale(n, 1.0 / nn.sqrt())))
}

/// The points of an arc of `sweep` radians (negative clockwise) from the
/// direction `start`, about `normal`, sampled as the tessellator samples
/// an ARC of that sweep.
fn arc_points(center: Vec3, radius: f64, normal: Vec3, start: Vec3, sweep: f64) -> Vec<Vec3> {
    let n = unit(normal).unwrap_or(Vec3::Z);
    // The start direction in the plane; the plane's X axis when it has none.
    let u = unit(sub(start, scale(n, dot(start, n)))).unwrap_or_else(|| axes(n).0);
    let v = cross(n, u);
    let (n_sweep, flip) = if sweep < 0.0 {
        (-sweep, -1.0)
    } else {
        (sweep, 1.0)
    };
    let flat = if n_sweep >= TAU {
        curves::flatten_circle(0.0, 0.0, radius)
    } else {
        curves::flatten_arc(0.0, 0.0, radius, 0.0, n_sweep)
    };
    flat.into_iter()
        .map(|[x, y]| add(center, add(scale(u, x), scale(v, y * flip))))
        .collect()
}

/// An elliptical arc's points, sampled as the tessellator samples an
/// ELLIPSE.
fn ellipse_points(e: &ProxyEllipse) -> Vec<Vec3> {
    if !(e.major_radius > 0.0) {
        return Vec::new();
    }
    let n = unit(e.normal).unwrap_or(Vec3::Z);
    let (ax, ay) = axes(n);
    let (s, c) = e.rotation.sin_cos();
    let u = add(scale(ax, c), scale(ay, s));
    let v = cross(n, u);
    curves::flatten_ellipse(
        0.0,
        0.0,
        e.major_radius,
        0.0,
        e.minor_radius / e.major_radius,
        e.start,
        e.end,
    )
    .into_iter()
    .map(|[x, y]| add(e.center, add(scale(u, x), scale(v, y))))
    .collect()
}

fn circle_points(center: Vec3, radius: f64, normal: Vec3) -> Vec<Vec3> {
    let (ax, _) = axes(normal);
    arc_points(center, radius, normal, ax, TAU)
}

/// The traits a stream has set so far, as an entity's common properties.
struct Traits {
    common: Entity,
    fill: bool,
}

/// The pieces `g` draws for the custom entity `owner`.
pub(super) fn explode(g: &ProxyGraphics, owner: &Entity, doc: &CadDrawing) -> Vec<Piece> {
    let mut t = Traits {
        common: Entity {
            handle: owner.handle,
            owner: owner.owner,
            layer: owner.layer.clone(),
            linetype: owner.linetype.clone(),
            color: owner.color,
            lineweight: owner.lineweight,
            transparency: owner.transparency,
            linetype_scale: owner.linetype_scale,
            paper_space: owner.paper_space,
            ..Entity::default()
        },
        fill: false,
    };
    let linetypes: Vec<&Linetype> = doc
        .linetypes
        .iter()
        .filter(|l| {
            !l.name.eq_ignore_ascii_case("BYLAYER") && !l.name.eq_ignore_ascii_case("BYBLOCK")
        })
        .collect();
    let mut stack: Vec<Matrix> = Vec::new();
    let mut m = IDENTITY;
    let mut out = Vec::new();
    for item in &g.items {
        let untransformed = m == IDENTITY;
        let at = |p: Vec3| apply(&m, p);
        match item {
            ProxyItem::Color(c) => t.common.color = *c,
            ProxyItem::Layer(i) => {
                if let Some(l) = usize::try_from(*i).ok().and_then(|i| doc.layers.get(i)) {
                    t.common.layer.clone_from(&l.name);
                }
            }
            ProxyItem::Linetype(i) => match *i {
                0xFFFF_FFFF | 32767 => t.common.linetype = "BYLAYER".to_string(),
                0xFFFF_FFFE | 32766 => t.common.linetype = "BYBLOCK".to_string(),
                i => match usize::try_from(i).ok().and_then(|i| linetypes.get(i)) {
                    Some(l) => t.common.linetype.clone_from(&l.name),
                    None => t.common.linetype = "BYLAYER".to_string(),
                },
            },
            ProxyItem::Fill(on) => t.fill = *on,
            ProxyItem::LineWeight(w) => t.common.lineweight = *w,
            ProxyItem::LinetypeScale(s) => t.common.linetype_scale = *s,
            ProxyItem::Thickness(_) => {}
            ProxyItem::PushTransform(x) => {
                stack.push(m);
                m = mul(&m, x);
            }
            ProxyItem::PopTransform => m = stack.pop().unwrap_or(IDENTITY),
            ProxyItem::Polyline { points, .. } => {
                let pts: Vec<Vec3> = points.iter().map(|p| at(*p)).collect();
                path(&mut out, &t, pts, false);
            }
            ProxyItem::Polygon(points) => {
                let pts: Vec<Vec3> = points.iter().map(|p| at(*p)).collect();
                if t.fill {
                    fill(&mut out, &t, vec![pts]);
                } else {
                    path(&mut out, &t, pts, true);
                }
            }
            ProxyItem::Circle {
                center,
                radius,
                normal,
            } => {
                let pts: Vec<Vec3> = circle_points(*center, *radius, *normal)
                    .into_iter()
                    .map(at)
                    .collect();
                closed_curve(&mut out, &t, pts);
            }
            ProxyItem::Circle3P(p) => {
                if let Some((c, r, n)) = circle3(p) {
                    let pts: Vec<Vec3> = circle_points(c, r, n).into_iter().map(at).collect();
                    closed_curve(&mut out, &t, pts);
                }
            }
            ProxyItem::Arc {
                center,
                radius,
                normal,
                start,
                sweep,
                kind,
            } => {
                let pts = arc_points(*center, *radius, *normal, *start, *sweep);
                arc(&mut out, &t, pts, at(*center), *kind, &at);
            }
            ProxyItem::Arc3P { points, kind } => {
                if let Some((c, r, n)) = circle3(points) {
                    let (u, w) = (sub(points[0], c), sub(points[2], c));
                    let v = cross(n, u);
                    // From the first point to the third, counterclockwise
                    // about the normal that passes through the second.
                    let sweep = dot(w, v).atan2(dot(w, u)).rem_euclid(TAU);
                    let pts = arc_points(c, r, n, u, sweep);
                    arc(&mut out, &t, pts, at(c), *kind, &at);
                }
            }
            ProxyItem::EllipticalArc(e) => {
                let pts = ellipse_points(e);
                let c = at(e.center);
                arc(&mut out, &t, pts, c, e.kind, &at);
            }
            ProxyItem::Mesh(mesh) => self::mesh(&mut out, &t, mesh, &at),
            ProxyItem::Shell(shell) => self::shell(&mut out, &t, shell, &at),
            ProxyItem::Text(x) => out.push(piece(&t, text(x, &m, doc))),
            ProxyItem::XLine { base, through, ray } => {
                let (b, p) = (at(*base), at(*through));
                let r = Ray {
                    base: b,
                    direction: sub(p, b),
                };
                let kind = if *ray {
                    EntityKind::Ray(r)
                } else {
                    EntityKind::XLine(r)
                };
                out.push(piece(&t, kind));
            }
            ProxyItem::LwPolyline(p) => {
                if untransformed {
                    out.push(piece(&t, EntityKind::LwPolyline((**p).clone())));
                } else {
                    lwpolyline(&mut out, &t, p, &at);
                }
            }
        }
    }
    out
}

fn piece(t: &Traits, kind: EntityKind) -> Piece {
    Piece {
        entity: Entity {
            kind,
            ..t.common.clone()
        },
        fill: None,
    }
}

/// An open or closed path of world points: a LINE for two, else a 3D
/// POLYLINE.
fn path(out: &mut Vec<Piece>, t: &Traits, pts: Vec<Vec3>, closed: bool) {
    if pts.len() == 2 && !closed {
        out.push(piece(
            t,
            EntityKind::Line(crate::cad::Line {
                start: pts[0],
                end: pts[1],
                ..crate::cad::Line::default()
            }),
        ));
        return;
    }
    if pts.len() < 2 {
        return;
    }
    let p = Polyline {
        flags: 8 | i16::from(closed),
        vertices: pts
            .into_iter()
            .map(|location| Vertex {
                location,
                ..Vertex::default()
            })
            .collect(),
        ..Polyline::default()
    };
    out.push(piece(t, EntityKind::Polyline(p)));
}

fn xy(pts: &[Vec3]) -> Vec<[f64; 2]> {
    pts.iter().map(|p| [p.x, p.y]).collect()
}

/// The signed area of a closed loop.
fn shoelace(l: &[[f64; 2]]) -> f64 {
    l.iter()
        .zip(l.iter().cycle().skip(1))
        .map(|(a, b)| a[0] * b[1] - b[0] * a[1])
        .sum::<f64>()
        / 2.0
}

/// Loops to fill; seen edge on (no area in XY, a circle about a horizontal
/// normal), their outlines instead, as the converter draws such a circle.
fn fill(out: &mut Vec<Piece>, t: &Traits, loops: Vec<Vec<Vec3>>) {
    let flat: Vec<Vec<[f64; 2]>> = loops
        .iter()
        .map(|l| xy(l))
        .filter(|l| l.len() >= 3)
        .collect();
    let area: f64 = flat.iter().map(|l| shoelace(l).abs()).sum();
    let perimeter: f64 = flat
        .iter()
        .flat_map(|l| l.iter().zip(l.iter().cycle().skip(1)))
        .map(|(a, b)| (b[0] - a[0]).hypot(b[1] - a[1]))
        .sum();
    if !(area > 1e-6 * perimeter * perimeter) {
        for l in loops {
            path(out, t, l, true);
        }
        return;
    }
    let loops = flat;
    if !loops.is_empty() {
        out.push(Piece {
            entity: t.common.clone(),
            fill: Some(loops),
        });
    }
}

/// A circle: filled while fill is on, else its outline.
fn closed_curve(out: &mut Vec<Piece>, t: &Traits, pts: Vec<Vec3>) {
    if t.fill {
        fill(out, t, vec![pts]);
    } else {
        path(out, t, pts, false);
    }
}

/// An arc, closed through its centre or by its chord as its kind says:
/// filled while fill is on, else its outline.
fn arc(
    out: &mut Vec<Piece>,
    t: &Traits,
    pts: Vec<Vec3>,
    center: Vec3,
    kind: ArcKind,
    at: &dyn Fn(Vec3) -> Vec3,
) {
    let mut pts: Vec<Vec3> = pts.into_iter().map(at).collect();
    match kind {
        ArcKind::Simple => path(out, t, pts, false),
        ArcKind::Sector | ArcKind::Chord => {
            if kind == ArcKind::Sector {
                pts.push(center);
            }
            if t.fill {
                fill(out, t, vec![pts]);
            } else {
                path(out, t, pts, true);
            }
        }
    }
}

fn mesh(out: &mut Vec<Piece>, t: &Traits, m: &ProxyMesh, at: &dyn Fn(Vec3) -> Vec3) {
    let (rows, cols) = (m.rows as usize, m.columns as usize);
    if rows.checked_mul(cols) != Some(m.vertices.len()) {
        return;
    }
    let v = |r: usize, c: usize| at(m.vertices[r * cols + c]);
    if t.fill {
        let mut loops = Vec::new();
        for r in 1..rows {
            for c in 1..cols {
                loops.push(vec![v(r - 1, c - 1), v(r - 1, c), v(r, c), v(r, c - 1)]);
            }
        }
        // Each quad on its own: neighbours must not cancel out.
        for l in loops {
            fill(out, t, vec![l]);
        }
        return;
    }
    let edges = rows.saturating_sub(1) * cols + cols.saturating_sub(1) * rows;
    if m.edge_visible.len() == edges {
        // Along each row first, then between rows: read so, the corpus's
        // pipes (2 by 9, the rows their end rings) show both rings whole
        // and every other edge between them.
        let mut k = 0;
        for r in 0..rows {
            for c in 1..cols {
                if m.edge_visible[k] {
                    path(out, t, vec![v(r, c - 1), v(r, c)], false);
                }
                k += 1;
            }
        }
        for r in 1..rows {
            for c in 0..cols {
                if m.edge_visible[k] {
                    path(out, t, vec![v(r - 1, c), v(r, c)], false);
                }
                k += 1;
            }
        }
        return;
    }
    for r in 0..rows {
        path(out, t, (0..cols).map(|c| v(r, c)).collect(), false);
    }
    for c in 0..cols {
        path(out, t, (0..rows).map(|r| v(r, c)).collect(), false);
    }
}

/// A shell's faces: filled while fill is on (a face with the holes after
/// it), else the edges of each face and hole that are not hidden.
fn shell(out: &mut Vec<Piece>, t: &Traits, s: &ProxyShell, at: &dyn Fn(Vec3) -> Vec3) {
    // Each loop: its points, whether it is a hole, the index of its first
    // edge.
    let mut loops: Vec<(Vec<Vec3>, bool, usize)> = Vec::new();
    let mut i = 0usize;
    let mut edge = 0usize;
    while let Some(&k) = s.faces.get(i) {
        let n = k.unsigned_abs() as usize;
        let Some(ids) = s.faces.get(i + 1..i + 1 + n) else {
            break;
        };
        let pts: Option<Vec<Vec3>> = ids
            .iter()
            .map(|&v| {
                usize::try_from(v)
                    .ok()
                    .and_then(|v| s.vertices.get(v))
                    .map(|p| at(*p))
            })
            .collect();
        if let Some(pts) = pts {
            loops.push((pts, k < 0, edge));
        }
        edge = edge.saturating_add(n);
        i += 1 + n;
    }
    if t.fill {
        let mut face: Vec<Vec<Vec3>> = Vec::new();
        for (pts, hole, _) in loops {
            if !hole && !face.is_empty() {
                fill(out, t, std::mem::take(&mut face));
            }
            face.push(pts);
        }
        fill(out, t, face);
        return;
    }
    for (pts, _, first) in loops {
        let n = pts.len();
        if s.edge_visible.is_empty() {
            path(out, t, pts, true);
            continue;
        }
        for j in 0..n {
            if s.edge_visible.get(first + j).copied().unwrap_or(true) {
                path(out, t, vec![pts[j], pts[(j + 1) % n]], false);
            }
        }
    }
}

fn lwpolyline(out: &mut Vec<Piece>, t: &Traits, p: &LwPolyline, at: &dyn Fn(Vec3) -> Vec3) {
    let verts: Vec<([f64; 2], f64)> = p
        .vertices
        .iter()
        .map(|v| ([v.point.x, v.point.y], v.bulge))
        .collect();
    let closed = p.is_closed();
    let n = p.plane.extrusion;
    let (ax, ay) = axes(n);
    let n = unit(n).unwrap_or(Vec3::Z);
    let pts: Vec<Vec3> = expand_bulges(&verts, closed)
        .into_iter()
        .map(|[x, y]| at(add(add(scale(ax, x), scale(ay, y)), scale(n, p.elevation))))
        .collect();
    path(out, t, pts, closed);
}

/// A text as a TEXT entity, in the object coordinates of its normal.
fn text(x: &ProxyText, m: &Matrix, doc: &CadDrawing) -> EntityKind {
    let position = apply(m, x.position);
    let dir = turn(m, x.direction);
    let up0 = cross(
        unit(x.normal).unwrap_or(Vec3::Z),
        unit(x.direction).unwrap_or(Vec3::new(1.0, 0.0, 0.0)),
    );
    let up = turn(m, up0);
    let normal = unit(cross(dir, up)).unwrap_or(Vec3::Z);
    let (ax, ay) = axes(normal);
    let height_scale = dot(up, up).sqrt();
    let height_scale = if height_scale.is_finite() && height_scale > 0.0 {
        height_scale
    } else {
        1.0
    };
    let insertion = Vec3::new(dot(position, ax), dot(position, ay), dot(position, normal));
    let text = Text {
        insertion,
        height: x.height * height_scale,
        // `%%%` is one percent sign: a raw text's `%` stay as written.
        value: if x.raw {
            x.value.replace('%', "%%%")
        } else {
            x.value.clone()
        },
        rotation: dot(dir, ay).atan2(dot(dir, ax)),
        width_factor: x.width_factor,
        oblique: x.oblique,
        style: style_for(x, doc),
        // Group 71: 2 mirrored in X, 4 upside down.
        generation: (i16::from(x.backwards) * 2) | (i16::from(x.upside_down) * 4),
        plane: Plane {
            thickness: 0.0,
            extrusion: normal,
        },
        ..Text::default()
    };
    EntityKind::Text(Box::new(text))
}

/// The text style a stream's font names: the style of that TrueType face
/// or font file, else STANDARD, which the converter gives every text.
fn style_for(x: &ProxyText, doc: &CadDrawing) -> String {
    let stem = |f: &str| {
        let f = f.rsplit(['/', '\\']).next().unwrap_or(f);
        f.rsplit_once('.')
            .map_or(f, |(s, _)| s)
            .to_ascii_lowercase()
    };
    let by_face = (!x.typeface.is_empty())
        .then(|| {
            doc.text_styles
                .iter()
                .find(|s| s.font_family.eq_ignore_ascii_case(&x.typeface))
        })
        .flatten();
    let by_file = (!x.font.is_empty())
        .then(|| {
            doc.text_styles
                .iter()
                .find(|s| !s.font_file.is_empty() && stem(&s.font_file) == stem(&x.font))
        })
        .flatten();
    by_face
        .or(by_file)
        .map_or_else(|| "STANDARD".to_string(), |s| s.name.clone())
}
