//! IFC (IFC2X3, IFC4, IFC4X3) models into a [`Scene`]: each product's body
//! geometry as triangles in metres, with its class, name, colour and the
//! spatial element containing it.
//!
//! Written from buildingSMART's published schemas and documentation: the
//! attribute positions below are those of the EXPRESS definitions, the
//! geometry that of the entities' semantic definitions (ISO 10303-42
//! conventions). Geometry is evaluated in `f64` in each product's own
//! coordinates, openings are subtracted there (`IfcRelVoidsElement`), and
//! the result is placed and offset by the scene origin.
//!
//! Bounded on any input: references are followed to a fixed depth (which
//! also breaks reference cycles), every curve and surface is sampled with a
//! fixed number of points per turn, booleans give up past a fixed amount of
//! work, and all triangles made, kept or not, come out of one budget.

mod csg;
mod curves;
mod items;
mod math;
mod profiles;
mod solids;
pub mod step;
mod triangulate;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use self::math::{cross, unit, Xf, V3};
use self::step::{StepFile, Value};
use super::mesh::{Element, Node, Part, Scene, SceneBuilder, Warnings, DEFAULT_MAX_TRIANGLES};

/// How much a reader may produce.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most triangles in the scene; elements past it are left out and
    /// counted in `warnings.truncated`.
    pub max_triangles: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_triangles: DEFAULT_MAX_TRIANGLES,
        }
    }
}

/// Why a file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Step(step::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Step(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

/// RGBA in 0..1.
pub(crate) type Color = [f32; 4];

/// Deepest chain of representation items (booleans, mapped items) and of
/// curves inside curves.
const MAX_DEPTH: u32 = 32;
/// Deepest chain of object placements.
const MAX_PLACEMENT_DEPTH: usize = 256;

/// Triangles in `f64`, in some coordinate system.
#[derive(Debug, Clone, Default)]
pub(crate) struct Mesh {
    pub p: Vec<V3>,
    pub t: Vec<[u32; 3]>,
}

impl Mesh {
    pub fn transform(&mut self, x: &Xf) {
        for p in &mut self.p {
            *p = x.point(*p);
        }
        if x.det() < 0.0 {
            for t in &mut self.t {
                t.swap(1, 2);
            }
        }
    }

    pub fn append(&mut self, o: &Mesh) {
        let base = self.p.len() as u32;
        self.p.extend_from_slice(&o.p);
        self.t
            .extend(o.t.iter().map(|t| [t[0] + base, t[1] + base, t[2] + base]));
    }

    /// Six times the signed volume (divergence theorem).
    pub fn volume6(&self) -> f64 {
        self.t
            .iter()
            .map(|t| {
                let (a, b, c) = (
                    self.p[t[0] as usize],
                    self.p[t[1] as usize],
                    self.p[t[2] as usize],
                );
                math::dot(a, cross(b, c))
            })
            .sum()
    }

    /// Turns a closed mesh outward (positive volume).
    pub fn orient_outward(&mut self) {
        if self.volume6() < 0.0 {
            for t in &mut self.t {
                t.swap(1, 2);
            }
        }
    }

    pub fn bounds(&self) -> Option<(V3, V3)> {
        let mut lo = [f64::INFINITY; 3];
        let mut hi = [f64::NEG_INFINITY; 3];
        for p in &self.p {
            for k in 0..3 {
                lo[k] = lo[k].min(p[k]);
                hi[k] = hi[k].max(p[k]);
            }
        }
        (lo[0] <= hi[0]).then_some((lo, hi))
    }
}

/// A coloured mesh, closed (a solid) or not.
#[derive(Debug, Clone)]
pub(crate) struct Piece {
    pub color: Option<Color>,
    pub mesh: Mesh,
    pub solid: bool,
}

/// The reader's state while one file is read.
pub(crate) struct Reader<'a> {
    pub f: &'a StepFile<'a>,
    /// Metres per length unit.
    pub length: f64,
    /// Radians per plane angle unit.
    pub angle: f64,
    pub warnings: Warnings,
    /// Triangles still allowed to be made, intermediate ones included.
    pub work: usize,
    placements: HashMap<u32, Xf>,
    maps: HashMap<u32, Rc<Vec<Piece>>>,
    /// Item -> style, from `IfcStyledItem`.
    styled: HashMap<u32, u32>,
    style_colors: HashMap<u32, Option<Color>>,
    material_colors: HashMap<u32, Option<Color>>,
}

/// The parameters of an instance whose type is one of `types`.
pub(crate) fn is(ty: &[u8], types: &[&[u8]]) -> bool {
    types.contains(&ty)
}

impl<'a> Reader<'a> {
    pub fn new(f: &'a StepFile<'a>, work: usize) -> Self {
        let mut r = Reader {
            f,
            length: 1.0,
            angle: 1.0,
            warnings: Warnings::default(),
            work,
            placements: HashMap::new(),
            maps: HashMap::new(),
            styled: HashMap::new(),
            style_colors: HashMap::new(),
            material_colors: HashMap::new(),
        };
        r.units();
        r
    }

    pub fn get(&self, id: u32) -> Option<(&'a [u8], Vec<Value<'a>>)> {
        let (ty, p) = self.f.get(id)?;
        // The type name lives as long as the file.
        let ty: &'a [u8] = self.f.type_name(id).unwrap_or(ty);
        Some((ty, p))
    }

    /// Counts an item class that is not drawn.
    pub fn unsupported(&mut self, ty: &[u8]) {
        *self
            .warnings
            .unsupported
            .entry(String::from_utf8_lossy(ty).into_owned())
            .or_insert(0) += 1;
    }

    /// Takes `n` triangles from the work budget.
    pub fn spend(&mut self, n: usize) -> Option<()> {
        self.work = self.work.checked_sub(n)?;
        Some(())
    }

    pub fn point(&self, id: u32) -> Option<V3> {
        let (ty, p) = self.get(id)?;
        if ty != b"IFCCARTESIANPOINT" {
            return None;
        }
        coords(p.first()?)
    }

    pub fn direction(&self, id: u32) -> Option<V3> {
        let (ty, p) = self.get(id)?;
        if ty != b"IFCDIRECTION" {
            return None;
        }
        unit(coords(p.first()?)?)
    }

    fn units(&mut self) {
        let assignment = self
            .f
            .of_type(b"IFCPROJECT")
            .next()
            .and_then(|p| self.f.params(p))
            .and_then(|p| p.get(8).and_then(Value::id))
            .or_else(|| self.f.of_type(b"IFCUNITASSIGNMENT").next());
        let Some(units) = assignment.and_then(|a| self.f.params(a)) else {
            return;
        };
        let Some(list) = units.first().and_then(Value::list) else {
            return;
        };
        for u in list.iter().filter_map(Value::id) {
            let Some((kind, factor)) = self.unit(u, 0) else {
                continue;
            };
            if !(factor.is_finite() && factor > 0.0) {
                continue;
            }
            match kind.as_slice() {
                b"LENGTHUNIT" => self.length = factor,
                b"PLANEANGLEUNIT" => self.angle = factor,
                _ => {}
            }
        }
    }

    /// The unit type and its size in SI units.
    fn unit(&self, id: u32, depth: u32) -> Option<(Vec<u8>, f64)> {
        if depth > 4 {
            return None;
        }
        let (ty, p) = self.get(id)?;
        let kind = p.get(1)?.enumeration()?.to_vec();
        match ty {
            b"IFCSIUNIT" => {
                let prefix = match p.get(2).and_then(Value::enumeration) {
                    Some(b"EXA") => 1e18,
                    Some(b"PETA") => 1e15,
                    Some(b"TERA") => 1e12,
                    Some(b"GIGA") => 1e9,
                    Some(b"MEGA") => 1e6,
                    Some(b"KILO") => 1e3,
                    Some(b"HECTO") => 1e2,
                    Some(b"DECA") => 1e1,
                    Some(b"DECI") => 1e-1,
                    Some(b"CENTI") => 1e-2,
                    Some(b"MILLI") => 1e-3,
                    Some(b"MICRO") => 1e-6,
                    Some(b"NANO") => 1e-9,
                    Some(b"PICO") => 1e-12,
                    Some(b"FEMTO") => 1e-15,
                    Some(b"ATTO") => 1e-18,
                    _ => 1.0,
                };
                Some((kind, prefix))
            }
            b"IFCCONVERSIONBASEDUNIT" | b"IFCCONVERSIONBASEDUNITWITHOFFSET" => {
                let name = p
                    .get(2)
                    .and_then(Value::text)
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                let measure = self.f.params(p.get(3)?.id()?)?;
                let value = measure.first()?.num()?;
                let base = measure
                    .get(1)
                    .and_then(Value::id)
                    .and_then(|b| self.unit(b, depth + 1))
                    .map_or(1.0, |(_, f)| f);
                let f = value * base;
                if kind == b"PLANEANGLEUNIT"
                    && !(f.is_finite() && f > 0.0)
                    && name.contains("DEGREE")
                {
                    return Some((kind, std::f64::consts::PI / 180.0));
                }
                Some((kind, f))
            }
            _ => None,
        }
    }

    /// An `IfcAxis2Placement2D` or `3D` as a transform.
    pub fn axis2(&self, id: u32) -> Option<Xf> {
        let (ty, p) = self.get(id)?;
        match ty {
            b"IFCAXIS2PLACEMENT3D" => {
                let o = self.point(p.first()?.id()?)?;
                let z = p
                    .get(1)
                    .and_then(Value::id)
                    .and_then(|d| self.direction(d))
                    .unwrap_or([0.0, 0.0, 1.0]);
                let r = p.get(2).and_then(Value::id).and_then(|d| self.direction(d));
                let x = first_proj_axis(z, r);
                let y = cross(z, x);
                Some(Xf::new(x, y, z, o))
            }
            b"IFCAXIS2PLACEMENT2D" => {
                let o = self.point(p.first()?.id()?)?;
                let x = p
                    .get(1)
                    .and_then(Value::id)
                    .and_then(|d| self.direction(d))
                    .unwrap_or([1.0, 0.0, 0.0]);
                let x = unit([x[0], x[1], 0.0]).unwrap_or([1.0, 0.0, 0.0]);
                Some(Xf::new(x, [-x[1], x[0], 0.0], [0.0, 0.0, 1.0], o))
            }
            _ => None,
        }
    }

    /// An optional placement attribute: absent is the identity.
    pub fn axis2_or_identity(&self, v: Option<&Value>) -> Option<Xf> {
        match v.and_then(Value::id) {
            Some(id) => self.axis2(id),
            None => Some(Xf::IDENTITY),
        }
    }

    /// An `IfcCartesianTransformationOperator2D`/`3D` (uniform or not).
    pub fn operator(&self, id: u32) -> Option<Xf> {
        let (ty, p) = self.get(id)?;
        let dir = |i: usize| p.get(i).and_then(Value::id).and_then(|d| self.direction(d));
        let o = self.point(p.get(2)?.id()?)?;
        let s = p.get(3).and_then(Value::num).unwrap_or(1.0);
        let (u, s2, s3) = match ty {
            b"IFCCARTESIANTRANSFORMATIONOPERATOR3D"
            | b"IFCCARTESIANTRANSFORMATIONOPERATOR3DNONUNIFORM" => {
                let z = dir(4).unwrap_or([0.0, 0.0, 1.0]);
                let x = first_proj_axis(z, dir(0));
                let y = second_proj_axis(z, x, dir(1));
                let nonuniform = ty == b"IFCCARTESIANTRANSFORMATIONOPERATOR3DNONUNIFORM";
                let s2 = if nonuniform {
                    p.get(5).and_then(Value::num).unwrap_or(s)
                } else {
                    s
                };
                let s3 = if nonuniform {
                    p.get(6).and_then(Value::num).unwrap_or(s)
                } else {
                    s
                };
                ([x, y, z], s2, s3)
            }
            b"IFCCARTESIANTRANSFORMATIONOPERATOR2D"
            | b"IFCCARTESIANTRANSFORMATIONOPERATOR2DNONUNIFORM" => {
                // IfcBaseAxis for two dimensions.
                let flat = |d: V3| unit([d[0], d[1], 0.0]);
                let (x, y) = match (dir(0).and_then(flat), dir(1).and_then(flat)) {
                    (Some(x), a2) => {
                        let mut y = [-x[1], x[0], 0.0];
                        if a2.is_some_and(|a| math::dot(a, y) < 0.0) {
                            y = [-y[0], -y[1], 0.0];
                        }
                        (x, y)
                    }
                    (None, Some(a)) => ([a[1], -a[0], 0.0], a),
                    (None, None) => ([1.0, 0.0, 0.0], [0.0, 1.0, 0.0]),
                };
                let s2 = if ty == b"IFCCARTESIANTRANSFORMATIONOPERATOR2DNONUNIFORM" {
                    p.get(4).and_then(Value::num).unwrap_or(s)
                } else {
                    s
                };
                ([x, y, [0.0, 0.0, 1.0]], s2, 1.0)
            }
            _ => return None,
        };
        let x = Xf::new(
            math::scale(u[0], s),
            math::scale(u[1], s2),
            math::scale(u[2], s3),
            o,
        );
        x.is_finite().then_some(x)
    }

    /// An `IfcObjectPlacement` as a transform to the model's coordinates.
    pub fn placement(&mut self, id: u32) -> Option<Xf> {
        let mut chain: Vec<(u32, Xf)> = Vec::new();
        let mut cur = Some(id);
        let mut base = Xf::IDENTITY;
        while let Some(pid) = cur {
            if let Some(x) = self.placements.get(&pid) {
                base = *x;
                break;
            }
            if chain.len() >= MAX_PLACEMENT_DEPTH || chain.iter().any(|(c, _)| *c == pid) {
                return None;
            }
            let (ty, p) = self.get(pid)?;
            let (parent, local) = match ty {
                b"IFCLOCALPLACEMENT" => {
                    (p.first().and_then(Value::id), self.axis2(p.get(1)?.id()?)?)
                }
                // IFC4X3: the placement along an alignment, with its
                // Cartesian equivalent precomputed by the writer.
                b"IFCLINEARPLACEMENT" => (
                    p.first().and_then(Value::id),
                    p.get(2)
                        .and_then(Value::id)
                        .and_then(|c| self.axis2(c))
                        .unwrap_or(Xf::IDENTITY),
                ),
                b"IFCGRIDPLACEMENT" => {
                    self.unsupported(ty);
                    let parent = if self.f.schema == step::Schema::Ifc4x3 {
                        p.first().and_then(Value::id)
                    } else {
                        None
                    };
                    (parent, Xf::IDENTITY)
                }
                _ => return None,
            };
            chain.push((pid, local));
            cur = parent;
        }
        for (pid, local) in chain.into_iter().rev() {
            base = base.mul(&local);
            self.placements.insert(pid, base);
        }
        Some(base)
    }

    /// The colour an `IfcStyledItem` gives `item`, if any.
    pub fn item_color(&mut self, item: u32) -> Option<Color> {
        let style = *self.styled.get(&item)?;
        self.styled_item_color(style)
    }

    fn styled_item_color(&mut self, styled: u32) -> Option<Color> {
        if let Some(c) = self.style_colors.get(&styled) {
            return *c;
        }
        let c = self
            .f
            .params(styled)
            .and_then(|p| self.styles_color(p.get(1)?, 0));
        self.style_colors.insert(styled, c);
        c
    }

    /// The first surface colour in a list of styles (IFC4), of style
    /// assignments (IFC2X3), or in one style.
    fn styles_color(&self, v: &Value, depth: u32) -> Option<Color> {
        if depth > 4 {
            return None;
        }
        if let Some(l) = v.list() {
            return l.iter().find_map(|s| self.styles_color(s, depth + 1));
        }
        let (ty, p) = self.get(v.id()?)?;
        match ty {
            b"IFCPRESENTATIONSTYLEASSIGNMENT" => self.styles_color(p.first()?, depth + 1),
            b"IFCSURFACESTYLE" => {
                let elements = p.get(2)?.list()?;
                let mut found = None;
                for e in elements.iter().filter_map(Value::id) {
                    let Some((ety, ep)) = self.get(e) else {
                        continue;
                    };
                    if !is(
                        ety,
                        &[b"IFCSURFACESTYLESHADING", b"IFCSURFACESTYLERENDERING"],
                    ) {
                        continue;
                    }
                    let Some(rgb) = ep
                        .first()
                        .and_then(Value::id)
                        .and_then(|c| self.colour_rgb(c))
                    else {
                        continue;
                    };
                    let transparency = ep
                        .get(1)
                        .and_then(Value::num)
                        .unwrap_or(0.0)
                        .clamp(0.0, 1.0);
                    found = Some([rgb[0], rgb[1], rgb[2], (1.0 - transparency) as f32]);
                    // Rendering is the more complete of the two.
                    if ety == b"IFCSURFACESTYLERENDERING" {
                        break;
                    }
                }
                found
            }
            _ => None,
        }
    }

    /// The colour of a material, of the first of a set's materials that
    /// has one, through layer and profile set usages.
    fn material_color(&mut self, id: u32, reps: &HashMap<u32, u32>, depth: u32) -> Option<Color> {
        if depth > 6 {
            return None;
        }
        if let Some(c) = self.material_colors.get(&id) {
            return *c;
        }
        let (ty, p) = self.get(id)?;
        let first_of = |r: &mut Self, v: Option<&Value>| -> Option<Color> {
            let v = v?;
            match v.list() {
                Some(l) => l
                    .iter()
                    .filter_map(Value::id)
                    .find_map(|m| r.material_color(m, reps, depth + 1)),
                None => r.material_color(v.id()?, reps, depth + 1),
            }
        };
        let c = match ty {
            b"IFCMATERIAL" => reps.get(&id).and_then(|&rep| {
                let rp = self.f.params(rep)?;
                let styled: Vec<u32> = rp
                    .get(2)?
                    .list()?
                    .iter()
                    .filter_map(Value::id)
                    .filter_map(|sr| self.f.params(sr))
                    .flat_map(|sr| {
                        sr.get(3)
                            .and_then(Value::list)
                            .map(|l| l.iter().filter_map(Value::id).collect::<Vec<_>>())
                            .unwrap_or_default()
                    })
                    .collect();
                styled.into_iter().find_map(|s| self.styled_item_color(s))
            }),
            b"IFCMATERIALLAYERSETUSAGE"
            | b"IFCMATERIALLAYER"
            | b"IFCMATERIALLAYERWITHOFFSETS"
            | b"IFCMATERIALLAYERSET"
            | b"IFCMATERIALLIST"
            | b"IFCMATERIALPROFILESETUSAGE"
            | b"IFCMATERIALPROFILESETUSAGETAPERING" => first_of(self, p.first()),
            b"IFCMATERIALPROFILESET"
            | b"IFCMATERIALPROFILE"
            | b"IFCMATERIALPROFILEWITHOFFSETS"
            | b"IFCMATERIALCONSTITUENTSET"
            | b"IFCMATERIALCONSTITUENT" => first_of(self, p.get(2)),
            _ => None,
        };
        self.material_colors.insert(id, c);
        c
    }

    fn colour_rgb(&self, id: u32) -> Option<[f32; 3]> {
        let (ty, p) = self.get(id)?;
        if ty != b"IFCCOLOURRGB" {
            return None;
        }
        let c = |i: usize| {
            p.get(i)
                .and_then(Value::num)
                .filter(|v| v.is_finite())
                .map(|v| v.clamp(0.0, 1.0) as f32)
        };
        Some([c(1)?, c(2)?, c(3)?])
    }
}

/// `IfcFirstProjAxis`: `arg` (or x) made perpendicular to `z`.
pub(crate) fn first_proj_axis(z: V3, arg: Option<V3>) -> V3 {
    let v = arg.unwrap_or(if z == [1.0, 0.0, 0.0] {
        [0.0, 1.0, 0.0]
    } else {
        [1.0, 0.0, 0.0]
    });
    let x = math::sub(v, math::scale(z, math::dot(v, z)));
    unit(x).unwrap_or_else(|| math::any_perpendicular(z))
}

/// `IfcSecondProjAxis`.
fn second_proj_axis(z: V3, x: V3, arg: Option<V3>) -> V3 {
    let v = arg.unwrap_or([0.0, 1.0, 0.0]);
    let y = math::sub(v, math::scale(z, math::dot(v, z)));
    let y = math::sub(y, math::scale(x, math::dot(v, x)));
    unit(y).unwrap_or_else(|| cross(z, x))
}

/// Two or three coordinates.
pub(crate) fn coords(v: &Value) -> Option<V3> {
    let l = v.list()?;
    let c = |i: usize| l.get(i).and_then(Value::num);
    let p = [c(0)?, c(1)?, c(2).unwrap_or(0.0)];
    p.iter().all(|v| v.is_finite()).then_some(p)
}

/// Spatial structure classes, which make the tree of [`Scene::nodes`].
const SPATIAL: &[&[u8]] = &[
    b"IFCPROJECT",
    b"IFCSITE",
    b"IFCBUILDING",
    b"IFCBUILDINGSTOREY",
    b"IFCSPACE",
    b"IFCFACILITY",
    b"IFCFACILITYPART",
    b"IFCFACILITYPARTCOMMON",
    b"IFCBRIDGE",
    b"IFCBRIDGEPART",
    b"IFCROAD",
    b"IFCROADPART",
    b"IFCRAILWAY",
    b"IFCRAILWAYPART",
    b"IFCMARINEFACILITY",
    b"IFCMARINEPART",
    b"IFCSPATIALZONE",
    b"IFCEXTERNALSPATIALELEMENT",
];

/// Products subtracted from others rather than drawn.
const SUBTRACTIONS: &[&[u8]] = &[
    b"IFCOPENINGELEMENT",
    b"IFCOPENINGSTANDARDCASE",
    b"IFCVOIDINGFEATURE",
];

/// Reads an IFC file.
pub fn read(bytes: &[u8], limits: &Limits) -> Result<Scene, Error> {
    let f = StepFile::parse(bytes).map_err(Error::Step)?;
    let work = limits
        .max_triangles
        .saturating_mul(4)
        .saturating_add(1_000_000);
    let mut r = Reader::new(&f, work);
    let mut out = SceneBuilder::new(limits.max_triangles);
    out.scene.warnings.damaged = f.damaged;

    // Relations, in one pass.
    let mut contained: HashMap<u32, u32> = HashMap::new();
    let mut parent_of: HashMap<u32, u32> = HashMap::new();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut voids: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut material_of: HashMap<u32, u32> = HashMap::new();
    let mut type_of: HashMap<u32, u32> = HashMap::new();
    let mut material_reps: HashMap<u32, u32> = HashMap::new();
    let mut shapes: HashSet<u32> = HashSet::new();
    let ids: Vec<u32> = f.ids().collect();
    for &id in &ids {
        let Some(ty) = f.type_name(id) else { continue };
        let wanted: &[&[u8]] = &[
            b"IFCRELCONTAINEDINSPATIALSTRUCTURE",
            b"IFCRELAGGREGATES",
            b"IFCRELNESTS",
            b"IFCRELVOIDSELEMENT",
            b"IFCSTYLEDITEM",
            b"IFCRELASSOCIATESMATERIAL",
            b"IFCRELDEFINESBYTYPE",
            b"IFCMATERIALDEFINITIONREPRESENTATION",
            b"IFCPRODUCTDEFINITIONSHAPE",
        ];
        if !is(ty, wanted) {
            continue;
        }
        if ty == b"IFCPRODUCTDEFINITIONSHAPE" {
            shapes.insert(id);
            continue;
        }
        let Some(p) = f.params(id) else { continue };
        let refs = |i: usize| -> Vec<u32> {
            match p.get(i) {
                Some(Value::Ref(r)) => vec![*r],
                Some(v) => v
                    .list()
                    .map(|l| l.iter().filter_map(Value::id).collect())
                    .unwrap_or_default(),
                None => Vec::new(),
            }
        };
        let one = |i: usize| p.get(i).and_then(Value::id);
        match ty {
            b"IFCRELCONTAINEDINSPATIALSTRUCTURE" => {
                if let Some(s) = one(5) {
                    for e in refs(4) {
                        contained.entry(e).or_insert(s);
                    }
                }
            }
            b"IFCRELAGGREGATES" | b"IFCRELNESTS" => {
                if let Some(s) = one(4) {
                    let kids = refs(5);
                    for &e in &kids {
                        parent_of.entry(e).or_insert(s);
                    }
                    if ty == b"IFCRELAGGREGATES" {
                        children.entry(s).or_default().extend(kids);
                    }
                }
            }
            b"IFCRELVOIDSELEMENT" => {
                if let (Some(h), Some(o)) = (one(4), one(5)) {
                    voids.entry(h).or_default().push(o);
                }
            }
            b"IFCSTYLEDITEM" => {
                if let Some(item) = one(0) {
                    r.styled.entry(item).or_insert(id);
                }
            }
            b"IFCRELASSOCIATESMATERIAL" => {
                if let Some(m) = one(5) {
                    for o in refs(4) {
                        material_of.entry(o).or_insert(m);
                    }
                }
            }
            b"IFCRELDEFINESBYTYPE" => {
                if let Some(t) = one(5) {
                    for o in refs(4) {
                        type_of.entry(o).or_insert(t);
                    }
                }
            }
            b"IFCMATERIALDEFINITIONREPRESENTATION" => {
                if let Some(m) = one(3) {
                    material_reps.entry(m).or_insert(id);
                }
            }
            _ => {}
        }
    }

    // The spatial tree, from the project down.
    let mut node_of: HashMap<u32, u32> = HashMap::new();
    let mut stack: Vec<(u32, Option<u32>)> = f.of_type(b"IFCPROJECT").map(|p| (p, None)).collect();
    stack.reverse();
    while let Some((id, parent)) = stack.pop() {
        if node_of.contains_key(&id) || out.scene.nodes.len() >= 1_000_000 {
            continue;
        }
        let Some((ty, p)) = r.get(id) else { continue };
        if !is(ty, SPATIAL) {
            continue;
        }
        let index = out.scene.nodes.len() as u32;
        out.scene.nodes.push(Node {
            id,
            class: String::from_utf8_lossy(ty).into_owned(),
            name: p.get(2).and_then(Value::text).unwrap_or_default(),
            parent,
        });
        node_of.insert(id, index);
        if let Some(kids) = children.get(&id) {
            for &k in kids.iter().rev() {
                stack.push((k, Some(index)));
            }
        }
    }

    // Products: GlobalId first, a product definition shape in seventh place.
    let mut origin: Option<V3> = None;
    for &id in &ids {
        let Some(raw) = f.raw(id) else { continue };
        if !raw.trim_ascii_start().starts_with(b"'") || !raw.contains(&b'#') {
            continue;
        }
        let Some((ty, p)) = r.get(id) else { continue };
        if p.len() < 7 || is(ty, SUBTRACTIONS) {
            continue;
        }
        let Some(shape) = p[6].id().filter(|s| shapes.contains(s)) else {
            continue;
        };
        let Some(world) = p[5].id().map_or(Some(Xf::IDENTITY), |pl| r.placement(pl)) else {
            r.warnings.invalid += 1;
            continue;
        };
        let class = String::from_utf8_lossy(ty).into_owned();
        // Colour from the material (of the occurrence, or of its type) when
        // the geometry has none.
        let material = material_of
            .get(&id)
            .or_else(|| type_of.get(&id).and_then(|t| material_of.get(t)))
            .copied()
            .and_then(|m| r.material_color(m, &material_reps, 0));
        let mut pieces = r.product(shape);
        if pieces.is_empty() {
            continue;
        }
        if let Some(openings) = voids.get(&id) {
            let to_local = world.inverse();
            for &o in openings {
                let (Some(to_local), Some(mut cutter)) = (to_local, r.opening(o)) else {
                    continue;
                };
                for c in &mut cutter {
                    c.mesh.transform(&to_local);
                }
                pieces = r.subtract(pieces, cutter);
            }
        }
        let to_model = Xf::scaling(r.length).mul(&world);
        let mut parts = Vec::with_capacity(pieces.len());
        for mut piece in pieces {
            piece.mesh.transform(&to_model);
            let o = *origin.get_or_insert_with(|| {
                piece.mesh.p.first().map_or([0.0; 3], |p| p.map(f64::round))
            });
            parts.push(Part {
                color: piece.color.or(material),
                positions: piece.mesh.p.iter().map(|p| math::sub(*p, o)).collect(),
                triangles: piece.mesh.t,
                solid: piece.solid,
                edges: true,
            });
        }
        // The spatial element: the container, or that of the nearest
        // aggregate that has one.
        let mut node = None;
        let mut cur = id;
        for _ in 0..32 {
            if let Some(n) = contained
                .get(&cur)
                .and_then(|s| node_of.get(s))
                .or_else(|| node_of.get(&cur).filter(|_| cur != id))
            {
                node = Some(*n);
                break;
            }
            match parent_of.get(&cur) {
                Some(&p) => cur = p,
                None => break,
            }
        }
        let element = Element {
            id,
            global_id: p[0].text().unwrap_or_default(),
            class,
            name: p.get(2).and_then(Value::text).unwrap_or_default(),
            node,
            ranges: Vec::new(),
        };
        out.add(element, parts);
    }
    out.scene.origin = origin.unwrap_or([0.0; 3]);
    let mut warnings = r.warnings;
    warnings.truncated += out.scene.warnings.truncated;
    warnings.damaged |= out.scene.warnings.damaged;
    out.scene.warnings = warnings;
    Ok(out.scene)
}
