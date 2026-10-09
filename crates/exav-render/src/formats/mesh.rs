//! Triangle meshes ready for a GPU, the output of the IFC and STL readers.
//!
//! A [`Scene`] holds its triangles in [`Batch`]es, one per class and colour,
//! so that a renderer draws a model in few calls; each [`Element`] says
//! which index ranges of which batches are its own, for picking and
//! highlighting. Positions are `f32` relative to [`Scene::origin`], which
//! keeps a georeferenced model, kilometres from zero, precise to the
//! millimetre. Z is up.

// The scene builder (welding, smoothing, outlines) is the IFC reader's; STL
// fills its one batch itself.
#![cfg_attr(not(feature = "ifc"), allow(dead_code))]

use std::collections::{BTreeMap, HashMap};

/// What a reader produced.
#[derive(Debug, Default, Clone)]
pub struct Scene {
    /// Added to every position to give model coordinates: metres for IFC,
    /// the file's own unit for STL.
    pub origin: [f64; 3],
    pub batches: Vec<Batch>,
    pub elements: Vec<Element>,
    /// The spatial structure (IFC: project, site, building, storeys),
    /// parents before their children.
    pub nodes: Vec<Node>,
    /// Smallest and largest corner of the triangles, relative to `origin`.
    pub bounds: Option<[[f32; 3]; 2]>,
    pub warnings: Warnings,
}

impl Scene {
    /// Triangles in all batches.
    pub fn triangles(&self) -> usize {
        self.batches.iter().map(|b| b.indices.len() / 3).sum()
    }
}

/// Triangles of one class and colour.
#[derive(Debug, Default, Clone)]
pub struct Batch {
    /// The IFC class as the file writes it (`IFCWALL`); empty for STL.
    pub class: String,
    /// RGBA in 0..1 as the file gives it (sRGB); `None` when the file gives
    /// no colour, which leaves the choice to the renderer.
    pub color: Option<[f32; 4]>,
    /// xyz per vertex.
    pub positions: Vec<f32>,
    /// Unit xyz per vertex.
    pub normals: Vec<f32>,
    /// Three per triangle, into this batch's vertices.
    pub indices: Vec<u32>,
    /// RGB per vertex, when the file colours facets one by one (STL).
    pub colors: Option<Vec<u8>>,
    /// Pairs of xyz: the creases and the open borders, for an outline.
    pub edges: Vec<f32>,
}

/// One drawn object.
#[derive(Debug, Default, Clone)]
pub struct Element {
    /// The STEP instance number (`#123`); 0 for STL.
    pub id: u32,
    /// IFC GlobalId.
    pub global_id: String,
    pub class: String,
    pub name: String,
    /// Index into [`Scene::nodes`] of the spatial element that contains it.
    pub node: Option<u32>,
    pub ranges: Vec<Range>,
}

/// A run of triangles in a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub batch: u32,
    /// First index (a multiple of 3) in [`Batch::indices`].
    pub first: u32,
    /// Number of indices.
    pub count: u32,
}

/// A spatial structure element.
#[derive(Debug, Default, Clone)]
pub struct Node {
    pub id: u32,
    pub class: String,
    pub name: String,
    pub parent: Option<u32>,
}

/// What could not be drawn, counted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Warnings {
    /// Representation items of a class the reader does not draw, by class.
    pub unsupported: BTreeMap<String, u32>,
    /// Items whose data was unusable (a broken reference, a degenerate
    /// profile, a loop in the references).
    pub invalid: u32,
    /// Boolean operations given up (too large, or failed); their first
    /// operand is drawn as is.
    pub booleans_skipped: u32,
    /// Elements left out once the triangle budget was spent.
    pub truncated: u32,
    /// The file ends early or has unreadable records.
    pub damaged: bool,
}

/// Most triangles a scene may hold by default: about 330 MB of buffers.
pub const DEFAULT_MAX_TRIANGLES: usize = 6_000_000;

/// Faces meeting at a smaller angle are shaded smooth and not outlined.
pub(crate) const CREASE_DEGREES: f64 = 30.0;

/// Faces around a vertex averaged for its smooth normal. Each corner is
/// compared with every face at its vertex, so the work for a fan of `n` faces
/// around one vertex is `n` squared; real meshes have a few to a few dozen
/// there. Past the window the face's own normal is added and the rest
/// left out.
const MAX_SHADED_FACES: usize = 256;

/// One coloured mesh of an element, in model coordinates relative to the
/// scene origin.
pub(crate) struct Part {
    pub color: Option<[f32; 4]>,
    pub positions: Vec<[f64; 3]>,
    pub triangles: Vec<[u32; 3]>,
    /// A closed solid: its open borders are artefacts, not outlines.
    pub solid: bool,
    /// Collect outline edges.
    pub edges: bool,
}

/// Builds a [`Scene`] element by element within a triangle budget.
pub(crate) struct SceneBuilder {
    pub scene: Scene,
    batches: HashMap<(String, Option<[u32; 4]>), u32>,
    pub budget: usize,
}

impl SceneBuilder {
    pub fn new(max_triangles: usize) -> Self {
        Self {
            scene: Scene::default(),
            batches: HashMap::new(),
            budget: max_triangles,
        }
    }

    fn batch(&mut self, class: &str, color: Option<[f32; 4]>) -> u32 {
        let key = (class.to_string(), color.map(|c| c.map(f32::to_bits)));
        if let Some(&i) = self.batches.get(&key) {
            return i;
        }
        let i = self.scene.batches.len() as u32;
        self.scene.batches.push(Batch {
            class: class.to_string(),
            color,
            ..Batch::default()
        });
        self.batches.insert(key, i);
        i
    }

    /// Adds an element with its parts. False (and nothing added) once the
    /// budget cannot hold it.
    pub fn add(&mut self, mut element: Element, parts: Vec<Part>) -> bool {
        let total: usize = parts.iter().map(|p| p.triangles.len()).sum();
        if total > self.budget {
            self.scene.warnings.truncated = self.scene.warnings.truncated.saturating_add(1);
            return false;
        }
        for part in parts {
            let finished = finish(&part);
            if finished.indices.is_empty() {
                continue;
            }
            self.budget -= finished.indices.len() / 3;
            let b = self.batch(&element.class, part.color);
            let batch = &mut self.scene.batches[b as usize];
            let base = (batch.positions.len() / 3) as u32;
            let first = batch.indices.len() as u32;
            batch
                .indices
                .extend(finished.indices.iter().map(|i| i + base));
            batch.positions.extend_from_slice(&finished.positions);
            batch.normals.extend_from_slice(&finished.normals);
            batch.edges.extend_from_slice(&finished.edges);
            grow(&mut self.scene.bounds, &finished.positions);
            match element.ranges.last_mut() {
                Some(r) if r.batch == b && r.first + r.count == first => {
                    r.count += finished.indices.len() as u32
                }
                _ => element.ranges.push(Range {
                    batch: b,
                    first,
                    count: finished.indices.len() as u32,
                }),
            }
        }
        if !element.ranges.is_empty() {
            self.scene.elements.push(element);
        }
        true
    }
}

pub(crate) fn grow(bounds: &mut Option<[[f32; 3]; 2]>, positions: &[f32]) {
    for p in positions.as_chunks::<3>().0 {
        let b = bounds.get_or_insert([[p[0], p[1], p[2]], [p[0], p[1], p[2]]]);
        for k in 0..3 {
            b[0][k] = b[0][k].min(p[k]);
            b[1][k] = b[1][k].max(p[k]);
        }
    }
}

/// A part's buffers.
struct Finished {
    positions: Vec<f32>,
    normals: Vec<f32>,
    indices: Vec<u32>,
    edges: Vec<f32>,
}

pub(crate) fn sub(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

pub(crate) fn cross(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

pub(crate) fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

/// Welds coincident vertices, shades faces smooth across shallow angles and
/// flat across creases, and collects the creases (and a surface's open
/// borders) as outline segments.
fn finish(part: &Part) -> Finished {
    let pos = &part.positions;
    // Triangles with three valid, distinct corners and an area.
    let mut tris: Vec<[u32; 3]> = Vec::with_capacity(part.triangles.len());
    let mut face_n: Vec<[f64; 3]> = Vec::with_capacity(part.triangles.len());
    for &t in &part.triangles {
        let (Some(&a), Some(&b), Some(&c)) = (
            pos.get(t[0] as usize),
            pos.get(t[1] as usize),
            pos.get(t[2] as usize),
        ) else {
            continue;
        };
        if !(a.iter().chain(&b).chain(&c).all(|v| v.is_finite())) {
            continue;
        }
        let n = cross(sub(b, a), sub(c, a));
        let len = dot(n, n).sqrt();
        if !len.is_finite() || len <= 0.0 {
            continue;
        }
        tris.push(t);
        face_n.push([n[0] / len, n[1] / len, n[2] / len]);
    }
    // Weld by position, on a grid fine relative to the part's size.
    let mut lo = [f64::INFINITY; 3];
    let mut hi = [f64::NEG_INFINITY; 3];
    for t in &tris {
        for &i in t {
            let p = pos[i as usize];
            for k in 0..3 {
                lo[k] = lo[k].min(p[k]);
                hi[k] = hi[k].max(p[k]);
            }
        }
    }
    let extent = (0..3).map(|k| hi[k] - lo[k]).fold(0.0f64, f64::max);
    let q = (extent * 1e-7).max(1e-9);
    let mut weld: HashMap<[i64; 3], u32> = HashMap::new();
    let mut welded_pos: Vec<[f64; 3]> = Vec::new();
    let mut corner_w: Vec<[u32; 3]> = Vec::with_capacity(tris.len());
    for t in &tris {
        let mut w = [0u32; 3];
        for (k, &i) in t.iter().enumerate() {
            let p = pos[i as usize];
            let key = [
                ((p[0] - lo[0]) / q).round() as i64,
                ((p[1] - lo[1]) / q).round() as i64,
                ((p[2] - lo[2]) / q).round() as i64,
            ];
            w[k] = *weld.entry(key).or_insert_with(|| {
                welded_pos.push(p);
                (welded_pos.len() - 1) as u32
            });
        }
        corner_w.push(w);
    }
    // Triangles collapsed by the weld.
    let keep: Vec<usize> = (0..tris.len())
        .filter(|&i| {
            let w = corner_w[i];
            w[0] != w[1] && w[1] != w[2] && w[0] != w[2]
        })
        .collect();
    // Triangles around each welded vertex (CSR).
    let nv = welded_pos.len();
    let mut start = vec![0u32; nv + 1];
    for &i in &keep {
        for &v in &corner_w[i] {
            start[v as usize + 1] += 1;
        }
    }
    for v in 0..nv {
        start[v + 1] += start[v];
    }
    let mut fill = start.clone();
    let mut around = vec![0u32; start[nv] as usize];
    for &i in &keep {
        for &v in &corner_w[i] {
            around[fill[v as usize] as usize] = i as u32;
            fill[v as usize] += 1;
        }
    }
    let cos_crease = CREASE_DEGREES.to_radians().cos();
    let mut out = Finished {
        positions: Vec::new(),
        normals: Vec::new(),
        indices: Vec::with_capacity(keep.len() * 3),
        edges: Vec::new(),
    };
    let mut vmap: HashMap<(u32, [i32; 3]), u32> = HashMap::new();
    for &i in &keep {
        let n = face_n[i];
        for &v in &corner_w[i] {
            let mut s = [0.0f64; 3];
            let faces = &around[start[v as usize] as usize..start[v as usize + 1] as usize];
            let window = &faces[..faces.len().min(MAX_SHADED_FACES)];
            for &j in window {
                let m = face_n[j as usize];
                if dot(n, m) >= cos_crease {
                    s = [s[0] + m[0], s[1] + m[1], s[2] + m[2]];
                }
            }
            if window.len() < faces.len() && !window.contains(&(i as u32)) {
                s = [s[0] + n[0], s[1] + n[1], s[2] + n[2]];
            }
            let len = dot(s, s).sqrt();
            let sn = if len > 1e-12 {
                [s[0] / len, s[1] / len, s[2] / len]
            } else {
                n
            };
            let key = (
                v,
                [
                    (sn[0] * 1e4) as i32,
                    (sn[1] * 1e4) as i32,
                    (sn[2] * 1e4) as i32,
                ],
            );
            let next = (out.positions.len() / 3) as u32;
            let idx = *vmap.entry(key).or_insert_with(|| {
                let p = welded_pos[v as usize];
                out.positions
                    .extend_from_slice(&[p[0] as f32, p[1] as f32, p[2] as f32]);
                out.normals
                    .extend_from_slice(&[sn[0] as f32, sn[1] as f32, sn[2] as f32]);
                next
            });
            out.indices.push(idx);
        }
    }
    if !part.edges {
        return out;
    }
    // Edges: the two faces of each, or one for an open border.
    let mut edges: HashMap<(u32, u32), (u32, u32, u32)> = HashMap::new();
    for &i in &keep {
        let w = corner_w[i];
        for k in 0..3 {
            let (a, b) = (w[k], w[(k + 1) % 3]);
            let key = (a.min(b), a.max(b));
            let e = edges.entry(key).or_insert((0, i as u32, u32::MAX));
            e.0 += 1;
            if e.0 == 2 {
                e.2 = i as u32;
            }
        }
    }
    let mut keys: Vec<_> = edges.into_iter().collect();
    keys.sort_unstable_by_key(|(k, _)| *k);
    for ((a, b), (count, f, g)) in keys {
        let draw = match count {
            1 => !part.solid,
            2 => dot(face_n[f as usize], face_n[g as usize]) < cos_crease,
            _ => true,
        };
        if draw {
            let (p, r) = (welded_pos[a as usize], welded_pos[b as usize]);
            out.edges.extend_from_slice(&[
                p[0] as f32,
                p[1] as f32,
                p[2] as f32,
                r[0] as f32,
                r[1] as f32,
                r[2] as f32,
            ]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cube() -> Part {
        let p = [
            [0., 0., 0.],
            [1., 0., 0.],
            [1., 1., 0.],
            [0., 1., 0.],
            [0., 0., 1.],
            [1., 0., 1.],
            [1., 1., 1.],
            [0., 1., 1.],
        ];
        let quads = [
            [0, 3, 2, 1],
            [4, 5, 6, 7],
            [0, 1, 5, 4],
            [1, 2, 6, 5],
            [2, 3, 7, 6],
            [3, 0, 4, 7],
        ];
        let mut triangles = Vec::new();
        for q in quads {
            triangles.push([q[0], q[1], q[2]]);
            triangles.push([q[0], q[2], q[3]]);
        }
        Part {
            color: None,
            positions: p.to_vec(),
            triangles,
            solid: true,
            edges: true,
        }
    }

    #[test]
    fn a_cube_has_flat_faces_and_twelve_outline_edges() {
        let f = finish(&cube());
        assert_eq!(f.indices.len(), 36);
        // Four corners per face, each with the face's own normal.
        assert_eq!(f.positions.len() / 3, 24);
        assert_eq!(f.edges.len() / 6, 12);
    }

    /// A fan of 100,000 faces around one vertex compared each corner with
    /// every face at the vertex, ten billion dot products.
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "timing")]
    fn a_fan_of_many_faces_around_one_vertex_is_shaded_in_bounded_time() {
        let n = 100_000u32;
        let mut positions = vec![[0.0, 0.0, 0.0]];
        for k in 0..n {
            let a = f64::from(k) / f64::from(n) * std::f64::consts::TAU;
            positions.push([a.cos(), a.sin(), 0.0]);
        }
        let triangles = (0..n).map(|k| [0, 1 + k, 1 + (k + 1) % n]).collect();
        let part = Part {
            color: None,
            positions,
            triangles,
            solid: false,
            edges: false,
        };
        let t = std::time::Instant::now();
        let f = finish(&part);
        assert!(t.elapsed().as_secs() < 2, "took {:?}", t.elapsed());
        assert_eq!(f.indices.len(), 3 * n as usize);
        // A flat fan: every normal is the plane's.
        for nrm in f.normals.chunks(3) {
            assert!((nrm[2] - 1.0).abs() < 1e-5, "normal {nrm:?}");
        }
    }

    #[test]
    fn the_budget_refuses_what_it_cannot_hold() {
        let mut b = SceneBuilder::new(11);
        assert!(!b.add(Element::default(), vec![cube()]));
        assert_eq!(b.scene.warnings.truncated, 1);
        let mut b = SceneBuilder::new(12);
        assert!(b.add(Element::default(), vec![cube()]));
        assert_eq!(b.scene.triangles(), 12);
        assert_eq!(
            b.scene.elements[0].ranges,
            vec![Range {
                batch: 0,
                first: 0,
                count: 36
            }]
        );
    }
}
