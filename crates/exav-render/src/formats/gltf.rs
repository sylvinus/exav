//! glTF 2.0, `.gltf` and `.glb`, into a [`Scene`] with one element per
//! node that has a mesh.
//!
//! Read: the scene's node tree with its transforms (`matrix`, or
//! `translation`, `rotation` and `scale`), the meshes' triangle primitives
//! with their `POSITION`, `NORMAL`, `COLOR_0` and indices (8, 16 or 32 bits),
//! positions and normals as floats or as small integers (what
//! `KHR_mesh_quantization` says the node's scale restores), sparse accessors, and the material's `baseColorFactor`, which with
//! `COLOR_0` colours the vertices. Coordinates are returned as written: glTF
//! is Y up, in metres.
//!
//! Ignored: textures, animations, skins, morph targets, cameras, lights, the
//! alpha of a colour, and every extension. Primitives drawn as points, lines,
//! strips or fans, or compressed (`KHR_draco_mesh_compression`,
//! `EXT_meshopt_compression`), are counted in `warnings.unsupported`. A
//! primitive whose accessors do not fit the buffers is dropped and counted
//! in `warnings.invalid`.
//!
//! Nothing is fetched: a buffer behind a URI other than a base64 `data:` one
//! is [`Error::External`] if a mesh needs it. The scene's nodes must form a
//! forest, no deeper than [`MAX_DEPTH`]; a node with two parents or a cycle
//! is refused. The work is bounded: triangles looked at, instances of a
//! mesh included, are limited to a multiple of the triangle budget.

mod json;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::rc::Rc;

use json::Value;

use super::mesh::Scene;
use super::soup::{Corner, Soup};

/// Why a file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Neither a glTF document nor a GLB container.
    NotGltf,
    /// Damaged or inconsistent.
    Invalid(&'static str),
    /// A glTF this reader does not read (a version, a compression).
    Unsupported(&'static str),
    /// A mesh's data is in a file or at an address, and nothing is fetched.
    External,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotGltf => f.write_str("not a glTF file"),
            Error::Invalid(what) => write!(f, "invalid glTF file: {what}"),
            Error::Unsupported(what) => write!(f, "unsupported glTF file: {what}"),
            Error::External => f.write_str("the glTF file references external files"),
        }
    }
}

impl std::error::Error for Error {}

/// Levels of nodes below the scene's roots.
pub const MAX_DEPTH: usize = 256;

/// Elements of an accessor that has no bytes of its own to bound it.
const MAX_ZERO_COUNT: usize = 1 << 22;

/// Most triangles looked at, for each of the budget's, and in all.
const WORK_FACTOR: u64 = 4;
const WORK_CAP: u64 = 1 << 26;
const WORK_MIN: u64 = 1 << 20;

/// A 4x4 matrix, column-major as glTF writes it.
type Mat = [f64; 16];

const IDENTITY: Mat = [
    1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
];

fn mul(a: &Mat, b: &Mat) -> Mat {
    let mut m = [0.0; 16];
    for col in 0..4 {
        for row in 0..4 {
            m[col * 4 + row] = (0..4).map(|k| a[k * 4 + row] * b[col * 4 + k]).sum();
        }
    }
    m
}

fn apply(m: &Mat, p: [f64; 3]) -> [f64; 3] {
    [
        m[0] * p[0] + m[4] * p[1] + m[8] * p[2] + m[12],
        m[1] * p[0] + m[5] * p[1] + m[9] * p[2] + m[13],
        m[2] * p[0] + m[6] * p[1] + m[10] * p[2] + m[14],
    ]
}

/// The transpose of the inverse of the matrix's upper 3x3, row-major: the
/// cofactors over the determinant, which keep the sign a mirror flips.
fn normal_matrix(m: &Mat, det: f64) -> [f64; 9] {
    let a = |r: usize, c: usize| m[c * 4 + r];
    [
        a(1, 1) * a(2, 2) - a(1, 2) * a(2, 1),
        a(1, 2) * a(2, 0) - a(1, 0) * a(2, 2),
        a(1, 0) * a(2, 1) - a(1, 1) * a(2, 0),
        a(0, 2) * a(2, 1) - a(0, 1) * a(2, 2),
        a(0, 0) * a(2, 2) - a(0, 2) * a(2, 0),
        a(0, 1) * a(2, 0) - a(0, 0) * a(2, 1),
        a(0, 1) * a(1, 2) - a(0, 2) * a(1, 1),
        a(0, 2) * a(1, 0) - a(0, 0) * a(1, 2),
        a(0, 0) * a(1, 1) - a(0, 1) * a(1, 0),
    ]
    .map(|v| v / det)
}

fn rotate(n: &[f64; 9], v: [f64; 3]) -> [f64; 3] {
    [
        n[0] * v[0] + n[1] * v[1] + n[2] * v[2],
        n[3] * v[0] + n[4] * v[1] + n[5] * v[2],
        n[6] * v[0] + n[7] * v[1] + n[8] * v[2],
    ]
}

/// A linear component as an sRGB byte.
fn srgb(v: f32) -> u8 {
    let v = f64::from(v.clamp(0.0, 1.0));
    let s = if v <= 0.003_130_8 {
        12.92 * v
    } else {
        1.055 * v.powf(1.0 / 2.4) - 0.055
    };
    (s * 255.0).round() as u8
}

/// Reads at most `max_triangles`; past them the rest is left out and
/// `warnings.truncated` is 1.
pub fn read(bytes: &[u8], max_triangles: usize) -> Result<Scene, Error> {
    read_with(bytes, max_triangles, &[])
}

/// The JSON of a document and the binary chunk of a GLB file.
fn document(bytes: &[u8]) -> Result<(Value, Option<&[u8]>), Error> {
    let (json_bytes, bin) = if bytes.starts_with(b"glTF") {
        container(bytes)?
    } else {
        (bytes, None)
    };
    // A chunk may be padded with zeros.
    let end = json_bytes
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i + 1);
    let json_bytes = &json_bytes[..end];
    if !json_bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'{' || b == 0xEF)
    {
        return Err(Error::NotGltf);
    }
    let root = json::parse(json_bytes).map_err(|_| Error::NotGltf)?;
    let version = root
        .get("asset")
        .and_then(|a| a.get("version"))
        .and_then(Value::str)
        .ok_or(Error::NotGltf)?;
    if !version.starts_with("2.") {
        return Err(Error::Unsupported("version"));
    }
    Ok((root, bin))
}

/// The files the document's buffers are in, as the document writes them (a
/// relative URI, percent-encoded), in the order of the buffers: those with a
/// URI that is not a `data:` one. [`read_with`] is given what they hold.
pub fn external_buffers(bytes: &[u8]) -> Result<Vec<String>, Error> {
    let (root, _) = document(bytes)?;
    Ok(root
        .get("buffers")
        .map_or(&[][..], Value::array)
        .iter()
        .filter_map(|b| b.get("uri").and_then(Value::str))
        .filter(|u| !u.starts_with("data:"))
        .map(str::to_string)
        .collect())
}

/// [`read`], with the contents of buffer files: each `(uri, bytes)` is
/// the buffer whose `uri` is that, as written.
pub fn read_with(
    bytes: &[u8],
    max_triangles: usize,
    files: &[(&str, &[u8])],
) -> Result<Scene, Error> {
    let (root, bin) = document(bytes)?;
    let mut doc = Doc {
        buffers: buffers(&root, bin, files)?,
        root: &root,
        floats: HashMap::new(),
        indices: HashMap::new(),
        soup: Soup::new(max_triangles),
        unsupported: BTreeMap::new(),
        done: false,
        work: 0,
        max_work: (max_triangles as u64)
            .saturating_mul(WORK_FACTOR)
            .clamp(WORK_MIN, WORK_CAP),
    };
    doc.walk()?;
    let invalid = doc.soup.invalid;
    let triangles = doc.soup.triangles();
    let unsupported = std::mem::take(&mut doc.unsupported);
    let mut scene = doc.soup.finish();
    if triangles == 0 && invalid > 0 && scene.warnings.truncated == 0 {
        return Err(Error::Invalid("no mesh can be drawn"));
    }
    scene.warnings.unsupported = unsupported;
    Ok(scene)
}

/// The JSON and the first binary chunk of a GLB file.
fn container(bytes: &[u8]) -> Result<(&[u8], Option<&[u8]>), Error> {
    let word = |at: usize| -> Option<u32> {
        let b = bytes.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    };
    if word(4) != Some(2) {
        return Err(Error::Unsupported("GLB version"));
    }
    let length = word(8).ok_or(Error::Invalid("GLB header"))? as usize;
    if length < 12 || length > bytes.len() {
        return Err(Error::Invalid("GLB length"));
    }
    let (mut json, mut bin) = (None, None);
    let mut at = 12usize;
    while at < length {
        if at + 8 > length {
            return Err(Error::Invalid("GLB chunk"));
        }
        let size = word(at).ok_or(Error::Invalid("GLB chunk"))? as usize;
        let kind = word(at + 4).ok_or(Error::Invalid("GLB chunk"))?;
        let start = at + 8;
        let end = start
            .checked_add(size)
            .filter(|&e| e <= length)
            .ok_or(Error::Invalid("GLB chunk length"))?;
        let data = &bytes[start..end];
        match kind {
            0x4E4F_534A if json.is_none() => json = Some(data),
            0x004E_4942 if bin.is_none() && json.is_some() => bin = Some(data),
            _ => {}
        }
        // A chunk's length includes its padding to four bytes. Some writers
        // leave the padding out of the length, or out of the file; the next
        // chunk is where one starts that is a JSON or binary chunk.
        let padded = end
            .checked_add(3)
            .ok_or(Error::Invalid("GLB chunk length"))?
            & !3;
        let starts_chunk = |p: usize| {
            matches!(
                (word(p), word(p + 4)),
                (Some(n), Some(0x4E4F_534A | 0x004E_4942))
                    if p.saturating_add(8).saturating_add(n as usize) <= length
            )
        };
        at = if padded != end && !starts_chunk(padded) && starts_chunk(end) {
            end
        } else {
            padded
        };
    }
    Ok((json.ok_or(Error::Invalid("GLB without JSON"))?, bin))
}

enum Buffer<'a> {
    Data(Cow<'a, [u8]>),
    /// A URI that is not a `data:` one, or no data at all.
    External,
}

fn buffers<'a>(
    root: &Value,
    bin: Option<&'a [u8]>,
    files: &[(&str, &'a [u8])],
) -> Result<Vec<Buffer<'a>>, Error> {
    let mut out = Vec::new();
    for (i, b) in root
        .get("buffers")
        .map_or(&[][..], Value::array)
        .iter()
        .enumerate()
    {
        let length = b
            .get("byteLength")
            .and_then(Value::usize)
            .ok_or(Error::Invalid("buffer length"))?;
        let file = b
            .get("uri")
            .and_then(Value::str)
            .and_then(|u| files.iter().find(|(f, _)| *f == u))
            .map(|(_, d)| *d);
        let data: Cow<[u8]> = match (b.get("uri").map(Value::str), bin) {
            (None, Some(bin)) if i == 0 => Cow::Borrowed(bin),
            (Some(Some(uri)), _) if uri.starts_with("data:") => {
                let (_, payload) = uri
                    .split_once(";base64,")
                    .ok_or(Error::Invalid("data URI"))?;
                Cow::Owned(base64(payload.as_bytes()).ok_or(Error::Invalid("base64"))?)
            }
            _ => match file {
                Some(d) => Cow::Borrowed(d),
                None => {
                    out.push(Buffer::External);
                    continue;
                }
            },
        };
        if data.len() < length {
            return Err(Error::Invalid("buffer shorter than its length"));
        }
        out.push(Buffer::Data(match data {
            Cow::Borrowed(d) => Cow::Borrowed(&d[..length]),
            Cow::Owned(mut d) => {
                d.truncate(length);
                Cow::Owned(d)
            }
        }));
    }
    Ok(out)
}

/// Standard base64, padded or not.
fn base64(text: &[u8]) -> Option<Vec<u8>> {
    let text = text
        .strip_suffix(b"==")
        .or_else(|| text.strip_suffix(b"="))
        .unwrap_or(text);
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in text {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // A last symbol alone says less than a byte.
    (text.len() % 4 != 1).then_some(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Comp {
    I8,
    U8,
    I16,
    U16,
    U32,
    F32,
}

impl Comp {
    fn from(code: usize) -> Option<Comp> {
        Some(match code {
            5120 => Comp::I8,
            5121 => Comp::U8,
            5122 => Comp::I16,
            5123 => Comp::U16,
            5125 => Comp::U32,
            5126 => Comp::F32,
            _ => return None,
        })
    }

    fn size(self) -> usize {
        match self {
            Comp::I8 | Comp::U8 => 1,
            Comp::I16 | Comp::U16 => 2,
            Comp::U32 | Comp::F32 => 4,
        }
    }

    /// One component, scaled to 0..1 or -1..1 when `normalized`. `b` holds
    /// at least `size()` bytes.
    fn float(self, b: &[u8], normalized: bool) -> f32 {
        let scale = |max: f32| if normalized { max } else { 1.0 };
        let v = match self {
            Comp::I8 => f32::from(b[0] as i8) / scale(127.0),
            Comp::U8 => f32::from(b[0]) / scale(255.0),
            Comp::I16 => f32::from(i16::from_le_bytes([b[0], b[1]])) / scale(32767.0),
            Comp::U16 => f32::from(u16::from_le_bytes([b[0], b[1]])) / scale(65535.0),
            Comp::U32 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f32,
            Comp::F32 => return f32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        };
        if normalized { v.max(-1.0) } else { v }
    }
}

/// A checked run of `count` elements of `elem` bytes, `stride` apart.
struct Run<'a> {
    bytes: &'a [u8],
    stride: usize,
    elem: usize,
    count: usize,
}

impl Run<'_> {
    fn at(&self, i: usize) -> &[u8] {
        let start = i * self.stride;
        &self.bytes[start..start + self.elem]
    }
}

struct Doc<'a> {
    root: &'a Value,
    buffers: Vec<Buffer<'a>>,
    floats: HashMap<usize, Rc<Vec<f32>>>,
    indices: HashMap<usize, Rc<Vec<u32>>>,
    soup: Soup,
    unsupported: BTreeMap<String, u32>,
    done: bool,
    work: u64,
    max_work: u64,
}

/// What a primitive draws with.
struct Prim {
    position: Rc<Vec<f32>>,
    normal: Option<Rc<Vec<f32>>>,
    /// And its components, 3 or 4.
    color: Option<(Rc<Vec<f32>>, usize)>,
    indices: Option<Rc<Vec<u32>>>,
    /// Linear, from the material.
    factor: [f32; 3],
}

fn optional(v: Option<&Value>) -> Result<usize, Error> {
    v.map_or(Ok(0), |v| v.usize().ok_or(Error::Invalid("offset")))
}

impl<'a> Doc<'a> {
    fn list(&self, key: &str) -> &'a [Value] {
        self.root.get(key).map_or(&[][..], Value::array)
    }

    fn unsupported(&mut self, what: &str) {
        let n = self.unsupported.entry(what.to_string()).or_insert(0);
        *n = n.saturating_add(1);
    }

    /// Charges `n` triangles looked at; false once the work is spent.
    fn charge(&mut self, n: u64) -> bool {
        self.work = self.work.saturating_add(n);
        if self.work > self.max_work {
            self.soup.truncated = true;
            self.done = true;
            return false;
        }
        true
    }

    /// `count` elements of `elem` bytes at `offset` in a buffer view,
    /// `stride` apart (the view's, if none is given), checked against the
    /// view and the buffer.
    fn run(
        &self,
        view: usize,
        offset: usize,
        elem: usize,
        count: usize,
        stride: Option<usize>,
    ) -> Result<Run<'_>, Error> {
        let bad = Error::Invalid("accessor out of bounds");
        let v = self.list("bufferViews").get(view).ok_or(bad.clone())?;
        if v.get("extensions")
            .is_some_and(|e| e.get("EXT_meshopt_compression").is_some())
        {
            return Err(Error::Unsupported("EXT_meshopt_compression"));
        }
        let buffer = v.get("buffer").and_then(Value::usize).ok_or(bad.clone())?;
        let data = match self.buffers.get(buffer) {
            Some(Buffer::Data(data)) => data,
            Some(Buffer::External) => return Err(Error::External),
            None => return Err(bad),
        };
        let start = optional(v.get("byteOffset"))?;
        let length = v
            .get("byteLength")
            .and_then(Value::usize)
            .ok_or(bad.clone())?;
        let stride = match (stride, v.get("byteStride")) {
            (Some(s), _) => s,
            (None, Some(s)) => s.usize().ok_or(bad.clone())?,
            (None, None) => elem,
        };
        if stride < elem {
            return Err(bad);
        }
        // In u64, so that a 32-bit build agrees with a 64-bit one.
        let used = match count as u64 {
            0 => 0,
            n => (n - 1)
                .checked_mul(stride as u64)
                .and_then(|s| s.checked_add(elem as u64))
                .ok_or(bad.clone())?,
        };
        let last = (offset as u64).checked_add(used).ok_or(bad.clone())?;
        let end = (start as u64)
            .checked_add(length as u64)
            .ok_or(bad.clone())?;
        if last > length as u64 || end > data.len() as u64 {
            return Err(bad);
        }
        // Each is within the buffer now.
        let from = start + offset;
        Ok(Run {
            bytes: &data[from..from + used as usize],
            stride,
            elem,
            count,
        })
    }

    /// An accessor's components as floats, `count * width` of them.
    fn floats(&mut self, index: usize, widths: &[usize]) -> Result<(Rc<Vec<f32>>, usize), Error> {
        let a = self
            .list("accessors")
            .get(index)
            .ok_or(Error::Invalid("accessor index"))?;
        let width = match a.get("type").and_then(Value::str) {
            Some("SCALAR") => 1,
            Some("VEC2") => 2,
            Some("VEC3") => 3,
            Some("VEC4") => 4,
            _ => return Err(Error::Invalid("accessor type")),
        };
        let comp = a
            .get("componentType")
            .and_then(Value::usize)
            .and_then(Comp::from)
            .ok_or(Error::Invalid("component type"))?;
        if !widths.contains(&width) {
            return Err(Error::Invalid("accessor type"));
        }
        if let Some(c) = self.floats.get(&index) {
            return Ok((c.clone(), width));
        }
        let normalized = matches!(a.get("normalized"), Some(Value::Bool(true)));
        let count = a
            .get("count")
            .and_then(Value::usize)
            .ok_or(Error::Invalid("accessor count"))?;
        let offset = optional(a.get("byteOffset"))?;
        let elem = width * comp.size();
        let mut out: Vec<f32>;
        match a.get("bufferView") {
            Some(view) => {
                let view = view.usize().ok_or(Error::Invalid("bufferView"))?;
                let run = self.run(view, offset, elem, count, None)?;
                out = Vec::with_capacity(count * width);
                for i in 0..run.count {
                    let e = run.at(i);
                    for k in 0..width {
                        out.push(comp.float(&e[k * comp.size()..], normalized));
                    }
                }
            }
            None => {
                if count > MAX_ZERO_COUNT {
                    return Err(Error::Invalid("accessor count"));
                }
                out = vec![0.0; count * width];
            }
        }
        if let Some(s) = a.get("sparse") {
            let bad = Error::Invalid("sparse accessor");
            let n = s.get("count").and_then(Value::usize).ok_or(bad.clone())?;
            if n > count {
                return Err(bad);
            }
            let ix = s.get("indices").ok_or(bad.clone())?;
            let vx = s.get("values").ok_or(bad.clone())?;
            let ix_comp = ix
                .get("componentType")
                .and_then(Value::usize)
                .and_then(Comp::from)
                .filter(|c| matches!(c, Comp::U8 | Comp::U16 | Comp::U32))
                .ok_or(bad.clone())?;
            let view_of = |v: &Value| {
                v.get("bufferView")
                    .and_then(Value::usize)
                    .ok_or(bad.clone())
            };
            let positions = self.run(
                view_of(ix)?,
                optional(ix.get("byteOffset"))?,
                ix_comp.size(),
                n,
                Some(ix_comp.size()),
            )?;
            let values = self.run(
                view_of(vx)?,
                optional(vx.get("byteOffset"))?,
                elem,
                n,
                Some(elem),
            )?;
            for j in 0..n {
                let p = positions.at(j);
                let target = match ix_comp {
                    Comp::U8 => usize::from(p[0]),
                    Comp::U16 => usize::from(u16::from_le_bytes([p[0], p[1]])),
                    _ => u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize,
                };
                if target >= count {
                    return Err(bad);
                }
                let e = values.at(j);
                for k in 0..width {
                    out[target * width + k] = comp.float(&e[k * comp.size()..], normalized);
                }
            }
        }
        let out = Rc::new(out);
        self.floats.insert(index, out.clone());
        Ok((out, width))
    }

    /// A SCALAR accessor of unsigned integers.
    fn index_list(&mut self, index: usize) -> Result<Rc<Vec<u32>>, Error> {
        if let Some(c) = self.indices.get(&index) {
            return Ok(c.clone());
        }
        let bad = Error::Invalid("index accessor");
        let a = self.list("accessors").get(index).ok_or(bad.clone())?;
        if a.get("type").and_then(Value::str) != Some("SCALAR") || a.get("sparse").is_some() {
            return Err(bad);
        }
        let comp = a
            .get("componentType")
            .and_then(Value::usize)
            .and_then(Comp::from)
            .filter(|c| matches!(c, Comp::U8 | Comp::U16 | Comp::U32))
            .ok_or(bad.clone())?;
        let count = a.get("count").and_then(Value::usize).ok_or(bad.clone())?;
        let offset = optional(a.get("byteOffset"))?;
        let view = a.get("bufferView").and_then(Value::usize).ok_or(bad)?;
        let run = self.run(view, offset, comp.size(), count, None)?;
        let list: Vec<u32> = (0..run.count)
            .map(|i| {
                let b = run.at(i);
                match comp {
                    Comp::U8 => u32::from(b[0]),
                    Comp::U16 => u32::from(u16::from_le_bytes([b[0], b[1]])),
                    _ => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                }
            })
            .collect();
        let list = Rc::new(list);
        self.indices.insert(index, list.clone());
        Ok(list)
    }

    /// A primitive's data; `None` where it is not drawn here.
    fn prim(&mut self, p: &Value) -> Result<Option<Prim>, Error> {
        let mode = match p.get("mode") {
            Some(m) => m.usize().ok_or(Error::Invalid("mode"))?,
            None => 4,
        };
        if mode != 4 {
            self.unsupported(match mode {
                0 => "points",
                1..=3 => "lines",
                5 => "triangle strips",
                6 => "triangle fans",
                _ => "mode",
            });
            return Ok(None);
        }
        if p.get("extensions")
            .is_some_and(|e| e.get("KHR_draco_mesh_compression").is_some())
        {
            self.unsupported("KHR_draco_mesh_compression");
            return Ok(None);
        }
        let attributes = p
            .get("attributes")
            .ok_or(Error::Invalid("primitive without attributes"))?;
        let attribute = |name: &str| attributes.get(name).and_then(Value::usize);
        let at = attribute("POSITION").ok_or(Error::Invalid("primitive without positions"))?;
        // Positions and normals may be small integers (KHR_mesh_quantization,
        // which gltfpack writes): the node's scale puts them back.
        let (position, _) = self.floats(at, &[3])?;
        let vertices = position.len() / 3;
        // A normal or a colour for another count of vertices is left out.
        let normal = attribute("NORMAL")
            .and_then(|i| self.floats(i, &[3]).ok())
            .map(|(n, _)| n)
            .filter(|n| n.len() / 3 == vertices);
        let color = attribute("COLOR_0")
            .and_then(|i| self.floats(i, &[3, 4]).ok())
            .filter(|(c, w)| c.len() / w == vertices);
        let indices = match p.get("indices") {
            Some(i) => Some(self.index_list(i.usize().ok_or(Error::Invalid("indices"))?)?),
            None => None,
        };
        let factor = p
            .get("material")
            .and_then(Value::usize)
            .and_then(|m| self.list("materials").get(m))
            .and_then(|m| m.get("pbrMetallicRoughness"))
            .and_then(|m| m.get("baseColorFactor"))
            .and_then(|f| f.numbers(4))
            .map_or([1.0; 3], |f| [f[0] as f32, f[1] as f32, f[2] as f32]);
        Ok(Some(Prim {
            position,
            normal,
            color,
            indices,
            factor,
        }))
    }

    /// Triangulates the primitives of a mesh under `world`.
    fn mesh(&mut self, mesh: usize, world: &Mat) -> Result<(), Error> {
        let primitives = self
            .list("meshes")
            .get(mesh)
            .ok_or(Error::Invalid("mesh index"))?
            .get("primitives")
            .map_or(&[][..], Value::array);
        let det = world[0] * (world[5] * world[10] - world[6] * world[9])
            - world[4] * (world[1] * world[10] - world[2] * world[9])
            + world[8] * (world[1] * world[6] - world[2] * world[5]);
        if !det.is_finite() {
            self.soup.invalid = self.soup.invalid.saturating_add(1);
            return Ok(());
        }
        // Scaled to nothing: nothing to draw.
        if det == 0.0 {
            return Ok(());
        }
        let normals = normal_matrix(world, det);
        for p in primitives {
            if !self.charge(1) {
                break;
            }
            let prim = match self.prim(p) {
                Ok(Some(prim)) => prim,
                Ok(None) => continue,
                Err(Error::External) => return Err(Error::External),
                Err(Error::Unsupported(what)) => {
                    self.unsupported(what);
                    continue;
                }
                Err(_) => {
                    self.soup.invalid = self.soup.invalid.saturating_add(1);
                    continue;
                }
            };
            let vertices = prim.position.len() / 3;
            let total = prim.indices.as_ref().map_or(vertices, |i| i.len()) / 3 * 3;
            let corner = |i: u32| -> Option<Corner> {
                let i = i as usize;
                if i >= vertices {
                    return None;
                }
                let v = &prim.position[i * 3..i * 3 + 3];
                let p = apply(world, [f64::from(v[0]), f64::from(v[1]), f64::from(v[2])]);
                let n = prim.normal.as_ref().map(|n| {
                    let n = &n[i * 3..i * 3 + 3];
                    rotate(
                        &normals,
                        [f64::from(n[0]), f64::from(n[1]), f64::from(n[2])],
                    )
                    .map(|v| v as f32)
                });
                let mut linear = prim.factor;
                let mut coloured = linear != [1.0; 3];
                if let Some((c, w)) = &prim.color {
                    for (k, l) in linear.iter_mut().enumerate() {
                        *l *= c[i * w + k];
                    }
                    coloured = true;
                }
                Some(Corner {
                    p: p.map(|v| v as f32),
                    n,
                    c: coloured.then(|| linear.map(srgb)),
                })
            };
            let mut at = 0;
            while at < total {
                if !self.charge(1) {
                    break;
                }
                let t = match &prim.indices {
                    Some(list) => [list[at], list[at + 1], list[at + 2]],
                    None => [at as u32, at as u32 + 1, at as u32 + 2],
                };
                at += 3;
                // A mirror turns the triangles inside out.
                let t = if det < 0.0 { [t[0], t[2], t[1]] } else { t };
                let [Some(a), Some(b), Some(c)] = t.map(corner) else {
                    self.soup.invalid = self.soup.invalid.saturating_add(1);
                    continue;
                };
                if !self.soup.polygon(&[a, b, c]) {
                    self.done = true;
                    break;
                }
            }
            if self.done {
                break;
            }
        }
        Ok(())
    }

    /// The matrix of a node.
    fn local(node: &Value) -> Result<Mat, Error> {
        let bad = Error::Invalid("node transform");
        if let Some(m) = node.get("matrix") {
            let v = m.numbers(16).ok_or(bad)?;
            return Ok(std::array::from_fn(|i| v[i]));
        }
        let vector = |key: &str, n: usize, default: &[f64]| -> Result<Vec<f64>, Error> {
            match node.get(key) {
                Some(v) => v.numbers(n).ok_or(Error::Invalid("node transform")),
                None => Ok(default.to_vec()),
            }
        };
        let t = vector("translation", 3, &[0.0, 0.0, 0.0])?;
        let q = vector("rotation", 4, &[0.0, 0.0, 0.0, 1.0])?;
        let s = vector("scale", 3, &[1.0, 1.0, 1.0])?;
        let len = q.iter().map(|v| v * v).sum::<f64>().sqrt();
        if !len.is_finite() {
            return Err(bad);
        }
        // All zeros is not a rotation; some exporters write it for none.
        let (x, y, z, w) = if len <= 1e-9 {
            (0.0, 0.0, 0.0, 1.0)
        } else {
            (q[0] / len, q[1] / len, q[2] / len, q[3] / len)
        };
        let r = [
            [
                1.0 - 2.0 * (y * y + z * z),
                2.0 * (x * y + z * w),
                2.0 * (x * z - y * w),
            ],
            [
                2.0 * (x * y - z * w),
                1.0 - 2.0 * (x * x + z * z),
                2.0 * (y * z + x * w),
            ],
            [
                2.0 * (x * z + y * w),
                2.0 * (y * z - x * w),
                1.0 - 2.0 * (x * x + y * y),
            ],
        ];
        let mut m = IDENTITY;
        for (c, col) in r.iter().enumerate() {
            for (row, v) in col.iter().enumerate() {
                m[c * 4 + row] = v * s[c];
            }
        }
        m[12..15].copy_from_slice(&t);
        Ok(m)
    }

    fn walk(&mut self) -> Result<(), Error> {
        let root = self.root;
        let nodes = self.list("nodes");
        let scenes = self.list("scenes");
        let roots: Vec<usize> = if scenes.is_empty() {
            let mut child = vec![false; nodes.len()];
            for n in nodes {
                for c in n.get("children").map_or(&[][..], Value::array) {
                    if let Some(i) = c.usize().filter(|&i| i < nodes.len()) {
                        child[i] = true;
                    }
                }
            }
            (0..nodes.len()).filter(|&i| !child[i]).collect()
        } else {
            let i = match root.get("scene") {
                Some(s) => s.usize().ok_or(Error::Invalid("scene"))?,
                None => 0,
            };
            scenes
                .get(i)
                .ok_or(Error::Invalid("scene"))?
                .get("nodes")
                .map_or(&[][..], Value::array)
                .iter()
                .map(|n| n.usize().ok_or(Error::Invalid("node index")))
                .collect::<Result<_, _>>()?
        };
        // Depth first, on a stack of the nodes being walked rather than by
        // recursion. The scene's roots are the children of a node of no
        // number at the bottom.
        struct Frame {
            node: Option<usize>,
            next: usize,
            world: Mat,
        }
        let mut seen = vec![false; nodes.len()];
        let mut stack = vec![Frame {
            node: None,
            next: 0,
            world: IDENTITY,
        }];
        while let Some(top) = stack.last_mut() {
            let next = match top.node {
                None => roots.get(top.next).map(|&i| Ok(i)),
                Some(n) => nodes[n]
                    .get("children")
                    .map_or(&[][..], Value::array)
                    .get(top.next)
                    .map(|c| c.usize().ok_or(Error::Invalid("child index"))),
            };
            let Some(next) = next else {
                stack.pop();
                continue;
            };
            top.next += 1;
            let parent = top.world;
            if self.done {
                break;
            }
            let index = next?;
            let node = nodes.get(index).ok_or(Error::Invalid("node index"))?;
            if std::mem::replace(&mut seen[index], true) {
                return Err(Error::Invalid("a node with two parents, or a cycle"));
            }
            // The root below counts as a level.
            if stack.len() > MAX_DEPTH {
                return Err(Error::Invalid("nodes nested too deep"));
            }
            let world = mul(&parent, &Self::local(node)?);
            if let Some(m) = node.get("mesh") {
                let m = m.usize().ok_or(Error::Invalid("mesh index"))?;
                let name = node
                    .get("name")
                    .or_else(|| self.list("meshes").get(m).and_then(|m| m.get("name")))
                    .and_then(Value::str)
                    .unwrap_or("");
                self.soup.begin(name);
                self.mesh(m, &world)?;
            }
            stack.push(Frame {
                node: Some(index),
                next: 0,
                world,
            });
        }
        Ok(())
    }
}
