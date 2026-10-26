//! Stanford PLY into a [`Scene`] of one element, ASCII or binary in either
//! byte order.
//!
//! Read: the `vertex` element's `x y z` (`z` is 0 when absent), `nx ny nz`
//! and colours (`red green blue`, or `r g b`; alpha is ignored), and the
//! `face` element's list of vertex indices (`vertex_indices` or
//! `vertex_index`) of any count and index type, triangulated as [`Soup`]
//! does. Every other element and
//! property is skipped by its declared type. A byte colour is used as is; a
//! 16-bit one is scaled down; a float one is taken as 0..1.
//!
//! A file without faces is a point cloud, which the scene cannot hold: it is
//! an [`Error::Unsupported`]. A face with an index past the vertices is
//! dropped and counted in `warnings.invalid`. Counts the data does not hold
//! are cut to what it holds, with `warnings.damaged`.
//!
//! The file has no up axis: coordinates are returned as written.

use std::fmt;

use super::mesh::Scene;
use super::soup::{number, Corner, Soup};

/// Why a file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No PLY header.
    NotPly,
    /// A PLY file this reader does not draw: a point cloud, or a format
    /// other than ascii and binary.
    Unsupported(&'static str),
    /// A header or a mesh that cannot be read.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotPly => f.write_str("not a PLY file"),
            Error::Unsupported(what) => write!(f, "unsupported PLY file: {what}"),
            Error::Invalid(what) => write!(f, "invalid PLY file: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// A header longer than this is not one.
const MAX_HEADER: usize = 64 * 1024;
const MAX_ELEMENTS: usize = 32;
const MAX_PROPS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    F32,
    F64,
}

impl Ty {
    fn parse(name: &str) -> Option<Ty> {
        Some(match name {
            "char" | "int8" => Ty::I8,
            "uchar" | "uint8" => Ty::U8,
            "short" | "int16" => Ty::I16,
            "ushort" | "uint16" => Ty::U16,
            "int" | "int32" => Ty::I32,
            "uint" | "uint32" => Ty::U32,
            "float" | "float32" => Ty::F32,
            "double" | "float64" => Ty::F64,
            _ => return None,
        })
    }

    fn size(self) -> usize {
        match self {
            Ty::I8 | Ty::U8 => 1,
            Ty::I16 | Ty::U16 => 2,
            Ty::I32 | Ty::U32 | Ty::F32 => 4,
            Ty::F64 => 8,
        }
    }

    /// A colour value as a byte.
    fn byte(self, v: f64) -> u8 {
        let scaled = match self {
            Ty::F32 | Ty::F64 => v * 255.0,
            Ty::I16 | Ty::U16 => v / 257.0,
            _ => v,
        };
        scaled.clamp(0.0, 255.0).round() as u8
    }
}

struct Prop {
    name: String,
    ty: Ty,
    /// The type of the count, for a list.
    count: Option<Ty>,
}

struct Element {
    name: String,
    count: u64,
    props: Vec<Prop>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Ascii,
    Little,
    Big,
}

struct Header {
    format: Format,
    elements: Vec<Element>,
    /// Where the data starts.
    body: usize,
}

fn header(bytes: &[u8]) -> Result<Header, Error> {
    if !bytes.starts_with(b"ply\n") && !bytes.starts_with(b"ply\r\n") {
        return Err(Error::NotPly);
    }
    let window = &bytes[..bytes.len().min(MAX_HEADER)];
    let mut format = None;
    let mut elements: Vec<Element> = Vec::new();
    let mut at = 0;
    for line in window.split_inclusive(|&b| b == b'\n') {
        at += line.len();
        if !line.ends_with(b"\n") {
            return Err(Error::NotPly);
        }
        let text = std::str::from_utf8(line).map_err(|_| Error::NotPly)?;
        // The `{ ... }` remarks of the format's own example are not words.
        let text = match (text.find('{'), text.rfind('}')) {
            (Some(a), Some(b)) if a < b => format!("{} {}", &text[..a], &text[b + 1..]),
            _ => text.to_string(),
        };
        let words: Vec<&str> = text.split_ascii_whitespace().collect();
        match words.as_slice() {
            ["ply"] | ["comment", ..] | ["obj_info", ..] | [] => {}
            ["format", name, _version] => {
                format = Some(match *name {
                    "ascii" => Format::Ascii,
                    "binary_little_endian" => Format::Little,
                    "binary_big_endian" => Format::Big,
                    _ => return Err(Error::Unsupported("format")),
                });
            }
            ["element", name, count] => {
                if elements.len() >= MAX_ELEMENTS {
                    return Err(Error::Invalid("too many elements"));
                }
                elements.push(Element {
                    name: (*name).to_string(),
                    count: count.parse().map_err(|_| Error::Invalid("element count"))?,
                    props: Vec::new(),
                });
            }
            ["property", "list", count, ty, name] => {
                let el = elements
                    .last_mut()
                    .ok_or(Error::Invalid("property before element"))?;
                if el.props.len() >= MAX_PROPS {
                    return Err(Error::Invalid("too many properties"));
                }
                el.props.push(Prop {
                    name: (*name).to_string(),
                    ty: Ty::parse(ty).ok_or(Error::Invalid("property type"))?,
                    count: Some(Ty::parse(count).ok_or(Error::Invalid("property type"))?),
                });
            }
            ["property", ty, name] => {
                let el = elements
                    .last_mut()
                    .ok_or(Error::Invalid("property before element"))?;
                if el.props.len() >= MAX_PROPS {
                    return Err(Error::Invalid("too many properties"));
                }
                el.props.push(Prop {
                    name: (*name).to_string(),
                    ty: Ty::parse(ty).ok_or(Error::Invalid("property type"))?,
                    count: None,
                });
            }
            ["end_header"] => {
                return Ok(Header {
                    format: format.ok_or(Error::Invalid("no format line"))?,
                    elements,
                    body: at,
                });
            }
            // A line of text of a writer's own: Blender 2.4 wrote one, and
            // some converters leave no space after `comment`.
            [first, ..] if !matches!(*first, "format" | "element" | "property" | "end_header") => {}
            _ => return Err(Error::Invalid("header line")),
        }
    }
    Err(Error::NotPly)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    format: Format,
    /// An ASCII record is a line: values past what the header declares, up to
    /// the end of the line, are left out.
    by_line: bool,
}

impl Cursor<'_> {
    /// The end of a record.
    fn end_record(&mut self) {
        if self.by_line && self.format == Format::Ascii {
            let rest = &self.data[self.pos..];
            self.pos += rest
                .iter()
                .position(|&b| b == b'\n')
                .map_or(rest.len(), |n| n + 1);
        }
    }

    fn scalar(&mut self, ty: Ty) -> Option<f64> {
        if self.format == Format::Ascii {
            let rest = &self.data[self.pos..];
            let start = rest.iter().position(|b| !b.is_ascii_whitespace())?;
            let len = rest[start..]
                .iter()
                .position(|b| b.is_ascii_whitespace())
                .unwrap_or(rest.len() - start);
            self.pos += start + len;
            return number(&rest[start..start + len]);
        }
        let end = self.pos.checked_add(ty.size())?;
        let b = self.data.get(self.pos..end)?;
        self.pos = end;
        let big = self.format == Format::Big;
        macro_rules! num {
            ($t:ty) => {{
                let a = b.try_into().ok()?;
                f64::from(if big {
                    <$t>::from_be_bytes(a)
                } else {
                    <$t>::from_le_bytes(a)
                })
            }};
        }
        Some(match ty {
            Ty::I8 => f64::from(b[0] as i8),
            Ty::U8 => f64::from(b[0]),
            Ty::I16 => num!(i16),
            Ty::U16 => num!(u16),
            Ty::I32 => num!(i32),
            Ty::U32 => num!(u32),
            Ty::F32 => num!(f32),
            Ty::F64 => num!(f64),
        })
    }

    /// Values of this type the data may still hold.
    fn left(&self, ty: Ty) -> usize {
        let rest = self.data.len() - self.pos;
        if self.format == Format::Ascii {
            rest
        } else {
            rest / ty.size()
        }
    }
}

/// Reads one record of `el`: its scalars into `values` (by property), and
/// the items of the list `keep` into `list`. False when the data ends or a
/// count is not one.
fn record(
    cur: &mut Cursor,
    el: &Element,
    values: &mut [f64],
    keep: Option<usize>,
    list: &mut Vec<f64>,
) -> bool {
    for (i, p) in el.props.iter().enumerate() {
        let Some(count) = p.count else {
            let Some(v) = cur.scalar(p.ty) else {
                return false;
            };
            values[i] = v;
            continue;
        };
        let Some(n) = cur.scalar(count) else {
            return false;
        };
        if !(n >= 0.0 && n.fract() == 0.0 && n <= cur.left(p.ty) as f64) {
            return false;
        }
        if keep == Some(i) {
            list.clear();
        }
        for _ in 0..n as usize {
            let Some(v) = cur.scalar(p.ty) else {
                return false;
            };
            if keep == Some(i) {
                list.push(v);
            }
        }
    }
    cur.end_record();
    true
}

/// How many records of `el` the data can hold, and whether it holds fewer
/// than declared.
fn records(cur: &Cursor, el: &Element) -> (usize, bool) {
    let each: usize = if cur.format == Format::Ascii {
        el.props.len()
    } else {
        el.props
            .iter()
            .map(|p| p.count.map_or(p.ty.size(), Ty::size))
            .sum()
    };
    let room = (cur.data.len() - cur.pos) / each.max(1);
    let declared = usize::try_from(el.count).unwrap_or(usize::MAX);
    (declared.min(room), declared > room)
}

/// Reads at most `max_triangles`; past them the rest is left out and
/// `warnings.truncated` is 1.
///
/// An ASCII file is a stream of values, and a record can run over lines. A
/// file that reads as damaged or with faces past the vertices may instead have
/// lines with more values than its header declares (a writer's extra
/// columns); it is read again a line to a record, and that is kept if it is
/// the better reading.
pub fn read(bytes: &[u8], max_triangles: usize) -> Result<Scene, Error> {
    let first = read_records(bytes, max_triangles, false);
    let dirty = match &first {
        Ok(scene) => scene.warnings.damaged || scene.warnings.invalid > 0,
        Err(error) => matches!(error, Error::Invalid(_)),
    };
    if dirty && header(bytes).is_ok_and(|h| h.format == Format::Ascii) {
        if let Ok(lines) = read_records(bytes, max_triangles, true) {
            let clean = !lines.warnings.damaged && lines.warnings.invalid == 0;
            let better = match &first {
                Err(_) => true,
                Ok(f) => clean || lines.triangles() > f.triangles(),
            };
            if better {
                return Ok(lines);
            }
        }
    }
    first
}

fn read_records(bytes: &[u8], max_triangles: usize, by_line: bool) -> Result<Scene, Error> {
    let head = header(bytes)?;
    let mut cur = Cursor {
        data: bytes,
        pos: head.body,
        format: head.format,
        by_line,
    };
    let mut damaged = false;
    let mut vertices: Option<Vertices> = None;
    let mut soup = Soup::new(max_triangles);
    let mut had_faces = false;
    let mut unsupported = std::collections::BTreeMap::<String, u32>::new();

    for el in &head.elements {
        if el.props.is_empty() {
            continue;
        }
        let (count, short) = records(&cur, el);
        damaged |= short;
        match el.name.as_str() {
            "vertex" if vertices.is_none() => {
                let v = vertex_data(&mut cur, el, count)?;
                damaged |= v.short;
                vertices = Some(v);
            }
            // An empty list of faces may come first.
            "face" if vertices.is_none() && count == 0 => {}
            "face" => {
                let Some(v) = &vertices else {
                    return Err(Error::Invalid("faces before vertices"));
                };
                had_faces |= count > 0;
                damaged |= faces(&mut cur, el, count, v, &mut soup);
                break;
            }
            name => {
                if name.starts_with("tristrips") {
                    unsupported.insert(name.to_string(), 1);
                }
                let mut values = vec![0.0; el.props.len()];
                let mut scratch = Vec::new();
                for _ in 0..count {
                    if !record(&mut cur, el, &mut values, None, &mut scratch) {
                        damaged = true;
                        break;
                    }
                }
            }
        }
    }
    if vertices.is_none() {
        return Err(Error::Invalid("no vertex element"));
    }
    if soup.triangles() == 0 && !soup.truncated {
        return Err(if had_faces || soup.invalid > 0 {
            Error::Invalid("no face can be drawn")
        } else {
            Error::Unsupported("a point cloud has no faces to draw")
        });
    }
    let mut scene = soup.finish();
    scene.warnings.damaged = damaged;
    scene.warnings.unsupported = unsupported;
    Ok(scene)
}

struct Vertices {
    positions: Vec<[f32; 3]>,
    normals: Option<Vec<[f32; 3]>>,
    colors: Option<Vec<[u8; 3]>>,
    short: bool,
}

fn vertex_data(cur: &mut Cursor, el: &Element, count: usize) -> Result<Vertices, Error> {
    let find = |names: &[&str]| {
        el.props
            .iter()
            .position(|p| p.count.is_none() && names.contains(&p.name.as_str()))
    };
    // A flat drawing has no z.
    let (Some(x), Some(y), z) = (find(&["x"]), find(&["y"]), find(&["z"])) else {
        return Err(Error::Invalid("vertices without x and y"));
    };
    let normal = match (find(&["nx"]), find(&["ny"]), find(&["nz"])) {
        (Some(a), Some(b), Some(c)) => Some([a, b, c]),
        _ => None,
    };
    let color = match (
        find(&["red", "r", "diffuse_red"]),
        find(&["green", "g", "diffuse_green"]),
        find(&["blue", "b", "diffuse_blue"]),
    ) {
        (Some(a), Some(b), Some(c)) => Some([a, b, c]),
        _ => None,
    };
    // The count is bounded by the data, but a vertex can be one byte of it.
    let room = count.min(1 << 16);
    let mut out = Vertices {
        positions: Vec::with_capacity(room),
        normals: normal.map(|_| Vec::with_capacity(room)),
        colors: color.map(|_| Vec::with_capacity(room)),
        short: false,
    };
    let mut values = vec![0.0; el.props.len()];
    let mut scratch = Vec::new();
    for _ in 0..count {
        if !record(cur, el, &mut values, None, &mut scratch) {
            out.short = true;
            break;
        }
        // `as f32` makes infinity of what is too large: dropped later.
        out.positions.push([
            values[x] as f32,
            values[y] as f32,
            z.map_or(0.0, |z| values[z] as f32),
        ]);
        if let (Some([a, b, c]), Some(n)) = (normal, out.normals.as_mut()) {
            n.push([values[a] as f32, values[b] as f32, values[c] as f32]);
        }
        if let (Some(k), Some(col)) = (color, out.colors.as_mut()) {
            col.push(k.map(|i| el.props[i].ty.byte(values[i])));
        }
    }
    Ok(out)
}

/// Triangulates the faces into `soup`; true when the data ended early.
fn faces(cur: &mut Cursor, el: &Element, count: usize, v: &Vertices, soup: &mut Soup) -> bool {
    let Some(keep) = el.props.iter().position(|p| {
        p.count.is_some() && (p.name == "vertex_indices" || p.name == "vertex_index")
    }) else {
        soup.invalid = soup.invalid.saturating_add(1);
        return false;
    };
    let mut values = vec![0.0; el.props.len()];
    let mut list: Vec<f64> = Vec::new();
    let mut corners: Vec<Corner> = Vec::new();
    for _ in 0..count {
        if !record(cur, el, &mut values, Some(keep), &mut list) {
            return true;
        }
        corners.clear();
        let mut valid = true;
        for &i in &list {
            let at = (i >= 0.0 && i.fract() == 0.0 && i < v.positions.len() as f64)
                .then_some(i as usize);
            let Some(at) = at else {
                valid = false;
                break;
            };
            corners.push(Corner {
                p: v.positions[at],
                n: v.normals.as_ref().map(|n| n[at]),
                c: v.colors.as_ref().map(|c| c[at]),
            });
        }
        if !valid {
            soup.invalid = soup.invalid.saturating_add(1);
        } else if !soup.polygon(&corners) {
            return false;
        }
    }
    false
}
