//! Proxy graphics streams (ODA spec 29) into [`ProxyGraphics`], for both
//! readers: DWG keeps the stream in an entity's common data, DXF in groups
//! 92 (160 from 2010) and 310.
//!
//! The stream starts with an RL of its size in bytes and an RL count of
//! chunks (the spec begins at the chunks; every stream of the corpus and of
//! the ODA converter starts so). A chunk is an RL size, counting the size
//! and the type, an RL type and the type's data, padded to 4 bytes. Each
//! chunk is read within its size, so that a type this reader does not know
//! (extents, markers, materials, plot styles, clipping), or data shorter
//! than its type needs, costs that chunk only.
//!
//! What the spec leaves open was settled with the ODA File Converter, by
//! writing streams into ACAD_PROXY_ENTITY records of a DXF and reading what
//! it makes of them (tests/fixtures/cad/proxy/make.py); see
//! [`ProxyItem`] for each.

use exav_unpack::dwg::{Bits, Version as DwgVersion};

use super::model::*;

/// The size and count before the chunks.
const HEAD: usize = 8;

/// One chunk's data.
struct Chunk<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Chunk<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let b = self.data.get(self.at..end)?;
        self.at = end;
        Some(b)
    }

    fn left(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }

    fn rl(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn rd(&mut self) -> Option<f64> {
        Some(f64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn p3(&mut self) -> Option<Vec3> {
        Some(Vec3::new(self.rd()?, self.rd()?, self.rd()?))
    }

    /// `n` points, which must fit in what is left.
    fn points(&mut self, n: u32, max: usize) -> Option<Vec<Vec3>> {
        let n = usize::try_from(n).ok()?;
        if n > self.left() / 24 {
            return None;
        }
        let mut out = Vec::with_capacity(n.min(max));
        for _ in 0..n {
            let p = self.p3()?;
            if out.len() < max {
                out.push(p);
            }
        }
        Some(out)
    }

    /// Skip to the next multiple of 4 from the chunk's start.
    fn align(&mut self) {
        self.at = self.at.saturating_add(3) & !3;
    }

    /// PS: bytes up to a zero, padded to 4.
    fn ps(&mut self) -> Option<&'a [u8]> {
        let rest = self.data.get(self.at..)?;
        let end = rest.iter().position(|&c| c == 0)?;
        let s = rest.get(..end)?;
        self.at += end + 1;
        self.align();
        Some(s)
    }

    /// PUS: UTF-16LE up to a zero unit, padded to 4.
    fn pus(&mut self) -> Option<String> {
        let rest = self.data.get(self.at..)?;
        let (units, _) = rest.as_chunks::<2>();
        let end = units.iter().position(|u| *u == [0, 0])?;
        let s: Vec<u16> = units
            .get(..end)?
            .iter()
            .map(|u| u16::from_le_bytes(*u))
            .collect();
        self.at += end * 2 + 2;
        self.align();
        Some(String::from_utf16_lossy(&s))
    }
}

/// How strings and limits apply to a stream.
pub(crate) struct Reading<'a> {
    /// The drawing's release: embedded LWPOLYLINE data has its layout.
    pub version: DwgVersion,
    /// A PS string in the drawing's code page.
    pub decode: &'a dyn Fn(&[u8]) -> String,
    pub max_items: usize,
    pub max_string_bytes: usize,
}

/// The stream `data`, and what was wrong with it when something was.
pub(crate) fn read(data: &[u8], r: &Reading<'_>) -> (ProxyGraphics, Option<String>) {
    let mut out = ProxyGraphics::default();
    let le32 = |at: usize| -> Option<u32> {
        let b = data.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    };
    let (Some(size), Some(count)) = (le32(0), le32(4)) else {
        return (out, Some(format!("{} bytes of proxy graphics", data.len())));
    };
    let end = usize::try_from(size).map_or(data.len(), |s| s.min(data.len()));
    let mut at = HEAD;
    let mut problem = None;
    for k in 0..count {
        if at >= end {
            problem = Some(format!("proxy graphics end after {k} of {count} chunks"));
            break;
        }
        let (Some(len), Some(kind)) = (le32(at), le32(at + 4)) else {
            problem = Some(format!("proxy graphics chunk {k} is cut short"));
            break;
        };
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        let Some(body) = (len >= 8)
            .then(|| at.checked_add(len))
            .flatten()
            .filter(|e| *e <= end)
            .and_then(|e| data.get(at + 8..e))
        else {
            problem = Some(format!(
                "proxy graphics chunk {k} of {len} bytes does not fit"
            ));
            break;
        };
        at += len;
        if out.items.len() >= r.max_items {
            problem = Some(format!(
                "proxy graphics past {} items were dropped",
                r.max_items
            ));
            break;
        }
        let mut c = Chunk { data: body, at: 0 };
        match item(&mut c, kind, r) {
            Some(Some(i)) => out.items.push(i),
            Some(None) => {}
            None => {
                if problem.is_none() {
                    problem = Some(format!(
                        "proxy graphics chunk {k} of type {kind} is cut short"
                    ));
                }
            }
        }
    }
    (out, problem)
}

/// One chunk: `Some(None)` for a type that draws nothing here, `None` when
/// its data runs short.
fn item(c: &mut Chunk<'_>, kind: u32, r: &Reading<'_>) -> Option<Option<ProxyItem>> {
    let max = r.max_items;
    let i = match kind {
        2 => ProxyItem::Circle {
            center: c.p3()?,
            radius: c.rd()?,
            normal: c.p3()?,
        },
        3 => ProxyItem::Circle3P([c.p3()?, c.p3()?, c.p3()?]),
        4 => ProxyItem::Arc {
            center: c.p3()?,
            radius: c.rd()?,
            normal: c.p3()?,
            start: c.p3()?,
            sweep: c.rd()?,
            kind: ArcKind::from_code(c.rl()?),
        },
        5 => ProxyItem::Arc3P {
            points: [c.p3()?, c.p3()?, c.p3()?],
            kind: ArcKind::from_code(c.rl()?),
        },
        // Not in the spec; AutoCAD's own surfaces and Plant 3D objects have
        // it. Read as centre, normal, major and minor radius, start and end
        // parameter, the major axis' angle from the normal's X axis and an
        // arc type, each matches a polyline of the converter's R12 output.
        44 => ProxyItem::EllipticalArc(Box::new(ProxyEllipse {
            center: c.p3()?,
            normal: c.p3()?,
            major_radius: c.rd()?,
            minor_radius: c.rd()?,
            start: c.rd()?,
            end: c.rd()?,
            rotation: c.rd()?,
            kind: ArcKind::from_code(c.rl()?),
        })),
        6 => {
            let n = c.rl()?;
            ProxyItem::Polyline {
                points: c.points(n, max)?,
                normal: None,
            }
        }
        // The spec gives the normal as one RD; the converter reads three.
        32 => {
            let n = c.rl()?;
            let points = c.points(n, max)?;
            ProxyItem::Polyline {
                points,
                normal: c.p3(),
            }
        }
        7 => {
            let n = c.rl()?;
            ProxyItem::Polygon(c.points(n, max)?)
        }
        8 => ProxyItem::Mesh(Box::new(mesh(c, max)?)),
        9 => ProxyItem::Shell(Box::new(shell(c, max)?)),
        10 | 36 => {
            let mut t = text_head(c)?;
            t.height = c.rd()?;
            t.width_factor = c.rd()?;
            t.oblique = c.rd()?;
            t.value = if kind == 36 {
                c.pus()?
            } else {
                (r.decode)(c.ps()?)
            };
            ProxyItem::Text(Box::new(cut(t, r)))
        }
        11 | 38 => ProxyItem::Text(Box::new(cut(text2(c, kind == 38, r)?, r))),
        12 | 13 => ProxyItem::XLine {
            base: c.p3()?,
            through: c.p3()?,
            ray: kind == 13,
        },
        // The data is laid out as the release that wrote the stream lays it
        // out, which need not be the file's: the converter's R13 DXF keeps
        // a stream written for 2000 as it was. The file's release first,
        // then the others, the first that reads to the end of the data.
        33 => {
            let n = usize::try_from(c.rl()?).ok()?;
            let bytes = c.take(n)?;
            let mut room = |len: usize| len < max;
            let mut found = None;
            for v in [
                r.version,
                DwgVersion::R2000,
                DwgVersion::R2010,
                DwgVersion::R13,
            ] {
                let mut b = Bits::new(bytes);
                if let Ok(p) = super::dwg::lwpolyline_bits(&mut b, v, &mut room) {
                    if b.remaining() < 8 {
                        found = Some(p);
                        break;
                    }
                }
            }
            ProxyItem::LwPolyline(Box::new(found?))
        }
        // An index, or an AcCmColor with its method byte; the converter
        // keeps the colour before an index past 256.
        14 => match c.rl()? {
            v @ 0..=256 => ProxyItem::Color(Color::from_aci(i64::from(v))),
            v if (0xC0..=0xC3).contains(&(v >> 24)) => {
                ProxyItem::Color(Color::from_raw(i64::from(v)))
            }
            _ => return Some(None),
        },
        // Not the spec's RC red, green, blue: an RL AcCmColor, 0xC2RRGGBB
        // for a true colour. The converter writes 0xC2FF0000 as ACI 1 in
        // R12, and ignores a chunk of other methods.
        22 => match c.rl()? {
            v if (0xC0..=0xC3).contains(&(v >> 24)) => {
                ProxyItem::Color(Color::from_raw(i64::from(v)))
            }
            _ => return Some(None),
        },
        16 => ProxyItem::Layer(c.rl()?),
        18 => ProxyItem::Linetype(c.rl()?),
        // The spec has 0 for off; the converter fills after a 0 as after a
        // 1, and writes 2 itself where a stream turns fill off.
        20 => ProxyItem::Fill(c.rl()? != 2),
        23 => ProxyItem::LineWeight(LineWeight::from_code(i64::from(c.rl()? as i32))),
        24 => ProxyItem::LinetypeScale(c.rd()?),
        25 => ProxyItem::Thickness(c.rd()?),
        29 => {
            let mut m = [0.0; 16];
            for v in &mut m {
                *v = c.rd()?;
            }
            ProxyItem::PushTransform(Box::new(m))
        }
        // PUSH_MODELXFORM2: the converter does not read its data as the
        // spec's matrix (a translation written so moves nothing, or turns X
        // into Y), and no stream of the corpus has one. An unchanged
        // transform keeps the pops after it paired.
        30 => ProxyItem::PushTransform(Box::new([
            1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
        ])),
        31 => ProxyItem::PopTransform,
        _ => return Some(None),
    };
    Some(Some(i))
}

/// Position, normal and direction, which every text type starts with.
fn text_head(c: &mut Chunk<'_>) -> Option<ProxyText> {
    Some(ProxyText {
        position: c.p3()?,
        normal: c.p3()?,
        direction: c.p3()?,
        ..ProxyText::default()
    })
}

/// TEXT2 (11) and its Unicode form (38).
fn text2(c: &mut Chunk<'_>, unicode: bool, r: &Reading<'_>) -> Option<ProxyText> {
    let mut t = text_head(c)?;
    let mut s = if unicode {
        c.pus()?
    } else {
        (r.decode)(c.ps()?)
    };
    // The length in characters, -1 when the string ends at its zero.
    let len = c.rl()? as i32;
    if let Ok(n) = usize::try_from(len) {
        if let Some((cut, _)) = s.char_indices().nth(n) {
            s.truncate(cut);
        }
    }
    t.value = s;
    // The spec has "0 if raw, 1 if not"; the converter writes the `%%` of
    // a text with 1 as `%%%%` (literal) for R12 and leaves those of a text
    // with 0 to be read as codes.
    t.raw = c.rl()? != 0;
    t.height = c.rd()?;
    t.width_factor = c.rd()?;
    t.oblique = c.rd()?;
    c.rd()?; // tracking
    t.backwards = c.rl()? != 0;
    t.upside_down = c.rl()? != 0;
    for _ in 0..3 {
        c.rl()?; // vertical, underlined, overlined
    }
    if unicode {
        t.bold = c.rl()? != 0;
        t.italic = c.rl()? != 0;
        c.rl()?; // charset
        c.rl()?; // pitch and family
        t.typeface = c.pus()?;
        t.font = c.pus()?;
        t.big_font = c.pus()?;
    } else {
        t.font = (r.decode)(c.ps()?);
        t.big_font = (r.decode)(c.ps()?);
    }
    Some(t)
}

/// A text's strings cut to the string limit.
fn cut(mut t: ProxyText, r: &Reading<'_>) -> ProxyText {
    for s in [&mut t.value, &mut t.font, &mut t.big_font, &mut t.typeface] {
        if s.len() > r.max_string_bytes {
            let mut end = r.max_string_bytes;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s.truncate(end);
        }
    }
    t
}

/// The edge visibilities of a mesh's or shell's edge data, `edges` of
/// them; empty when the stream gives none. The other per-edge data (colours,
/// layers, linetypes, markers) is skipped.
fn edge_visibility(c: &mut Chunk<'_>, edges: usize) -> Option<Vec<bool>> {
    let flags = c.rl()?;
    if flags & 0xFFFF == 0 {
        return Some(Vec::new());
    }
    if edges > c.left() / 4 {
        return None;
    }
    // Colours, layers, linetypes, markers: an RL per edge each.
    for bit in [0x01, 0x02, 0x04, 0x20] {
        if flags & bit != 0 {
            c.take(edges * 4)?;
        }
    }
    if flags & 0x40 == 0 {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(edges);
    for _ in 0..edges {
        out.push(c.rl()? != 0);
    }
    Some(out)
}

fn mesh(c: &mut Chunk<'_>, max: usize) -> Option<ProxyMesh> {
    let rows = c.rl()?;
    let columns = c.rl()?;
    let n = rows.checked_mul(columns)?;
    let vertices = c.points(n, max)?;
    let (r, k) = (rows as usize, columns as usize);
    let edges = r.saturating_sub(1) * k + k.saturating_sub(1) * r;
    // Face and vertex data follow; nothing drawn here needs them.
    let edge_visible = edge_visibility(c, edges).unwrap_or_default();
    Some(ProxyMesh {
        rows,
        columns,
        vertices,
        edge_visible,
    })
}

fn shell(c: &mut Chunk<'_>, max: usize) -> Option<ProxyShell> {
    let n = c.rl()?;
    let vertices = c.points(n, max)?;
    let count = usize::try_from(c.rl()?).ok()?;
    if count > c.left() / 4 {
        return None;
    }
    let mut faces = Vec::with_capacity(count.min(max));
    for _ in 0..count {
        let v = c.rl()? as i32;
        if faces.len() < max {
            faces.push(v);
        }
    }
    // An edge per vertex of each face and hole.
    let mut edges = 0usize;
    let mut i = 0usize;
    while let Some(&k) = faces.get(i) {
        let k = k.unsigned_abs() as usize;
        edges = edges.saturating_add(k);
        i = i.saturating_add(k).saturating_add(1);
    }
    let edge_visible = edge_visibility(c, edges).unwrap_or_default();
    Some(ProxyShell {
        vertices,
        faces,
        edge_visible,
    })
}

/// A DXF's release as the DWG release whose layouts it has; R13 before it.
pub(crate) fn dwg_version(v: Version) -> DwgVersion {
    match v {
        Version::R12 | Version::R13 => DwgVersion::R13,
        Version::R14 => DwgVersion::R14,
        Version::R2000 => DwgVersion::R2000,
        Version::R2004 => DwgVersion::R2004,
        Version::R2007 => DwgVersion::R2007,
        Version::R2010 => DwgVersion::R2010,
        Version::R2013 => DwgVersion::R2013,
        Version::R2018 => DwgVersion::R2018,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(v: u32) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    fn rd(v: &[f64]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    fn chunk(kind: u32, mut data: Vec<u8>) -> Vec<u8> {
        while !data.len().is_multiple_of(4) {
            data.push(0);
        }
        let mut out = rl(8 + data.len() as u32);
        out.extend(rl(kind));
        out.extend(data);
        out
    }

    fn stream(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = chunks.concat();
        let mut out = rl(8 + body.len() as u32);
        out.extend(rl(chunks.len() as u32));
        out.extend(body);
        out
    }

    fn reading() -> Reading<'static> {
        Reading {
            version: DwgVersion::R2018,
            decode: &|b: &[u8]| String::from_utf8_lossy(b).into_owned(),
            max_items: 1000,
            max_string_bytes: 1000,
        }
    }

    fn polyline(points: &[[f64; 3]]) -> Vec<u8> {
        let mut d = rl(points.len() as u32);
        for p in points {
            d.extend(rd(p));
        }
        chunk(6, d)
    }

    #[test]
    fn a_chunk_of_an_unknown_type_or_cut_short_costs_only_itself() {
        let s = stream(&[
            chunk(99, rl(7)),
            // A circle whose data stops after the centre.
            chunk(2, rd(&[1.0, 2.0, 3.0])),
            polyline(&[[0.0, 0.0, 0.0], [1.0, 1.0, 0.0]]),
        ]);
        let (g, problem) = read(&s, &reading());
        assert_eq!(g.items.len(), 1, "{g:?}");
        assert!(matches!(&g.items[0], ProxyItem::Polyline { points, .. } if points.len() == 2));
        assert!(problem.unwrap().contains("type 2"));
    }

    #[test]
    fn a_chunk_past_the_stream_stops_the_reading() {
        let mut s = stream(&[
            polyline(&[[0.0; 3], [1.0; 3]]),
            polyline(&[[2.0; 3], [3.0; 3]]),
        ]);
        // The second chunk's size says more than the stream holds.
        let second = 8 + 4 + 2 * 24 + 8;
        s[second..second + 4].copy_from_slice(&1000u32.to_le_bytes());
        let (g, problem) = read(&s, &reading());
        assert_eq!(g.items.len(), 1);
        assert!(problem.unwrap().contains("does not fit"));
        // A count of points no chunk could hold.
        let s = stream(&[chunk(6, rl(u32::MAX))]);
        let (g, problem) = read(&s, &reading());
        assert!(g.items.is_empty() && problem.is_some());
    }

    #[test]
    fn strings_are_padded_to_four_bytes_from_the_chunk() {
        // TEXT2: a 5-byte string takes 8, then its length and the rest.
        let mut d = rd(&[1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0]);
        d.extend(b"Hello\0\0\0");
        d.extend(rl(u32::MAX));
        d.extend(rl(1));
        d.extend(rd(&[2.5, 0.75, 0.25, 0.0]));
        for _ in 0..5 {
            d.extend(rl(0));
        }
        d.extend(b"romans.shx\0\0");
        d.extend(b"\0\0\0\0");
        let (g, problem) = read(&stream(&[chunk(11, d)]), &reading());
        assert_eq!(problem, None);
        let ProxyItem::Text(t) = &g.items[0] else {
            panic!("{g:?}");
        };
        assert_eq!(
            (t.value.as_str(), t.height, t.width_factor, t.oblique),
            ("Hello", 2.5, 0.75, 0.25)
        );
        assert_eq!(
            (t.font.as_str(), t.big_font.as_str(), t.raw),
            ("romans.shx", "", true)
        );
    }
}
