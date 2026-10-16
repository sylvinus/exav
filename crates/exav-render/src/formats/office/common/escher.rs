//! OfficeArt records ([MS-ODRAW] 2.2): an 8-byte header (version and
//! instance, type, length) and a body; containers hold records. Shape
//! property tables, the shape tree of a drawing and the picture store.

use super::bytes::Cur;
use std::io::Read;

pub const DGG_CONTAINER: u16 = 0xF000;
pub const BSTORE_CONTAINER: u16 = 0xF001;
pub const DG_CONTAINER: u16 = 0xF002;
pub const SPGR_CONTAINER: u16 = 0xF003;
pub const SP_CONTAINER: u16 = 0xF004;
pub const BSE: u16 = 0xF007;
pub const FSPGR: u16 = 0xF009;
pub const FSP: u16 = 0xF00A;
pub const FOPT: u16 = 0xF00B;
pub const CLIENT_TEXTBOX: u16 = 0xF00D;
pub const CHILD_ANCHOR: u16 = 0xF00F;
pub const CLIENT_ANCHOR: u16 = 0xF010;
pub const CLIENT_DATA: u16 = 0xF011;
pub const SECONDARY_FOPT: u16 = 0xF121;
pub const TERTIARY_FOPT: u16 = 0xF122;

pub const F_GROUP: u32 = 0x1;
pub const F_CHILD: u32 = 0x2;
pub const F_PATRIARCH: u32 = 0x4;
pub const F_DELETED: u32 = 0x8;
pub const F_OLE: u32 = 0x10;
pub const F_HAVE_MASTER: u32 = 0x20;
pub const F_FLIP_H: u32 = 0x40;
pub const F_FLIP_V: u32 = 0x80;
pub const F_CONNECTOR: u32 = 0x100;
pub const F_HAVE_ANCHOR: u32 = 0x200;
pub const F_BACKGROUND: u32 = 0x400;
pub const F_HAVE_SPT: u32 = 0x800;

#[derive(Clone, Copy, Debug)]
pub struct Rec<'a> {
    pub ver: u8,
    pub inst: u16,
    pub typ: u16,
    pub data: &'a [u8],
    /// Offset of the header in the slice it was read from.
    pub at: usize,
}

impl<'a> Rec<'a> {
    pub fn children(&self) -> Children<'a> {
        Children::new(self.data)
    }

    pub fn child(&self, typ: u16) -> Option<Rec<'a>> {
        self.children().find(|r| r.typ == typ)
    }

    pub fn cur(&self) -> Cur<'a> {
        Cur::new(self.data)
    }
}

/// The record at `at` in `d`; a length past the end is cut to what is there.
pub fn read_at(d: &[u8], at: usize) -> Option<Rec<'_>> {
    let mut c = Cur::at(d, at);
    if c.left() < 8 {
        return None;
    }
    let vi = c.u16();
    let typ = c.u16();
    let len = c.u32() as usize;
    let start = at + 8;
    let end = start.saturating_add(len).min(d.len());
    Some(Rec {
        ver: (vi & 0xF) as u8,
        inst: vi >> 4,
        typ,
        data: &d[start..end],
        at,
    })
}

/// The records one after another in a container's body.
pub struct Children<'a> {
    d: &'a [u8],
    p: usize,
    n: usize,
}

impl<'a> Children<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Children { d, p: 0, n: 0 }
    }
}

const MAX_CHILDREN: usize = 1 << 18;

impl<'a> Iterator for Children<'a> {
    type Item = Rec<'a>;

    fn next(&mut self) -> Option<Rec<'a>> {
        if self.n >= MAX_CHILDREN {
            return None;
        }
        let r = read_at(self.d, self.p)?;
        self.p = self.p + 8 + r.data.len();
        self.n += 1;
        Some(r)
    }
}

/// One entry of a property table: id (without its flags), value, and for a
/// complex property its data.
#[derive(Clone, Debug)]
pub struct Prop<'a> {
    pub id: u16,
    pub value: u32,
    pub complex: Option<&'a [u8]>,
}

#[derive(Clone, Debug, Default)]
pub struct Props<'a>(pub Vec<Prop<'a>>);

impl<'a> Props<'a> {
    pub fn get(&self, id: u16) -> Option<u32> {
        self.0.iter().rev().find(|p| p.id == id).map(|p| p.value)
    }

    pub fn int(&self, id: u16) -> Option<i32> {
        self.get(id).map(|v| v as i32)
    }

    pub fn complex(&self, id: u16) -> Option<&'a [u8]> {
        self.0
            .iter()
            .rev()
            .find(|p| p.id == id)
            .and_then(|p| p.complex)
    }

    /// A boolean of a set (its property id `set`): bit `bit` (0 for the last
    /// of the set's 16 values) when its "use" bit (bit + 16) is set.
    pub fn flag(&self, set: u16, bit: u32) -> Option<bool> {
        let v = self.get(set)?;
        (v & (1 << (bit + 16)) != 0).then_some(v & (1 << bit) != 0)
    }

    /// `o`'s properties over these.
    pub fn overlay(&mut self, o: &Props<'a>) {
        for p in &o.0 {
            if let Some(q) = self.0.iter_mut().find(|q| q.id == p.id) {
                // Boolean sets merge bit by bit: each "use" bit of `o` wins.
                if p.id & 0x3F == 0x3F && p.complex.is_none() {
                    let used = p.value >> 16;
                    q.value = (q.value & !(used | used << 16)) | (p.value & (used | used << 16));
                } else {
                    *q = p.clone();
                }
            } else {
                self.0.push(p.clone());
            }
        }
    }
}

/// Reads a property table: `n` entries, then the complex data in order.
pub fn read_props(d: &[u8], n: u16) -> Props<'_> {
    let mut c = Cur::new(d);
    let mut entries = vec![];
    for _ in 0..n.min(1024) {
        let opid = c.u16();
        let value = c.u32();
        if c.short {
            break;
        }
        entries.push((opid, value));
    }
    let mut p = c.p;
    let mut out = Vec::with_capacity(entries.len());
    for (opid, value) in entries {
        let id = opid & 0x3FFF;
        if opid & 0x8000 != 0 {
            let len = value as usize;
            let end = p.saturating_add(len).min(d.len());
            out.push(Prop {
                id,
                value,
                complex: Some(&d[p.min(end)..end]),
            });
            p = end;
        } else {
            out.push(Prop {
                id,
                value,
                complex: None,
            });
        }
    }
    Props(out)
}

/// The elements of an IMsoArray ([MS-ODRAW] 2.2.51). Element size 0xFFF0
/// means 4-byte elements holding two 16-bit halves.
pub fn array(d: &[u8]) -> Vec<&[u8]> {
    let mut c = Cur::new(d);
    let n = c.u16() as usize;
    let _alloc = c.u16();
    let mut size = c.u16() as usize;
    if size == 0xFFF0 {
        size = 4;
    }
    if size == 0 || c.short {
        return vec![];
    }
    let body = &d[6.min(d.len())..];
    body.chunks_exact(size).take(n.min(1 << 20)).collect()
}

#[derive(Clone, Debug, Default)]
pub struct OShape<'a> {
    pub spt: u16,
    pub spid: u32,
    pub flags: u32,
    pub props: Props<'a>,
    /// Left, top, right, bottom of a ClientAnchor.
    pub anchor: Option<[i32; 4]>,
    /// Left, top, right, bottom in the group's coordinates.
    pub child: Option<[i32; 4]>,
    /// A group's own coordinate space.
    pub group: Option<[i32; 4]>,
    pub client_data: Option<Rec<'a>>,
    pub textbox: Option<Rec<'a>>,
    pub children: Vec<OShape<'a>>,
}

impl OShape<'_> {
    pub fn is_group(&self) -> bool {
        self.flags & F_GROUP != 0
    }
}

pub fn sp_container<'a>(r: &Rec<'a>) -> OShape<'a> {
    let mut s = OShape::default();
    for k in r.children() {
        let mut c = k.cur();
        match k.typ {
            FSP => {
                s.spt = k.inst;
                s.spid = c.u32();
                s.flags = c.u32();
            }
            FSPGR => s.group = Some([c.i32(), c.i32(), c.i32(), c.i32()]),
            CHILD_ANCHOR => s.child = Some([c.i32(), c.i32(), c.i32(), c.i32()]),
            CLIENT_ANCHOR => {
                s.anchor = if k.data.len() >= 16 {
                    let (t, l, r, b) = (c.i32(), c.i32(), c.i32(), c.i32());
                    Some([l, t, r, b])
                } else if k.data.len() >= 8 {
                    let (t, l, r, b) = (c.i16(), c.i16(), c.i16(), c.i16());
                    Some([l.into(), t.into(), r.into(), b.into()])
                } else {
                    None
                };
            }
            FOPT | SECONDARY_FOPT | TERTIARY_FOPT => {
                let p = read_props(k.data, k.inst);
                s.props.overlay(&p);
            }
            CLIENT_DATA => s.client_data = Some(k),
            CLIENT_TEXTBOX => s.textbox = Some(k),
            _ => {}
        }
    }
    s
}

pub fn group<'a>(r: &Rec<'a>, depth: u32) -> OShape<'a> {
    let mut kids = r.children();
    let mut g = match kids.next() {
        Some(k) if k.typ == SP_CONTAINER => sp_container(&k),
        _ => OShape {
            flags: F_GROUP,
            ..OShape::default()
        },
    };
    g.flags |= F_GROUP;
    for k in kids {
        match k.typ {
            SP_CONTAINER => g.children.push(sp_container(&k)),
            SPGR_CONTAINER if depth < 32 => g.children.push(group(&k, depth + 1)),
            _ => {}
        }
        if g.children.len() >= 1 << 16 {
            break;
        }
    }
    g
}

/// A drawing's shapes (the top group's members) and background shape.
pub struct Drawing<'a> {
    pub shapes: Vec<OShape<'a>>,
    pub background: Option<OShape<'a>>,
}

/// Reads an OfficeArtDgContainer.
pub fn drawing<'a>(dg: &Rec<'a>) -> Drawing<'a> {
    let mut out = Drawing {
        shapes: vec![],
        background: None,
    };
    for k in dg.children() {
        match k.typ {
            SPGR_CONTAINER => {
                let g = group(&k, 0);
                out.shapes.extend(g.children);
            }
            SP_CONTAINER => {
                let s = sp_container(&k);
                if s.flags & F_BACKGROUND != 0 {
                    out.background = Some(s);
                }
            }
            _ => {}
        }
    }
    out
}

pub struct Blip {
    pub ext: &'static str,
    pub data: Vec<u8>,
}

/// Metafiles past this size inflated are dropped.
const MAX_METAFILE: u64 = 64 << 20;

/// The picture records of the store (OfficeArtDggContainer's BStore), in
/// order: a shape's `pib` is 1-based in it. A BSE whose picture is not in
/// its record is read from `delay` (the stream the format keeps them in) at
/// the BSE's offset.
pub fn blip_records<'a>(dgg: &Rec<'a>, delay: &'a [u8]) -> Vec<Option<Rec<'a>>> {
    let mut out = vec![];
    let Some(store) = dgg.child(BSTORE_CONTAINER) else {
        return out;
    };
    for bse in store.children() {
        if out.len() >= 1 << 16 {
            break;
        }
        if bse.typ != BSE {
            // A blip itself, where a store lists them directly.
            out.push(matches!(bse.typ, 0xF01A..=0xF02A).then_some(bse));
            continue;
        }
        let d = bse.data;
        let size = Cur::at(d, 20).u32() as usize;
        let at = Cur::at(d, 28).u32() as usize;
        let name_len = d.get(33).copied().unwrap_or(0) as usize;
        let inline = d.get(36 + name_len..).filter(|r| r.len() >= 8);
        let rec = match inline {
            Some(rest) => read_at(rest, 0),
            None if size > 0 => read_at(delay, at),
            None => None,
        };
        out.push(rec);
    }
    out
}

/// A picture record's image: its bytes, with metafiles inflated.
pub fn blip(r: &Rec) -> Option<Blip> {
    // An instance with its low bit set has a second 16-byte id.
    let two = |base: u16| if r.inst == base + 1 { 32 } else { 16 };
    let (ext, skip, meta) = match r.typ {
        0xF01A => ("emf", two(0x3D4), true),
        0xF01B => ("wmf", two(0x216), true),
        0xF01C => ("pict", two(0x542), true),
        0xF01D | 0xF02A => (
            "jpeg",
            if r.inst == 0x46B || r.inst == 0x6E3 {
                33
            } else {
                17
            },
            false,
        ),
        0xF01E => ("png", two(0x6E0) + 1, false),
        0xF01F => ("bmp", two(0x7A8) + 1, false),
        0xF029 => ("tiff", two(0x6E4) + 1, false),
        _ => return None,
    };
    let d = r.data;
    if !meta {
        let data = d.get(skip..)?.to_vec();
        if ext == "bmp" {
            return Some(Blip {
                ext,
                data: super::image::dib_to_bmp(&data),
            });
        }
        return Some(Blip { ext, data });
    }
    let hdr = d.get(skip..skip + 34)?;
    let body = d.get(skip + 34..)?;
    let data = if hdr[32] == 0 {
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(body)
            .take(MAX_METAFILE)
            .read_to_end(&mut out)
            .ok()?;
        out
    } else {
        body.to_vec()
    };
    let data = if ext == "wmf" && !data.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) {
        placeable_wmf(&data, hdr)
    } else {
        data
    };
    Some(Blip { ext, data })
}

/// A WMF without its placeable header gets one, from the blip's bounds.
fn placeable_wmf(data: &[u8], hdr: &[u8]) -> Vec<u8> {
    let mut c = Cur::at(hdr, 4);
    let mut h = vec![0xD7, 0xCD, 0xC6, 0x9A, 0, 0];
    for _ in 0..4 {
        h.extend_from_slice(&(c.i32() as i16).to_le_bytes());
    }
    h.extend_from_slice(&1440u16.to_le_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    let mut sum = 0u16;
    for k in 0..10 {
        sum ^= u16::from_le_bytes([h[2 * k], h[2 * k + 1]]);
    }
    h.extend_from_slice(&sum.to_le_bytes());
    h.extend_from_slice(data);
    h
}

/// Records written for tests.
#[cfg(any(test, feature = "office-test-util"))]
pub mod build {
    pub fn rec(ver: u8, inst: u16, typ: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(body.len() + 8);
        v.extend_from_slice(&(u16::from(ver & 0xF) | inst << 4).to_le_bytes());
        v.extend_from_slice(&typ.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    pub fn container(typ: u16, inst: u16, children: &[Vec<u8>]) -> Vec<u8> {
        rec(0xF, inst, typ, &children.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn fopte(id: u16, v: u32) -> Vec<u8> {
        let mut b = id.to_le_bytes().to_vec();
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    #[test]
    fn children_and_truncation() {
        let c = container(
            0x03E8,
            0,
            &[rec(0, 1, 0x03E9, &[1, 2]), rec(0, 0, 0x0FA0, b"hi")],
        );
        let r = read_at(&c, 0).unwrap();
        let kids: Vec<_> = r
            .children()
            .map(|k| (k.typ, k.inst, k.data.to_vec()))
            .collect();
        assert_eq!(
            kids,
            vec![(0x03E9, 1, vec![1, 2]), (0x0FA0, 0, b"hi".to_vec())]
        );
        let r = read_at(&c[..c.len() - 1], 0).unwrap();
        assert_eq!(r.children().last().unwrap().data, b"h");
        assert!(read_at(&c, c.len() - 4).is_none());
    }

    #[test]
    fn property_tables_with_complex_data() {
        let mut body = fopte(0x0181, 0x00FF_0000);
        body.extend(fopte(0x8145, 6 + 8));
        body.extend(fopte(0x01BF, 0x0010_0010));
        body.extend(fopte(0xC380, 4));
        body.extend([2, 0, 2, 0, 4, 0, 1, 0, 2, 0, 3, 0, 4, 0]);
        body.extend(b"N\0a\0");
        let p = read_props(&body, 4);
        assert_eq!(p.get(0x0181), Some(0x00FF_0000));
        let pts = array(p.complex(0x0145).unwrap());
        assert_eq!(pts, vec![&[1, 0, 2, 0][..], &[3, 0, 4, 0][..]]);
        assert_eq!(p.complex(0x0380), Some(&b"N\0a\0"[..]));
        assert_eq!(p.flag(0x01BF, 4), Some(true));
        assert_eq!(p.flag(0x01BF, 3), None);
        // Element size 0xFFF0: four bytes each.
        let packed = [1, 0, 1, 0, 0xF0, 0xFF, 9, 0, 8, 0];
        assert_eq!(array(&packed), vec![&[9, 0, 8, 0][..]]);
        // No element size, or fewer bytes than the header.
        assert!(array(&[1, 0, 1, 0, 0, 0]).is_empty());
        assert!(array(&[1]).is_empty());
    }

    #[test]
    fn groups_and_anchors() {
        let fsp = |spt: u16, flags: u32| {
            let mut b = 1024u32.to_le_bytes().to_vec();
            b.extend_from_slice(&flags.to_le_bytes());
            rec(2, spt, FSP, &b)
        };
        let anchor = rec(0, 0, CLIENT_ANCHOR, &[10, 0, 20, 0, 120, 0, 60, 0]);
        let g = container(
            SPGR_CONTAINER,
            0,
            &[
                container(SP_CONTAINER, 0, &[fsp(0, 4), rec(1, 0, FSPGR, &[0; 16])]),
                container(SP_CONTAINER, 0, &[fsp(3, 0), anchor]),
            ],
        );
        let top = group(&read_at(&g, 0).unwrap(), 0);
        assert!(top.is_group());
        assert_eq!(top.children.len(), 1);
        let dg = container(DG_CONTAINER, 0, &[g]);
        let d = drawing(&read_at(&dg, 0).unwrap());
        assert_eq!(d.shapes.len(), 1);
        assert_eq!(d.shapes[0].spt, 3);
        assert_eq!(d.shapes[0].anchor, Some([20, 10, 120, 60]));
    }

    #[test]
    fn boolean_sets_merge_bit_by_bit() {
        // Bits 4 (used, set) of the first; of the second, bit 3 (used, set)
        // and bit 4 (used, clear).
        let (da, db) = (fopte(0x01BF, 0x0010_0010), fopte(0x01BF, 0x0008_0008));
        let mut a = read_props(&da, 1);
        a.overlay(&read_props(&db, 1));
        assert_eq!(a.flag(0x01BF, 3), Some(true));
        // Bit 4 is not used by the second set: the first's stays.
        assert_eq!(a.flag(0x01BF, 4), Some(true));
        // A used bit that is clear turns it off.
        let dc = fopte(0x01BF, 0x0010_0000);
        a.overlay(&read_props(&dc, 1));
        assert_eq!(a.flag(0x01BF, 4), Some(false));
        assert_eq!(a.flag(0x01BF, 3), Some(true));
        // Other properties are replaced.
        let (da, db) = (fopte(0x0181, 1), fopte(0x0181, 2));
        let mut a = read_props(&da, 1);
        a.overlay(&read_props(&db, 1));
        assert_eq!(a.get(0x0181), Some(2));
    }

    #[test]
    fn client_anchors_come_in_two_sizes() {
        let mut long = vec![];
        for v in [20i32, 10, 120, 60] {
            long.extend_from_slice(&v.to_le_bytes());
        }
        let c = container(SP_CONTAINER, 0, &[rec(0, 0, CLIENT_ANCHOR, &long)]);
        let s = sp_container(&read_at(&c, 0).unwrap());
        // Top, left, right, bottom in the record; left, top, ... in the shape.
        assert_eq!(s.anchor, Some([10, 20, 120, 60]));
        let c = container(SP_CONTAINER, 0, &[rec(0, 0, CLIENT_ANCHOR, &[1, 0, 2, 0])]);
        assert_eq!(sp_container(&read_at(&c, 0).unwrap()).anchor, None);
    }

    #[test]
    fn metafile_blips_are_inflated_and_wmf_gets_a_header() {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
        z.write_all(b"META").unwrap();
        let packed = z.finish().unwrap();
        // Metafile header: size, bounds (0, 0, 1000, 500), ..., compression
        // (0: deflate, 0xFE: none) at 32, filter.
        let header = |compression: u8| {
            let mut h = vec![0u8; 34];
            h[12..16].copy_from_slice(&1000i32.to_le_bytes());
            h[16..20].copy_from_slice(&500i32.to_le_bytes());
            h[32] = compression;
            h[33] = 0xFE;
            h
        };
        let record = |typ: u16, inst: u16, uid: usize, compression: u8, body: &[u8]| {
            let mut d = vec![0u8; uid];
            d.extend(header(compression));
            d.extend_from_slice(body);
            rec(0, inst, typ, &d)
        };
        // An EMF with one 16-byte id, deflated.
        let b = blip(&read_at(&record(0xF01A, 0x3D4, 16, 0, &packed), 0).unwrap()).unwrap();
        assert_eq!((b.ext, b.data.as_slice()), ("emf", &b"META"[..]));
        // The odd instance has two ids, 32 bytes; stored as it is.
        let b = blip(&read_at(&record(0xF01A, 0x3D5, 32, 0xFE, b"META"), 0).unwrap()).unwrap();
        assert_eq!(b.data, b"META");
        // A WMF without the placeable header gets one with the bounds.
        let b = blip(&read_at(&record(0xF01B, 0x216, 16, 0xFE, b"META"), 0).unwrap()).unwrap();
        assert_eq!(b.ext, "wmf");
        assert!(b.data.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A, 0, 0]));
        assert_eq!(&b.data[10..14], [0xE8, 3, 0xF4, 1]);
        assert_eq!(&b.data[14..16], 1440u16.to_le_bytes());
        assert!(b.data.ends_with(b"META"));
        // Not a picture record.
        assert!(blip(&read_at(&rec(0, 0, 0xF000, &[0; 40]), 0).unwrap()).is_none());
    }

    #[test]
    fn blips_from_the_store() {
        // A PNG blip: uid, tag, then the image.
        let mut png = vec![0u8; 16];
        png.push(0xFF);
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let blip_rec = rec(0, 0x6E0, 0xF01E, &png);
        // A BSE with the blip inline.
        let mut bse = vec![0u8; 36];
        bse[1] = 6;
        bse.extend_from_slice(&blip_rec);
        let store = container(BSTORE_CONTAINER, 1, &[rec(2, 6, BSE, &bse)]);
        let dgg = container(DGG_CONTAINER, 0, &[store]);
        let r = read_at(&dgg, 0).unwrap();
        let blips = blip_records(&r, &[]);
        assert_eq!(blips.len(), 1);
        let b = blip(&blips[0].unwrap()).unwrap();
        assert_eq!(b.ext, "png");
        assert!(b.data.starts_with(b"\x89PNG"));
    }
}
