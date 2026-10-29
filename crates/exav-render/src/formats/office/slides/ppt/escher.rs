//! OfficeArt drawings ([MS-ODRAW]) as PPT stores them: a slide's
//! OfficeArtDgContainer holds a tree of shapes, each with its type, flags,
//! property table, anchor and the client records PowerPoint adds (text,
//! placeholder, links). The picture store (BStore) is read here too.

use super::records::{Rec, read_at};
use crate::formats::office::common::bytes::Cur;
use std::io::Read;

pub const DG_CONTAINER: u16 = 0xF002;
pub const SPGR_CONTAINER: u16 = 0xF003;
pub const SP_CONTAINER: u16 = 0xF004;
const FSPGR: u16 = 0xF009;
const FSP: u16 = 0xF00A;
const FOPT: u16 = 0xF00B;
const SECONDARY_FOPT: u16 = 0xF121;
const TERTIARY_FOPT: u16 = 0xF122;
pub const CLIENT_TEXTBOX: u16 = 0xF00D;
const CHILD_ANCHOR: u16 = 0xF00F;
const CLIENT_ANCHOR: u16 = 0xF010;
const CLIENT_DATA: u16 = 0xF011;

pub const F_GROUP: u32 = 0x1;
pub const F_DELETED: u32 = 0x8;
pub const F_OLE: u32 = 0x10;
pub const F_HAVE_MASTER: u32 = 0x20;
pub const F_FLIP_H: u32 = 0x40;
pub const F_FLIP_V: u32 = 0x80;
pub const F_CONNECTOR: u32 = 0x100;
pub const F_BACKGROUND: u32 = 0x400;

/// One entry of a property table: id (without its flags), value, and for
/// a complex property its data.
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

    /// A boolean of a set (its property id `set`): bit `bit` (0 for the
    /// last of the set's 16 values) when its "use" bit (bit + 16) is set.
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
        let complex = opid & 0x8000 != 0;
        let id = opid & 0x3FFF;
        if complex {
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

/// The elements of an IMsoArray ([MS-ODRAW] 2.2.51): count, allocated
/// count, element size, then the elements. Element size 0xFFF0 means
/// 4-byte elements holding two 16-bit halves.
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
    /// Left, top, right, bottom in master units (ClientAnchor).
    pub anchor: Option<[i32; 4]>,
    /// Left, top, right, bottom in the group's coordinates.
    pub child: Option<[i32; 4]>,
    /// A group's own coordinate space.
    pub group: Option<[i32; 4]>,
    pub client_data: Option<Rec<'a>>,
    pub textbox: Option<Rec<'a>>,
    pub children: Vec<OShape<'a>>,
}

impl<'a> OShape<'a> {
    pub fn is_group(&self) -> bool {
        self.flags & F_GROUP != 0
    }
}

fn sp_container<'a>(r: &Rec<'a>) -> OShape<'a> {
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
                    // RectStruct: top, left, right, bottom.
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

fn group<'a>(r: &Rec<'a>, depth: u32) -> OShape<'a> {
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

/// Reads an OfficeArtDgContainer's body.
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
/// order: a shape's `pib` is 1-based in it. A BSE whose picture is in the
/// Pictures stream (delay) is read from there at the BSE's offset. Each
/// decodes with [`blip`].
pub fn blip_records<'a>(dgg: &Rec<'a>, pictures: &'a [u8]) -> Vec<Option<Rec<'a>>> {
    let mut out = vec![];
    let Some(store) = dgg.child(0xF001) else {
        return out;
    };
    for bse in store.children() {
        if out.len() >= 1 << 16 {
            break;
        }
        if bse.typ != 0xF007 {
            out.push(None);
            continue;
        }
        let d = bse.data;
        let size = Cur::at(d, 20).u32() as usize;
        let delay = Cur::at(d, 28).u32() as usize;
        let name_len = d.get(33).copied().unwrap_or(0) as usize;
        let inline = d.get(36 + name_len..).filter(|r| r.len() >= 8);
        let rec = match inline {
            Some(rest) => read_at(rest, 0),
            None if size > 0 => read_at(pictures, delay),
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
                data: dib_to_bmp(&data),
            });
        }
        return Some(Blip { ext, data });
    }
    let hdr = d.get(skip..skip + 34)?;
    let body = d.get(skip + 34..)?;
    let data = if hdr[32] == 0 {
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(body)
            .take(MAX_METAFILE + 1)
            .read_to_end(&mut out)
            .ok()?;
        if out.len() as u64 > MAX_METAFILE {
            return None;
        }
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

/// A device-independent bitmap with the file header it lacks.
fn dib_to_bmp(dib: &[u8]) -> Vec<u8> {
    let hsize = Cur::at(dib, 0).u32() as usize;
    let bits = Cur::at(dib, 14).u16() as u32;
    let used = Cur::at(dib, 32).u32();
    let colors = if bits <= 8 && bits > 0 {
        if used > 0 { used.min(256) } else { 1 << bits }
    } else {
        used.min(256)
    };
    let off = 14 + hsize.min(1 << 16) + colors as usize * 4;
    let mut out = Vec::with_capacity(dib.len() + 14);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&((dib.len() + 14) as u32).to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(off as u32).to_le_bytes());
    out.extend_from_slice(dib);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::slides::ppt::records::build::*;

    fn fopte(id: u16, v: u32) -> Vec<u8> {
        let mut b = id.to_le_bytes().to_vec();
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    /// An EMF picture record whose metafile of `n` bytes is deflated.
    fn compressed_emf(n: usize) -> Vec<u8> {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk = vec![0u8; 1 << 20];
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len());
            z.write_all(&chunk[..k]).unwrap();
            left -= k;
        }
        // 16 bytes of identifier, then the 34-byte header: sizes, bounds,
        // compression (0 is deflate) and filter at its end.
        let mut body = vec![0u8; 16 + 34];
        body[16 + 32] = 0;
        body[16 + 33] = 0xFE;
        body.extend(z.finish().unwrap());
        rec(0, 0x3D4, 0xF01A, &body)
    }

    #[test]
    fn deflated_metafiles_past_the_bound_are_dropped() {
        let r = compressed_emf(1000);
        let b =
            blip(&crate::formats::office::slides::ppt::records::read_at(&r, 0).unwrap()).unwrap();
        assert_eq!((b.ext, b.data.len()), ("emf", 1000));
        let r = compressed_emf(MAX_METAFILE as usize);
        let b =
            blip(&crate::formats::office::slides::ppt::records::read_at(&r, 0).unwrap()).unwrap();
        assert_eq!(b.data.len() as u64, MAX_METAFILE);
        let r = compressed_emf(MAX_METAFILE as usize + 1);
        assert!(
            blip(&crate::formats::office::slides::ppt::records::read_at(&r, 0).unwrap()).is_none()
        );
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
        // The second complex value follows the first.
        assert_eq!(p.complex(0x0380), Some(&b"N\0a\0"[..]));
        assert_eq!(p.flag(0x01BF, 4), Some(true));
        assert_eq!(p.flag(0x01BF, 3), None);
    }

    #[test]
    fn boolean_sets_merge_by_bit() {
        let mut a = Props(vec![Prop {
            id: 0x01BF,
            value: 0x0018_0010,
            complex: None,
        }]);
        let b = Props(vec![Prop {
            id: 0x01BF,
            value: 0x0010_0000,
            complex: None,
        }]);
        a.overlay(&b);
        assert_eq!(a.flag(0x01BF, 4), Some(false));
        assert_eq!(a.flag(0x01BF, 3), Some(false));
    }

    #[test]
    fn groups_and_anchors() {
        let fsp = |spt: u16, flags: u32| {
            let mut b = 1024u32.to_le_bytes().to_vec();
            b.extend_from_slice(&flags.to_le_bytes());
            rec(2, spt, FSP, &b)
        };
        let anchor = rec(0, 0, CLIENT_ANCHOR, &[10, 0, 20, 0, 120, 0, 60, 0]);
        let child = container(
            SP_CONTAINER,
            0,
            &[fsp(1, 2), rec(0, 0, CHILD_ANCHOR, &[0; 16])],
        );
        let g = container(
            SPGR_CONTAINER,
            0,
            &[
                container(
                    SP_CONTAINER,
                    0,
                    &[fsp(0, 1 | 4), rec(1, 0, FSPGR, &[0; 16])],
                ),
                container(
                    SPGR_CONTAINER,
                    0,
                    &[
                        container(SP_CONTAINER, 0, &[fsp(0, 1), anchor.clone()]),
                        child,
                    ],
                ),
                container(SP_CONTAINER, 0, &[fsp(3, 0), anchor]),
            ],
        );
        let dg = container(DG_CONTAINER, 0, &[g]);
        let d = drawing(&read_at(&dg, 0).unwrap());
        assert_eq!(d.shapes.len(), 2);
        assert!(d.shapes[0].is_group());
        assert_eq!(d.shapes[0].children.len(), 1);
        assert_eq!(d.shapes[1].spt, 3);
        assert_eq!(d.shapes[1].anchor, Some([20, 10, 120, 60]));
    }
}
