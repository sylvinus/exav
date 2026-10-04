//! The files a DWG drawing carries, for the scanner: the preview images
//! (spec 14.2), the objects its OLE2FRAME entities embed (20.4.88), the VBA
//! project (spec 15 and the VBA_PROJECT object, 20.3), and a text member
//! with the hyperlinks, external-reference paths and the names of the
//! applications its proxy and custom objects demand, for signatures and
//! heuristics to match.

use super::{file, BitError, BitResult, Dwg, Error, PreviewKind, Version};
use crate::*;

/// The compound file signature (MS-CFB 2.2).
const OLE2: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// OLE2FRAME's fixed type code (spec 20.3); files also give it a class.
const OLE2FRAME: u16 = 0x4A;

/// VBA_PROJECT's fixed type code (spec 20.3).
const VBA_PROJECT: u16 = 0x51;

/// BLOCK_RECORD's fixed type code (spec 20.3): its xref path is read for
/// the metadata member.
const BLOCK_HEADER: u16 = 0x31;

/// A BMP file of a device-independent bitmap: the 14-byte file header
/// (`BM`, file size, pixel data offset) the preview leaves out, then the
/// bitmap. `None` when the bitmap's own header does not fit it.
pub fn bmp_file(dib: &[u8]) -> Option<Vec<u8>> {
    let le32 = |at: usize| -> Option<u32> {
        let b = dib.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let header = le32(0)?;
    if !(12..=124).contains(&header) || header as usize > dib.len() {
        return None;
    }
    // BITMAPCOREHEADER's 3-byte palette entries are not worth a case: the
    // previews AutoCAD writes use BITMAPINFOHEADER.
    if header < 40 {
        return None;
    }
    let bits = u16::from_le_bytes([*dib.get(14)?, *dib.get(15)?]);
    let compression = le32(16)?;
    let used = le32(32)?;
    let colors = match used {
        0 if bits <= 8 => 1u32 << bits,
        n => n,
    };
    let masks = if compression == 3 && header == 40 {
        12
    } else {
        0
    };
    let offset = 14u32
        .checked_add(header)?
        .checked_add(colors.checked_mul(4)?)?
        .checked_add(masks)?;
    let size = u32::try_from(dib.len().checked_add(14)?).ok()?;
    if offset > size {
        return None;
    }
    let mut out = Vec::with_capacity(dib.len() + 14);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(dib);
    Some(out)
}

fn emit<R>(
    name: String,
    bytes: Vec<u8>,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    if bytes.len() as u64 > cap {
        return Err(LimitHit::new(format!(
            "dwg: {name} ({} bytes) exceeds the per-member budget",
            bytes.len()
        )));
    }
    budget.commit(bytes.len() as u64);
    Ok(visit(Entry::new(name, bytes), budget))
}

pub(crate) fn extract_dwg<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // A release before R13 is a drawing whose contents were not examined.
    if let Some(v) = super::pre_r13_version(data) {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                format!("dwg-{v}"),
                data.len() as u64,
                false,
                "a DWG release before R13 (AC1009, R12, or older), which exav does not read",
            ),
            budget,
        ));
    }
    // The file header locates the preview on its own: a file damaged past
    // its header still yields it.
    if !file::has_file_header(data) {
        return Ok(None);
    }
    let mut seen: Vec<String> = Vec::new();
    for image in file::preview(data) {
        let (base, bytes) = match image.kind {
            PreviewKind::Header => continue,
            PreviewKind::Bmp => match bmp_file(image.data) {
                Some(b) => ("thumbnail.bmp".to_string(), b),
                None => ("thumbnail.dib".to_string(), image.data.to_vec()),
            },
            PreviewKind::Wmf => ("thumbnail.wmf".to_string(), image.data.to_vec()),
            PreviewKind::Png => ("thumbnail.png".to_string(), image.data.to_vec()),
            PreviewKind::Other(c) => (format!("thumbnail-{c}.bin"), image.data.to_vec()),
        };
        if bytes.is_empty() {
            continue;
        }
        let n = seen.iter().filter(|s| **s == base).count();
        seen.push(base.clone());
        let name = if n == 0 {
            base
        } else {
            match base.rsplit_once('.') {
                Some((stem, ext)) => format!("{stem}-{n}.{ext}"),
                None => format!("{base}-{n}"),
            }
        };
        if let Some(r) = emit(name, bytes, budget, visit)? {
            return Ok(Some(r));
        }
    }
    from_objects(data, budget, visit)
}

/// The compound file a VBA project is: from the OLE2 signature in `bytes`
/// (the project data may have a header before it), `None` when there is
/// none.
fn vba_member(name: String, bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    let at = bytes.windows(OLE2.len()).position(|w| w == OLE2)?;
    Some((name, bytes.get(at..).unwrap_or(&[]).to_vec()))
}

/// An OLE2FRAME's data (spec 20.4.88): flags, from R2000 a mode, the
/// length, then the bytes DXF writes as group 310.
fn frame_data(dwg: &Dwg<'_>, offset: usize) -> BitResult<Vec<u8>> {
    let mut o = dwg.object_at(offset)?;
    o.data.bs()?;
    if dwg.version() >= Version::R2000 {
        o.data.bs()?;
    }
    let n = usize::try_from(o.data.bl()?).map_err(|_| BitError::Invalid)?;
    o.data.bytes(n)
}

/// What the objects of a drawing carry: each OLE2FRAME's embedded object
/// (`ole2frame-<HANDLE>.ole` from the compound file's signature, AutoCAD's
/// header before it dropped as for DXF, `.bin` when there is none), the VBA
/// project (`vbaproject.ole` from the R2004+ section, `vbaproject-<H>.ole`
/// from a VBA_PROJECT object), and the metadata text member. A drawing
/// whose objects cannot be read is reported, since they were not examined.
fn from_objects<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // What the sections decompress to is held while they are searched.
    let cap = budget.reserve()?;
    let dwg = match Dwg::open_with(data, cap) {
        Ok(d) => d,
        Err(Error::NotDwg | Error::UnsupportedVersion(_)) => return Ok(None),
        Err(Error::LimitExceeded(why)) => return Err(LimitHit::new(format!("dwg: {why}"))),
        Err(Error::Damaged(_)) => {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "dwg-objects".into(),
                    data.len() as u64,
                    false,
                    "the drawing's objects could not be read",
                ),
                budget,
            ));
        }
    };
    let mut meta = Metadata::default();
    for &(handle, offset) in dwg.object_map() {
        let Ok(t) = dwg.type_at(offset) else {
            continue;
        };
        meta.note_class(&dwg, t);
        if t == OLE2FRAME || (t >= 500 && dwg.class(t).is_some_and(|c| c.name() == "OLE2FRAME")) {
            let label = format!("ole2frame-{handle:X}");
            let bytes = match frame_data(&dwg, offset) {
                Ok(b) => b,
                Err(_) => {
                    budget.count_entry()?;
                    if let Some(r) = visit(
                        Entry::unsupported(label, 0, false, "OLE2FRAME data could not be read"),
                        budget,
                    ) {
                        return Ok(Some(r));
                    }
                    continue;
                }
            };
            let member = match bytes.windows(OLE2.len()).position(|w| w == OLE2) {
                Some(at) => Some((
                    format!("{label}.ole"),
                    bytes.get(at..).unwrap_or(&[]).to_vec(),
                )),
                None if bytes.is_empty() => None,
                None => Some((format!("{label}.bin"), bytes)),
            };
            if let Some((name, bytes)) = member {
                if let Some(r) = emit(name, bytes, budget, visit)? {
                    return Ok(Some(r));
                }
            }
        } else if t == VBA_PROJECT
            || (t >= 500 && dwg.class(t).is_some_and(|c| c.name() == "VBA_PROJECT"))
        {
            // R13 to R2000, and any file whose VBA is an object: the
            // project is the compound file in the object's bytes (spec
            // 20.3 lists no prescription; it is DXF's group 310 data).
            if let Some((name, bytes)) = dwg
                .object_bytes(offset)
                .and_then(|b| vba_member(format!("vbaproject-{handle:X}.ole"), b))
            {
                if let Some(r) = emit(name, bytes, budget, visit)? {
                    return Ok(Some(r));
                }
            }
        }
        meta.note_xref(&dwg, t, offset);
    }
    // R2004 on: the VBA project is a section of its own (spec 15), a
    // 16-byte header then the compound file.
    if let Some((name, bytes)) = dwg
        .vba_project()
        .and_then(|b| vba_member("vbaproject.ole".to_string(), b))
    {
        if let Some(r) = emit(name, bytes, budget, visit)? {
            return Ok(Some(r));
        }
    }
    if let Some(bytes) = meta.finish() {
        if let Some(r) = emit("dwg-metadata".to_string(), bytes, budget, visit)? {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// The text member a drawing's objects fill for signatures and heuristics:
/// the names of the applications its proxy and custom objects demand (the
/// classes' application names, spec 10), and the external-reference paths
/// of its block records (spec 20.4.52). One string a line, `kind: value`,
/// as [`crate::formats::pdf`] emits its URIs; hyperlinks are on entities'
/// extended data, which the scanner reaches through the drawing model's
/// reader, so they are not duplicated here.
#[derive(Default)]
struct Metadata {
    lines: Vec<String>,
    seen_classes: std::collections::HashSet<String>,
}

impl Metadata {
    fn note_class(&mut self, dwg: &Dwg<'_>, t: u16) {
        if t < 500 {
            return;
        }
        if let Some(c) = dwg.class(t) {
            let app = c.application();
            // AutoCAD and the ODA toolkit write a handful of feature
            // classes into almost every drawing (`ObjectDBX Classes` for
            // the standard ones, the `ACAD_`/`ACDB_` namespaces, the
            // renderer's `SCENEOE`, the material mapper's `ISM`); those are
            // not an application a custom object demands. A third-party ARX
            // application's name (a TArch or a WipeOut) is kept.
            let boilerplate = app.is_empty()
                || app.starts_with("ObjectDBX Classes")
                || app.starts_with("ACAD_")
                || app.starts_with("ACDB_")
                || matches!(app.as_str(), "ISM" | "SCENEOE" | "AcDbDwgEngine");
            if !boilerplate && self.seen_classes.insert(app.clone()) {
                self.lines.push(format!("app: {app}"));
            }
        }
    }

    fn note_xref(&mut self, dwg: &Dwg<'_>, t: u16, offset: usize) {
        if t != BLOCK_HEADER {
            return;
        }
        if let Ok(mut o) = dwg.object_at(offset) {
            if let Some(path) = block_xref_path(&mut o, dwg.version()) {
                if !path.is_empty() {
                    self.lines.push(format!("xref: {path}"));
                }
            }
        }
    }

    fn finish(self) -> Option<Vec<u8>> {
        (!self.lines.is_empty()).then(|| {
            let mut s = self.lines.join("\n");
            s.push('\n');
            s.into_bytes()
        })
    }
}

/// A block record's external-reference path (spec 20.4.52): after the name
/// and flags, the base point, then the path, a TV. Decoded loosely to
/// bytes; a path that does not read is skipped.
fn block_xref_path(o: &mut super::Object<'_>, version: Version) -> Option<String> {
    use super::Text;
    // The entry head (spec 20.4.54): the name, the 64-flag, the xref index
    // (a BS before R2007), the xref-dependent bit.
    o.tv().ok()?;
    o.data.b().ok()?;
    if version < Version::R2007 {
        o.data.bs().ok()?;
    }
    o.data.b().ok()?;
    // The block record's flags (spec 20.4.52): anonymous, has-attributes,
    // xref, overlay, and from R2000 the loaded bit; an xref has no owned
    // list to skip. Then the base point and the path.
    o.data.b().ok()?;
    o.data.b().ok()?;
    let xref = o.data.b().ok()?;
    o.data.b().ok()?;
    if !xref {
        return None;
    }
    if version >= Version::R2000 {
        o.data.b().ok()?;
    }
    o.data.bd3().ok()?;
    match o.tv().ok()? {
        Text::Unicode(s) => Some(s),
        Text::Bytes(b) => Some(String::from_utf8_lossy(super::trim_zeros(&b)).into_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bitmap_gets_the_file_header_it_lacks() {
        // A 2x1 8-bit bitmap with a 256-colour palette.
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&2i32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&8u16.to_le_bytes());
        dib.extend_from_slice(&[0u8; 24]);
        dib.extend_from_slice(&[0u8; 1024]);
        dib.extend_from_slice(&[1, 2, 0, 0]);
        let bmp = bmp_file(&dib).unwrap();
        assert_eq!(&bmp[..2], b"BM");
        assert_eq!(
            u32::from_le_bytes(bmp[2..6].try_into().unwrap()) as usize,
            bmp.len()
        );
        assert_eq!(
            u32::from_le_bytes(bmp[10..14].try_into().unwrap()),
            14 + 40 + 1024
        );
        assert_eq!(&bmp[14..], &dib[..]);
        assert_eq!(bmp_file(&dib[..20]), None);
        assert_eq!(bmp_file(b"not a bitmap"), None);
    }

    /// A VBA project's compound file is carved from the OLE2 signature on,
    /// with the 16-byte header the AcDb:VBAProject section (spec 15) puts
    /// before it dropped; bytes with no signature are not a member. The
    /// ODA File Converter drops a VBA_PROJECT object and neither it nor
    /// ezdxf writes the section, so this path is unit-tested rather than
    /// through a converted fixture.
    #[test]
    fn a_vba_project_is_the_compound_file_from_its_signature() {
        let mut section = vec![0u8; 16];
        section.extend_from_slice(OLE2);
        section.extend_from_slice(b"the project data");
        let (name, bytes) = vba_member("vbaproject.ole".to_string(), &section).expect("a member");
        assert_eq!(name, "vbaproject.ole");
        assert_eq!(&bytes[..OLE2.len()], OLE2);
        assert_eq!(&bytes[OLE2.len()..], b"the project data");
        // No compound file in the bytes: no member.
        assert!(vba_member("x".to_string(), b"no signature here").is_none());
    }
}
