//! The thumbnail a drawing was saved with: DWG's preview images (ODA spec
//! 14.2), DXF's THUMBNAILIMAGE section.

use exav_unpack::dwg::{self, PreviewImage, PreviewKind};
use exav_unpack::dxf::Tag;

use super::model::{Preview, PreviewFormat};

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

/// An image as a file a browser shows: a PNG, a BMP file, or a
/// device-independent bitmap given its BMP file header.
pub(crate) fn from_image(data: &[u8]) -> Option<Preview> {
    if data.starts_with(PNG) {
        return Some(Preview {
            format: PreviewFormat::Png,
            data: data.to_vec(),
        });
    }
    let data = if data.starts_with(b"BM") {
        data.to_vec()
    } else {
        dwg::bmp_file(data)?
    };
    Some(Preview {
        format: PreviewFormat::Bmp,
        data,
    })
}

/// The best of a DWG's preview images: the PNG of 2013 on, else the bitmap
/// (a metafile is not shown).
pub(crate) fn from_dwg(images: &[PreviewImage<'_>]) -> Option<Preview> {
    let of = |kind: PreviewKind| images.iter().find(|i| i.kind == kind);
    of(PreviewKind::Png)
        .and_then(|i| from_image(i.data))
        .or_else(|| of(PreviewKind::Bmp).and_then(|i| from_image(i.data)))
}

/// A THUMBNAILIMAGE section's groups: 90, the size, then 310 chunks.
pub(crate) fn from_dxf(tags: &[Tag<'_>]) -> Option<Preview> {
    let size = tags.iter().find(|t| t.code == 90).map(|t| t.int())?;
    let size = usize::try_from(size).ok()?;
    let mut data = Vec::new();
    for t in tags.iter().filter(|t| t.code == 310) {
        if data.len() >= size || !t.chunk_into(&mut data) {
            break;
        }
    }
    data.truncate(size);
    from_image(&data)
}

/// A drawing's thumbnail without reading the drawing: a DWG's from where
/// its file header points, an ASCII DXF's from its THUMBNAILIMAGE section,
/// found from the end of the file where writers put it. `None` for a binary
/// DXF, whose thumbnail comes with the drawing.
pub fn preview(bytes: &[u8]) -> Option<Preview> {
    if dwg::Version::from_magic(bytes).is_some() {
        return from_dwg(&dwg::preview(bytes));
    }
    const NAME: &[u8] = b"THUMBNAILIMAGE";
    let at = bytes
        .windows(NAME.len())
        .rposition(|w| w == NAME)
        .filter(|&at| section_name(bytes, at))?;
    let rest = bytes.get(at + NAME.len()..)?;
    // From the line after the name: 90, its size, then the 310 chunks.
    let rest = rest.get(rest.iter().position(|&c| c == b'\n')? + 1..)?;
    let mut tags = Vec::new();
    let mut pairs = exav_unpack::dxf::Tags::new(rest);
    for t in pairs.by_ref() {
        if t.code == 0 {
            break;
        }
        tags.push(t);
    }
    from_dxf(&tags)
}

/// Whether `NAME` at `at` is the value of a group 2 line: the line before
/// holds `2`.
fn section_name(bytes: &[u8], at: usize) -> bool {
    let Some(before) = bytes.get(..at) else {
        return false;
    };
    let mut lines = before.rsplit(|&c| c == b'\n');
    // What precedes the name on its own line, then the line before.
    let own = lines.next().unwrap_or_default();
    let code = lines.next().unwrap_or_default();
    own.iter().all(|c| c.is_ascii_whitespace()) && code.trim_ascii() == b"2"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ascii_dxf_thumbnail_is_found_from_the_end() {
        // A 1x1 24-bit bitmap.
        let mut dib = Vec::new();
        dib.extend(40u32.to_le_bytes());
        dib.extend(1i32.to_le_bytes());
        dib.extend(1i32.to_le_bytes());
        dib.extend(1u16.to_le_bytes());
        dib.extend(24u16.to_le_bytes());
        dib.extend([0u8; 24]);
        dib.extend([0x10, 0x20, 0x30, 0]);
        let hex: String = dib.iter().map(|b| format!("{b:02X}")).collect();
        let dxf = format!(
            "  0\r\nSECTION\r\n  2\r\nENTITIES\r\n  0\r\nTEXT\r\n  1\r\nTHUMBNAILIMAGE\r\n  0\r\nENDSEC\r\n\
             \x20 0\r\nSECTION\r\n  2\r\nTHUMBNAILIMAGE\r\n 90\r\n{}\r\n310\r\n{hex}\r\n  0\r\nENDSEC\r\n  0\r\nEOF\r\n",
            dib.len()
        );
        let p = preview(dxf.as_bytes()).unwrap();
        assert_eq!(p.format, PreviewFormat::Bmp);
        assert_eq!(&p.data[..2], b"BM");
        assert_eq!(&p.data[14..], &dib[..]);
        // The reader puts the same in the model.
        let d = crate::formats::cad::read_dxf(dxf.as_bytes()).unwrap();
        assert_eq!(d.preview, Some(p));
        // The same name as a text value is not the section.
        let cut = dxf.find("  0\r\nSECTION\r\n  2\r\nTHUMB").unwrap();
        assert_eq!(preview(&dxf.as_bytes()[..cut]), None);
    }
}
