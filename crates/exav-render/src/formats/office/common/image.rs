//! Pictures by their first bytes: the format, the size in pixels, and the
//! natural size in EMU where the file says it (resolution of a bitmap,
//! frame of a metafile).

use super::bytes::{Cur, u16_at, u32_at};

/// The extension of a picture's format: png, jpeg, gif, bmp, tiff, emf,
/// wmf or svg.
pub fn ext(d: &[u8]) -> Option<&'static str> {
    Some(match d {
        [0x89, b'P', b'N', b'G', ..] => "png",
        [0xFF, 0xD8, ..] => "jpeg",
        [b'G', b'I', b'F', ..] => "gif",
        [b'B', b'M', ..] => "bmp",
        [b'I', b'I', 42, 0, ..] | [b'M', b'M', 0, 42, ..] => "tiff",
        [1, 0, 0, 0, _, _, _, _, ..] if d.len() > 44 && &d[40..44] == b" EMF" => "emf",
        [0xD7, 0xCD, 0xC6, 0x9A, ..] | [1, 0, 9, 0, ..] | [2, 0, 9, 0, ..] => "wmf",
        _ => {
            let head = String::from_utf8_lossy(&d[..d.len().min(512)]);
            if head.contains("<svg") {
                "svg"
            } else {
                return None;
            }
        }
    })
}

/// Width and height in pixels of a PNG, JPEG, GIF or BMP.
pub fn pixel_size(d: &[u8]) -> Option<(u32, u32)> {
    match ext(d)? {
        "png" if d.len() >= 24 => {
            let w = be32(d, 16);
            let h = be32(d, 20);
            Some((w, h))
        }
        "gif" if d.len() >= 10 => Some((u32::from(u16_at(d, 6)), u32::from(u16_at(d, 8)))),
        "bmp" if d.len() >= 26 => {
            let hdr = u32_at(d, 14);
            if hdr == 12 {
                Some((u32::from(u16_at(d, 18)), u32::from(u16_at(d, 20))))
            } else {
                let w = u32_at(d, 18) as i32;
                let h = u32_at(d, 22) as i32;
                Some((w.unsigned_abs(), h.unsigned_abs()))
            }
        }
        "jpeg" => jpeg_size(d).map(|(w, h, _)| (w, h)),
        _ => None,
    }
}

fn be32(d: &[u8], p: usize) -> u32 {
    match d.get(p..p + 4) {
        Some(&[a, b, c, e]) => u32::from_be_bytes([a, b, c, e]),
        _ => 0,
    }
}

fn be16(d: &[u8], p: usize) -> u16 {
    match d.get(p..p + 2) {
        Some(&[a, b]) => u16::from_be_bytes([a, b]),
        _ => 0,
    }
}

/// Dots per inch, horizontally and vertically.
type Dpi = (f64, f64);

/// Width, height and the JFIF density of a JPEG.
fn jpeg_size(d: &[u8]) -> Option<(u32, u32, Option<Dpi>)> {
    let mut p = 2usize;
    let mut dpi = None;
    let mut n = 0;
    while p + 4 <= d.len() && n < 4096 {
        n += 1;
        if d[p] != 0xFF {
            p += 1;
            continue;
        }
        let m = d[p + 1];
        if m == 0xFF {
            p += 1;
            continue;
        }
        if (0xD0..=0xD9).contains(&m) || m == 0x01 {
            p += 2;
            continue;
        }
        let len = usize::from(be16(d, p + 2));
        if m == 0xE0 && d.get(p + 4..p + 9) == Some(b"JFIF\0") {
            let unit = d.get(p + 11).copied().unwrap_or(0);
            let (x, y) = (f64::from(be16(d, p + 12)), f64::from(be16(d, p + 14)));
            if x > 0.0 && y > 0.0 {
                dpi = match unit {
                    1 => Some((x, y)),
                    2 => Some((x * 2.54, y * 2.54)),
                    _ => None,
                };
            }
        }
        if (0xC0..=0xCF).contains(&m) && !matches!(m, 0xC4 | 0xC8 | 0xCC) {
            let h = u32::from(be16(d, p + 5));
            let w = u32::from(be16(d, p + 7));
            return Some((w, h, dpi));
        }
        if len < 2 {
            return None;
        }
        p += 2 + len;
    }
    None
}

/// The resolution of a PNG (pHYs chunk), dots per inch.
fn png_dpi(d: &[u8]) -> Option<(f64, f64)> {
    let mut p = 8usize;
    let mut n = 0;
    while p + 12 <= d.len() && n < 256 {
        n += 1;
        let len = be32(d, p) as usize;
        let kind = d.get(p + 4..p + 8)?;
        if kind == b"pHYs" && len >= 9 && d.get(p + 16) == Some(&1) {
            // Dots per metre are whole numbers: 2835 is 72 dpi, not 72.009.
            let snap = |v: f64| {
                if (v - v.round()).abs() < 0.05 {
                    v.round()
                } else {
                    v
                }
            };
            let x = snap(f64::from(be32(d, p + 8)) * 0.0254);
            let y = snap(f64::from(be32(d, p + 12)) * 0.0254);
            return (x > 0.0 && y > 0.0).then_some((x, y));
        }
        if kind == b"IDAT" {
            break;
        }
        p = p.checked_add(12 + len)?;
    }
    None
}

/// The picture's natural size in EMU, when it can be told.
pub fn natural_emu(d: &[u8]) -> Option<(i64, i64)> {
    const EMU_IN: f64 = 914_400.0;
    match ext(d)? {
        "emf" => {
            // Header: bounds (device), frame in 0.01 mm at 24..40.
            let mut c = Cur::at(d, 24);
            let (l, t, r, b) = (c.i32(), c.i32(), c.i32(), c.i32());
            let (w, h) = (i64::from(r) - i64::from(l), i64::from(b) - i64::from(t));
            (w > 0 && h > 0).then_some((w * 360, h * 360))
        }
        "wmf" if d.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) => {
            let mut c = Cur::at(d, 6);
            let (l, t, r, b) = (c.i16(), c.i16(), c.i16(), c.i16());
            let inch = f64::from(c.u16()).max(1.0);
            let (w, h) = (f64::from(r) - f64::from(l), f64::from(b) - f64::from(t));
            (w > 0.0 && h > 0.0).then(|| ((w / inch * EMU_IN) as i64, (h / inch * EMU_IN) as i64))
        }
        "png" => {
            let (w, h) = pixel_size(d)?;
            let (dx, dy) = png_dpi(d).unwrap_or((96.0, 96.0));
            Some((
                (f64::from(w) / dx * EMU_IN) as i64,
                (f64::from(h) / dy * EMU_IN) as i64,
            ))
        }
        "jpeg" => {
            let (w, h, dpi) = jpeg_size(d)?;
            let (dx, dy) = dpi.unwrap_or((96.0, 96.0));
            Some((
                (f64::from(w) / dx * EMU_IN) as i64,
                (f64::from(h) / dy * EMU_IN) as i64,
            ))
        }
        "gif" | "bmp" => {
            let (w, h) = pixel_size(d)?;
            Some((i64::from(w) * 9525, i64::from(h) * 9525))
        }
        _ => None,
    }
}

/// A device-independent bitmap (BITMAPINFO and pixels) with the file header
/// it lacks.
pub fn dib_to_bmp(dib: &[u8]) -> Vec<u8> {
    let hsize = u32_at(dib, 0) as usize;
    let bits = u32::from(u16_at(dib, 14));
    let used = u32_at(dib, 32);
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

    fn png(w: u32, h: u32, phys: Option<(u32, u32)>) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 2, 0, 0, 0, 0, 0, 0, 0]);
        if let Some((x, y)) = phys {
            v.extend_from_slice(&9u32.to_be_bytes());
            v.extend_from_slice(b"pHYs");
            v.extend_from_slice(&x.to_be_bytes());
            v.extend_from_slice(&y.to_be_bytes());
            v.push(1);
            v.extend_from_slice(&[0; 4]);
        }
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(b"IDAT");
        v
    }

    #[test]
    fn formats_and_sizes() {
        assert_eq!(ext(b"\x89PNG\r\n"), Some("png"));
        assert_eq!(ext(&[0xFF, 0xD8, 0xFF]), Some("jpeg"));
        assert_eq!(ext(b"<?xml version='1.0'?><svg>"), Some("svg"));
        assert_eq!(ext(b"VCLMTF"), None);
        let p = png(100, 50, None);
        assert_eq!(pixel_size(&p), Some((100, 50)));
        assert_eq!(natural_emu(&p), Some((952_500, 476_250)));
        // 2835 dots per metre is 72 dpi.
        let p = png(72, 36, Some((2835, 2835)));
        assert_eq!(natural_emu(&p), Some((914_400, 457_200)));
    }

    #[test]
    fn jpeg_and_metafile_sizes() {
        let mut j = vec![0xFF, 0xD8];
        j.extend_from_slice(&[0xFF, 0xE0, 0, 16]);
        j.extend_from_slice(b"JFIF\0\x01\x01\x01");
        j.extend_from_slice(&[0, 96, 0, 96, 0, 0]);
        j.extend_from_slice(&[0xFF, 0xC0, 0, 11, 8, 0, 20, 0, 40, 1, 1, 0x11, 0]);
        assert_eq!(pixel_size(&j), Some((40, 20)));
        assert_eq!(natural_emu(&j), Some((40 * 9525, 20 * 9525)));
        // Placeable WMF: 1440 units per inch, 1440 x 720.
        let mut w = vec![0xD7, 0xCD, 0xC6, 0x9A, 0, 0];
        for v in [0i16, 0, 1440, 720] {
            w.extend_from_slice(&v.to_le_bytes());
        }
        w.extend_from_slice(&1440u16.to_le_bytes());
        assert_eq!(natural_emu(&w), Some((914_400, 457_200)));
        // An EMF frame of 100 x 50 mm.
        let mut e = vec![0u8; 88];
        e[0] = 1;
        e[40..44].copy_from_slice(b" EMF");
        e[24..40].copy_from_slice(
            &[0i32, 0, 10_000, 5_000]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        assert_eq!(natural_emu(&e), Some((3_600_000, 1_800_000)));
    }

    #[test]
    fn dib_gets_a_file_header() {
        let mut dib = vec![0u8; 40];
        dib[0] = 40;
        dib[14] = 8;
        let b = dib_to_bmp(&dib);
        assert_eq!(&b[..2], b"BM");
        // 14 + 40 + 256 palette entries.
        assert_eq!(u32_at(&b, 10), 14 + 40 + 1024);
    }
}
