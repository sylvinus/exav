//! STL, binary and ASCII, into a [`Scene`] of one element.
//!
//! A binary file is 80 bytes of header, a little-endian `u32` count, and
//! 50 bytes per facet: a normal, three corners (`f32` each) and a 16-bit
//! attribute. An ASCII file is `solid`, then `facet normal .. outer loop
//! vertex x y z .. endloop endfacet` records, then `endsolid`. Binary
//! headers often start with "solid" too, so a file is read as ASCII only
//! when its size is not that of the binary file its count declares and its
//! start is text.
//!
//! The facet normals are not used: some writers leave them zero. Each facet
//! is shaded flat with the normal its corners give.
//!
//! Colours (binary only), two conventions for the attribute:
//! - VisCAM and SolidView: bit 15 set means a colour, 5 bits each of red
//!   (bits 10 to 14), green and blue (bits 0 to 4).
//! - Materialise Magics, whose header holds `COLOR=` and four bytes of a
//!   default RGBA: bit 15 clear means the facet's own colour, red in bits 0
//!   to 4 and blue in bits 10 to 14; set means the default.

use std::fmt;

use super::mesh::{cross, dot, sub, Batch, Element, Range, Scene};

/// Why a file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Neither a binary nor an ASCII STL.
    NotStl,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotStl => f.write_str("not an STL file"),
        }
    }
}

impl std::error::Error for Error {}

/// Reads at most `max_triangles` facets; past them the rest are counted in
/// `warnings.truncated` (as one element). A binary file shorter than its
/// count says is read as far as it goes and flagged `damaged`.
pub fn read(bytes: &[u8], max_triangles: usize) -> Result<Scene, Error> {
    let mut scene = Scene::default();
    let declared = (bytes.len() >= 84)
        .then(|| u32::from_le_bytes([bytes[80], bytes[81], bytes[82], bytes[83]]) as u64);
    let exact_binary = declared.is_some_and(|n| 84 + 50 * n == bytes.len() as u64);
    let batch = if !exact_binary && looks_ascii(bytes) {
        read_ascii(bytes, max_triangles, &mut scene)
    } else if let Some(n) = declared {
        read_binary(bytes, n, max_triangles, &mut scene)
    } else {
        return Err(Error::NotStl);
    };
    let count = batch.indices.len() as u32;
    super::mesh::grow(&mut scene.bounds, &batch.positions);
    if count > 0 {
        scene.elements.push(Element {
            ranges: vec![Range {
                batch: 0,
                first: 0,
                count,
            }],
            ..Element::default()
        });
        scene.batches.push(batch);
    }
    Ok(scene)
}

fn looks_ascii(bytes: &[u8]) -> bool {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let rest = &bytes[start..];
    rest.len() >= 5
        && rest[..5].eq_ignore_ascii_case(b"solid")
        && rest[..rest.len().min(4096)]
            .iter()
            .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..0x7f).contains(&b))
}

/// Appends one flat-shaded triangle; false when it has no area.
fn push(batch: &mut Batch, c: [[f32; 3]; 3]) -> bool {
    let p = c.map(|v| v.map(f64::from));
    if !p.iter().flatten().all(|v| v.is_finite()) {
        return false;
    }
    let n = cross(sub(p[1], p[0]), sub(p[2], p[0]));
    let len = dot(n, n).sqrt();
    if !len.is_finite() || len <= 0.0 {
        return false;
    }
    let n = [
        (n[0] / len) as f32,
        (n[1] / len) as f32,
        (n[2] / len) as f32,
    ];
    let base = (batch.positions.len() / 3) as u32;
    for v in c {
        batch.positions.extend_from_slice(&v);
        batch.normals.extend_from_slice(&n);
    }
    batch.indices.extend_from_slice(&[base, base + 1, base + 2]);
    true
}

fn read_binary(bytes: &[u8], declared: u64, max: usize, scene: &mut Scene) -> Batch {
    let available = ((bytes.len() - 84) / 50) as u64;
    if declared > available {
        scene.warnings.damaged = true;
    }
    let count = declared.min(available) as usize;
    let header = &bytes[..80];
    let magics = header
        .windows(6)
        .position(|w| w == b"COLOR=")
        .and_then(|i| header.get(i + 6..i + 10));
    let default = magics.map(|c| [c[0], c[1], c[2]]);
    let mut batch = Batch::default();
    let mut colors: Vec<u8> = Vec::new();
    let mut coloured = false;
    let take = count.min(max);
    if count > max {
        scene.warnings.truncated = 1;
    }
    batch.positions.reserve(take * 9);
    for facet in bytes[84..].as_chunks::<50>().0.iter().take(take) {
        let f = |i: usize| f32::from_le_bytes([facet[i], facet[i + 1], facet[i + 2], facet[i + 3]]);
        let c = [
            [f(12), f(16), f(20)],
            [f(24), f(28), f(32)],
            [f(36), f(40), f(44)],
        ];
        let attr = u16::from_le_bytes([facet[48], facet[49]]);
        let five = |shift: u16| (((attr >> shift) & 31) as u32 * 255 / 31) as u8;
        let rgb = match default {
            Some(d) if attr & 0x8000 != 0 => Some(d),
            Some(_) => Some([five(0), five(5), five(10)]),
            None if attr & 0x8000 != 0 => Some([five(10), five(5), five(0)]),
            None => None,
        };
        if push(&mut batch, c) {
            coloured |= rgb.is_some();
            let rgb = rgb.unwrap_or([255, 255, 255]);
            for _ in 0..3 {
                colors.extend_from_slice(&rgb);
            }
        }
    }
    // A Magics default alone colours the whole part; VisCAM colours only
    // when a facet has one.
    if coloured || default.is_some() {
        batch.colors = Some(colors);
    }
    batch
}

fn read_ascii(bytes: &[u8], max: usize, scene: &mut Scene) -> Batch {
    let mut batch = Batch::default();
    let mut corners: Vec<[f32; 3]> = Vec::new();
    let mut tokens = bytes
        .split(|b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let mut triangles = 0usize;
    let number = |t: Option<&[u8]>| {
        t.and_then(|t| std::str::from_utf8(t).ok())
            .and_then(|s| s.parse::<f32>().ok())
    };
    let mut flush = |corners: &mut Vec<[f32; 3]>, batch: &mut Batch, scene: &mut Scene| {
        // A loop of more than three corners is a fan.
        for k in 1..corners.len().saturating_sub(1) {
            if triangles >= max {
                scene.warnings.truncated = 1;
                break;
            }
            if push(batch, [corners[0], corners[k], corners[k + 1]]) {
                triangles += 1;
            }
        }
        corners.clear();
    };
    while let Some(t) = tokens.next() {
        if t.eq_ignore_ascii_case(b"vertex") {
            match (
                number(tokens.next()),
                number(tokens.next()),
                number(tokens.next()),
            ) {
                (Some(x), Some(y), Some(z)) => corners.push([x, y, z]),
                _ => scene.warnings.damaged = true,
            }
            // Bounded by the file: a loop never holds more corners than
            // the file has `vertex` keywords.
        } else if t.eq_ignore_ascii_case(b"endloop")
            || t.eq_ignore_ascii_case(b"endfacet")
            || t.eq_ignore_ascii_case(b"facet")
        {
            flush(&mut corners, &mut batch, scene);
        }
        if scene.warnings.truncated > 0 {
            break;
        }
    }
    flush(&mut corners, &mut batch, scene);
    batch
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary(header: &[u8], facets: &[([[f32; 3]; 3], u16)], declared: Option<u32>) -> Vec<u8> {
        let mut b = header.to_vec();
        b.resize(80, b' ');
        b.extend_from_slice(&declared.unwrap_or(facets.len() as u32).to_le_bytes());
        for (c, attr) in facets {
            b.extend_from_slice(&[0u8; 12]);
            for v in c.iter().flatten() {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&attr.to_le_bytes());
        }
        b
    }

    const T: [[f32; 3]; 3] = [[0., 0., 0.], [1., 0., 0.], [0., 1., 0.]];

    #[test]
    fn a_binary_header_saying_solid_is_still_binary() {
        let s = read(&binary(b"solid fooled you", &[(T, 0), (T, 0)], None), 100).unwrap();
        assert_eq!(s.triangles(), 2);
        assert!(!s.warnings.damaged);
    }

    #[test]
    fn a_count_past_the_end_reads_what_is_there() {
        let s = read(&binary(b"x", &[(T, 0)], Some(1_000_000)), 100).unwrap();
        assert_eq!(s.triangles(), 1);
        assert!(s.warnings.damaged);
    }

    #[test]
    fn viscam_colours_need_bit_15() {
        let red: u16 = 0x8000 | (31 << 10);
        let s = read(&binary(b"x", &[(T, red), (T, 0)], None), 100).unwrap();
        let c = s.batches[0].colors.as_ref().unwrap();
        assert_eq!(&c[..3], &[255, 0, 0]);
        assert_eq!(&c[9..12], &[255, 255, 255]);
    }

    #[test]
    fn ascii_with_a_polygon_loop_is_a_fan() {
        let text = b"solid q\nfacet normal 0 0 1\nouter loop\nvertex 0 0 0\nvertex 1 0 0\nvertex 1 1 0\nvertex 0 1 0\nendloop\nendfacet\nendsolid q\n";
        let s = read(text, 100).unwrap();
        assert_eq!(s.triangles(), 2);
    }

    #[test]
    fn the_budget_stops_reading() {
        let s = read(&binary(b"x", &[(T, 0); 5], None), 3).unwrap();
        assert_eq!(s.triangles(), 3);
        assert_eq!(s.warnings.truncated, 1);
    }

    #[test]
    fn short_input_is_not_stl() {
        assert_eq!(read(b"hello", 10).unwrap_err(), Error::NotStl);
    }
}
