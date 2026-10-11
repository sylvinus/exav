//! A compact, directly-addressable form of a parsed stroke font.
//!
//! The text form is convenient to author and slow to load: NewStroke is 314 KB
//! of decimal numbers that would have to be parsed on the way into the wasm.
//! This is the same font as a byte table the build step produces once, laid out
//! so a glyph is found by binary search and read without allocating.
//!
//! The encoder half is also compiled into `build.rs`, so this module depends on
//! nothing but `fontobene`.
//!
//! One property of real stroke fonts makes this small: NewStroke's 68,968
//! coordinates take only 64 distinct values, so a coordinate is a byte indexing
//! a palette rather than a number. Fonts with a wider range of coordinates fall
//! back to storing them outright, which the header records.

use std::collections::BTreeSet;

// `super` is the stroke font module in the library and the build script's
// crate root in `build.rs`, which includes this file and `fontobene.rs` too.
use super::fontobene::Font;

/// File magic: "FoBe" for FontoBene.
pub const MAGIC: u32 = u32::from_le_bytes(*b"FoBe");
pub const VERSION: u16 = 1;

/// Fixed-point divisor for stored coordinates, advances and spacings.
///
/// Source coordinates are given to two decimals in a 9-unit em, so 1/128 of a
/// unit is well under the precision anyone authored.
pub const SCALE: f32 = 128.0;

/// Coordinates are palette indices rather than values.
pub const FLAG_PALETTE: u16 = 1 << 0;
/// The font is monospaced and `monospace_width` applies.
pub const FLAG_MONOSPACE: u16 = 1 << 1;

/// Above this many distinct coordinates a palette index no longer fits a byte.
const MAX_PALETTE: usize = 256;

// Header layout, in bytes from the start. The three spacings are whole floats
// rather than fixed point: there is one of each, they are applied to every
// glyph, and rounding 1.8 onto a 128th grid would bias every advance.
const H_MAGIC: usize = 0;
const H_VERSION: usize = 4;
const H_FLAGS: usize = 6;
const H_LETTER_SPACING: usize = 8;
const H_LINE_SPACING: usize = 12;
const H_MONOSPACE_WIDTH: usize = 16;
const H_PALETTE_LEN: usize = 20;
const H_GLYPH_COUNT: usize = 24;
const H_POLY_COUNT: usize = 28;
const H_VERT_COUNT: usize = 32;
pub const HEADER_BYTES: usize = 36;

fn fixed(v: f32) -> i16 {
    (v * SCALE).round().clamp(i16::MIN as f32, i16::MAX as f32) as i16
}

/// Pack a parsed font into the byte table `StrokeFont` reads.
///
/// Sections follow the header in this order, each tightly packed and
/// little-endian:
///
/// | section | entries | width |
/// |---|---|---|
/// | palette | `palette_len` | `i16` |
/// | codepoints, ascending | `glyph_count` | `u32` |
/// | first polyline of each glyph, plus a terminator | `glyph_count + 1` | `u32` |
/// | advance of each glyph | `glyph_count` | `i16` |
/// | first vertex of each polyline, plus a terminator | `poly_count + 1` | `u32` |
/// | vertices | `vert_count` | 2 bytes if palettised, else two `i16` |
pub fn encode(font: &Font) -> Vec<u8> {
    let mut codepoints: Vec<u32> = font.glyphs.keys().copied().collect();
    codepoints.sort_unstable();

    // Collect the distinct coordinates. Fixed point first, so that two values
    // that round together share an entry.
    let mut distinct: BTreeSet<i16> = BTreeSet::new();
    for cp in &codepoints {
        for p in font.glyphs[cp].polylines.iter().flatten() {
            distinct.insert(fixed(p[0]));
            distinct.insert(fixed(p[1]));
            if distinct.len() > MAX_PALETTE {
                break;
            }
        }
    }
    let palettised = distinct.len() <= MAX_PALETTE;
    // Sorted, so a coordinate finds its index by binary search.
    let palette: Vec<i16> = if palettised {
        distinct.into_iter().collect()
    } else {
        Vec::new()
    };
    let index_of = |v: f32| -> u8 {
        palette
            .binary_search(&fixed(v))
            .expect("every coordinate was collected above") as u8
    };

    let mut flags = 0u16;
    if palettised {
        flags |= FLAG_PALETTE;
    }
    if font.monospace_width.is_some() {
        flags |= FLAG_MONOSPACE;
    }

    let poly_count: usize = codepoints
        .iter()
        .map(|c| font.glyphs[c].polylines.len())
        .sum();
    let vert_count: usize = codepoints
        .iter()
        .flat_map(|c| font.glyphs[c].polylines.iter())
        .map(|p| p.len())
        .sum();

    let mut out = Vec::with_capacity(HEADER_BYTES + vert_count * 4);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&font.letter_spacing.to_le_bytes());
    out.extend_from_slice(&font.line_spacing.to_le_bytes());
    out.extend_from_slice(&font.monospace_width.unwrap_or(0.0).to_le_bytes());
    out.extend_from_slice(&(palette.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // pad, keeping the counts aligned
    out.extend_from_slice(&(codepoints.len() as u32).to_le_bytes());
    out.extend_from_slice(&(poly_count as u32).to_le_bytes());
    out.extend_from_slice(&(vert_count as u32).to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_BYTES);

    for v in &palette {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for c in &codepoints {
        out.extend_from_slice(&c.to_le_bytes());
    }

    let mut poly = 0u32;
    for c in &codepoints {
        out.extend_from_slice(&poly.to_le_bytes());
        poly += font.glyphs[c].polylines.len() as u32;
    }
    out.extend_from_slice(&poly.to_le_bytes());

    for c in &codepoints {
        out.extend_from_slice(&fixed(font.advance(&font.glyphs[c])).to_le_bytes());
    }

    let mut vert = 0u32;
    for c in &codepoints {
        for p in &font.glyphs[c].polylines {
            out.extend_from_slice(&vert.to_le_bytes());
            vert += p.len() as u32;
        }
    }
    out.extend_from_slice(&vert.to_le_bytes());

    for c in &codepoints {
        for p in &font.glyphs[c].polylines {
            for v in p {
                if palettised {
                    out.push(index_of(v[0]));
                    out.push(index_of(v[1]));
                } else {
                    out.extend_from_slice(&fixed(v[0]).to_le_bytes());
                    out.extend_from_slice(&fixed(v[1]).to_le_bytes());
                }
            }
        }
    }

    out
}

/// Where each section begins, once the header has been read.
#[derive(Clone, Copy)]
pub(crate) struct Layout {
    pub palette: usize,
    pub codepoints: usize,
    pub glyph_poly: usize,
    pub advances: usize,
    pub poly_vert: usize,
    pub verts: usize,
    pub glyph_count: usize,
    pub palettised: bool,
}

pub(crate) fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

pub(crate) fn i16_at(b: &[u8], o: usize) -> i16 {
    i16::from_le_bytes([b[o], b[o + 1]])
}

pub(crate) fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub(crate) fn f32_at(b: &[u8], o: usize) -> f32 {
    f32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Validate a byte table and locate its sections.
///
/// Every later accessor indexes without bounds checks of its own, so this has
/// to reject anything whose counts do not match its length.
pub(crate) fn layout(b: &[u8]) -> Option<Layout> {
    if b.len() < HEADER_BYTES || u32_at(b, H_MAGIC) != MAGIC || u16_at(b, H_VERSION) != VERSION {
        return None;
    }
    let flags = u16_at(b, H_FLAGS);
    let palettised = flags & FLAG_PALETTE != 0;
    let palette_len = u16_at(b, H_PALETTE_LEN) as usize;
    let glyph_count = u32_at(b, H_GLYPH_COUNT) as usize;
    let poly_count = u32_at(b, H_POLY_COUNT) as usize;
    let vert_count = u32_at(b, H_VERT_COUNT) as usize;
    if palettised && palette_len > MAX_PALETTE {
        return None;
    }

    let palette = HEADER_BYTES;
    let codepoints = palette.checked_add(palette_len.checked_mul(2)?)?;
    let glyph_poly = codepoints.checked_add(glyph_count.checked_mul(4)?)?;
    let advances = glyph_poly.checked_add(glyph_count.checked_add(1)?.checked_mul(4)?)?;
    let poly_vert = advances.checked_add(glyph_count.checked_mul(2)?)?;
    let verts = poly_vert.checked_add(poly_count.checked_add(1)?.checked_mul(4)?)?;
    let end = verts.checked_add(vert_count.checked_mul(if palettised { 2 } else { 4 })?)?;
    if end != b.len() {
        return None;
    }

    // The offset tables are read without checking, so they have to be sane:
    // ascending, and ending exactly at the counts the header declares.
    for i in 0..glyph_count {
        let (a, z) = (
            u32_at(b, glyph_poly + i * 4),
            u32_at(b, glyph_poly + i * 4 + 4),
        );
        if a > z || z as usize > poly_count {
            return None;
        }
    }
    if glyph_count > 0 && u32_at(b, glyph_poly + glyph_count * 4) as usize != poly_count {
        return None;
    }
    for i in 0..poly_count {
        let (a, z) = (
            u32_at(b, poly_vert + i * 4),
            u32_at(b, poly_vert + i * 4 + 4),
        );
        if a > z || z as usize > vert_count {
            return None;
        }
    }
    if poly_count > 0 && u32_at(b, poly_vert + poly_count * 4) as usize != vert_count {
        return None;
    }
    // A palette index is a byte, so any value below the length is in range;
    // only an undersized palette can be out of range.
    if palettised && vert_count > 0 {
        for i in 0..vert_count * 2 {
            if b[verts + i] as usize >= palette_len {
                return None;
            }
        }
    }

    Some(Layout {
        palette,
        codepoints,
        glyph_poly,
        advances,
        poly_vert,
        verts,
        glyph_count,
        palettised,
    })
}

pub(crate) fn letter_spacing(b: &[u8]) -> f32 {
    f32_at(b, H_LETTER_SPACING)
}

pub(crate) fn line_spacing(b: &[u8]) -> f32 {
    f32_at(b, H_LINE_SPACING)
}

pub(crate) fn monospace_width(b: &[u8]) -> Option<f32> {
    (u16_at(b, H_FLAGS) & FLAG_MONOSPACE != 0).then(|| f32_at(b, H_MONOSPACE_WIDTH))
}

/// Read one vertex, in font units.
pub(crate) fn vertex(b: &[u8], l: &Layout, i: usize) -> [f32; 2] {
    if l.palettised {
        let o = l.verts + i * 2;
        let c = |k: usize| i16_at(b, l.palette + b[o + k] as usize * 2) as f32 / SCALE;
        [c(0), c(1)]
    } else {
        let o = l.verts + i * 4;
        [i16_at(b, o) as f32 / SCALE, i16_at(b, o + 2) as f32 / SCALE]
    }
}
