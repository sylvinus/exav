//! DDS textures to look at that `image` does not decode (it reads DXT1, DXT3
//! and DXT5 of sizes that are multiples of 4, and nothing else): BC1 to BC7,
//! uncompressed layouts by their masks, 8-bit palettes, half and
//! single-precision floats. Also DXT1 with transparent texels, which `image`
//! draws opaque. Used by `decode_any` only, so that `decode`, and what is
//! hashed, stay what ClamAV's would be.
//!
//! The first surface of the file is the picture: the largest mip level of the
//! first face of a cube map, slice of a volume or element of an array.

use super::{within, Channels, Error, Pixels, Samples};

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

/// How the texels of a surface are stored.
enum Layout {
    /// 4x4 blocks: bytes per block, and what is in them.
    Blocks(usize, Block),
    /// Pixels of `bytes` each, with the masks of the channels.
    Masks {
        bytes: usize,
        red: u32,
        green: u32,
        blue: u32,
        alpha: u32,
        /// Red is a luminance; with no alpha mask, the alpha is opaque.
        luminance: bool,
    },
    /// Half (16 bits) or single (32 bits) floats, this many per pixel.
    Floats { bits: usize, channels: usize },
    /// 256 RGBA entries, then a byte per pixel.
    Palette,
}

#[derive(Clone, Copy)]
enum Block {
    Bc1,
    Bc2,
    Bc3,
    Bc4 { signed: bool },
    Bc5 { signed: bool },
    Bc6h { signed: bool },
    Bc7,
}

const fn masks(bytes: usize, red: u32, green: u32, blue: u32, alpha: u32) -> Layout {
    Layout::Masks {
        bytes,
        red,
        green,
        blue,
        alpha,
        luminance: false,
    }
}

const fn floats(bits: usize, channels: usize) -> Layout {
    Layout::Floats { bits, channels }
}

/// The layout a `DXGI_FORMAT` number stands for.
fn dxgi(format: u32) -> Option<Layout> {
    use Block::*;
    Some(match format {
        70..=72 => Layout::Blocks(8, Bc1),
        73..=75 => Layout::Blocks(16, Bc2),
        76..=78 => Layout::Blocks(16, Bc3),
        79 | 80 => Layout::Blocks(8, Bc4 { signed: false }),
        81 => Layout::Blocks(8, Bc4 { signed: true }),
        82 | 83 => Layout::Blocks(16, Bc5 { signed: false }),
        84 => Layout::Blocks(16, Bc5 { signed: true }),
        94 | 95 => Layout::Blocks(16, Bc6h { signed: false }),
        96 => Layout::Blocks(16, Bc6h { signed: true }),
        97..=99 => Layout::Blocks(16, Bc7),
        2 | 3 => floats(32, 4),
        10 | 11 => floats(16, 4),
        16 | 17 => floats(32, 2),
        34 => floats(16, 2),
        41 => floats(32, 1),
        54 => floats(16, 1),
        23..=25 => masks(4, 0x3ff, 0xffc00, 0x3ff0_0000, 0xc000_0000),
        27..=30 => masks(4, 0xff, 0xff00, 0xff_0000, 0xff00_0000),
        35 | 36 => masks(4, 0xffff, 0xffff_0000, 0, 0),
        48..=50 => masks(2, 0xff, 0xff00, 0, 0),
        56 => Layout::Masks {
            bytes: 2,
            red: 0xffff,
            green: 0,
            blue: 0,
            alpha: 0,
            luminance: true,
        },
        60..=62 => Layout::Masks {
            bytes: 1,
            red: 0xff,
            green: 0,
            blue: 0,
            alpha: 0,
            luminance: true,
        },
        65 => masks(1, 0, 0, 0, 0xff),
        85 => masks(2, 0xf800, 0x7e0, 0x1f, 0),
        86 => masks(2, 0x7c00, 0x3e0, 0x1f, 0x8000),
        87 | 90 | 91 => masks(4, 0xff_0000, 0xff00, 0xff, 0xff00_0000),
        88 | 92 | 93 => masks(4, 0xff_0000, 0xff00, 0xff, 0),
        115 => masks(2, 0xf00, 0xf0, 0xf, 0xf000),
        _ => return None,
    })
}

/// The layout the pixel format of the header says, and where the texels start.
fn layout(data: &[u8]) -> Option<(Layout, usize)> {
    let flags = u32_at(data, 80)?;
    let four_cc = data.get(84..88)?;
    if flags & 4 != 0 {
        use Block::*;
        let block = |bytes, b| Some((Layout::Blocks(bytes, b), 128));
        return match four_cc {
            b"DXT1" => block(8, Bc1),
            b"DXT2" | b"DXT3" => block(16, Bc2),
            b"DXT4" | b"DXT5" => block(16, Bc3),
            b"ATI1" | b"BC4U" => block(8, Bc4 { signed: false }),
            b"BC4S" => block(8, Bc4 { signed: true }),
            b"ATI2" | b"BC5U" => block(16, Bc5 { signed: false }),
            b"BC5S" => block(16, Bc5 { signed: true }),
            b"DX10" => Some((dxgi(u32_at(data, 128)?)?, 148)),
            // D3DFORMAT numbers written in place of a FourCC.
            _ => match u32::from_le_bytes(four_cc.try_into().ok()?) {
                111 => Some((floats(16, 1), 128)),
                112 => Some((floats(16, 2), 128)),
                113 => Some((floats(16, 4), 128)),
                114 => Some((floats(32, 1), 128)),
                115 => Some((floats(32, 2), 128)),
                116 => Some((floats(32, 4), 128)),
                _ => None,
            },
        };
    }
    if flags & 0x20 != 0 && flags & 0x40 == 0 {
        return Some((Layout::Palette, 128));
    }
    let bytes = (u32_at(data, 88)? as usize).div_ceil(8);
    if !(1..=4).contains(&bytes) {
        return None;
    }
    let (red, green, blue, alpha) = (
        u32_at(data, 92)?,
        u32_at(data, 96)?,
        u32_at(data, 100)?,
        u32_at(data, 104)?,
    );
    let luminance = flags & 0x2_0000 != 0;
    // DDPF_ALPHA: alpha and nothing else.
    let alpha_only = flags & 2 != 0 && flags & 0x40 == 0 && !luminance;
    if red | green | blue | alpha == 0 {
        return None;
    }
    Some((
        Layout::Masks {
            bytes,
            red,
            green,
            blue,
            alpha: if flags & 3 != 0 || alpha_only {
                alpha
            } else {
                0
            },
            luminance,
        },
        128,
    ))
}

/// Whether the file is BC1 with a transparent texel, which `image` draws
/// opaque: a block with its first colour not above its second keeps the index
/// 3 for no colour.
pub(super) fn punches_through(data: &[u8]) -> bool {
    let (Some((Layout::Blocks(8, Block::Bc1), start)), Some(height), Some(width)) =
        (layout(data), u32_at(data, 12), u32_at(data, 16))
    else {
        return false;
    };
    let blocks = (width as usize)
        .div_ceil(4)
        .saturating_mul((height as usize).div_ceil(4));
    data.get(start..).is_some_and(|body| {
        body.as_chunks::<8>().0.iter().take(blocks).any(|b| {
            u16::from_le_bytes([b[0], b[1]]) <= u16::from_le_bytes([b[2], b[3]])
                && b[4..]
                    .iter()
                    .any(|&i| (0..4).any(|k| i >> (2 * k) & 3 == 3))
        })
    })
}

pub(super) fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    if data.get(..4) != Some(b"DDS ") || u32_at(data, 4) != Some(124) {
        return Err(Error::Undecodable);
    }
    let height = u32_at(data, 12).ok_or(Error::Undecodable)?;
    let width = u32_at(data, 16).ok_or(Error::Undecodable)?;
    if width == 0 || height == 0 {
        return Err(Error::Undecodable);
    }
    let (layout, start) = layout(data).ok_or(Error::Undecodable)?;
    let texels = u64::from(width) * u64::from(height);
    within(texels.saturating_mul(24), max_alloc)?;
    let (w, h) = (width as usize, height as usize);
    let body = data.get(start..).ok_or(Error::Undecodable)?;
    match layout {
        Layout::Blocks(size, block) => blocks(body, w, h, size, block),
        Layout::Masks {
            bytes,
            red,
            green,
            blue,
            alpha,
            luminance,
        } => {
            let needed = w
                .checked_mul(h)
                .and_then(|n| n.checked_mul(bytes))
                .ok_or(Error::Undecodable)?;
            let rows = body.get(..needed).ok_or(Error::Undecodable)?;
            let channel = |px: u32, mask: u32| -> u8 {
                if mask == 0 {
                    return 0;
                }
                let shift = mask.trailing_zeros();
                let max = u64::from(mask >> shift);
                ((u64::from((px & mask) >> shift) * 255 + max / 2) / max) as u8
            };
            let mut out = Vec::with_capacity(w * h * 4);
            for p in rows.chunks_exact(bytes) {
                let mut px = 0u32;
                for (i, b) in p.iter().enumerate() {
                    px |= u32::from(*b) << (8 * i);
                }
                let a = if alpha != 0 { channel(px, alpha) } else { 255 };
                if luminance {
                    let l = channel(px, red);
                    out.extend([l, l, l, a]);
                } else if red | green | blue == 0 {
                    // Alpha alone, drawn as grey.
                    out.extend([a, a, a, 255]);
                } else {
                    out.extend([channel(px, red), channel(px, green), channel(px, blue), a]);
                }
            }
            Ok(rgba(width, height, out))
        }
        Layout::Palette => {
            let (palette, indices) = body.split_at_checked(1024).ok_or(Error::Undecodable)?;
            let indices = indices
                .get(..w.checked_mul(h).ok_or(Error::Undecodable)?)
                .ok_or(Error::Undecodable)?;
            let mut out = Vec::with_capacity(indices.len() * 4);
            for &i in indices {
                let at = usize::from(i) * 4;
                out.extend_from_slice(&palette[at..at + 4]);
            }
            Ok(rgba(width, height, out))
        }
        Layout::Floats { bits, channels } => {
            let needed = w
                .checked_mul(h)
                .and_then(|n| n.checked_mul(channels * bits / 8))
                .ok_or(Error::Undecodable)?;
            let raw = body.get(..needed).ok_or(Error::Undecodable)?;
            let value = |i: usize| -> f32 {
                if bits == 32 {
                    f32::from_le_bytes([raw[4 * i], raw[4 * i + 1], raw[4 * i + 2], raw[4 * i + 3]])
                } else {
                    half(u16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]))
                }
            };
            let mut out = Vec::with_capacity(w * h * 4);
            for p in 0..w * h {
                let v = |c: usize| value(p * channels + c);
                match channels {
                    1 => out.extend([v(0), v(0), v(0), 1.0]),
                    2 => out.extend([v(0), v(1), 0.0, 1.0]),
                    _ => out.extend([v(0), v(1), v(2), v(3)]),
                }
            }
            Ok(Pixels {
                width,
                height,
                channels: Channels::Rgba,
                samples: Samples::F32(out),
            })
        }
    }
}

fn rgba(width: u32, height: u32, samples: Vec<u8>) -> Pixels {
    Pixels {
        width,
        height,
        channels: Channels::Rgba,
        samples: Samples::U8(samples),
    }
}

/// An IEEE half-precision value from its bits.
fn half(bits: u16) -> f32 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from((bits >> 10) & 0x1f);
    let fraction = f32::from(bits & 0x3ff);
    match exponent {
        0 => sign * fraction * 2f32.powi(-24),
        31 if fraction == 0.0 => sign * f32::INFINITY,
        31 => f32::NAN,
        e => sign * (1.0 + fraction / 1024.0) * 2f32.powi(e - 15),
    }
}

/// The first surface of block-compressed texels, cropped from whole blocks.
fn blocks(body: &[u8], w: usize, h: usize, size: usize, block: Block) -> Result<Pixels, Error> {
    let (bx, by) = (w.div_ceil(4), h.div_ceil(4));
    let needed = bx
        .checked_mul(by)
        .and_then(|n| n.checked_mul(size))
        .ok_or(Error::Undecodable)?;
    let body = body.get(..needed).ok_or(Error::Undecodable)?;
    let (pw, ph) = (bx * 4, by * 4);
    let mut rgba8 = vec![0u8; pw * ph * 4];
    let mut hdr = matches!(block, Block::Bc6h { .. }).then(|| vec![0f32; pw * ph * 3]);
    for (i, b) in body.chunks_exact(size).enumerate() {
        let (x, y) = (i % bx * 4, i / bx * 4);
        let at = (y * pw + x) * 4;
        match block {
            Block::Bc1 => bcdec_rs::bc1(b, &mut rgba8[at..], pw * 4),
            Block::Bc2 => bcdec_rs::bc2(b, &mut rgba8[at..], pw * 4),
            Block::Bc3 => bcdec_rs::bc3(b, &mut rgba8[at..], pw * 4),
            Block::Bc7 => bcdec_rs::bc7(b, &mut rgba8[at..], pw * 4),
            Block::Bc4 { signed } => {
                let mut one = [0u8; 16];
                bcdec_rs::bc4(b, &mut one, 4, signed);
                for (k, v) in one.iter().enumerate() {
                    let o = ((y + k / 4) * pw + x + k % 4) * 4;
                    let v = if signed { v.wrapping_add(128) } else { *v };
                    rgba8[o..o + 4].copy_from_slice(&[v, v, v, 255]);
                }
            }
            Block::Bc5 { signed } => {
                let mut two = [0u8; 32];
                bcdec_rs::bc5(b, &mut two, 8, signed);
                for k in 0..16 {
                    let o = ((y + k / 4) * pw + x + k % 4) * 4;
                    let (mut r, mut g) = (two[2 * k], two[2 * k + 1]);
                    if signed {
                        r = r.wrapping_add(128);
                        g = g.wrapping_add(128);
                    }
                    // Two channels are a normal map's x and y: z follows.
                    let (nx, ny) = (f32::from(r) / 127.5 - 1.0, f32::from(g) / 127.5 - 1.0);
                    let nz = (1.0 - nx * nx - ny * ny).max(0.0).sqrt();
                    rgba8[o..o + 4].copy_from_slice(&[
                        r,
                        g,
                        ((nz + 1.0) * 127.5).round() as u8,
                        255,
                    ]);
                }
            }
            Block::Bc6h { signed } => {
                if let Some(hdr) = hdr.as_mut() {
                    bcdec_rs::bc6h_float(b, &mut hdr[(y * pw + x) * 3..], pw * 3, signed);
                }
            }
        }
    }
    if let Some(hdr) = hdr {
        let mut out = Vec::with_capacity(w * h * 4);
        for row in 0..h {
            for col in 0..w {
                let o = (row * pw + col) * 3;
                out.extend([hdr[o], hdr[o + 1], hdr[o + 2], 1.0]);
            }
        }
        return Ok(Pixels {
            width: w as u32,
            height: h as u32,
            channels: Channels::Rgba,
            samples: Samples::F32(out),
        });
    }
    let mut out = Vec::with_capacity(w * h * 4);
    for row in 0..h {
        out.extend_from_slice(&rgba8[row * pw * 4..(row * pw + w) * 4]);
    }
    Ok(rgba(w as u32, h as u32, out))
}
