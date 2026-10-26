//! Truevision TGA (Targa) files, for the eye only: a TGA has no magic number at
//! its start, so [`Format::detect`](super::Format::detect) does not know it and
//! the hash never sees it. `decode_any` tries this when no other format fits,
//! and takes a file for a TGA only if its header is sane and its pixel data
//! fills the rest of the file exactly (before the `TRUEVISION-XFILE.` footer of
//! version 2 files, when there is one). Colour-mapped, true-colour and grey
//! images, raw or run-length coded (types 1 to 3 and 9 to 11), 8 to 32 bits.

use super::{within, Channels, Error, Pixels, Samples};

const SIGNATURE: &[u8] = b"TRUEVISION-XFILE.\0";

struct Header {
    /// 1 colour-mapped, 2 true-colour, 3 grey.
    kind: u8,
    rle: bool,
    id_len: usize,
    map_first: usize,
    map_len: usize,
    map_bits: u8,
    width: usize,
    height: usize,
    depth: u8,
    descriptor: u8,
}

impl Header {
    fn parse(d: &[u8]) -> Option<Header> {
        let h = d.get(..18)?;
        let word = |at: usize| usize::from(u16::from_le_bytes([h[at], h[at + 1]]));
        let (has_map, code) = (h[1], h[2]);
        let kind = match code {
            1..=3 | 9..=11 => code & 7,
            _ => return None,
        };
        let header = Header {
            kind,
            rle: code > 8,
            id_len: usize::from(h[0]),
            map_first: word(3),
            map_len: if has_map == 1 { word(5) } else { 0 },
            map_bits: h[7],
            width: word(12),
            height: word(14),
            depth: h[16],
            descriptor: h[17],
        };
        let depth_ok = match kind {
            1 => matches!(header.depth, 8 | 16),
            2 => matches!(header.depth, 15 | 16 | 24 | 32),
            _ => matches!(header.depth, 8 | 16),
        };
        let map_ok = match kind {
            1 => has_map == 1 && header.map_len > 0 && matches!(header.map_bits, 15 | 16 | 24 | 32),
            // A colour map some writers leave in a true-colour or grey file.
            _ => has_map == 0 || (has_map == 1 && matches!(header.map_bits, 15 | 16 | 24 | 32)),
        };
        // The two top bits of the descriptor are unused.
        (depth_ok && map_ok && header.width > 0 && header.height > 0 && h[17] & 0xC0 == 0)
            .then_some(header)
    }

    /// Bytes of one pixel in the file.
    fn pixel_bytes(&self) -> usize {
        usize::from(self.depth).div_ceil(8)
    }

    /// Where the colour map starts, and where the pixels do.
    fn map_at(&self) -> usize {
        18 + self.id_len
    }

    fn data_at(&self) -> usize {
        self.map_at() + self.map_len * usize::from(self.map_bits).div_ceil(8)
    }
}

/// The bytes of the footer of a version 2 file: the offsets of the extension
/// area and the developer directory, then the signature (some writers leave
/// off its final NUL).
fn footer_len(d: &[u8]) -> Option<usize> {
    let len = if d.ends_with(SIGNATURE) {
        8 + SIGNATURE.len()
    } else if d.ends_with(&SIGNATURE[..SIGNATURE.len() - 1]) {
        8 + SIGNATURE.len() - 1
    } else {
        return None;
    };
    (d.len() >= 18 + len).then_some(len)
}

/// The attribute type of the extension area of a version 2 file: 0 to 2 say the
/// alpha channel holds nothing, 3 and 4 that it is meant to be used.
fn attribute_type(d: &[u8], footer: Option<usize>) -> Option<u8> {
    let at = d.len() - footer?;
    let area = u32::from_le_bytes(d[at..at + 4].try_into().ok()?) as usize;
    if area == 0 || area.checked_add(495)? > at {
        return None;
    }
    d.get(area + 494).copied()
}

/// One 5-5-5 pixel as 8-bit red, green and blue.
fn rgb555(v: u16) -> [u8; 3] {
    let c = |shift: u32| {
        let c = ((v >> shift) & 31) as u8;
        c << 3 | c >> 2
    };
    [c(10), c(5), c(0)]
}

/// `count` pixels of `bytes` bytes, from the run-length packets of `data`, and
/// the bytes the packets take.
fn expand_rle(data: &[u8], bytes: usize, count: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::with_capacity(count * bytes);
    let mut at = 0;
    while out.len() < count * bytes {
        let packet = *data.get(at)?;
        at += 1;
        let left = count - out.len() / bytes;
        let n = (usize::from(packet & 0x7F) + 1).min(left);
        if packet & 0x80 != 0 {
            let pixel = data.get(at..at + bytes)?;
            at += bytes;
            for _ in 0..n {
                out.extend_from_slice(pixel);
            }
        } else {
            out.extend_from_slice(data.get(at..at + n * bytes)?);
            at += n * bytes;
        }
    }
    Some((out, at))
}

/// The pixels of a TGA file, `Unsupported` for a file that is not one.
pub(super) fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let h = Header::parse(data).ok_or(Error::Unsupported)?;
    let footer_len = footer_len(data);
    let footer = footer_len.is_some();
    let (map_at, data_at) = (h.map_at(), h.data_at());
    if data_at > data.len() {
        return Err(Error::Unsupported);
    }
    let bytes = h.pixel_bytes();
    let count = h.width * h.height;
    within((count as u64).saturating_mul(bytes as u64 + 4), max_alloc)?;
    // With a footer, the pixels may run into it, as some writers leave a
    // last packet short and readers go on past the end of the image data.
    let body = &data[data_at..];
    let source = if h.rle {
        let (pixels, used) = expand_rle(body, bytes, count).ok_or(Error::Unsupported)?;
        // Without a footer, nothing may follow the packets.
        if !footer && used != body.len() {
            return Err(Error::Unsupported);
        }
        pixels
    } else {
        if body.len() < count * bytes || (!footer && body.len() != count * bytes) {
            return Err(Error::Unsupported);
        }
        body[..count * bytes].to_vec()
    };

    let attribute = attribute_type(data, footer_len);
    let alpha_bits = h.descriptor & 15;
    // A file that says it has alpha, or says nothing about it.
    let wants_alpha = alpha_bits > 0 || !matches!(attribute, Some(0..=2));
    // A bit of a 16-bit pixel is alpha only if the file says so.
    let bit_alpha = alpha_bits > 0 || matches!(attribute, Some(3 | 4));

    let map: Vec<[u8; 4]> = if h.kind == 1 {
        let entry = usize::from(h.map_bits).div_ceil(8);
        data[map_at..data_at]
            .chunks_exact(entry)
            .map(|e| match entry {
                2 => {
                    let v = u16::from_le_bytes([e[0], e[1]]);
                    let [r, g, b] = rgb555(v);
                    [r, g, b, if v >> 15 != 0 { 255 } else { 0 }]
                }
                3 => [e[2], e[1], e[0], 255],
                _ => [e[2], e[1], e[0], e[3]],
            })
            .collect()
    } else {
        Vec::new()
    };

    // Each pixel as RGBA, or (for grey) luma and alpha.
    let pixel = |p: &[u8]| -> [u8; 4] {
        match (h.kind, bytes) {
            (1, _) => {
                let index = if bytes == 2 {
                    usize::from(u16::from_le_bytes([p[0], p[1]]))
                } else {
                    usize::from(p[0])
                };
                index
                    .checked_sub(h.map_first)
                    .and_then(|i| map.get(i))
                    .copied()
                    .unwrap_or([0, 0, 0, 255])
            }
            (3, 1) => [p[0], p[0], p[0], 255],
            (3, _) => [p[0], p[0], p[0], p[1]],
            (_, 2) => {
                let v = u16::from_le_bytes([p[0], p[1]]);
                let [r, g, b] = rgb555(v);
                [r, g, b, if v >> 15 != 0 { 255 } else { 0 }]
            }
            (_, 3) => [p[2], p[1], p[0], 255],
            _ => [p[2], p[1], p[0], p[3]],
        }
    };
    // Whether the alpha of a pixel is read at all: a colour map of 32-bit
    // entries or 32-bit pixels, a bit of a 16-bit pixel, a grey pixel's second
    // byte.
    let has_alpha = match (h.kind, bytes) {
        (1, _) => h.map_bits == 32 && wants_alpha || h.map_bits == 16 && bit_alpha,
        (3, 1) => false,
        (3, _) => true,
        (_, 2) => bit_alpha,
        (_, 3) => false,
        _ => wants_alpha,
    };

    let (w, rows) = (h.width, h.height);
    let top_down = h.descriptor & 0x20 != 0;
    let right_to_left = h.descriptor & 0x10 != 0;
    let mut rgba = vec![0u8; count * 4];
    for y in 0..rows {
        let from = if top_down { y } else { rows - 1 - y };
        for x in 0..w {
            let sx = if right_to_left { w - 1 - x } else { x };
            let at = (from * w + sx) * bytes;
            rgba[(y * w + x) * 4..][..4].copy_from_slice(&pixel(&source[at..at + bytes]));
        }
    }
    // Alpha nobody set (a 32-bit file whose writer left the byte at zero) would
    // draw nothing.
    let has_alpha = has_alpha && rgba.as_chunks::<4>().0.iter().any(|p| p[3] != 0);

    let grey = h.kind == 3;
    let (channels, samples) = match (grey, has_alpha) {
        (true, false) => (
            Channels::Luma,
            rgba.as_chunks::<4>()
                .0
                .iter()
                .map(|p| p[0])
                .collect::<Vec<u8>>(),
        ),
        (true, true) => (
            Channels::LumaAlpha,
            rgba.as_chunks::<4>()
                .0
                .iter()
                .flat_map(|p| [p[0], p[3]])
                .collect(),
        ),
        (false, true) => (Channels::Rgba, rgba),
        (false, false) => (
            Channels::Rgb,
            rgba.as_chunks::<4>()
                .0
                .iter()
                .flat_map(|p| [p[0], p[1], p[2]])
                .collect(),
        ),
    };
    Ok(Pixels {
        width: w as u32,
        height: rows as u32,
        channels,
        samples: Samples::U8(samples),
    })
}
