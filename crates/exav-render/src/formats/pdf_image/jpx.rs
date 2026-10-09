//! JPXDecode: the codestream through hayro-jpeg2000, the JP2 boxes and the
//! layout of pdf.js's OpenJPEG decoder applied here.
//!
//! hayro-jpeg2000 is handed the bare codestream, so it neither resolves a
//! palette nor reorders or converts components: that is done below, the way
//! pdf.js's decoder does it, as observed on its output.

use hayro_jpeg2000::{DecodeSettings, DecoderContext, Image};

use super::Error;

/// What pdf.js asks of a JPX image (`JpxImage.decode`).
#[derive(Clone, Copy, Debug, Default)]
pub struct JpxParams {
    /// Components wanted, from the image's `/ColorSpace`; 0 for RGBA.
    pub num_components: u32,
    /// An `/Indexed` colour space: palette indices are given unscaled, and
    /// the file's palette, mapping and channel boxes are ignored.
    pub indexed: bool,
    /// `/SMaskInData`: a fourth component is the image's alpha.
    pub smask_in_data: bool,
    /// Decode at 1 / 2^`reduce_power` of the size.
    pub reduce_power: u32,
}

/// A decoded JPX image, in the layout pdf.js reads: `components` bytes a
/// pixel, row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JpxImage {
    pub width: u32,
    pub height: u32,
    pub components: u32,
    pub data: Vec<u8>,
}

const JP2_SIGNATURE: &[u8] = b"\0\0\0\x0cjP  \r\n\x87\n";
const SOC_SIZ: &[u8] = &[0xFF, 0x4F, 0xFF, 0x51];

/// Decodes `data`. `Ok(None)` is a decode that gives pdf.js no pixels without
/// an error, as its own decoder does for a layout it does not produce (two
/// components and no alpha wanted, for one).
pub fn decode_jpx(
    data: &[u8],
    params: JpxParams,
    max_alloc: u64,
) -> Result<Option<JpxImage>, Error> {
    let (codestream, boxes) = if data.starts_with(JP2_SIGNATURE) {
        let boxes = read_boxes(data)?;
        (
            boxes
                .codestream
                .ok_or(Error::new("No codestream in the JP2 file"))?,
            boxes,
        )
    } else if data.starts_with(SOC_SIZ) {
        (data, Boxes::default())
    } else {
        return Err(Error::new("Unknown format"));
    };
    let siz = read_siz(codestream)?;
    check_tile_parts(codestream)?;

    if params.reduce_power > 0 && !siz.reducible(params.reduce_power) {
        return Err(Error::new("Failed to decode the image at a reduced size"));
    }
    let full = (siz.width, siz.height);
    let target = (params.reduce_power > 0).then(|| {
        let shift = params.reduce_power.min(31);
        ((full.0 >> shift).max(1), (full.1 >> shift).max(1))
    });
    let settings = DecodeSettings {
        resolve_palette_indices: false,
        strict: false,
        target_resolution: target,
    };
    // In a JP2 file of its own with no colour specification: hayro-jpeg2000
    // then takes any number of components as they are (a bare codestream of
    // five or more it refuses).
    let wrapped = bare_jp2(codestream);
    let image =
        Image::new(&wrapped, &settings).map_err(|_| Error::new("Failed to read the header"))?;
    let (width, height) = (image.width(), image.height());
    let pixels = u64::from(width) * u64::from(height);
    let n = siz.components.len();
    // Every component as `f32` in the decoder, then as bytes, then the
    // components wanted.
    let needed = pixels
        .saturating_mul(n as u64)
        .saturating_mul(5)
        .saturating_add(pixels.saturating_mul(4));
    if needed > max_alloc {
        return Err(Error::new("Image too large"));
    }
    let interleaved = image
        .decode(&mut DecoderContext::default())
        .map_err(|_| Error::new("Failed to decode the image"))?
        .data_u8();
    if interleaved.len() as u64 != pixels * n as u64 {
        return Err(Error::new("Failed to decode the image"));
    }
    let pixels = pixels as usize;

    // One plane per component, at the precision pdf.js's decoder works in:
    // 8-bit, or the raw values for an indexed image.
    let mut planes: Vec<Plane> = siz
        .components
        .iter()
        .enumerate()
        .map(|(c, info)| {
            let samples = interleaved.iter().skip(c).step_by(n).copied();
            // hayro-jpeg2000 level-shifts signed components as unsigned ones;
            // pdf.js's decoder keeps them signed.
            let values = match (params.indexed, info.signed) {
                (true, false) => samples.map(|v| unscale(v, info.precision)).collect(),
                (true, true) => {
                    let half = 1i32 << (info.precision.min(31) - 1);
                    samples
                        .map(|v| unscale(v, info.precision).wrapping_sub(half))
                        .collect()
                }
                (false, false) => samples.map(i32::from).collect(),
                (false, true) => samples.map(|v| i32::from(v) - 128).collect(),
            };
            Plane {
                values,
                precision: if params.indexed { info.precision } else { 8 },
                dx: info.dx,
            }
        })
        .collect();

    let mut space = boxes.colour;
    if !params.indexed {
        if let (Some(palette), Some(mapping)) = (&boxes.palette, &boxes.mapping) {
            planes = apply_palette(&planes, palette, mapping, &siz)?;
        }
        if let Some(definitions) = &boxes.definitions {
            apply_channel_definitions(&mut planes, definitions);
        }
    }
    if space == Colour::Unspecified
        && planes.len() == 3
        && siz.components.first().is_some_and(|c| c.dx == c.dy)
        && siz.components.get(1).is_some_and(|c| c.dx != 1)
    {
        space = Colour::Sycc;
    }

    fn channels(planes: &[Plane], k: usize) -> Vec<&[i32]> {
        planes[..k].iter().map(|p| p.values.as_slice()).collect()
    }
    let count = planes.len();
    let out = if params.num_components == 0 {
        if params.smask_in_data && count == 4 {
            Some(interleave(&channels(&planes, 4), None, pixels))
        } else {
            convert(&mut planes, space);
            let count = planes.len();
            let grey = space == Colour::Grey || count < 3;
            if grey && count == 1 {
                Some(grey_rgba(&planes[0].values, None))
            } else if grey && params.smask_in_data && count >= 2 {
                Some(grey_rgba(&planes[0].values, Some(&planes[1].values)))
            } else if grey {
                None
            } else {
                Some(interleave(&channels(&planes, 3), Some(255), pixels))
            }
        }
    } else {
        match (params.num_components as usize).min(count) {
            k @ (1 | 3 | 4) => Some(interleave(&channels(&planes, k), None, pixels)),
            _ => None,
        }
    };
    Ok(out.map(|data| JpxImage {
        width,
        height,
        components: (data.len() / pixels.max(1)) as u32,
        data,
    }))
}

/// A component's values, in the order pdf.js's decoder holds them.
struct Plane {
    values: Vec<i32>,
    precision: u8,
    dx: u8,
}

/// hayro-jpeg2000 scales every component to 8 bits; an index is wanted as
/// the file holds it. Exact up to 8 bits, the nearest value above.
fn unscale(v: u8, precision: u8) -> i32 {
    let max = (1u64 << precision.min(32)) - 1;
    ((u64::from(v) * max + 127) / 255) as i32
}

fn interleave(planes: &[&[i32]], alpha: Option<u8>, pixels: usize) -> Vec<u8> {
    let per = planes.len() + usize::from(alpha.is_some());
    let mut out = Vec::with_capacity(pixels * per);
    for i in 0..pixels {
        for p in planes {
            out.push(clamp(p[i]));
        }
        if let Some(a) = alpha {
            out.push(a);
        }
    }
    out
}

fn grey_rgba(grey: &[i32], alpha: Option<&[i32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(grey.len() * 4);
    for (i, &g) in grey.iter().enumerate() {
        let g = clamp(g);
        out.extend([g, g, g, alpha.map_or(255, |a| clamp(a[i]))]);
    }
    out
}

/// What a `Uint8ClampedArray` stores.
fn clamp(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// The colour space the first `colr` box enumerates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Colour {
    #[default]
    Unspecified,
    Grey,
    Sycc,
    Esycc,
    Cmyk,
    Other,
}

/// To RGB, as pdf.js's decoder does when it gives RGBA: YCC and CMYK
/// components converted, in floating point as there, the result truncated.
fn convert(planes: &mut Vec<Plane>, space: Colour) {
    match space {
        Colour::Sycc | Colour::Esycc if planes.len() >= 3 => {
            let offset = 128.0f32;
            for i in 0..planes[0].values.len() {
                let y = planes[0].values[i] as f32;
                let cb = planes[1].values[i] as f32 - offset;
                let cr = planes[2].values[i] as f32 - offset;
                let rgb = if space == Colour::Sycc {
                    // Palette entries can be any `i32`.
                    [
                        planes[0].values[i].saturating_add((1.402f64 * f64::from(cr)) as i32),
                        planes[0].values[i].saturating_sub(
                            (0.344f64 * f64::from(cb) + 0.714f64 * f64::from(cr)) as i32,
                        ),
                        planes[0].values[i].saturating_add((1.772f64 * f64::from(cb)) as i32),
                    ]
                } else {
                    [
                        (y - 0.0000368f32 * cb + 1.40199f32 * cr + 0.5f32) as i32,
                        (1.0003f32 * y - 0.344125f32 * cb - 0.7141128f32 * cr + 0.5f32) as i32,
                        (0.999823f32 * y + 1.77204f32 * cb - 0.000008f32 * cr + 0.5f32) as i32,
                    ]
                };
                for (c, v) in rgb.into_iter().enumerate() {
                    planes[c].values[i] = v.clamp(0, 255);
                }
            }
        }
        Colour::Cmyk if planes.len() >= 4 => {
            let scale = 1.0f32 / 255.0f32;
            let (cmy, rest) = planes.split_at_mut(3);
            for (i, &black) in rest[0].values.iter().enumerate() {
                let k = 1.0f32 - black as f32 * scale;
                for p in cmy.iter_mut() {
                    let v = 1.0f32 - p.values[i] as f32 * scale;
                    p.values[i] = (255.0f32 * v * k) as i32;
                }
            }
            planes.remove(3);
        }
        _ => {}
    }
}

#[derive(Default)]
struct Boxes<'a> {
    codestream: Option<&'a [u8]>,
    colour: Colour,
    palette: Option<Palette>,
    mapping: Option<Vec<Mapping>>,
    definitions: Option<Vec<[u16; 3]>>,
}

struct Palette {
    /// `entries[e][column]`.
    entries: Vec<Vec<i32>>,
    columns: usize,
}

#[derive(Clone, Copy)]
struct Mapping {
    component: u16,
    palette_column: Option<u8>,
}

/// The boxes of a JP2 file: the first codestream, and from its header the
/// first colour specification, the palette, the component mapping and the
/// channel definitions.
fn read_boxes(data: &[u8]) -> Result<Boxes<'_>, Error> {
    let mut boxes = Boxes::default();
    for (kind, body) in BoxIter(data) {
        match kind {
            b"jp2h" => {
                let mut colour = None;
                for (kind, body) in BoxIter(body) {
                    match kind {
                        b"colr" if colour.is_none() => colour = Some(read_colour(body)),
                        b"pclr" => boxes.palette = read_palette(body),
                        b"cmap" => {
                            boxes.mapping = Some(
                                body.as_chunks::<4>()
                                    .0
                                    .iter()
                                    .map(|m| Mapping {
                                        component: u16::from_be_bytes([m[0], m[1]]),
                                        palette_column: (m[2] == 1).then_some(m[3]),
                                    })
                                    .collect(),
                            )
                        }
                        b"cdef" => {
                            let n = body
                                .get(..2)
                                .map_or(0, |n| u16::from_be_bytes([n[0], n[1]]));
                            boxes.definitions = Some(
                                body.get(2..)
                                    .unwrap_or_default()
                                    .as_chunks::<6>()
                                    .0
                                    .iter()
                                    .take(usize::from(n))
                                    .map(|d| {
                                        [0, 2, 4].map(|o| u16::from_be_bytes([d[o], d[o + 1]]))
                                    })
                                    .collect(),
                            )
                        }
                        _ => {}
                    }
                }
                boxes.colour = colour.unwrap_or_default();
            }
            b"jp2c" if boxes.codestream.is_none() => boxes.codestream = Some(body),
            _ => {}
        }
    }
    Ok(boxes)
}

fn read_colour(body: &[u8]) -> Colour {
    match body {
        [1, _, _, e @ ..] if e.len() >= 4 => match u32::from_be_bytes([e[0], e[1], e[2], e[3]]) {
            12 => Colour::Cmyk,
            17 => Colour::Grey,
            18 => Colour::Sycc,
            24 => Colour::Esycc,
            _ => Colour::Other,
        },
        _ => Colour::Other,
    }
}

fn read_palette(body: &[u8]) -> Option<Palette> {
    let entries = usize::from(u16::from_be_bytes([*body.first()?, *body.get(1)?]));
    let columns = usize::from(*body.get(2)?);
    let depths = body.get(3..3 + columns)?;
    let sizes: Vec<usize> = depths
        .iter()
        .map(|b| usize::from(b & 0x7F) / 8 + 1)
        .collect();
    let mut at = 3 + columns;
    let mut table = Vec::with_capacity(entries.min(body.len()));
    for _ in 0..entries {
        let mut row = Vec::with_capacity(columns);
        for &size in &sizes {
            let bytes = body.get(at..at + size)?;
            row.push(bytes.iter().fold(0i32, |v, &b| (v << 8) | i32::from(b)));
            at += size;
        }
        table.push(row);
    }
    (columns > 0 && !table.is_empty()).then_some(Palette {
        entries: table,
        columns,
    })
}

/// Components through the palette: each mapping gives a component, either
/// a codestream component as is or a palette column indexed by one (the
/// index clamped to the palette).
fn apply_palette(
    planes: &[Plane],
    palette: &Palette,
    mapping: &[Mapping],
    siz: &Siz,
) -> Result<Vec<Plane>, Error> {
    let mut out = Vec::with_capacity(mapping.len());
    for m in mapping {
        let source = planes
            .get(usize::from(m.component))
            .ok_or(Error::new("Invalid component mapping"))?;
        let info = &siz.components[usize::from(m.component)];
        out.push(match m.palette_column {
            None => Plane {
                values: source.values.clone(),
                precision: source.precision,
                dx: source.dx,
            },
            Some(column) if usize::from(column) < palette.columns => {
                let last = palette.entries.len() - 1;
                let values = source
                    .values
                    .iter()
                    .map(|&v| {
                        // The index as the file holds it, from hayro's 8 bits.
                        let index = unscale(v.clamp(0, 255) as u8, info.precision);
                        palette.entries[(index.max(0) as usize).min(last)][usize::from(column)]
                    })
                    .collect();
                Plane {
                    values,
                    precision: 8,
                    dx: 1,
                }
            }
            Some(_) => return Err(Error::new("Invalid palette column")),
        });
    }
    Ok(out)
}

/// Channel definitions: a component associated with colour `k` moves to
/// position `k - 1`, by swaps in the order the definitions come, the later
/// definitions following the components they name.
fn apply_channel_definitions(planes: &mut [Plane], definitions: &[[u16; 3]]) {
    let mut defs = definitions.to_vec();
    for i in 0..defs.len() {
        let [cn, _, asoc] = defs[i];
        let cn = usize::from(cn);
        if cn >= planes.len() || asoc == 0 || asoc == u16::MAX {
            continue;
        }
        let acn = usize::from(asoc) - 1;
        if acn >= planes.len() || acn == cn {
            continue;
        }
        planes.swap(cn, acn);
        for d in &mut defs[i + 1..] {
            if usize::from(d[0]) == cn {
                d[0] = acn as u16;
            } else if usize::from(d[0]) == acn {
                d[0] = cn as u16;
            }
        }
    }
}

struct Component {
    precision: u8,
    signed: bool,
    dx: u8,
    dy: u8,
}

/// `codestream` as the only content of a JP2 file with a header box of an
/// image header alone.
fn bare_jp2(codestream: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(codestream.len() + 72);
    out.extend_from_slice(JP2_SIGNATURE);
    out.extend_from_slice(b"\0\0\0\x14ftypjp2 \0\0\0\0jp2 ");
    // The image header's fields are not read: the codestream's SIZ is.
    out.extend_from_slice(b"\0\0\0\x1ejp2h\0\0\0\x16ihdr");
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 7, 7, 0, 0]);
    let len = u32::try_from(codestream.len() + 8).unwrap_or(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b"jp2c");
    out.extend_from_slice(codestream);
    out
}

struct Siz {
    width: u32,
    height: u32,
    components: Vec<Component>,
    grid: Grid,
}

/// The reference grid and its tiles (Xsiz to YTOsiz).
struct Grid {
    x: u32,
    y: u32,
    offset: (u32, u32),
    tile: (u32, u32),
    tile_offset: (u32, u32),
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

/// The SIZ marker segment, which follows SOC.
fn read_siz(cs: &[u8]) -> Result<Siz, Error> {
    let bad = || Error::new("Failed to read the header");
    if !cs.starts_with(SOC_SIZ) {
        return Err(bad());
    }
    let s = &cs[4..];
    let x = be32(s, 4).ok_or_else(bad)?;
    let y = be32(s, 8).ok_or_else(bad)?;
    let x0 = be32(s, 12).ok_or_else(bad)?;
    let y0 = be32(s, 16).ok_or_else(bad)?;
    // Lsiz, Rsiz, Xsiz, Ysiz, XOsiz, YOsiz, XTsiz, YTsiz, XTOsiz, YTOsiz,
    // Csiz, then Ssiz, XRsiz and YRsiz per component.
    let n = be16(s, 36).ok_or_else(bad)?;
    let components = (0..usize::from(n))
        .map(|c| {
            let at = 38 + c * 3;
            let ssiz = *s.get(at).ok_or_else(bad)?;
            Ok(Component {
                precision: (ssiz & 0x7F) + 1,
                signed: ssiz & 0x80 != 0,
                dx: *s.get(at + 1).ok_or_else(bad)?,
                dy: *s.get(at + 2).ok_or_else(bad)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if x <= x0 || y <= y0 || components.is_empty() {
        return Err(bad());
    }
    Ok(Siz {
        width: x - x0,
        height: y - y0,
        components,
        grid: Grid {
            x,
            y,
            offset: (x0, y0),
            tile: (be32(s, 20).ok_or_else(bad)?, be32(s, 24).ok_or_else(bad)?),
            tile_offset: (be32(s, 28).ok_or_else(bad)?, be32(s, 32).ok_or_else(bad)?),
        },
    })
}

impl Siz {
    /// Whether hayro-jpeg2000 0.4.1 can decode the image at 1 / 2^`power` of
    /// its size (or less reduced). Its reduced decode places the samples with
    /// full-resolution coordinates, which agree only with no image area
    /// offset, and for a subsampled component only in a single tile;
    /// otherwise it panics or leaves samples out. It also panics on a column
    /// of tiles that is empty at that size.
    fn reducible(&self, power: u32) -> bool {
        let g = &self.grid;
        let x = u64::from(g.x);
        let (tw, th) = (u64::from(g.tile.0), u64::from(g.tile.1));
        let (tx0, ty0) = (u64::from(g.tile_offset.0), u64::from(g.tile_offset.1));
        let columns = x.saturating_sub(tx0) > tw;
        let several = columns || u64::from(g.y).saturating_sub(ty0) > th;
        let subsampled = self.components.iter().any(|c| c.dx != 1 || c.dy != 1);
        if g.offset != (0, 0) || (several && subsampled) {
            return false;
        }
        if !columns {
            return true;
        }
        // A column is empty at a scale when its two edges round up to the
        // same sample. An inner one is as wide as a tile; the last one ends
        // at the image's edge.
        let scale = 1u64 << power.min(31);
        tw >= scale && {
            let last = tx0 + (x - tx0 - 1) / tw * tw;
            last.div_ceil(scale) < x.div_ceil(scale)
        }
    }
}

/// Fails, as pdf.js's decoder does, when a tile-part declares more bytes
/// than the stream has, or when nothing follows the last one: a truncated
/// file.
fn check_tile_parts(cs: &[u8]) -> Result<(), Error> {
    let mut at = 2;
    // Main header marker segments, up to the first SOT.
    loop {
        let Some(marker) = be16(cs, at) else {
            return Ok(());
        };
        if marker == 0xFF90 {
            break;
        }
        if marker == 0xFFD9 {
            return Ok(());
        }
        let Some(len) = be16(cs, at + 2) else {
            return Ok(());
        };
        at += 2 + usize::from(len);
    }
    // Tile-parts, each Psot bytes from its SOT (0: to the end).
    while be16(cs, at) == Some(0xFF90) {
        let psot = be32(cs, at + 6).ok_or(Error::new("Stream too short"))? as usize;
        if psot == 0 {
            return Ok(());
        }
        if at.checked_add(psot).is_none_or(|end| end > cs.len()) {
            return Err(Error::new(
                "Tile part length size inconsistent with stream length",
            ));
        }
        at += psot;
    }
    if at + 2 > cs.len() {
        return Err(Error::new("Stream too short"));
    }
    Ok(())
}

/// The boxes of a box sequence: type and body. Stops at the first box
/// that does not fit.
struct BoxIter<'a>(&'a [u8]);

impl<'a> Iterator for BoxIter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let d = self.0;
        let len = u64::from(be32(d, 0)?);
        let kind = d.get(4..8)?;
        let (header, len) = match len {
            0 => (8, d.len() as u64),
            1 => (16, u64::from(be32(d, 8)?) << 32 | u64::from(be32(d, 12)?)),
            n => (8, n),
        };
        if len < header || len > d.len() as u64 {
            self.0 = &[];
            return None;
        }
        let body = &d[header as usize..len as usize];
        self.0 = &d[len as usize..];
        Some((kind, body))
    }
}
