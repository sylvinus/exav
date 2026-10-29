//! TIFF files to look at that the decoder `fuzzy_img` hashes with does not
//! read: signed, wide and floating-point grey samples (elevation models,
//! scientific rasters), palette images, planar ones, CMYK, YCbCr and Zstandard. It is a
//! fallback of `decode_any`, never of `decode`, so that a hash stays what
//! ClamAV's would be.
//!
//! Samples that are not 8-bit are stretched from the 0.5th to the 99.5th
//! percentile of the values to the grey scale, nodata values left out: the
//! file says nothing about a range to show.

use std::io::Cursor;

use super::{Channels, Error, Pixels, Samples, within};
use crate::image_codecs::tiff::ColorType;
use crate::image_codecs::tiff::decoder::{
    ChunkType, Decoder, DecodingResult, Limits, with_viewer_codecs,
};
use crate::image_codecs::tiff::tags::Tag;

/// Most values looked at to find the range to stretch.
const RANGE_SAMPLE: usize = 1 << 20;

pub(super) fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    with_viewer_codecs(|| read(data, max_alloc))
}

fn read(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let limits = Limits {
        decoding_buffer_size: max_alloc.min(super::DECODE_MAX) as usize,
        ..Limits::default()
    };
    let mut d = Decoder::new(Cursor::new(data))
        .map_err(|_| Error::Undecodable)?
        .with_limits(limits);
    let (width, height) = d.dimensions().map_err(|_| Error::Undecodable)?;
    // The decoder's colour type refuses a palette; its samples are still read.
    let palette_file = d
        .find_tag_unsigned::<u16>(Tag::PhotometricInterpretation)
        .ok()
        .flatten()
        == Some(3);
    let color = match d.colortype() {
        Ok(c) => c,
        Err(_) if palette_file => ColorType::Palette(8),
        Err(_) => return Err(Error::Undecodable),
    };
    let pixels = u64::from(width) * u64::from(height);
    // The samples as they are read, and the grey or RGB bytes made of them.
    within(pixels.saturating_mul(16), max_alloc)?;
    #[cfg(feature = "ccitt")]
    if let (ColorType::Gray(1), Some(compression @ 2..=4)) = (
        color,
        d.find_tag_unsigned::<u16>(Tag::Compression).ok().flatten(),
    ) {
        return fax(&mut d, data, compression, width, height, max_alloc);
    }
    if let ColorType::RGB(bits @ (8 | 16))
    | ColorType::RGBA(bits @ (8 | 16))
    | ColorType::CMYK(bits @ (8 | 16))
    | ColorType::YCbCr(bits @ 8) = color
    {
        let stored = match color {
            ColorType::RGB(_) | ColorType::YCbCr(_) => 3,
            _ => 4,
        };
        return bands(&mut d, color, bits, width, height, stored);
    }
    // Palette indices with an alpha beside each.
    if palette_file
        && matches!(
            color,
            ColorType::Multiband {
                bit_depth: 8,
                num_samples: 2
            }
        )
    {
        let map = d
            .get_tag_u16_vec(Tag::ColorMap)
            .map_err(|_| Error::Undecodable)?;
        let unspecified = unspecified_extra(&mut d);
        let DecodingResult::U8(v) = d.read_image().map_err(|_| Error::Undecodable)? else {
            return Err(Error::Undecodable);
        };
        let pairs = v.as_chunks::<2>().0;
        let rgb = palette(pairs.iter().map(|p| usize::from(p[0])), Some(&map))?;
        let samples: Vec<u8> = rgb
            .as_chunks::<3>()
            .0
            .iter()
            .zip(pairs)
            .flat_map(|(c, p)| [c[0], c[1], c[2], if unspecified { 255 } else { p[1] }])
            .collect();
        if samples.len() as u64 != pixels * 4 {
            return Err(Error::Undecodable);
        }
        return Ok(Pixels {
            width,
            height,
            channels: Channels::Rgba,
            samples: Samples::U8(samples),
        });
    }
    if let (
        ColorType::Multiband {
            bit_depth: 8,
            num_samples: 3,
        },
        Some(8),
    ) = (
        color,
        d.find_tag_unsigned::<u16>(Tag::PhotometricInterpretation)
            .ok()
            .flatten(),
    ) {
        let lab = all_values(&mut d, (width, height), 3)?;
        return Ok(Pixels {
            width,
            height,
            channels: Channels::Rgb,
            samples: Samples::U8(lab_to_rgb(&lab)),
        });
    }
    // CMYK with spot or alpha channels after the four inks: the inks only.
    if let (
        ColorType::Multiband {
            bit_depth: bits @ (8 | 16),
            num_samples: n @ 6..=8,
        },
        Some(5),
    ) = (
        color,
        d.find_tag_unsigned::<u16>(Tag::PhotometricInterpretation)
            .ok()
            .flatten(),
    ) {
        return bands(
            &mut d,
            ColorType::CMYK(bits),
            bits,
            width,
            height,
            usize::from(n),
        );
    }
    // A raster of several bands with no colour meaning (a satellite scene):
    // the first, as grey.
    if let ColorType::Multiband {
        bit_depth: bits @ (8 | 16),
        num_samples: n @ 3..=6,
    } = color
    {
        let nodata = d
            .get_tag_ascii_string(Tag::GdalNodata)
            .ok()
            .and_then(|s| s.trim().trim_end_matches('\0').parse::<f64>().ok());
        return first_band(&mut d, bits, usize::from(n), (width, height), nodata);
    }
    let channels = match color {
        ColorType::Gray(_) => Channels::Luma,
        ColorType::Palette(_) => Channels::Rgb,
        // Grey and alpha, which the photometric interpretation does not say.
        ColorType::Multiband {
            bit_depth: 8,
            num_samples: 2,
        } => Channels::LumaAlpha,
        _ => return Err(Error::Undecodable),
    };
    let nodata = d
        .get_tag_ascii_string(Tag::GdalNodata)
        .ok()
        .and_then(|s| s.trim().trim_end_matches('\0').parse::<f64>().ok());
    let map = match color {
        ColorType::Palette(_) => d.get_tag_u16_vec(Tag::ColorMap).ok(),
        _ => None,
    };
    let image = d.read_image().map_err(|_| Error::Undecodable)?;
    let associated = associated_alpha(&mut d);
    let unspecified = unspecified_extra(&mut d);
    // The decoder ignores a fill order of 2, bits taken from the low end.
    let reversed = fill_order_2(&mut d);
    let (w, h) = (width as usize, height as usize);
    // Indices of fewer than 8 bits come packed, each row to a byte.
    let image = match (color, image) {
        (ColorType::Palette(bits @ 1..=7), DecodingResult::U8(v)) => {
            DecodingResult::U8(unpack(&v, w, h, bits, reversed))
        }
        // Grey of fewer bits, spread over the scale.
        (ColorType::Gray(bits @ 1..=7), DecodingResult::U8(v)) => {
            let max = (1u16 << bits) - 1;
            let mut grey = unpack(&v, w, h, bits, reversed);
            for g in &mut grey {
                *g = (u16::from(*g) * 255 / max) as u8;
            }
            DecodingResult::U8(grey)
        }
        // Grey of 9 to 15 bits, left packed by the decoder.
        (ColorType::Gray(bits @ 9..=15), DecodingResult::U16(v)) => {
            let white_is_zero = d
                .find_tag_unsigned::<u16>(Tag::PhotometricInterpretation)
                .ok()
                .flatten()
                == Some(0);
            DecodingResult::U16(unpack_wide(&v, w, h, bits, white_is_zero))
        }
        (_, image) => image,
    };
    let samples = match (channels, image) {
        (Channels::Rgb, DecodingResult::U8(v)) if matches!(color, ColorType::Palette(_)) => {
            palette(v.iter().map(|&i| usize::from(i)), map.as_deref())?
        }
        (Channels::Rgb, DecodingResult::U16(v)) if matches!(color, ColorType::Palette(_)) => {
            palette(v.iter().map(|&i| usize::from(i)), map.as_deref())?
        }
        (Channels::Luma, DecodingResult::U8(v)) => v,
        (Channels::LumaAlpha, DecodingResult::U8(v)) if associated => unpremultiply(v, 2),
        (Channels::LumaAlpha, DecodingResult::U8(v)) if unspecified => opaque(v, 2),
        (Channels::LumaAlpha, DecodingResult::U8(v)) => v,
        (Channels::Luma, DecodingResult::U16(v)) => stretch(&v, f64::from, nodata),
        (Channels::Luma, DecodingResult::U32(v)) => stretch(&v, f64::from, nodata),
        (Channels::Luma, DecodingResult::U64(v)) => stretch(&v, |x| x as f64, nodata),
        (Channels::Luma, DecodingResult::I8(v)) => stretch(&v, f64::from, nodata),
        (Channels::Luma, DecodingResult::I16(v)) => stretch(&v, f64::from, nodata),
        (Channels::Luma, DecodingResult::I32(v)) => stretch(&v, f64::from, nodata),
        (Channels::Luma, DecodingResult::I64(v)) => stretch(&v, |x| x as f64, nodata),
        (Channels::Luma, DecodingResult::F16(v)) => stretch(&v, half, nodata),
        (Channels::Luma, DecodingResult::F32(v)) => stretch(&v, f64::from, nodata),
        (Channels::Luma, DecodingResult::F64(v)) => stretch(&v, |x| x, nodata),
        _ => return Err(Error::Undecodable),
    };
    if samples.len() as u64 != pixels * channels.count() as u64 {
        return Err(Error::Undecodable);
    }
    Ok(Pixels {
        width,
        height,
        channels,
        samples: Samples::U8(samples),
    })
}

/// Strips of CCITT fax (compression 2, 3 and 4) through hayro-ccitt: the
/// decoder reads Group 4 only, and not with a fill order of 2. A white run is
/// a 0 bit, which is white or black as the photometric interpretation says.
#[cfg(feature = "ccitt")]
fn fax(
    d: &mut Decoder<Cursor<&[u8]>>,
    data: &[u8],
    compression: u16,
    width: u32,
    height: u32,
    max_alloc: u64,
) -> Result<Pixels, Error> {
    use crate::formats::pdf_image::{CcittParams, decode_ccitt};

    let offsets = d
        .get_tag_u64_vec(Tag::StripOffsets)
        .map_err(|_| Error::Undecodable)?;
    let counts = d
        .get_tag_u64_vec(Tag::StripByteCounts)
        .map_err(|_| Error::Undecodable)?;
    let rows_per_strip = d
        .find_tag_unsigned::<u32>(Tag::RowsPerStrip)
        .ok()
        .flatten()
        .unwrap_or(height)
        .clamp(1, height.max(1));
    // Group 3 options (tag 292): bit 0 is 2-dimensional coding.
    let options = d
        .find_tag_unsigned::<u32>(Tag::Unknown(292))
        .ok()
        .flatten()
        .unwrap_or(0);
    let reversed = d.find_tag_unsigned::<u16>(Tag::FillOrder).ok().flatten() == Some(2);
    let black_is_zero = d
        .find_tag_unsigned::<u16>(Tag::PhotometricInterpretation)
        .ok()
        .flatten()
        == Some(1);
    let k = match compression {
        4 => -1,
        3 if options & 1 != 0 => 4,
        _ => 0,
    };
    let (w, h) = (width as usize, height as usize);
    let mut grey = Vec::with_capacity(w * h);
    for (&at, &len) in offsets.iter().zip(&counts) {
        let rows = rows_per_strip.min(height.saturating_sub((grey.len() / w.max(1)) as u32));
        if rows == 0 {
            break;
        }
        let at = usize::try_from(at).map_err(|_| Error::Undecodable)?;
        let end = at.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
        let mut strip = data
            .get(at..end.min(data.len()))
            .ok_or(Error::Undecodable)?
            .to_vec();
        if reversed {
            strip.iter_mut().for_each(|b| *b = b.reverse_bits());
        }
        let params = CcittParams {
            width,
            height: rows,
            k,
            end_of_line: compression == 3,
            encoded_byte_align: compression == 2,
            black_is_1: false,
            columns: width,
            rows,
        };
        let bits = decode_ccitt(&strip, params, max_alloc).map_err(|_| Error::Undecodable)?;
        for row in bits.chunks(w.div_ceil(8)).take(rows as usize) {
            grey.extend((0..w).map(|x| {
                let white_run = row[x / 8] >> (7 - x % 8) & 1 == 1;
                if white_run != black_is_zero { 255 } else { 0 }
            }));
        }
    }
    if grey.len() != w * h {
        return Err(Error::Undecodable);
    }
    Ok(Pixels {
        width,
        height,
        channels: Channels::Luma,
        samples: Samples::U8(grey),
    })
}

/// An uncompressed image whose bytes hold their samples low bit first.
fn fill_order_2(d: &mut Decoder<Cursor<&[u8]>>) -> bool {
    let mut tag = |t| d.find_tag_unsigned::<u16>(t).ok().flatten();
    tag(Tag::FillOrder) == Some(2) && tag(Tag::Compression).unwrap_or(1) == 1
}

/// The image turned as the file's Orientation tag says it is to be shown
/// (what libtiff does, and a viewer): 2 mirrors it left to right, 3 turns it
/// round, 4 mirrors it top to bottom, 5 to 8 are those with the rows and
/// columns swapped (6 a quarter turn clockwise, 8 anticlockwise). Anything
/// else leaves it as it is.
pub(super) fn oriented(data: &[u8], pixels: Pixels) -> Pixels {
    let orientation = Decoder::new(Cursor::new(data))
        .ok()
        .and_then(|mut d| d.find_tag_unsigned::<u16>(Tag::Orientation).ok().flatten())
        .unwrap_or(1);
    if !(2..=8).contains(&orientation) {
        return pixels;
    }
    let (w, h, n) = (
        pixels.width as usize,
        pixels.height as usize,
        pixels.channels.count(),
    );
    let swap = orientation >= 5;
    let (out_w, out_h) = if swap { (h, w) } else { (w, h) };
    // The pixel of the source that lands at (x, y).
    let source = |x: usize, y: usize| -> usize {
        let (sx, sy) = match orientation {
            2 => (w - 1 - x, y),
            3 => (w - 1 - x, h - 1 - y),
            4 => (x, h - 1 - y),
            5 => (y, x),
            6 => (y, h - 1 - x),
            7 => (w - 1 - y, h - 1 - x),
            _ => (w - 1 - y, x),
        };
        sy * w + sx
    };
    fn turn<T: Copy>(
        src: &[T],
        out: (usize, usize),
        n: usize,
        at: &dyn Fn(usize, usize) -> usize,
    ) -> Vec<T> {
        let mut dst = Vec::with_capacity(src.len());
        for y in 0..out.1 {
            for x in 0..out.0 {
                let from = at(x, y) * n;
                dst.extend_from_slice(&src[from..from + n]);
            }
        }
        dst
    }
    let len = match &pixels.samples {
        Samples::U8(v) => v.len(),
        Samples::U16(v) => v.len(),
        Samples::F32(v) => v.len(),
    };
    if len != w * h * n {
        return pixels;
    }
    let out = (out_w, out_h);
    let samples = match &pixels.samples {
        Samples::U8(v) => Samples::U8(turn(v, out, n, &source)),
        Samples::U16(v) => Samples::U16(turn(v, out, n, &source)),
        Samples::F32(v) => Samples::F32(turn(v, out, n, &source)),
    };
    Pixels {
        width: out_w as u32,
        height: out_h as u32,
        channels: pixels.channels,
        samples,
    }
}

/// What the first extra sample is: 0 is data of no stated use, 1 an associated
/// (premultiplied) alpha, 2 an unassociated one. `None` when there is no tag.
fn extra_sample(d: &mut Decoder<Cursor<&[u8]>>) -> Option<u16> {
    d.find_tag_unsigned_vec::<u16>(Tag::ExtraSamples)
        .ok()
        .flatten()
        .and_then(|v| v.first().copied())
}

fn associated_alpha(d: &mut Decoder<Cursor<&[u8]>>) -> bool {
    extra_sample(d) == Some(1)
}

/// An extra sample of no stated use is not a transparency: libtiff's reader
/// and Pillow draw such a picture opaque.
fn unspecified_extra(d: &mut Decoder<Cursor<&[u8]>>) -> bool {
    extra_sample(d) == Some(0)
}

/// Alpha of 255, the last sample of each pixel.
fn opaque(mut samples: Vec<u8>, per_pixel: usize) -> Vec<u8> {
    for px in samples.chunks_exact_mut(per_pixel) {
        px[per_pixel - 1] = 255;
    }
    samples
}

/// Colours of 8-bit samples with the alpha last divided by it, as a viewer
/// draws a premultiplied image.
fn unpremultiply(mut samples: Vec<u8>, per_pixel: usize) -> Vec<u8> {
    for px in samples.chunks_exact_mut(per_pixel) {
        let alpha = u32::from(px[per_pixel - 1]);
        for c in &mut px[..per_pixel - 1] {
            *c = (u32::from(*c) * 255 + alpha / 2)
                .checked_div(alpha)
                .map_or(0, |v| v.min(255) as u8);
        }
    }
    samples
}

/// Whether [`decode`] reads the file differently from the hashing decoder:
/// which ignores a fill order of 2 (samples of fewer than 8 bits, or Group 4)
/// and draws premultiplied colours as they are.
pub(super) fn reads_differently(data: &[u8]) -> bool {
    let Ok(mut d) = Decoder::new(Cursor::new(data)) else {
        return false;
    };
    let fax = cfg!(feature = "ccitt")
        && d.find_tag_unsigned::<u16>(Tag::Compression).ok().flatten() == Some(4)
        && d.find_tag_unsigned::<u16>(Tag::FillOrder).ok().flatten() == Some(2);
    fax || (fill_order_2(&mut d)
        && matches!(
            d.colortype(),
            Ok(ColorType::Gray(1..=7) | ColorType::Palette(1..=7))
        ))
        || (matches!(extra_sample(&mut d), Some(0 | 1))
            && matches!(
                d.colortype(),
                Ok(ColorType::RGBA(8 | 16)
                    | ColorType::Multiband {
                        bit_depth: 8,
                        num_samples: 2
                    })
            ))
}

/// RGB, RGBA, CMYK and YCbCr of 8 or 16 bits: those the hashing decoder
/// refuses when each strip or tile holds one band (planar), and CMYK and
/// YCbCr, which it does not convert. 16-bit values keep their high byte.
/// `stored` is the samples to a pixel in the file; those after the colour
/// ones are left out.
fn bands(
    d: &mut Decoder<Cursor<&[u8]>>,
    color: ColorType,
    bits: u8,
    width: u32,
    height: u32,
    stored: usize,
) -> Result<Pixels, Error> {
    let count = if matches!(color, ColorType::RGB(_) | ColorType::YCbCr(_)) {
        3
    } else {
        4
    };
    let values = all_values(d, (width, height), stored)?;
    let bytes: Vec<u8> = values
        .chunks_exact(stored)
        .flat_map(|p| &p[..count])
        .map(|&v| if bits == 16 { (v >> 8) as u8 } else { v as u8 })
        .collect();
    let (channels, samples) = match color {
        ColorType::RGB(_) => (Channels::Rgb, bytes),
        ColorType::RGBA(_) if associated_alpha(d) => (Channels::Rgba, unpremultiply(bytes, 4)),
        ColorType::RGBA(_) if unspecified_extra(d) => (Channels::Rgba, opaque(bytes, 4)),
        ColorType::RGBA(_) => (Channels::Rgba, bytes),
        ColorType::CMYK(_) => (Channels::Rgb, cmyk_to_rgb(&bytes)),
        _ => (Channels::Rgb, super::ycc_to_rgb(bytes)),
    };
    Ok(Pixels {
        width,
        height,
        channels,
        samples: Samples::U8(samples),
    })
}

/// CMYK bytes to RGB the way the hashing decoder does it for chunky ones:
/// `(255 - c) * (1 - k / 255)`.
fn cmyk_to_rgb(cmyk: &[u8]) -> Vec<u8> {
    cmyk.as_chunks::<4>()
        .0
        .iter()
        .flat_map(|p| {
            let k = 1.0 - f32::from(p[3]) / 255.0;
            [0, 1, 2].map(|i| ((255.0 - f32::from(p[i])) * k) as u8)
        })
        .collect()
}

/// Every sample of an 8 or 16-bit image, `count` to a pixel, chunky or planar.
fn all_values(
    d: &mut Decoder<Cursor<&[u8]>>,
    (width, height): (u32, u32),
    count: usize,
) -> Result<Vec<u16>, Error> {
    let (w, h) = (width as usize, height as usize);
    let planar = d
        .find_tag_unsigned::<u16>(Tag::PlanarConfiguration)
        .ok()
        .flatten()
        == Some(2);
    let values: Vec<u16> = if planar {
        planes(d, w, h, count)?
    } else {
        match d.read_image().map_err(|_| Error::Undecodable)? {
            DecodingResult::U8(v) => v.into_iter().map(u16::from).collect(),
            DecodingResult::U16(v) => v,
            _ => return Err(Error::Undecodable),
        }
    };
    if values.len() != w * h * count {
        return Err(Error::Undecodable);
    }
    Ok(values)
}

/// CIELab of 8 bits (photometric 8) as sRGB: L* of 0 to 255 stands for 0 to
/// 100, a* and b* are signed bytes. D50 is the white, as libtiff assumes.
fn lab_to_rgb(lab: &[u16]) -> Vec<u8> {
    const WHITE: [f64; 3] = [0.9642, 1.0, 0.8249];
    let f = |t: f64| {
        if t > 6.0 / 29.0 {
            t.powi(3)
        } else {
            3.0 * (6.0f64 / 29.0).powi(2) * (t - 4.0 / 29.0)
        }
    };
    let encode = |v: f64| {
        let v = v.clamp(0.0, 1.0);
        let v = if v <= 0.003_130_8 {
            12.92 * v
        } else {
            1.055 * v.powf(1.0 / 2.4) - 0.055
        };
        (v * 255.0 + 0.5) as u8
    };
    lab.as_chunks::<3>()
        .0
        .iter()
        .flat_map(|p| {
            let l = f64::from(p[0] as u8) * 100.0 / 255.0;
            let a = f64::from(p[1] as u8 as i8);
            let b = f64::from(p[2] as u8 as i8);
            let fy = (l + 16.0) / 116.0;
            let (x, y, z) = (
                WHITE[0] * f(fy + a / 500.0),
                WHITE[1] * f(fy),
                WHITE[2] * f(fy - b / 200.0),
            );
            [
                3.133_856_1 * x - 1.616_866_7 * y - 0.490_614_6 * z,
                -0.978_768_4 * x + 1.916_141_5 * y + 0.033_454_0 * z,
                0.071_945_3 * x - 0.228_991_4 * y + 1.405_242_7 * z,
            ]
            .map(encode)
        })
        .collect()
}

/// The first of `count` bands as grey bytes: 8-bit values as they are, 16-bit
/// ones stretched like other wide samples.
fn first_band(
    d: &mut Decoder<Cursor<&[u8]>>,
    bits: u8,
    count: usize,
    (width, height): (u32, u32),
    nodata: Option<f64>,
) -> Result<Pixels, Error> {
    let values = all_values(d, (width, height), count)?;
    let band: Vec<u16> = values.chunks_exact(count).map(|p| p[0]).collect();
    let grey = if bits == 8 {
        band.iter().map(|&v| v as u8).collect()
    } else {
        stretch(&band, f64::from, nodata)
    };
    Ok(Pixels {
        width,
        height,
        channels: Channels::Luma,
        samples: Samples::U8(grey),
    })
}

/// The bands of a planar image put together, `count` values to a pixel. The
/// chunks of the first band come first, then those of the next.
fn planes(
    d: &mut Decoder<Cursor<&[u8]>>,
    width: usize,
    height: usize,
    count: usize,
) -> Result<Vec<u16>, Error> {
    let chunks = match d.get_chunk_type() {
        ChunkType::Strip => d.strip_count(),
        ChunkType::Tile => d.tile_count(),
    }
    .map_err(|_| Error::Undecodable)? as usize;
    if chunks == 0 || !chunks.is_multiple_of(count) {
        return Err(Error::Undecodable);
    }
    let per_band = chunks / count;
    let (chunk_width, chunk_height) = d.chunk_dimensions();
    let (chunk_width, chunk_height) = (chunk_width as usize, chunk_height as usize);
    if chunk_width == 0 || chunk_height == 0 {
        return Err(Error::Undecodable);
    }
    let across = width.div_ceil(chunk_width);
    let mut out = vec![0u16; width * height * count];
    for band in 0..count {
        for c in 0..per_band {
            let index = (band * per_band + c) as u32;
            let (w, h) = d.chunk_data_dimensions(index);
            let (w, h) = (w as usize, h as usize);
            let values: Vec<u16> = match d.read_chunk(index).map_err(|_| Error::Undecodable)? {
                DecodingResult::U8(v) => v.into_iter().map(u16::from).collect(),
                DecodingResult::U16(v) => v,
                _ => return Err(Error::Undecodable),
            };
            let (x0, y0) = match d.get_chunk_type() {
                ChunkType::Strip => (0, c * chunk_height),
                ChunkType::Tile => (c % across * chunk_width, c / across * chunk_height),
            };
            for row in 0..h {
                for col in 0..w {
                    let (x, y) = (x0 + col, y0 + row);
                    if x < width && y < height {
                        out[(y * width + x) * count + band] =
                            values.get(row * w + col).copied().unwrap_or(0);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// `bits`-bit values, most significant first, `width` to a row and each row
/// padded to a byte, as one byte each. With `reversed` the bits of every byte
/// are taken in the opposite order first, as libtiff does for a fill order of 2.
fn unpack(packed: &[u8], width: usize, height: usize, bits: u8, reversed: bool) -> Vec<u8> {
    let bits = usize::from(bits);
    let row = (width * bits).div_ceil(8);
    let mut out = Vec::with_capacity(width * height);
    for y in 0..height {
        for x in 0..width {
            let at = y * row + x * bits / 8;
            let shift = 8 - bits - (x * bits) % 8;
            out.push(packed.get(at).map_or(0, |&b| {
                let b = if reversed { b.reverse_bits() } else { b };
                (b >> shift) & ((1u8 << bits) - 1)
            }));
        }
    }
    out
}

/// `bits`-bit values of 9 to 15 bits, most significant first, `width` to a row
/// and each row padded to a byte, as 16-bit values. `packed` is what the
/// decoder left in its buffer of 16-bit values (the bytes as the file has them,
/// in the memory order of the buffer). With `invert`, a white-is-zero image.
fn unpack_wide(packed: &[u16], width: usize, height: usize, bits: u8, invert: bool) -> Vec<u16> {
    let bits = usize::from(bits);
    let bytes: Vec<u8> = packed.iter().flat_map(|v| v.to_ne_bytes()).collect();
    let row = (width * bits).div_ceil(8);
    let max = (1u32 << bits) - 1;
    let mut out = Vec::with_capacity(width * height);
    for y in 0..height {
        for x in 0..width {
            // The 16 bits that hold the value are read from the byte it starts in.
            let first = y * row + x * bits / 8;
            let word = [first, first + 1, first + 2]
                .map(|i| u32::from(bytes.get(i).copied().unwrap_or(0)));
            let word = word[0] << 16 | word[1] << 8 | word[2];
            let value = (word >> (24 - bits - (x * bits) % 8)) & max;
            out.push((if invert { max - value } else { value }) as u16);
        }
    }
    out
}

/// RGB bytes from palette indices and a TIFF colour map (all reds, then all
/// greens, then all blues, 16 bits each).
fn palette(indices: impl Iterator<Item = usize>, map: Option<&[u16]>) -> Result<Vec<u8>, Error> {
    let map = map.ok_or(Error::Undecodable)?;
    let n = map.len() / 3;
    if n == 0 {
        return Err(Error::Undecodable);
    }
    let mut out = Vec::new();
    for i in indices {
        // An index past the map is the last colour, as a short map is a truncated one.
        let i = i.min(n - 1);
        out.extend([map[i], map[n + i], map[2 * n + i]].map(|c| (c >> 8) as u8));
    }
    Ok(out)
}

/// An IEEE half-precision value from its bits.
fn half(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from((bits >> 10) & 0x1f);
    let fraction = f64::from(bits & 0x3ff);
    match exponent {
        0 => sign * fraction * 2f64.powi(-24),
        31 if fraction == 0.0 => sign * f64::INFINITY,
        31 => f64::NAN,
        e => sign * (1.0 + fraction / 1024.0) * 2f64.powi(e - 15),
    }
}

/// Grey bytes from values: `lo` to `hi` (the 0.5th and 99.5th percentiles of
/// those that are numbers and not nodata) is 0 to 255, values outside it are
/// clipped, nodata and what is not a number are 0.
fn stretch<T: Copy>(values: &[T], f: impl Fn(T) -> f64, nodata: Option<f64>) -> Vec<u8> {
    let valid = |x: f64| x.is_finite() && nodata != Some(x);
    let step = values.len().div_ceil(RANGE_SAMPLE).max(1);
    let mut sample: Vec<f64> = values
        .iter()
        .step_by(step)
        .map(|&x| f(x))
        .filter(|&x| valid(x))
        .collect();
    sample.sort_by(f64::total_cmp);
    let at = |q: f64| {
        sample
            .get(((sample.len() - 1) as f64 * q) as usize)
            .copied()
    };
    let (lo, hi) = match (at(0.005), at(0.995)) {
        (Some(lo), Some(hi)) => (lo, hi),
        _ => return vec![0; values.len()],
    };
    let scale = if hi > lo { 255.0 / (hi - lo) } else { 0.0 };
    values
        .iter()
        .map(|&x| {
            let x = f(x);
            if valid(x) {
                ((x - lo) * scale).clamp(0.0, 255.0).round() as u8
            } else {
                0
            }
        })
        .collect()
}
