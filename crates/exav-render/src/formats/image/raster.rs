//! Grey pixels from the raw samples of a PDF image that exav-unpack describes
//! ([`Raster`]): the predictor undone, the samples (1, 2, 4, 8 or 16 bits) of
//! Gray, RGB, CMYK or an Indexed palette taken through `/Decode`, then to grey
//! as the QR search reads it. An image mask is a 1-bit grey image. JPEG and
//! JPEG 2000 streams are files and go through [`super::decode`]; CCITT and
//! JBIG2 streams are decoded by [`crate::pdf_image`] (features `ccitt` and
//! `jbig2`) into 1-bit samples, which are read the same way.

use std::borrow::Cow;

use exav_unpack::{Raster, RasterCodec, RasterSpace};

use super::{Channels, Error, Pixels, Samples, cmyk_pixel, within};

/// The grey pixels of the image `raster` describes, whose samples are `data`:
/// the stream with its filters undone, a predictor aside. At most `max_alloc`
/// bytes (and [`super::DECODE_MAX`]) are allocated; an image that needs more is
/// [`Error::TooLarge`], before it is allocated. [`Error::Unsupported`] for a
/// codec not built in, a color space or a predictor not read here, a
/// dictionary that gave no size, and JBIG2 globals that could not be read;
/// [`Error::Undecodable`] for samples that do not reach the image's size and a
/// codec stream that does not decode. For a CCITT or JBIG2 image `data` is the
/// codec's stream.
pub fn from_raster(raster: &Raster, data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    std::panic::catch_unwind(|| grey(raster, data, max_alloc)).unwrap_or(Err(Error::Undecodable))
}

/// How a sample becomes a level, a 256-entry table for each of the 1 (gray,
/// or an index in a palette, already grey), 3 (RGB) or 4 (CMYK) components.
struct Mapping {
    components: u64,
    lut: [[u8; 256]; 4],
}

fn grey(raster: &Raster, data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    if let Some(codec) = &raster.codec {
        // The codec gives 1-bit rows: the samples of a Gray, Indexed or mask
        // image, which are read as any other.
        mapping(raster)?;
        let (w, h) = (u64::from(raster.width), u64::from(raster.height));
        // The bitmap and the grey pixels built from it are held together.
        within(
            w.saturating_mul(h)
                .saturating_add(w.div_ceil(8).saturating_mul(h)),
            max_alloc,
        )?;
        let bitmap = decode_codec(raster, codec, data, max_alloc)?;
        let samples = Raster {
            codec: None,
            ..raster.clone()
        };
        return grey(&samples, &bitmap, max_alloc);
    }
    let mapping = mapping(raster)?;
    let (w, h) = (u64::from(raster.width), u64::from(raster.height));
    if w == 0 || h == 0 {
        return Err(Error::Undecodable);
    }
    let bits = raster.bits;
    let stride = (w * mapping.components * u64::from(bits)).div_ceil(8);
    let need = stride.checked_mul(h).ok_or(Error::Undecodable)?;
    let pixels = w * h;
    let samples: Cow<'_, [u8]> = match &raster.predictor {
        None => {
            if (data.len() as u64) < need {
                return Err(Error::Undecodable);
            }
            within(pixels, max_alloc)?;
            Cow::Borrowed(data)
        }
        Some(p) => {
            let Some((rowlen, tagged)) = p.row() else {
                return Err(if matches!(p.kind, 2 | 10..=15) {
                    Error::Undecodable
                } else {
                    Error::Unsupported
                });
            };
            let rows = need.div_ceil(rowlen);
            let len = rows
                .checked_mul(rowlen + u64::from(tagged))
                .filter(|&n| n <= data.len() as u64)
                .ok_or(Error::Undecodable)?;
            within(pixels.saturating_add(len), max_alloc)?;
            let mut samples = data[..len as usize].to_vec();
            p.undo(&mut samples);
            Cow::Owned(samples)
        }
    };
    let (w, stride) = (w as usize, stride as usize);
    let mut out = vec![0u8; pixels as usize];
    let lut = &mapping.lut;
    match mapping.components {
        1 => fill(&mut out, w, &samples, stride, |row, x| {
            lut[0][sample(row, x, bits)]
        }),
        3 => fill(&mut out, w, &samples, stride, |row, x| {
            let at = 3 * x;
            luma(
                lut[0][sample(row, at, bits)],
                lut[1][sample(row, at + 1, bits)],
                lut[2][sample(row, at + 2, bits)],
            )
        }),
        _ => fill(&mut out, w, &samples, stride, |row, x| {
            let at = 4 * x;
            let [r, g, b] = cmyk_pixel(
                lut[0][sample(row, at, bits)],
                lut[1][sample(row, at + 1, bits)],
                lut[2][sample(row, at + 2, bits)],
                lut[3][sample(row, at + 3, bits)],
            );
            luma(r, g, b)
        }),
    }
    Ok(Pixels {
        width: raster.width,
        height: raster.height,
        channels: Channels::Luma,
        samples: Samples::U8(out),
    })
}

/// Neither codec is built in.
#[cfg(not(any(feature = "ccitt", feature = "jbig2")))]
fn decode_codec(_: &Raster, _: &RasterCodec, _: &[u8], _: u64) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported)
}

/// The 1-bit rows of the stream `data` of a CCITT or JBIG2 image, which the
/// decoder of `pdf_image` limits to `max_alloc` bytes.
#[cfg(any(feature = "ccitt", feature = "jbig2"))]
fn decode_codec(
    raster: &Raster,
    codec: &RasterCodec,
    data: &[u8],
    max_alloc: u64,
) -> Result<Vec<u8>, Error> {
    let decoded: Option<Result<Vec<u8>, crate::pdf_image::Error>> = match codec {
        #[cfg(feature = "ccitt")]
        RasterCodec::Ccitt {
            k,
            end_of_line,
            encoded_byte_align,
            black_is_1,
            columns,
            rows,
        } => Some(crate::pdf_image::decode_ccitt(
            data,
            crate::pdf_image::CcittParams {
                width: raster.width,
                height: raster.height,
                k: *k,
                end_of_line: *end_of_line,
                encoded_byte_align: *encoded_byte_align,
                black_is_1: *black_is_1,
                columns: *columns,
                rows: *rows,
            },
            max_alloc,
        )),
        #[cfg(feature = "jbig2")]
        RasterCodec::Jbig2 {
            globals_unread: true,
            ..
        } => return Err(Error::Unsupported),
        #[cfg(feature = "jbig2")]
        RasterCodec::Jbig2 { globals, .. } => Some(crate::pdf_image::decode_jbig2_strict(
            data,
            raster.width,
            raster.height,
            globals.as_deref(),
            max_alloc,
        )),
        _ => None,
    };
    let decoded = decoded.ok_or(Error::Unsupported)?;
    decoded.map_err(|e| {
        if e.is_too_large() {
            Error::TooLarge
        } else {
            Error::Undecodable
        }
    })
}

/// The grey of each pixel, `w` to a row, from the `stride`-byte rows of `src`.
fn fill(out: &mut [u8], w: usize, src: &[u8], stride: usize, pixel: impl Fn(&[u8], usize) -> u8) {
    for (dst, row) in out.chunks_exact_mut(w).zip(src.chunks_exact(stride)) {
        for (x, d) in dst.iter_mut().enumerate() {
            *d = pixel(row, x);
        }
    }
}

/// The `i`th sample of a row, as an index into a 256-entry table: a 16-bit
/// sample by its high byte. `row` holds the whole row.
#[inline]
fn sample(row: &[u8], i: usize, bits: u8) -> usize {
    match bits {
        8 => usize::from(row[i]),
        16 => usize::from(row[2 * i]),
        _ => {
            let b = usize::from(bits);
            let shift = 8 - b * (1 + i % (8 / b));
            usize::from(row[i * b / 8] >> shift) & ((1 << b) - 1)
        }
    }
}

/// The weights of the QR search's own grey (`qr`), for the pixels it reads.
fn luma(r: u8, g: u8, b: u8) -> u8 {
    ((299 * u32::from(r) + 587 * u32::from(g) + 114 * u32::from(b)) / 1000) as u8
}

fn mapping(raster: &Raster) -> Result<Mapping, Error> {
    let bits = raster.bits;
    if !matches!(bits, 1 | 2 | 4 | 8 | 16) {
        return Err(Error::Unsupported);
    }
    // The last value of a sample; a 16-bit one is read by its high byte.
    let last = (1u32 << bits.min(8)) - 1;
    // Component `c` of every sample value, through `/Decode`, as a level
    // between 0 and 1 (`hi`: the default end of the range).
    let decoded = |c: usize, hi: f32| {
        let (d0, d1) = raster
            .decode
            .as_deref()
            .and_then(|d| Some((*d.get(2 * c)?, *d.get(2 * c + 1)?)))
            .unwrap_or((0.0, hi));
        (0..=last).map(move |s| d0 + s as f32 / last as f32 * (d1 - d0))
    };
    let level = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u8;
    // The tables of `n` components.
    let tables = |n: usize| {
        let mut lut = [[0u8; 256]; 4];
        for (c, table) in lut.iter_mut().enumerate().take(n) {
            for (slot, v) in table.iter_mut().zip(decoded(c, 1.0)) {
                *slot = level(v);
            }
        }
        Ok(Mapping {
            components: n as u64,
            lut,
        })
    };
    match &raster.space {
        RasterSpace::Gray | RasterSpace::Mask => tables(1),
        RasterSpace::Rgb => tables(3),
        RasterSpace::Cmyk => tables(4),
        RasterSpace::Indexed {
            base,
            hival,
            palette,
        } if bits <= 8 => {
            let components = match **base {
                RasterSpace::Gray => 1,
                RasterSpace::Rgb => 3,
                RasterSpace::Cmyk => 4,
                _ => return Err(Error::Unsupported),
            };
            let mut lut = [[0u8; 256]; 4];
            for (slot, v) in lut[0].iter_mut().zip(decoded(0, last as f32)) {
                let at = (v.round().clamp(0.0, f32::from(*hival)) as usize) * components;
                let e = |k: usize| palette.get(at + k).copied().unwrap_or(0);
                *slot = match components {
                    1 => e(0),
                    3 => luma(e(0), e(1), e(2)),
                    _ => {
                        let [r, g, b] = cmyk_pixel(e(0), e(1), e(2), e(3));
                        luma(r, g, b)
                    }
                };
            }
            Ok(Mapping { components: 1, lut })
        }
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exav_unpack::Predictor;

    fn raster(width: u32, height: u32, bits: u8, space: RasterSpace) -> Raster {
        Raster {
            width,
            height,
            bits,
            space,
            ..Raster::default()
        }
    }

    fn grey_of(r: &Raster, data: &[u8]) -> Vec<u8> {
        match from_raster(r, data, 1 << 20).unwrap().samples {
            Samples::U8(v) => v,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn samples_become_grey_levels() {
        let indexed = |base, palette: &[u8]| RasterSpace::Indexed {
            base: Box::new(base),
            hival: 1,
            palette: palette.to_vec(),
        };
        let png = Raster {
            predictor: Some(Predictor {
                kind: 15,
                colors: 1,
                bits: 8,
                columns: 2,
            }),
            ..raster(2, 5, 8, RasterSpace::Gray)
        };
        let inverted = Raster {
            decode: Some(vec![1.0, 0.0]),
            ..raster(2, 1, 8, RasterSpace::Gray)
        };
        let cases: Vec<(&str, Raster, Vec<u8>, Vec<u8>)> = vec![
            (
                "gray 8",
                raster(2, 2, 8, RasterSpace::Gray),
                vec![0, 85, 170, 255],
                vec![0, 85, 170, 255],
            ),
            (
                "gray 1, rows padded to a byte",
                raster(3, 2, 1, RasterSpace::Gray),
                vec![0b1010_0000, 0b0100_0000],
                vec![255, 0, 255, 0, 255, 0],
            ),
            (
                "gray 2",
                raster(4, 1, 2, RasterSpace::Gray),
                vec![0b0001_1011],
                vec![0, 85, 170, 255],
            ),
            (
                "gray 4",
                raster(3, 1, 4, RasterSpace::Gray),
                vec![0x0F, 0x80],
                vec![0, 255, 136],
            ),
            (
                "gray 16, by the high byte",
                raster(2, 1, 16, RasterSpace::Gray),
                vec![0x00, 0x12, 0xFF, 0xFF],
                vec![0, 255],
            ),
            (
                "rgb 8",
                raster(2, 1, 8, RasterSpace::Rgb),
                vec![255, 0, 0, 0, 255, 0],
                vec![76, 149],
            ),
            (
                "cmyk 8: black, white, cyan",
                raster(3, 1, 8, RasterSpace::Cmyk),
                vec![0, 0, 0, 255, 0, 0, 0, 0, 255, 0, 0, 0],
                vec![0, 255, 178],
            ),
            (
                "indexed 1 over rgb",
                raster(2, 1, 1, indexed(RasterSpace::Rgb, &[255, 0, 0, 0, 0, 255])),
                vec![0b0100_0000],
                vec![76, 29],
            ),
            (
                "indexed over gray, a palette shorter than hival",
                raster(2, 1, 1, indexed(RasterSpace::Gray, &[200])),
                vec![0b0100_0000],
                vec![200, 0],
            ),
            (
                "indexed over cmyk",
                raster(
                    2,
                    1,
                    1,
                    indexed(RasterSpace::Cmyk, &[0, 0, 0, 255, 0, 0, 0, 0]),
                ),
                vec![0b0100_0000],
                vec![0, 255],
            ),
            (
                "mask: a set bit is not painted",
                raster(2, 1, 1, RasterSpace::Mask),
                vec![0b0100_0000],
                vec![0, 255],
            ),
            ("decode inverts", inverted, vec![0, 255], vec![255, 0]),
            (
                "png: none, sub, up, average, paeth",
                png,
                vec![0, 10, 20, 1, 5, 5, 2, 1, 1, 3, 2, 2, 4, 1, 1],
                vec![10, 20, 5, 10, 6, 11, 5, 10, 6, 11],
            ),
        ];
        for (what, r, data, want) in cases {
            assert_eq!(grey_of(&r, &data), want, "{what}");
        }
    }

    #[test]
    fn what_is_not_read_or_too_large_is_refused() {
        let gray = raster(4, 4, 8, RasterSpace::Gray);
        assert_eq!(
            from_raster(&gray, &[0; 15], 1 << 20),
            Err(Error::Undecodable)
        );
        assert_eq!(from_raster(&gray, &[0; 16], 15), Err(Error::TooLarge));
        let lab = raster(1, 1, 8, RasterSpace::Other("Lab".into()));
        assert_eq!(from_raster(&lab, &[0; 3], 1 << 20), Err(Error::Unsupported));
        let predicted = |kind| Raster {
            predictor: Some(Predictor {
                kind,
                colors: 1,
                bits: 8,
                columns: 4,
            }),
            ..gray.clone()
        };
        assert_eq!(
            from_raster(&predicted(5), &[0; 16], 1 << 20),
            Err(Error::Unsupported)
        );
        // A PNG predictor's rows are a byte longer each.
        assert_eq!(
            from_raster(&predicted(12), &[0; 16], 1 << 20),
            Err(Error::Undecodable)
        );
    }

    /// The TIFF predictor: a sample is the difference to the one before it.
    #[test]
    fn a_tiff_predictor_is_undone() {
        let tiff = Raster {
            predictor: Some(Predictor {
                kind: 2,
                colors: 1,
                bits: 8,
                columns: 2,
            }),
            ..raster(2, 2, 8, RasterSpace::Gray)
        };
        assert_eq!(grey_of(&tiff, &[10, 5, 200, 50]), [10, 15, 200, 250]);
    }
}
