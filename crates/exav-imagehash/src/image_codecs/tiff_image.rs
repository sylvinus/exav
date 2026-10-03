//! `image` 0.25.9's TIFF decoder (`src/codecs/tiff.rs`, and the
//! `expand_bits` it calls from `src/utils/mod.rs`), over the vendored `tiff`:
//! see `README.md`. Only what decoding uses is kept.

use std::io::{BufRead, Cursor, Seek, Write};

use image::error::{
    DecodingError, ImageError, ImageResult, LimitError, LimitErrorKind, UnsupportedError,
    UnsupportedErrorKind,
};
use image::{ColorType, ExtendedColorType, ImageDecoder, ImageFormat, LimitSupport};

use super::tiff;
use super::tiff::decoder::{Decoder, DecodingResult};
use super::tiff::tags::Tag;

pub(crate) struct TiffDecoder<R>
where
    R: BufRead + Seek,
{
    dimensions: (u32, u32),
    color_type: ColorType,
    original_color_type: ExtendedColorType,

    // We only use an Option here so we can call with_limits on the decoder without moving.
    inner: Option<Decoder<R>>,
}

impl<R> TiffDecoder<R>
where
    R: BufRead + Seek,
{
    /// Create a new `TiffDecoder`.
    pub(crate) fn new(r: R) -> Result<TiffDecoder<R>, ImageError> {
        let mut inner = Decoder::new(r).map_err(from_tiff_decode)?;

        let dimensions = inner.dimensions().map_err(from_tiff_decode)?;
        let tiff_color_type = inner.colortype().map_err(from_tiff_decode)?;

        match inner.find_tag_unsigned_vec::<u16>(Tag::SampleFormat) {
            Ok(Some(sample_formats)) => {
                for format in sample_formats {
                    check_sample_format(format, tiff_color_type)?;
                }
            }
            Ok(None) => { /* assume UInt format */ }
            Err(other) => return Err(from_tiff_decode(other)),
        }

        let planar_config = inner
            .find_tag(Tag::PlanarConfiguration)
            .map(|res| res.and_then(|r| r.into_u16().ok()).unwrap_or_default())
            .unwrap_or_default();

        // Decode not supported for non Chunky Planar Configuration
        if planar_config > 1 {
            Err(ImageError::Unsupported(
                UnsupportedError::from_format_and_kind(
                    ImageFormat::Tiff.into(),
                    UnsupportedErrorKind::GenericFeature(String::from("PlanarConfiguration = 2")),
                ),
            ))?;
        }

        let color_type = match tiff_color_type {
            tiff::ColorType::Gray(1) => ColorType::L8,
            tiff::ColorType::Gray(8) => ColorType::L8,
            tiff::ColorType::Gray(16) => ColorType::L16,
            tiff::ColorType::GrayA(8) => ColorType::La8,
            tiff::ColorType::GrayA(16) => ColorType::La16,
            tiff::ColorType::RGB(8) => ColorType::Rgb8,
            tiff::ColorType::RGB(16) => ColorType::Rgb16,
            tiff::ColorType::RGBA(8) => ColorType::Rgba8,
            tiff::ColorType::RGBA(16) => ColorType::Rgba16,
            tiff::ColorType::CMYK(8) => ColorType::Rgb8,
            tiff::ColorType::CMYK(16) => ColorType::Rgb16,
            tiff::ColorType::RGB(32) => ColorType::Rgb32F,
            tiff::ColorType::RGBA(32) => ColorType::Rgba32F,

            tiff::ColorType::Palette(n) | tiff::ColorType::Gray(n) => {
                return Err(err_unknown_color_type(n))
            }
            tiff::ColorType::GrayA(n) => return Err(err_unknown_color_type(n.saturating_mul(2))),
            tiff::ColorType::RGB(n) => return Err(err_unknown_color_type(n.saturating_mul(3))),
            tiff::ColorType::YCbCr(n) => return Err(err_unknown_color_type(n.saturating_mul(3))),
            tiff::ColorType::RGBA(n) | tiff::ColorType::CMYK(n) => {
                return Err(err_unknown_color_type(n.saturating_mul(4)))
            }
            tiff::ColorType::Multiband {
                bit_depth,
                num_samples,
            } => {
                return Err(err_unknown_color_type(
                    bit_depth.saturating_mul(num_samples.min(255) as u8),
                ))
            }
            _ => return Err(err_unknown_color_type(0)),
        };

        let original_color_type = match tiff_color_type {
            tiff::ColorType::Gray(1) => ExtendedColorType::L1,
            tiff::ColorType::CMYK(8) => ExtendedColorType::Cmyk8,
            tiff::ColorType::CMYK(16) => ExtendedColorType::Cmyk16,
            _ => color_type.into(),
        };

        Ok(TiffDecoder {
            dimensions,
            color_type,
            original_color_type,
            inner: Some(inner),
        })
    }

    // The buffer can be larger for CMYK than the RGB output
    fn total_bytes_buffer(&self) -> u64 {
        let dimensions = self.dimensions();
        let total_pixels = u64::from(dimensions.0) * u64::from(dimensions.1);

        let bytes_per_pixel = match self.original_color_type {
            ExtendedColorType::Cmyk8 => 4,
            ExtendedColorType::Cmyk16 => 8,
            _ => u64::from(self.color_type().bytes_per_pixel()),
        };
        total_pixels.saturating_mul(bytes_per_pixel)
    }
}

fn check_sample_format(sample_format: u16, color_type: tiff::ColorType) -> Result<(), ImageError> {
    use tiff::{tags::SampleFormat, ColorType};
    let num_bits = match color_type {
        ColorType::CMYK(k) => k,
        ColorType::Gray(k) => k,
        ColorType::RGB(k) => k,
        ColorType::RGBA(k) => k,
        ColorType::GrayA(k) => k,
        ColorType::Palette(k) | ColorType::YCbCr(k) => {
            return Err(ImageError::Unsupported(
                UnsupportedError::from_format_and_kind(
                    ImageFormat::Tiff.into(),
                    UnsupportedErrorKind::GenericFeature(format!(
                        "Unhandled TIFF color type {color_type:?} for {k} bits",
                    )),
                ),
            ))
        }
        _ => {
            return Err(ImageError::Unsupported(
                UnsupportedError::from_format_and_kind(
                    ImageFormat::Tiff.into(),
                    UnsupportedErrorKind::GenericFeature(format!(
                        "Unhandled TIFF color type {color_type:?}",
                    )),
                ),
            ))
        }
    };

    match SampleFormat::from_u16(sample_format) {
        Some(SampleFormat::Uint) if num_bits <= 16 => Ok(()),
        Some(SampleFormat::IEEEFP) if num_bits == 32 => Ok(()),
        _ => Err(ImageError::Unsupported(
            UnsupportedError::from_format_and_kind(
                ImageFormat::Tiff.into(),
                UnsupportedErrorKind::GenericFeature(format!(
                    "Unhandled TIFF sample format {sample_format:?} for {num_bits} bits",
                )),
            ),
        )),
    }
}

fn err_unknown_color_type(value: u8) -> ImageError {
    ImageError::Unsupported(UnsupportedError::from_format_and_kind(
        ImageFormat::Tiff.into(),
        UnsupportedErrorKind::Color(ExtendedColorType::Unknown(value)),
    ))
}

fn from_tiff_decode(err: tiff::TiffError) -> ImageError {
    match err {
        tiff::TiffError::IoError(err) => ImageError::IoError(err),
        err @ (tiff::TiffError::FormatError(_)
        | tiff::TiffError::IntSizeError
        | tiff::TiffError::UsageError(_)) => {
            ImageError::Decoding(DecodingError::new(ImageFormat::Tiff.into(), err))
        }
        tiff::TiffError::UnsupportedError(desc) => {
            ImageError::Unsupported(UnsupportedError::from_format_and_kind(
                ImageFormat::Tiff.into(),
                UnsupportedErrorKind::GenericFeature(desc.to_string()),
            ))
        }
        tiff::TiffError::LimitsExceeded => {
            ImageError::Limits(LimitError::from_kind(LimitErrorKind::InsufficientMemory))
        }
    }
}

impl<R: BufRead + Seek> ImageDecoder for TiffDecoder<R> {
    fn dimensions(&self) -> (u32, u32) {
        self.dimensions
    }

    fn color_type(&self) -> ColorType {
        self.color_type
    }

    fn original_color_type(&self) -> ExtendedColorType {
        self.original_color_type
    }

    fn set_limits(&mut self, limits: image::Limits) -> ImageResult<()> {
        limits.check_support(&LimitSupport::default())?;

        let (width, height) = self.dimensions();
        limits.check_dimensions(width, height)?;

        let max_alloc = limits.max_alloc.unwrap_or(u64::MAX);
        let max_intermediate_alloc = max_alloc.saturating_sub(self.total_bytes_buffer());

        let mut tiff_limits: tiff::decoder::Limits = Default::default();
        tiff_limits.decoding_buffer_size =
            usize::try_from(max_alloc - max_intermediate_alloc).unwrap_or(usize::MAX);
        tiff_limits.intermediate_buffer_size =
            usize::try_from(max_intermediate_alloc).unwrap_or(usize::MAX);
        tiff_limits.ifd_value_size = tiff_limits.intermediate_buffer_size;
        self.inner = Some(self.inner.take().unwrap().with_limits(tiff_limits));

        Ok(())
    }

    fn read_image(self, buf: &mut [u8]) -> ImageResult<()> {
        assert_eq!(u64::try_from(buf.len()), Ok(self.total_bytes()));

        match self.inner.unwrap().read_image().map_err(from_tiff_decode)? {
            DecodingResult::U8(v) if self.original_color_type == ExtendedColorType::Cmyk8 => {
                let mut out_cur = Cursor::new(buf);
                for cmyk in v.chunks_exact(4) {
                    out_cur.write_all(&cmyk_to_rgb(cmyk))?;
                }
            }
            DecodingResult::U16(v) if self.original_color_type == ExtendedColorType::Cmyk16 => {
                let mut out_cur = Cursor::new(buf);
                for cmyk in v.chunks_exact(4) {
                    out_cur.write_all(bytemuck::cast_slice(&cmyk_to_rgb16(cmyk)))?;
                }
            }
            DecodingResult::U8(v) if self.original_color_type == ExtendedColorType::L1 => {
                let width = self.dimensions.0;
                let row_bytes = width.div_ceil(8);

                for (in_row, out_row) in v
                    .chunks_exact(row_bytes as usize)
                    .zip(buf.chunks_exact_mut(width as usize))
                {
                    out_row.copy_from_slice(&expand_bits(1, width, in_row));
                }
            }
            DecodingResult::U8(v) => {
                buf.copy_from_slice(&v);
            }
            DecodingResult::U16(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::U32(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::U64(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::I8(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::I16(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::I32(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::I64(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::F32(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::F64(v) => {
                buf.copy_from_slice(bytemuck::cast_slice(&v));
            }
            DecodingResult::F16(_) => unreachable!(),
        }
        Ok(())
    }

    fn read_image_boxed(self: Box<Self>, buf: &mut [u8]) -> ImageResult<()> {
        (*self).read_image(buf)
    }
}

fn cmyk_to_rgb(cmyk: &[u8]) -> [u8; 3] {
    let c = f32::from(cmyk[0]);
    let m = f32::from(cmyk[1]);
    let y = f32::from(cmyk[2]);
    let kf = 1. - f32::from(cmyk[3]) / 255.;
    [
        ((255. - c) * kf) as u8,
        ((255. - m) * kf) as u8,
        ((255. - y) * kf) as u8,
    ]
}

fn cmyk_to_rgb16(cmyk: &[u16]) -> [u16; 3] {
    let c = f32::from(cmyk[0]);
    let m = f32::from(cmyk[1]);
    let y = f32::from(cmyk[2]);
    let kf = 1. - f32::from(cmyk[3]) / 65535.;
    [
        ((65535. - c) * kf) as u16,
        ((65535. - m) * kf) as u16,
        ((65535. - y) * kf) as u16,
    ]
}

/// Expand a buffer of packed 1, 2, or 4 bits integers into u8's. Assumes that
/// every `row_size` entries there are padding bits up to the next byte boundary.
fn expand_bits(bit_depth: u8, row_size: u32, buf: &[u8]) -> Vec<u8> {
    // Note: this conversion assumes that the scanlines begin on byte boundaries
    let mask = (1u8 << bit_depth as usize) - 1;
    let scaling_factor = 255 / ((1 << bit_depth as usize) - 1);
    let bit_width = row_size * u32::from(bit_depth);
    let skip = if bit_width % 8 == 0 {
        0
    } else {
        (8 - bit_width % 8) / u32::from(bit_depth)
    };
    let row_len = row_size + skip;
    let mut p = Vec::new();
    let mut i = 0;
    for v in buf {
        for shift_inv in 1..=8 / bit_depth {
            let shift = 8 - bit_depth * shift_inv;
            // skip the pixels that can be neglected because scanlines should
            // start at byte boundaries
            if i % (row_len as usize) < (row_size as usize) {
                let pixel = (v & (mask << shift as usize)) >> shift as usize;
                p.push(pixel * scaling_factor);
            }
            i += 1;
        }
    }
    p
}
