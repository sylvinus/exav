//! Raster images into pixels.
//!
//! [`decode`] gives the samples as the decoder produced them ([`Pixels`]):
//! 8 or 16 bits or `f32`, grey or colour, with or without alpha, unconverted,
//! because what a caller does with them may depend on that (exav-imagehash
//! turns them grey as ClamAV or as Pillow does). [`Pixels::to_rgba8`] is the
//! conversion a display wants.

use image::{DynamicImage, ImageBuffer, ImageFormat};

use crate::image_codecs;

/// An image format this build decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    Png,
    Gif,
    Jpeg,
    Tiff,
    Bmp,
    #[cfg(feature = "webp")]
    Webp,
    #[cfg(feature = "ico")]
    Ico,
    #[cfg(feature = "pnm")]
    Pnm,
    #[cfg(feature = "qoi")]
    Qoi,
    #[cfg(feature = "dds")]
    Dds,
    #[cfg(feature = "ff")]
    Farbfeld,
    #[cfg(feature = "hdr")]
    Hdr,
    /// JP2, JPX or a raw codestream.
    #[cfg(feature = "jp2")]
    Jpeg2000,
    /// A JBIG2 file.
    #[cfg(feature = "jbig2")]
    Jbig2,
}

impl Format {
    /// Every format this build decodes.
    pub const ALL: &'static [Format] = &[
        Format::Png,
        Format::Gif,
        Format::Jpeg,
        Format::Tiff,
        Format::Bmp,
        #[cfg(feature = "webp")]
        Format::Webp,
        #[cfg(feature = "ico")]
        Format::Ico,
        #[cfg(feature = "pnm")]
        Format::Pnm,
        #[cfg(feature = "qoi")]
        Format::Qoi,
        #[cfg(feature = "dds")]
        Format::Dds,
        #[cfg(feature = "ff")]
        Format::Farbfeld,
        #[cfg(feature = "hdr")]
        Format::Hdr,
        #[cfg(feature = "jp2")]
        Format::Jpeg2000,
        #[cfg(feature = "jbig2")]
        Format::Jbig2,
    ];

    /// The format `data` starts as, by its magic bytes.
    pub fn detect(data: &[u8]) -> Option<Format> {
        let s = |m: &[u8]| data.starts_with(m);
        Some(if s(b"\x89PNG\r\n\x1a\n") {
            Format::Png
        } else if s(b"GIF87a") || s(b"GIF89a") {
            Format::Gif
        } else if s(&[0xFF, 0xD8, 0xFF]) {
            Format::Jpeg
        } else if s(b"II*\x00") || s(b"MM\x00*") {
            Format::Tiff
        } else if s(b"BM") {
            Format::Bmp
        } else {
            return Self::detect_extra(data);
        })
    }

    #[allow(unused_variables)]
    fn detect_extra(data: &[u8]) -> Option<Format> {
        #[cfg(feature = "webp")]
        if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
            return Some(Format::Webp);
        }
        #[cfg(feature = "ico")]
        if data.starts_with(&[0, 0, 1, 0]) {
            return Some(Format::Ico);
        }
        #[cfg(feature = "pnm")]
        if data.len() >= 2 && data[0] == b'P' && (b'1'..=b'7').contains(&data[1]) {
            return Some(Format::Pnm);
        }
        #[cfg(feature = "qoi")]
        if data.starts_with(b"qoif") {
            return Some(Format::Qoi);
        }
        #[cfg(feature = "dds")]
        if data.starts_with(b"DDS ") {
            return Some(Format::Dds);
        }
        #[cfg(feature = "ff")]
        if data.starts_with(b"farbfeld") {
            return Some(Format::Farbfeld);
        }
        #[cfg(feature = "hdr")]
        if data.starts_with(b"#?RADIANCE") {
            return Some(Format::Hdr);
        }
        // The JP2 signature box (JPX files start with it too), or a
        // codestream's SOC and SIZ markers.
        #[cfg(feature = "jp2")]
        if data.starts_with(b"\0\0\0\x0cjP  \r\n\x87\n")
            || data.starts_with(&[0xFF, 0x4F, 0xFF, 0x51])
        {
            return Some(Format::Jpeg2000);
        }
        #[cfg(feature = "jbig2")]
        if data.starts_with(b"\x97JB2\r\n\x1a\n") {
            return Some(Format::Jbig2);
        }
        None
    }

    /// Lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            Format::Png => "png",
            Format::Gif => "gif",
            Format::Jpeg => "jpeg",
            Format::Tiff => "tiff",
            Format::Bmp => "bmp",
            #[cfg(feature = "webp")]
            Format::Webp => "webp",
            #[cfg(feature = "ico")]
            Format::Ico => "ico",
            #[cfg(feature = "pnm")]
            Format::Pnm => "pnm",
            #[cfg(feature = "qoi")]
            Format::Qoi => "qoi",
            #[cfg(feature = "dds")]
            Format::Dds => "dds",
            #[cfg(feature = "ff")]
            Format::Farbfeld => "farbfeld",
            #[cfg(feature = "hdr")]
            Format::Hdr => "hdr",
            #[cfg(feature = "jp2")]
            Format::Jpeg2000 => "jpeg2000",
            #[cfg(feature = "jbig2")]
            Format::Jbig2 => "jbig2",
        }
    }
}

/// Why an image has no pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Not a format this build decodes.
    Unsupported,
    /// A corrupt image, one the decoders do not read, or one past
    /// [`DECODE_MAX`] decoded. A decoder panicking on a crafted file is this
    /// too.
    Undecodable,
    /// Decoding it takes more than the limit asked for, under [`DECODE_MAX`].
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Unsupported => "not an image format this build decodes",
            Error::Undecodable => "undecodable image",
            Error::TooLarge => "image too large to decode within the limit",
        })
    }
}

impl std::error::Error for Error {}

/// Most bytes a decoded image may take: the `image` crate's default, which
/// ClamAV decodes with.
pub const DECODE_MAX: u64 = 512 * 1024 * 1024;

/// Which channels each pixel has, in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channels {
    Luma,
    LumaAlpha,
    Rgb,
    Rgba,
}

impl Channels {
    pub fn count(self) -> usize {
        match self {
            Channels::Luma => 1,
            Channels::LumaAlpha => 2,
            Channels::Rgb => 3,
            Channels::Rgba => 4,
        }
    }
}

/// The samples, row-major, `channels.count()` per pixel.
#[derive(Clone, Debug, PartialEq)]
pub enum Samples {
    U8(Vec<u8>),
    U16(Vec<u16>),
    F32(Vec<f32>),
}

/// A decoded image, as the decoder produced it.
#[derive(Clone, Debug, PartialEq)]
pub struct Pixels {
    pub width: u32,
    pub height: u32,
    pub channels: Channels,
    pub samples: Samples,
}

impl Pixels {
    /// 8-bit RGBA, row-major, as the `image` crate converts: 16-bit samples
    /// scaled, floats clamped to `0..=1`.
    pub fn to_rgba8(&self) -> Vec<u8> {
        match (&self.channels, &self.samples) {
            (Channels::Rgba, Samples::U8(v)) => v.clone(),
            _ => self.clone().into_dynamic().to_rgba8().into_raw(),
        }
    }

    fn from_dynamic(img: DynamicImage) -> Pixels {
        let (width, height) = (img.width(), img.height());
        let (channels, samples) = match img {
            DynamicImage::ImageLuma8(i) => (Channels::Luma, Samples::U8(i.into_raw())),
            DynamicImage::ImageLumaA8(i) => (Channels::LumaAlpha, Samples::U8(i.into_raw())),
            DynamicImage::ImageRgb8(i) => (Channels::Rgb, Samples::U8(i.into_raw())),
            DynamicImage::ImageRgba8(i) => (Channels::Rgba, Samples::U8(i.into_raw())),
            DynamicImage::ImageLuma16(i) => (Channels::Luma, Samples::U16(i.into_raw())),
            DynamicImage::ImageLumaA16(i) => (Channels::LumaAlpha, Samples::U16(i.into_raw())),
            DynamicImage::ImageRgb16(i) => (Channels::Rgb, Samples::U16(i.into_raw())),
            DynamicImage::ImageRgba16(i) => (Channels::Rgba, Samples::U16(i.into_raw())),
            DynamicImage::ImageRgb32F(i) => (Channels::Rgb, Samples::F32(i.into_raw())),
            DynamicImage::ImageRgba32F(i) => (Channels::Rgba, Samples::F32(i.into_raw())),
            // `DynamicImage` is non-exhaustive: a layout added later arrives
            // as 32-bit float RGBA, which loses nothing.
            other => (Channels::Rgba, Samples::F32(other.to_rgba32f().into_raw())),
        };
        Pixels {
            width,
            height,
            channels,
            samples,
        }
    }

    fn into_dynamic(self) -> DynamicImage {
        let (w, h) = (self.width, self.height);
        const SIZED: &str = "a buffer built by `from_dynamic` has its own size";
        match (self.channels, self.samples) {
            (Channels::Luma, Samples::U8(v)) => {
                DynamicImage::ImageLuma8(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::LumaAlpha, Samples::U8(v)) => {
                DynamicImage::ImageLumaA8(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::Rgb, Samples::U8(v)) => {
                DynamicImage::ImageRgb8(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::Rgba, Samples::U8(v)) => {
                DynamicImage::ImageRgba8(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::Luma, Samples::U16(v)) => {
                DynamicImage::ImageLuma16(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::LumaAlpha, Samples::U16(v)) => {
                DynamicImage::ImageLumaA16(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::Rgb, Samples::U16(v)) => {
                DynamicImage::ImageRgb16(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::Rgba, Samples::U16(v)) => {
                DynamicImage::ImageRgba16(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::Rgb, Samples::F32(v)) => {
                DynamicImage::ImageRgb32F(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            (Channels::Rgba, Samples::F32(v)) => {
                DynamicImage::ImageRgba32F(ImageBuffer::from_raw(w, h, v).expect(SIZED))
            }
            // Grey floats: no `DynamicImage` holds them, and no decoder here
            // produces them.
            (c, Samples::F32(v)) => {
                let n = c.count();
                let rgba = v
                    .chunks_exact(n)
                    .flat_map(|p| [p[0], p[0], p[0], if n == 2 { p[1] } else { 1.0 }])
                    .collect();
                DynamicImage::ImageRgba32F(ImageBuffer::from_raw(w, h, rgba).expect(SIZED))
            }
        }
    }
}

/// Decode `data` as `format`, within `max_alloc` bytes of pixels (at most
/// [`DECODE_MAX`]). A decoder panic is caught and reported
/// [`Error::Undecodable`].
pub fn decode(data: &[u8], format: Format, max_alloc: u64) -> Result<Pixels, Error> {
    std::panic::catch_unwind(|| match format {
        #[cfg(feature = "jp2")]
        Format::Jpeg2000 => jp2::decode(data, max_alloc),
        #[cfg(feature = "jbig2")]
        Format::Jbig2 => jbig2::decode(data, max_alloc),
        _ => decode_dynamic(data, format, max_alloc).map(Pixels::from_dynamic),
    })
    .unwrap_or(Err(Error::Undecodable))
}

/// Refuses a decode that needs more than `max_alloc` bytes (at most
/// [`DECODE_MAX`]), as the `image` crate's limit does.
#[cfg(any(feature = "jp2", feature = "jbig2"))]
fn within(needed: u64, max_alloc: u64) -> Result<(), Error> {
    let limit = max_alloc.min(DECODE_MAX);
    if needed <= limit {
        Ok(())
    } else if limit < DECODE_MAX {
        Err(Error::TooLarge)
    } else {
        Err(Error::Undecodable)
    }
}

/// CMYK (or CMYKA) bytes to RGB (or RGBA): `255 - min(255, C + K)` and the
/// same for M and Y, as PDF's DeviceCMYK to DeviceRGB.
#[cfg(feature = "jp2")]
fn cmyk_to_rgb(cmyk: &[u8], alpha: bool) -> Vec<u8> {
    let n = if alpha { 5 } else { 4 };
    let mut out = Vec::with_capacity(cmyk.len() / n * (n - 1));
    for p in cmyk.chunks_exact(n) {
        let k = u16::from(p[3]);
        out.extend(
            p[..3]
                .iter()
                .map(|&c| 255 - (u16::from(c) + k).min(255) as u8),
        );
        if alpha {
            out.push(p[4]);
        }
    }
    out
}

/// [`decode`], the format read from the first bytes.
pub fn decode_any(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    decode(
        data,
        Format::detect(data).ok_or(Error::Unsupported)?,
        max_alloc,
    )
}

fn decode_dynamic(data: &[u8], format: Format, max_alloc: u64) -> Result<DynamicImage, Error> {
    let limit = max_alloc.min(DECODE_MAX);
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(limit);
    // JPEG and TIFF go through `image`'s own decoders, built without SIMD
    // (`image_codecs`); the rest through `image`.
    let decoded = match format {
        Format::Jpeg => {
            image_codecs::jpeg::JpegDecoder::new(data).and_then(|d| image_codecs::decode(d, limits))
        }
        Format::Tiff => image_codecs::tiff_image::TiffDecoder::new(std::io::Cursor::new(data))
            .and_then(|d| image_codecs::decode(d, limits)),
        other => {
            let mut reader = image::ImageReader::with_format(
                std::io::Cursor::new(data),
                image_format(other).ok_or(Error::Unsupported)?,
            );
            reader.limits(limits);
            reader.decode()
        }
    };
    decoded.map_err(|e| match e {
        image::ImageError::Limits(_) if limit < DECODE_MAX => Error::TooLarge,
        _ => Error::Undecodable,
    })
}

fn image_format(f: Format) -> Option<ImageFormat> {
    Some(match f {
        Format::Png => ImageFormat::Png,
        Format::Gif => ImageFormat::Gif,
        Format::Bmp => ImageFormat::Bmp,
        #[cfg(feature = "webp")]
        Format::Webp => ImageFormat::WebP,
        #[cfg(feature = "ico")]
        Format::Ico => ImageFormat::Ico,
        #[cfg(feature = "pnm")]
        Format::Pnm => ImageFormat::Pnm,
        #[cfg(feature = "qoi")]
        Format::Qoi => ImageFormat::Qoi,
        #[cfg(feature = "dds")]
        Format::Dds => ImageFormat::Dds,
        #[cfg(feature = "ff")]
        Format::Farbfeld => ImageFormat::Farbfeld,
        #[cfg(feature = "hdr")]
        Format::Hdr => ImageFormat::Hdr,
        Format::Jpeg | Format::Tiff => return None,
        #[cfg(feature = "jp2")]
        Format::Jpeg2000 => return None,
        #[cfg(feature = "jbig2")]
        Format::Jbig2 => return None,
    })
}

#[cfg(feature = "jbig2")]
mod jbig2;
#[cfg(feature = "jp2")]
mod jp2;
#[cfg(test)]
mod tests;
