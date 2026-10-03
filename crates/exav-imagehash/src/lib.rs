//! Perceptual image hashes: a DCT hash of an image's luminance, the kind
//! called "pHash", with every step that tells one implementation from another
//! a parameter, and two settings of those steps that reproduce existing tools:
//!
//! - [`Preset::ClamAv`]: the hash ClamAV matches `fuzzy_img#` signatures
//!   against, equal to `sigtool --fuzzy-img` from ClamAV 1.4.6 and 1.5.4;
//! - [`Preset::ImagehashPhash`]: Python `imagehash.phash(Image.open(f))` with
//!   its default arguments, equal wherever this crate's decoders give Pillow's
//!   pixels: not on every JPEG, which Pillow decodes with libjpeg-turbo (the
//!   README has the details).
//!
//! The pipeline: decode, convert to grey ([`Grey`]), resize to a square of
//! `hash_size × highfreq_factor` pixels ([`Resize`]), take a 2-D DCT-II in
//! [`Precision`], keep the top-left `hash_size × hash_size` block (or the one
//! next to it, without the DC term), and set each bit where its coefficient
//! is above the block's median or mean ([`Threshold`]). The bits are read row
//! by row, the first the most significant, as both tools print them.
//!
//! ```no_run
//! use exav_imagehash::{Hasher, Params, Preset};
//!
//! let bytes = std::fs::read("logo.png").unwrap();
//! let clamav = Hasher::new(Preset::ClamAv).hash(&bytes).unwrap();
//! println!("{clamav}"); // 16 hex digits, as `sigtool --fuzzy-img` prints
//!
//! let p = Params { hash_size: 16, ..Params::IMAGEHASH_PHASH };
//! let big = Hasher::with_params(p).unwrap().hash(&bytes).unwrap();
//! assert_eq!(big.bits().len(), 256);
//! ```

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

use image::{imageops::FilterType, DynamicImage, GrayImage, ImageFormat};

mod image_codecs;
mod pillow;

pub use pillow::PillowFilter;

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
        None
    }

    /// Lower-case name, as the CLI takes it.
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
        }
    }

    fn bit(self) -> u16 {
        1 << Format::ALL.iter().position(|f| *f == self).unwrap_or(0)
    }
}

/// A set of formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Formats(u16);

impl Formats {
    pub const NONE: Formats = Formats(0);

    /// What clamscan treats as graphics (`Target:5`), and so the only images
    /// it hashes while scanning: PNG, GIF, JPEG, TIFF and BMP. `sigtool
    /// --fuzzy-img` decodes more.
    pub const CLAMAV_GRAPHICS: Formats = Formats(0b1_1111);

    /// Every format this build decodes.
    pub const ALL: Formats = Formats(u16::MAX);

    /// Every format this build decodes.
    pub fn all() -> Formats {
        Formats::ALL
    }

    pub fn contains(self, f: Format) -> bool {
        self.0 & f.bit() != 0
    }

    pub fn with(self, f: Format) -> Formats {
        Formats(self.0 | f.bit())
    }

    pub fn iter(self) -> impl Iterator<Item = Format> {
        Format::ALL
            .iter()
            .copied()
            .filter(move |f| self.contains(*f))
    }
}

/// How the decoded image becomes grey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Grey {
    /// To 8-bit RGB as the `image` crate converts, then
    /// `0.299 R + 0.587 G + 0.114 B` in `f32`, rounded half away from zero:
    /// ClamAV's.
    Bt601Float,
    /// Pillow's `convert("L")` from the mode Pillow decodes the file to: the
    /// same weights in 16-bit fixed point, 16-bit grey saturating at 255,
    /// 16-bit colour through its high byte (a PPM's scaled to 8 bits, as
    /// Pillow reads one): imagehash's.
    Pillow,
}

/// How the grey image is resized to the DCT's square.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resize {
    /// The `image` crate's Lanczos (3 lobes): ClamAV's.
    Lanczos3,
    /// The `image` crate's Catmull-Rom.
    CatmullRom,
    /// The `image` crate's Gaussian.
    Gaussian,
    /// The `image` crate's bilinear.
    Triangle,
    /// The `image` crate's nearest neighbour.
    Nearest,
    /// Pillow's `Image.resize` with this filter; `PillowFilter::Lanczos` is
    /// imagehash's.
    Pillow(PillowFilter),
}

/// The arithmetic of the DCT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Precision {
    /// Pixels as `value / 255` in `f32`: ClamAV's.
    F32,
    /// Pixels as `0..=255` in `f64`, as `scipy.fftpack.dct` takes them:
    /// imagehash's.
    F64,
}

/// What each coefficient is compared with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Threshold {
    /// The block's median (the mean of the two middle values when even).
    Median,
    /// The block's mean.
    Mean,
}

/// Every step of the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Bits per side: the hash has `hash_size²` bits.
    pub hash_size: u32,
    /// The DCT is `hash_size × highfreq_factor` square.
    pub highfreq_factor: u32,
    pub grey: Grey,
    pub resize: Resize,
    pub precision: Precision,
    pub threshold: Threshold,
    /// Keep the DC term: the block is the top-left one. Without it, the block
    /// starts one row and one column in.
    pub keep_dc: bool,
    /// The formats hashed; any other file is [`Error::Unsupported`].
    pub formats: Formats,
    /// The most a decoded image may take, capped at 512 MiB (the `image`
    /// crate's default, which ClamAV decodes with).
    pub max_decode_bytes: u64,
}

/// Most bytes a decoded image may take.
pub const DECODE_MAX: u64 = 512 * 1024 * 1024;

/// Largest DCT side the parameters may ask for.
const MAX_SIDE: u32 = 4096;

impl Params {
    /// ClamAV's `fuzzy_img` hash, on every format this build decodes, as
    /// `sigtool --fuzzy-img` hashes them. A scan that does what clamscan does
    /// limits `formats` to [`Formats::CLAMAV_GRAPHICS`].
    pub const CLAMAV: Params = Params {
        hash_size: 8,
        highfreq_factor: 4,
        grey: Grey::Bt601Float,
        resize: Resize::Lanczos3,
        precision: Precision::F32,
        threshold: Threshold::Median,
        keep_dc: true,
        formats: Formats::ALL,
        max_decode_bytes: DECODE_MAX,
    };

    /// Python `imagehash.phash` with its defaults, on every format this build
    /// decodes.
    pub const IMAGEHASH_PHASH: Params = Params {
        hash_size: 8,
        highfreq_factor: 4,
        grey: Grey::Pillow,
        resize: Resize::Pillow(PillowFilter::Lanczos),
        precision: Precision::F64,
        threshold: Threshold::Median,
        keep_dc: true,
        formats: Formats::ALL,
        max_decode_bytes: DECODE_MAX,
    };

    fn side(&self) -> u32 {
        self.hash_size * self.highfreq_factor
    }

    fn check(&self) -> Result<(), Error> {
        if self.hash_size < 2 {
            return Err(Error::InvalidParams("hash size must be at least 2"));
        }
        if self.highfreq_factor < 1 {
            return Err(Error::InvalidParams("highfreq factor must be at least 1"));
        }
        let side = self.hash_size.checked_mul(self.highfreq_factor);
        if side.is_none_or(|s| s > MAX_SIDE) {
            return Err(Error::InvalidParams(
                "hash size × highfreq factor is over 4096",
            ));
        }
        if !self.keep_dc && self.highfreq_factor < 2 {
            return Err(Error::InvalidParams(
                "without the DC term the highfreq factor must be at least 2",
            ));
        }
        Ok(())
    }
}

/// A named setting of [`Params`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Preset {
    /// [`Params::CLAMAV`].
    ClamAv,
    /// [`Params::IMAGEHASH_PHASH`].
    ImagehashPhash,
}

impl Preset {
    pub fn params(self) -> Params {
        match self {
            Preset::ClamAv => Params::CLAMAV,
            Preset::ImagehashPhash => Params::IMAGEHASH_PHASH,
        }
    }
}

/// Why an image has no hash.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Not one of the formats asked for.
    Unsupported,
    /// A corrupt image, one the decoders do not read, or one past 512 MiB
    /// decoded.
    Undecodable,
    /// Decoding it takes more than `max_decode_bytes`, under 512 MiB.
    TooLarge,
    InvalidParams(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported => f.write_str("not an image of the formats asked for"),
            Error::Undecodable => f.write_str("undecodable image"),
            Error::TooLarge => f.write_str("image too large to decode within the limit"),
            Error::InvalidParams(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

/// A hash: `hash_size²` bits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ImageHash {
    bits: Vec<bool>,
}

impl ImageHash {
    pub fn bits(&self) -> &[bool] {
        &self.bits
    }

    /// The bits as a big-endian number, as [`fmt::Display`] prints it in hex.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pad = (8 - self.bits.len() % 8) % 8;
        let padded: Vec<bool> = std::iter::repeat_n(false, pad)
            .chain(self.bits.iter().copied())
            .collect();
        padded
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |b, &bit| (b << 1) | u8::from(bit)))
            .collect()
    }

    /// The number of bits that differ, or `None` between hashes of different
    /// sizes.
    pub fn distance(&self, other: &ImageHash) -> Option<u32> {
        (self.bits.len() == other.bits.len()).then(|| {
            self.bits
                .iter()
                .zip(&other.bits)
                .filter(|(a, b)| a != b)
                .count() as u32
        })
    }
}

/// Hex, `ceil(bits / 4)` digits: imagehash's `str(hash)`, and for 64 bits
/// `sigtool --fuzzy-img`'s.
impl fmt::Display for ImageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pad = (4 - self.bits.len() % 4) % 4;
        let padded: Vec<bool> = std::iter::repeat_n(false, pad)
            .chain(self.bits.iter().copied())
            .collect();
        for nibble in padded.chunks(4) {
            let v = nibble.iter().fold(0u32, |n, &b| (n << 1) | u32::from(b));
            write!(f, "{v:x}")?;
        }
        Ok(())
    }
}

/// From hex: 4 bits per digit.
impl FromStr for ImageHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<ImageHash, Error> {
        let mut bits = Vec::with_capacity(s.len() * 4);
        for c in s.chars() {
            let v = c
                .to_digit(16)
                .ok_or(Error::InvalidParams("not a hex hash"))?;
            bits.extend((0..4).rev().map(|i| v >> i & 1 == 1));
        }
        if bits.is_empty() {
            return Err(Error::InvalidParams("not a hex hash"));
        }
        Ok(ImageHash { bits })
    }
}

/// Computes hashes with one set of [`Params`].
#[derive(Clone, Debug)]
pub struct Hasher {
    params: Params,
}

impl Hasher {
    pub fn new(preset: Preset) -> Hasher {
        Hasher {
            params: preset.params(),
        }
    }

    pub fn with_params(params: Params) -> Result<Hasher, Error> {
        params.check()?;
        Ok(Hasher { params })
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    /// The hash of an encoded image, its format recognised from its first
    /// bytes. A decoder panicking on a crafted file is caught and reported
    /// [`Error::Undecodable`].
    pub fn hash(&self, data: &[u8]) -> Result<ImageHash, Error> {
        let format = Format::detect(data)
            .filter(|f| self.params.formats.contains(*f))
            .ok_or(Error::Unsupported)?;
        let gray = std::panic::catch_unwind(|| {
            let img = decode(data, format, self.params.max_decode_bytes)?;
            if img.width() == 0 || img.height() == 0 {
                return Err(Error::Undecodable);
            }
            Ok(match self.params.grey {
                Grey::Bt601Float => gray_bt601(img),
                Grey::Pillow => gray_pillow(img, format),
            })
        })
        .unwrap_or(Err(Error::Undecodable))?;
        Ok(self.hash_gray_image(gray))
    }

    /// The hash of 8-bit RGB pixels, row-major.
    pub fn hash_rgb8(&self, width: u32, height: u32, rgb: &[u8]) -> Result<ImageHash, Error> {
        self.hash_pixels(width, height, rgb, 3)
    }

    /// The hash of 8-bit RGBA pixels, row-major; alpha is ignored.
    pub fn hash_rgba8(&self, width: u32, height: u32, rgba: &[u8]) -> Result<ImageHash, Error> {
        self.hash_pixels(width, height, rgba, 4)
    }

    /// The hash of 8-bit grey pixels, row-major: only the resize and the DCT
    /// apply.
    pub fn hash_gray(&self, width: u32, height: u32, gray: &[u8]) -> Result<ImageHash, Error> {
        let img = GrayImage::from_raw(width, height, gray.to_vec())
            .filter(|_| width > 0 && height > 0)
            .ok_or(Error::InvalidParams(
                "pixel count does not match the dimensions",
            ))?;
        Ok(self.hash_gray_image(img))
    }

    fn hash_pixels(&self, w: u32, h: u32, px: &[u8], n: usize) -> Result<ImageHash, Error> {
        if w == 0 || h == 0 || px.len() != w as usize * h as usize * n {
            return Err(Error::InvalidParams(
                "pixel count does not match the dimensions",
            ));
        }
        let luma = match self.params.grey {
            Grey::Bt601Float => luma_bt601,
            Grey::Pillow => pillow::l24,
        };
        let gray = px.chunks_exact(n).map(|p| luma(p[0], p[1], p[2])).collect();
        Ok(self.hash_gray_image(GrayImage::from_raw(w, h, gray).expect("one byte per pixel")))
    }

    fn hash_gray_image(&self, gray: GrayImage) -> ImageHash {
        let p = &self.params;
        let side = p.side();
        let small = resize(gray, side, p.resize);
        let n = side as usize;
        let block = match p.precision {
            Precision::F32 => {
                let mut v: Vec<f32> = small.iter().map(|&x| x as f32 / 255.0).collect();
                dct2d(&mut v, n);
                low_block(&v, n, p)
                    .iter()
                    .map(|&x| f64::from(x))
                    .collect::<Vec<_>>()
            }
            Precision::F64 => {
                let mut v: Vec<f64> = small.iter().map(|&x| f64::from(x)).collect();
                dct2d(&mut v, n);
                low_block(&v, n, p)
            }
        };
        let bits = match (p.threshold, p.precision) {
            // In `f32` the median is taken in `f32`, as ClamAV does.
            (Threshold::Median, Precision::F32) => {
                let b: Vec<f32> = block.iter().map(|&x| x as f32).collect();
                let m = median(&b);
                b.iter().map(|&x| x > m).collect()
            }
            (Threshold::Median, Precision::F64) => {
                let m = median(&block);
                block.iter().map(|&x| x > m).collect()
            }
            (Threshold::Mean, _) => {
                let m = block.iter().sum::<f64>() / block.len() as f64;
                block.iter().map(|&x| x > m).collect()
            }
        };
        ImageHash { bits }
    }
}

/// The hash block, row-major.
fn low_block<T: Copy>(v: &[T], n: usize, p: &Params) -> Vec<T> {
    let off = usize::from(!p.keep_dc);
    let h = p.hash_size as usize;
    (off..off + h)
        .flat_map(|r| v[r * n + off..r * n + off + h].iter().copied())
        .collect()
}

fn median<
    T: Copy + PartialOrd + std::ops::Add<Output = T> + std::ops::Div<Output = T> + From<u8>,
>(
    v: &[T],
) -> T {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = s.len() / 2;
    if s.len().is_multiple_of(2) {
        (s[mid - 1] + s[mid]) / T::from(2)
    } else {
        s[mid]
    }
}

/// In-place 2-D DCT-II of an `n × n` row-major buffer: the columns, then the
/// rows, each pass scaled by 2 (`scipy.fftpack.dct`'s unnormalised scale).
fn dct2d<T: rustdct::DctNum>(buf: &mut [T], n: usize) {
    let dct = rustdct::DctPlanner::new().plan_dct2(n);
    let two = T::from_f64(2.0).expect("2 is representable");
    let mut scratch = vec![T::zero(); n * n];
    transpose::transpose(buf, &mut scratch, n, n);
    for row in scratch.chunks_mut(n) {
        dct.process_dct2(row);
        for v in row {
            *v = *v * two;
        }
    }
    transpose::transpose(&scratch, buf, n, n);
    for row in buf.chunks_mut(n) {
        dct.process_dct2(row);
        for v in row {
            *v = *v * two;
        }
    }
}

fn resize(gray: GrayImage, side: u32, how: Resize) -> Vec<u8> {
    let filter = match how {
        Resize::Pillow(f) => {
            let (w, h) = (gray.width() as usize, gray.height() as usize);
            let g = pillow::Gray {
                width: w,
                height: h,
                pixels: gray.into_raw(),
            };
            return pillow::resize(&g, side as usize, side as usize, f).pixels;
        }
        Resize::Lanczos3 => FilterType::Lanczos3,
        Resize::CatmullRom => FilterType::CatmullRom,
        Resize::Gaussian => FilterType::Gaussian,
        Resize::Triangle => FilterType::Triangle,
        Resize::Nearest => FilterType::Nearest,
    };
    DynamicImage::ImageLuma8(gray)
        .resize_exact(side, side, filter)
        .into_luma8()
        .into_raw()
}

/// Decode, within `max_alloc` bytes of pixels (at most [`DECODE_MAX`]).
fn decode(data: &[u8], format: Format, max_alloc: u64) -> Result<DynamicImage, Error> {
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
    })
}

/// BT.601 luma, rounded half away from zero: not the `image` crate's
/// grayscale, which uses other coefficients.
fn luma_bt601(r: u8, g: u8, b: u8) -> u8 {
    (0.299_f32 * r as f32 + 0.587_f32 * g as f32 + 0.114_f32 * b as f32).round() as u8
}

/// Largest strip of a non-RGB8 image converted to RGB8 at once.
const STRIP_BYTES: usize = 1024 * 1024;

/// [`Grey::Bt601Float`] without a second full-size copy: an RGB8 image is
/// turned grey in place, any other converted to RGB8 a strip of rows at a
/// time.
fn gray_bt601(img: DynamicImage) -> GrayImage {
    let (w, h) = (img.width(), img.height());
    let pixels = w as usize * h as usize;
    let other = match img {
        DynamicImage::ImageRgb8(rgb) => {
            let mut v = rgb.into_raw();
            // Pixel `i` is written at `i` once read from `3 * i`, never ahead
            // of what is still to be read.
            for i in 0..pixels {
                v[i] = luma_bt601(v[3 * i], v[3 * i + 1], v[3 * i + 2]);
            }
            v.truncate(pixels);
            v.shrink_to_fit();
            return GrayImage::from_raw(w, h, v).expect("one byte per pixel");
        }
        other => other,
    };
    // Converting to RGB8 goes pixel by pixel and does not depend on the colour
    // space (only a conversion to luma does), so a strip converts as it would
    // within the whole image.
    let row = w as usize * usize::from(other.color().bytes_per_pixel());
    let rows = (STRIP_BYTES / row.max(1)).max(1) as u32;
    let mut out = Vec::with_capacity(pixels);
    let mut y = 0;
    while y < h {
        let n = rows.min(h - y);
        let strip = other.crop_imm(0, y, w, n).to_rgb8();
        out.extend(strip.pixels().map(|p| luma_bt601(p[0], p[1], p[2])));
        y += n;
    }
    GrayImage::from_raw(w, h, out).expect("one byte per pixel")
}

/// [`Grey::Pillow`]: what Pillow's `convert("L")` gives from the mode its
/// decoder opens such a file as. 8-bit grey (`L`, and `1` as 0 and 255) is
/// kept, alpha is dropped (`la2l`), colour goes through `rgb2l` (a palette's
/// entries too, `p2l`), 16-bit grey (`I;16`) saturates at 255 (`I16L_L`), and
/// 16-bit colour or grey with alpha is unpacked to its high byte first
/// (`RGB;16B`, `LA;16B`), except from a PPM, whose samples Pillow scales as
/// `round(v / maxval * 255)`. Float images have no Pillow decoder to follow;
/// they go through the `image` crate's conversion to 8-bit RGB.
fn gray_pillow(img: DynamicImage, format: Format) -> GrayImage {
    #[cfg(feature = "pnm")]
    let ppm = format == Format::Pnm;
    #[cfg(not(feature = "pnm"))]
    let ppm = {
        let _ = format;
        false
    };
    // `PpmDecoder`: in `f64`, Python's round half to even. The `image` crate
    // gives a 16-bit PPM's samples as they are, so this is right for a maxval
    // of 65535; another maxval it has already rescaled.
    let ppm16 = |v: u16| (f64::from(v) / 65535.0 * 255.0).round_ties_even() as u8;
    let (w, h) = (img.width(), img.height());
    let v: Vec<u8> = match img {
        DynamicImage::ImageLuma8(i) => return i,
        DynamicImage::ImageLumaA8(i) => {
            i.as_raw().as_chunks::<2>().0.iter().map(|p| p[0]).collect()
        }
        DynamicImage::ImageRgb8(i) => {
            let mut v = i.into_raw();
            let n = v.len() / 3;
            for k in 0..n {
                v[k] = pillow::l24(v[3 * k], v[3 * k + 1], v[3 * k + 2]);
            }
            v.truncate(n);
            v.shrink_to_fit();
            v
        }
        DynamicImage::ImageRgba8(i) => i
            .as_raw()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|p| pillow::l24(p[0], p[1], p[2]))
            .collect(),
        DynamicImage::ImageLuma16(i) => i.as_raw().iter().map(|&v| v.min(255) as u8).collect(),
        DynamicImage::ImageLumaA16(i) => i
            .as_raw()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| (p[0] >> 8) as u8)
            .collect(),
        DynamicImage::ImageRgb16(i) if ppm => i
            .as_raw()
            .as_chunks::<3>()
            .0
            .iter()
            .map(|p| pillow::l24(ppm16(p[0]), ppm16(p[1]), ppm16(p[2])))
            .collect(),
        DynamicImage::ImageRgb16(i) => i
            .as_raw()
            .as_chunks::<3>()
            .0
            .iter()
            .map(|p| pillow::l24((p[0] >> 8) as u8, (p[1] >> 8) as u8, (p[2] >> 8) as u8))
            .collect(),
        DynamicImage::ImageRgba16(i) => i
            .as_raw()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|p| pillow::l24((p[0] >> 8) as u8, (p[1] >> 8) as u8, (p[2] >> 8) as u8))
            .collect(),
        other => other
            .to_rgb8()
            .pixels()
            .map(|p| pillow::l24(p[0], p[1], p[2]))
            .collect(),
    };
    GrayImage::from_raw(w, h, v).expect("one byte per pixel")
}

#[cfg(test)]
mod tests;
