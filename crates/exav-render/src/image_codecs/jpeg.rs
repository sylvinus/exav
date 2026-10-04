//! `image` 0.25.9's JPEG decoder (`src/codecs/jpeg/decoder.rs`), over
//! zune-jpeg 0.5.8 built without its SIMD code: see `README.md`. Only what
//! decoding uses is kept, and the input is borrowed where upstream copies it.

use image::error::{
    DecodingError, ImageError, ImageResult, LimitError, LimitErrorKind, UnsupportedError,
    UnsupportedErrorKind,
};
use image::{ColorType, ImageDecoder, ImageFormat, LimitSupport, Limits};
use zune_core::bytestream::ZCursor;

type ZuneColorSpace = zune_core::colorspace::ColorSpace;

pub(crate) struct JpegDecoder<'a> {
    input: &'a [u8],
    orig_color_space: ZuneColorSpace,
    width: u16,
    height: u16,
    limits: Limits,
}

impl<'a> JpegDecoder<'a> {
    pub(crate) fn new(input: &'a [u8]) -> ImageResult<JpegDecoder<'a>> {
        let options = zune_core::options::DecoderOptions::default()
            .set_strict_mode(false)
            .set_max_width(usize::MAX)
            .set_max_height(usize::MAX);
        let mut decoder = zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(input), options);
        decoder.decode_headers().map_err(from_jpeg)?;
        let (width, height) = decoder.dimensions().unwrap();
        let width: u16 = width.try_into().unwrap();
        let height: u16 = height.try_into().unwrap();
        let orig_color_space = decoder.input_colorspace().expect("headers were decoded");
        // Upstream also sets the output colour space on this decoder, which is
        // then dropped: `read_image` decodes with a decoder of its own.
        Ok(JpegDecoder {
            input,
            orig_color_space,
            width,
            height,
            limits: Limits::no_limits(),
        })
    }
}

impl ImageDecoder for JpegDecoder<'_> {
    fn dimensions(&self) -> (u32, u32) {
        (u32::from(self.width), u32::from(self.height))
    }

    fn color_type(&self) -> ColorType {
        color_type_from_jpeg(self.orig_color_space)
    }

    fn read_image(self, buf: &mut [u8]) -> ImageResult<()> {
        let advertised_len = self.total_bytes();
        let actual_len = buf.len() as u64;

        if actual_len != advertised_len {
            return Err(ImageError::Decoding(DecodingError::new(
                ImageFormat::Jpeg.into(),
                format!(
                    "Length of the decoded data {actual_len} \
                    doesn't match the advertised dimensions of the image \
                    that imply length {advertised_len}"
                ),
            )));
        }

        let mut decoder = new_zune_decoder(self.input, self.orig_color_space, self.limits);
        decoder.decode_into(buf).map_err(from_jpeg)?;
        Ok(())
    }

    fn set_limits(&mut self, limits: Limits) -> ImageResult<()> {
        limits.check_support(&LimitSupport::default())?;
        let (width, height) = self.dimensions();
        limits.check_dimensions(width, height)?;
        self.limits = limits;
        Ok(())
    }

    fn read_image_boxed(self: Box<Self>, buf: &mut [u8]) -> ImageResult<()> {
        (*self).read_image(buf)
    }
}

fn color_type_from_jpeg(colorspace: ZuneColorSpace) -> ColorType {
    let colorspace = to_supported_color_space(colorspace);
    use zune_core::colorspace::ColorSpace::*;
    match colorspace {
        // As of zune-jpeg 0.3.13 the output is always 8-bit,
        // but support for 16-bit JPEG might be added in the future.
        RGB => ColorType::Rgb8,
        RGBA => ColorType::Rgba8,
        Luma => ColorType::L8,
        LumaA => ColorType::La8,
        // to_supported_color_space() doesn't return any of the other variants
        _ => unreachable!(),
    }
}

fn to_supported_color_space(orig: ZuneColorSpace) -> ZuneColorSpace {
    use zune_core::colorspace::ColorSpace::*;
    match orig {
        RGB | RGBA | Luma | LumaA => orig,
        // the rest is not supported by `image` so it will be converted to RGB during decoding
        _ => RGB,
    }
}

fn new_zune_decoder(
    input: &[u8],
    orig_color_space: ZuneColorSpace,
    limits: Limits,
) -> zune_jpeg::JpegDecoder<ZCursor<&[u8]>> {
    let target_color_space = to_supported_color_space(orig_color_space);
    let mut options = zune_core::options::DecoderOptions::default()
        .jpeg_set_out_colorspace(target_color_space)
        .set_strict_mode(false);
    options = options.set_max_width(match limits.max_image_width {
        Some(max_width) => max_width as usize, // u32 to usize never truncates
        None => usize::MAX,
    });
    options = options.set_max_height(match limits.max_image_height {
        Some(max_height) => max_height as usize, // u32 to usize never truncates
        None => usize::MAX,
    });
    zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(input), options)
}

fn from_jpeg(err: zune_jpeg::errors::DecodeErrors) -> ImageError {
    use zune_jpeg::errors::DecodeErrors::*;
    match err {
        Unsupported(desc) => ImageError::Unsupported(UnsupportedError::from_format_and_kind(
            ImageFormat::Jpeg.into(),
            UnsupportedErrorKind::GenericFeature(format!("{desc:?}")),
        )),
        LargeDimensions(_) => {
            ImageError::Limits(LimitError::from_kind(LimitErrorKind::DimensionError))
        }
        err => ImageError::Decoding(DecodingError::new(ImageFormat::Jpeg.into(), err)),
    }
}
