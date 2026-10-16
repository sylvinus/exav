//! JPEG XL through zenjxl-decoder: the first frame, as 8-bit samples (grey with
//! alpha, or RGBA), in the colour space the file's own profile names
//! converted to sRGB by the decoder.

use zenjxl_decoder::api::{decode_with, Error as JxlError, JxlDecoderLimits, JxlDecoderOptions};

use super::{Channels, Error, Pixels, Samples, DECODE_MAX};

/// Most pixels of one image, whatever the memory: the decode costs time per
/// pixel (about 20 Mpx a second in a browser).
const MAX_PIXELS: u64 = 1 << 27;

pub(super) fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let limit = max_alloc.min(DECODE_MAX);
    let mut limits = JxlDecoderLimits::restrictive();
    // The decoder tracks what it allocates against this budget. The result
    // is 8 bits a sample and four samples a pixel at most.
    limits.max_memory_bytes = Some(limit);
    limits.max_pixels = Some((limit / 4).min(MAX_PIXELS) as usize);
    let mut options = JxlDecoderOptions::default();
    options.limits = limits;
    let image = decode_with(data, options).map_err(|e| match e {
        JxlError::LimitExceeded { .. } if limit < DECODE_MAX => Error::TooLarge,
        _ => Error::Undecodable,
    })?;
    let (width, height) = (
        u32::try_from(image.width).map_err(|_| Error::Undecodable)?,
        u32::try_from(image.height).map_err(|_| Error::Undecodable)?,
    );
    let channels = if image.is_grayscale {
        Channels::LumaAlpha
    } else {
        Channels::Rgba
    };
    if image.channels != channels.count()
        || image.data.len() as u64 != u64::from(width) * u64::from(height) * channels.count() as u64
    {
        return Err(Error::Undecodable);
    }
    Ok(Pixels {
        width,
        height,
        channels,
        samples: Samples::U8(image.data),
    })
}
