//! JPEG XL through zenjxl-decoder: the first frame, as 8-bit samples (grey with
//! alpha, or RGBA), in the colour space the file's own profile names
//! converted to sRGB by the decoder.

use zenjxl_decoder::api::{Error as JxlError, JxlDecoderLimits, JxlDecoderOptions, decode_with};

use super::{Channels, DECODE_MAX, Error, Pixels, Samples};

/// Most pixels of one image, whatever the memory: the decode costs time per
/// pixel (about 20 Mpx a second in a browser).
const MAX_PIXELS: u64 = 1 << 27;

/// What the decoder holds for a pixel while it works: the colour as three
/// floats, each extra channel as one, and the 8-bit result. Its own memory
/// budget does not see all of it, so the pixel count is what holds it: a file
/// that declares the most pixels the budget allows, and the most channels,
/// takes this much of each.
const BYTES_PER_PIXEL: u64 = 12 + 4 * MAX_EXTRA_CHANNELS as u64 + 4;

/// Extra channels beyond what is drawn: the alpha, and one more. A file with
/// more is refused as too large, and each costs a float a pixel.
const MAX_EXTRA_CHANNELS: usize = 2;

pub(super) fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let limit = max_alloc.min(DECODE_MAX);
    let mut limits = JxlDecoderLimits::restrictive();
    // The decoder tracks what it allocates against this budget. The result
    // is 8 bits a sample and four samples a pixel at most.
    limits.max_memory_bytes = Some(limit);
    limits.max_extra_channels = Some(MAX_EXTRA_CHANNELS);
    limits.max_pixels = Some((limit / BYTES_PER_PIXEL).min(MAX_PIXELS) as usize);
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
