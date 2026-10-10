//! JPEG 2000 through hayro-jpeg2000, which gives 8-bit samples.

use hayro_jpeg2000::{ColorSpace, DecodeSettings, DecoderContext, Image};

use super::{cmyk_to_rgb, within, Channels, Error, Pixels, Samples};

pub(super) fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let image = Image::new(data, &DecodeSettings::default()).map_err(|_| Error::Undecodable)?;
    let (width, height) = (image.width(), image.height());
    let colour = u64::from(image.color_space().num_channels());
    let channels = colour + u64::from(image.has_alpha());
    // The decoder holds every component as `f32` at full size, then packs
    // them into bytes.
    within(
        u64::from(width)
            .saturating_mul(u64::from(height))
            .saturating_mul(channels)
            .saturating_mul(5),
        max_alloc,
    )?;
    let data = image
        .decode(&mut DecoderContext::default())
        .map_err(|_| Error::Undecodable)?
        .data_u8();
    let alpha = image.has_alpha();
    let (channels, samples) = match (image.color_space(), colour, alpha) {
        (ColorSpace::CMYK, _, _) | (ColorSpace::Icc { .. }, 4, _) => (
            if alpha { Channels::Rgba } else { Channels::Rgb },
            cmyk_to_rgb(&data, alpha),
        ),
        (_, 1, false) => (Channels::Luma, data),
        (_, 1, true) => (Channels::LumaAlpha, data),
        (_, 3, false) => (Channels::Rgb, data),
        (_, 3, true) => (Channels::Rgba, data),
        // A two-component image with no colour specification.
        (ColorSpace::Unknown { .. }, 2, false) => (Channels::LumaAlpha, data),
        _ => return Err(Error::Undecodable),
    };
    if samples.len() as u64 != u64::from(width) * u64::from(height) * channels.count() as u64 {
        return Err(Error::Undecodable);
    }
    Ok(Pixels {
        width,
        height,
        channels,
        samples: Samples::U8(samples),
    })
}
