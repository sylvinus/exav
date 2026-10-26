//! JPEG 2000 through hayro-jpeg2000, which gives 8-bit samples.

use hayro_jpeg2000::{ColorSpace, DecodeSettings, DecoderContext, Image};

use super::{cmyk_to_rgb, within, ycc_to_rgb, Channels, Error, Pixels, Samples};

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
    let ycc = chroma_subsampled_codestream(data);
    let grey_bands = enumerated_colourspace(data) == Some(GREYSCALE);
    let data = image
        .decode(&mut DecoderContext::default())
        .map_err(|_| Error::Undecodable)?
        .data_u8();
    let alpha = image.has_alpha();
    let (channels, samples) = match (image.color_space(), colour, alpha) {
        // Four bands under a greyscale colour box (GDAL's multi-band files)
        // are not CMYK: the first is shown, as for a multi-band TIFF.
        (ColorSpace::CMYK, 4, false) if grey_bands => (
            Channels::Luma,
            data.as_chunks::<4>().0.iter().map(|p| p[0]).collect(),
        ),
        (ColorSpace::CMYK, _, _) | (ColorSpace::Icc { .. }, 4, _) => (
            if alpha { Channels::Rgba } else { Channels::Rgb },
            cmyk_to_rgb(&data, alpha),
        ),
        (_, 1, false) => (Channels::Luma, data),
        (_, 1, true) => (Channels::LumaAlpha, data),
        (_, 3, false) if ycc => (Channels::Rgb, ycc_to_rgb(data)),
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

/// A bare codestream of three components whose second is subsampled has no
/// colour box to say so, and is YCbCr (the reading of OpenJPEG's tools).
fn chroma_subsampled_codestream(data: &[u8]) -> bool {
    // SOC, SIZ, then Csiz at 40 and one (Ssiz, XRsiz, YRsiz) per component.
    if !data.starts_with(&[0xFF, 0x4F, 0xFF, 0x51]) || data.get(40..42) != Some(&[0, 3]) {
        return false;
    }
    let Some(c) = data.get(42..51) else {
        return false;
    };
    c[1] == c[2] && c[4] != 1
}

/// The enumerated colour space for greyscale in a colour box.
const GREYSCALE: u32 = 17;

/// The enumerated colour space of a JP2 file's colour box (method 1).
fn enumerated_colourspace(data: &[u8]) -> Option<u32> {
    /// The boxes of `data`: type and contents.
    fn boxes(data: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
        let mut at = 0;
        std::iter::from_fn(move || {
            let head = data.get(at..at + 8)?;
            let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
            let (start, end) = match len {
                0 => (at + 8, data.len()),
                1 => {
                    let big = data.get(at + 8..at + 16)?;
                    let len = u64::from_be_bytes(big.try_into().ok()?);
                    (at + 16, at.checked_add(usize::try_from(len).ok()?)?)
                }
                _ => (at + 8, at.checked_add(len)?),
            };
            let body = data.get(start..end.min(data.len()))?;
            at = end.max(start);
            Some((&head[4..8], body))
        })
    }
    let (_, header) = boxes(data).find(|(t, _)| *t == b"jp2h")?;
    let (_, colour) = boxes(header).find(|(t, _)| *t == b"colr")?;
    match colour {
        [1, _, _, e @ ..] => Some(u32::from_be_bytes(e.get(..4)?.try_into().ok()?)),
        _ => None,
    }
}
