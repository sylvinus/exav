//! JBIG2 files (T.88 Annex D.1 and D.2) through hayro-jbig2: the first page,
//! as 8-bit grey, black 0 and white 255.

use hayro_jbig2::{DecodeSettings, Decoder, File};

use super::{Channels, Error, Pixels, Samples, within};
use crate::formats::pdf_image::region_pixels;

/// With `strict`, a file that breaks the specification is refused; else it is
/// decoded as far as it goes.
pub(super) fn decode(data: &[u8], max_alloc: u64, strict: bool) -> Result<Pixels, Error> {
    let file = File::new(data, &DecodeSettings { strict }).map_err(|_| Error::Undecodable)?;
    let image = file.page(0).ok_or(Error::Undecodable)?;
    let (width, height) = (image.width(), image.height());
    let pixels = u64::from(width) * u64::from(height);
    // The segments follow the header; bit 0 of its flags is the sequential
    // organisation.
    let flags = data.get(8).copied().unwrap_or(0);
    let segments = data
        .get(if flags & 2 != 0 { 9 } else { 13 }..)
        .unwrap_or_default();
    let regions = region_pixels(segments, flags & 1 == 0);
    // Decoding a region costs time per pixel, whatever the memory its bitmap
    // takes, so the declared pixels are charged at a byte each as well.
    within(regions, max_alloc)?;
    // The page and region bitmaps, one bit a pixel, and the bytes the page
    // is unpacked into.
    within(
        pixels
            .saturating_add(pixels.div_ceil(8))
            .saturating_add(regions.div_ceil(8)),
        max_alloc,
    )?;
    let mut out = Grey {
        samples: Vec::with_capacity(pixels as usize),
    };
    image.decode(&mut out).map_err(|_| Error::Undecodable)?;
    if out.samples.len() as u64 != pixels {
        return Err(Error::Undecodable);
    }
    Ok(Pixels {
        width,
        height,
        channels: Channels::Luma,
        samples: Samples::U8(out.samples),
    })
}

struct Grey {
    samples: Vec<u8>,
}

impl Decoder for Grey {
    fn push_pixel(&mut self, black: bool) {
        self.samples.push(if black { 0 } else { 255 });
    }

    fn push_pixel_chunk(&mut self, black: bool, chunk_count: u32) {
        let n = (chunk_count as usize).saturating_mul(8);
        self.samples
            .resize(self.samples.len() + n, if black { 0 } else { 255 });
    }

    fn next_line(&mut self) {}
}
