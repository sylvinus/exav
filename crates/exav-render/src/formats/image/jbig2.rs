//! JBIG2 files (T.88 Annex D.1 and D.2) through hayro-jbig2: one page, as
//! 8-bit grey, black 0 and white 255.

use hayro_jbig2::{Decoder, Image};

use super::{within, Channels, Error, Pixels, Samples};
use crate::formats::pdf_image::region_pixels;

pub(super) fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    // hayro-jbig2 draws the regions of every page onto the first page's
    // bitmap, so a file of several pages is refused rather than shown wrong.
    // Header: 8-byte ID, flags, then the page count unless flag bit 1 says
    // it is unknown.
    if data.get(8).is_some_and(|flags| flags & 2 == 0) {
        let pages = data.get(9..13).ok_or(Error::Undecodable)?;
        if u32::from_be_bytes(pages.try_into().expect("four bytes")) > 1 {
            return Err(Error::Undecodable);
        }
    }
    let image = Image::new(data).map_err(|_| Error::Undecodable)?;
    let (width, height) = (image.width(), image.height());
    let pixels = u64::from(width) * u64::from(height);
    // The segments follow the header; bit 0 of its flags is the sequential
    // organisation.
    let flags = data.get(8).copied().unwrap_or(0);
    let segments = data
        .get(if flags & 2 != 0 { 9 } else { 13 }..)
        .unwrap_or_default();
    let regions = region_pixels(segments, flags & 1 == 0);
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
