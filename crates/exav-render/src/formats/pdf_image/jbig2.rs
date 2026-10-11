//! JBIG2Decode: an embedded stream (T.88 Annex D.3) and its optional
//! `/JBIG2Globals`, through hayro-jbig2.

use hayro_jbig2::{DecodeError, Decoder, FormatError, Image};

use super::{row_bytes, Error};

/// The page as `height` rows of `width` bits (the image dictionary's size),
/// 1 for white, each row padded to a byte with 1s. A page of another size is
/// cut or padded with white; a stream cut before its page information is a
/// white page, as pdf.js's decoder gives one.
pub fn decode_jbig2(
    data: &[u8],
    width: u32,
    height: u32,
    globals: Option<&[u8]>,
    max_alloc: u64,
) -> Result<Vec<u8>, Error> {
    let failed = || Error::new("Failed to decode the image");
    let stride = row_bytes(width);
    let out_len = stride as u64 * u64::from(height);
    if data.is_empty() {
        return Err(failed());
    }
    if out_len > max_alloc {
        return Err(Error::new("Image too large"));
    }
    let clipped;
    let data = match clip_last_segment(data) {
        Some(c) => {
            clipped = c;
            &clipped[..]
        }
        None => data,
    };
    let image = match Image::new_embedded(data, globals) {
        Ok(image) => image,
        Err(DecodeError::Format(FormatError::MissingPageInfo)) => {
            return Ok(vec![0xFF; out_len as usize])
        }
        Err(_) => return Err(failed()),
    };
    let page = u64::from(image.width()) * u64::from(image.height());
    let regions =
        region_pixels(data, false).saturating_add(globals.map_or(0, |g| region_pixels(g, false)));
    // Decoding a region costs time per pixel, whatever the memory its bitmap
    // takes, so the declared pixels are charged at a byte each as well.
    if regions > max_alloc {
        return Err(Error::new("Image too large"));
    }
    // The page and region bitmaps, the page's rows as the decoder emits
    // them, and the output.
    if (page / 8)
        .saturating_add(regions / 8)
        .saturating_add(u64::from(image.width()) + out_len)
        > max_alloc
    {
        return Err(Error::new("Image too large"));
    }
    let mut out = vec![0xFF; out_len as usize];
    let mut rows = Rows {
        out: &mut out,
        stride,
        width: width as usize,
        height: height as usize,
        x: 0,
        y: 0,
    };
    image.decode(&mut rows).map_err(|_| failed())?;
    Ok(out)
}

/// A copy of `data` whose last segment, cut short, declares only the bytes
/// it has (or is left out, when its header is cut), or `None` when no
/// segment runs past the end. pdf.js's decoder draws what a truncated
/// region gives; hayro-jbig2 refuses a segment shorter than its declared
/// length.
fn clip_last_segment(data: &[u8]) -> Option<Vec<u8>> {
    let mut at = 0usize;
    loop {
        if at >= data.len() {
            return None;
        }
        let Some((length_at, h, length)) = segment_header(data, at) else {
            return Some(data[..at].to_vec());
        };
        if length == u32::MAX {
            return None;
        }
        let end = h.checked_add(length as usize)?;
        if end > data.len() {
            let mut out = data.to_vec();
            let have = (data.len() - h) as u32;
            out[length_at..length_at + 4].copy_from_slice(&have.to_be_bytes());
            return Some(out);
        }
        at = end;
    }
}

/// The pixels of the bitmaps the region segments of `segments` declare
/// (T.88 7.4.1: text, halftone, generic and refinement regions), which
/// hayro-jbig2 decodes at their declared size, up to 65,535 by 65,535,
/// wherever they lie on the page. `random_access`: every header comes
/// first, up to an end of file segment, then every data part (Annex D.2);
/// otherwise each header is followed by its data.
pub(crate) fn region_pixels(segments: &[u8], random_access: bool) -> u64 {
    let size = |data_at: usize| {
        let be32 = |at: usize| {
            Some(u64::from(u32::from_be_bytes(
                segments.get(at..at.checked_add(4)?)?.try_into().ok()?,
            )))
        };
        Some(be32(data_at)? * be32(data_at.checked_add(4)?)?)
    };
    let is_region = |flags: u8| {
        matches!(
            flags & 0x3F,
            4 | 6 | 7 | 20 | 22 | 23 | 36 | 38 | 39 | 40 | 42 | 43
        )
    };
    let mut total = 0u64;
    let mut at = 0;
    // Random access: (flags, data length) of each header, then the data.
    let mut headers = Vec::new();
    while let Some((_, h, length)) = segment_header(segments, at) {
        let flags = segments[at + 4];
        if random_access {
            headers.push((flags, length));
            at = h;
            if flags & 0x3F == 51 {
                break;
            }
            continue;
        }
        if is_region(flags) {
            total = total.saturating_add(size(h).unwrap_or(0));
        }
        match h.checked_add(length as usize) {
            Some(end) if length != u32::MAX => at = end,
            _ => break,
        }
    }
    for (flags, length) in headers {
        if is_region(flags) {
            total = total.saturating_add(size(at).unwrap_or(0));
        }
        match at.checked_add(length as usize) {
            Some(end) if length != u32::MAX => at = end,
            _ => break,
        }
    }
    total
}

/// The segment header at `at`: where its data length is, where its data
/// starts, and that length.
fn segment_header(data: &[u8], at: usize) -> Option<(usize, usize, u32)> {
    let be32 = |at: usize| {
        Some(u32::from_be_bytes(
            data.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    // T.88 7.2: number, flags, referred-to segments, page association,
    // data length.
    let number = be32(at)?;
    let flags = *data.get(at.checked_add(4)?)?;
    let mut h = at + 5;
    let first = *data.get(h)?;
    let referred = if first >> 5 == 7 {
        let count = be32(h)? & 0x1FFF_FFFF;
        h = h.checked_add(4 + (count as usize + 1).div_ceil(8))?;
        count as usize
    } else {
        h += 1;
        usize::from(first >> 5)
    };
    let size = match number {
        0..=256 => 1,
        257..=65536 => 2,
        _ => 4,
    };
    h = h
        .checked_add(referred.checked_mul(size)?)?
        .checked_add(if flags & 0x40 != 0 { 4 } else { 1 })?;
    let length = be32(h)?;
    Some((h, h + 4, length))
}

/// Writes the black pixels that fall inside the output as 0 bits.
struct Rows<'a> {
    out: &'a mut [u8],
    stride: usize,
    width: usize,
    height: usize,
    x: usize,
    y: usize,
}

impl Decoder for Rows<'_> {
    fn push_pixel(&mut self, black: bool) {
        if black && self.x < self.width && self.y < self.height {
            self.out[self.y * self.stride + self.x / 8] &= !(0x80 >> (self.x % 8));
        }
        self.x += 1;
    }

    fn push_pixel_chunk(&mut self, black: bool, chunk_count: u32) {
        let n = chunk_count as usize * 8;
        if black {
            for _ in 0..n {
                self.push_pixel(true);
            }
        } else {
            self.x += n;
        }
    }

    fn next_line(&mut self) {
        self.x = 0;
        self.y += 1;
    }
}
