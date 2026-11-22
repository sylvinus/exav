//! JBIG2Decode: an embedded stream (T.88 Annex D.3) and its optional
//! `/JBIG2Globals`, through hayro-jbig2.

use hayro_jbig2::{DecodeError, DecodeSettings, Decoder, FormatError, Globals, Page};

use super::{Error, row_bytes};

/// The page as `height` rows of `width` bits (the image dictionary's size),
/// 1 for white, each row padded to a byte with 1s. A page of another size is
/// cut or padded with white; a stream cut before its page information is a
/// white page, as pdf.js's decoder gives one. A stream that breaks the
/// specification, such as a text region whose symbols are missing, is decoded
/// as far as it goes (this is for pdf.js, in the viewer).
pub fn decode_jbig2(
    data: &[u8],
    width: u32,
    height: u32,
    globals: Option<&[u8]>,
    max_alloc: u64,
) -> Result<Vec<u8>, Error> {
    decode(data, width, height, globals, max_alloc, false)
}

/// [`decode_jbig2`] for the scanner: a stream that breaks the specification is
/// an error.
pub fn decode_jbig2_strict(
    data: &[u8],
    width: u32,
    height: u32,
    globals: Option<&[u8]>,
    max_alloc: u64,
) -> Result<Vec<u8>, Error> {
    decode(data, width, height, globals, max_alloc, true)
}

fn decode(
    data: &[u8],
    width: u32,
    height: u32,
    globals: Option<&[u8]>,
    max_alloc: u64,
    strict: bool,
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
    let regions = declared_pixels(data, globals);
    // Decoding a region costs time per pixel, whatever the memory its bitmap
    // takes, so the declared pixels are charged at a byte each as well. The
    // budget may be a gigabyte (the viewer's), but the time is bounded as it
    // is for a file: by `DECODE_MAX`. Checked before the globals, whose
    // symbol dictionaries are decoded as they are read.
    if regions > max_alloc.min(crate::formats::DECODE_MAX) {
        return Err(Error::new("Image too large"));
    }
    let settings = DecodeSettings { strict };
    let shared = match globals {
        Some(g) => Some(Globals::new(g, &settings).map_err(|_| failed())?),
        None => None,
    };
    let image = match Page::new_embedded(data, shared.as_ref(), &settings) {
        Ok(image) => image,
        Err(DecodeError::Format(FormatError::MissingPageInfo)) => {
            return Ok(vec![0xFF; out_len as usize]);
        }
        Err(_) => return Err(failed()),
    };
    let page = u64::from(image.width()) * u64::from(image.height());
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

/// The pixels the regions of an embedded stream `data` and of its `globals`
/// declare ([`region_pixels`]).
pub(crate) fn declared_pixels(data: &[u8], globals: Option<&[u8]>) -> u64 {
    region_pixels(data, false).saturating_add(globals.map_or(0, |g| region_pixels(g, false)))
}

/// The pixels of the page bitmap that the page information segments of an
/// embedded stream `data` and of its `globals` declare (T.88 7.4.8), the
/// largest of them: hayro-jbig2 allocates the bitmap of one of them, the
/// size the stream gives, not the image dictionary's. A height of
/// `0xFFFFFFFF` is the last row of the end of stripe segments plus one, as
/// hayro-jbig2 reads it (0 pixels when there is none).
#[cfg(feature = "qr")]
pub(crate) fn declared_page_pixels(data: &[u8], globals: Option<&[u8]>) -> u64 {
    let mut pages = Vec::new();
    let mut stripes = 0u64;
    for part in globals.into_iter().chain([data]) {
        let be32 = |at: usize| {
            Some(u64::from(u32::from_be_bytes(
                part.get(at..at.checked_add(4)?)?.try_into().ok()?,
            )))
        };
        let mut at = 0;
        while let Some((_, h, length)) = segment_header(part, at) {
            match part[at + 4] & 0x3F {
                48 => pages.extend(be32(h).zip(be32(h + 4))),
                50 => stripes = stripes.max(be32(h).map_or(0, |last| last + 1)),
                _ => {}
            }
            match h.checked_add(length as usize) {
                Some(end) if length != u32::MAX => at = end,
                _ => break,
            }
        }
    }
    pages
        .into_iter()
        .map(|(width, height)| {
            let height = if height == u64::from(u32::MAX) {
                stripes
            } else {
                height
            };
            width * height
        })
        .max()
        .unwrap_or(0)
}

/// The pixels of the bitmaps the region segments of `segments` declare
/// (T.88 7.4.1: text, halftone, generic and refinement regions), which
/// hayro-jbig2 decodes at their declared size, up to 65,535 by 65,535,
/// wherever they lie on the page. A symbol dictionary that declares more
/// new symbols than its length can hold counts as `u64::MAX`: the decoder
/// goes on decoding symbols from what is left of the stream, and 243 bytes
/// took it two minutes and 7 GB. `random_access`: every header comes
/// first, up to an end of file segment, then every data part (Annex D.2);
/// otherwise each header is followed by its data.
pub(crate) fn region_pixels(segments: &[u8], random_access: bool) -> u64 {
    // T.88 7.4.2.1: flags, the adaptive template pixels (none for Huffman
    // coding), the refinement ones, then the numbers of exported and new
    // symbols. A real symbol takes more than a byte of the stream.
    let too_many_symbols = |data_at: usize, length: u32| {
        let be = |at: usize, n: usize| {
            let b = segments.get(at..at.checked_add(n)?)?;
            Some(b.iter().fold(0u64, |v, &x| v << 8 | u64::from(x)))
        };
        let Some(flags) = be(data_at, 2) else {
            return false;
        };
        let (huffman, aggregate) = (flags & 1 != 0, flags & 2 != 0);
        let template = flags >> 10 & 3;
        let refinement_template = flags >> 12 & 1;
        let mut at = data_at + 2;
        if !huffman {
            at += if template == 0 { 8 } else { 2 };
        }
        if aggregate && refinement_template == 0 {
            at += 4;
        }
        be(at + 4, 4)
            .is_some_and(|new| new > u64::from(length).saturating_mul(8).saturating_add(64))
    };
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
        } else if flags & 0x3F == 0 && too_many_symbols(h, length) {
            return u64::MAX;
        }
        match h.checked_add(length as usize) {
            Some(end) if length != u32::MAX => at = end,
            _ => break,
        }
    }
    for (flags, length) in headers {
        if is_region(flags) {
            total = total.saturating_add(size(at).unwrap_or(0));
        } else if flags & 0x3F == 0 && too_many_symbols(at, length) {
            return u64::MAX;
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
