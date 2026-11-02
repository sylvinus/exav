//! ICO and CUR files as the eye picks an image of them, and some that `image`
//! refuses as a whole: a PNG that is not 32-bit, or one image that does not
//! decode among several. Each image is tried alone, the largest first and of
//! those the one with most colour. Used by `decode_any` only, so that the
//! image the hash is of stays the one ClamAV's decoder picks.

use super::{Error, Format, Pixels, decode};

pub(super) fn decode_largest(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let count = usize::from(u16::from_le_bytes([
        *data.get(4).ok_or(Error::Undecodable)?,
        *data.get(5).ok_or(Error::Undecodable)?,
    ]));
    let mut entries = Vec::new();
    for i in 0..count.min(256) {
        let e = data
            .get(6 + 16 * i..22 + 16 * i)
            .ok_or(Error::Undecodable)?;
        // A width or height of 0 is 256.
        let side = |b: u8| if b == 0 { 256usize } else { usize::from(b) };
        let size = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as usize;
        let at = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as usize;
        // Bits per pixel: the entry's, or the image header's when it gives none.
        let bits = match u16::from_le_bytes([e[6], e[7]]) {
            0 => data
                .get(at.saturating_add(14)..at.saturating_add(16))
                .filter(|_| data.get(at..at.saturating_add(4)) == Some(&[40, 0, 0, 0]))
                .map_or(32, |b| u16::from_le_bytes([b[0], b[1]])),
            n => n,
        };
        entries.push(((side(e[0]) * side(e[1]), bits), e.to_vec(), size, at));
    }
    // The largest, and of those the one with most colour: a file that holds
    // an image at several depths has the same size more than once.
    entries.sort_by_key(|e| std::cmp::Reverse(e.0));
    for (_, entry, size, at) in entries {
        // The length the entry gives, then all that follows it: a length
        // that is too short is a common fault.
        let stated = at.checked_add(size).and_then(|end| data.get(at..end));
        for image in [stated, data.get(at..)].into_iter().flatten() {
            let decoded = if image.starts_with(b"\x89PNG") {
                decode(image, Format::Png, max_alloc)
            } else {
                decode(&single_icon(&entry, image), Format::Ico, max_alloc)
            };
            if let Ok(pixels) = decoded {
                return Ok(pixels);
            }
        }
    }
    Err(Error::Undecodable)
}

/// An icon file of the one image: its entry corrected to what the image
/// holds (size, length, offset), and an AND mask cut short filled with
/// zeros, which keep the pixels.
fn single_icon(entry: &[u8], image: &[u8]) -> Vec<u8> {
    let mut e = entry.to_vec();
    let mut image = image.to_vec();
    let le = |at: usize, n: usize| {
        image.get(at..at + n).map_or(0, |b| {
            b.iter().rev().fold(0u64, |v, &x| v << 8 | u64::from(x))
        })
    };
    // The header is BITMAPINFOHEADER, or the V4 or V5 one that extends it.
    let header = le(0, 4);
    if matches!(header, 40 | 108 | 124) {
        let (width, rows) = (le(4, 4), le(8, 4) as u32 as i32);
        let (rows, bpp, used) = (u64::from(rows.unsigned_abs()) / 2, le(14, 2), le(32, 4));
        let compression = le(16, 4);
        // A V5 header may name a colour profile placed after the pixels,
        // where `image` would read the AND mask.
        let profile_at = if header == 124 && le(116, 4) > 0 {
            usize::try_from(le(112, 4)).unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };
        // Only an image of 8 bits or fewer has a palette in front of it.
        let colors = match (bpp <= 8, used) {
            (true, 0) => 1 << bpp,
            (true, n) => n,
            (false, _) => 0,
        };
        // The colour masks that follow a plain header, with `BI_BITFIELDS`
        // (3) or `BI_ALPHABITFIELDS` (6).
        let masks = match (header, compression) {
            (40, 3) => 12,
            (40, 6) => 16,
            _ => 0,
        };
        let start = header + masks + colors.min(256) * 4;
        let stride = |bits: u64| width.saturating_mul(bits).div_ceil(32) * 4;
        let xor_end = start.saturating_add(stride(bpp).saturating_mul(rows));
        let mask = stride(1).saturating_mul(rows);
        let with_mask = xor_end.saturating_add(mask);
        image.truncate(profile_at.max(start as usize));
        // The mask is never longer than the pixels in front of it, and a header
        // that says otherwise (no bits to a pixel) does not get a buffer made
        // as large as the width and height say.
        if (image.len() as u64) >= xor_end
            && (image.len() as u64) < with_mask
            && mask <= image.len() as u64
        {
            image.resize(with_mask as usize, 0);
        }
        if bpp == 32
            && compression == 0
            && (image.len() as u64) >= with_mask
            && let (Ok(start), Ok(w), Ok(r)) = (
                usize::try_from(start),
                usize::try_from(width),
                usize::try_from(rows),
            )
        {
            alpha_or_mask(&mut image, start, w, r);
        }
        // Zero stands for 256.
        e[0] = if width >= 256 { 0 } else { width as u8 };
        e[1] = if rows >= 256 { 0 } else { rows as u8 };
    }
    e[8..12].copy_from_slice(&u32::try_from(image.len()).unwrap_or(u32::MAX).to_le_bytes());
    e[12..16].copy_from_slice(&22u32.to_le_bytes());
    let mut one = vec![0, 0, 1, 0, 1, 0];
    one.extend_from_slice(&e);
    one.extend_from_slice(&image);
    one
}

/// A 32-bit image is drawn by its alpha channel when it has one, and its AND
/// mask is cut off (Windows does the same; `image` makes transparent every
/// pixel the mask covers, so a soft edge is lost). With no alpha anywhere the
/// mask says which pixels are there: those it leaves are made opaque.
/// `start` is where the pixels start, in rows of `width`, bottom row first.
fn alpha_or_mask(image: &mut Vec<u8>, start: usize, width: usize, rows: usize) {
    let end = width
        .checked_mul(rows)
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_add(start));
    let Some(end) = end.filter(|&e| e <= image.len()) else {
        return;
    };
    if image[start..end]
        .as_chunks::<4>()
        .0
        .iter()
        .any(|p| p[3] != 0)
    {
        image.truncate(end);
        return;
    }
    let row_bytes = width.div_ceil(32) * 4;
    for r in 0..rows {
        for x in 0..width {
            let masked = image
                .get(end + r * row_bytes + x / 8)
                .is_some_and(|b| b >> (7 - x % 8) & 1 == 1);
            if !masked {
                image[start + (r * width + x) * 4 + 3] = 255;
            }
        }
    }
}

/// A cursor file as an icon file: type 1, and the hotspots, which sit where
/// an icon has its planes and bit count, cleared.
pub(super) fn cursor_as_icon(data: &[u8]) -> Option<Vec<u8>> {
    let count = usize::from(u16::from_le_bytes([*data.get(4)?, *data.get(5)?]));
    // No images: not a cursor (an uncompressed Targa without an ID field
    // starts the same four bytes).
    if count == 0 {
        return None;
    }
    let mut icon = data.get(..6 + 16 * count)?.to_vec();
    icon[2] = 1;
    for i in 0..count {
        icon[10 + 16 * i..14 + 16 * i].fill(0);
    }
    icon.extend_from_slice(data.get(icon.len()..)?);
    Some(icon)
}
