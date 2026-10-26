//! BMP files to look at that `image` refuses: an OS/2 2.x header of 64 bytes,
//! a plane count other than 1, and RLE rows stored top-down (a negative
//! height, which the format does not allow with compression), and RLE data
//! with deltas or a missing end that `image` calls corrupt. The header is
//! rewritten, or the data expanded, and the file decoded again. A fallback of
//! `decode_any` only.

use super::{decode, within, Error, Format, Pixels, Samples};

pub(super) fn decode_repaired(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let mut file = data.to_vec();
    let le = |file: &[u8], at: usize, n: usize| {
        file.get(at..at + n).map_or(0u64, |b| {
            b.iter().rev().fold(0, |v, &x| v << 8 | u64::from(x))
        })
    };
    let mut changed = false;
    if le(&file, 14, 4) == 64 && file.len() >= 78 {
        // The OS/2 fields after the 40 of a Windows header are dropped.
        file.drain(54..78);
        file[14..18].copy_from_slice(&40u32.to_le_bytes());
        let offset = (le(&file, 10, 4) as u32).saturating_sub(24);
        file[10..14].copy_from_slice(&offset.to_le_bytes());
        changed = true;
    }
    if le(&file, 14, 4) < 40 || file.len() < 54 {
        return Err(Error::Undecodable);
    }
    if le(&file, 26, 2) != 1 {
        file[26..28].copy_from_slice(&1u16.to_le_bytes());
        changed = true;
    }
    let (height, compression) = (le(&file, 22, 4) as u32 as i32, le(&file, 30, 4));
    let flip = height < 0 && matches!(compression, 1 | 2);
    if flip {
        file[22..26].copy_from_slice(&height.unsigned_abs().to_le_bytes());
        changed = true;
    }
    let rle = matches!(compression, 1 | 2);
    if !changed && !rle {
        return Err(Error::Undecodable);
    }
    let decoded = match decode(&file, Format::Bmp, max_alloc) {
        // `image` refuses an RLE stream that is not exactly as the format has
        // it; a lenient reading is expanded to a plain 8-bit file.
        Err(Error::Undecodable) if rle => {
            let plain = expand_rle(&file, compression == 2, max_alloc)?;
            decode(&plain, Format::Bmp, max_alloc)
        }
        other => other,
    };
    let mut pixels = decoded?;
    if flip {
        if let Samples::U8(samples) = &mut pixels.samples {
            let row = pixels.width as usize * pixels.channels.count();
            let rows: Vec<&[u8]> = samples.chunks(row.max(1)).collect();
            *samples = rows.into_iter().rev().flatten().copied().collect();
        }
    }
    Ok(pixels)
}

/// The file with its RLE4 or RLE8 data expanded to one byte for each pixel, as
/// a plain 8-bit file with a palette of 256. The stream is read as Windows
/// does and Pillow does: a run past the row is cut, a delta moves the position,
/// and what the data never reaches is the first colour.
fn expand_rle(file: &[u8], four: bool, max_alloc: u64) -> Result<Vec<u8>, Error> {
    let le = |at: usize, n: usize| {
        file.get(at..at + n).map_or(0usize, |b| {
            b.iter().rev().fold(0, |v, &x| v << 8 | usize::from(x))
        })
    };
    let (width, height) = (le(18, 4), le(22, 4));
    let bits = le(28, 2);
    if width == 0 || height == 0 || bits != if four { 4 } else { 8 } {
        return Err(Error::Undecodable);
    }
    within(
        (width as u64)
            .saturating_mul(height as u64)
            .saturating_mul(2),
        max_alloc,
    )?;
    let header = le(14, 4);
    let colors = match le(46, 4) {
        0 => 1 << bits,
        n => n.min(256),
    };
    let palette = file
        .get(14usize.saturating_add(header)..)
        .map(|p| &p[..p.len().min(colors * 4)])
        .ok_or(Error::Undecodable)?;
    let body = file.get(le(10, 4)..).ok_or(Error::Undecodable)?;

    let mut index = vec![0u8; width * height];
    let (mut x, mut y, mut i) = (0usize, 0usize, 0usize);
    let put = |index: &mut [u8], x: usize, y: usize, v: u8| {
        if x < width && y < height {
            index[y * width + x] = v;
        }
    };
    while y < height {
        let (Some(&n), Some(&v)) = (body.get(i), body.get(i + 1)) else {
            break;
        };
        i += 2;
        match (n, v) {
            (0, 0) => (x, y) = (0, y + 1),
            (0, 1) => break,
            (0, 2) => {
                let (Some(&dx), Some(&dy)) = (body.get(i), body.get(i + 1)) else {
                    break;
                };
                i += 2;
                (x, y) = (x + usize::from(dx), y + usize::from(dy));
            }
            (0, count) => {
                let bytes = if four {
                    usize::from(count).div_ceil(2)
                } else {
                    usize::from(count)
                };
                let data = body.get(i..).unwrap_or_default();
                for k in 0..usize::from(count) {
                    let byte = if four { k / 2 } else { k };
                    let Some(&b) = data.get(byte) else { break };
                    let v = match (four, k % 2) {
                        (false, _) => b,
                        (true, 0) => b >> 4,
                        (true, _) => b & 15,
                    };
                    put(&mut index, x + k, y, v);
                }
                x += usize::from(count);
                // A run of literals ends on a word boundary.
                i += bytes + bytes % 2;
            }
            (count, v) => {
                for k in 0..usize::from(count) {
                    let v = match (four, k % 2) {
                        (false, _) => v,
                        (true, 0) => v >> 4,
                        (true, _) => v & 15,
                    };
                    put(&mut index, x + k, y, v);
                }
                x += usize::from(count);
            }
        }
    }

    let stride = width.div_ceil(4) * 4;
    let offset = 14 + 40 + 1024;
    let mut out = Vec::with_capacity(offset + stride * height);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&((offset + stride * height) as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(offset as u32).to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(width as u32).to_le_bytes());
    out.extend_from_slice(&(height as u32).to_le_bytes());
    out.extend_from_slice(&[1, 0, 8, 0]);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&((stride * height) as u32).to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&256u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(palette);
    out.resize(14 + 40 + 1024, 0);
    for row in index.chunks(width) {
        out.extend_from_slice(row);
        out.resize(out.len() + (stride - width), 0);
    }
    Ok(out)
}
