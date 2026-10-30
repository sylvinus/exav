//! Finding JPEG streams in a byte range, and what their headers say.
//!
//! The walk follows ITU-T T.81 (the JPEG standard): marker segments by their
//! length until the first scan, then the entropy-coded data until the end of
//! image marker. Nothing here decodes pixels.

use super::tiff;

/// Marker segments read before the first scan. A real file has a few dozen.
const MAX_SEGMENTS: usize = 256;

/// Where a stream is searched for with [`find`]: candidates tried and found,
/// so that a file made of nothing but start markers costs a bounded time.
const MAX_ATTEMPTS: usize = 512;
const MAX_FOUND: usize = 64;

/// What the headers of one JPEG stream say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Info {
    pub width: u32,
    pub height: u32,
    pub components: u8,
    /// Bytes from the start marker to the end of the stream: after the end
    /// marker, or the end of the data when the stream is cut short.
    pub len: usize,
    /// The Exif orientation (1 to 8) of the stream's own APP1 segment.
    pub orientation: Option<u8>,
}

fn u16_at(d: &[u8], at: usize) -> Option<usize> {
    let b = d.get(at..at.checked_add(2)?)?;
    Some(usize::from(b[0]) << 8 | usize::from(b[1]))
}

/// The stream that starts at `data[0]`: a start marker, then segments up to a
/// first scan, with a baseline, extended sequential or progressive frame of 8
/// bits and one, three or four components, which the decoder reads. Lossless,
/// hierarchical and arithmetic-coded streams are `None`, as is anything else.
pub(super) fn parse(data: &[u8]) -> Option<Info> {
    if !data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return None;
    }
    let mut at = 2;
    let (mut width, mut height, mut components) = (0usize, 0usize, 0u8);
    let mut orientation = None;
    for _ in 0..MAX_SEGMENTS {
        // Fill bytes may come before a marker.
        while *data.get(at)? == 0xFF && *data.get(at + 1)? == 0xFF {
            at += 1;
        }
        if *data.get(at)? != 0xFF {
            return None;
        }
        let marker = *data.get(at + 1)?;
        let len = u16_at(data, at + 2)?;
        match marker {
            // Standalone markers, a second start marker, or an end of image
            // before any scan.
            0x00 | 0x01 | 0xD0..=0xD9 => return None,
            // Lossless, differential and arithmetic frames.
            0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => return None,
            _ => {}
        }
        if len < 2 {
            return None;
        }
        let body = data.get(at + 4..at.checked_add(2 + len)?)?;
        match marker {
            0xC0..=0xC2 => {
                if width != 0 || body.len() < 6 || body[0] != 8 {
                    return None;
                }
                height = usize::from(body[1]) << 8 | usize::from(body[2]);
                width = usize::from(body[3]) << 8 | usize::from(body[4]);
                components = body[5];
                if width == 0
                    || height == 0
                    || !matches!(components, 1 | 3 | 4)
                    || body.len() != 6 + 3 * usize::from(components)
                {
                    return None;
                }
            }
            0xE1 if orientation.is_none() => {
                orientation = body.strip_prefix(b"Exif\0\0").and_then(tiff::orientation);
            }
            0xDA => {
                if width == 0 {
                    return None;
                }
                return Some(Info {
                    width: width as u32,
                    height: height as u32,
                    components,
                    len: entropy_end(data, at + 2 + len),
                    orientation,
                });
            }
            _ => {}
        }
        at += 2 + len;
    }
    None
}

/// The end of the stream whose entropy-coded data starts at `at`: past the
/// end of image marker, or the end of the data. Markers between scans (a
/// progressive stream's) are skipped by their length.
fn entropy_end(data: &[u8], mut at: usize) -> usize {
    while let Some(i) = data[at.min(data.len())..].iter().position(|&b| b == 0xFF) {
        let ff = at + i;
        match data.get(ff + 1) {
            None => return data.len(),
            Some(0xD9) => return ff + 2,
            // A stuffed byte, a restart marker, or a fill byte.
            Some(0x00 | 0xD0..=0xD7 | 0xFF) => at = ff + 1,
            Some(_) => match u16_at(data, ff + 2) {
                Some(len) if len >= 2 && ff + 2 + len <= data.len() => at = ff + 2 + len,
                _ => return data.len(),
            },
        }
    }
    data.len()
}

/// The streams in `data`, by their start markers, in file order, with their
/// offsets. A stream found is not searched again inside. A file that holds
/// more start markers than the limits allow is read as far as they reach.
pub(super) fn find(data: &[u8]) -> Vec<(usize, Info)> {
    let mut found = Vec::new();
    let (mut at, mut attempts) = (0, 0);
    while let Some(i) = data[at..].iter().position(|&b| b == 0xFF) {
        let start = at + i;
        at = start + 1;
        if data.get(start + 1..start + 3) != Some(&[0xD8, 0xFF]) {
            continue;
        }
        attempts += 1;
        if attempts > MAX_ATTEMPTS {
            break;
        }
        if let Some(info) = parse(&data[start..]) {
            at = start + info.len;
            found.push((start, info));
            if found.len() == MAX_FOUND {
                break;
            }
        }
    }
    found
}
