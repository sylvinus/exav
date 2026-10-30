//! What a PDF declares before hayro is given it.
//!
//! hayro sizes its buffers by what an image says of itself, in its dictionary
//! or in the header of its JPEG, JPEG 2000 or JBIG2 data: a 123 KB file with
//! JBIG2 data for 100000 by 100000 pixels took it 8.9 GB. This reads those
//! numbers, and nothing else of the data, from every stream of the document,
//! and refuses a document in which one is past [`MAX_IMAGE_PIXELS`] or cannot
//! be read.

use std::collections::HashMap;

use crate::formats::pdf::{apply_filters, filter_names};
use crate::formats::pdf_parse::lex::Lexer;
use crate::formats::pdf_parse::parse::parse_indirect_object_body;
use crate::formats::pdf_parse::types::Primitive;

/// Most pixels an image of the document may declare (a 134 million pixel image
/// is 536 MB of RGBA).
pub(super) const MAX_IMAGE_PIXELS: u64 = 1 << 27;

/// Whether every image of `data` is within [`MAX_IMAGE_PIXELS`], by what it
/// declares. `cap` bounds what a stream decodes to before its image codec.
pub(super) fn images_are_small(data: &[u8], cap: u64) -> bool {
    let mut lex = Lexer::new(data);
    while let Some((_, _, start)) = lex.find_next_obj() {
        lex.set_pos(start);
        let Some((obj, _)) = parse_indirect_object_body(&mut lex) else {
            continue;
        };
        let (info, raw) = match obj {
            Primitive::Stream { info, data } => (info, Some(data)),
            Primitive::Dictionary(info) => (info, None),
            _ => continue,
        };
        if declared(&info).is_some_and(|(w, h)| w.saturating_mul(h) > MAX_IMAGE_PIXELS) {
            return false;
        }
        let Some(raw) = raw else { continue };
        let Some(codec) = filter_names(&info).into_iter().find_map(|f| codec(&f)) else {
            continue;
        };
        // The data as the codec gets it, after the filters before it.
        let Ok(decoded) = apply_filters(&raw, &info, cap) else {
            return false;
        };
        if decoded.truncated {
            return false;
        }
        match header_dims(codec, &decoded.buf) {
            Some((w, h)) if w.saturating_mul(h) <= MAX_IMAGE_PIXELS => {}
            _ => return false,
        }
    }
    true
}

#[derive(Clone, Copy)]
enum Codec {
    Jpeg,
    Jpx,
    Jbig2,
}

/// The image codec a filter name is, when it is one whose header is read.
fn codec(filter: &str) -> Option<Codec> {
    match filter {
        "DCTDecode" | "DCT" => Some(Codec::Jpeg),
        "JPXDecode" => Some(Codec::Jpx),
        "JBIG2Decode" => Some(Codec::Jbig2),
        _ => None,
    }
}

/// `/Width` and `/Height` of a dictionary, when it has both as integers.
fn declared(info: &HashMap<String, Primitive>) -> Option<(u64, u64)> {
    let n = |k: &str| {
        info.get(k)
            .and_then(Primitive::as_i64)
            .map(|v| u64::try_from(v).unwrap_or(0))
    };
    Some((n("Width")?, n("Height")?))
}

fn header_dims(codec: Codec, d: &[u8]) -> Option<(u64, u64)> {
    match codec {
        Codec::Jpeg => jpeg_dims(d),
        Codec::Jpx => jpx_dims(d),
        Codec::Jbig2 => jbig2_dims(d),
    }
}

fn be16(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from(u16::from_be_bytes(
        d.get(at..at + 2)?.try_into().ok()?,
    )))
}

fn be32(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from(u32::from_be_bytes(
        d.get(at..at + 4)?.try_into().ok()?,
    )))
}

/// A JPEG's size, from its first start-of-frame marker.
fn jpeg_dims(d: &[u8]) -> Option<(u64, u64)> {
    let mut at = 2;
    for _ in 0..4096 {
        if *d.get(at)? != 0xff {
            at += 1;
            continue;
        }
        let marker = *d.get(at + 1)?;
        match marker {
            0xff => at += 1,
            // Start of frame (not the Huffman table, the JPEG extension or the
            // arithmetic conditioning).
            0xc0..=0xcf if !matches!(marker, 0xc4 | 0xc8 | 0xcc) => {
                return Some((be16(d, at + 7)?, be16(d, at + 5)?));
            }
            // Markers without a length.
            0x00 | 0x01 | 0xd0..=0xd9 => at += 2,
            _ => at += 2 + usize::try_from(be16(d, at + 2)?).ok()?,
        }
    }
    None
}

/// A JPEG 2000 image's size: from the codestream's SIZ marker, or the `ihdr`
/// box of a JP2 file.
fn jpx_dims(d: &[u8]) -> Option<(u64, u64)> {
    let head = &d[..d.len().min(4096)];
    if let Some(at) = memchr::memmem::find(head, b"ihdr") {
        return Some((be32(d, at + 8)?, be32(d, at + 4)?));
    }
    let at = memchr::memmem::find(head, &[0xff, 0x4f, 0xff, 0x51])? + 2;
    let (x, y) = (be32(d, at + 6)?, be32(d, at + 10)?);
    let (xo, yo) = (be32(d, at + 14)?, be32(d, at + 18)?);
    Some((x.saturating_sub(xo), y.saturating_sub(yo)))
}

/// A JBIG2 page's size, from its page information segment (embedded
/// organisation, as PDF has it: a run of segments).
fn jbig2_dims(d: &[u8]) -> Option<(u64, u64)> {
    let mut at = 0usize;
    for _ in 0..64 {
        let number = be32(d, at)?;
        let flags = *d.get(at + 4)?;
        let kind = flags & 0x3f;
        let mut p = at + 5;
        // Referred-to segments: a count, retain bits, and their numbers.
        let first = *d.get(p)?;
        let count = if first >> 5 == 7 {
            let n = be32(d, p)? & 0x1fff_ffff;
            p += 4 + usize::try_from(n + 1).ok()?.div_ceil(8);
            n
        } else {
            p += 1;
            u64::from(first >> 5)
        };
        let size = if number <= 256 {
            1
        } else if number <= 65536 {
            2
        } else {
            4
        };
        p += usize::try_from(count).ok()?.checked_mul(size)?;
        // The page the segment belongs to, then its length.
        p += if flags & 0x40 != 0 { 4 } else { 1 };
        let length = be32(d, p)?;
        p += 4;
        if kind == 48 {
            return Some((be32(d, p)?, be32(d, p + 4)?));
        }
        if length == 0xffff_ffff {
            return None;
        }
        at = p.checked_add(usize::try_from(length).ok()?)?;
    }
    None
}
