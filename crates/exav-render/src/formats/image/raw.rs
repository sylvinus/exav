//! Camera RAW files, shown by the preview they carry.
//!
//! A RAW file holds the sensor data and, next to it, JPEG previews of
//! several sizes, sometimes an uncompressed RGB one. [`decode`] finds them
//! and gives the largest the budget allows, with the Exif orientation applied.
//! The sensor data is not decoded.
//!
//! The families it reads, detected from the bytes (never the name):
//!
//! - TIFF-structured: Adobe DNG (and the Leica, Ricoh, Pentax, GoPro and
//!   phone files that are DNG), Canon CR2, Phase One IIQ, Olympus ORF
//!   (`IIRO`, `IIRS`, `MMOR`), Panasonic RW2, RAW and RWL (`IIU\0`), and
//!   every other TIFF/EP file that holds a colour filter array or one of the
//!   makers' own compressions: Nikon NEF and NRW, Sony ARW, SR2 and SRF,
//!   Pentax PEF, Samsung SRW, Hasselblad 3FR, Kodak, Epson, Mamiya, Leaf.
//! - Canon CR3 (an ISO base media file with the `crx ` brand), Fujifilm RAF,
//!   Sigma X3F, Canon CRW, Minolta MRW.
//!
//! A plain TIFF is not one of them: [`detect`] says `None`, and the TIFF
//! decoder reads it.
//!
//! The previews of a TIFF-structured file are listed by the tags TIFF 6.0
//! and the DNG specification define for them (JPEGInterchangeFormat, strips
//! of JPEG or of uncompressed RGB, in any directory reached through the
//! chain, SubIFDs and the Exif pointer). Every file is also searched for
//! the JPEG streams it embeds anywhere else, which is where the makers keep
//! theirs (inside makernotes, boxes and sections): a stream counts when its
//! headers are well formed up to its first scan (see `jpeg.rs`). The sensor
//! data is never taken for a preview: lossless JPEG (what DNG, CR2 and others
//! compress it with) is not a stream the decoder reads, and the strips of a
//! directory that holds colour filter array data are skipped.
//!
//! Written from the public specifications: TIFF 6.0 and the DNG
//! specification (Adobe), Exif 2.32 (CIPA DC-008), ITU-T T.81 (JPEG) and
//! ISO/IEC 14496-12. What the makers' own containers hold (the signatures,
//! the compression numbers, where the Exif of a CR3 is) was read off CC0
//! sample files from raw.pixls.us, with tools of our own, not from another
//! implementation.

use super::{Channels, Error, Pixels, Samples, DECODE_MAX};
use crate::image_codecs;

mod bmff;
mod jpeg;
mod tiff;

/// Previews tried before giving up on a file.
const MAX_TRIES: usize = 8;

/// The family of a RAW file, as far as its bytes say.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// Adobe DNG, and files that are DNG under another extension.
    Dng,
    /// Canon CR2.
    Cr2,
    /// Canon CR3.
    Cr3,
    /// Canon CRW (CIFF).
    Crw,
    /// Olympus ORF (and ORI).
    Orf,
    /// Panasonic RW2, RAW and Leica RWL.
    Rw2,
    /// Fujifilm RAF.
    Raf,
    /// Sigma X3F.
    X3f,
    /// Minolta MRW.
    Mrw,
    /// Phase One IIQ.
    Iiq,
    /// Any other TIFF/EP RAW file: Nikon NEF and NRW, Sony ARW, SR2 and
    /// SRF, Pentax PEF, Samsung SRW, Hasselblad 3FR, Kodak, Epson, Mamiya.
    TiffEp,
}

impl Kind {
    /// Lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Dng => "dng",
            Kind::Cr2 => "cr2",
            Kind::Cr3 => "cr3",
            Kind::Crw => "crw",
            Kind::Orf => "orf",
            Kind::Rw2 => "rw2",
            Kind::Raf => "raf",
            Kind::X3f => "x3f",
            Kind::Mrw => "mrw",
            Kind::Iiq => "iiq",
            Kind::TiffEp => "tiff-ep",
        }
    }
}

/// Compressions the makers number for their sensor data (Sony, Epson,
/// Samsung, Nikon, Adobe's lossy DNG, Kodak, Pentax, Leaf).
const VENDOR_COMPRESSIONS: [u32; 8] = [99, 32767, 32769, 32772, 34713, 34892, 65000, 65535];
/// PhotometricInterpretation of colour filter array and linear raw data.
const CFA: u32 = 32803;
const LINEAR_RAW: u32 = 34892;

/// Holds sensor data, not a picture.
fn is_sensor(ifd: &tiff::Ifd) -> bool {
    ifd.cfa
        || matches!(ifd.photometric, Some(CFA | LINEAR_RAW))
        || ifd
            .compression
            .is_some_and(|c| VENDOR_COMPRESSIONS.contains(&c))
}

/// Makers of cameras and scanners, as their Make tag begins.
const MAKES: [&[u8]; 20] = [
    b"CANON",
    b"NIKON",
    b"SONY",
    b"OLYMPUS",
    b"PANASONIC",
    b"LEICA",
    b"FUJIFILM",
    b"PENTAX",
    b"RICOH",
    b"SAMSUNG",
    b"KODAK",
    b"EASTMAN KODAK",
    b"EPSON",
    b"MINOLTA",
    b"MAMIYA",
    b"LEAF",
    b"PHASE ONE",
    b"HASSELBLAD",
    b"CASIO",
    b"SIGMA",
];

/// How sure [`classify`] is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// A signature, or sensor data in the file.
    Strong,
    /// A camera maker's name next to the structure of its files (a SubIFD or
    /// a thumbnail) and nothing else: a TIFF a program saved from a camera's
    /// could look so.
    Weak,
}

/// The family of a RAW file, or `None` for anything else, a plain TIFF
/// included. A TIFF-structured file is a RAW file when it holds sensor
/// data (a colour filter array, a maker's compression) or the DNG tags, or
/// carries a camera maker's name and the SubIFD or JPEG thumbnail such a
/// maker writes; [`preview`] refuses that last kind when it has no preview,
/// as [`Error::Unsupported`], so that the TIFF it may be is read as one.
pub fn detect(data: &[u8]) -> Option<Kind> {
    classify(data).map(|(kind, _)| kind)
}

fn classify(data: &[u8]) -> Option<(Kind, Evidence)> {
    let strong = |k| Some((k, Evidence::Strong));
    if data.starts_with(b"FUJIFILMCCD-RAW") {
        return strong(Kind::Raf);
    }
    if data.starts_with(b"FOVb") {
        return strong(Kind::X3f);
    }
    if data.starts_with(b"\0MRM") {
        return strong(Kind::Mrw);
    }
    if bmff::is_cr3(data) {
        return strong(Kind::Cr3);
    }
    // CIFF: a byte order, the offset of the heap (26), "HEAPCCDR".
    if matches!(data.get(..2), Some(b"II")) && data.get(2..6) == Some(&[0x1A, 0, 0, 0][..]) {
        return if data.get(6..14) == Some(b"HEAPCCDR") {
            strong(Kind::Crw)
        } else {
            None
        };
    }
    let header = tiff::header(data)?;
    match header.magic {
        0x4F52 | 0x5352 => return strong(Kind::Orf),
        0x0055 => return strong(Kind::Rw2),
        42 => {}
        _ => return None,
    }
    if data.get(8..11) == Some(b"CR\x02") {
        return strong(Kind::Cr2);
    }
    if data.get(8..12) == Some(b"IIII") {
        return strong(Kind::Iiq);
    }
    let scan = tiff::scan(data, header);
    if scan.ifds.iter().any(|i| i.dng) {
        return strong(Kind::Dng);
    }
    if scan.ifds.iter().any(|i| is_sensor(i) || i.private_data) {
        return strong(Kind::TiffEp);
    }
    let made_by_camera_maker = scan.ifds.first().is_some_and(|i| {
        let make = i.make.to_ascii_uppercase();
        MAKES.iter().any(|m| make.starts_with(m))
    });
    let camera_structure = scan.ifds.iter().any(|i| i.sub_ifds || i.jpeg.is_some());
    (made_by_camera_maker && camera_structure).then_some((Kind::TiffEp, Evidence::Weak))
}

/// Where a preview is.
#[derive(Clone, Copy, Debug)]
enum Source {
    /// A JPEG stream at an offset, of this length.
    Jpeg { at: usize, len: usize },
    /// Uncompressed 8-bit samples in the strips of directory `ifd`.
    Samples { ifd: usize },
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    source: Source,
    width: u32,
    height: u32,
    /// 1 to 8; 1 when nothing says.
    orientation: u8,
}

/// What [`preview`] chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub kind: Kind,
    /// The preview's size as stored, before the orientation turns it.
    pub width: u32,
    pub height: u32,
    /// The Exif orientation applied, 1 to 8.
    pub orientation: u8,
    /// A JPEG preview, not uncompressed samples.
    pub jpeg: bool,
    /// Previews found in the file, whether the budget allows them or not.
    pub found: usize,
}

/// The largest preview of a RAW file that fits `max_alloc` (at most
/// [`DECODE_MAX`]) bytes, as 8-bit pixels with the orientation applied. A
/// preview is budgeted as the RGBA form a display takes (4 bytes a pixel, 6
/// when it must be turned). [`Error::Unsupported`] when the bytes are not a
/// RAW file, [`Error::NoPreview`] when it holds none a decoder reads.
pub fn decode(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    preview(data, max_alloc).map(|(p, _)| p)
}

/// [`decode`], with what was chosen. A decoder panic is caught and reported
/// [`Error::Undecodable`].
pub fn preview(data: &[u8], max_alloc: u64) -> Result<(Pixels, Info), Error> {
    std::panic::catch_unwind(|| read(data, max_alloc)).unwrap_or(Err(Error::Undecodable))
}

fn read(data: &[u8], max_alloc: u64) -> Result<(Pixels, Info), Error> {
    let (kind, evidence) = classify(data).ok_or(Error::Unsupported)?;
    let limit = max_alloc.min(DECODE_MAX);
    let tiff = tiff::header(data)
        .filter(|_| {
            !matches!(
                kind,
                Kind::Crw | Kind::Cr3 | Kind::Raf | Kind::X3f | Kind::Mrw
            )
        })
        .map(|h| tiff::scan(data, h));
    let mut found = candidates(data, kind, tiff.as_ref());
    if found.is_empty() && evidence == Evidence::Weak {
        return Err(Error::Unsupported);
    }
    // Largest first; the first listed (the structured ones) among equals.
    found.sort_by_key(|c| std::cmp::Reverse(u64::from(c.width) * u64::from(c.height)));
    let (mut too_large, mut tries) = (false, 0);
    for c in &found {
        let pixels = u64::from(c.width) * u64::from(c.height);
        let per_pixel = if c.orientation > 1 { 6 } else { 4 };
        if pixels.saturating_mul(per_pixel) > limit {
            too_large = true;
            continue;
        }
        tries += 1;
        if tries > MAX_TRIES {
            break;
        }
        let Some(decoded) = decode_candidate(data, c, tiff.as_ref(), limit) else {
            continue;
        };
        let info = Info {
            kind,
            width: c.width,
            height: c.height,
            orientation: c.orientation,
            jpeg: matches!(c.source, Source::Jpeg { .. }),
            found: found.len(),
        };
        return Ok((orient(decoded, c.orientation), info));
    }
    Err(if too_large {
        if limit < DECODE_MAX {
            Error::TooLarge
        } else {
            Error::Undecodable
        }
    } else if found.is_empty() {
        Error::NoPreview
    } else {
        Error::Undecodable
    })
}

/// The previews a file holds.
fn candidates(data: &[u8], kind: Kind, tiff: Option<&tiff::Scan>) -> Vec<Candidate> {
    let main_orientation = match (kind, tiff) {
        // The JPEGs of a CR3 hold no Exif of their own.
        (Kind::Cr3, _) => bmff::orientation(data),
        (_, Some(scan)) => scan
            .ifds
            .first()
            .and_then(|i| i.orientation)
            .and_then(|o| u8::try_from(o).ok())
            .filter(|o| (1..=8).contains(o)),
        _ => None,
    }
    .unwrap_or(1);
    let mut out: Vec<Candidate> = Vec::new();
    // Where sensor data is, which a stream found by its start marker inside
    // must not be taken for.
    let mut sensor: Vec<(usize, usize)> = Vec::new();
    if let Some(scan) = tiff {
        for (n, ifd) in scan.ifds.iter().enumerate() {
            if is_sensor(ifd) {
                sensor.extend(
                    ifd.chunks
                        .iter()
                        .filter(|c| c.1 > 0)
                        .map(|&(at, len)| (at as usize, len as usize)),
                );
                continue;
            }
            if let Some(c) = ifd_jpeg(data, ifd, main_orientation) {
                out.push(c);
            } else if let Some(c) = ifd_samples(data, n, ifd, main_orientation) {
                out.push(c);
            }
        }
    }
    for (at, info) in jpeg::find(data) {
        if out
            .iter()
            .any(|c| matches!(c.source, Source::Jpeg { at: a, .. } if a == at))
            || sensor.iter().any(|&(s, len)| at >= s && at - s < len)
        {
            continue;
        }
        out.push(Candidate {
            source: Source::Jpeg { at, len: info.len },
            width: info.width,
            height: info.height,
            orientation: info.orientation.unwrap_or(main_orientation),
        });
    }
    out
}

/// A directory's JPEG preview: JPEGInterchangeFormat, or one strip of JPEG.
fn ifd_jpeg(data: &[u8], ifd: &tiff::Ifd, main_orientation: u8) -> Option<Candidate> {
    let (at, len) = match (ifd.jpeg, ifd.compression, ifd.chunks.as_slice()) {
        (Some(j), _, _) => j,
        (None, Some(6 | 7), &[one]) if !ifd.tiled => one,
        _ => return None,
    };
    let at = at as usize;
    let end = if len == 0 {
        data.len()
    } else {
        at.saturating_add(len as usize).min(data.len())
    };
    let info = jpeg::parse(data.get(at..end)?)?;
    Some(Candidate {
        source: Source::Jpeg { at, len: info.len },
        width: info.width,
        height: info.height,
        orientation: info.orientation.unwrap_or(main_orientation),
    })
}

/// A directory's uncompressed 8-bit grey or RGB preview.
fn ifd_samples(data: &[u8], n: usize, ifd: &tiff::Ifd, main_orientation: u8) -> Option<Candidate> {
    let (width, height) = (ifd.width?, ifd.height?);
    let samples = ifd.samples.unwrap_or(1);
    let fits = match (ifd.photometric?, samples) {
        (2, 3) | (1, 1) => {
            ifd.bits.len() == samples as usize
                && ifd.bits.iter().all(|&b| b == 8 || b == 16)
                && ifd.bits.iter().all(|&b| b == ifd.bits[0])
        }
        _ => false,
    };
    if !fits
        || ifd.compression.unwrap_or(1) != 1
        || ifd.planar.unwrap_or(1) != 1
        || ifd.tiled
        || ifd.chunks_lost
        || ifd.chunks.is_empty()
        || width == 0
        || height == 0
    {
        return None;
    }
    // The strips are read when the preview is chosen; here they must be there.
    strips(data, ifd, sample_bytes(ifd, width, height)?)?;
    Some(Candidate {
        source: Source::Samples { ifd: n },
        width,
        height,
        orientation: main_orientation,
    })
}

/// Bytes of a `width` by `height` image of a directory's samples.
fn sample_bytes(ifd: &tiff::Ifd, width: u32, height: u32) -> Option<u64> {
    let per_sample = u64::from(ifd.bits.first()? / 8);
    Some(
        (u64::from(width) * u64::from(height))
            .saturating_mul(u64::from(ifd.samples.unwrap_or(1)))
            .saturating_mul(per_sample),
    )
}

/// The `need` bytes of a directory's strips, laid end to end, as ranges.
fn strips(data: &[u8], ifd: &tiff::Ifd, need: u64) -> Option<Vec<std::ops::Range<usize>>> {
    let mut left = usize::try_from(need).ok()?;
    let mut ranges = Vec::new();
    for &(at, len) in &ifd.chunks {
        if left == 0 {
            break;
        }
        let at = at as usize;
        // A strip with no stated length is the rest of what is needed.
        let take = if len == 0 {
            left
        } else {
            (len as usize).min(left)
        };
        let end = at.checked_add(take)?;
        data.get(at..end)?;
        ranges.push(at..end);
        left -= take;
    }
    (left == 0).then_some(ranges)
}

fn decode_candidate(
    data: &[u8],
    c: &Candidate,
    tiff: Option<&tiff::Scan>,
    limit: u64,
) -> Option<Pixels> {
    match c.source {
        Source::Jpeg { at, len } => {
            let mut limits = image::Limits::default();
            limits.max_alloc = Some(limit);
            let slice = data.get(at..at.checked_add(len)?)?;
            let img = image_codecs::jpeg::JpegDecoder::new(slice)
                .and_then(|d| image_codecs::decode(d, limits))
                .ok()?;
            let p = Pixels::from_dynamic(img);
            // The SOF the candidate was ranked by is what the decoder reads.
            (p.width == c.width && p.height == c.height).then_some(p)
        }
        Source::Samples { ifd } => {
            let scan = tiff?;
            let ifd = scan.ifds.get(ifd)?;
            let channels = if ifd.samples == Some(3) {
                Channels::Rgb
            } else {
                Channels::Luma
            };
            // 16-bit samples are shown by their high byte.
            let wide = ifd.bits.first() == Some(&16);
            let total = sample_bytes(ifd, c.width, c.height)?;
            // The strips hold all of it, so the allocation is no larger than
            // the data it is read from.
            let ranges = strips(data, ifd, total)?;
            let mut out =
                Vec::with_capacity(usize::try_from(total / if wide { 2 } else { 1 }).ok()?);
            let mut k = 0usize;
            for r in ranges {
                for &b in &data[r] {
                    if !wide || k.is_multiple_of(2) != scan.le {
                        out.push(b);
                    }
                    k += 1;
                }
            }
            Some(Pixels {
                width: c.width,
                height: c.height,
                channels,
                samples: Samples::U8(out),
            })
        }
    }
}

/// `pixels` turned and mirrored as Exif orientation `orientation` says (1 is
/// as stored; 5 to 8 swap width and height).
fn orient(pixels: Pixels, orientation: u8) -> Pixels {
    let Samples::U8(src) = &pixels.samples else {
        return pixels;
    };
    if !(2..=8).contains(&orientation) {
        return pixels;
    }
    let (w, h) = (pixels.width as usize, pixels.height as usize);
    let n = pixels.channels.count();
    let (nw, nh) = if orientation >= 5 { (h, w) } else { (w, h) };
    let mut dst = vec![0u8; src.len()];
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = match orientation {
                2 => (w - 1 - x, y),
                3 => (w - 1 - x, h - 1 - y),
                4 => (x, h - 1 - y),
                5 => (y, x),
                6 => (h - 1 - y, x),
                7 => (h - 1 - y, w - 1 - x),
                _ => (y, w - 1 - x),
            };
            let from = (y * w + x) * n;
            let to = (dy * nw + dx) * n;
            dst[to..to + n].copy_from_slice(&src[from..from + n]);
        }
    }
    Pixels {
        width: nw as u32,
        height: nh as u32,
        channels: pixels.channels,
        samples: Samples::U8(dst),
    }
}

#[cfg(test)]
mod tests;
