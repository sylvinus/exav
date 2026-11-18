//! Whether a file that starts like an image has the rest of a header.
//!
//! [`Format::detect`] takes a file by its first bytes, and for BMP, ICO, PNM,
//! DDS, QOI and a bare JPEG XL codestream those are two to four bytes: a text
//! or binary file can start with them. A caller that has to tell an image that
//! does not decode from a file that is not an image asks [`Format::has_header`]
//! once the decode has failed. The checks are fields the format fixes in its
//! header; they say nothing of the data after it.

use super::Format;

#[cfg(feature = "ico")]
fn u16_le(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_le(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

impl Format {
    /// Whether `data`, which [`Format::detect`] took for this format, also has
    /// the fixed fields of its header. True for every format whose signature is
    /// long enough to say it. A file too short for the fields has no header.
    pub(crate) fn has_header(self, data: &[u8]) -> bool {
        match self {
            Format::Bmp => bmp(data),
            #[cfg(feature = "ico")]
            Format::Ico => ico(data),
            #[cfg(feature = "pnm")]
            Format::Pnm => pnm(data),
            #[cfg(feature = "qoi")]
            Format::Qoi => qoi(data),
            #[cfg(feature = "dds")]
            Format::Dds => u32_le(data, 4) == Some(124),
            #[cfg(feature = "jxl")]
            Format::Jxl => !data.starts_with(&[0xFF, 0x0A]) || super::jxl::has_header(data),
            _ => true,
        }
    }
}

/// The size of the DIB header, which follows the 14 bytes of the file header,
/// is one of the sizes of the OS/2 and Windows variants.
fn bmp(data: &[u8]) -> bool {
    matches!(
        u32_le(data, 14),
        Some(12 | 16 | 24 | 40 | 48 | 52 | 56 | 64 | 108 | 124)
    )
}

/// The directory holds an image, and its first entry has no reserved byte, at
/// most one plane and 32 bits to a pixel, and points past the directory's first
/// entry.
#[cfg(feature = "ico")]
fn ico(data: &[u8]) -> bool {
    let Some(entry) = data.get(6..22) else {
        return false;
    };
    u16_le(data, 4).is_some_and(|count| count > 0)
        && entry[3] == 0
        && u16_le(entry, 4).is_some_and(|planes| planes <= 1)
        && u16_le(entry, 6).is_some_and(|bits| bits <= 32)
        && u32_le(entry, 12).is_some_and(|at| at >= 22)
}

/// P1 to P6: the width and the height, as decimal numbers after white space or
/// comments. P7 (PAM): a header keyword.
#[cfg(feature = "pnm")]
fn pnm(data: &[u8]) -> bool {
    // White space and comment lines, which must be there at least once.
    let separator = |at: &mut usize| {
        let start = *at;
        loop {
            match data.get(*at) {
                Some(b'#') => {
                    while data.get(*at).is_some_and(|&c| c != b'\n') {
                        *at += 1;
                    }
                }
                Some(c) if c.is_ascii_whitespace() => *at += 1,
                _ => break,
            }
        }
        *at > start
    };
    let number = |at: &mut usize| {
        let start = *at;
        while data.get(*at).is_some_and(u8::is_ascii_digit) {
            *at += 1;
        }
        *at > start
    };
    let mut at = 2;
    if data.get(1) == Some(&b'7') {
        const KEYWORDS: [&[u8]; 6] = [
            b"WIDTH",
            b"HEIGHT",
            b"DEPTH",
            b"MAXVAL",
            b"TUPLTYPE",
            b"ENDHDR",
        ];
        return separator(&mut at)
            && KEYWORDS
                .iter()
                .any(|keyword| data[at..].starts_with(keyword));
    }
    separator(&mut at) && number(&mut at) && separator(&mut at) && number(&mut at)
}

/// A width and height that are not 0, 3 or 4 channels and a color space of 0
/// (sRGB) or 1 (linear), after the 4 bytes of signature.
#[cfg(feature = "qoi")]
fn qoi(data: &[u8]) -> bool {
    let be = |at: usize| Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?));
    matches!(
        (be(4), be(8), data.get(12), data.get(13)),
        (Some(1..), Some(1..), Some(3 | 4), Some(0 | 1))
    )
}
