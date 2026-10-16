//! PowerPoint 2, 3 and 4 presentations: a file that starts with 0xED 0xDE
//! 0xAD 0x0B (Windows, little endian) or 0x0B 0xAD 0xDE 0xED (Macintosh,
//! big endian) and a version number, as one file (2 and 3), as the "PP40"
//! stream of a compound file (4), or as the data fork of a Macintosh file in
//! BinHex 4.0 text. Microsoft published no specification of them: they are
//! recognised and refused as unsupported, so that the caller can tell them
//! from a file that is not a presentation.

use crate::formats::office::slides::error::{Error, Result};

/// What an old presentation is: its version and its byte order.
pub struct Old {
    pub version: u32,
    pub big_endian: bool,
}

const MAGIC_LE: [u8; 4] = [0xED, 0xDE, 0xAD, 0x0B];
const MAGIC_BE: [u8; 4] = [0x0B, 0xAD, 0xDE, 0xED];

/// The presentation `d` holds, when it is the stream of one: starting with
/// the magic number.
pub fn parse(d: &[u8]) -> Option<Old> {
    let big_endian = match d.get(..4)? {
        m if m == MAGIC_LE => false,
        m if m == MAGIC_BE => true,
        _ => return None,
    };
    let v: [u8; 4] = d.get(4..8)?.try_into().ok()?;
    let version = if big_endian {
        u32::from_be_bytes(v)
    } else {
        u32::from_le_bytes(v)
    };
    (2..=4).contains(&version).then_some(Old {
        version,
        big_endian,
    })
}

/// The data fork of a BinHex 4.0 file (RFC 1741): text of 64 characters,
/// after a line saying it must be converted and a colon, ending at another;
/// a header (name, version, type, creator, flags, fork lengths, checksum),
/// the data fork and its checksum, run-length coded with 0x90.
pub fn binhex(text: &[u8]) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] =
        b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
    if !text.starts_with(b"(This file must be converted with BinHex") {
        return None;
    }
    let start = text.iter().position(|&c| c == b':')? + 1;
    let mut bits = 0u32;
    let mut n = 0u32;
    let mut raw: Vec<u8> = vec![];
    for &c in &text[start..] {
        if c == b':' {
            break;
        }
        if matches!(c, b'\r' | b'\n' | b' ' | b'\t') {
            continue;
        }
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        bits = (bits << 6 | v) & 0xFFFF;
        n += 6;
        if n >= 8 {
            n -= 8;
            raw.push((bits >> n) as u8);
            if raw.len() > 64 << 20 {
                return None;
            }
        }
    }
    // Run-length decoding: 0x90 then a count; 0 is a 0x90 itself.
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == 0x90 {
            let count = *raw.get(i + 1)? as usize;
            if count == 0 {
                out.push(0x90);
            } else {
                let last = *out.last()?;
                out.extend(std::iter::repeat_n(last, count - 1));
            }
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
        if out.len() > 64 << 20 {
            return None;
        }
    }
    let name = usize::from(*out.first()?);
    let p = 1 + name;
    // Version, type, creator, flags, then the data fork's length.
    let len = u32::from_be_bytes(out.get(p + 11..p + 15)?.try_into().ok()?) as usize;
    let data = out.get(p + 21..p + 21 + len)?;
    Some(data.to_vec())
}

/// Whether `input` is an old presentation on its own (not in a compound
/// file): its bytes, or its BinHex text's data fork.
pub fn open(input: &[u8]) -> Option<Old> {
    parse(input).or_else(|| binhex(input).and_then(|d| parse(&d)))
}

pub fn read(old: &Old) -> Result<crate::formats::office::slides::model::Presentation> {
    Err(Error::Unsupported(format!(
        "PowerPoint {}{}",
        old.version,
        if old.big_endian { " for Macintosh" } else { "" }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_byte_orders() {
        let le = [0xED, 0xDE, 0xAD, 0x0B, 3, 0, 0, 0, 1];
        let o = parse(&le).unwrap();
        assert_eq!((o.version, o.big_endian), (3, false));
        let be = [0x0B, 0xAD, 0xDE, 0xED, 0, 0, 0, 2, 1];
        let o = parse(&be).unwrap();
        assert_eq!((o.version, o.big_endian), (2, true));
        // Not a version of PowerPoint's.
        assert!(parse(&[0xED, 0xDE, 0xAD, 0x0B, 9, 0, 0, 0]).is_none());
        assert!(parse(b"hello world").is_none());
    }

    #[test]
    fn binhex_data_fork() {
        // A file "a", version 0, type "SLDS", creator "PPNT", flags 0, a data
        // fork of 4 bytes (the magic) and an empty resource fork.
        let mut raw: Vec<u8> = vec![1, b'a', 0];
        raw.extend(b"SLDSPPNT");
        raw.extend([0, 0]);
        raw.extend(4u32.to_be_bytes());
        raw.extend(0u32.to_be_bytes());
        raw.extend([0, 0]); // header checksum
        raw.extend(MAGIC_BE);
        raw.extend([0, 0]); // data checksum
        let alphabet = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
        let mut text = b"(This file must be converted with BinHex 4.0)\r\r:".to_vec();
        let (mut bits, mut n) = (0u32, 0u32);
        for &b in &raw {
            bits = bits << 8 | u32::from(b);
            n += 8;
            while n >= 6 {
                n -= 6;
                text.push(alphabet[(bits >> n & 63) as usize]);
            }
        }
        if n > 0 {
            text.push(alphabet[(bits << (6 - n) & 63) as usize]);
        }
        text.push(b':');
        assert_eq!(binhex(&text).unwrap(), MAGIC_BE);
        assert!(binhex(b"not binhex").is_none());
    }
}
