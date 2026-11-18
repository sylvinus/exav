//! PowerPoint 2, 3 and 4 presentations ([`exav_unpack::old_ppt`] recognises
//! them): recognised and refused as unsupported, so that the caller can tell
//! them from a file that is not a presentation.

use crate::formats::office::slides::error::{Error, Result};
pub use exav_unpack::old_ppt::{Old, parse};

/// Whether `input` is an old presentation on its own (not in a compound
/// file): its bytes, or its BinHex text's data fork.
pub fn open(input: &[u8]) -> Option<Old> {
    parse(input).or_else(|| {
        let fork = exav_unpack::binhex::header(input, 8)?.fork;
        parse(&fork)
    })
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
    fn a_binhex_file_holding_a_presentation_is_one() {
        // A file "a", version 0, type "SLDS", creator "PPNT", flags 0, a data
        // fork of 4 bytes (the magic) and an empty resource fork.
        let magic = [0x0B, 0xAD, 0xDE, 0xED, 0, 0, 0, 3];
        let mut raw: Vec<u8> = vec![1, b'a', 0];
        raw.extend(b"SLDSPPNT");
        raw.extend([0, 0]);
        raw.extend((magic.len() as u32).to_be_bytes());
        raw.extend(0u32.to_be_bytes());
        raw.extend([0, 0]); // header checksum
        raw.extend(magic);
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
        let old = open(&text).unwrap();
        assert_eq!((old.version, old.big_endian), (3, true));
        assert!(open(b"not binhex").is_none());
    }
}
