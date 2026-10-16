//! Text in a Windows code page number (an XLS CODEPAGE record's, a font's
//! character set): Windows and Mac code pages through encoding_rs, DOS (OEM)
//! and the remaining Mac ones through tables of our own.

use super::codepage_tables::TABLES;
use encoding_rs::Encoding;

enum Decoder {
    Utf16,
    Encoding(&'static Encoding),
    Table(&'static [u16; 256]),
}

fn decoder(cp: u16) -> Option<Decoder> {
    use encoding_rs::{
        BIG5, EUC_KR, GBK, IBM866, MACINTOSH, SHIFT_JIS, WINDOWS_1250, WINDOWS_1251, WINDOWS_1252,
        WINDOWS_1253, WINDOWS_1254, WINDOWS_1255, WINDOWS_1256, WINDOWS_1257, WINDOWS_1258,
        WINDOWS_874, X_MAC_CYRILLIC,
    };
    Some(Decoder::Encoding(match cp {
        1200 => return Some(Decoder::Utf16),
        // US-ASCII, and 32769, which BIFF2 to BIFF4 write for Windows 1252.
        367 | 1252 | 0x8001 => WINDOWS_1252,
        866 => IBM866,
        874 => WINDOWS_874,
        932 => SHIFT_JIS,
        936 => GBK,
        949 => EUC_KR,
        950 => BIG5,
        1250 => WINDOWS_1250,
        1251 => WINDOWS_1251,
        1253 => WINDOWS_1253,
        1254 => WINDOWS_1254,
        1255 => WINDOWS_1255,
        1256 => WINDOWS_1256,
        1257 => WINDOWS_1257,
        1258 => WINDOWS_1258,
        // Mac Roman; 32768 is how BIFF names it.
        10000 | 0x8000 => MACINTOSH,
        10007 => X_MAC_CYRILLIC,
        _ => {
            return TABLES
                .iter()
                .find(|t| t.0 == cp)
                .map(|t| Decoder::Table(&t.1))
        }
    }))
}

/// Whether `cp` is a code page this module decodes.
pub fn known(cp: u16) -> bool {
    decoder(cp).is_some()
}

/// `b` in code page `cp`; an unknown code page is read as Windows 1252.
pub fn decode(b: &[u8], cp: u16) -> String {
    match decoder(cp).unwrap_or(Decoder::Encoding(encoding_rs::WINDOWS_1252)) {
        Decoder::Utf16 => {
            let u: Vec<u16> = b
                .as_chunks::<2>()
                .0
                .iter()
                .map(|x| u16::from_le_bytes(*x))
                .collect();
            String::from_utf16_lossy(&u)
        }
        Decoder::Encoding(e) => e.decode_without_bom_handling(b).0.into_owned(),
        Decoder::Table(t) => {
            let u: Vec<u16> = b.iter().map(|&x| t[x as usize]).collect();
            String::from_utf16_lossy(&u)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_and_windows_pages() {
        // 0x82 is é in DOS Latin 1 and Latin US, a low quotation mark in 1252.
        assert_eq!(decode(&[0x82], 850), "é");
        assert_eq!(decode(&[0x82], 437), "é");
        assert_eq!(decode(&[0x82], 1252), "\u{201A}");
        assert_eq!(decode(&[0xD5], 858), "€");
        assert_eq!(decode(&[0x8E], 866), "О");
        assert_eq!(decode(&[0x80], 10029), "Ä");
        assert_eq!(decode(b"A\0", 1200), "A");
        assert!(known(437) && known(869) && !known(1361));
        // An unknown page reads as 1252.
        assert_eq!(decode(&[0xE9], 1361), "é");
    }
}
