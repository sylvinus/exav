//! PowerPoint 2, 3 and 4 presentations: a file that starts with 0xED 0xDE
//! 0xAD 0x0B (Windows, little endian) or 0x0B 0xAD 0xDE 0xED (Macintosh,
//! big endian) and a version number, as one file (2 and 3), as the "PP40"
//! stream of a compound file (4), or as the data fork of a Macintosh file in
//! BinHex 4.0 text. Microsoft published no specification of them: readers
//! recognise them to tell them from a file that is not a presentation.

/// What an old presentation is: its version and its byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}
