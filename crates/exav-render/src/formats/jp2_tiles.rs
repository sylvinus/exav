//! The tiles a JPEG 2000 codestream's header implies.
//!
//! A tile-part names its tile with 16 bits (ISO 15444-1, A.4.2), so a file has
//! at most 65,535 tiles. hayro-jpeg2000 works through every tile the SIZ
//! segment implies, whatever the file holds: a 776-byte codestream with tiles
//! of two samples took minutes to decode.

/// The most tiles a codestream can name.
const MAX_TILES: u64 = 65_535;

fn be32(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from(u32::from_be_bytes(
        d.get(at..at + 4)?.try_into().ok()?,
    )))
}

/// The codestream of `data`: the data itself, or the `jp2c` box of a JP2 file.
fn codestream(data: &[u8]) -> Option<&[u8]> {
    if data.starts_with(&[0xFF, 0x4F]) {
        return Some(data);
    }
    let mut rest = data;
    while let Some(len) = be32(rest, 0) {
        let kind = rest.get(4..8)?;
        let (header, len) = match len {
            0 => (8, rest.len() as u64),
            1 => (16, be32(rest, 8)? << 32 | be32(rest, 12)?),
            n => (8, n),
        };
        if len < header {
            return None;
        }
        let end = usize::try_from(len).ok()?.min(rest.len());
        if kind == b"jp2c" {
            return rest.get(header as usize..end);
        }
        rest = rest.get(end..)?;
    }
    None
}

/// Whether the header of the codestream in `data` (a bare one or a JP2 file's)
/// implies more tiles than a file can hold. A header that cannot be read is
/// left to the decoder.
pub(super) fn has_too_many_tiles(data: &[u8]) -> bool {
    let Some(cs) = codestream(data) else {
        return false;
    };
    if !cs.starts_with(&[0xFF, 0x4F, 0xFF, 0x51]) {
        return false;
    }
    // After SOC and SIZ's marker: Lsiz, Rsiz, then Xsiz, Ysiz, XOsiz, YOsiz,
    // XTsiz, YTsiz, XTOsiz and YTOsiz, four bytes each.
    let s = &cs[4..];
    let (Some(x), Some(y), Some(tw), Some(th), Some(tx0), Some(ty0)) = (
        be32(s, 4),
        be32(s, 8),
        be32(s, 20),
        be32(s, 24),
        be32(s, 28),
        be32(s, 32),
    ) else {
        return false;
    };
    if tw == 0 || th == 0 {
        return false;
    }
    let across = x.saturating_sub(tx0).div_ceil(tw);
    let down = y.saturating_sub(ty0).div_ceil(th);
    across.saturating_mul(down) > MAX_TILES
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SOC and a SIZ segment of one 8-bit component.
    fn siz(x: u32, y: u32, tile: (u32, u32)) -> Vec<u8> {
        let mut v = vec![0xFF, 0x4F, 0xFF, 0x51, 0, 41, 0, 0];
        for n in [x, y, 0, 0, tile.0, tile.1, 0, 0] {
            v.extend_from_slice(&n.to_be_bytes());
        }
        v.extend_from_slice(&[0, 1, 7, 1, 1]);
        v
    }

    #[test]
    fn the_tiles_of_the_grid_are_counted() {
        assert!(!has_too_many_tiles(&siz(4080, 4080, (16, 16))));
        // 256 x 256 tiles is one more than 16 bits name.
        assert!(has_too_many_tiles(&siz(4096, 4096, (16, 16))));
        assert!(has_too_many_tiles(&siz(u32::MAX, u32::MAX, (1, 1))));
        assert!(!has_too_many_tiles(&siz(u32::MAX, 1, (u32::MAX, 1))));
    }

    #[test]
    fn a_header_that_cannot_be_read_is_not_judged() {
        assert!(!has_too_many_tiles(b""));
        assert!(!has_too_many_tiles(&[0xFF, 0x4F, 0xFF, 0x51, 0, 41]));
        assert!(!has_too_many_tiles(&siz(100, 100, (0, 0))));
    }

    #[test]
    fn a_jp2_file_is_judged_by_its_codestream() {
        let cs = siz(u32::MAX, u32::MAX, (1, 1));
        let mut file = b"\0\0\0\x0cjP  \r\n\x87\n".to_vec();
        file.extend_from_slice(&(8 + cs.len() as u32).to_be_bytes());
        file.extend_from_slice(b"jp2c");
        file.extend_from_slice(&cs);
        assert!(has_too_many_tiles(&file));
    }
}
