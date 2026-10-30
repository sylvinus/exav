//! Snappy decompression of one raw block (the format description in
//! Google's snappy repository, format_description.txt): a varint of the
//! uncompressed length, then literals and back references. IWA streams use
//! raw blocks inside chunks of their own, without the framing format's
//! stream identifier or checksums.

/// Decompresses `src`, appending to `out`, refusing to grow `out` past
/// `limit` bytes. `None` when the block is damaged.
pub fn decompress(src: &[u8], out: &mut Vec<u8>, limit: usize) -> Option<()> {
    let mut p = 0usize;
    let mut len: u64 = 0;
    let mut shift = 0;
    loop {
        let b = *src.get(p)?;
        p += 1;
        len |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    let base = out.len();
    let end = base.checked_add(usize::try_from(len).ok()?)?;
    if end > limit {
        return None;
    }
    out.reserve(end - base);
    while p < src.len() {
        let tag = src[p];
        p += 1;
        match tag & 3 {
            0 => {
                let mut n = usize::from(tag >> 2);
                if n >= 60 {
                    let extra = n - 59;
                    let b = src.get(p..p + extra)?;
                    n = b
                        .iter()
                        .rev()
                        .fold(0usize, |a, &x| (a << 8) | usize::from(x));
                    p += extra;
                }
                let n = n + 1;
                let lit = src.get(p..p.checked_add(n)?)?;
                if out.len() + n > end {
                    return None;
                }
                out.extend_from_slice(lit);
                p += n;
            }
            kind => {
                let (n, off) = match kind {
                    1 => {
                        let b = *src.get(p)?;
                        p += 1;
                        (
                            usize::from((tag >> 2) & 7) + 4,
                            usize::from(tag >> 5) << 8 | usize::from(b),
                        )
                    }
                    2 => {
                        let b = src.get(p..p + 2)?;
                        p += 2;
                        (
                            usize::from(tag >> 2) + 1,
                            usize::from(u16::from_le_bytes([b[0], b[1]])),
                        )
                    }
                    _ => {
                        let b = src.get(p..p + 4)?;
                        p += 4;
                        (
                            usize::from(tag >> 2) + 1,
                            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize,
                        )
                    }
                };
                if off == 0 || off > out.len() - base || out.len() + n > end {
                    return None;
                }
                let start = out.len() - off;
                if off >= n {
                    out.extend_from_within(start..start + n);
                } else {
                    // An overlapping copy repeats the last `off` bytes.
                    for i in 0..n {
                        let b = out[start + i];
                        out.push(b);
                    }
                }
            }
        }
    }
    (out.len() == end).then_some(())
}

/// Compresses `src` as literals only: a valid block, for tests.
#[cfg(any(test, feature = "office-test-util"))]
pub fn literal_block(src: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    let mut n = src.len() as u64;
    loop {
        let b = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    for chunk in src.chunks(60) {
        out.push(((chunk.len() - 1) as u8) << 2);
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_copies() {
        // "abcabcabcd": a literal "abc", a copy of 6 at offset 3, a literal "d".
        let block = [10, 2 << 2, b'a', b'b', b'c', 0b0000_1001, 3, 0, b'd'];
        let mut out = vec![];
        decompress(&block, &mut out, 100).unwrap();
        assert_eq!(out, b"abcabcabcd");
        let mut out = vec![];
        let data =
            b"hello hello hello, a longer literal of more than sixty bytes, to use the long form";
        decompress(&literal_block(data), &mut out, 1000).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn damaged_blocks_are_refused() {
        let mut out = vec![];
        // A copy before any output.
        assert!(decompress(&[4, 0b0000_0001, 1], &mut out, 100).is_none());
        // A length past the limit.
        assert!(decompress(&[0xFF, 0xFF, 0xFF, 0x7F], &mut out, 100).is_none());
        // Truncated literal.
        assert!(decompress(&[5, 4 << 2, b'a'], &mut out, 100).is_none());
    }
}
