//! Base64 (RFC 4648) decoding for binary data embedded in XML.

/// Decodes `s`, ignoring white space; `None` on any other character that is
/// not in the alphabet, or past `max` bytes of output. Padding is optional.
pub fn decode(s: &str, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((s.len() / 4 * 3).min(max));
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
            if out.len() > max {
                return None;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_with_and_without_padding() {
        assert_eq!(decode("aGVsbG8=", 100).unwrap(), b"hello");
        assert_eq!(decode("aGVs\nbG8", 100).unwrap(), b"hello");
        assert_eq!(decode("", 100).unwrap(), b"");
        assert_eq!(decode("aGVs*G8", 100), None);
        // Both alphabets: 62 and 63 are `+/` or `-_`.
        assert_eq!(decode("+/8=", 100).unwrap(), [0xFB, 0xFF]);
        assert_eq!(decode("-_8=", 100).unwrap(), [0xFB, 0xFF]);
        assert_eq!(decode("aGVsbG8=", 3), None);
    }
}
