//! Hex decoding and `.ndb` body parsing.
//!
//! An `.ndb` hex body may contain wildcards (`??`, `*`, `{n}`, `[a-b]`,
//! `(aa|bb)`). Literal bodies are decoded to bytes; bodies with wildcards
//! are returned as [`NdbPattern::Unsupported`] so callers can count them.

/// Result of parsing an `.ndb` hex body.
pub enum NdbPattern {
    /// A literal byte string, usable directly by the streaming matcher.
    Literal(Vec<u8>),
    /// Contains wildcard constructs not yet supported by the streaming
    /// matcher. Carries a human-readable reason.
    Unsupported(&'static str),
}

/// Parse the hex body of an `.ndb` signature.
pub fn parse_ndb_body(hex: &str) -> NdbPattern {
    let hex = hex.trim();
    if hex.is_empty() {
        return NdbPattern::Unsupported("empty body");
    }
    // Detect wildcard constructs.
    if hex.contains('*') {
        return NdbPattern::Unsupported("contains '*' wildcard");
    }
    if hex.contains('{') || hex.contains('[') || hex.contains('(') {
        return NdbPattern::Unsupported("contains {n}/[a-b]/(alt) construct");
    }
    if hex.contains("??") || hex.contains('?') {
        return NdbPattern::Unsupported("contains '?' nibble wildcard");
    }
    match decode_hex(hex) {
        Ok(bytes) => NdbPattern::Literal(bytes),
        Err(_) => NdbPattern::Unsupported("invalid hex"),
    }
}

/// Decode an even-length hex string into bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Ok(out)
}

/// Encode bytes as lowercase hex.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("invalid hex char {:?}", other as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        assert_eq!(
            decode_hex("aabb00ff").unwrap(),
            vec![0xAA, 0xBB, 0x00, 0xFF]
        );
        assert_eq!(encode_hex(&[0xAA, 0xBB, 0x00, 0xFF]), "aabb00ff");
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn ndb_literal_vs_wildcard() {
        assert!(matches!(parse_ndb_body("deadbeef"), NdbPattern::Literal(_)));
        assert!(matches!(
            parse_ndb_body("dead*beef"),
            NdbPattern::Unsupported(_)
        ));
        assert!(matches!(
            parse_ndb_body("dead??ef"),
            NdbPattern::Unsupported(_)
        ));
        assert!(matches!(
            parse_ndb_body("de{4}ad"),
            NdbPattern::Unsupported(_)
        ));
    }
}
