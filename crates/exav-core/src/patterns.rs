//! exav's own literal signature format, `Name=HEX` (`.db`).

/// The EICAR anti-virus test string, assembled at runtime.
///
/// Re-exported rather than redefined so the sequence has exactly one home in the
/// workspace — see [`exav_unpack::eicar`] for why it is never stored as a
/// literal.
pub use exav_unpack::eicar;

/// Parse a `Name=HEX` database into `(name, bytes)` pairs.
pub fn parse_simple(text: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut patterns = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, hex) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected Name=HEX", i + 1))?;
        let bytes = crate::hexsig::decode_hex(hex).map_err(|e| format!("line {}: {e}", i + 1))?;
        patterns.push((name.trim().to_string(), bytes));
    }
    Ok(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_db_lines_parse() {
        let got = parse_simple("# comment\nSig.A =4142\n\nSig.B=ff\n").unwrap();
        assert_eq!(
            got,
            vec![
                ("Sig.A".to_string(), b"AB".to_vec()),
                ("Sig.B".to_string(), vec![0xff])
            ]
        );
        assert!(parse_simple("no separator").is_err());
    }
}
