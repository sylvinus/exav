//! exav's own literal signature format, `Name=HEX` (`.db`).

/// The EICAR anti-virus test string, assembled at runtime.
///
/// Re-exported rather than redefined so the sequence has exactly one home in the
/// workspace: see [`exav_unpack::eicar`] for why it is never stored as a
/// literal.
pub use exav_unpack::eicar;

/// Parse a `Name=HEX` database into `(name, bytes)` pairs, and the number of
/// lines skipped because they are not a name and plain hex: no `=`, or a body
/// that is not an even number of hex digits (one with a wildcard, say).
pub fn parse_simple(text: &str) -> (Vec<(String, Vec<u8>)>, usize) {
    let mut patterns = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = line
            .split_once('=')
            .and_then(|(name, hex)| Some((name.trim().to_string(), crate::hexsig::decode_hex(hex).ok()?)));
        match parsed {
            Some(p) => patterns.push(p),
            None => skipped += 1,
        }
    }
    (patterns, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_db_lines_parse() {
        let got = parse_simple("# comment\nSig.A =4142\n\nno separator\nSig.W=41??\nSig.B=ff\n");
        assert_eq!(
            got,
            (
                vec![
                    ("Sig.A".to_string(), b"AB".to_vec()),
                    ("Sig.B".to_string(), vec![0xff])
                ],
                2
            )
        );
    }
}
