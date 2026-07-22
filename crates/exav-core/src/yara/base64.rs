//! base64 sub-pattern generation for the `base64` / `base64wide` modifiers.
//
// Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X.
// Specifically, `base64_patterns` is a close port of
// `lib/src/compiler/base64.rs` from yara-x. The algorithm and its supporting
// documentation are reproduced with attribution as permitted by the license.
// yara-x is Copyright (c) The YARA-X Authors; this crate does not use the
// "YARA-X" name or its authors' names to endorse or promote exav.

use base64::Engine;

/// Given a slice of bytes, returns up to three strings of which one must be
/// present in the base64-encoded version of any buffer that contains the
/// slice, together with the amount of left-padding (0, 1 or 2) each assumes.
///
/// See yara-x's `lib/src/compiler/base64.rs` for the full derivation. If some
/// string `S` contains `s`, then `base64(S)` must contain one of the returned
/// patterns.
///
/// # Panics
///
/// Panics if `s.len() <= 1`, or if `alphabet` is provided but invalid.
pub(crate) fn base64_patterns(s: &[u8], alphabet: Option<&str>) -> Vec<(u8, Vec<u8>)> {
    assert!(s.len() > 1);

    let alphabet = alphabet.map_or(base64::alphabet::STANDARD, |a| {
        base64::alphabet::Alphabet::new(a).unwrap()
    });

    let base64_engine =
        base64::engine::GeneralPurpose::new(&alphabet, base64::engine::general_purpose::NO_PAD);

    // Prepend "XX" to the original string. These two characters are irrelevant;
    // the portion of the base64 result affected by them is stripped from the
    // final results. They allow computing base64 with 1 and 2 extra bytes to
    // the left of the pattern.
    let mut pattern: Vec<u8> = Vec::with_capacity(3 + s.len());
    pattern.extend_from_slice(b"XX");
    pattern.extend_from_slice(s);

    let mut base64_patterns = Vec::new();

    let mut buf = vec![0; base64::encoded_len(pattern.len(), false).unwrap()];

    for i in 0..=2_u8 {
        let pattern = &pattern[i as usize..];

        let base64_len = base64_engine.encode_slice(pattern, &mut buf).unwrap();
        buf.truncate(base64_len);

        // If the pattern's length is not a multiple of 3, drop the right-most
        // character from the produced base64.
        let right_trim = usize::from(!pattern.len().is_multiple_of(3));

        let range = match i {
            0 => 3..base64_len - right_trim,
            1 => 2..base64_len - right_trim,
            2 => 0..base64_len - right_trim,
            _ => unreachable!(),
        };

        base64_patterns.push((2 - i, buf[range].to_vec()));
    }

    base64_patterns
}

#[cfg(test)]
mod tests {
    use super::base64_patterns;

    #[test]
    fn base64() {
        assert_eq!(
            base64_patterns(b"fooba", None),
            vec![
                (2, b"mb29iY".to_vec()),
                (1, b"Zvb2Jh".to_vec()),
                (0, b"Zm9vYm".to_vec())
            ]
        );
        assert_eq!(
            base64_patterns(b"foobar", None),
            vec![
                (2, b"mb29iYX".to_vec()),
                (1, b"Zvb2Jhc".to_vec()),
                (0, b"Zm9vYmFy".to_vec())
            ]
        );
        assert_eq!(
            base64_patterns(
                b"foobar",
                Some("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
            ),
            vec![
                (2, b"kZ07gWV".to_vec()),
                (1, b"XtZ0Hfa".to_vec()),
                (0, b"Xk7tWkDw".to_vec())
            ]
        );
    }
}
