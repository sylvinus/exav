//! Minimal, allocation-free DER (ASN.1) reader — **vendored** to keep the tree
//! `unsafe`-free and dependency-light (no `der`/`rsa`/`nom`/`x509` crates). Only
//! the definite-length subset needed for Authenticode / X.509 is implemented;
//! every operation is bounds-checked and panic-free (no indexing, no slicing
//! without a length guard).

// ASN.1 universal tags we reference.
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OID: u8 = 0x06;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;
/// Context-specific, constructed, tag number `n`: `[n] IMPLICIT/EXPLICIT`.
pub(crate) const fn context(n: u8) -> u8 {
    0xA0 | n
}

/// A single tag-length-value triple, borrowing the input.
pub(crate) struct Tlv<'a> {
    /// The identifier octet (e.g. [`SEQUENCE`]).
    pub tag: u8,
    /// The value bytes (content), excluding tag and length.
    pub content: &'a [u8],
    /// The full encoding (tag + length + content) — used to SHA-1 a certificate's
    /// exact DER for its thumbprint.
    pub full: &'a [u8],
}

/// Read the definite-form length at the front of `input`, returning
/// `(length, rest_after_length_bytes)`. Rejects the indefinite form (not valid
/// DER) and lengths whose header claims more than 4 bytes (> 4 GiB).
fn read_len(input: &[u8]) -> Option<(usize, &[u8])> {
    let (&b0, rest) = input.split_first()?;
    if b0 < 0x80 {
        return Some((b0 as usize, rest)); // short form
    }
    let n = (b0 & 0x7f) as usize;
    if n == 0 || n > 4 || n > rest.len() {
        return None; // indefinite form, or implausibly large
    }
    let mut len = 0usize;
    for &b in &rest[..n] {
        len = (len << 8) | b as usize;
    }
    Some((len, &rest[n..]))
}

/// Read one TLV from the front of `input`, returning `(tlv, remaining)`.
/// `None` on any truncation or malformed length.
pub(crate) fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, after_tag) = input.split_first()?;
    let (len, after_len) = read_len(after_tag)?;
    if len > after_len.len() {
        return None;
    }
    let content = &after_len[..len];
    let consumed = input.len() - after_len.len() + len;
    Some((
        Tlv {
            tag,
            content,
            full: &input[..consumed],
        },
        &input[consumed..],
    ))
}

/// The single top-level TLV of a complete DER object (ignoring trailing bytes).
pub(crate) fn top(input: &[u8]) -> Option<Tlv<'_>> {
    read(input).map(|(tlv, _)| tlv)
}

/// Iterator over the child TLVs contained in a constructed value's `content`.
/// Stops at the first malformed child (so a truncated tail can't panic).
pub(crate) struct Children<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Children<'a> {
    type Item = Tlv<'a>;
    fn next(&mut self) -> Option<Tlv<'a>> {
        let (tlv, rest) = read(self.rest)?;
        self.rest = rest;
        Some(tlv)
    }
}

/// Iterate the children of a constructed TLV's content.
pub(crate) fn children(content: &[u8]) -> Children<'_> {
    Children { rest: content }
}

/// Find the first child TLV with tag `tag` inside `content`.
pub(crate) fn find(content: &[u8], tag: u8) -> Option<Tlv<'_>> {
    children(content).find(|t| t.tag == tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_and_long_form_lengths() {
        // SEQUENCE { INTEGER 1 } short form.
        let seq = [0x30, 0x03, 0x02, 0x01, 0x01];
        let t = top(&seq).unwrap();
        assert_eq!(t.tag, SEQUENCE);
        let int = find(t.content, INTEGER).unwrap();
        assert_eq!(int.content, &[0x01]);

        // Long form length: 0x81 0x80 => 128-byte content.
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend(std::iter::repeat_n(0xAB, 128));
        let t = top(&long).unwrap();
        assert_eq!(t.tag, OCTET_STRING);
        assert_eq!(t.content.len(), 128);
    }

    #[test]
    fn rejects_truncated_and_indefinite() {
        assert!(read(&[0x30, 0x05, 0x00]).is_none()); // claims 5, has 1
        assert!(read(&[0x30, 0x80]).is_none()); // indefinite form
        assert!(read(&[]).is_none());
        assert!(read(&[0x30]).is_none()); // no length
    }

    #[test]
    fn children_stops_cleanly_on_bad_tail() {
        // Two INTEGERs then a truncated third.
        let content = [0x02, 0x01, 0x0A, 0x02, 0x01, 0x0B, 0x02, 0x05];
        let got: Vec<_> = children(&content).map(|t| t.content.to_vec()).collect();
        assert_eq!(got, vec![vec![0x0A], vec![0x0B]]);
    }

    #[test]
    fn full_spans_the_whole_encoding() {
        let seq = [0x30, 0x03, 0x02, 0x01, 0x2A, 0xFF, 0xFF];
        let (t, rest) = read(&seq).unwrap();
        assert_eq!(t.full, &[0x30, 0x03, 0x02, 0x01, 0x2A]);
        assert_eq!(rest, &[0xFF, 0xFF]);
    }
}
