//! HWP3 — Hangul Word Processor v3 documents.
//!
//! exav had no code for it, which is the worst shape a gap can take: the body is
//! deflate-compressed, so a raw pattern scan over the file matched nothing and it
//! came back **`OK`**.
//!
//! The document is a fixed-size preamble followed by a single compressed stream
//! holding the fonts, styles, paragraphs and any embedded objects. Decompressing
//! it is what makes the content scannable; parsing the paragraph structure would
//! buy names and boundaries, not reach.
//!
//! Layout derived from `java-hwp` (Apache-2.0, see NOTICE), which documents the
//! preamble offsets. Only v3 is handled here: HWP5 is an OLE2 compound file and
//! reaches exav's existing OLE path instead.

use crate::{Budget, Entry, Format, LimitHit, Sink};

/// Byte offsets within the preamble, all fixed by the format.
mod at {
    /// `HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05`.
    pub const SIGNATURE_LEN: usize = 30;
    /// Non-zero when the document is password-protected.
    pub const PASSWORD: usize = SIGNATURE_LEN + 96;
    /// Non-zero when the body stream is deflate-compressed.
    pub const COMPRESSED: usize = PASSWORD + 2 + 26;
    /// Length of the variable info block that follows the document summary.
    pub const INFO_BLOCK_LEN: usize = COMPRESSED + 2;
    /// The 1008-byte document summary sits between the length and the block.
    pub const SUMMARY_LEN: usize = 1008;
}

pub(crate) fn extract_hwp3<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !super::sniff::is(data, Format::Hwp3) {
        return Ok(None);
    }

    let report = |reason: &'static str, encrypted: bool, budget: &mut Budget, visit: Sink<R>| {
        budget.count_entry()?;
        Ok(visit(
            Entry::unsupported(
                "hwp3-document".to_string(),
                data.len() as u64,
                encrypted,
                reason,
            ),
            budget,
        ))
    };

    let Some(pw) = data
        .get(at::PASSWORD..at::PASSWORD + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
    else {
        return report(
            "HWP3 document is too short to hold its own header",
            false,
            budget,
            visit,
        );
    };
    if pw != 0 {
        // The body is encrypted with the user's password; exav has no key.
        return report(
            "password-protected HWP3 document: its text and embedded objects were not examined",
            true,
            budget,
            visit,
        );
    }

    let compressed = data.get(at::COMPRESSED).is_some_and(|&b| b != 0);
    let Some(info_len) = data
        .get(at::INFO_BLOCK_LEN..at::INFO_BLOCK_LEN + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    else {
        return report(
            "HWP3 document is too short to hold its own header",
            false,
            budget,
            visit,
        );
    };

    let body_at = at::INFO_BLOCK_LEN + 2 + at::SUMMARY_LEN + info_len;
    let Some(body) = data.get(body_at..) else {
        // The preamble declares an info block the file does not contain: those
        // bytes are absent rather than hidden, so there is nothing to recover.
        return report(
            "HWP3 document ends before its body begins",
            false,
            budget,
            visit,
        );
    };
    if body.is_empty() {
        return report("HWP3 document has an empty body", false, budget, visit);
    }

    budget.count_entry()?;
    let cap = budget.reserve()?;
    let entry = if compressed {
        match inflate(body, cap) {
            Some(s) if !s.over_cap => {
                crate::ratio_guard(body.len() as u64, s.data.len() as u64, budget)?;
                budget.commit(s.data.len() as u64);
                // The body runs to the end of the file, so a stream that runs
                // out of input was cut there: only damage leaves bytes unread.
                let why = s.undecoded.then_some(
                    "HWP3 body failed to decompress part way; the bytes before the failure \
                     were scanned",
                );
                Entry {
                    unsupported: why,
                    ..Entry::new("hwp3-body".to_string(), s.data)
                }
            }
            Some(_) => Entry::unsupported(
                "hwp3-body".to_string(),
                body.len() as u64,
                false,
                "HWP3 body exceeds the per-member decompression budget",
            ),
            None => Entry::unsupported(
                "hwp3-body".to_string(),
                body.len() as u64,
                false,
                "HWP3 body would not decompress",
            ),
        }
    } else {
        if body.len() as u64 > cap {
            return Err(LimitHit::new("hwp3 body exceeds budget".to_string()));
        }
        budget.commit(body.len() as u64);
        Entry::new("hwp3-body".to_string(), body.to_vec())
    };
    Ok(visit(entry, budget))
}

/// Inflate the body. Writers differ on whether the stream carries a zlib
/// wrapper, so both are tried rather than assuming one and reporting the other
/// as undecodable. A stream that decodes whole wins; failing that, one that
/// only ran out of input (a body cut short); failing that, what decoded
/// before an error. zlib first each time.
fn inflate(body: &[u8], cap: u64) -> Option<crate::Salvaged> {
    let rank = |s: &crate::Salvaged| match (s.undecoded, s.cut_short) {
        (false, false) => 0,
        (false, true) => 1,
        _ => 2,
    };
    let zlib = crate::inflate::zlib_body(body)
        .map(|z| crate::salvage(z, cap))
        .filter(|s| !s.data.is_empty());
    if zlib.as_ref().is_some_and(|s| rank(s) == 0) {
        return zlib;
    }
    let raw = Some(crate::salvage(crate::inflate::Inflate::new(body), cap))
        .filter(|s| !s.data.is_empty());
    // `min_by_key` keeps the first of equals.
    [zlib, raw].into_iter().flatten().min_by_key(rank)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;
    use std::io::Write;

    // The magic itself is tested in `formats::sniff`, which owns it.

    fn members(blob: &[u8]) -> Vec<Entry> {
        let mut b = Budget::new(Limits::default());
        let mut seen = Vec::new();
        let _ = extract_hwp3(blob, &mut b, &mut |e: Entry, _: &mut Budget| {
            seen.push(e);
            None::<()>
        });
        seen
    }

    /// A document built to the documented preamble layout. This validates the
    /// offsets against themselves, so it proves the *parser* matches the layout
    /// as recorded — not that the layout is right. The layout's authority is
    /// `java-hwp`. A fixture this crate wrote can only prove the decoder is
    /// self-consistent, which is why the real-sample check matters.
    fn build(compressed: bool, password: u16, info_len: usize, body: &[u8]) -> Vec<u8> {
        let mut v = b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05".to_vec();
        assert_eq!(v.len(), at::SIGNATURE_LEN);
        v.resize(at::PASSWORD, 0);
        v.extend_from_slice(&password.to_le_bytes());
        v.resize(at::COMPRESSED, 0);
        v.push(compressed as u8);
        v.resize(at::INFO_BLOCK_LEN, 0);
        v.extend_from_slice(&(info_len as u16).to_le_bytes());
        v.resize(v.len() + at::SUMMARY_LEN + info_len, 0);
        if compressed {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(body).unwrap();
            v.extend_from_slice(&e.finish().unwrap());
        } else {
            v.extend_from_slice(body);
        }
        v
    }

    #[test]
    fn a_compressed_body_is_decompressed_and_scannable() {
        // The point of the whole module: the payload is behind deflate, so
        // without this a signature in the text can never match.
        let secret = crate::eicar();
        let seen = members(&build(true, 0, 4, secret));
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].unsupported.is_none(), "{seen:?}");
        assert_eq!(seen[0].data, secret, "the body must come back intact");
    }

    #[test]
    fn an_uncompressed_body_is_emitted_as_is() {
        let body = b"plain hwp3 body bytes";
        let seen = members(&build(false, 0, 0, body));
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].data, body);
    }

    #[test]
    fn the_info_block_length_shifts_where_the_body_starts() {
        // Getting this wrong slices into the summary and yields garbage that
        // still "decompresses" for some inputs — so it is pinned explicitly.
        let body = b"body after a long info block";
        let seen = members(&build(true, 0, 257, body));
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].data, body);
    }

    #[test]
    fn a_password_protected_document_reports_and_yields_nothing() {
        let seen = members(&build(true, 1, 4, b"anything"));
        assert_eq!(seen.len(), 1);
        assert!(seen[0].encrypted, "must read as password-protected");
        assert!(seen[0].data.is_empty(), "no plaintext may be produced");
    }

    #[test]
    fn a_body_that_will_not_decompress_is_reported_not_dropped() {
        // The zlib header kept, the deflate data after it not deflate.
        let mut v = build(true, 0, 4, b"ignored");
        let body = at::INFO_BLOCK_LEN + 2 + at::SUMMARY_LEN + 4;
        v.truncate(body + 2);
        v.extend_from_slice(&[0xFF; 16]);
        let seen = members(&v);
        assert_eq!(seen.len(), 1);
        assert!(seen[0].unsupported.is_some(), "{seen:?}");
    }

    #[test]
    fn a_truncated_document_is_reported_never_silently_clean() {
        for len in [30usize, 100, 130, 200] {
            let mut v = build(true, 0, 4, b"body");
            v.truncate(len);
            let seen = members(&v);
            assert_eq!(seen.len(), 1, "len {len}: {seen:?}");
            assert!(
                seen[0].unsupported.is_some(),
                "len {len} must be reported: {seen:?}"
            );
        }
    }

    #[test]
    fn hostile_preamble_values_never_panic() {
        // `info_len` is attacker-controlled and is added to a fixed offset.
        for info_len in [0usize, 1, 0xFFFF] {
            let v = build(true, 0, 0, b"x");
            let mut v2 = v.clone();
            v2[at::INFO_BLOCK_LEN..at::INFO_BLOCK_LEN + 2]
                .copy_from_slice(&(info_len as u16).to_le_bytes());
            let _ = members(&v2);
        }
    }
}
