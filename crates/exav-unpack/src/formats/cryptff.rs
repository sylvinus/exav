//! CryptFF: a 16-byte header, then the content with every byte XORed with 0xFF.
//! The header is the 8-byte magic and 8 bytes that do not change the decoding;
//! there is no key and no size field. No specification is published: this is
//! what a reference scanner does with the format, measured on samples (random
//! second halves of the header, size-like values, content of every byte value
//! up to 300000 bytes).
//!
//! The content is decoded as it is read, so it is never held here. A file cut
//! inside the header has no content to decode and is reported as damaged.
use std::io::{self, Read};

use crate::source::{ByteSource, Reader};
use crate::stream::{Visit, emit_stream, single_meta};
use crate::{Budget, LimitHit};

const HEADER: usize = 16;

pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    budget.count_entry()?;
    if src.len() < HEADER {
        let meta = single_meta("cryptff-content", src, Some("CryptFF header cut short"));
        return Ok(visit(&meta, None, budget));
    }
    emit_stream(
        &single_meta("cryptff-content", src, None),
        &mut Unxor(Reader::range(src, HEADER, src.len())),
        budget,
        visit,
    )
}

/// The bytes of `R` with every bit flipped.
struct Unxor<R>(R);

impl<R: Read> Read for Unxor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(buf)?;
        for b in &mut buf[..n] {
            *b ^= 0xFF;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{Member, MemberMeta, walk as walk_format};
    use crate::{Format, Limits};

    const MAGIC: [u8; 8] = [0xB6, 0xB9, 0xAC, 0xAE, 0xFE, 0xFF, 0xFF, 0xFF];

    /// A CryptFF file: the magic, the 8 bytes `second`, the content flipped.
    fn encode(second: [u8; 8], content: &[u8]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.extend(second);
        v.extend(content.iter().map(|b| b ^ 0xFF));
        v
    }

    /// Every member `(meta, bytes)` of `blob` under `limits`, a failed read of
    /// a member being a panic.
    fn members_under(blob: &[u8], limits: Limits) -> Result<Vec<(MemberMeta, Vec<u8>)>, LimitHit> {
        let mut budget = Budget::new(limits);
        let mut seen = Vec::new();
        walk_format(
            Format::CryptFf,
            &blob,
            &mut budget,
            &mut |meta, content, budget| {
                let bytes = match content {
                    Some(Member::Stream(r)) => {
                        let mut v = Vec::new();
                        let _ = r.read_to_end(&mut v);
                        v
                    }
                    Some(m) => m.into_bytes(meta, budget).unwrap().0,
                    None => Vec::new(),
                };
                seen.push((meta.clone(), bytes));
                None::<()>
            },
        )?;
        Ok(seen)
    }

    fn members(blob: &[u8]) -> Vec<(MemberMeta, Vec<u8>)> {
        members_under(blob, Limits::default()).unwrap()
    }

    #[test]
    fn the_content_is_the_bytes_after_the_header_flipped() {
        let content: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
        let seen = members(&encode([0; 8], &content));
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.name, "cryptff-content");
        assert_eq!(seen[0].0.unsupported, None);
        assert!(!seen[0].0.encrypted);
        assert!(seen[0].1 == content, "decoded content differs");
    }

    #[test]
    fn the_second_half_of_the_header_does_not_change_the_content() {
        let content = b"payload that only the decoded bytes show";
        for second in [[0; 8], [0xFF; 8], *b"ABCDEFGH", [1, 2, 3, 4, 5, 6, 7, 8]] {
            let seen = members(&encode(second, content));
            assert_eq!(seen[0].1, content, "second half {second:?}");
        }
        // Not a size: one claiming less or more than the content has changes nothing.
        for size in [0u64, 10, content.len() as u64, 1 << 40] {
            let seen = members(&encode(size.to_le_bytes(), content));
            assert_eq!(seen[0].1, content, "size {size}");
        }
    }

    #[test]
    fn a_header_alone_is_an_empty_member() {
        let seen = members(&encode([0; 8], b""));
        assert_eq!(seen.len(), 1);
        assert!(seen[0].1.is_empty());
        assert_eq!(seen[0].0.unsupported, None);
        let seen = members(&encode([0; 8], b"x"));
        assert_eq!(seen[0].1, b"x");
    }

    #[test]
    fn a_header_cut_short_is_reported_not_passed_as_empty() {
        for len in 8..HEADER {
            let mut blob = MAGIC.to_vec();
            blob.extend([0u8; 8]);
            blob.truncate(len);
            let seen = members(&blob);
            assert_eq!(seen.len(), 1, "len {len}");
            assert!(seen[0].0.unsupported.is_some(), "len {len}");
            assert!(seen[0].1.is_empty(), "len {len}");
        }
    }

    #[test]
    fn the_content_is_decoded_as_it_is_read_under_the_scan_budget() {
        let content = vec![0x41u8; 100_000];
        let blob = encode([0; 8], &content);
        let limits = Limits {
            max_scanned_bytes: 50_000,
            ..Limits::default()
        };
        let err = members_under(&blob, limits).unwrap_err();
        let said = format!("{err:?}");
        assert!(said.contains("exceeds scan budget"), "{said}");
    }

    #[test]
    fn the_member_counts_toward_the_member_limit() {
        let limits = Limits {
            max_members: 0,
            ..Limits::default()
        };
        assert!(members_under(&encode([0; 8], b"x"), limits).is_err());
    }

    #[test]
    fn every_byte_value_round_trips_through_a_small_reader_buffer() {
        // A read of one byte at a time reaches the flip the same way.
        let content: Vec<u8> = (0..=255u8).collect();
        let blob = encode([9; 8], &content);
        let mut r = Unxor(Reader::range(&blob, HEADER, blob.len()));
        let mut out = Vec::new();
        let mut one = [0u8; 1];
        while r.read(&mut one).unwrap() == 1 {
            out.push(one[0]);
        }
        assert_eq!(out, content);
    }
}
