//! SWF (Adobe Flash) decompressor.
//!
//! An SWF movie opens with an 8-byte header: a 3-byte signature, a 1-byte
//! version, and a little-endian u32 `FileLength`, the *uncompressed* total size
//! (header included). The signature selects the body encoding from byte 8 on:
//! `FWS` = uncompressed, `CWS` = zlib (RFC1950), `ZWS` = LZMA. We rebuild an
//! uncompressed `FWS` movie so signatures match the inner bytes: keep the
//! 8-byte header (with the signature rewritten to `FWS`) and append the
//! decompressed body.
//!
//! `FWS` is already uncompressed, so there is nothing to unpack; only `CWS` and
//! `ZWS` are decoded, as they are read. An attacker-controlled `FileLength`
//! never drives an allocation: an LZMA dictionary over the buffer limit is a
//! limit reached, and the output is bounded by the scan budget as it flows.
use std::io::{BufReader, Cursor, Read};

use super::lzma::SansIo;
use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_stream};
use crate::{Budget, LimitHit};

/// Walk an SWF movie: the rebuilt `FWS` header, then the body decoded as it is
/// read. A non-SWF input or an `FWS` movie yields no member: its bytes are the
/// container's own, scanned as they are.
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let hdr = src.window(0, 17);
    if hdr.len() < 8 || (&hdr[0..3] != b"CWS" && &hdr[0..3] != b"ZWS") {
        return Ok(None);
    }
    budget.count_entry()?;
    let mut fws = Vec::with_capacity(8);
    fws.extend_from_slice(b"FWS");
    fws.extend_from_slice(&hdr[3..8]);
    let meta = MemberMeta {
        name: "movie.swf".to_string(),
        comp_size: (src.len() as u64).saturating_sub(8),
        size: Some(u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64),
        ..MemberMeta::default()
    };
    if &hdr[0..3] == b"CWS" {
        let body = BufReader::new(Reader::range(src, 8, src.len()));
        return match crate::inflate::zlib_reader(body) {
            Ok(Some(body)) => emit_stream(&meta, &mut Cursor::new(fws).chain(body), budget, visit),
            // Cut inside the zlib header: no byte of the body is here.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                emit_stream(&meta, &mut Cursor::new(fws), budget, visit)
            }
            _ => {
                let unsupported = MemberMeta {
                    unsupported: Some("SWF body is not a zlib stream"),
                    ..meta
                };
                Ok(visit(&unsupported, None, budget))
            }
        };
    }
    // ZWS / LZMA: 8 header + 4 comp-length + 5 LZMA props before the stream.
    let unsupported = MemberMeta {
        unsupported: Some("SWF LZMA decode unsupported"),
        reason_kind: Some(crate::tree::ReasonKind::Unsupported),
        ..meta.clone()
    };
    if hdr.len() < 17 {
        return Ok(visit(&unsupported, None, budget));
    }
    let file_length = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
    let want = file_length.saturating_sub(8);
    let declared = u32::from_le_bytes([hdr[13], hdr[14], hdr[15], hdr[16]]);
    let Some(dict) = window(declared, want, budget.limits().max_buffer_bytes) else {
        let over = MemberMeta {
            unsupported: Some(DICT_OVER_LIMIT),
            reason_kind: Some(crate::tree::ReasonKind::OVER_SIZE),
            ..meta
        };
        return Ok(visit(&over, None, budget));
    };
    let stream = Reader::range(src, 17, src.len());
    match lzma_rust2::LzmaStream::new_with_props(want, hdr[12], dict, None) {
        Ok(lzma) => {
            let mut body = Cursor::new(fws).chain(SansIo::new(stream, lzma));
            emit_stream(&meta, &mut body, budget, visit)
        }
        Err(_) => Ok(visit(&unsupported, None, budget)),
    }
}

/// Why a `ZWS` movie whose LZMA dictionary is over the buffer limit is not
/// decoded.
const DICT_OVER_LIMIT: &str =
    "SWF movie's LZMA dictionary is over the buffer limit (--max-object-bytes)";

/// The LZMA dictionary to allocate for a `ZWS` movie, or `None` when it is
/// over `max_buffer`. `declared` (the props header's field) and `want` (the
/// movie's `FileLength` less the 8-byte header) are both the file's word, and
/// the dictionary is allocated up front. One larger than the output is never
/// consulted, so `want` bounds it; past that the movie is refused, not decoded
/// with a smaller window, which fails on the first match reaching further back.
fn window(declared: u32, want: u64, max_buffer: u64) -> Option<u32> {
    (u64::from(declared).min(want) <= max_buffer).then(|| crate::bounded_dict(declared, want))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, Limits, extract};
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    /// Assemble an 8-byte SWF header for `sig` with a `FileLength` covering the
    /// (uncompressed) header + body.
    fn swf_header(sig: &[u8; 3], version: u8, body_len: usize) -> Vec<u8> {
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(sig);
        h.push(version);
        h.extend_from_slice(&((8 + body_len) as u32).to_le_bytes());
        h
    }

    #[test]
    fn cws_zlib_rebuilds_fws_with_payload() {
        // A tiny FWS movie whose body carries a marker, zlib-compressed into a CWS.
        let body = b"....MALWARETEST....".to_vec();
        let mut cws = swf_header(b"CWS", 13, body.len());
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&body).unwrap();
        cws.extend_from_slice(&enc.finish().unwrap());

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Swf, &cws, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        let m = &entries[0].data;
        // Rebuilt movie is an uncompressed FWS with the original header tail.
        assert_eq!(&m[0..3], b"FWS");
        assert_eq!(m[3], 13); // version preserved
        assert_eq!(&m[4..8], &((8 + body.len()) as u32).to_le_bytes());
        assert!(
            m.windows(11).any(|w| w == b"MALWARETEST"),
            "marker recovered in decompressed movie"
        );
    }

    #[test]
    fn fws_yields_nothing() {
        // Already uncompressed: no member to extract.
        let mut fws = swf_header(b"FWS", 6, 4);
        fws.extend_from_slice(b"body");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Swf, &fws, &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn cws_bomb_trips_budget() {
        let body = vec![0u8; 4096];
        let mut cws = swf_header(b"CWS", 13, body.len());
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&body).unwrap();
        cws.extend_from_slice(&enc.finish().unwrap());
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: 1024,
            max_compression_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Swf, &cws, &mut budget).unwrap_err();
        assert!(err.reason.contains("budget") || err.reason.contains("extracted"));
    }

    #[test]
    fn malformed_zws_is_unsupported_not_panic() {
        // ZWS magic with a garbage LZMA stream must not panic and must surface as
        // an unsupported member.
        let mut zws = swf_header(b"ZWS", 13, 100);
        zws.extend_from_slice(&50u32.to_le_bytes()); // comp length
        zws.extend_from_slice(&[0x5d, 0x00, 0x00, 0x10, 0x00]); // props + dict
        zws.extend_from_slice(&[0xffu8; 32]); // junk stream
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Swf, &zws, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].unsupported.is_some());
    }

    /// A `ZWS` movie whose LZMA stream cannot be started is reported as a
    /// codec not decoded: one cut inside its header, and one whose properties
    /// byte is out of range.
    #[test]
    fn an_lzma_stream_that_cannot_start_is_reported_as_unsupported() {
        let cut = swf_header(b"ZWS", 13, 100);
        let mut bad_props = swf_header(b"ZWS", 13, 100);
        bad_props.extend_from_slice(&50u32.to_le_bytes());
        bad_props.extend_from_slice(&[0xe1, 0x00, 0x00, 0x10, 0x00]);
        bad_props.extend_from_slice(&[0u8; 32]);
        for (what, zws) in [("cut", cut), ("bad props", bad_props)] {
            let mut budget = Budget::new(Limits::default());
            let entries = extract(Format::Swf, &zws, &mut budget).unwrap();
            assert_eq!(entries.len(), 1, "{what}: {entries:?}");
            assert!(entries[0].data.is_empty(), "{what}: {entries:?}");
            assert_eq!(
                entries[0].unsupported,
                Some("SWF LZMA decode unsupported"),
                "{what}"
            );
            assert_eq!(
                entries[0].reason_kind,
                Some(crate::tree::ReasonKind::Unsupported),
                "{what}"
            );
        }
    }

    #[test]
    fn short_and_non_swf_input_is_ignored() {
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Swf, b"CW", &mut budget).unwrap().is_empty());
        assert!(
            extract(Format::Swf, b"NOTASWF!", &mut budget)
                .unwrap()
                .is_empty()
        );
    }

    // A `ZWS` header carries two attacker-chosen sizes, and the LZMA dictionary
    // is allocated before a single byte is decoded. Neither may set that size.
    #[test]
    fn a_dictionary_over_the_buffer_limit_is_refused() {
        let max_buffer = Limits::default().max_buffer_bytes;
        // The sizes from a movie that asked for a 2.7 GiB dictionary by declaring
        // a ~4 GiB FileLength: refused, not allocated.
        assert_eq!(window(0xA1A1_C32B, 0xF04A_0957 - 8, max_buffer), None);
        // A dictionary under both bounds is used as it is.
        assert_eq!(window(1 << 16, 1 << 20, max_buffer), Some(1 << 16));
        // The declared output bounds it: no more history than output.
        assert_eq!(window(u32::MAX, 1 << 20, max_buffer), Some(1 << 20));

        // Through the walk: a limit reached, nothing decoded.
        let mut zws = swf_header(b"ZWS", 13, 1 << 20);
        zws.extend_from_slice(&50u32.to_le_bytes());
        zws.extend_from_slice(&[0x5d, 0x00, 0x00, 0x10, 0x00]); // a 1 MiB dictionary
        zws.extend_from_slice(&[0u8; 32]);
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: 64 * 1024,
            ..Default::default()
        });
        let entries = extract(Format::Swf, &zws, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].unsupported, Some(DICT_OVER_LIMIT));
        assert!(entries[0].data.is_empty());
    }
}
