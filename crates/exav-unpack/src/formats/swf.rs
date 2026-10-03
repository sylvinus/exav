//! SWF (Adobe Flash) decompressor.
//!
//! An SWF movie opens with an 8-byte header: a 3-byte signature, a 1-byte
//! version, and a little-endian u32 `FileLength` — the *uncompressed* total size
//! (header included). The signature selects the body encoding from byte 8 on:
//! `FWS` = uncompressed, `CWS` = zlib (RFC1950), `ZWS` = LZMA. We rebuild an
//! uncompressed `FWS` movie so signatures match the inner bytes — keep the
//! 8-byte header (with the signature rewritten to `FWS`) and append the
//! decompressed body.
//!
//! `FWS` is already uncompressed, so there is nothing to unpack; only `CWS` and
//! `ZWS` are decoded, as they are read. An attacker-controlled `FileLength`
//! never drives an allocation: the LZMA dictionary is clamped to the buffer
//! limit, and the output is bounded by the scan budget as it flows.
use std::io::{Cursor, Read};

use crate::source::{ByteSource, Reader};
use crate::stream::{emit_stream, MemberMeta, Visit};
use crate::{Budget, LimitHit};

/// Walk an SWF movie: the rebuilt `FWS` header, then the body decoded as it is
/// read. A non-SWF input or an `FWS` movie yields no member: its bytes are the
/// container's own, scanned as they are.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
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
        let body = flate2::read::ZlibDecoder::new(Reader::range(src, 8, src.len()));
        return emit_stream(&meta, &mut Cursor::new(fws).chain(body), budget, visit);
    }
    // ZWS / LZMA: 8 header + 4 comp-length + 5 LZMA props before the stream.
    let unsupported = MemberMeta {
        unsupported: Some("SWF LZMA decode unsupported"),
        ..meta.clone()
    };
    if hdr.len() < 17 {
        return Ok(visit(&unsupported, None, budget));
    }
    let file_length = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
    let want = file_length.saturating_sub(8);
    let dict = dict_size(
        u32::from_le_bytes([hdr[13], hdr[14], hdr[15], hdr[16]]),
        want,
        budget.limits().max_buffer_bytes,
    );
    let stream = Reader::range(src, 17, src.len());
    match lzma_rust2::LzmaReader::new_with_props(stream, want, hdr[12], dict, None) {
        Ok(body) => emit_stream(&meta, &mut Cursor::new(fws).chain(body), budget, visit),
        Err(_) => Ok(visit(&unsupported, None, budget)),
    }
}

/// Pick the LZMA dictionary size for a `ZWS` movie. Both `declared` (the props
/// header's dictionary field) and `want` (the movie header's own `FileLength`,
/// less the 8-byte header) are attacker-controlled, and the dictionary is
/// allocated up front — so `want` is no ceiling on its own: a movie declaring
/// 4 GiB would buy itself a 4 GiB dictionary. `max_buffer` is the real bound;
/// `want` only ever tightens it, since a dictionary larger than the bytes it
/// will be used to look back into cannot be consulted.
fn dict_size(declared: u32, want: u64, max_buffer: u64) -> u32 {
    crate::bounded_dict(declared, want.min(max_buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{extract, Format, Limits};
    use flate2::{write::ZlibEncoder, Compression};
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
        // Already uncompressed — no member to extract.
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

    #[test]
    fn short_and_non_swf_input_is_ignored() {
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Swf, b"CW", &mut budget).unwrap().is_empty());
        assert!(extract(Format::Swf, b"NOTASWF!", &mut budget)
            .unwrap()
            .is_empty());
    }

    // A `ZWS` header carries two attacker-chosen sizes, and the LZMA dictionary
    // is allocated before a single byte is decoded. Neither may set that size.
    #[test]
    fn dictionary_is_bounded_by_the_buffer_limit() {
        let max_buffer = Limits::default().max_buffer_bytes;
        // The sizes from a movie that asked for a 2.7 GiB dictionary by declaring
        // a ~4 GiB FileLength: neither number may be believed.
        assert_eq!(
            dict_size(0xA1A1_C32B, 0xF04A_0957 - 8, max_buffer),
            max_buffer as u32,
            "a huge declared dictionary is clamped to the buffer limit"
        );
        // A movie small enough to be honest keeps its own (smaller) dictionary.
        assert_eq!(
            dict_size(1 << 16, 1 << 20, max_buffer),
            1 << 16,
            "a dictionary under both bounds is used as-is"
        );
        // `want` still tightens: no point holding more history than output.
        assert_eq!(
            dict_size(u32::MAX, 1 << 20, max_buffer),
            1 << 20,
            "the declared output bounds the dictionary when it is the smaller"
        );
    }
}
