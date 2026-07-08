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
//! `ZWS` are decoded. All sizing is bounded by the [`Budget`]: an attacker-
//! controlled `FileLength` can never drive an allocation — the LZMA decode target
//! and the zlib inflate are both clamped to the remaining budget, and a body that
//! would exceed it is rejected.
use crate::*;
use std::io::Cursor;

pub(crate) fn extract_swf<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Need the full 8-byte header to know the encoding and FileLength.
    if data.len() < 8 {
        return Ok(None);
    }
    let sig = &data[0..3];
    // FWS is already uncompressed — nothing to unpack. Non-SWF magic: ignore.
    if sig != b"CWS" && sig != b"ZWS" {
        return Ok(None);
    }

    budget.count_entry()?;
    let cap = budget.reserve()?;

    // Decompress the body (bytes 8..) per the signature.
    let body = if sig == b"CWS" {
        use flate2::read::ZlibDecoder;
        let (out, truncated) = bounded_read(ZlibDecoder::new(&data[8..]), cap)
            .map_err(|e| LimitHit::corrupt(format!("swf zlib: {e}")))?;
        if truncated {
            return Err(LimitHit::new(
                "swf: decompressed size exceeds budget".into(),
            ));
        }
        out
    } else {
        // ZWS / LZMA. If the stream doesn't decode cleanly, report the member as
        // unsupported rather than failing the whole scan or panicking.
        match decode_zws_lzma(data, cap) {
            Ok((out, truncated)) => {
                if truncated {
                    return Err(LimitHit::new(
                        "swf: decompressed size exceeds budget".into(),
                    ));
                }
                out
            }
            Err(()) => {
                let comp = (data.len() as u64).saturating_sub(8);
                return Ok(visit(
                    Entry::unsupported(
                        "movie.swf".into(),
                        comp,
                        false,
                        "SWF LZMA decode unsupported",
                    ),
                    budget,
                ));
            }
        }
    };

    // Rebuild an FWS movie: the original 8-byte header with the signature forced
    // to `FWS` (version + FileLength kept verbatim), then the decompressed body.
    let mut fws = Vec::with_capacity(8 + body.len());
    fws.extend_from_slice(b"FWS");
    fws.extend_from_slice(&data[3..8]);
    fws.extend_from_slice(&body);
    budget.commit(fws.len() as u64);
    Ok(visit(Entry::new("movie.swf".into(), fws), budget))
}

/// Decode a `ZWS` (LZMA) SWF body. After the 8-byte movie header the layout is a
/// 4-byte compressed-length u32 LE, then a 5-byte LZMA properties header (1 props
/// byte + u32 LE dictionary size), then the range-coded stream. The uncompressed
/// body size is `FileLength - 8`. Returns `(bytes, truncated)` — `truncated` true
/// if the output hit the budget cap — or `Err(())` if the stream can't be decoded
/// (short/malformed input, unsupported variant), so the caller can fall back to
/// an `unsupported` member instead of aborting.
fn decode_zws_lzma(data: &[u8], cap: u64) -> Result<(Vec<u8>, bool), ()> {
    // 8 header + 4 comp-length + 5 LZMA props = 17 bytes before the stream.
    if data.len() < 17 {
        return Err(());
    }
    let file_length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
    // Declared uncompressed body size. Untrusted: used only as the decode target,
    // and memory is bounded by `bounded_read(cap)` regardless of how large it is.
    let want = file_length.saturating_sub(8);
    let props = data[12];
    let dict_size = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
    let stream = &data[17..];
    let reader =
        lzma_rust2::LzmaReader::new_with_props(Cursor::new(stream), want, props, dict_size, None)
            .map_err(|_| ())?;
    bounded_read(reader, cap).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            max_total_bytes: 1024,
            max_ratio: u64::MAX,
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
        assert_eq!(entries[0].unsupported, Some("SWF LZMA decode unsupported"));
    }

    #[test]
    fn short_and_non_swf_input_is_ignored() {
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Swf, b"CW", &mut budget).unwrap().is_empty());
        assert!(extract(Format::Swf, b"NOTASWF!", &mut budget)
            .unwrap()
            .is_empty());
    }
}
