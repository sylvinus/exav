//! BinHex 4.0 (`.hqx`) decoder.
//!
//! BinHex 4.0 is a 7-bit-safe text encoding used on classic Mac OS to ship a
//! file (with its data and resource forks plus Finder metadata) through email
//! and Usenet. Malware occasionally rides inside one, so we decode the *data
//! fork* (and the resource fork) out for the engine to recurse into.
//!
//! Layout of a `.hqx` file:
//!
//! ```text
//! (This file must be converted with BinHex 4.0)   <- marker line
//! :<6-bit-encoded stream>:                          <- opens/closes with ':'
//! ```
//!
//! The encoded stream is a base-64-style 6-bit code over a fixed 64-character
//! alphabet (RFC 1741); 4 encoded chars decode to 3 bytes. The decoded byte
//! stream is then RLE90-compressed: the marker byte `0x90` introduces a run —
//! `x 0x90 n` expands to byte `x` repeated `n` times, and `0x90 0x00` is a
//! literal `0x90`. After RLE the bytes are a header:
//!
//! ```text
//! u8  namelen
//! u8  name[namelen]
//! u8  0                (version / pad)
//! u32 type             (big-endian, all multi-byte fields are BE)
//! u32 creator
//! u16 flags
//! u32 dataLen
//! u32 rsrcLen
//! u16 headerCRC
//! u8  data[dataLen]    (data fork)
//! u16 CRC
//! u8  rsrc[rsrcLen]    (resource fork)
//! ```
//!
//! CRCs are ignored. Every length is clamped to the bytes actually present, so
//! a truncated or hostile file decodes partially and never panics or reads out
//! of bounds.

use crate::*;

/// The marker line that opens every BinHex 4.0 file. Detection scans the head
/// of the input for this substring (it may be preceded by blank lines or mail
/// headers).
const MARKER: &[u8] = b"(This file must be converted with BinHex";

/// RFC 1741 BinHex 6-bit alphabet (64 chars): index = 6-bit value, byte = the
/// ASCII character used to encode it.
const ALPHABET: &[u8; 64] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

/// RLE90 run marker.
const RLE_MARKER: u8 = 0x90;

/// True if `data` looks like a BinHex 4.0 file: the marker line appears within
/// the first kilobyte (conservative — the marker is highly specific).
pub(crate) fn looks_like_binhex(data: &[u8]) -> bool {
    let head = &data[..data.len().min(1024)];
    head.windows(MARKER.len()).any(|w| w == MARKER)
}

/// Build the reverse lookup: ASCII char -> 6-bit value, or 0xFF for chars not
/// in the alphabet (whitespace, newlines, the framing `:` — all skipped).
fn decode_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    let mut i = 0;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
}

/// Decode the 6-bit-encoded stream between the opening and closing `:` into raw
/// bytes (before RLE). Non-alphabet bytes are skipped. `cap` bounds the output
/// so a huge file can't drive an unbounded allocation.
fn sixbit_decode(stream: &[u8], cap: usize) -> Vec<u8> {
    let table = decode_table();
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in stream {
        let v = table[c as usize];
        if v == 0xFF {
            continue; // whitespace / newline / stray char
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// Expand an RLE90 stream. `x 0x90 n` -> `x` repeated `n` times; `0x90 0x00` ->
/// a literal `0x90`. `cap` bounds the output length.
fn rle90_expand(input: &[u8], cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        i += 1;
        if b != RLE_MARKER {
            out.push(b);
        } else {
            // Marker: the next byte is the repeat count.
            let n = input.get(i).copied().unwrap_or(0);
            i += 1;
            if n == 0 {
                // Escaped literal 0x90.
                out.push(RLE_MARKER);
            } else if let Some(&last) = out.last() {
                // `last` was already emitted once; emit n-1 more copies.
                for _ in 1..n {
                    out.push(last);
                    if out.len() >= cap {
                        break;
                    }
                }
            }
        }
        if out.len() >= cap {
            break;
        }
    }
    out
}

pub(crate) fn extract_binhex<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Locate the marker, then the opening ':' that begins the encoded stream.
    let marker_at = data
        .windows(MARKER.len())
        .position(|w| w == MARKER)
        .map(|p| p + MARKER.len())
        .unwrap_or(0);
    let Some(rel_open) = data[marker_at..].iter().position(|&b| b == b':') else {
        return Ok(None); // no encoded stream
    };
    let stream_start = marker_at + rel_open + 1;
    // The stream ends at the next ':' (or EOF if the file is truncated).
    let stream_end = data[stream_start..]
        .iter()
        .position(|&b| b == b':')
        .map(|p| stream_start + p)
        .unwrap_or(data.len());
    let stream = &data[stream_start..stream_end];

    // Decode 6-bit -> bytes -> RLE-expanded payload, each bounded by the budget
    // so a decompression bomb can't blow past the caps. The reserve is the
    // ceiling for both intermediate buffers.
    let cap = budget.reserve()?;
    let cap_usize = usize::try_from(cap.saturating_add(1)).unwrap_or(usize::MAX);
    let raw = sixbit_decode(stream, cap_usize);
    let bytes = rle90_expand(&raw, cap_usize);

    // --- parse the BinHex header (all multi-byte fields big-endian) ---
    let len = bytes.len();
    if len == 0 {
        return Ok(None);
    }
    let namelen = bytes[0] as usize;
    let mut p = 1usize;
    let name_end = p.saturating_add(namelen).min(len);
    let name = String::from_utf8_lossy(&bytes[p..name_end]).into_owned();
    let name = if name.is_empty() {
        "binhex-data".to_string()
    } else {
        name
    };
    p = name_end;
    p = p.saturating_add(1); // version / pad byte

    // Read a big-endian u32 at `p`, clamping to available bytes (missing bytes
    // read as 0), and advance `p` by 4.
    let be32 = |p: &mut usize| -> u32 {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 8) | bytes.get(*p).copied().unwrap_or(0) as u32;
            *p += 1;
        }
        v
    };
    let _type = be32(&mut p);
    let _creator = be32(&mut p);
    p = p.saturating_add(2); // flags (u16)
    let data_len = be32(&mut p) as usize;
    let rsrc_len = be32(&mut p) as usize;
    p = p.saturating_add(2); // headerCRC

    // --- data fork: clamp to what's present ---
    let data_start = p.min(len);
    let data_end = data_start.saturating_add(data_len).min(len);
    let data_fork = bytes[data_start..data_end].to_vec();

    budget.count_entry()?;
    let cap = budget.reserve()?;
    if data_fork.len() as u64 > cap {
        return Err(LimitHit::new("binhex data fork exceeds budget".to_string()));
    }
    budget.commit(data_fork.len() as u64);
    if let Some(r) = visit(Entry::new(name.clone(), data_fork), budget) {
        return Ok(Some(r));
    }

    // --- resource fork: after data fork + u16 CRC ---
    let rsrc_start = data_end.saturating_add(2).min(len);
    let rsrc_end = rsrc_start.saturating_add(rsrc_len).min(len);
    if rsrc_end > rsrc_start {
        let rsrc_fork = bytes[rsrc_start..rsrc_end].to_vec();
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if rsrc_fork.len() as u64 > cap {
            return Err(LimitHit::new(
                "binhex resource fork exceeds budget".to_string(),
            ));
        }
        budget.commit(rsrc_fork.len() as u64);
        if let Some(r) = visit(Entry::new(format!("{name}.rsrc"), rsrc_fork), budget) {
            return Ok(Some(r));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode raw bytes with the BinHex 6-bit alphabet (MSB-first bitstream),
    /// mirroring [`sixbit_decode`].
    fn sixbit_encode(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut nbits: u32 = 0;
        for &b in bytes {
            acc = (acc << 8) | b as u32;
            nbits += 8;
            while nbits >= 6 {
                nbits -= 6;
                out.push(ALPHABET[((acc >> nbits) & 0x3F) as usize]);
            }
        }
        if nbits > 0 {
            // Pad the final partial group with zero bits.
            let v = (acc << (6 - nbits)) & 0x3F;
            out.push(ALPHABET[v as usize]);
        }
        out
    }

    /// Build a BinHex 4.0 file around a data fork. The payload is chosen to
    /// contain no `0x90` byte, so the identity RLE stream below is valid.
    fn make_binhex(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.push(name.len() as u8);
        hdr.extend_from_slice(name);
        hdr.push(0); // version / pad
        hdr.extend_from_slice(&0u32.to_be_bytes()); // type
        hdr.extend_from_slice(&0u32.to_be_bytes()); // creator
        hdr.extend_from_slice(&0u16.to_be_bytes()); // flags
        hdr.extend_from_slice(&(data.len() as u32).to_be_bytes()); // dataLen
        hdr.extend_from_slice(&0u32.to_be_bytes()); // rsrcLen
        hdr.extend_from_slice(&0u16.to_be_bytes()); // headerCRC
        hdr.extend_from_slice(data); // data fork
        hdr.extend_from_slice(&0u16.to_be_bytes()); // data-fork CRC
                                                    // rsrcLen == 0, so no resource fork bytes.

        // RLE90 identity (no 0x90 in `hdr` by construction), then 6-bit encode.
        let encoded = sixbit_encode(&hdr);

        let mut file = Vec::new();
        file.extend_from_slice(b"(This file must be converted with BinHex 4.0)\n");
        file.push(b':');
        file.extend_from_slice(&encoded);
        file.push(b':');
        file.push(b'\n');
        file
    }

    #[test]
    fn roundtrip_data_fork() {
        let blob = make_binhex(b"evil.bin", b"MALWARETEST");
        assert!(looks_like_binhex(&blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Binhex, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "evil.bin");
        assert_eq!(entries[0].data, b"MALWARETEST");
    }

    #[test]
    fn eicar_fixture_data_fork() {
        // A real BinHex 4.0 of the EICAR test file.
        let blob = include_bytes!("../../tests/fixtures/binhex/eicar.hqx");
        assert!(looks_like_binhex(blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Binhex, blob, &mut budget).unwrap();
        assert!(!entries.is_empty(), "no members extracted");
        // The EICAR signature substring must appear in the decoded data fork.
        assert!(
            entries
                .iter()
                .any(|e| e.data.windows(9).any(|w| w == b"X5O!P%@AP")),
            "EICAR substring not found in extracted forks"
        );
    }

    #[test]
    fn truncated_input_does_not_panic() {
        // Marker + opening ':' but a chopped stream with no closing ':' and a
        // header that claims far more data than is present. Must not panic.
        let mut blob = Vec::new();
        blob.extend_from_slice(b"(This file must be converted with BinHex 4.0)\n:");
        // A few encoded chars, then EOF (no closing colon).
        blob.extend_from_slice(b"iiiiiiii");
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Binhex, &blob, &mut budget); // just must not panic

        // Also a header declaring an absurd data length.
        let mut hdr = Vec::new();
        hdr.push(3);
        hdr.extend_from_slice(b"abc");
        hdr.push(0);
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&0u16.to_be_bytes());
        hdr.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // absurd dataLen
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&0u16.to_be_bytes());
        hdr.extend_from_slice(b"short"); // only a few bytes actually present
        let encoded = sixbit_encode(&hdr);
        let mut file = Vec::new();
        file.extend_from_slice(b"(This file must be converted with BinHex 4.0)\n:");
        file.extend_from_slice(&encoded);
        file.push(b':');
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Binhex, &file, &mut budget).unwrap();
        // The data fork is clamped to EOF — never reads out of bounds.
        assert_eq!(entries.len(), 1);
        assert!(entries[0].data.len() <= file.len());
    }
}
