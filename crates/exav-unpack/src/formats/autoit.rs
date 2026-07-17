//! Compiled AutoIt3 script extractor.
//!
//! AutoIt3 compiles a `.au3` script into a Windows executable; the compiled
//! script is embedded (usually a PE resource, often appended past the image) and
//! tagged with an `AU3!EA05` or `AU3!EA06` marker. Malware ships as compiled
//! AutoIt, so carving the embedded script back out lets the engine scan it.
//!
//! Implemented from the MIT-licensed **AutoIt-Ripper** reference
//! (<https://github.com/nazywam/AutoIt-Ripper>, MIT) and the public format:
//!
//! * **EA05** (older) — after the marker, a 16-byte region is summed into a
//!   checksum, then a run of `FILE` records. Each record's 4-byte tag decrypts
//!   (via AutoIt's Mersenne-Twister keystream, seed `0x16FA`) to `"FILE"`; the
//!   subtype/name strings, sizes and CRC are keyed likewise, and the content is
//!   MT-decrypted with `checksum + 0x22AF`. A compressed member is a `EA05`
//!   magic + big-endian output size + an LZSS bitstream. We decode this in full.
//! * **EA06** (newer) — keyed by a floating-point PRNG and a tokenised opcode
//!   stream; recognised and reported [`Entry::unsupported`] (`autoit-ea06`),
//!   never silently clean.
//!
//! Every read is bounds-checked, output grows dynamically (never pre-allocated
//! from an attacker size), and members are charged against the [`Budget`], so
//! hostile input can neither panic nor over-allocate.

use crate::*;

const MARKER_EA05: &[u8; 8] = b"AU3!EA05";
const MARKER_EA06: &[u8; 8] = b"AU3!EA06";

// AutoIt EA05 keystream seeds / XOR keys (format constants).
const KEY_FILE_TAG: u32 = 0x16FA; // decrypts the 4-byte record tag to "FILE"
const KEY_SUBTYPE_LEN: u32 = 0x29BC;
const KEY_SUBTYPE_DATA: u32 = 0xA25E;
const KEY_NAME_LEN: u32 = 0x29AC;
const KEY_NAME_DATA: u32 = 0xF25E;
const KEY_SIZE: u32 = 0x45AA;
const KEY_CRC: u32 = 0xC3D2;
const KEY_CONTENT: u32 = 0x22AF;

pub(crate) fn is_autoit(data: &[u8]) -> bool {
    find_marker(data, MARKER_EA05).is_some() || find_marker(data, MARKER_EA06).is_some()
}

fn find_marker(data: &[u8], needle: &[u8; 8]) -> Option<usize> {
    memchr::memmem::find(data, needle)
}

#[inline]
fn le32(d: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?))
}
#[inline]
fn be32(d: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(p..p + 4)?.try_into().ok()?))
}

pub(crate) fn extract_autoit<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if let Some(off) = find_marker(data, MARKER_EA05) {
        return ea05(&data[off + 8..], budget, visit);
    }
    if let Some(off) = find_marker(data, MARKER_EA06) {
        budget.count_entry()?;
        let size = (data.len() - (off + 8).min(data.len())) as u64;
        let e = Entry::unsupported(
            "autoit-ea06".to_string(),
            size,
            false,
            "AutoIt EA06 unsupported",
        );
        return Ok(visit(e, budget));
    }
    Ok(None)
}

/// Decode the EA05 record stream (`body` starts just past the marker).
fn ea05<R>(body: &[u8], budget: &mut Budget, visit: Sink<R>) -> Result<Option<R>, LimitHit> {
    if body.len() < 16 {
        return Ok(None);
    }
    // The first 16 bytes are summed into the content-decrypt checksum.
    let checksum: u32 = body[..16]
        .iter()
        .fold(0u32, |a, &b| a.wrapping_add(b as u32));

    let mut pos = 16usize;
    let mut emitted = 0u32;
    // Record tag: 4 bytes that MT-decrypt to "FILE".
    while let Some(tag_enc) = body.get(pos..pos + 4) {
        let mut tag = tag_enc.to_vec();
        mt_xor(&mut tag, KEY_FILE_TAG);
        if tag != b"FILE" {
            break;
        }
        pos += 4;

        // Subtype and name strings: u32 length (XOR key) then `len` MT-decrypted
        // bytes (seed = length + data-key). We only need to advance past them, but
        // decode the subtype to recognise the script member.
        let Some(subtype) = read_string(body, &mut pos, KEY_SUBTYPE_LEN, KEY_SUBTYPE_DATA) else {
            break;
        };
        if read_string(body, &mut pos, KEY_NAME_LEN, KEY_NAME_DATA).is_none() {
            break;
        }

        // Data header: compressed flag (u8), compressed size, uncompressed size,
        // CRC (each XOR-keyed), then two 8-byte timestamps.
        let Some(&comp) = body.get(pos) else { break };
        pos += 1;
        let (Some(csize_raw), Some(_usize_raw), Some(crc_raw)) =
            (le32(body, pos), le32(body, pos + 4), le32(body, pos + 8))
        else {
            break;
        };
        let csize = (csize_raw ^ KEY_SIZE) as usize;
        let _crc = crc_raw ^ KEY_CRC; // decoded CRC-32 (not verified)
        pos += 12; // csize + usize + crc
        pos += 16; // two u64 timestamps
        if (csize as i32) < 0 {
            break;
        }

        let Some(enc) = body.get(pos..pos + csize) else {
            break;
        };
        pos += csize;
        let mut content = enc.to_vec();
        mt_xor(&mut content, checksum.wrapping_add(KEY_CONTENT));

        let cap = budget.reserve()?;
        let out = if comp == 1 {
            match decompress_ea05(&content, cap as usize) {
                Some(v) => v,
                None => continue,
            }
        } else {
            content
        };
        if out.len() < 4 {
            continue;
        }
        if out.len() as u64 > cap {
            return Err(LimitHit::new("autoit member exceeds budget".to_string()));
        }

        budget.count_entry()?;
        budget.commit(out.len() as u64);
        let name = if subtype.contains("SCRIPT") || emitted == 0 {
            "autoit-script.au3".to_string()
        } else {
            format!("autoit-{:03}.au3", emitted + 1)
        };
        emitted += 1;
        if let Some(r) = visit(Entry::new(name, out), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Read an XOR-length + MT-encrypted string, advancing `pos`. EA05 strings are
/// single-byte (non-unicode).
fn read_string(body: &[u8], pos: &mut usize, key_len: u32, key_data: u32) -> Option<String> {
    let len = (le32(body, *pos)? ^ key_len) as usize;
    *pos += 4;
    if (len as i32) < 0 {
        return None;
    }
    let mut bytes = body.get(*pos..*pos + len)?.to_vec();
    *pos += len;
    mt_xor(&mut bytes, (len as u32).wrapping_add(key_data));
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

// --- AutoIt Mersenne-Twister keystream (from AutoIt-Ripper mt.py, MIT) --------

/// XOR `buf` in place with AutoIt's MT keystream seeded by `seed` (symmetric).
fn mt_xor(buf: &mut [u8], seed: u32) {
    let mut mt = Mt::new(seed);
    for b in buf.iter_mut() {
        *b ^= mt.next_byte();
    }
}

struct Mt {
    state: [u32; 624],
    i: usize,
}

impl Mt {
    fn new(seed: u32) -> Self {
        let mut state = [0u32; 624];
        state[0] = seed;
        for i in 1..624 {
            let last = state[i - 1];
            state[i] = (i as u32).wrapping_add(0x6C07_8965u32.wrapping_mul(last ^ (last >> 30)));
        }
        Mt { state, i: 0 }
    }

    fn twist(&mut self) {
        let s = &mut self.state;
        for i in 0..227 {
            let mut v = s[i + 397];
            v ^= (s[i] ^ ((s[i + 1] ^ s[i]) & 0x7FFF_FFFE)) >> 1;
            if s[i + 1] & 1 != 0 {
                v ^= 0x9908_B0DF;
            }
            s[i] = v;
        }
        for i in 0..396 {
            let mut v = s[i];
            v ^= (s[i + 227] ^ ((s[i + 228] ^ s[i + 227]) & 0x7FFF_FFFE)) >> 1;
            if s[i + 228] & 1 != 0 {
                v ^= 0x9908_B0DF;
            }
            s[227 + i] = v;
        }
        let mut v = s[396];
        v ^= (s[623] ^ ((s[0] ^ s[623]) & 0x7FFF_FFFE)) >> 1;
        if s[0] & 1 != 0 {
            v ^= 0x9908_B0DF;
        }
        s[623] = v;
    }

    fn next_byte(&mut self) -> u8 {
        if self.i.is_multiple_of(624) {
            self.twist();
        }
        let mut r = self.state[self.i % 624];
        self.i += 1;
        r = ((((r >> 11) ^ r) & 0xFF3A_58AD) << 7) ^ (r >> 11) ^ r;
        r = (((r & 0xFFFF_DF8C) << 15) ^ r ^ ((((r & 0xFFFF_DF8C) << 15) ^ r) >> 18)) >> 1;
        (r & 0xFF) as u8
    }
}

// --- EA05 LZSS decompressor (from AutoIt-Ripper decompress.py, MIT) -----------

/// MSB-first bit reader over a byte slice.
struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
    err: bool,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            data,
            bit: 0,
            err: false,
        }
    }
    fn get(&mut self, n: u32) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = self.bit / 8;
            if byte >= self.data.len() {
                self.err = true;
                return 0;
            }
            let b = (self.data[byte] >> (7 - (self.bit % 8))) & 1;
            v = (v << 1) | b as u32;
            self.bit += 1;
        }
        v
    }
}

/// Read an EA05 match length via the variable-length ladder (min 3).
fn read_match_len(bits: &mut Bits) -> usize {
    // (base, bits, sentinel)
    const LADDER: &[(usize, u32, u32)] = &[
        (3, 2, 0b11),
        (6, 3, 0b111),
        (13, 5, 0b11111),
        (44, 8, 255),
        (299, 8, 255),
    ];
    let mut base = 3usize;
    let mut nbits = 2u32;
    let mut sentinel = 0b11u32;
    for &(b, nb, s) in LADDER {
        base = b;
        nbits = nb;
        sentinel = s;
        let add = bits.get(nb);
        if add != s {
            return base + add as usize;
        }
    }
    // Past the ladder: keep adding the last sentinel.
    let mut total = base;
    loop {
        total += sentinel as usize;
        let add = bits.get(nbits);
        if add != sentinel {
            return total + add as usize;
        }
    }
}

/// Decompress a `EA05`-magic + big-endian-size + LZSS bitstream, bounded by `cap`.
fn decompress_ea05(content: &[u8], cap: usize) -> Option<Vec<u8>> {
    if content.len() < 8 || &content[0..4] != b"EA05" {
        return None;
    }
    let mut want = be32(content, 4)? as usize;
    if want == 0 {
        want = content.len();
    }
    let want = want.min(cap.saturating_add(1));

    let mut bits = Bits::new(&content[8..]);
    let mut out: Vec<u8> = Vec::new();
    while !bits.err && out.len() < want {
        if bits.get(1) == 0 {
            // literal
            out.push(bits.get(8) as u8);
        } else {
            let offset = bits.get(15) as usize;
            let len = read_match_len(&mut bits);
            if bits.err || offset == 0 || offset > out.len() || out.len() + len > want {
                break;
            }
            for _ in 0..len {
                let b = out[out.len() - offset];
                out.push(b);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MT is symmetric, so encrypting == decrypting.
    fn mt_apply(plain: &[u8], seed: u32) -> Vec<u8> {
        let mut v = plain.to_vec();
        mt_xor(&mut v, seed);
        v
    }

    /// Build an EA05 blob with one stored (uncompressed) FILE record, per the
    /// AutoIt-Ripper layout (16-byte checksum region of zeros → checksum 0).
    fn build_ea05_stored(subtype: &[u8], script: &[u8]) -> Vec<u8> {
        let checksum = 0u32; // 16 zero bytes
        let mut d = Vec::new();
        d.extend_from_slice(MARKER_EA05);
        d.extend_from_slice(&[0u8; 16]); // checksum region
        d.extend_from_slice(&mt_apply(b"FILE", KEY_FILE_TAG)); // tag
                                                               // subtype string
        d.extend_from_slice(&((subtype.len() as u32) ^ KEY_SUBTYPE_LEN).to_le_bytes());
        d.extend_from_slice(&mt_apply(
            subtype,
            (subtype.len() as u32).wrapping_add(KEY_SUBTYPE_DATA),
        ));
        // name string ("x")
        let name = b"x";
        d.extend_from_slice(&((name.len() as u32) ^ KEY_NAME_LEN).to_le_bytes());
        d.extend_from_slice(&mt_apply(
            name,
            (name.len() as u32).wrapping_add(KEY_NAME_DATA),
        ));
        // data header
        d.push(0); // comp = 0 (stored)
        d.extend_from_slice(&((script.len() as u32) ^ KEY_SIZE).to_le_bytes()); // csize
        d.extend_from_slice(&((script.len() as u32) ^ KEY_SIZE).to_le_bytes()); // usize
        d.extend_from_slice(&(0u32 ^ KEY_CRC).to_le_bytes()); // crc
        d.extend_from_slice(&[0u8; 16]); // two u64 timestamps
        d.extend_from_slice(&mt_apply(script, checksum.wrapping_add(KEY_CONTENT))); // content
        d
    }

    /// Encode `plain` as an all-literal EA05 LZSS stream ("EA05" + BE size + bits).
    fn ea05_all_literal(plain: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut cur = 0u8;
        let mut nbits = 0u8;
        let push_bit = |bit: u8, bytes: &mut Vec<u8>, cur: &mut u8, nbits: &mut u8| {
            *cur = (*cur << 1) | (bit & 1);
            *nbits += 1;
            if *nbits == 8 {
                bytes.push(*cur);
                *cur = 0;
                *nbits = 0;
            }
        };
        for &b in plain {
            push_bit(0, &mut bytes, &mut cur, &mut nbits); // literal flag
            for k in (0..8).rev() {
                push_bit((b >> k) & 1, &mut bytes, &mut cur, &mut nbits);
            }
        }
        if nbits != 0 {
            cur <<= 8 - nbits;
            bytes.push(cur);
        }
        bytes.push(0); // trailing slack
        let mut out = Vec::new();
        out.extend_from_slice(b"EA05");
        out.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
        out
    }

    #[test]
    fn mt_keystream_is_symmetric() {
        let plain = b"MALWARETEST keystream roundtrip";
        assert_eq!(mt_apply(&mt_apply(plain, 0x1234), 0x1234), plain);
    }

    #[test]
    fn stored_script_extracted() {
        let script = b"; AutoIt\nMsgBox(0, \"x\", \"MALWARETEST\")\n";
        let blob = build_ea05_stored(b">>>AUTOIT SCRIPT<<<", script);
        assert!(is_autoit(&blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Autoit, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "autoit-script.au3");
        assert_eq!(entries[0].data, script);
    }

    #[test]
    fn lzss_literal_roundtrip() {
        let plain = b"MALWARETEST-lzss-literal-stream";
        let stream = ea05_all_literal(plain);
        let out = decompress_ea05(&stream, 1 << 20).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn compressed_script_extracted() {
        let script = b"Run(\"calc.exe\") ; MALWARETEST inside compressed EA05";
        let comp = ea05_all_literal(script);
        // Build a compressed FILE record.
        let mut d = Vec::new();
        d.extend_from_slice(MARKER_EA05);
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&mt_apply(b"FILE", KEY_FILE_TAG));
        d.extend_from_slice(&(0u32 ^ KEY_SUBTYPE_LEN).to_le_bytes()); // empty subtype
        d.extend_from_slice(&(0u32 ^ KEY_NAME_LEN).to_le_bytes()); // empty name
        d.push(1); // compressed
        d.extend_from_slice(&((comp.len() as u32) ^ KEY_SIZE).to_le_bytes());
        d.extend_from_slice(&((script.len() as u32) ^ KEY_SIZE).to_le_bytes());
        d.extend_from_slice(&(0u32 ^ KEY_CRC).to_le_bytes());
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&mt_apply(&comp, KEY_CONTENT)); // checksum 0
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Autoit, &d, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, script);
    }

    #[test]
    fn ea06_marker_unsupported() {
        let mut blob = MARKER_EA06.to_vec();
        blob.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Autoit, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].unsupported.is_some());
    }

    #[test]
    fn truncated_and_garbage_no_panic() {
        for cut in 0..40usize {
            let full = build_ea05_stored(b"x", b"MALWARETEST short");
            let mut budget = Budget::new(Limits::default());
            let _ = extract(Format::Autoit, &full[..cut.min(full.len())], &mut budget).unwrap();
        }
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Autoit, b"not autoit", &mut budget)
            .unwrap()
            .is_empty());
    }
}
