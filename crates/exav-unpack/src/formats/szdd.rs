//! MS-Compress SZDD and KWAJ (`expand.exe` / `compress.exe` single-file format).
//!
//! Both wrap one file. **SZDD** (`SZDD\x88\xF0\x27\x33`) uses a fixed LZSS scheme:
//! a 4096-byte ring buffer preset to spaces, driven by flag bytes whose bits
//! select a literal (1) or a (offset,length) back-reference (0). **KWAJ**
//! (`KWAJ\x88\xF0\x27\xD1`) is a richer header with several compression methods;
//! we decode the stored (method 0) and XORed (method 1) variants and report the
//! LZSS/MSZIP/LZH methods as unsupported (metadata-only) rather than guessing.
//!
//! Every bound is clamped to the input length and the ring index is masked to
//! 12 bits, so truncated/hostile streams decode partially without panicking.

use crate::*;

const SZDD_MAGIC: &[u8; 8] = b"SZDD\x88\xF0\x27\x33";
const KWAJ_MAGIC: &[u8; 8] = b"KWAJ\x88\xF0\x27\xD1";

pub(crate) fn is_szdd(data: &[u8]) -> bool {
    data.starts_with(SZDD_MAGIC) || data.starts_with(KWAJ_MAGIC)
}

pub(crate) fn extract_szdd<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if data.starts_with(KWAJ_MAGIC) {
        extract_kwaj(data, budget, visit)
    } else if data.starts_with(SZDD_MAGIC) {
        extract_szdd_inner(data, budget, visit)
    } else {
        Err(LimitHit::corrupt("szdd: bad magic".to_string()))
    }
}

/// Decode the SZDD LZSS stream starting at `input`, stopping at `declared`
/// output bytes or input exhaustion. Never panics: the ring index is masked and
/// every input read is `get`-guarded.
fn lzss_decompress(input: &[u8], declared: usize, cap: u64) -> Result<Vec<u8>, LimitHit> {
    const WIN: usize = 4096;
    let mut window = [0x20u8; WIN];
    let mut wpos = WIN - 16; // 4080
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < input.len() && out.len() < declared {
        let flags = input[i];
        i += 1;
        for bit in 0..8 {
            if out.len() >= declared {
                break;
            }
            if (flags >> bit) & 1 == 1 {
                // Literal byte.
                let Some(&b) = input.get(i) else {
                    return finish(out, cap);
                };
                i += 1;
                out.push(b);
                window[wpos] = b;
                wpos = (wpos + 1) & (WIN - 1);
            } else {
                // Back-reference: two bytes -> 12-bit offset + 4-bit length.
                let (Some(&b0), Some(&b1)) = (input.get(i), input.get(i + 1)) else {
                    return finish(out, cap);
                };
                i += 2;
                let mut mpos = (b0 as usize) | (((b1 as usize) & 0xF0) << 4);
                let len = ((b1 as usize) & 0x0F) + 3;
                for _ in 0..len {
                    if out.len() >= declared {
                        break;
                    }
                    let b = window[mpos & (WIN - 1)];
                    out.push(b);
                    window[wpos] = b;
                    wpos = (wpos + 1) & (WIN - 1);
                    mpos = mpos.wrapping_add(1);
                }
            }
            if out.len() as u64 > cap {
                return Err(LimitHit::new("szdd member exceeds budget".to_string()));
            }
        }
    }
    finish(out, cap)
}

fn finish(out: Vec<u8>, cap: u64) -> Result<Vec<u8>, LimitHit> {
    if out.len() as u64 > cap {
        return Err(LimitHit::new("szdd member exceeds budget".to_string()));
    }
    Ok(out)
}

fn extract_szdd_inner<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // 14-byte header: magic[8], compression 'A' [8], last-char [9], size u32 LE.
    if data.len() < 14 {
        return Err(LimitHit::corrupt("szdd: truncated header".to_string()));
    }
    let declared = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
    let body = &data[14..];

    budget.count_entry()?;
    let cap = budget.reserve()?;
    // Clamp the attacker-declared size so a huge value can't drive a giant
    // allocation; the ratio/total caps still bound the real output.
    let want = declared.min((cap as usize).saturating_add(1));
    let out = lzss_decompress(body, want, cap)?;
    budget.commit(out.len() as u64);
    if let Some(r) = visit(Entry::new(szdd_name(data), out), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

/// Reconstruct a plausible name from the SZDD "last character" field: the
/// original name's final char was replaced by `_` on compression and stored at
/// byte 9. We can't recover the rest, so this is best-effort.
fn szdd_name(_data: &[u8]) -> String {
    "expanded.bin".to_string()
}

/// KWAJ compression method identifiers.
const KWAJ_NONE: u16 = 0;
const KWAJ_XOR: u16 = 1;

fn extract_kwaj<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Fixed 14-byte header: magic[8], comp u16, data_offset u16, flags u16.
    if data.len() < 14 {
        return Err(LimitHit::corrupt("kwaj: truncated header".to_string()));
    }
    let method = u16::from_le_bytes([data[8], data[9]]);
    let data_offset = u16::from_le_bytes([data[10], data[11]]) as usize;
    let flags = u16::from_le_bytes([data[12], data[13]]);

    // Optional header fields follow, in order, gated by `flags`.
    let mut p = 14usize;
    let mut declared: Option<usize> = None;
    if flags & 0x01 != 0 {
        // uncompressed length (u32 LE)
        if p + 4 <= data.len() {
            declared =
                Some(u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as usize);
        }
        p += 4;
    }
    if flags & 0x02 != 0 {
        p += 2; // unknown u16
    }
    if flags & 0x04 != 0 {
        // length-prefixed unknown data
        if p + 2 <= data.len() {
            let n = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
            p = p.saturating_add(2).saturating_add(n);
        } else {
            p = p.saturating_add(2);
        }
    }
    let mut fname = read_cstr(data, &mut p, flags & 0x08 != 0);
    let ext = read_cstr(data, &mut p, flags & 0x10 != 0);
    if !ext.is_empty() {
        fname = if fname.is_empty() {
            format!("expanded.{ext}")
        } else {
            format!("{fname}.{ext}")
        };
    }
    let name = if fname.is_empty() {
        "expanded.bin".to_string()
    } else {
        fname
    };

    // Compressed data starts at `data_offset` from the file start.
    let body_start = data_offset.min(data.len());
    let body = &data[body_start..];

    budget.count_entry()?;
    let cap = budget.reserve()?;
    match method {
        KWAJ_NONE => {
            if body.len() as u64 > cap {
                return Err(LimitHit::new("kwaj member exceeds budget".to_string()));
            }
            let out = body.to_vec();
            budget.commit(out.len() as u64);
            if let Some(r) = visit(Entry::new(name, out), budget) {
                return Ok(Some(r));
            }
        }
        KWAJ_XOR => {
            if body.len() as u64 > cap {
                return Err(LimitHit::new("kwaj member exceeds budget".to_string()));
            }
            let out: Vec<u8> = body.iter().map(|b| b ^ 0xFF).collect();
            budget.commit(out.len() as u64);
            if let Some(r) = visit(Entry::new(name, out), budget) {
                return Ok(Some(r));
            }
        }
        _ => {
            // LZSS / MSZIP / LZH: recognised but not decoded here.
            let _ = declared;
            let e = Entry::unsupported(
                name,
                body.len() as u64,
                false,
                "KWAJ: unsupported compression method",
            );
            if let Some(r) = visit(e, budget) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}

/// Read a NUL-terminated string starting at `*p` (advancing past the NUL) when
/// `present`; otherwise return empty and leave `*p` untouched. Bounds-clamped.
fn read_cstr(data: &[u8], p: &mut usize, present: bool) -> String {
    if !present || *p >= data.len() {
        return String::new();
    }
    let start = *p;
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|n| start + n)
        .unwrap_or(data.len());
    *p = (end + 1).min(data.len());
    // Basename only — never let a stored name carry a path separator.
    String::from_utf8_lossy(&data[start..end])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an all-literal SZDD stream: every flag byte is 0xFF (8 literals),
    /// so the body is just the payload interleaved with flag bytes and decodes
    /// back to exactly the payload.
    fn szdd_all_literal(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SZDD_MAGIC);
        out.push(b'A'); // compression mode
        out.push(b'X'); // last char of name
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        for chunk in payload.chunks(8) {
            // Flag byte: low `chunk.len()` bits set = that many literals.
            let flag = if chunk.len() == 8 {
                0xFFu8
            } else {
                (1u16 << chunk.len()) as u8 - 1
            };
            out.push(flag);
            out.extend_from_slice(chunk);
        }
        out
    }

    #[test]
    fn szdd_all_literal_roundtrip() {
        let payload = b"MALWARETEST inside an SZDD LZSS stream, all literals!";
        let blob = szdd_all_literal(payload);
        assert!(is_szdd(&blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Szdd, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "expanded.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn szdd_back_reference_decodes() {
        // Hand-built stream: literal 'A' then a back-reference copying the 4
        // spaces preset before wpos would be wrong; instead reference the just
        // written 'A'. Simpler: 8 literals "ABCDEFGH", then a flag with one
        // match bit (bit0=0) copying 3 bytes from offset = wpos-8.
        let payload = b"ABCDEFGH";
        let mut blob = Vec::new();
        blob.extend_from_slice(SZDD_MAGIC);
        blob.push(b'A');
        blob.push(b'X');
        blob.extend_from_slice(&(11u32).to_le_bytes()); // 8 literals + 3 copied
        blob.push(0xFF); // 8 literals
        blob.extend_from_slice(payload);
        // Next flag: bit0 = 0 (match), rest unused (output stops at declared=11).
        blob.push(0x00);
        // Match: offset points at where "ABC" was written. wpos started 4080,
        // after 8 literals wpos = 4088. The 'A' is at 4080.
        let off = 4080usize;
        let b0 = (off & 0xFF) as u8;
        let b1 = (((off >> 4) & 0xF0) as u8) | ((3 - 3) as u8); // len=3
        blob.push(b0);
        blob.push(b1);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Szdd, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"ABCDEFGHABC");
    }

    #[test]
    fn kwaj_store_roundtrip() {
        let payload = b"MALWARETEST stored in a KWAJ container";
        let mut blob = Vec::new();
        blob.extend_from_slice(KWAJ_MAGIC);
        blob.extend_from_slice(&KWAJ_NONE.to_le_bytes()); // method 0
        let data_off = 14u16;
        blob.extend_from_slice(&data_off.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes()); // flags
        blob.extend_from_slice(payload);
        assert!(is_szdd(&blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Szdd, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn kwaj_unsupported_method_is_metadata_only() {
        let mut blob = Vec::new();
        blob.extend_from_slice(KWAJ_MAGIC);
        blob.extend_from_slice(&3u16.to_le_bytes()); // MSZIP: unsupported
        blob.extend_from_slice(&14u16.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(b"whatever");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Szdd, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].unsupported.is_some());
        assert!(entries[0].data.is_empty());
    }

    #[test]
    fn truncated_szdd_does_not_panic() {
        let mut blob = SZDD_MAGIC.to_vec();
        blob.push(b'A');
        blob.push(b'X');
        blob.extend_from_slice(&1000u32.to_le_bytes()); // claims 1000 bytes
        blob.push(0xFF); // flag says 8 literals but none follow
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Szdd, &blob, &mut budget).unwrap();
        // Decoder stops at input exhaustion without panicking.
        assert_eq!(entries.len(), 1);
    }
}
