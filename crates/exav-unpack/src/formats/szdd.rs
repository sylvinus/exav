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
use std::io::Read;

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

/// Walk an MS-Compress file. SZDD is decoded as it is read; KWAJ is decoded
/// whole.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::stream::{emit_stream, whole, MemberMeta};
    let hdr = src.window(0, 14);
    if !hdr.starts_with(SZDD_MAGIC) {
        return whole(Format::Szdd, src, budget, visit);
    }
    if hdr.len() < 14 {
        return Err(LimitHit::corrupt("szdd: truncated header".to_string()));
    }
    let declared = u32::from_le_bytes([hdr[10], hdr[11], hdr[12], hdr[13]]) as u64;
    budget.count_entry()?;
    let mut body = crate::source::Reader::range(src, 14, src.len());
    let mut rdr = SzddReader::new(&mut body, declared);
    let meta = MemberMeta {
        name: szdd_name(&hdr),
        comp_size: (src.len() - 14) as u64,
        size: Some(declared),
        ..MemberMeta::default()
    };
    emit_stream(&meta, &mut rdr, budget, visit)
}

/// SZDD's LZSS decoder as a `Read`: a 4 KiB ring preset to spaces, driven by
/// flag bytes whose bits select a literal (1) or a 12-bit offset and 4-bit
/// length back-reference (0). Output stops at the declared size or when the
/// input runs out. The ring index is masked, so hostile input cannot panic.
struct SzddReader<'a> {
    src: &'a mut dyn Read,
    window: [u8; 4096],
    wpos: usize,
    declared: u64,
    produced: u64,
    out: [u8; 18], // one token emits at most 18 bytes (back-reference length 3..18)
    out_len: usize,
    out_pos: usize,
    flags: u32,
    bits_left: u8,
    done: bool,
}

impl<'a> SzddReader<'a> {
    fn new(src: &'a mut dyn Read, declared: u64) -> Self {
        Self {
            src,
            window: [0x20u8; 4096],
            wpos: 4096 - 16,
            declared,
            produced: 0,
            out: [0u8; 18],
            out_len: 0,
            out_pos: 0,
            flags: 0,
            bits_left: 0,
            done: false,
        }
    }
    fn next_byte(&mut self) -> std::io::Result<Option<u8>> {
        let mut b = [0u8; 1];
        match self.src.read(&mut b)? {
            0 => Ok(None),
            _ => Ok(Some(b[0])),
        }
    }
    fn emit(&mut self, b: u8) {
        self.out[self.out_len] = b;
        self.out_len += 1;
        self.window[self.wpos] = b;
        self.wpos = (self.wpos + 1) & 4095;
        self.produced += 1;
    }
}

impl Read for SzddReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut w = 0;
        while w < buf.len() {
            if self.out_pos < self.out_len {
                buf[w] = self.out[self.out_pos];
                self.out_pos += 1;
                w += 1;
                continue;
            }
            if self.done || self.produced >= self.declared {
                break;
            }
            self.out_len = 0;
            self.out_pos = 0;
            if self.bits_left == 0 {
                match self.next_byte()? {
                    Some(f) => {
                        self.flags = f as u32;
                        self.bits_left = 8;
                    }
                    None => {
                        self.done = true;
                        break;
                    }
                }
            }
            let is_literal = (self.flags & 1) == 1;
            self.flags >>= 1;
            self.bits_left -= 1;
            if is_literal {
                match self.next_byte()? {
                    Some(b) => self.emit(b),
                    None => {
                        self.done = true;
                        break;
                    }
                }
            } else {
                let (b0, b1) = match (self.next_byte()?, self.next_byte()?) {
                    (Some(a), Some(b)) => (a, b),
                    _ => {
                        self.done = true;
                        break;
                    }
                };
                let mut mpos = (b0 as usize) | (((b1 as usize) & 0xF0) << 4);
                let len = ((b1 as usize) & 0x0F) + 3;
                for _ in 0..len {
                    if self.produced >= self.declared {
                        break;
                    }
                    let b = self.window[mpos & 4095];
                    self.emit(b);
                    mpos = mpos.wrapping_add(1);
                }
            }
        }
        Ok(w)
    }
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
    let declared = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as u64;
    let mut body = &data[14..];

    budget.count_entry()?;
    let cap = budget.reserve()?;
    let mut out = Vec::new();
    // Reading a slice cannot fail.
    let _ = SzddReader::new(&mut body, declared)
        .take(cap.saturating_add(1))
        .read_to_end(&mut out);
    if out.len() as u64 > cap {
        return Err(LimitHit::new("szdd member exceeds budget".to_string()));
    }
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
