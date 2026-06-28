//! UPX unpacker, implemented from the public on-disk format. UPX wraps a
//! normal PE/ELF/Mach-O around a compressed copy of the
//! original; we locate the `PackHeader`, walk the block chain, and decompress so
//! the engine can scan the *original* bytes (not just the packed stub).
//!
//! On-disk layout (verified against `upx` 4.x):
//! - `l_info` (12B): `l_checksum u32`, magic `"UPX!"`, `l_lsize u16`, `l_version u8`, `l_format u8`
//! - `p_info` (12B): `p_progid u32`, `p_filesize u32` (original size), `p_blocksize u32`
//! - one or more blocks, each `b_info` (12B): `sz_unc u32`, `sz_cpr u32`,
//!   `b_method u8`, `b_ftid u8`, `b_cto8 u8`, `_`, followed by `sz_cpr` bytes.
//!   `sz_cpr == sz_unc` ⇒ stored. Chain ends at a `b_info` with `sz_unc == 0`.
//!
//! Methods: 2 = NRV2B, 5 = NRV2D, 8 = NRV2E (UPX default), 14 = LZMA, 15 = DEFLATE.
//! Stored, NRV2B, NRV2D, NRV2E, LZMA and DEFLATE are all decompressed (NRV2D/E
//! and the LZMA 2-byte property framing are implemented from the public
//! UCL/UPX on-disk format and validated byte-exact against the
//! `upx` CLI; DEFLATE is raw deflate via flate2). The x86 call/jmp un-filter
//! (`b_ftid`) is not applied; an unhandled block stops the walk and the raw file
//! is still scanned, so packer signatures still match.
#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

const M_NRV2B: u8 = 2;
const M_NRV2D: u8 = 5;
const M_NRV2E: u8 = 8;
const M_LZMA: u8 = 14;
const M_DEFLATE: u8 = 15;

/// Locate the UPX `PackHeader` (`l_info`) by finding the `"UPX!"` magic and
/// validating that a sane `p_info`/`b_info` follow. UPX writes the magic more
/// than once (a copy sits in the overlay near EOF); we take the first candidate
/// whose first block is well-formed. Returns the `l_info` start offset.
pub(crate) fn find_packheader(data: &[u8]) -> Option<usize> {
    let mut search = 0usize;
    while let Some(rel) = memchr::memmem::find(&data[search..], b"UPX!") {
        let magic = search + rel;
        search = magic + 1;
        // l_info starts 4 bytes before the magic (the checksum).
        let Some(li) = magic.checked_sub(4) else {
            continue;
        };
        // Need l_info(12) + p_info(12) + first b_info(12).
        if li + 36 > data.len() {
            continue;
        }
        let filesize = u32_le(data, li + 16);
        let bi = li + 24;
        let sz_unc = u32_le(data, bi);
        let sz_cpr = u32_le(data, bi + 4);
        // Sanity: a real first block decompresses to >0 bytes, fits in the file,
        // and isn't absurdly large; original filesize is plausible.
        if sz_unc == 0
            || sz_cpr == 0
            || filesize == 0
            || sz_unc > (256 << 20)
            || (bi + 12).saturating_add(sz_cpr as usize) > data.len()
        {
            continue;
        }
        return Some(li);
    }
    None
}

pub(crate) fn extract_upx<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let Some(li) = find_packheader(data) else {
        return Ok(None);
    };
    budget.count_entry()?;
    let cap = budget.reserve()?;

    let mut out: Vec<u8> = Vec::new();
    let mut pos = li + 24; // first b_info
    loop {
        if pos + 12 > data.len() {
            break;
        }
        let sz_unc = u32_le(data, pos) as usize;
        let sz_cpr = u32_le(data, pos + 4) as usize;
        let method = data[pos + 8];
        if sz_unc == 0 {
            break; // terminator
        }
        let dstart = pos + 12;
        if sz_cpr == 0 || dstart.saturating_add(sz_cpr) > data.len() {
            break; // malformed chain — stop, keep what we have
        }
        if out.len() as u64 + sz_unc as u64 > cap {
            return Err(LimitHit::new(
                "upx: decompressed size exceeds budget".into(),
            ));
        }
        let cdata = &data[dstart..dstart + sz_cpr];
        let block = if sz_cpr == sz_unc {
            cdata.to_vec() // stored
        } else if method == M_NRV2B {
            nrv2b_decompress(cdata, sz_unc)?
        } else if method == M_NRV2D {
            nrv2d_decompress(cdata, sz_unc)?
        } else if method == M_NRV2E {
            nrv2e_decompress(cdata, sz_unc)?
        } else if method == M_LZMA {
            match lzma_block_decompress(cdata, sz_unc) {
                Ok(b) => b,
                Err(_) => break, // unfilter/variant we can't handle — keep what we have
            }
        } else if method == M_DEFLATE {
            match deflate_block_decompress(cdata, sz_unc) {
                Ok(b) => b,
                Err(_) => break,
            }
        } else {
            break; // unknown method — stop the walk, keep what we have
        };
        if block.len() != sz_unc {
            break;
        }
        out.extend_from_slice(&block);
        pos = dstart + sz_cpr;
    }
    // NOTE: `b_ftid` (x86 call/jmp filter) is intentionally not reversed. Modern
    // `upx` does not filter ELF (the id is 0), and the filter only rewrites the
    // 4-byte operands of CALL/JMP — strings and data, which signatures mostly key
    // on, are recovered exactly regardless. Reversing it for PE needs a nonzero
    // `addvalue` derived from the unpacked PE layout, and no filtered-ELF test
    // vector exists to validate against, so it is deferred rather than shipped
    // unvalidated (a wrong inverse would corrupt code bytes).

    if out.is_empty() {
        return Ok(None);
    }
    budget.commit(out.len() as u64);
    Ok(visit(
        Entry::new("upx-decompressed".to_string(), out),
        budget,
    ))
}

/// Decompress a UPX DEFLATE (method 15) block: a raw DEFLATE stream (no zlib
/// header/footer); the uncompressed size comes from `b_info.sz_unc`.
fn deflate_block_decompress(cdata: &[u8], sz_unc: usize) -> Result<Vec<u8>, LimitHit> {
    use flate2::read::DeflateDecoder;
    let mut out = Vec::with_capacity(sz_unc.min(1 << 20));
    DeflateDecoder::new(cdata)
        .take(sz_unc as u64)
        .read_to_end(&mut out)
        .map_err(|e| LimitHit::new(format!("upx deflate: {e}")))?;
    Ok(out)
}

#[inline]
fn u32_le(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

/// Decompress a UPX LZMA (method 14) block. UPX stores the LZMA lc/lp/pb
/// properties in a 2-byte header at the start of the compressed payload (NOT the
/// standard 5-byte header), and the uncompressed size comes from `b_info.sz_unc`
/// (not embedded). Reconstruct the `.lzma` (alone) framing and decode with
/// `lzma_rust2`.
fn lzma_block_decompress(cdata: &[u8], sz_unc: usize) -> Result<Vec<u8>, LimitHit> {
    if cdata.len() < 2 {
        return Err(LimitHit::new("upx lzma: short block".into()));
    }
    let (b0, b1) = (cdata[0], cdata[1]);
    let pb = (b0 & 7) as u32;
    let lp = (b1 >> 4) as u32;
    let lc = (b1 & 0x0f) as u32;
    // The top 5 bits of byte 0 redundantly encode lc+lp; reject if inconsistent
    // or out of the LZMA-legal ranges.
    if pb >= 5 || lp >= 5 || lc >= 9 || (b0 >> 3) as u32 != lc + lp {
        return Err(LimitHit::new("upx lzma: bad props".into()));
    }
    // Standard single LZMA properties byte, then a `.lzma`-alone header
    // (props + dict_size LE32 + uncompressed_size LE64) + the range-coded stream.
    let props = ((pb * 5 + lp) * 9 + lc) as u8;
    let dict = (sz_unc as u32).max(1 << 12);
    let mut framed = Vec::with_capacity(13 + cdata.len() - 2);
    framed.push(props);
    framed.extend_from_slice(&dict.to_le_bytes());
    framed.extend_from_slice(&(sz_unc as u64).to_le_bytes());
    framed.extend_from_slice(&cdata[2..]);
    let mut reader = lzma_rust2::LzmaReader::new_mem_limit(Cursor::new(framed), u32::MAX, None)
        .map_err(|e| LimitHit::new(format!("upx lzma: {e}")))?;
    let mut out = Vec::with_capacity(sz_unc.min(1 << 20));
    std::io::Read::read_to_end(&mut reader, &mut out)
        .map_err(|e| LimitHit::new(format!("upx lzma: {e}")))?;
    Ok(out)
}

/// Shared UCL/NRV bit reader (LE32): refill a 32-bit little-endian word from the
/// input, consume bits MSB-first; the bit-refill cursor and the literal/low-byte
/// cursor share one input position `ip`. Bounds-checked (any underrun is an Err,
/// never a panic on attacker-controlled data).
struct Br<'a> {
    src: &'a [u8],
    ip: usize,
    bb: u32,
    bc: u32,
}
impl<'a> Br<'a> {
    #[inline]
    fn new(src: &'a [u8]) -> Self {
        Br {
            src,
            ip: 0,
            bb: 0,
            bc: 0,
        }
    }
    #[inline]
    fn bit(&mut self) -> Result<u32, LimitHit> {
        if self.bc == 0 {
            if self.ip + 4 > self.src.len() {
                return Err(LimitHit::new("upx nrv: input underrun".into()));
            }
            self.bb = u32::from_le_bytes([
                self.src[self.ip],
                self.src[self.ip + 1],
                self.src[self.ip + 2],
                self.src[self.ip + 3],
            ]);
            self.ip += 4;
            self.bc = 32;
        }
        self.bc -= 1;
        Ok((self.bb >> self.bc) & 1)
    }
    #[inline]
    fn byte(&mut self) -> Result<usize, LimitHit> {
        let b = *self
            .src
            .get(self.ip)
            .ok_or_else(|| LimitHit::new("upx nrv: byte underrun".into()))?;
        self.ip += 1;
        Ok(b as usize)
    }
}

/// Copy an LZ back-reference: `count` bytes from `out[len-off..]`, byte-by-byte
/// (overlap-safe). `Ok(true)` once `dst_len` is reached.
#[inline]
fn copy_match(
    out: &mut Vec<u8>,
    off: usize,
    count: usize,
    dst_len: usize,
) -> Result<bool, LimitHit> {
    if off == 0 || off > out.len() {
        return Err(LimitHit::new("upx nrv: bad back-reference".into()));
    }
    let start = out.len() - off;
    for k in 0..count {
        let b = out[start + k];
        out.push(b);
        if out.len() >= dst_len {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Upper bound for any NRV gamma (offset/length) value. UPX match offsets and
/// lengths are bounded by the output size (≤ `max_entry_bytes`, ~256 MiB), far
/// below this; a larger value means a corrupt stream and would only ever be a
/// rejected match. Capping keeps the doubling loops and the downstream
/// `(m-3)*256` arithmetic from overflowing on hostile input.
const NRV_GAMMA_MAX: usize = u32::MAX as usize;

/// NRV2B offset-gamma: `m=1; do { m=2m+bit } while(!bit)`.
#[inline]
fn nrv_gamma(r: &mut Br) -> Result<usize, LimitHit> {
    let mut m = 1usize;
    loop {
        m = m * 2 + r.bit()? as usize;
        if m > NRV_GAMMA_MAX {
            return Err(LimitHit::corrupt("upx: corrupt NRV gamma".into()));
        }
        if r.bit()? == 1 {
            break;
        }
    }
    Ok(m)
}

/// Finish an NRV match length from a seeded first bit `ml`:
/// `ml = 2*ml + bit; if ml==0 { ml=1; do{ml=2ml+bit}while(!bit); ml+=2 }`.
#[inline]
fn nrv_len_tail(r: &mut Br, mut ml: usize) -> Result<usize, LimitHit> {
    ml = ml * 2 + r.bit()? as usize;
    if ml == 0 {
        ml = 1;
        loop {
            ml = ml * 2 + r.bit()? as usize;
            if ml > NRV_GAMMA_MAX {
                return Err(LimitHit::corrupt("upx: corrupt NRV length".into()));
            }
            if r.bit()? == 1 {
                break;
            }
        }
        ml += 2;
    }
    Ok(ml)
}

/// NRV2B (UCL) decompressor, LE32 variant.
fn nrv2b_decompress(src: &[u8], dst_len: usize) -> Result<Vec<u8>, LimitHit> {
    let mut r = Br::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(dst_len.min(1 << 20));
    let mut last: usize = 1;
    while out.len() < dst_len {
        while r.bit()? == 1 {
            out.push(r.byte()? as u8);
            if out.len() >= dst_len {
                return Ok(out);
            }
        }
        let m = nrv_gamma(&mut r)?;
        let off = if m == 2 {
            last
        } else {
            let v = (m - 3) * 256 + r.byte()?;
            if v == 0xffff_ffff {
                break; // end-of-stream marker
            }
            last = v + 1;
            last
        };
        let seed = r.bit()? as usize;
        let mut ml = nrv_len_tail(&mut r, seed)?;
        if off > 0xd00 {
            ml += 1;
        }
        if copy_match(&mut out, off, ml + 1, dst_len)? {
            return Ok(out);
        }
    }
    Ok(out)
}

/// NRV2D/NRV2E offset-gamma loop: like NRV2B but folds an extra data bit on each
/// non-terminating step. `m=1; loop { m=2m+bit; if bit break; m=(m-1)*2+bit }`.
#[inline]
fn nrv_gamma_de(r: &mut Br) -> Result<usize, LimitHit> {
    let mut m = 1usize;
    loop {
        m = m * 2 + r.bit()? as usize;
        if m > NRV_GAMMA_MAX {
            return Err(LimitHit::corrupt("upx: corrupt NRV gamma".into()));
        }
        if r.bit()? == 1 {
            break;
        }
        // `m >= 2` here (it only grows from 1), so `m - 1` can't underflow.
        m = (m - 1) * 2 + r.bit()? as usize;
        if m > NRV_GAMMA_MAX {
            return Err(LimitHit::corrupt("upx: corrupt NRV gamma".into()));
        }
    }
    Ok(m)
}

/// Resolve the NRV2D/NRV2E match offset and the seeded first length bit.
/// Non-reuse: `raw=(m-3)*256+byte`; end marker when `raw==0xffffffff`; the
/// inverted LSB of `raw` is the first length bit, then `off=(raw>>1)+1`.
/// Returns `None` on the end-of-stream marker.
#[inline]
fn nrv_de_offset(r: &mut Br, last: &mut usize) -> Result<Option<(usize, usize)>, LimitHit> {
    let m = nrv_gamma_de(r)?;
    if m == 2 {
        // reuse: first length bit comes from the stream
        Ok(Some((*last, r.bit()? as usize)))
    } else {
        let raw = (m - 3) * 256 + r.byte()?;
        if raw == 0xffff_ffff {
            return Ok(None); // end-of-stream marker
        }
        let len_seed = (!raw) & 1; // inverted LSB → first length bit
        *last = (raw >> 1) + 1;
        Ok(Some((*last, len_seed)))
    }
}

/// NRV2D (UCL) decompressor. Offset uses [`nrv_gamma_de`] + the LSB/shift; length
/// is NRV2B-style (2 bits then gamma+2); long-match threshold `0x500`.
fn nrv2d_decompress(src: &[u8], dst_len: usize) -> Result<Vec<u8>, LimitHit> {
    let mut r = Br::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(dst_len.min(1 << 20));
    let mut last: usize = 1;
    while out.len() < dst_len {
        while r.bit()? == 1 {
            out.push(r.byte()? as u8);
            if out.len() >= dst_len {
                return Ok(out);
            }
        }
        let Some((off, seed)) = nrv_de_offset(&mut r, &mut last)? else {
            break;
        };
        let mut ml = nrv_len_tail(&mut r, seed)?;
        if off > 0x500 {
            ml += 1;
        }
        if copy_match(&mut out, off, ml + 1, dst_len)? {
            return Ok(out);
        }
    }
    Ok(out)
}

/// NRV2E (UCL) decompressor — UPX's *default* method. Same offset code as NRV2D,
/// but a distinct match-length prefix tree: seeded bit 1 ⇒ len 1+bit (1..2);
/// else next bit 1 ⇒ len 3+bit (3..4); else a gamma length with a `+3` bias.
/// Long-match threshold `0x500`.
fn nrv2e_decompress(src: &[u8], dst_len: usize) -> Result<Vec<u8>, LimitHit> {
    let mut r = Br::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(dst_len.min(1 << 20));
    let mut last: usize = 1;
    while out.len() < dst_len {
        while r.bit()? == 1 {
            out.push(r.byte()? as u8);
            if out.len() >= dst_len {
                return Ok(out);
            }
        }
        let Some((off, seed)) = nrv_de_offset(&mut r, &mut last)? else {
            break;
        };
        // NRV2E length prefix tree.
        let mut ml = if seed != 0 {
            1 + r.bit()? as usize // 1..2
        } else if r.bit()? == 1 {
            3 + r.bit()? as usize // 3..4
        } else {
            // long gamma length with a +3 bias
            let mut m = 1usize;
            loop {
                m = m * 2 + r.bit()? as usize;
                if m > NRV_GAMMA_MAX {
                    return Err(LimitHit::corrupt("upx: corrupt NRV length".into()));
                }
                if r.bit()? == 1 {
                    break;
                }
            }
            m + 3
        };
        if off > 0x500 {
            ml += 1;
        }
        if copy_match(&mut out, off, ml + 1, dst_len)? {
            return Ok(out);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflate_block_roundtrips() {
        // UPX method 15 is a raw DEFLATE stream; verify the decoder recovers the
        // original size-bounded payload.
        use flate2::{write::DeflateEncoder, Compression};
        use std::io::Write as _;
        let orig: Vec<u8> = (0..4096u32).map(|i| (i * 7) as u8).collect();
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&orig).unwrap();
        let packed = enc.finish().unwrap();
        let out = deflate_block_decompress(&packed, orig.len()).expect("inflate");
        assert_eq!(out, orig);
    }

    #[test]
    fn nrv2b_block_roundtrips() {
        // Synthetic minimal UPX-ELF file with one NRV2B block (real upx output).
        let data = include_bytes!("../../tests/fixtures/upx_nrv2b_min.bin");
        let expected = include_bytes!("../../tests/fixtures/upx_nrv2b_expected.bin");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Upx, data, &mut budget).expect("extract");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data.len(), expected.len());
        assert_eq!(&entries[0].data, expected);
        // The recovered bytes are the original ELF header.
        assert_eq!(&entries[0].data[..4], b"\x7fELF");
    }

    /// NRV2D, NRV2E and LZMA each pack the SAME marker ELF, so all must
    /// decompress to byte-identical output containing the marker — validating the
    /// decoders against real `upx` output.
    #[test]
    fn nrv2d_nrv2e_lzma_decode_byte_exact() {
        let nrv2b = include_bytes!("../../tests/fixtures/upx_nrv2b_min.bin");
        let expected = include_bytes!("../../tests/fixtures/upx_nrv2b_expected.bin");
        // The nrv2d/nrv2e/lzma fixtures pack a different marker binary; cross-check
        // them against each other (identical source) and the marker string.
        const MARKER: &[u8] = b"EXAV_UNIQUE_MARKER";
        let decode = |data: &[u8]| -> Vec<u8> {
            let mut b = Budget::new(Limits {
                max_total_bytes: 1 << 30,
                max_entry_bytes: 1 << 30,
                max_ratio: u64::MAX,
                ..Default::default()
            });
            extract(Format::Upx, data, &mut b)
                .unwrap()
                .into_iter()
                .next()
                .map(|e| e.data)
                .unwrap_or_default()
        };
        // Sanity: NRV2B fixture still decodes to its expected ELF.
        assert_eq!(decode(nrv2b), expected);
        let d = decode(include_bytes!("../../tests/fixtures/upx_nrv2d.upx"));
        let e = decode(include_bytes!("../../tests/fixtures/upx_nrv2e.upx"));
        let l = decode(include_bytes!("../../tests/fixtures/upx_lzma.upx"));
        assert!(
            !d.is_empty() && d == e && e == l,
            "nrv2d/nrv2e/lzma must agree"
        );
        assert!(
            d.windows(MARKER.len()).any(|w| w == MARKER),
            "marker recovered"
        );
    }

    #[test]
    fn not_upx_returns_empty() {
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Upx, b"\x7fELF not packed at all", &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn truncated_block_does_not_panic() {
        let data = include_bytes!("../../tests/fixtures/upx_nrv2b_min.bin");
        let mut budget = Budget::new(Limits::default());
        // Chop the compressed data mid-block; must not panic.
        let _ = extract(Format::Upx, &data[..data.len() - 80], &mut budget);
    }
}
