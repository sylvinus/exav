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
//! Only NRV2B and stored are decompressed today; other methods stop the walk and
//! we return whatever earlier blocks decompressed (the raw file is still scanned
//! by the caller, so packer signatures still match).
#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

const M_NRV2B: u8 = 2;

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
        let Some(li) = magic.checked_sub(4) else { continue };
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

pub(crate) fn extract_upx(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let Some(li) = find_packheader(data) else {
        return Ok(vec![]);
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
            return Err(LimitHit::new("upx: decompressed size exceeds budget".into()));
        }
        let cdata = &data[dstart..dstart + sz_cpr];
        let block = if sz_cpr == sz_unc {
            cdata.to_vec() // stored
        } else if method == M_NRV2B {
            nrv2b_decompress(cdata, sz_unc)?
        } else {
            // NRV2D/NRV2E/LZMA/DEFLATE not yet supported — stop the walk.
            break;
        };
        if block.len() != sz_unc {
            break;
        }
        out.extend_from_slice(&block);
        pos = dstart + sz_cpr;
    }

    if out.is_empty() {
        return Ok(vec![]);
    }
    budget.commit(out.len() as u64);
    Ok(vec![Entry::new("upx-decompressed".to_string(), out)])
}

#[inline]
fn u32_le(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

/// NRV2B (UCL) decompressor, LE32 variant. Bit buffer is refilled 32 bits at a
/// time (little-endian word) and consumed MSB-first; the bit-refill cursor and
/// the literal/low-offset-byte cursor share one input position. Bounds-checked:
/// any input underrun or bad back-reference returns a `LimitHit` rather than
/// panicking on attacker-controlled data.
fn nrv2b_decompress(src: &[u8], dst_len: usize) -> Result<Vec<u8>, LimitHit> {
    struct Br<'a> {
        src: &'a [u8],
        ip: usize,
        bb: u32,
        bc: u32,
    }
    impl Br<'_> {
        #[inline]
        fn bit(&mut self) -> Result<u32, LimitHit> {
            if self.bc == 0 {
                if self.ip + 4 > self.src.len() {
                    return Err(LimitHit::new("upx nrv2b: input underrun".into()));
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
                .ok_or_else(|| LimitHit::new("upx nrv2b: byte underrun".into()))?;
            self.ip += 1;
            Ok(b as usize)
        }
    }

    let mut r = Br {
        src,
        ip: 0,
        bb: 0,
        bc: 0,
    };
    let mut out: Vec<u8> = Vec::with_capacity(dst_len.min(1 << 20));
    let mut last: usize = 1;

    while out.len() < dst_len {
        // Literal run.
        while r.bit()? == 1 {
            let b = r.byte()? as u8;
            out.push(b);
            if out.len() >= dst_len {
                return Ok(out);
            }
        }
        // Offset high bits (gamma), then optional low byte.
        let mut m: usize = 1;
        loop {
            m = m * 2 + r.bit()? as usize;
            if r.bit()? == 1 {
                break;
            }
        }
        let off = if m == 2 {
            last
        } else {
            // m >= 3 here, so m - 3 cannot underflow.
            let v = (m - 3) * 256 + r.byte()?;
            if v == 0xffff_ffff {
                break; // explicit end-of-stream marker
            }
            last = v + 1;
            last
        };
        // Match length (gamma).
        let mut ml: usize = r.bit()? as usize;
        ml = ml * 2 + r.bit()? as usize;
        if ml == 0 {
            ml = 1;
            loop {
                ml = ml * 2 + r.bit()? as usize;
                if r.bit()? == 1 {
                    break;
                }
            }
            ml += 2;
        }
        if off > 0xd00 {
            ml += 1;
        }
        // Copy ml + 1 bytes from the back-reference.
        if off == 0 || off > out.len() {
            return Err(LimitHit::new("upx nrv2b: bad back-reference".into()));
        }
        let start = out.len() - off;
        for k in 0..=ml {
            let b = out[start + k];
            out.push(b);
            if out.len() >= dst_len {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nrv2b_block_roundtrips() {
        // Synthetic minimal UPX-ELF file with one NRV2B block (real upx output).
        let data = include_bytes!("../../tests/fixtures/upx_nrv2b_min.bin");
        let expected = include_bytes!("../../tests/fixtures/upx_nrv2b_expected.bin");
        let mut budget = Budget::new(Limits::default());
        let entries = extract_upx(data, &mut budget).expect("extract");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data.len(), expected.len());
        assert_eq!(&entries[0].data, expected);
        // The recovered bytes are the original ELF header.
        assert_eq!(&entries[0].data[..4], b"\x7fELF");
    }

    #[test]
    fn not_upx_returns_empty() {
        let mut budget = Budget::new(Limits::default());
        let entries = extract_upx(b"\x7fELF not packed at all", &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn truncated_block_does_not_panic() {
        let data = include_bytes!("../../tests/fixtures/upx_nrv2b_min.bin");
        let mut budget = Budget::new(Limits::default());
        // Chop the compressed data mid-block; must not panic.
        let _ = extract_upx(&data[..data.len() - 80], &mut budget);
    }
}
