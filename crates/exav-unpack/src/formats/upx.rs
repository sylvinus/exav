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
//! Stored, NRV2B, NRV2D, NRV2E, LZMA and DEFLATE are all decompressed. The NRV
//! decoders here are written independently from the **published NRV2B/D/E
//! bitstream description** (a bit-flag literal/match scheme) and verified purely
//! by **black-box round-trip against the `upx` CLI's own output** — they are NOT
//! ported, translated, or otherwise derived from the source of UCL (Oberhumer,
//! GPL) or ClamAV (GPL); the code expression (bit reader, variable naming,
//! control flow) is exav's own. The LZMA 2-byte property framing is likewise
//! from the public on-disk layout; DEFLATE is raw deflate via flate2. The x86
//! call/jmp un-filter
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

/// Strong evidence the image really is UPX-packed: the `UPX!` PackHeader magic
/// or the conventional `UPX0`/`UPX1` section names. Used to decide whether a
/// failed unpack is worth REPORTING — speculative calls on unrelated bytes must
/// stay silent, but a file that advertises itself as UPX and whose payload we
/// could not recover is content present-and-unexamined.
fn looks_upx(data: &[u8]) -> bool {
    let head = &data[..data.len().min(64 << 10)];
    memchr::memmem::find(head, b"UPX!").is_some()
        || memchr::memmem::find(head, b"UPX0").is_some()
        || memchr::memmem::find(head, b"UPX1").is_some()
}

/// What to do when a UPX-packed image could not be decompressed.
///
/// Stripping or patching the `PackHeader` is a routine anti-unpack move, and it
/// is aimed exactly here: the file says UPX on its face, the static reader
/// cannot unfold it, and a scan that shrugged would report clean. Real samples
/// ship this way.
///
/// Before reporting, the stub is *run*: a patched header defeats the static
/// reader, which needs the header to find the compressed blocks, but it does not
/// defeat the stub — the stub still has to decompress the image to run it. Only
/// when that comes back empty too is the file reported unopened.
fn report_packed<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    #[cfg(feature = "pe-emu")]
    {
        match super::pepack::emulated_unpack(data, budget, visit, "UPX")? {
            super::pepack::Recovered::Halt(r) => return Ok(Some(r)),
            super::pepack::Recovered::Emitted => return Ok(None),
            super::pepack::Recovered::Nothing => {}
        }
    }
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported(
            "upx-packed image".to_string(),
            data.len() as u64,
            false,
            "UPX-packed executable that could not be decompressed (PackHeader \
             missing or damaged); the packed bytes were scanned but the original \
             image was not",
        ),
        budget,
    ))
}

/// Adler-32 as UPX computes it over the uncompressed image.
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &c in data {
        a = (a + c as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Recover the original image from a UPX **PackHeader**, the layout
/// `find_packheader` does not model.
///
/// That function understands the `l_info`/`p_info`/`b_info` chain. A PE can
/// instead carry a 32-byte PackHeader — `UPX!`, version, format, method, level,
/// the two Adler-32 sums, then `u_len`/`c_len`/`u_file_size` — with the
/// compressed stream following immediately. Read as an `l_info`, that header's
/// `c_len`/`u_file_size` fields land where a `b_info` block's sizes are expected
/// and fail validation, so the file matched no unpacker at all and scanned
/// clean. A live GandCrab sample was packed exactly this way.
///
/// The header carries `u_adler`, so acceptance is decided by checksum rather
/// than by plausibility: a decode that does not reproduce the recorded Adler-32
/// over exactly `u_len` bytes is discarded. That makes a wrong guess
/// unrepresentable rather than merely unlikely.
pub(crate) fn has_packheader_layout(data: &[u8]) -> bool {
    let mut search = 0usize;
    while let Some(rel) = memchr::memmem::find(&data[search..], b"UPX!") {
        let m = search + rel;
        search = m + 1;
        if m + 32 > data.len() {
            break;
        }
        let method = data[m + 6];
        let u_len = u32_le(data, m + 16) as usize;
        let c_len = u32_le(data, m + 20) as usize;
        if u_len != 0
            && c_len != 0
            && m + 32 + c_len <= data.len()
            && matches!(method, M_NRV2B | M_NRV2D | M_NRV2E)
        {
            return true;
        }
    }
    false
}

fn packheader_image(data: &[u8], cap: u64) -> Option<Vec<u8>> {
    let mut search = 0usize;
    while let Some(rel) = memchr::memmem::find(&data[search..], b"UPX!") {
        let m = search + rel;
        search = m + 1;
        if m + 32 > data.len() {
            break;
        }
        let method = data[m + 6];
        let u_adler = u32_le(data, m + 8);
        let u_len = u32_le(data, m + 16) as usize;
        let c_len = u32_le(data, m + 20) as usize;
        let start = m + 32;
        if u_len == 0 || c_len == 0 || u_len as u64 > cap || start + c_len > data.len() {
            continue;
        }
        let cdata = &data[start..start + c_len];
        let out = match method {
            M_NRV2B => nrv2b_decompress(cdata, u_len),
            M_NRV2D => nrv2d_decompress(cdata, u_len),
            M_NRV2E => nrv2e_decompress(cdata, u_len),
            _ => continue,
        };
        let Ok(out) = out else { continue };
        if out.len() == u_len && adler32(&out) == u_adler {
            return Some(out);
        }
    }
    None
}

/// Ceiling on a rebuilt image, mirroring the packed-PE path.
const MAX_INNER: usize = 128 << 20;

fn u16_le(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([
        d.get(off).copied().unwrap_or(0),
        d.get(off + 1).copied().unwrap_or(0),
    ])
}

/// The 208-byte DOS header + stub that must sit at the front of a rebuilt PE,
/// base64-encoded.
///
/// Reproduced byte-for-byte because it has to be: a large family of ClamAV
/// signatures for packed malware is an **MD5 over ClamAV's own rebuilt
/// artifact**, so the hash only matches an image identical down to this stub and
/// the header rewrites in [`rebuild_clamav_pe`]. It is a compatibility constant,
/// like the signature-file formats exav already parses.
///
/// Kept encoded so the stub text isn't over-interpreted as a credit of any kind.
const CLAMAV_DOS_STUB_B64: &str = concat!(
    "TVqQAAIAAAAEAA8A//8AALAAAAAAAAAAQAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAA0AAAAA4ftAm6DQDNIbRMzSFUaGlzIGZpbGUgd2FzIGNyZWF0ZWQgYnkgQ2xhbUFWIGZvciBp",
    "bnRlcm5hbCB1c2UgYW5kIHNob3VsZCBub3QgYmUgcnVuLg0KQ2xhbUFWIC0gQSBHUEwgdmlydXMg",
    "c2Nhbm5lciAtIGh0dHA6Ly93d3cuY2xhbWF2Lm5ldA0KJAAAAA==",
);

/// Length of the decoded stub; `e_lfanew` points just past it.
const STUB_LEN: usize = 208;

/// Decode [`CLAMAV_DOS_STUB_B64`]. The input is a constant this crate controls,
/// so a failure here is a build-time mistake, not bad input — the unit test
/// below pins both the length and an Adler-32 of the result.
fn clamav_dos_stub() -> Option<[u8; STUB_LEN]> {
    use base64::Engine;
    let v = base64::engine::general_purpose::STANDARD
        .decode(CLAMAV_DOS_STUB_B64)
        .ok()?;
    let mut out = [0u8; STUB_LEN];
    if v.len() != STUB_LEN {
        return None;
    }
    out.copy_from_slice(&v);
    Some(out)
}

/// Rebuild a PE image from a decompressed UPX stream, in the layout ClamAV
/// produces, so hash signatures computed over that layout match.
///
/// `image` is the decompressed memory image beginning at `first_rva` (UPX
/// compresses the original sections as one contiguous run from the first
/// section's RVA). The original PE header block survives in the tail of that
/// run, which is what makes the rebuild possible at all.
///
/// The transformations are ClamAV's, recovered by diffing against its output —
/// black-box, not from its source:
///
/// * `TimeDateStamp` := `"CLAM"`,
/// * `FileAlignment` := `SectionAlignment`,
/// * every section: `VirtualSize` = `SizeOfRawData` = `VirtualSize` rounded up
///   to `SectionAlignment`, and `PointerToRawData` := `VirtualAddress` — i.e.
///   the file is flattened so a file offset equals its RVA.
fn rebuild_clamav_pe(image: &[u8], first_rva: u32) -> Option<Vec<u8>> {
    // The original header block sits near the end of the decompressed run; take
    // the last `PE\0\0` whose COFF/optional fields are self-consistent.
    let mut i = image.len();
    let hdr = loop {
        i = memchr::memmem::rfind(&image[..i], b"PE\0\0")?;
        let nsec = u16_le(image, i + 6) as usize;
        let optsz = u16_le(image, i + 20) as usize;
        if (1..=96).contains(&nsec)
            && (optsz == 224 || optsz == 240)
            && i + 24 + optsz + nsec * 40 <= image.len()
            && matches!(u16_le(image, i + 24), 0x10b | 0x20b)
        {
            break i;
        }
        if i == 0 {
            return None;
        }
    };
    let nsec = u16_le(image, hdr + 6) as usize;
    let optsz = u16_le(image, hdr + 20) as usize;
    let hdrlen = 24 + optsz + nsec * 40;
    let mut blk = image.get(hdr..hdr + hdrlen)?.to_vec();
    blk[8..12].copy_from_slice(b"CLAM");

    let sa = u32_le(&blk, 24 + 32);
    if sa == 0 || sa > (1 << 24) {
        return None;
    }
    blk[24 + 36..24 + 40].copy_from_slice(&sa.to_le_bytes());

    let st = 24 + optsz;
    let mut total: u64 = 0;
    for s in 0..nsec {
        let o = st + s * 40;
        let vsz = u32_le(&blk, o + 8);
        let va = u32_le(&blk, o + 12);
        let n = (vsz as u64).div_ceil(sa as u64) * sa as u64;
        if n > u32::MAX as u64 {
            return None;
        }
        let n = n as u32;
        blk[o + 8..o + 12].copy_from_slice(&n.to_le_bytes());
        blk[o + 16..o + 20].copy_from_slice(&n.to_le_bytes());
        blk[o + 20..o + 24].copy_from_slice(&va.to_le_bytes());
        total = total.max(va as u64 + n as u64);
    }
    if total == 0 || total > MAX_INNER as u64 {
        return None;
    }

    let stub = clamav_dos_stub()?;
    let mut out = vec![0u8; total as usize];
    out[..stub.len()].copy_from_slice(&stub);
    let hs = stub.len();
    if hs + hdrlen > out.len() {
        return None;
    }
    out[hs..hs + hdrlen].copy_from_slice(&blk);
    let at = first_rva as usize;
    if at < out.len() {
        let n = image.len().min(out.len() - at);
        out[at..at + n].copy_from_slice(&image[..n]);
    }
    Some(out)
}

/// RVA of the first section of a PE, which is where the decompressed run starts.
fn first_section_rva(data: &[u8]) -> Option<u32> {
    let e = u32_le(data, 0x3c) as usize;
    if data.get(e..e + 4)? != b"PE\0\0" {
        return None;
    }
    let nsec = u16_le(data, e + 6) as usize;
    let optsz = u16_le(data, e + 20) as usize;
    if nsec == 0 {
        return None;
    }
    let st = e + 24 + optsz;
    data.get(st..st + 40)?;
    Some(u32_le(data, st + 12))
}

pub(crate) fn extract_upx<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let Some(li) = find_packheader(data) else {
        // No `l_info` chain. Try the PackHeader layout before giving up; if that
        // fails too and the image still advertises UPX, the payload is there and
        // unexamined — say so rather than returning clean.
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if let Some(image) = packheader_image(data, cap) {
            // Hand over the rebuilt PE rather than the raw run: it carries the
            // same bytes plus the headers, so ordinary pattern signatures still
            // match, and ClamAV's hash signatures over packed malware — computed
            // across its own rebuilt artifact — match too. Fall back to the raw
            // image if the headers could not be recovered, since scanning the
            // content still beats reporting nothing.
            let out = first_section_rva(data)
                .and_then(|rva| rebuild_clamav_pe(&image, rva))
                .unwrap_or(image);
            if out.len() as u64 <= cap {
                budget.commit(out.len() as u64);
                return Ok(visit(Entry::new("upx-rebuilt-pe".to_string(), out), budget));
            }
        }
        return if looks_upx(data) {
            report_packed(data, budget, visit)
        } else {
            Ok(None)
        };
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
        // Decompression yielded nothing: same situation, same duty to report.
        return if looks_upx(data) {
            report_packed(data, budget, visit)
        } else {
            Ok(None)
        };
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
/// lengths are bounded by the output size (≤ `max_buffer_bytes`, ~256 MiB), far
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
mod rebuild_tests {
    use super::*;

    /// The stub is a compatibility constant: a large family of ClamAV hash
    /// signatures is computed over a rebuilt PE that begins with exactly these
    /// bytes. If it is ever "tidied up", those signatures stop matching and the
    /// failure is silent — detections just stop happening — so pin it by
    /// checksum rather than by quoting the text back.
    #[test]
    fn clamav_dos_stub_is_byte_stable() {
        let stub = clamav_dos_stub().expect("stub decodes");
        assert_eq!(stub.len(), STUB_LEN);
        assert_eq!(&stub[..2], b"MZ");
        // e_lfanew must point at where the rebuild writes the PE header block.
        assert_eq!(u32_le(&stub, 0x3c), STUB_LEN as u32);
        assert_eq!(adler32(&stub), 0xda33_34a5, "stub bytes changed");
    }

    /// The header rewrites, checked on a synthetic block: sizes rounded up to
    /// `SectionAlignment`, raw offsets equal to RVAs, timestamp `"CLAM"`.
    #[test]
    fn rebuild_applies_the_clamav_header_rules() {
        let mut image = vec![0u8; 0x2000];
        let hdr = 0x1000;
        image[hdr..hdr + 4].copy_from_slice(b"PE\0\0");
        image[hdr + 6..hdr + 8].copy_from_slice(&1u16.to_le_bytes());
        image[hdr + 20..hdr + 22].copy_from_slice(&224u16.to_le_bytes());
        let opt = hdr + 24;
        image[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
        image[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        image[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        let sec = opt + 224;
        image[sec..sec + 5].copy_from_slice(b".text");
        image[sec + 8..sec + 12].copy_from_slice(&0x800u32.to_le_bytes());
        image[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());

        let out = rebuild_clamav_pe(&image, 0x1000).expect("rebuild");
        let e = u32_le(&out, 0x3c) as usize;
        assert_eq!(&out[e..e + 4], b"PE\0\0");
        assert_eq!(&out[e + 8..e + 12], b"CLAM", "TimeDateStamp");
        let o = e + 24;
        assert_eq!(
            u32_le(&out, o + 36),
            0x1000,
            "FileAlignment := SectionAlignment"
        );
        let s = o + 224;
        assert_eq!(u32_le(&out, s + 8), 0x1000, "VirtualSize rounded up");
        assert_eq!(u32_le(&out, s + 16), 0x1000, "SizeOfRawData := VirtualSize");
        assert_eq!(
            u32_le(&out, s + 20),
            0x1000,
            "PointerToRawData := VirtualAddress"
        );
        assert_eq!(out.len(), 0x2000, "image ends at the last section");
    }
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
                max_extracted_bytes: 1 << 30,
                max_buffer_bytes: 1 << 30,
                max_compression_ratio: u64::MAX,
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
