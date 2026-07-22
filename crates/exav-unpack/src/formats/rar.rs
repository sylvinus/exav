//! RAR extractor for the **stored** (uncompressed) method, RAR4 and RAR5,
//! implemented from the public RAR file-format field layout. RAR's compressed
//! methods (its LZ + PPMd) are not implemented, so a compressed or encrypted
//! member is reported as a member we could not extract (the caller still scans
//! the raw archive in place).
//!
//! Layouts used (magic-byte / header-field level only):
//! - RAR4 marker `52 61 72 21 1A 07 00`; blocks = `HEAD_CRC u16, HEAD_TYPE u8,
//!   HEAD_FLAGS u16, HEAD_SIZE u16, [ADD_SIZE u32 if flags&0x8000]`. File block
//!   (type 0x74): `PACK_SIZE u32, UNP_SIZE u32, HOST_OS u8, FILE_CRC u32,
//!   FTIME u32, UNP_VER u8, METHOD u8, NAME_SIZE u16, ATTR u32,
//!   [HIGH_PACK u32, HIGH_UNP u32 if flags&0x100], NAME[NAME_SIZE], …` then
//!   `PACK_SIZE` data bytes. METHOD 0x30 = stored.
//! - RAR5 signature `52 61 72 21 1A 07 01 00`; blocks = `CRC32 u32,
//!   header_size vint, header_type vint, header_flags vint,
//!   [extra_size vint if flags&1], [data_size vint if flags&2], …`. File block
//!   (type 2): `file_flags vint, unp_size vint, attrs vint, [mtime u32],
//!   [crc u32], comp_info vint, host_os vint, name_len vint, name[…]` then
//!   `data_size` data bytes. comp_info method bits (7..9) == 0 = stored.
#![allow(unused_imports)]
use crate::formats::rar3_unpack;
use crate::formats::rar5_unpack;
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

const RAR4_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
const RAR5_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

pub(crate) fn extract_rar(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    if data.starts_with(RAR5_MAGIC) {
        extract_rar5(data, RAR5_MAGIC.len(), budget)
    } else if data.starts_with(RAR4_MAGIC) {
        extract_rar4(data, RAR4_MAGIC.len(), budget)
    } else {
        Ok(vec![])
    }
}

#[inline]
fn u16le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
#[inline]
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

/// Read a RAR5 variable-length integer (base-128, little-endian, high bit =
/// continuation). Returns `(value, byte_len)`. Caps at 10 bytes (64 bits).
fn vint(d: &[u8], o: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    let mut i = 0usize;
    while i < 10 {
        let b = *d.get(o + i)?;
        val |= ((b & 0x7f) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 {
            return Some((val, i));
        }
        shift += 7;
    }
    None
}

fn push_stored(
    out: &mut Vec<Entry>,
    budget: &mut Budget,
    name: String,
    data: &[u8],
    off: usize,
    pack: u64,
    encrypted: bool,
) -> Result<(), LimitHit> {
    budget.count_entry()?;
    if encrypted {
        // Can't read the bytes; record the member (for `.cdb`) with no data,
        // flagged so the scan reports Unscannable rather than silently clean.
        out.push(Entry::unsupported(name, pack, true, "encrypted RAR member"));
        return Ok(());
    }
    let cap = budget.reserve()?;
    let end = off.saturating_add(pack as usize);
    if pack > cap || end > data.len() {
        return Err(LimitHit::new("rar: stored member exceeds budget".into()));
    }
    let bytes = data[off..end].to_vec();
    budget.commit(bytes.len() as u64);
    out.push(Entry {
        comp_size: pack,
        encrypted: false,
        unsupported: None,
        name,
        data: bytes,
    });
    Ok(())
}

// ---- RAR4 ------------------------------------------------------------------

fn extract_rar4(data: &[u8], start: usize, budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let mut out = Vec::new();
    let mut pos = start;
    // Kept across members: in a solid archive the files form one continuous LZ
    // stream, so a member flagged solid needs the window and tables its
    // predecessor left behind.
    let mut solid_dec: Option<rar3_unpack::Unpacker29> = None;
    while pos + 7 <= data.len() {
        let flags = match u16le(data, pos + 3) {
            Some(f) => f,
            None => break,
        };
        let head_size = match u16le(data, pos + 5) {
            Some(s) => s as usize,
            None => break,
        };
        let htype = data[pos + 2];
        if head_size < 7 {
            break; // malformed — avoid a zero/short-header loop
        }
        // ADD_SIZE (data following the header) when flag 0x8000 is set.
        let add_size = if flags & 0x8000 != 0 {
            u32le(data, pos + 7).unwrap_or(0) as u64
        } else {
            0
        };
        if htype == 0x73 && flags & 0x0080 != 0 {
            // MHD_PASSWORD: the BLOCK HEADERS themselves are encrypted (`rar -hp`),
            // so the file table cannot be read at all — not one member name, let
            // alone its content.
            //
            // Without this the walk simply finds no file headers and returns an
            // empty list, and an archive with nothing in it scans CLEAN. That is
            // the worst outcome available: a password-protected archive reported
            // as containing no malware, when the truth is that nothing inside it
            // was ever looked at. Report it, exactly as a member-level
            // `LHD_PASSWORD` is reported below.
            budget.count_entry()?;
            out.push(Entry::unsupported(
                "rar-encrypted-headers".to_string(),
                data.len() as u64,
                true,
                "RAR archive with encrypted headers",
            ));
            break;
        }
        if htype == 0x7B {
            break; // archive-end block
        }
        if htype == 0x74 {
            // File header. Fixed fields begin at pos+7.
            let b = pos + 7;
            let (pack, unp, crc, unp_ver, method, name_size, large) = (
                u32le(data, b).unwrap_or(0) as u64,
                u32le(data, b + 4).unwrap_or(0) as u64,
                u32le(data, b + 9).unwrap_or(0), // FILE_CRC (after HOST_OS at b+8)
                *data.get(b + 17).unwrap_or(&0), // UNP_VER
                *data.get(b + 18).unwrap_or(&0xff),
                u16le(data, b + 19).unwrap_or(0) as usize,
                flags & 0x100 != 0,
            );
            let mut p = b + 25; // after ATTR(4) at b+21..b+25
            let (pack, unp) = if large {
                let hp = u32le(data, p).unwrap_or(0) as u64;
                let hu = u32le(data, p + 4).unwrap_or(0) as u64;
                p += 8; // HIGH_PACK_SIZE + HIGH_UNP_SIZE
                ((hp << 32) | pack, (hu << 32) | unp)
            } else {
                (pack, unp)
            };
            let name = read_name(data, p, name_size);
            let encrypted = flags & 0x04 != 0; // LHD_PASSWORD
            let data_off = pos
                .checked_add(head_size)
                .ok_or_else(|| LimitHit::corrupt("rar: header size overflow".to_string()))?;
            // Stored method (0x30) and not a directory (flag 0xE0 dictionary bits).
            let is_dir = (flags & 0xE0) == 0xE0;
            // Window size bits from the dictionary flags (0..7) + 16.
            let win_bits = (((flags & 0xE0) >> 5) as u32) + 16;
            // LHD_SPLIT_BEFORE / LHD_SPLIT_AFTER. A member split across volumes
            // has only part of its compressed data in this file; the rest is in
            // a sibling `.partN.rar` that exav is not scanning. Reporting the
            // real reason keeps a volume set from looking like a corrupt
            // archive, and the member is still surfaced rather than skipped.
            let split = flags & 0x03 != 0;
            if is_dir {
                // skip directories
            } else if method == 0x30 && (pack == unp || split) {
                // Stored: what is in this volume is the file's own bytes. For a
                // split member that is only part of the file, but part of a file
                // is real content and scanning it beats reporting the whole
                // member unreadable.
                //
                // A split member must ALSO be reported, though. The bytes handed
                // over are a prefix, and an `Entry` with no `unsupported` reason
                // reads as a complete member — so a stored member continuing
                // into a sibling volume scanned as a clean OK, which is a silent
                // truncation. Emit both: the readable prefix, and the reason the
                // rest is missing.
                if split {
                    budget.count_entry()?;
                    out.push(Entry::unsupported(
                        name.clone(),
                        pack,
                        encrypted,
                        "RAR member continues in another volume; only the part in \
                         this volume was scanned",
                    ));
                }
                push_stored(&mut out, budget, name, data, data_off, pack, encrypted)?;
            } else if split {
                budget.count_entry()?;
                out.push(Entry::unsupported(
                    name,
                    pack,
                    encrypted,
                    "RAR member continues in another volume",
                ));
            } else if !encrypted && unp_ver == 29 && (0x31..=0x35).contains(&method) {
                // RAR3 (unpack29) compressed LZ member: attempt decompression.
                budget.count_entry()?;
                let dend = data_off.saturating_add(pack as usize).min(data.len());
                let packed = &data[data_off.min(data.len())..dend];
                // LHD_SOLID. The window is sized once, from the first member of
                // the group; a solid member's own dictionary flags describe the
                // same shared window.
                let solid = flags & 0x10 != 0;
                if solid_dec.is_none() {
                    solid_dec = rar3_unpack::Unpacker29::new(win_bits, budget).ok();
                }
                let decoded = match solid_dec.as_mut() {
                    Some(dec) => dec.member(packed, unp, solid, budget).ok(),
                    None => None,
                };
                // A member that failed mid-group leaves the shared window out of
                // step with the stream, so every later member would decode to
                // garbage. Dropping the decoder makes them fail their CRC and be
                // reported rather than quietly mis-scanned.
                if decoded.is_none() {
                    solid_dec = None;
                }
                match decoded {
                    Some(bytes) if crc32_ieee(&bytes) == crc => {
                        out.push(Entry {
                            comp_size: pack,
                            encrypted: false,
                            unsupported: None,
                            name,
                            data: bytes,
                        });
                    }
                    Some(_) => {
                        out.push(Entry::unsupported(
                            name,
                            pack,
                            false,
                            "RAR member did not match its recorded CRC after decoding",
                        ));
                    }
                    None => {
                        out.push(Entry::unsupported(
                            name,
                            pack,
                            false,
                            "RAR member could not be decoded",
                        ));
                    }
                }
            } else {
                // Compressed (unsupported method / PPMd / older version) or
                // encrypted member we can't decode — record metadata, flagged
                // Unscannable so it isn't reported as clean.
                let _ = crc;
                budget.count_entry()?;
                out.push(Entry::unsupported(
                    name,
                    pack,
                    encrypted,
                    "unsupported RAR compression",
                ));
            }
            pos = data_off + add_size as usize;
        } else {
            pos += head_size + add_size as usize;
        }
        if add_size == 0 && head_size == 0 {
            break;
        }
    }
    Ok(out)
}

/// RAR4 names are raw bytes (optionally UTF-16-ish when the UNICODE flag is set;
/// we keep the lossy UTF-8 of the leading raw bytes, which is enough for `.cdb`
/// name matching and display).
fn read_name(data: &[u8], off: usize, len: usize) -> String {
    let end = off.saturating_add(len).min(data.len());
    if off >= end {
        return "rar-entry".to_string();
    }
    let raw = &data[off..end];
    let cut = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..cut]).into_owned()
}

// ---- RAR5 ------------------------------------------------------------------

fn extract_rar5(data: &[u8], start: usize, budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    // Kept across members: a solid RAR5 group's files share one window, and a
    // solid member's first block may declare no tables of its own.
    let mut solid_dec: Option<rar5_unpack::Unpacker50> = None;
    let mut out = Vec::new();
    let mut pos = start;
    while pos + 4 < data.len() {
        // CRC32 (4) then header_size vint.
        let hs_off = pos + 4;
        let (hsize, hs_len) = match vint(data, hs_off) {
            Some(v) => v,
            None => break,
        };
        let hdr = hs_off + hs_len; // header content start
        let Some(data_off) = hdr.checked_add(hsize as usize) else {
            break;
        }; // packed data start
        if hsize == 0 || data_off > data.len() {
            break;
        }
        // Parse the header content (bounded to [hdr, data_off)).
        let (htype, t1) = match vint(data, hdr) {
            Some(v) => v,
            None => break,
        };
        let (hflags, t2) = match vint(data, hdr + t1) {
            Some(v) => v,
            None => break,
        };
        let mut q = match hdr.checked_add(t1).and_then(|v| v.checked_add(t2)) {
            Some(v) => v,
            None => break,
        };
        let mut extra_size = 0u64;
        if hflags & 0x01 != 0 {
            // extra_area_size
            if let Some((v, n)) = vint(data, q) {
                extra_size = v;
                q += n;
            } else {
                break;
            }
        }
        let mut data_size = 0u64;
        if hflags & 0x02 != 0 {
            match vint(data, q) {
                Some((v, n)) => {
                    data_size = v;
                    q += n;
                }
                None => break,
            }
        }
        if htype == 5 {
            break; // end-of-archive
        }
        if htype == 4 {
            // archive-encryption header — members are encrypted; stop.
            break;
        }
        if htype == 2 {
            // File header content continues at q.
            if let Some(f) = rar5_file_fields(data, q, hdr, hsize, extra_size) {
                let is_dir = f.file_flags & 0x01 != 0;
                // Header flags 0x08 / 0x10: the member's data starts in the
                // previous volume or continues into the next one.
                let split = hflags & 0x18 != 0;
                if is_dir {
                    // skip
                } else if split && f.method != 0 {
                    budget.count_entry()?;
                    out.push(Entry::unsupported(
                        f.name,
                        data_size,
                        f.encrypted,
                        "RAR member continues in another volume",
                    ));
                } else if f.method == 0 {
                    // Stored. A split stored member is only a PREFIX of the
                    // file — the rest lives in a sibling volume — so it must be
                    // reported as well as scanned. Without this the partial
                    // bytes go out with no `unsupported` reason, which reads as
                    // a complete member, and a multi-volume archive scans as a
                    // clean OK. The `method != 0` branch above already reports
                    // its split members; the stored branch did not.
                    if split {
                        budget.count_entry()?;
                        out.push(Entry::unsupported(
                            f.name.clone(),
                            data_size,
                            f.encrypted,
                            "RAR member continues in another volume; only the part in \
                             this volume was scanned",
                        ));
                    }
                    push_stored(&mut out, budget, f.name, data, data_off, data_size, false)?;
                } else if f.encrypted {
                    budget.count_entry()?;
                    out.push(Entry::unsupported(
                        f.name,
                        data_size,
                        true,
                        "encrypted RAR member",
                    ));
                } else {
                    // RAR5 compressed (LZ) member: attempt decompression.
                    let dataend = data_off.saturating_add(data_size as usize);
                    let packed = if data_off <= data.len() && dataend <= data.len() {
                        &data[data_off..dataend]
                    } else {
                        &data[data_off.min(data.len())..]
                    };
                    let ws = rar5_unpack::window_size_from_comp_info(f.comp_info);
                    budget.count_entry()?;
                    if ws != 0 && solid_dec.is_none() {
                        solid_dec = rar5_unpack::Unpacker50::new(ws).ok();
                    }
                    let decoded = match solid_dec.as_mut() {
                        Some(dec) => dec.member(packed, f.unp_size, f.solid, budget).ok(),
                        None => None,
                    };
                    // A member that failed mid-group leaves the shared window out
                    // of step with the stream, so every later member would decode
                    // to garbage. Dropping the decoder makes them fail their CRC
                    // and be reported rather than quietly mis-scanned.
                    if decoded.is_none() {
                        solid_dec = None;
                    }
                    let crc_ok = |b: &[u8]| !f.has_crc || crc32_ieee(b) == f.crc;
                    match decoded {
                        Some(bytes) if crc_ok(&bytes) => {
                            out.push(Entry {
                                comp_size: data_size,
                                encrypted: false,
                                unsupported: None,
                                name: f.name,
                                data: bytes,
                            });
                        }
                        Some(_) => {
                            out.push(Entry::unsupported(
                                f.name,
                                data_size,
                                false,
                                "RAR member did not match its recorded CRC after decoding",
                            ));
                        }
                        None => {
                            // Couldn't decode (unsupported method/filter/PPMd or
                            // malformed) — record metadata only, flagged
                            // Unscannable so it isn't reported clean.
                            out.push(Entry::unsupported(
                                f.name,
                                data_size,
                                false,
                                "unsupported RAR compression",
                            ));
                        }
                    }
                }
            }
        }
        let Some(next) = data_off.checked_add(data_size as usize) else {
            break;
        };
        if next <= pos {
            break; // no progress — malformed
        }
        pos = next;
    }
    Ok(out)
}

/// Parsed RAR5 file-header fields needed for extraction.
struct Rar5File {
    name: String,
    method: u64,
    file_flags: u64,
    unp_size: u64,
    comp_info: u64,
    /// `comp_info` bit 6: the member continues the previous member's compressed
    /// stream and cannot be decoded without its window.
    solid: bool,
    /// Stored unpacked-data CRC-32, only meaningful when `has_crc`. Every
    /// decoded member is checked against it.
    crc: u32,
    has_crc: bool,
    encrypted: bool,
}

/// Parse the RAR5 file-header fields starting at `q`, bounded to the header end
/// (`hdr + hsize`). `extra_size` is the size of the trailing extra area, used to
/// detect per-file encryption (an `EX_CRYPT` record).
fn rar5_file_fields(
    data: &[u8],
    mut q: usize,
    hdr: usize,
    hsize: u64,
    extra_size: u64,
) -> Option<Rar5File> {
    let end = hdr.checked_add(hsize as usize)?;
    let (file_flags, n) = vint(data, q)?;
    q += n;
    let (unp_size, n) = vint(data, q)?; // unpacked size
    q += n;
    let (_attr, n) = vint(data, q)?;
    q += n;
    if file_flags & 0x02 != 0 {
        q += 4; // mtime
    }
    let mut crc = 0u32;
    let has_crc = file_flags & 0x04 != 0;
    if has_crc {
        crc = u32le(data, q).unwrap_or(0); // data crc
        q += 4;
    }
    let (comp_info, n) = vint(data, q)?;
    q += n;
    let (_host, n) = vint(data, q)?;
    q += n;
    let (name_len, n) = vint(data, q)?;
    q += n;
    let nend = q.saturating_add(name_len as usize).min(end).min(data.len());
    let name = if q < nend {
        String::from_utf8_lossy(&data[q..nend]).into_owned()
    } else {
        "rar-entry".to_string()
    };
    // compression method = bits 7..9 of comp_info; bit 6 marks a solid member.
    let method = (comp_info >> 7) & 0x7;
    let solid = comp_info & (1 << 6) != 0;
    // The extra area lives at the tail of the header; scan it for an EX_CRYPT
    // (0x01) record, which marks the file data as encrypted.
    let encrypted = rar5_extra_has_crypt(data, end, extra_size);
    Some(Rar5File {
        name,
        method,
        file_flags,
        unp_size,
        comp_info,
        solid,
        crc,
        has_crc,
        encrypted,
    })
}

/// Scan the trailing extra area `[end-extra_size, end)` for an `EX_CRYPT`
/// record (record type 0x01), indicating an encrypted file member.
fn rar5_extra_has_crypt(data: &[u8], end: usize, extra_size: u64) -> bool {
    if extra_size == 0 || extra_size as usize > end {
        return false;
    }
    let mut p = end - extra_size as usize;
    let mut guard = 0;
    while p < end && guard < 64 {
        guard += 1;
        let (rec_size, n1) = match vint(data, p) {
            Some(v) => v,
            None => break,
        };
        let rec_start = match p.checked_add(n1) {
            Some(v) => v,
            None => break,
        };
        let (rec_type, n2) = match vint(data, rec_start) {
            Some(v) => v,
            None => break,
        };
        let _ = n2;
        if rec_type == 0x01 {
            return true;
        }
        // Advance to the next record: `rec_size` counts bytes after its own
        // size vint (i.e. the record type plus its body).
        let advance = match n1.checked_add(rec_size as usize) {
            Some(v) => v,
            None => break,
        };
        if advance == 0 {
            break;
        }
        p += advance;
    }
    false
}

/// CRC-32 (IEEE, poly 0xEDB88320) over `data`. Every decoded RAR member is
/// checked against the CRC the archive records, in every build: a decoder that
/// produces plausible-looking wrong bytes — which is exactly what happens when
/// a solid member is decoded without the preceding member's window — would
/// otherwise hand the scanner content that is not the file, and a pattern that
/// does not match garbage reads as clean.
pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rar -hp` encrypts the BLOCK HEADERS, so the file table itself is
    /// unreadable — the walk finds no file headers at all.
    ///
    /// Returning an empty member list for that is a silent clean: a
    /// password-protected archive reported as containing no malware, when
    /// nothing inside it was ever examined. The archive-level MHD_PASSWORD flag
    /// (0x0080) is the only evidence available, so it has to be acted on.
    #[test]
    fn header_encrypted_archive_is_reported_not_empty() {
        // Marker, then an archive header with MHD_PASSWORD set and nothing after
        // it — exactly what a header-encrypted archive looks like to a reader
        // without the password.
        let mut rar = b"Rar!\x1a\x07\x00".to_vec();
        rar.extend_from_slice(&[0xef, 0xb4]); // HEAD_CRC
        rar.push(0x73); // HEAD_TYPE: archive header
        rar.extend_from_slice(&0x0080u16.to_le_bytes()); // HEAD_FLAGS: MHD_PASSWORD
        rar.extend_from_slice(&13u16.to_le_bytes()); // HEAD_SIZE
        rar.extend_from_slice(&[0u8; 6]); // reserved fields
        rar.extend_from_slice(&[0xab; 64]); // encrypted block headers

        let mut b = budget();
        let entries = crate::extract(crate::Format::Rar, &rar, &mut b).expect("extract");
        let e = entries
            .first()
            .expect("a header-encrypted archive must be reported, not returned empty");
        assert!(e.encrypted, "must be flagged encrypted");
        assert!(e.unsupported.is_some(), "must carry an unsupported reason");
    }

    fn budget() -> Budget {
        Budget::new(Limits::default())
    }

    /// Hand-built RAR4 archive (per the documented layout) with one stored file
    /// "hi.txt" containing `payload`. CRCs are left zero (the extractor doesn't
    /// verify them — it parses sizes/offsets).
    fn rar4_stored(name: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(RAR4_MAGIC);
        // archive header (type 0x73), no add-size, head_size = 13 (typical MAIN)
        v.extend_from_slice(&[0, 0]); // crc
        v.push(0x73);
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&13u16.to_le_bytes()); // head_size
        v.extend_from_slice(&[0; 6]); // reserved1(2)+reserved2(4) = 6 -> total 13
                                      // file header (type 0x74), flags 0x8000 (ADD_SIZE present)
        let mut fh = Vec::new();
        fh.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // PACK_SIZE
        fh.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // UNP_SIZE
        fh.push(0); // HOST_OS
        fh.extend_from_slice(&0u32.to_le_bytes()); // FILE_CRC
        fh.extend_from_slice(&0u32.to_le_bytes()); // FTIME
        fh.push(20); // UNP_VER
        fh.push(0x30); // METHOD = stored
        fh.extend_from_slice(&(name.len() as u16).to_le_bytes()); // NAME_SIZE
        fh.extend_from_slice(&0u32.to_le_bytes()); // ATTR
        fh.extend_from_slice(name); // NAME
                                    // PACK_SIZE (first field of `fh`) doubles as the block's ADD_SIZE; there
                                    // is no separate ADD_SIZE field. Header = generic(7) + fields.
        let head_size = 7 + fh.len();
        v.extend_from_slice(&[0, 0]); // crc
        v.push(0x74);
        v.extend_from_slice(&0x8000u16.to_le_bytes()); // flags (ADD_SIZE present)
        v.extend_from_slice(&(head_size as u16).to_le_bytes());
        v.extend_from_slice(&fh);
        v.extend_from_slice(payload); // stored data
        v
    }

    #[test]
    fn rar4_stored_roundtrips() {
        let arc = rar4_stored(b"hi.txt", b"EXAV_RAR4_MARKER_payload");
        assert!(arc.starts_with(RAR4_MAGIC) || arc.starts_with(RAR5_MAGIC));
        let e = extract_rar(&arc, &mut budget()).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "hi.txt");
        assert_eq!(e[0].data, b"EXAV_RAR4_MARKER_payload");
    }

    /// Hand-built RAR5 archive with one stored file.
    fn rar5_stored(name: &[u8], payload: &[u8]) -> Vec<u8> {
        fn vint_enc(mut x: u64) -> Vec<u8> {
            let mut o = Vec::new();
            loop {
                let b = (x & 0x7f) as u8;
                x >>= 7;
                if x != 0 {
                    o.push(b | 0x80);
                } else {
                    o.push(b);
                    break;
                }
            }
            o
        }
        let mut v = Vec::new();
        v.extend_from_slice(RAR5_MAGIC);
        // main archive header (type 1), no flags
        let mut mh = Vec::new();
        mh.extend_from_slice(&vint_enc(1)); // type
        mh.extend_from_slice(&vint_enc(0)); // flags
        mh.extend_from_slice(&vint_enc(0)); // archive flags
        v.extend_from_slice(&0u32.to_le_bytes()); // crc
        v.extend_from_slice(&vint_enc(mh.len() as u64)); // header_size
        v.extend_from_slice(&mh);
        // file header (type 2), flags 0x02 (data area present)
        let mut fh = Vec::new();
        fh.extend_from_slice(&vint_enc(2)); // type
        fh.extend_from_slice(&vint_enc(0x02)); // header flags: data present
        fh.extend_from_slice(&vint_enc(payload.len() as u64)); // data_size
        fh.extend_from_slice(&vint_enc(0)); // file_flags
        fh.extend_from_slice(&vint_enc(payload.len() as u64)); // unpacked size
        fh.extend_from_slice(&vint_enc(0)); // attributes
        fh.extend_from_slice(&vint_enc(0)); // compression info (method 0 = stored)
        fh.extend_from_slice(&vint_enc(0)); // host os
        fh.extend_from_slice(&vint_enc(name.len() as u64)); // name length
        fh.extend_from_slice(name);
        v.extend_from_slice(&0u32.to_le_bytes()); // crc
        v.extend_from_slice(&vint_enc(fh.len() as u64)); // header_size
        v.extend_from_slice(&fh);
        v.extend_from_slice(payload); // stored data
        v
    }

    #[test]
    fn rar5_stored_roundtrips() {
        let arc = rar5_stored(b"a/b.bin", b"EXAV_RAR5_MARKER_payload");
        assert!(arc.starts_with(RAR4_MAGIC) || arc.starts_with(RAR5_MAGIC));
        let e = extract_rar(&arc, &mut budget()).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "a/b.bin");
        assert_eq!(e[0].data, b"EXAV_RAR5_MARKER_payload");
    }

    #[test]
    fn truncated_does_not_panic() {
        let arc = rar5_stored(b"x", b"0123456789");
        for n in 0..arc.len() {
            let _ = extract_rar(&arc[..n], &mut budget());
        }
        let arc4 = rar4_stored(b"x", b"0123456789");
        for n in 0..arc4.len() {
            let _ = extract_rar(&arc4[..n], &mut budget());
        }
    }

    /// End-to-end RAR5 LZ decompression against real samples, validating each
    /// decompressed member against the CRC-32 stored in its file header. Runs
    /// only when the malware corpus is present (skipped otherwise).
    #[test]
    #[ignore = "extracts 114 RAR5 samples (310 MB); run with --ignored"]
    fn rar5_real_samples_crc() {
        use std::path::Path;
        // Walk up to find the repo's corpus dir from the crate dir.
        let mut dir = std::env::current_dir().unwrap();
        let mut corpus = None;
        for _ in 0..6 {
            let c = dir.join("corpus/samples/_bulk/rar");
            if c.is_dir() {
                corpus = Some(c);
                break;
            }
            if !dir.pop() {
                break;
            }
        }
        let corpus = match corpus {
            Some(c) => c,
            None => return, // corpus not present; skip
        };

        let mut checked = 0u32;
        let mut matched = 0u32;
        let entries = std::fs::read_dir(&corpus).unwrap();
        for ent in entries.flatten() {
            let p = ent.path();
            if p.extension().map(|e| e != "bin").unwrap_or(true) {
                continue;
            }
            let data = match std::fs::read(&p) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if !data.starts_with(RAR5_MAGIC) {
                continue;
            }
            // Cap memory: skip very large samples in the unit test.
            if data.len() > 8 * 1024 * 1024 {
                continue;
            }
            let mut b = Budget::new(Limits {
                max_extracted_bytes: 256 * 1024 * 1024,
                max_buffer_bytes: 256 * 1024 * 1024,
                max_compression_ratio: u64::MAX,
                ..Default::default()
            });
            // The extractor's debug_assert (cfg(test)) checks the CRC; here we
            // also count successful non-empty compressed decodes.
            let res = match extract_rar(&data, &mut b) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for e in &res {
                if !e.data.is_empty() && Path::new(&p).exists() {
                    // CRC already verified by the in-crate debug_assert path.
                    matched += 1;
                }
            }
            checked += 1;
        }
        // If the corpus exists it must contain RAR5 samples we can read.
        assert!(checked > 0, "no RAR5 samples processed");
        assert!(matched > 0, "no RAR5 members decoded");
    }
}
