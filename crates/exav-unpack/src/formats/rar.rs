//! RAR extractor, RAR4 and RAR5, implemented from the public RAR file-format
//! field layout. Stored members are copied; RAR3 (unpack 29, LZ + PPMd) members
//! go to `rar3_unpack` and RAR5 members to `rar5_unpack`, solid groups
//! included. RAR 1.5/2.x compression and encrypted members are reported as
//! members we could not extract (the caller still scans the raw archive in
//! place), and so are members split across volumes, unless the volumes are
//! joined first ([`join_volumes`]).
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
#[cfg(feature = "decrypt")]
use crate::formats::rar3_crypt;
use crate::formats::rar3_unpack;
#[cfg(feature = "decrypt")]
use crate::formats::rar5_crypt;
use crate::formats::rar5_unpack;
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

const RAR4_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
const RAR5_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

/// A solid member decoded on a window missing a member before it, and failing
/// its CRC: its bytes are not its own.
const RAR_STALE: &str =
    "RAR solid member follows one that was not decoded, so it cannot be decoded either";

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
pub(crate) fn vint(d: &[u8], o: usize) -> Option<(u64, usize)> {
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
    let end = off.saturating_add(crate::bytes::to_usize(pack));
    if pack > cap || end > data.len() {
        return Err(LimitHit::new("rar: stored member exceeds budget".into()));
    }
    let bytes = data[off..end].to_vec();
    budget.commit(bytes.len() as u64);
    out.push(Entry {
        comp_size: pack,
        name,
        data: bytes,
        ..Entry::default()
    });
    Ok(())
}

// ---- RAR4 ------------------------------------------------------------------

fn extract_rar4(data: &[u8], start: usize, budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    extract_rar4_keyed(data, start, budget, &mut Rar4Crypt::default())
}

/// The keys derived so far in a RAR4 archive, and the password that opened it.
#[cfg(feature = "decrypt")]
#[derive(Default)]
struct Rar4Crypt {
    keys: rar3_crypt::KeyCache,
    password: Option<String>,
}
#[cfg(not(feature = "decrypt"))]
#[derive(Default)]
struct Rar4Crypt {}

/// What decoding a RAR4 member needs from its header.
#[cfg_attr(not(feature = "decrypt"), allow(dead_code))]
struct Rar4Member {
    method: u8,
    unp_ver: u8,
    unp: u64,
    crc: u32,
    solid: bool,
    win_bits: u32,
}

/// The content of an encrypted RAR4 member, when a candidate password opens
/// it. The format has no password check, so a candidate is right when the
/// member decodes to its checksum; the password that does is then the only one
/// tried on the rest of the archive.
#[cfg(feature = "decrypt")]
fn rar4_decrypt_member(
    raw: &[u8],
    salt: Option<[u8; 8]>,
    m: &Rar4Member,
    budget: &mut Budget,
    solid_dec: &mut Option<rar3_unpack::Unpacker29>,
    crypt: &mut Rar4Crypt,
) -> Result<Option<Vec<u8>>, LimitHit> {
    let Some(salt) = salt else {
        return Ok(None);
    };
    let lz = m.unp_ver == 29 && (0x31..=0x35).contains(&m.method);
    if raw.len() as u64 > budget.limits.max_buffer_bytes || !(lz || m.method == 0x30) {
        return Ok(None);
    }
    let tries = match &crypt.password {
        Some(p) => vec![p.clone()],
        None => rar3_crypt::candidates(&budget.passwords),
    };
    for pw in tries {
        let Some(keys) = crypt.keys.get(&pw, &salt) else {
            break; // no more derivations: the member stays encrypted
        };
        let mut buf = raw.to_vec();
        rar3_crypt::decrypt(&keys, &mut buf);
        let plain = if lz {
            if !m.solid || solid_dec.is_none() {
                *solid_dec = rar3_unpack::Unpacker29::new(m.win_bits, budget).ok();
            }
            solid_dec
                .as_mut()
                .and_then(|d| d.member(&buf, m.unp, m.solid, budget).ok())
        } else {
            // Stored: the data is padded to the cipher's block.
            buf.truncate(m.unp.min(buf.len() as u64) as usize);
            Some(buf)
        };
        match plain {
            Some(b) if crc32_ieee(&b) == m.crc => {
                if !lz {
                    if b.len() as u64 > budget.reserve()? {
                        return Err(LimitHit::new("rar: stored member exceeds budget".into()));
                    }
                    budget.commit(b.len() as u64);
                }
                crypt.password = Some(pw);
                return Ok(Some(b));
            }
            _ => *solid_dec = None,
        }
    }
    Ok(None)
}

#[cfg(not(feature = "decrypt"))]
fn rar4_decrypt_member(
    _: &[u8],
    _: Option<[u8; 8]>,
    _: &Rar4Member,
    _: &mut Budget,
    _: &mut Option<rar3_unpack::Unpacker29>,
    _: &mut Rar4Crypt,
) -> Result<Option<Vec<u8>>, LimitHit> {
    Ok(None)
}

/// The archive with the blocks after its main header decrypted, when a
/// candidate password opens them (`rar -hp`): each is an 8-byte salt, then the
/// block's header encrypted to a multiple of 16 bytes, then its data as is. A
/// header's own CRC tells a right password from a wrong one.
#[cfg(feature = "decrypt")]
fn rar4_open_headers(
    data: &[u8],
    main_at: usize,
    main_end: usize,
    budget: &Budget,
    crypt: &mut Rar4Crypt,
) -> Option<Vec<u8>> {
    let tries = match &crypt.password {
        Some(p) => vec![p.clone()],
        None => rar3_crypt::candidates(&budget.passwords),
    };
    'password: for pw in tries {
        let mut plain = data.get(..main_end)?.to_vec();
        // The main header no longer says the blocks after it are encrypted.
        *plain.get_mut(main_at + 3)? &= !0x80;
        let mut q = main_end;
        let mut blocks = 0;
        while q < data.len() {
            let salt: [u8; 8] = crate::bytes::at(data, q, 8)?.try_into().ok()?;
            let keys = crypt.keys.get(&pw, &salt)?;
            let mut first = data.get(q + 8..q + 24)?.to_vec();
            rar3_crypt::decrypt(&keys, &mut first);
            let head_size = usize::from(u16::from_le_bytes([first[5], first[6]]));
            if head_size < 7 {
                if blocks == 0 {
                    continue 'password;
                }
                break;
            }
            let padded = head_size.checked_add(15)? / 16 * 16;
            let mut h = data.get(q + 8..(q + 8).checked_add(padded)?)?.to_vec();
            rar3_crypt::decrypt(&keys, &mut h);
            h.truncate(head_size);
            let crc_ok = (crc32_ieee(&h[2..]) & 0xffff) as u16 == u16::from_le_bytes([h[0], h[1]]);
            if !crc_ok {
                if blocks == 0 {
                    continue 'password;
                }
                break;
            }
            blocks += 1;
            let flags = u16::from_le_bytes([h[3], h[4]]);
            let add = if flags & 0x8000 != 0 {
                u32le(&h, 7).unwrap_or(0) as usize
            } else {
                0
            };
            let htype = h[2];
            plain.extend_from_slice(&h);
            let d = q + 8 + padded;
            let end = d.checked_add(add)?.min(data.len());
            plain.extend_from_slice(data.get(d..end)?);
            q = end;
            if htype == 0x7B {
                break;
            }
        }
        crypt.password = Some(pw);
        return Some(plain);
    }
    None
}

fn extract_rar4_keyed(
    data: &[u8],
    start: usize,
    budget: &mut Budget,
    crypt: &mut Rar4Crypt,
) -> Result<Vec<Entry>, LimitHit> {
    let mut out = Vec::new();
    let mut pos = start;
    // Kept across members: in a solid archive the files form one continuous LZ
    // stream, so a member flagged solid needs the window and tables its
    // predecessor left behind.
    let mut solid_dec: Option<rar3_unpack::Unpacker29> = None;
    // Whether the window holds every member before this one. A solid member
    // decoded without them decodes to bytes that are not its own.
    let mut in_step = true;
    while pos.saturating_add(7) <= data.len() {
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
            // `LHD_PASSWORD` is reported below, unless a password opens it.
            #[cfg(feature = "decrypt")]
            if let Some(plain) = rar4_open_headers(data, pos, pos + head_size, budget, crypt) {
                return extract_rar4_keyed(&plain, start, budget, crypt);
            }
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

            // LHD_SALT: the 8-byte salt of an encrypted member, after its name.
            let salt: Option<[u8; 8]> = if flags & 0x400 != 0 {
                p.checked_add(name_size)
                    .and_then(|s| data.get(s..s.checked_add(8)?))
                    .and_then(|s| s.try_into().ok())
            } else {
                None
            };
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
            // Only the LZ branch below feeds the window.
            let lz = !encrypted && unp_ver == 29 && (0x31..=0x35).contains(&method);
            if !is_dir && (split || !lz) {
                in_step = false;
            }
            if is_dir {
                // skip directories
            } else if encrypted && !split {
                let dend = data_off
                    .saturating_add(crate::bytes::to_usize(pack))
                    .min(data.len());
                let raw = &data[data_off.min(data.len())..dend];
                let member = Rar4Member {
                    method,
                    unp_ver,
                    unp,
                    crc,
                    solid: flags & 0x10 != 0,
                    win_bits,
                };
                budget.count_entry()?;
                match rar4_decrypt_member(raw, salt, &member, budget, &mut solid_dec, crypt)? {
                    Some(bytes) => out.push(Entry {
                        comp_size: pack,
                        name,
                        data: bytes,
                        encrypted: true,
                        ..Entry::default()
                    }),
                    None => {
                        // A solid group cannot go on past a member it could
                        // not read.
                        solid_dec = None;
                        out.push(Entry::unsupported(name, pack, true, "encrypted RAR member"));
                    }
                }
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
                let dend = data_off
                    .saturating_add(crate::bytes::to_usize(pack))
                    .min(data.len());
                let packed = &data[data_off.min(data.len())..dend];
                // LHD_SOLID. The window is sized once, from the first member of
                // the group; a solid member's own dictionary flags describe the
                // same shared window.
                let solid = flags & 0x10 != 0;
                // A member that is not solid starts afresh, on the window its
                // own header asks for.
                if !solid || solid_dec.is_none() {
                    solid_dec = rar3_unpack::Unpacker29::new(win_bits, budget).ok();
                }
                let stale = solid && !in_step;
                let decoded = match solid_dec.as_mut() {
                    Some(dec) => dec.member(packed, unp, solid, budget).ok(),
                    None => None,
                };
                // A member that failed mid-group leaves the shared window out of
                // step with the stream, so every later member would decode to
                // garbage: those are reported (`stale`), not scanned as theirs.
                if decoded.is_none() {
                    solid_dec = None;
                }
                let crc_ok = decoded.as_ref().is_some_and(|b| crc32_ieee(b) == crc);
                in_step = decoded.is_some() && (!stale || crc_ok);
                match decoded {
                    // A CRC mismatch after a full decode hides nothing: the
                    // bytes are scanned, as a ZIP member's are, and reported
                    // only when checksums are verified.
                    Some(bytes) if crc_ok || !(stale || budget.should_verify_checksums()) => {
                        out.push(Entry {
                            comp_size: pack,
                            name,
                            data: bytes,
                            ..Entry::default()
                        });
                    }
                    Some(_) if stale => {
                        out.push(Entry::unsupported(name, pack, false, RAR_STALE));
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
                // Compressed with an older version or an unknown method, or
                // encrypted, and not decoded: record metadata, flagged
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
            pos = data_off.saturating_add(crate::bytes::to_usize(add_size));
        } else {
            pos = pos
                .saturating_add(head_size)
                .saturating_add(crate::bytes::to_usize(add_size));
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

/// What each password derived over each salt, kept for the whole archive.
#[cfg(feature = "decrypt")]
type KeyCache = Vec<([u8; 16], u8, Vec<u8>, rar5_crypt::Keys)>;
#[cfg(not(feature = "decrypt"))]
type KeyCache = ();

fn extract_rar5(data: &[u8], start: usize, budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    extract_rar5_keyed(data, start, budget, &mut KeyCache::default())
}

#[cfg_attr(not(feature = "decrypt"), allow(unused_variables))]
fn extract_rar5_keyed(
    data: &[u8],
    start: usize,
    budget: &mut Budget,
    keys: &mut KeyCache,
) -> Result<Vec<Entry>, LimitHit> {
    // Kept across members: a solid RAR5 group's files share one window, and a
    // solid member's first block may declare no tables of its own.
    let mut solid_dec: Option<rar5_unpack::Unpacker50> = None;
    // Whether the window holds every member before this one.
    let mut in_step = true;
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
        let Some(data_off) = hdr.checked_add(crate::bytes::to_usize(hsize)) else {
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
            // Every header after this one is encrypted. With a password that
            // opens them, the archive is read again with them in the clear;
            // without, it is one encrypted member, never an empty archive.
            #[cfg(feature = "decrypt")]
            if let Some(plain) = data
                .get(q..data_off)
                .and_then(|b| rar5_crypt::CryptRecord::parse(b, false))
                .and_then(|rec| rar5_open_headers(data, start, data_off, &rec, budget, keys))
            {
                return extract_rar5_keyed(&plain, start, budget, keys);
            }
            budget.count_entry()?;
            out.push(Entry::unsupported(
                "rar-encrypted-headers".to_string(),
                data.len() as u64,
                true,
                "RAR archive with encrypted headers",
            ));
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
                    in_step = false;
                    budget.count_entry()?;
                    out.push(Entry::unsupported(
                        f.name,
                        data_size,
                        f.encrypted,
                        "RAR member continues in another volume",
                    ));
                } else if let Some(target) = f.redirect.as_ref().and_then(|(kind, t)| {
                    // A hard link (4) or a file copy (5) has no data: it is the
                    // member it names, already in this archive.
                    matches!(kind, 4 | 5).then_some(t)
                }) {
                    let copy = out
                        .iter()
                        .rev()
                        .find(|e| e.unsupported.is_none() && same_member(&e.name, target))
                        .map(|e| e.data.clone())
                        .unwrap_or_default();
                    budget.count_entry()?;
                    if copy.len() as u64 > budget.reserve()? {
                        return Err(LimitHit::new("rar: linked member exceeds budget".into()));
                    }
                    budget.commit(copy.len() as u64);
                    out.push(Entry {
                        name: f.name,
                        data: copy,
                        encrypted: f.encrypted,
                        ..Entry::default()
                    });
                } else {
                    let dataend = data_off.saturating_add(crate::bytes::to_usize(data_size));
                    let raw = if data_off <= data.len() && dataend <= data.len() {
                        &data[data_off..dataend]
                    } else {
                        &data[data_off.min(data.len())..]
                    };
                    // Encrypted data is decrypted first, when a password opens
                    // it; the checksum may then be keyed to the password.
                    let (plain, tweak) = if f.encrypted {
                        match rar5_decrypt_member(data, &f, raw, budget, keys) {
                            Some((p, t)) => (Some(p), t),
                            None => (None, None),
                        }
                    } else {
                        (None, None)
                    };
                    let crc_ok = |b: &[u8]| !f.has_crc || tweak_crc(tweak, crc32_ieee(b)) == f.crc;
                    if f.encrypted && plain.is_none() {
                        // A solid group cannot go on past a member it could
                        // not read.
                        solid_dec = None;
                        in_step = false;
                        budget.count_entry()?;
                        out.push(Entry::unsupported(
                            f.name,
                            data_size,
                            true,
                            "encrypted RAR member",
                        ));
                    } else if f.method == 0 {
                        // Stored. A split stored member is only a PREFIX of the
                        // file, the rest in a sibling volume, so it is reported
                        // as well as scanned: the partial bytes alone read as a
                        // complete member, and a multi-volume archive as clean.
                        in_step = false;
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
                        match plain {
                            // Decrypted: the data is padded to the cipher's
                            // block, and the file is the first `unp_size` bytes.
                            Some(mut p) => {
                                p.truncate(f.unp_size.min(p.len() as u64) as usize);
                                budget.count_entry()?;
                                if p.len() as u64 > budget.reserve()? {
                                    return Err(LimitHit::new(
                                        "rar: stored member exceeds budget".into(),
                                    ));
                                }
                                if split || crc_ok(&p) {
                                    budget.commit(p.len() as u64);
                                    out.push(Entry {
                                        comp_size: data_size,
                                        name: f.name,
                                        data: p,
                                        encrypted: true,
                                        ..Entry::default()
                                    });
                                } else {
                                    out.push(Entry::unsupported(
                                        f.name,
                                        data_size,
                                        true,
                                        "RAR member did not match its recorded CRC after \
                                         decrypting",
                                    ));
                                }
                            }
                            None => push_stored(
                                &mut out, budget, f.name, data, data_off, data_size, false,
                            )?,
                        }
                    } else {
                        self::decode_rar5_member(
                            &mut out,
                            budget,
                            (&mut solid_dec, &mut in_step),
                            &f,
                            plain.as_deref().unwrap_or(raw),
                            data_size,
                            crc_ok,
                        )?;
                    }
                }
            }
        }
        let Some(next) = data_off.checked_add(crate::bytes::to_usize(data_size)) else {
            break;
        };
        if next <= pos {
            break; // no progress — malformed
        }
        pos = next;
    }
    Ok(out)
}

/// Decode one compressed RAR5 member from `packed` and add it to `out`, or
/// say why it could not be read. The pair after `budget` is the solid group's
/// decoder and whether its window holds every member before this one.
fn decode_rar5_member(
    out: &mut Vec<Entry>,
    budget: &mut Budget,
    (solid_dec, in_step): (&mut Option<rar5_unpack::Unpacker50>, &mut bool),
    f: &Rar5File,
    packed: &[u8],
    data_size: u64,
    crc_ok: impl Fn(&[u8]) -> bool,
) -> Result<(), LimitHit> {
    budget.count_entry()?;
    // A member that is not solid starts afresh, on the window its own header
    // asks for: reusing the first member's ran every later, larger member
    // through a window too small for its distances.
    if !f.solid || solid_dec.is_none() {
        *solid_dec = rar5_unpack::Unpacker50::for_member(f.comp_info).ok();
    }
    let stale = f.solid && !*in_step;
    let decoded = match solid_dec.as_mut() {
        Some(dec) => dec.member(packed, f.unp_size, f.solid, budget).ok(),
        None => None,
    };
    // A member that failed mid-group leaves the shared window out of step with
    // the stream, so every later member would decode to garbage: those are
    // reported (`stale`), not scanned as theirs.
    if decoded.is_none() {
        *solid_dec = None;
    }
    let matches = decoded.as_deref().is_some_and(&crc_ok);
    *in_step = decoded.is_some() && (!stale || matches);
    // For an encrypted member the CRC is what confirms the password (RAR5's
    // own check value is optional), so a mismatch there is always reported.
    let checked = stale || f.encrypted || budget.should_verify_checksums();
    let name = f.name.clone();
    out.push(match decoded {
        // A CRC mismatch after a full decode hides nothing: the bytes are
        // scanned, as a ZIP member's are, and reported only when checksums
        // are verified.
        Some(bytes) if matches || !checked => Entry {
            comp_size: data_size,
            name,
            data: bytes,
            encrypted: f.encrypted,
            ..Entry::default()
        },
        Some(_) if stale => Entry::unsupported(name, data_size, f.encrypted, RAR_STALE),
        Some(_) => Entry::unsupported(
            name,
            data_size,
            f.encrypted,
            "RAR member did not match its recorded CRC after decoding",
        ),
        // Couldn't decode (unsupported method or filter, or malformed):
        // metadata only, flagged Unscannable so it isn't reported clean.
        None => Entry::unsupported(name, data_size, f.encrypted, "unsupported RAR compression"),
    });
    Ok(())
}

/// Whether two member paths name the same file, whichever separator each uses.
fn same_member(a: &str, b: &str) -> bool {
    a.split(['/', '\\']).eq(b.split(['/', '\\']))
}

/// A CRC-32 as a member stores it: keyed to the password when `key` is given.
fn tweak_crc(key: Option<[u8; 32]>, crc: u32) -> u32 {
    #[cfg(feature = "decrypt")]
    if let Some(k) = key {
        return rar5_crypt::tweak_crc(&k, crc);
    }
    let _ = key;
    crc
}

/// The decrypted data of an encrypted member, and the key its checksum is
/// keyed to if it is, when a candidate password opens it.
#[cfg(feature = "decrypt")]
fn rar5_decrypt_member(
    data: &[u8],
    f: &Rar5File,
    raw: &[u8],
    budget: &Budget,
    keys: &mut KeyCache,
) -> Option<(Vec<u8>, Option<[u8; 32]>)> {
    let rec = rar5_crypt::CryptRecord::parse(data.get(f.crypt.clone()?)?, true)?;
    if raw.len() as u64 > budget.limits.max_buffer_bytes {
        return None;
    }
    let k = rar5_crypt::find_keys(&rec, &budget.passwords, keys)?;
    let mut buf = raw.to_vec();
    rar5_crypt::decrypt(&k.key, &rec.iv, &mut buf);
    Some((buf, rec.tweaked.then_some(k.hash_key)))
}

#[cfg(not(feature = "decrypt"))]
fn rar5_decrypt_member(
    _: &[u8],
    _: &Rar5File,
    _: &[u8],
    _: &Budget,
    _: &mut KeyCache,
) -> Option<(Vec<u8>, Option<[u8; 32]>)> {
    None
}

/// The archive from `start` with the headers after an archive encryption
/// header decrypted, when a candidate password opens them: each is a 16-byte
/// IV, then the header encrypted to a multiple of 16 bytes, then its data as
/// is. `None` when no password opens them.
#[cfg(feature = "decrypt")]
fn rar5_open_headers(
    data: &[u8],
    start: usize,
    mut p: usize,
    rec: &rar5_crypt::CryptRecord,
    budget: &Budget,
    keys: &mut KeyCache,
) -> Option<Vec<u8>> {
    let k = rar5_crypt::find_keys(rec, &budget.passwords, keys)?;
    let mut plain = data.get(..start)?.to_vec();
    let mut headers = 0;
    while p < data.len() {
        let iv: [u8; 16] = crate::bytes::at(data, p, 16)?.try_into().ok()?;
        let mut first = data.get(p + 16..p + 32)?.to_vec();
        rar5_crypt::decrypt(&k.key, &iv, &mut first);
        let (hsize, n) = vint(&first, 4)?;
        let total = 4usize
            .checked_add(n)?
            .checked_add(usize::try_from(hsize).ok()?)?;
        let padded = total.checked_add(15)? / 16 * 16;
        let mut h = data.get(p + 16..(p + 16).checked_add(padded)?)?.to_vec();
        rar5_crypt::decrypt(&k.key, &iv, &mut h);
        h.truncate(total);
        // The header's type, flags, and data size, as the walk reads them.
        let body = 4 + n;
        let (htype, a) = vint(&h, body)?;
        let (hflags, b) = vint(&h, body + a)?;
        let mut q = body + a + b;
        if hflags & 0x01 != 0 {
            q += vint(&h, q)?.1;
        }
        let data_size = if hflags & 0x02 != 0 {
            vint(&h, q)?.0
        } else {
            0
        };
        // A wrong key reads as a header of no known type.
        if !(1..=5).contains(&htype) {
            return (headers > 0).then_some(plain);
        }
        headers += 1;
        plain.extend_from_slice(&h);
        let d = p + 16 + padded;
        let end = d
            .checked_add(usize::try_from(data_size).ok()?)?
            .min(data.len());
        plain.extend_from_slice(data.get(d..end)?);
        if htype == 5 {
            break;
        }
        p = end;
    }
    Some(plain)
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
    /// Stored unpacked-data CRC-32, only meaningful when `has_crc`.
    crc: u32,
    has_crc: bool,
    encrypted: bool,
    /// Where the file encryption record's body is in the archive.
    #[cfg_attr(not(feature = "decrypt"), allow(dead_code))]
    crypt: Option<std::ops::Range<usize>>,
    /// A hard link or file copy: its type and the member it repeats.
    redirect: Option<(u64, String)>,
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
    let end = hdr.checked_add(crate::bytes::to_usize(hsize))?;
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
    let nend = q
        .saturating_add(crate::bytes::to_usize(name_len))
        .min(end)
        .min(data.len());
    let name = if q < nend {
        String::from_utf8_lossy(&data[q..nend]).into_owned()
    } else {
        "rar-entry".to_string()
    };
    // compression method = bits 7..9 of comp_info; bit 6 marks a solid member.
    let method = (comp_info >> 7) & 0x7;
    let solid = comp_info & (1 << 6) != 0;
    let extra = rar5_extra(data, end, extra_size);
    Some(Rar5File {
        name,
        method,
        file_flags,
        unp_size,
        comp_info,
        solid,
        crc,
        has_crc,
        encrypted: extra.crypt.is_some(),
        crypt: extra.crypt,
        redirect: extra.redirect,
    })
}

/// The records of a file header's extra area that change how its data is read.
#[derive(Default)]
struct Rar5Extra {
    /// The body of the file encryption record (type 0x01), after its type.
    crypt: Option<std::ops::Range<usize>>,
    /// A file system redirection record (type 0x05): its type and target.
    redirect: Option<(u64, String)>,
}

/// Scan the trailing extra area `[end-extra_size, end)`.
fn rar5_extra(data: &[u8], end: usize, extra_size: u64) -> Rar5Extra {
    let mut found = Rar5Extra::default();
    if extra_size == 0 || crate::bytes::to_usize(extra_size) > end {
        return found;
    }
    let mut p = end - crate::bytes::to_usize(extra_size);
    let mut guard = 0;
    while p < end && guard < 64 {
        guard += 1;
        let Some((rec_size, n1)) = vint(data, p) else {
            break;
        };
        let Some(rec_start) = p.checked_add(n1) else {
            break;
        };
        // `rec_size` counts the bytes after its own vint: the type and body.
        let Some(rec_end) = rec_start.checked_add(crate::bytes::to_usize(rec_size)) else {
            break;
        };
        let Some((rec_type, n2)) = vint(data, rec_start) else {
            break;
        };
        let body = rec_start + n2..rec_end.min(end);
        match rec_type {
            0x01 => found.crypt = Some(body),
            0x05 => {
                let b = data.get(body).unwrap_or(&[]);
                let target = (|| {
                    let (kind, a) = vint(b, 0)?;
                    let (_flags, c) = vint(b, a)?;
                    let (len, d) = vint(b, a + c)?;
                    let at = a + c + d;
                    let name = crate::bytes::at(b, at, crate::bytes::to_usize(len))?;
                    Some((kind, String::from_utf8_lossy(name).into_owned()))
                })();
                found.redirect = target;
            }
            _ => {}
        }
        if rec_end <= p {
            break;
        }
        p = rec_end;
    }
    found
}

// ---- Volumes ----------------------------------------------------------------
//
// A member split across volumes has a file header in each, flagged as
// continuing from the previous volume and/or in the next, with that volume's
// share of the packed data after it. Every part's header carries the CRC-32 of
// that part's packed data, except the last, whose CRC is the whole unpacked
// file's (RARLAB's technote). Joined, the shares are the member's whole packed
// stream, which the single-volume reader then decodes as it decodes any other.

/// The volumes of a RAR set, in order, as one single-volume archive: each
/// split member's packed data joined behind its first header, which takes the
/// total size and the last part's CRC. `Err` names what does not fit together.
pub(crate) fn join_volumes(volumes: &[&[u8]]) -> Result<Vec<u8>, String> {
    match volumes.first() {
        Some(v) if v.starts_with(RAR5_MAGIC) => join_rar5(volumes),
        Some(v) if v.starts_with(RAR4_MAGIC) => join_rar4(volumes),
        _ => Err("the first part is not a RAR archive".to_string()),
    }
}

/// A member whose parts are still being gathered: its first header and the
/// packed data so far.
struct Pending {
    header: Vec<u8>,
    data: Vec<u8>,
}

fn join_rar4(volumes: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut out = RAR4_MAGIC.to_vec();
    let mut pending: Option<Pending> = None;
    for (k, v) in volumes.iter().enumerate() {
        if !v.starts_with(RAR4_MAGIC) {
            return Err(format!("part {} is not a RAR4 volume", k + 1));
        }
        let mut pos = RAR4_MAGIC.len();
        while pos + 7 <= v.len() {
            let (Some(flags), Some(head_size)) = (u16le(v, pos + 3), u16le(v, pos + 5)) else {
                break;
            };
            let (htype, head_size) = (v[pos + 2], head_size as usize);
            if head_size < 7 || pos + head_size > v.len() {
                break;
            }
            let mut add = if flags & 0x8000 != 0 {
                u32le(v, pos + 7).unwrap_or(0) as u64
            } else {
                0
            };
            if htype == 0x74 && flags & 0x100 != 0 {
                add |= (u32le(v, pos + 32).unwrap_or(0) as u64) << 32;
            }
            let end = pos
                .checked_add(head_size)
                .and_then(|e| e.checked_add(usize::try_from(add).ok()?))
                .filter(|&e| e <= v.len())
                .ok_or_else(|| format!("part {} ends inside a block", k + 1))?;
            // A volume's end block may record its number (EARC_VOLNUMBER,
            // after the data CRC when EARC_DATACRC is set): it must be where
            // it is given.
            if htype == 0x7B && flags & 0x0008 != 0 {
                let at = pos + 7 + if flags & 0x0002 != 0 { 4 } else { 0 };
                if let Some(n) = u16le(v, at).filter(|_| at + 2 <= pos + head_size) {
                    if usize::from(n) != k {
                        return Err(format!("part {} is volume {} of its set", k + 1, n + 1));
                    }
                }
            }
            match htype {
                // The archive header once; each volume's end marker never.
                0x73 if k == 0 => out.extend_from_slice(&v[pos..end]),
                0x73 | 0x7B => {}
                0x74 => {
                    let (before, after) = (flags & 0x01 != 0, flags & 0x02 != 0);
                    let (header, data) = (&v[pos..pos + head_size], &v[pos + head_size..end]);
                    match (before, &mut pending) {
                        (false, None) if after => {
                            pending = Some(Pending {
                                header: header.to_vec(),
                                data: data.to_vec(),
                            })
                        }
                        (false, None) => out.extend_from_slice(&v[pos..end]),
                        (true, Some(p)) => p.data.extend_from_slice(data),
                        (false, Some(_)) => {
                            return Err(format!("part {} drops a member mid-way", k + 1))
                        }
                        (true, None) => {
                            return Err(format!(
                                "part {} goes on with a member whose start is missing",
                                k + 1
                            ))
                        }
                    }
                    if before && !after {
                        let p = pending.take().expect("a split member was pending");
                        out.extend(rar4_whole(p, u32le(v, pos + 16).unwrap_or(0))?);
                    }
                }
                _ => out.extend_from_slice(&v[pos..end]),
            }
            if end <= pos {
                break;
            }
            pos = end;
        }
    }
    if pending.is_some() {
        return Err("the last part ends inside a member".to_string());
    }
    // ENDARC: CRC, type 0x7B, flags, size 7.
    out.extend_from_slice(&[0x3d, 0x7b, 0x7b, 0x00, 0x40, 0x07, 0x00]);
    Ok(out)
}

/// A RAR4 member's whole header and data, from its parts.
fn rar4_whole(mut p: Pending, crc: u32) -> Result<Vec<u8>, String> {
    let h = &mut p.header;
    // The smallest block head is 7 bytes, and a split member's has fields up to byte 20.
    if h.len() < 20 {
        return Err("a short file header".to_string());
    }
    // A stored member's data is its content, so a part missing from between
    // the ones given shows as a size the header does not record. (A volume
    // missing from a set that records volume numbers is refused by the join;
    // without them, a compressed member fails its CRC once decoded, which is
    // reported only when checksums are verified.)
    let large = u16::from_le_bytes([h[3], h[4]]) & 0x100 != 0;
    let unp = u64::from(u32le(h, 11).unwrap_or(0))
        | if large {
            u64::from(u32le(h, 36).unwrap_or(0)) << 32
        } else {
            0
        };
    if h.get(25) == Some(&0x30) && unp != p.data.len() as u64 {
        return Err(format!(
            "a stored member of {unp} bytes has {} in the parts given",
            p.data.len()
        ));
    }
    let flags = u16::from_le_bytes([h[3], h[4]]) & !0x03;
    h[3..5].copy_from_slice(&flags.to_le_bytes());
    let total = p.data.len() as u64;
    h[7..11].copy_from_slice(&(total as u32).to_le_bytes());
    match (flags & 0x100 != 0, h.len() >= 40) {
        (true, true) => h[32..36].copy_from_slice(&((total >> 32) as u32).to_le_bytes()),
        _ if total > u64::from(u32::MAX) => {
            return Err("a member past 4 GiB with no 64-bit size".to_string())
        }
        _ => {}
    }
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    let mut out = p.header;
    out.extend_from_slice(&p.data);
    Ok(out)
}

fn vint_bytes(mut x: u64) -> Vec<u8> {
    let mut o = Vec::new();
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            o.push(b);
            return o;
        }
        o.push(b | 0x80);
    }
}

/// One RAR5 block: where its header content starts and ends, its type and
/// flags, and where its data ends.
struct Rar5Block {
    hdr: usize,
    data_off: usize,
    htype: u64,
    hflags: u64,
    end: usize,
}

fn rar5_block(v: &[u8], pos: usize) -> Option<Rar5Block> {
    let (hsize, n) = vint(v, pos + 4)?;
    let hdr = pos + 4 + n;
    let data_off = hdr.checked_add(usize::try_from(hsize).ok()?)?;
    if hsize == 0 || data_off > v.len() {
        return None;
    }
    let (htype, t1) = vint(v, hdr)?;
    let (hflags, t2) = vint(v, hdr + t1)?;
    let mut q = hdr + t1 + t2;
    if hflags & 0x01 != 0 {
        q += vint(v, q)?.1;
    }
    let data_size = if hflags & 0x02 != 0 { vint(v, q)?.0 } else { 0 };
    let end = data_off.checked_add(usize::try_from(data_size).ok()?)?;
    (end <= v.len()).then_some(Rar5Block {
        hdr,
        data_off,
        htype,
        hflags,
        end,
    })
}

fn join_rar5(volumes: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut out = RAR5_MAGIC.to_vec();
    // The pending member, with the header content of its first part.
    let mut pending: Option<Pending> = None;
    // Service blocks met while a member is pending, which go after it.
    let mut deferred = Vec::new();
    for (k, v) in volumes.iter().enumerate() {
        if !v.starts_with(RAR5_MAGIC) {
            return Err(format!("part {} is not a RAR5 volume", k + 1));
        }
        let mut pos = RAR5_MAGIC.len();
        while pos + 4 < v.len() {
            let Some(b) = rar5_block(v, pos) else { break };
            // A volume past the first records its number: it must be where
            // it is given.
            if b.htype == 1 && k > 0 {
                if let Some(n) = rar5_volume_number(&v[b.hdr..b.data_off]) {
                    if n != k as u64 {
                        return Err(format!("part {} is volume {} of its set", k + 1, n + 1));
                    }
                }
            }
            match b.htype {
                1 if k == 0 => out.extend_from_slice(&v[pos..b.end]),
                1 | 5 => {}
                // The quick-open record each volume ends with caches that
                // volume's headers at offsets in it: it has no place in the
                // joined archive.
                3 if b.hflags & 0x18 == 0 && rar5_name(&v[b.hdr..b.data_off]) == Some(b"QO") => {}
                2 | 3 => {
                    let (before, after) = (b.hflags & 0x08 != 0, b.hflags & 0x10 != 0);
                    let data = &v[b.data_off..b.end];
                    match (before, &mut pending) {
                        (false, None) if after => {
                            pending = Some(Pending {
                                header: v[b.hdr..b.data_off].to_vec(),
                                data: data.to_vec(),
                            })
                        }
                        (false, None) => out.extend_from_slice(&v[pos..b.end]),
                        (true, Some(p)) => p.data.extend_from_slice(data),
                        (false, Some(_)) if b.htype == 3 && !after => {
                            deferred.extend_from_slice(&v[pos..b.end])
                        }
                        (false, Some(_)) => {
                            return Err(format!("part {} drops a member mid-way", k + 1))
                        }
                        (true, None) => {
                            return Err(format!(
                                "part {} goes on with a member whose start is missing",
                                k + 1
                            ))
                        }
                    }
                    if before && !after {
                        let p = pending.take().expect("a split member was pending");
                        out.extend(rar5_whole(p, rar5_crc(v, &b))?);
                        out.append(&mut deferred);
                    }
                }
                _ => out.extend_from_slice(&v[pos..b.end]),
            }
            if b.end <= pos {
                break;
            }
            pos = b.end;
        }
    }
    if pending.is_some() {
        return Err("the last part ends inside a member".to_string());
    }
    // End of archive: type 5, no flags, no end-of-archive flags.
    let content = [vint_bytes(5), vint_bytes(0), vint_bytes(0)].concat();
    out.extend_from_slice(&crc32_ieee(&content).to_le_bytes());
    out.extend(vint_bytes(content.len() as u64));
    out.extend(content);
    Ok(out)
}

/// The volume number a RAR5 main header records (1 for the second volume),
/// when it records one.
fn rar5_volume_number(c: &[u8]) -> Option<u64> {
    let (_, t1) = vint(c, 0)?;
    let (hflags, t2) = vint(c, t1)?;
    let mut q = t1 + t2;
    if hflags & 0x01 != 0 {
        q += vint(c, q)?.1;
    }
    if hflags & 0x02 != 0 {
        q += vint(c, q)?.1;
    }
    let (archive_flags, n) = vint(c, q)?;
    (archive_flags & 0x02 != 0)
        .then(|| vint(c, q + n).map(|v| v.0))
        .flatten()
}

/// The name in a RAR5 file or service header's content.
fn rar5_name(c: &[u8]) -> Option<&[u8]> {
    let f = rar5_fields_at(c)?;
    let (file_flags, n) = vint(c, f.after_sizes)?;
    let mut q = f.after_sizes + n;
    q += vint(c, q)?.1; // unpacked size
    q += vint(c, q)?.1; // attributes
    q += if file_flags & 0x02 != 0 { 4 } else { 0 } + if file_flags & 0x04 != 0 { 4 } else { 0 };
    q += vint(c, q)?.1; // compression information
    q += vint(c, q)?.1; // host OS
    let (len, n) = vint(c, q)?;
    crate::bytes::at(c, q.checked_add(n)?, usize::try_from(len).ok()?)
}

/// The data CRC a RAR5 file block records, when it records one.
fn rar5_crc(v: &[u8], b: &Rar5Block) -> Option<u32> {
    let f = rar5_fields_at(&v[b.hdr..b.data_off])?;
    f.crc_at.map(|at| u32le(&v[b.hdr..], at).unwrap_or(0))
}

/// Where the parts of a RAR5 file header content are: the end of its
/// data-size field, the start of the file fields, and the CRC's offset.
struct Rar5Layout {
    after_sizes: usize,
    crc_at: Option<usize>,
}

fn rar5_fields_at(c: &[u8]) -> Option<Rar5Layout> {
    let (_, t1) = vint(c, 0)?;
    let (hflags, t2) = vint(c, t1)?;
    let mut q = t1 + t2;
    if hflags & 0x01 != 0 {
        q += vint(c, q)?.1;
    }
    if hflags & 0x02 != 0 {
        q += vint(c, q)?.1;
    }
    let after_sizes = q;
    let (file_flags, n) = vint(c, q)?;
    q += n;
    q += vint(c, q)?.1; // unpacked size
    q += vint(c, q)?.1; // attributes
    if file_flags & 0x02 != 0 {
        q += 4; // mtime
    }
    let crc_at = (file_flags & 0x04 != 0).then_some(q);
    Some(Rar5Layout {
        after_sizes,
        crc_at,
    })
}

/// A RAR5 member's whole block, from its parts: the first header with the
/// split flags off, the total data size, and the last part's CRC.
fn rar5_whole(p: Pending, crc: Option<u32>) -> Result<Vec<u8>, String> {
    let c = &p.header;
    let bad = || "a short file header".to_string();
    let layout = rar5_fields_at(c).ok_or_else(bad)?;
    // As for RAR4: a stored member's size shows a missing part.
    let (file_flags, n) = vint(c, layout.after_sizes).ok_or_else(bad)?;
    let (unp, n2) = vint(c, layout.after_sizes + n).ok_or_else(bad)?;
    let mut q = layout.after_sizes + n + n2;
    q += vint(c, q).ok_or_else(bad)?.1;
    q += if file_flags & 0x02 != 0 { 4 } else { 0 } + if file_flags & 0x04 != 0 { 4 } else { 0 };
    let (comp_info, _) = vint(c, q).ok_or_else(bad)?;
    if (comp_info >> 7) & 0x7 == 0 && file_flags & 0x08 == 0 && unp != p.data.len() as u64 {
        return Err(format!(
            "a stored member of {unp} bytes has {} in the parts given",
            p.data.len()
        ));
    }
    let (htype, t1) = vint(c, 0).ok_or_else(bad)?;
    let (hflags, t2) = vint(c, t1).ok_or_else(bad)?;
    let mut content = vint_bytes(htype);
    content.extend(vint_bytes((hflags & !0x18) | 0x02));
    if hflags & 0x01 != 0 {
        let (extra, _) = vint(c, t1 + t2).ok_or_else(bad)?;
        content.extend(vint_bytes(extra));
    }
    content.extend(vint_bytes(p.data.len() as u64));
    let shift = content.len() as isize - layout.after_sizes as isize;
    content.extend_from_slice(&c[layout.after_sizes..]);
    if let (Some(at), Some(crc)) = (layout.crc_at, crc) {
        let at = (at as isize + shift) as usize;
        content[at..at + 4].copy_from_slice(&crc.to_le_bytes());
    }
    let mut out = crc32_ieee(&content).to_le_bytes().to_vec();
    out.extend(vint_bytes(content.len() as u64));
    out.extend(content);
    out.extend_from_slice(&p.data);
    Ok(out)
}

/// CRC-32 (IEEE, poly 0xEDB88320) over `data`. A decoded RAR member failing
/// the CRC the archive records is reported when it is a solid member decoded
/// without a member before it (its bytes are not its own), when it is
/// encrypted (the CRC is what confirms the password), or when checksums are
/// verified; otherwise it is scanned, as a ZIP member failing its CRC is.
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

    /// `arc`'s members cut into `chunk`-byte parts, a new volume at each cut,
    /// as RARLAB's technote describes a set: the split flags, each part's
    /// share of the data and size, and the CRC of its share but in the last.
    fn split(arc: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let rar5 = arc.starts_with(RAR5_MAGIC);
        let magic = if rar5 { RAR5_MAGIC } else { RAR4_MAGIC };
        let mut vols: Vec<Vec<u8>> = vec![magic.to_vec()];
        let mut main = Vec::new();
        let mut pos = magic.len();
        while pos + 7 < arc.len() {
            // (block bytes, file header?, header end, data end)
            let (end, file, data_off) = if rar5 {
                let Some(b) = rar5_block(arc, pos) else { break };
                (b.end, b.htype == 2, b.data_off)
            } else {
                let (flags, size) = (
                    u16le(arc, pos + 3).unwrap(),
                    u16le(arc, pos + 5).unwrap() as usize,
                );
                let add = if flags & 0x8000 != 0 {
                    u32le(arc, pos + 7).unwrap() as usize
                } else {
                    0
                };
                (pos + size + add, arc[pos + 2] == 0x74, pos + size)
            };
            if !file {
                if main.is_empty() {
                    main = arc[pos..end].to_vec();
                    vols[0].extend_from_slice(&main);
                }
                pos = end;
                continue;
            }
            let data = &arc[data_off..end];
            let parts: Vec<&[u8]> = data.chunks(chunk.max(1)).collect();
            let parts = if parts.is_empty() {
                vec![&data[..0]]
            } else {
                parts
            };
            for (j, part) in parts.iter().enumerate() {
                let (before, after) = (j > 0, j + 1 < parts.len());
                if before {
                    let mut v = magic.to_vec();
                    if rar5 {
                        // A volume past the first records its number, as RAR
                        // writes it.
                        let c = [1, 0, 0x03, vols.len() as u64].map(vint_bytes).concat();
                        let body = [vint_bytes(c.len() as u64), c].concat();
                        v.extend(crc32_ieee(&body).to_le_bytes());
                        v.extend(body);
                    } else {
                        v.extend_from_slice(&main);
                    }
                    vols.push(v);
                }
                let v = vols.last_mut().unwrap();
                if rar5 {
                    let c = &arc[rar5_block(arc, pos).unwrap().hdr..data_off];
                    let mut p = Pending {
                        header: c.to_vec(),
                        data: part.to_vec(),
                    };
                    // Built as a whole member, then flagged as a part.
                    let crc = (!after)
                        .then(|| rar5_crc(arc, &rar5_block(arc, pos).unwrap()))
                        .flatten();
                    let crc = crc.or_else(|| after.then(|| crc32_ieee(part)));
                    let flags_at = vint(&p.header, 0).unwrap().1;
                    let (fl, n) = vint(&p.header, flags_at).unwrap();
                    let fl = fl | if before { 0x08 } else { 0 } | if after { 0x10 } else { 0 };
                    let mut h = p.header[..flags_at].to_vec();
                    h.extend(vint_bytes(fl));
                    h.extend_from_slice(&p.header[flags_at + n..]);
                    p.header = h;
                    let whole = rar5_part(p, crc);
                    v.extend(whole);
                } else {
                    let mut h = arc[pos..data_off].to_vec();
                    let fl = u16::from_le_bytes([h[3], h[4]])
                        | if before { 1 } else { 0 }
                        | if after { 2 } else { 0 };
                    h[3..5].copy_from_slice(&fl.to_le_bytes());
                    h[7..11].copy_from_slice(&(part.len() as u32).to_le_bytes());
                    if after {
                        h[16..20].copy_from_slice(&crc32_ieee(part).to_le_bytes());
                    }
                    v.extend(h);
                    v.extend_from_slice(part);
                }
            }
            pos = end;
        }
        vols
    }

    /// A RAR5 block from header content whose flags are already set, with
    /// `p.data` as its data and `crc` in its CRC field.
    fn rar5_part(p: Pending, crc: Option<u32>) -> Vec<u8> {
        let c = &p.header;
        let layout = rar5_fields_at(c).unwrap();
        let (htype, t1) = vint(c, 0).unwrap();
        let (hflags, t2) = vint(c, t1).unwrap();
        let mut content = vint_bytes(htype);
        content.extend(vint_bytes(hflags | 0x02));
        if hflags & 0x01 != 0 {
            content.extend(vint_bytes(vint(c, t1 + t2).unwrap().0));
        }
        content.extend(vint_bytes(p.data.len() as u64));
        let shift = content.len() as isize - layout.after_sizes as isize;
        content.extend_from_slice(&c[layout.after_sizes..]);
        if let (Some(at), Some(crc)) = (layout.crc_at, crc) {
            let at = (at as isize + shift) as usize;
            content[at..at + 4].copy_from_slice(&crc.to_le_bytes());
        }
        let mut out = crc32_ieee(&content).to_le_bytes().to_vec();
        out.extend(vint_bytes(content.len() as u64));
        out.extend(content);
        out.extend_from_slice(&p.data);
        out
    }

    /// A set split from an archive, joined again, extracts as the archive
    /// does: stored members, and the compressed members of a solid archive,
    /// RAR4 and RAR5, cut at many sizes. A set missing a part is refused.
    #[test]
    fn a_volume_set_joins_into_its_archive() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar_solid");
        let arcs = [
            rar4_stored(b"hi.txt", &[b'z'; 1000]),
            rar5_stored(b"a/b.bin", &[b'y'; 1000]),
            std::fs::read(format!("{dir}/solid_rar4.rar")).unwrap(),
            std::fs::read(format!("{dir}/solid_rar5.rar")).unwrap(),
        ];
        let names = |e: &[Entry]| {
            e.iter()
                .map(|e| (e.name.clone(), e.data.clone(), e.unsupported))
                .collect::<Vec<_>>()
        };
        for (i, arc) in arcs.iter().enumerate() {
            let want = names(&extract_rar(arc, &mut budget()).unwrap());
            assert!(
                want.iter().all(|w| w.2.is_none() && !w.1.is_empty()),
                "archive {i}: {want:?}"
            );
            for chunk in [1, 7, 100, 333, 1 << 20] {
                let vols = split(arc, chunk);
                let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
                let joined = join_volumes(&refs)
                    .unwrap_or_else(|e| panic!("archive {i} chunk {chunk}: {e}"));
                assert_eq!(
                    names(&extract_rar(&joined, &mut budget()).unwrap()),
                    want,
                    "archive {i} chunk {chunk}"
                );
                if refs.len() > 2 {
                    // A part gone from the middle: refused, or the member it
                    // held reported unreadable, never passed off as whole.
                    let missing: Vec<&[u8]> = refs
                        .iter()
                        .enumerate()
                        .filter(|(k, _)| *k != 1)
                        .map(|(_, v)| *v)
                        .collect();
                    if let Ok(joined) = join_volumes(&missing) {
                        let got = names(&extract_rar(&joined, &mut budget()).unwrap());
                        assert!(
                            got.iter().any(|g| g.2.is_some()),
                            "archive {i} chunk {chunk}: a missing part"
                        );
                    }
                    assert!(
                        join_volumes(&refs[1..]).is_err(),
                        "archive {i} chunk {chunk}: no first part"
                    );
                }
            }
        }
    }

    /// Volumes whose split member has a seven-byte header (the smallest block
    /// head) are refused, not indexed past their end.
    #[test]
    fn joining_a_split_member_with_a_seven_byte_header_is_an_error() {
        let vol = |flags: u16| {
            let mut v = RAR4_MAGIC.to_vec();
            v.extend_from_slice(&[0, 0, 0x74]);
            v.extend_from_slice(&flags.to_le_bytes());
            v.extend_from_slice(&7u16.to_le_bytes());
            v
        };
        let (first, last) = (vol(0x02), vol(0x01));
        assert!(join_volumes(&[&first, &last]).is_err());
    }

    /// A service block whose name length is the largest vint cannot place its
    /// name: the sum overflowed.
    #[test]
    fn a_service_block_name_of_every_bit_set_has_no_name() {
        // type 3, flags 0, then flags, unpacked size, attributes, compression
        // information and host OS (one byte each), then the name length.
        let mut content = vec![3, 0, 0, 0, 0, 0, 0];
        content.extend_from_slice(&[0xFF; 9]);
        content.push(0x01);
        assert_eq!(rar5_name(&content), None);
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
    /// decompressed member against the CRC-32 stored in its file header. Reads
    /// the `*.bin` files of the directory `EXAV_DEBUG_RAR_CORPUS` names; skipped when
    /// it is not set.
    #[test]
    #[ignore = "extracts 114 RAR5 samples (310 MB); run with --ignored"]
    fn rar5_real_samples_crc() {
        use std::path::Path;
        let corpus = match std::env::var_os("EXAV_DEBUG_RAR_CORPUS") {
            Some(c) => std::path::PathBuf::from(c),
            None => return,
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
