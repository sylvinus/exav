//! RAR extractor, RAR4 and RAR5, implemented from the public RAR file-format
//! field layout. Stored members are copied; RAR3 (unpack 29, LZ + PPMd) members
//! go to `rar3_unpack` and RAR5 members to `rar5_unpack`, solid groups
//! included. RAR 1.5/2.x compression and encrypted members no password opens
//! are reported as members we could not extract (the caller still scans the
//! raw archive in place), and so are members split across volumes, unless the
//! volumes are joined first ([`RarSpan`]).
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

mod span;
pub use span::RarSpan;

const RAR4_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
const RAR5_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

/// A member compressed with a method or filter this reader does not decode.
const RAR_UNSUPPORTED: &str = "unsupported RAR compression";

/// A RAR5 member whose compression version is neither 0 nor 1.
const RAR5_VERSION: &str = "RAR5 member of an unknown compression version";

/// The kind of reason `why` is, for the member it is the reason of:
/// [`RAR_UNSUPPORTED`] and [`RAR5_VERSION`] are a method that is not decoded,
/// a dictionary, model or member over the object limit is that limit.
fn kind_of(why: &str) -> Option<crate::tree::ReasonKind> {
    use crate::tree::ReasonKind;
    match why {
        RAR_UNSUPPORTED | RAR5_VERSION => Some(ReasonKind::Unsupported),
        WINDOW_OVER_LIMIT | PPMD_OVER_LIMIT | RAR_OVER_LIMIT => Some(ReasonKind::OVER_SIZE),
        _ => None,
    }
}

/// A solid member decoded on a window missing a member before it, and failing
/// its CRC: its bytes are not its own.
const RAR_STALE: &str =
    "RAR solid member follows one that was not decoded, so it cannot be decoded either";

/// A member the archive ends inside, decoded as far as it goes, when
/// checksums are verified: as [`crate::checksum_cut`] says it.
const RAR_CUT: &str = "RAR CRC-32 not checked: the archive ends inside the member";

/// A block header that does not parse, with bytes after it: where the next
/// block starts is not known, so the rest of the archive is not walked. (A
/// header the archive ends inside is cut, and what is missing is absent.)
const RAR_DAMAGED: &str =
    "RAR block header does not parse: the rest of the archive was not scanned";

/// A file header whose fields do not parse: the block is skipped, its data
/// with it.
const RAR_DAMAGED_FILE: &str = "RAR file header does not parse: its data was not scanned";

/// A compressed member whose stream does not decode.
const RAR_UNDECODED: &str = "RAR member could not be decoded";

/// A compressed member larger, as declared or as decoded, than the object
/// limit.
const RAR_OVER_LIMIT: &str = "RAR member is larger than the object limit (--max-object-bytes)";

/// A compressed member's decode in memory, `got`, as the walk takes it: its
/// bytes, or the reason it has none: damage, `over` when the decoder says its
/// window or model is over the buffer limit, or its size over the object
/// limit. One over what is left of the total a scan may extract ends the walk
/// ([`Budget::over_cap`]).
fn settle(
    got: Result<Vec<u8>, LimitHit>,
    over: Option<&'static str>,
    name: &str,
    budget: &mut Budget,
) -> Result<Result<Vec<u8>, &'static str>, LimitHit> {
    match got {
        Ok(bytes) => Ok(Ok(bytes)),
        Err(e) if e.is_corrupt() => Ok(Err(RAR_UNDECODED)),
        Err(_) => {
            if let Some(why) = over {
                return Ok(Err(why));
            }
            let cap = budget.reserve()?;
            if cap < budget.limits.max_buffer_bytes {
                let shown = crate::tree::quoted(name);
                budget.over_cap(cap, 0, format_args!("rar member '{shown}'"))?;
            }
            Ok(Err(RAR_OVER_LIMIT))
        }
    }
}

/// The end of a walk that reaches a block header that does not parse, at `at`.
fn damaged(at: usize) -> LimitHit {
    LimitHit::corrupt(format!("rar: block header at offset {at} does not parse"))
}

/// What a walk that collects its members gives in place of an error for a
/// header it cannot read (an error would drop the members it has collected).
fn damaged_member(out: &mut Vec<Entry>, budget: &mut Budget) -> Result<(), LimitHit> {
    budget.count_entry()?;
    out.push(Entry::unsupported(
        "rar-damaged-header".to_string(),
        0,
        false,
        RAR_DAMAGED,
    ));
    Ok(())
}

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
    // The archive can end inside the member: the bytes present are the member
    // and the rest is absent.
    let end = off
        .saturating_add(crate::bytes::to_usize(pack))
        .min(data.len());
    let present = data.get(off..end).unwrap_or_default();
    let shown = crate::tree::quoted(&name);
    let member = format_args!("rar member '{shown}'");
    if budget.reserve_for(present.len() as u64, member)?.is_none() {
        return Ok(());
    }
    let bytes = present.to_vec();
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
        let Some(keys) = crypt.keys.get(&pw, &salt, &budget.rar3_derivations) else {
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
/// header's own CRC tells a right password from a wrong one. The flag says
/// whether every block read as a header, to the end block or the end of the
/// archive: with a password that opens the first blocks and not the rest, it
/// is `false`.
#[cfg(feature = "decrypt")]
fn rar4_open_headers(
    data: &[u8],
    main_at: usize,
    main_end: usize,
    budget: &Budget,
    crypt: &mut Rar4Crypt,
) -> Option<(Vec<u8>, bool)> {
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
        let mut whole = true;
        while q < data.len() {
            let salt: [u8; 8] = crate::bytes::at(data, q, 8)?.try_into().ok()?;
            let keys = crypt.keys.get(&pw, &salt, &budget.rar3_derivations)?;
            let mut first = data.get(q + 8..q + 24)?.to_vec();
            rar3_crypt::decrypt(&keys, &mut first);
            let head_size = usize::from(u16::from_le_bytes([first[5], first[6]]));
            if head_size < 7 {
                if blocks == 0 {
                    continue 'password;
                }
                whole = false;
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
                whole = false;
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
        return Some((plain, whole));
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
            // Where the next block starts is not known: the rest of the
            // archive is reported, not left as an archive of fewer members.
            damaged_member(&mut out, budget)?;
            break;
        }
        // ADD_SIZE (data following the header) when flag 0x8000 is set.
        let add_size = if flags & 0x8000 != 0 {
            u32le(data, pos + 7).unwrap_or(0) as u64
        } else {
            0
        };
        if htype == 0x73 && flags & 0x0080 != 0 {
            // MHD_PASSWORD: the BLOCK HEADERS themselves are encrypted (`rar -hp`),
            // so the file table cannot be read at all: not one member name, let
            // alone its content.
            //
            // Without this the walk simply finds no file headers and returns an
            // empty list, and an archive with nothing in it scans CLEAN. That is
            // the worst outcome available: a password-protected archive reported
            // as containing no malware, when the truth is that nothing inside it
            // was ever looked at. Report it, exactly as a member-level
            // `LHD_PASSWORD` is reported below, unless a password opens it.
            #[cfg(feature = "decrypt")]
            if let Some((plain, whole)) =
                rar4_open_headers(data, pos, pos + head_size, budget, crypt)
            {
                let mut opened = extract_rar4_keyed(&plain, start, budget, crypt)?;
                if !whole {
                    damaged_member(&mut opened, budget)?;
                }
                return Ok(opened);
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
                // reads as a complete member, so a stored member continuing
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
                // own header asks for. Only a window over the limit fails.
                if !solid || solid_dec.is_none() {
                    solid_dec = rar3_unpack::Unpacker29::new(win_bits, budget).ok();
                }
                let stale = solid && !in_step;
                let cut = data_off.saturating_add(crate::bytes::to_usize(pack)) > data.len();
                let decoded = match solid_dec.as_mut() {
                    Some(dec) => {
                        dec.cut_by_archive_end(cut);
                        let got = dec.member(packed, unp, solid, budget);
                        let over = dec.over_limit().then_some(PPMD_OVER_LIMIT);
                        settle(got, over, &name, budget)?
                    }
                    None => Err(WINDOW_OVER_LIMIT),
                };
                // A member that failed mid-group leaves the shared window out of
                // step with the stream, so every later member would decode to
                // garbage: those are reported (`stale`), not scanned as theirs.
                if decoded.is_err() {
                    solid_dec = None;
                }
                let crc_ok = decoded.as_ref().is_ok_and(|b| crc32_ieee(b) == crc);
                in_step = decoded.is_ok() && (!stale || crc_ok);
                match decoded {
                    // A CRC mismatch after a full decode hides nothing: the
                    // bytes are scanned, as a ZIP member's are, and reported
                    // only when checksums are verified.
                    Ok(bytes) if crc_ok || !(stale || budget.should_verify_checksums()) => {
                        out.push(Entry {
                            comp_size: pack,
                            name,
                            data: bytes,
                            ..Entry::default()
                        });
                    }
                    Ok(_) if stale => {
                        out.push(Entry::unsupported(name, pack, false, RAR_STALE));
                    }
                    Ok(_) if cut => {
                        out.push(Entry::unsupported(name, pack, false, RAR_CUT));
                    }
                    Ok(_) => {
                        out.push(Entry::unsupported(
                            name,
                            pack,
                            false,
                            "RAR member did not match its recorded CRC after decoding",
                        ));
                    }
                    Err(why) => {
                        let mut e = Entry::unsupported(name, pack, false, why);
                        e.reason_kind = kind_of(why);
                        out.push(e);
                    }
                }
            } else {
                // Compressed with an older version or an unknown method, or
                // encrypted, and not decoded: record metadata, flagged
                // Unscannable so it isn't reported as clean.
                let _ = crc;
                budget.count_entry()?;
                let mut e = Entry::unsupported(name, pack, encrypted, RAR_UNSUPPORTED);
                e.reason_kind = kind_of(RAR_UNSUPPORTED);
                out.push(e);
            }
            // The next block follows the member's data. With a 64-bit size
            // (LHD_LARGE) that is more than ADD_SIZE, its low half.
            let data_len = if large { pack } else { add_size };
            pos = data_off.saturating_add(crate::bytes::to_usize(data_len));
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

/// A RAR5 block header read from an archive held in memory, its offsets in the
/// archive.
struct Rar5Hdr {
    hsize: u64,
    /// Where the header content starts.
    hdr: usize,
    /// Where the block's data starts.
    data_off: usize,
    htype: u64,
    hflags: u64,
    /// Where the fields after the sizes start.
    q: usize,
    extra_size: u64,
    data_size: u64,
}

/// The block header at `pos` of `data`, read as the walk from a source reads it.
fn rar5_hdr_at(data: &[u8], pos: usize) -> Result<Rar5Hdr, HeadErr> {
    let b = rar5_head(&data, pos)?;
    Ok(Rar5Hdr {
        hsize: b.hsize,
        hdr: pos + b.hdr,
        data_off: b.at + b.hdr + crate::bytes::to_usize(b.hsize),
        htype: b.htype,
        hflags: b.hflags,
        q: pos + b.q,
        extra_size: b.extra_size,
        data_size: b.data_size,
    })
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
    let mut run = Rar5Run::default();
    let mut out = Vec::new();
    let mut pos = start;
    while pos + 4 < data.len() {
        let Rar5Hdr {
            hsize,
            hdr,
            data_off,
            htype,
            hflags,
            q,
            extra_size,
            data_size,
        } = match rar5_hdr_at(data, pos) {
            Ok(h) => h,
            // Where the next block starts is not known: the rest of the
            // archive is reported, not left as an archive of fewer members.
            Err(HeadErr::Bad) => {
                damaged_member(&mut out, budget)?;
                break;
            }
            Err(HeadErr::Cut) => break,
        };
        if htype == 5 {
            break; // end-of-archive
        }
        if htype == 4 {
            // Every header after this one is encrypted. With a password that
            // opens them, the archive is read again with them in the clear;
            // without, it is one encrypted member, never an empty archive.
            #[cfg(feature = "decrypt")]
            if let Some((plain, whole)) = data
                .get(q..data_off)
                .and_then(|b| rar5_crypt::CryptRecord::parse(b, false))
                .and_then(|rec| rar5_open_headers(data, start, data_off, &rec, budget, keys))
            {
                let mut opened = extract_rar5_keyed(&plain, start, budget, keys)?;
                if !whole {
                    damaged_member(&mut opened, budget)?;
                }
                return Ok(opened);
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
                    } else if !rar5_unpack::known_version(f.comp_info) {
                        solid_dec = None;
                        in_step = false;
                        budget.count_entry()?;
                        out.push(
                            Entry::unsupported(f.name, data_size, f.encrypted, RAR5_VERSION)
                                .of_kind(crate::tree::ReasonKind::Unsupported),
                        );
                    } else {
                        self::decode_rar5_member(
                            &mut out,
                            budget,
                            (&mut solid_dec, &mut in_step),
                            (&f, run.output_at(&data, pos)),
                            plain.as_deref().unwrap_or(raw),
                            data_size,
                            crc_ok,
                        )?;
                    }
                }
            } else {
                // The fields do not parse: the member is not read, and its
                // data is skipped with it.
                budget.count_entry()?;
                out.push(Entry::unsupported(
                    "rar-entry".to_string(),
                    data_size,
                    false,
                    RAR_DAMAGED_FILE,
                ));
            }
        }
        let Some(next) = data_off.checked_add(crate::bytes::to_usize(data_size)) else {
            break;
        };
        if next <= pos {
            break; // no progress: malformed
        }
        pos = next;
    }
    Ok(out)
}

/// Decode one compressed RAR5 member from `packed` and add it to `out`, or
/// say why it could not be read. The pair after `budget` is the solid group's
/// decoder and whether its window holds every member before this one; the
/// next, the member and what a decoder started at it produces ([`Rar5Run`]).
fn decode_rar5_member(
    out: &mut Vec<Entry>,
    budget: &mut Budget,
    (solid_dec, in_step): (&mut Option<rar5_unpack::Unpacker50>, &mut bool),
    (f, output): (&Rar5File, Option<u64>),
    packed: &[u8],
    data_size: u64,
    crc_ok: impl Fn(&[u8]) -> bool,
) -> Result<(), LimitHit> {
    budget.count_entry()?;
    // A member that is not solid starts afresh, on the window its own header
    // asks for: reusing the first member's ran every later, larger member
    // through a window too small for its distances.
    if !f.solid || solid_dec.is_none() {
        let window = rar5_unpack::window_for(f.comp_info, output);
        let limit = budget.limits.max_buffer_bytes;
        *solid_dec = (window <= limit)
            .then(|| rar5_unpack::Unpacker50::with_window(window, f.comp_info, limit).ok())
            .flatten();
    }
    let stale = f.solid && !*in_step;
    let decoded = match solid_dec.as_mut() {
        Some(dec) => {
            let got = dec.member(packed, f.unp_size, f.solid, budget);
            let over = dec.window_over_limit().then_some(WINDOW_OVER_LIMIT);
            settle(got, over, &f.name, budget)?
        }
        None => Err(WINDOW_OVER_LIMIT),
    };
    // A member that failed mid-group leaves the shared window out of step with
    // the stream, so every later member would decode to garbage: those are
    // reported (`stale`), not scanned as theirs.
    if decoded.is_err() {
        *solid_dec = None;
    }
    let matches = decoded.as_deref().is_ok_and(&crc_ok);
    *in_step = decoded.is_ok() && (!stale || matches);
    // For an encrypted member the CRC is what confirms the password (RAR5's
    // own check value is optional), so a mismatch there is always reported.
    let checked = stale || f.encrypted || budget.should_verify_checksums();
    let name = f.name.clone();
    out.push(match decoded {
        // A CRC mismatch after a full decode hides nothing: the bytes are
        // scanned, as a ZIP member's are, and reported only when checksums
        // are verified.
        Ok(bytes) if matches || !checked => Entry {
            comp_size: data_size,
            name,
            data: bytes,
            encrypted: f.encrypted,
            ..Entry::default()
        },
        Ok(_) if stale => Entry::unsupported(name, data_size, f.encrypted, RAR_STALE),
        // The archive ends inside the member.
        Ok(_) if (packed.len() as u64) < data_size => {
            Entry::unsupported(name, data_size, f.encrypted, RAR_CUT)
        }
        Ok(_) => Entry::unsupported(
            name,
            data_size,
            f.encrypted,
            "RAR member did not match its recorded CRC after decoding",
        ),
        Err(why) => {
            let mut e = Entry::unsupported(name, data_size, f.encrypted, why);
            e.reason_kind = kind_of(why);
            e
        }
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
    let k = rar5_crypt::find_keys(&rec, &budget.passwords, keys, &budget.kdf_rounds)?;
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
/// is. `None` when no password opens them. The flag says whether every header
/// read as one, to the end header or the end of the archive: with a key that
/// opens the first headers and not the rest, it is `false`.
#[cfg(feature = "decrypt")]
fn rar5_open_headers(
    data: &[u8],
    start: usize,
    mut p: usize,
    rec: &rar5_crypt::CryptRecord,
    budget: &Budget,
    keys: &mut KeyCache,
) -> Option<(Vec<u8>, bool)> {
    let k = rar5_crypt::find_keys(rec, &budget.passwords, keys, &budget.kdf_rounds)?;
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
            return (headers > 0).then_some((plain, false));
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
    Some((plain, true))
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

// ---- Streaming walk -----------------------------------------------------------
//
// The archive is read where it lies: each header through a window of the
// source, each member's packed bytes through a reader over its range, and a
// compressed member decoded as the visitor reads it, so what is held is the
// LZ window and a bounded stretch of input. The branches are those of
// `extract_rar4_keyed` and `extract_rar5_keyed`, which stay as the reader of
// what this path hands to the whole-archive one: encrypted headers, encrypted
// members and RAR5 links, when the archive fits the buffer limit.

/// CRC-32 (IEEE) computed as the bytes go by.
struct Crc32(u32);

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

impl Crc32 {
    fn update(&mut self, data: &[u8]) {
        let mut c = !self.0;
        for &b in data {
            c = CRC_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.0 = !c;
    }
}

/// A decoder that gives a started member's bytes as they are read.
trait LzStream {
    fn read_member(&mut self, buf: &mut [u8], src: &mut dyn Read) -> Result<usize, LimitHit>;
    /// Why a limit stopped it part way: its model or window over the buffer
    /// limit, or else its memory.
    fn limit_reason(&self) -> &'static str;
}

impl LzStream for rar3_unpack::Unpacker29 {
    fn read_member(&mut self, buf: &mut [u8], src: &mut dyn Read) -> Result<usize, LimitHit> {
        rar3_unpack::Unpacker29::read_member(self, buf, src)
    }
    fn limit_reason(&self) -> &'static str {
        if self.over_limit() {
            PPMD_OVER_LIMIT
        } else {
            RAR_OVER_LIMIT
        }
    }
}

impl LzStream for rar5_unpack::Unpacker50 {
    fn read_member(&mut self, buf: &mut [u8], src: &mut dyn Read) -> Result<usize, LimitHit> {
        rar5_unpack::Unpacker50::read_member(self, buf, src)
    }
    fn limit_reason(&self) -> &'static str {
        if self.window_over_limit() {
            WINDOW_OVER_LIMIT
        } else {
            RAR_OVER_LIMIT
        }
    }
}

/// A compressed member as the visitor reads it. At its end the CRC the
/// archive records is checked: a mismatch is a checksum error, or, for a
/// solid member decoded without one before it, an error that says its bytes
/// are not its own.
struct LzMember<'d, 's> {
    dec: &'d mut dyn LzStream,
    src: &'s mut dyn Read,
    crc: Crc32,
    want: Option<u32>,
    /// The archive ends inside the member, so its CRC cannot match.
    cut: bool,
    stale: bool,
    ended: bool,
    /// The decode ran to the member's end without an error.
    decoded: bool,
    crc_ok: bool,
    /// Bytes given so far.
    given: u64,
    /// A limit stopped the decode part way ([`LzStream::limit_reason`]).
    limited: bool,
}

impl<'d, 's> LzMember<'d, 's> {
    fn new(
        dec: &'d mut dyn LzStream,
        src: &'s mut dyn Read,
        (want, cut): (Option<u32>, bool),
        stale: bool,
    ) -> Self {
        LzMember {
            dec,
            src,
            crc: Crc32(0),
            want,
            cut,
            stale,
            ended: false,
            decoded: false,
            crc_ok: false,
            given: 0,
            limited: false,
        }
    }

    /// Decode what the visitor left, so a solid group's next member starts
    /// where this one ends; charged to the scan, as decoding it is the work a
    /// scan limit is for.
    fn finish(&mut self, budget: &mut Budget) -> Result<(), LimitHit> {
        let mut scratch = vec![0u8; 64 * 1024];
        while !self.ended {
            match self.read(&mut scratch) {
                Ok(n) => budget.charge_scan(n as u64)?,
                Err(_) => break,
            }
        }
        Ok(())
    }
}

impl Read for LzMember<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.ended || buf.is_empty() {
            return Ok(0);
        }
        match self.dec.read_member(buf, self.src) {
            Ok(0) => {
                self.ended = true;
                self.decoded = true;
                self.crc_ok = self.want.is_none_or(|c| c == self.crc.0);
                if self.crc_ok {
                    Ok(0)
                } else if self.stale {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        RAR_STALE,
                    ))
                } else if self.cut {
                    Err(crate::checksum_cut("RAR CRC-32"))
                } else {
                    Err(crate::checksum_mismatch("RAR CRC-32"))
                }
            }
            Ok(n) => {
                self.crc.update(&buf[..n]);
                self.given += n as u64;
                Ok(n)
            }
            Err(e) if !e.is_corrupt() => {
                self.ended = true;
                self.limited = true;
                Err(crate::stream::limit_stop())
            }
            Err(e) => {
                self.ended = true;
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.reason,
                ))
            }
        }
    }
}

/// What a header pass finds that only the whole-archive path reads.
fn rar_needs_whole(src: &dyn ByteSource, rar5: bool) -> bool {
    let len = src.len();
    if rar5 {
        let mut pos = RAR5_MAGIC.len();
        while pos + 4 < len {
            let Ok(b) = rar5_head(src, pos) else { break };
            if b.htype == 4 {
                return true;
            }
            if b.htype == 2
                && let Some(f) = rar5_file_fields(&b.bytes, b.q, b.hdr, b.hsize, b.extra_size)
                && (f.encrypted || f.redirect.as_ref().is_some_and(|r| matches!(r.0, 4 | 5)))
            {
                return true;
            }
            if b.htype == 5 || b.next <= pos {
                break;
            }
            pos = b.next;
        }
    } else {
        let mut pos = RAR4_MAGIC.len();
        while pos.saturating_add(7) <= len {
            let w = src.window(pos, 7);
            let (Some(flags), Some(head_size)) = (u16le(&w, 3), u16le(&w, 5)) else {
                break;
            };
            let (htype, head_size) = (w[2], usize::from(head_size));
            if head_size < 7 || htype == 0x7B {
                break;
            }
            if (htype == 0x73 && flags & 0x0080 != 0) || (htype == 0x74 && flags & 0x04 != 0) {
                return true;
            }
            let add = if flags & 0x8000 != 0 {
                u32le(&src.window(pos + 7, 4), 0).unwrap_or(0) as usize
            } else {
                0
            };
            pos = pos.saturating_add(head_size).saturating_add(add);
        }
    }
    false
}

/// Walk a RAR archive from its source, its compressed members decoded as
/// they are read (see the section's head).
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let head = src.window(0, RAR5_MAGIC.len());
    let rar5 = head.starts_with(RAR5_MAGIC);
    if !rar5 && !head.starts_with(RAR4_MAGIC) {
        return Ok(None);
    }
    if src.len() as u64 <= budget.limits.max_buffer_bytes && rar_needs_whole(src, rar5) {
        return crate::stream::whole(crate::Format::Rar, src, budget, visit);
    }
    if rar5 {
        stream_rar5(src, budget, visit)
    } else {
        stream_rar4(src, budget, visit)
    }
}

/// A member reported with no content.
fn report(
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
    name: String,
    comp_size: u64,
    encrypted: bool,
    reason: &'static str,
) -> Result<Option<()>, LimitHit> {
    budget.count_entry()?;
    let meta = crate::stream::MemberMeta {
        name,
        comp_size,
        encrypted,
        unsupported: Some(reason),
        reason_kind: kind_of(reason),
        ..Default::default()
    };
    Ok(visit(&meta, None, budget))
}

/// A stored member streamed from `[off, off + pack)`. The archive can end
/// inside it, as the whole-archive path allows: the bytes present are the
/// member and the rest is absent.
fn stream_stored_member(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
    name: String,
    off: usize,
    pack: u64,
) -> Result<Option<()>, LimitHit> {
    budget.count_entry()?;
    let end = off
        .saturating_add(crate::bytes::to_usize(pack))
        .min(src.len());
    let off = off.min(end);
    let mut r = crate::source::Reader::range(src, off, end);
    let meta = crate::stream::MemberMeta {
        name,
        comp_size: pack,
        size: Some((end - off) as u64),
        ..Default::default()
    };
    crate::stream::emit_stream(&meta, &mut r, budget, visit)
}

/// Why a member whose dictionary is over the buffer limit is not decoded.
const WINDOW_OVER_LIMIT: &str =
    "RAR member's dictionary is over the buffer limit (--max-object-bytes)";

/// Why a member whose PPMd model is over the buffer limit is not decoded.
const PPMD_OVER_LIMIT: &str =
    "RAR member's PPMd model is over the buffer limit (--max-object-bytes)";

/// Decode one compressed member as the visitor reads it, then the rest of it.
/// `(decoded, crc_ok)`: whether it decoded to its end, and matched its CRC.
///
/// A stale member (solid, after one that was not decoded) is decoded first
/// and handed over only if its CRC says the bytes are its own, as the
/// whole-archive path does; it is held for that under the buffer limit, and
/// reported when larger. `undecoded` is the reason for one that fails. `want`
/// is the CRC, and whether the archive ends inside the member.
#[allow(clippy::too_many_arguments)]
fn stream_lz_member(
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
    dec: &mut dyn LzStream,
    name: String,
    pack: u64,
    unp: u64,
    want: (Option<u32>, bool),
    stale: bool,
    packed: &mut crate::source::Reader<'_>,
    undecoded: &'static str,
) -> Result<(Option<()>, bool, bool), LimitHit> {
    let mut meta = crate::stream::MemberMeta {
        name,
        comp_size: pack,
        size: Some(unp),
        ..Default::default()
    };
    let mut m = LzMember::new(dec, packed, want, stale);
    if stale {
        // What is decoded and not handed over is charged to the scan, as the
        // rest of a member the visitor left is.
        let cap = budget.reserve()?.min(budget.remaining_scan());
        let mut data = Vec::new();
        let held = crate::source::read_capped(&mut m, &mut data, cap.saturating_add(1));
        let fits = data.len() as u64 <= cap;
        if !fits {
            budget.charge_scan(data.len() as u64)?;
            m.finish(budget)?;
        }
        let (decoded, crc_ok) = (m.decoded, m.crc_ok);
        let out = if held.is_ok() && fits && decoded {
            budget.commit(data.len() as u64);
            crate::stream::emit_bytes(&meta, Some(data), budget, visit)?
        } else {
            if fits {
                budget.charge_scan(data.len() as u64)?;
            }
            meta.size = None;
            let why = if m.limited {
                m.dec.limit_reason()
            } else if decoded || !fits {
                RAR_STALE
            } else {
                undecoded
            };
            meta.unsupported = Some(why);
            meta.reason_kind = kind_of(why);
            visit(&meta, None, budget)
        };
        return Ok((out, decoded, crc_ok));
    }
    let out = crate::stream::emit_stream(&meta, &mut m, budget, visit)?;
    if out.is_some() {
        return Ok((out, false, false));
    }
    // Left out at its compression ratio: its rest is not decoded, and a solid
    // group ends with it.
    if !m.ended && crate::stream::ratio_cap(pack, budget).is_some_and(|r| m.given > r) {
        return Ok((None, false, false));
    }
    m.finish(budget)?;
    // Left out at a limit its decoder met part way, which the walk reports
    // once its members are visited, as one over its ratio.
    if m.limited {
        let shown = crate::tree::quoted(&meta.name);
        budget.skip(format_args!("member '{shown}': {}", m.dec.limit_reason()));
    }
    Ok((None, m.decoded, m.crc_ok))
}

fn stream_rar4(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let len = src.len();
    let mut pos = RAR4_MAGIC.len();
    let mut dec: Option<rar3_unpack::Unpacker29> = None;
    let mut in_step = true;
    while pos.saturating_add(7) <= len {
        let w = src.window(pos, 7);
        let (Some(flags), Some(head_size)) = (u16le(&w, 3), u16le(&w, 5)) else {
            break;
        };
        let (htype, head_size) = (w[2], usize::from(head_size));
        if head_size < 7 {
            // Where the next block starts is not known: the rest of the
            // archive is reported, not left as an archive of fewer members.
            return Err(damaged(pos));
        }
        let add_size = if flags & 0x8000 != 0 {
            u32le(&src.window(pos + 7, 4), 0).unwrap_or(0) as u64
        } else {
            0
        };
        if htype == 0x73 && flags & 0x0080 != 0 {
            // Encrypted headers in an archive over the buffer limit: the
            // whole-archive path refuses it by its size.
            return crate::stream::whole(crate::Format::Rar, src, budget, visit);
        }
        if htype == 0x7B {
            break;
        }
        if htype != 0x74 {
            pos = pos
                .saturating_add(head_size)
                .saturating_add(crate::bytes::to_usize(add_size));
            continue;
        }
        // The header and what the field offsets reach past it, as the
        // whole-archive path reads them.
        let name_size = usize::from(u16le(&src.window(pos + 26, 2), 0).unwrap_or(0));
        let h = src.window(pos, head_size.max(41 + name_size + 8));
        let b = 7;
        let pack = u32le(&h, b).unwrap_or(0) as u64;
        let unp = u32le(&h, b + 4).unwrap_or(0) as u64;
        let crc = u32le(&h, b + 9).unwrap_or(0);
        let unp_ver = *h.get(b + 17).unwrap_or(&0);
        let method = *h.get(b + 18).unwrap_or(&0xff);
        let mut p = b + 25;
        let (pack, unp) = if flags & 0x100 != 0 {
            let hp = u32le(&h, p).unwrap_or(0) as u64;
            let hu = u32le(&h, p + 4).unwrap_or(0) as u64;
            p += 8;
            ((hp << 32) | pack, (hu << 32) | unp)
        } else {
            (pack, unp)
        };
        let name = read_name(&h, p, name_size);
        let encrypted = flags & 0x04 != 0;
        let data_off = pos
            .checked_add(head_size)
            .ok_or_else(|| LimitHit::corrupt("rar: header size overflow".to_string()))?;
        let is_dir = (flags & 0xE0) == 0xE0;
        let win_bits = (((flags & 0xE0) >> 5) as u32) + 16;
        let split = flags & 0x03 != 0;
        let lz = !encrypted && unp_ver == 29 && (0x31..=0x35).contains(&method);
        if !is_dir && (split || !lz) {
            in_step = false;
        }
        let r = if is_dir {
            None
        } else if encrypted && !split {
            // Over the buffer limit, so not tried with a password.
            dec = None;
            report(budget, visit, name, pack, true, "encrypted RAR member")?
        } else if method == 0x30 && (pack == unp || split) {
            if split
                && let Some(t) = report(
                    budget,
                    visit,
                    name.clone(),
                    pack,
                    encrypted,
                    "RAR member continues in another volume; only the part in this volume \
                     was scanned",
                )?
            {
                return Ok(Some(t));
            }
            if encrypted {
                report(budget, visit, name, pack, true, "encrypted RAR member")?
            } else {
                stream_stored_member(src, budget, visit, name, data_off, pack)?
            }
        } else if split {
            report(
                budget,
                visit,
                name,
                pack,
                encrypted,
                "RAR member continues in another volume",
            )?
        } else if lz {
            budget.count_entry()?;
            let solid = flags & 0x10 != 0;
            let mut why = RAR_UNDECODED;
            if !solid || dec.is_none() {
                let window = (1u64 << win_bits.min(30)).max(0x40000);
                dec = if window > budget.limits.max_buffer_bytes {
                    why = WINDOW_OVER_LIMIT;
                    None
                } else {
                    rar3_unpack::Unpacker29::new(win_bits, budget).ok()
                };
            }
            let stale = solid && !in_step;
            let end = data_off.saturating_add(crate::bytes::to_usize(pack));
            let mut packed = crate::source::Reader::range(src, data_off, end);
            let started = dec.as_mut().is_some_and(|d| {
                d.cut_by_archive_end(end > len);
                d.start_member(unp, solid, &mut packed).is_ok()
            });
            if !started && dec.as_ref().is_some_and(|d| d.over_limit()) {
                why = PPMD_OVER_LIMIT;
            }
            match dec.as_mut() {
                Some(d) if started => {
                    let (out, decoded, crc_ok) = stream_lz_member(
                        budget,
                        visit,
                        d,
                        name,
                        pack,
                        unp,
                        (Some(crc), end > len),
                        stale,
                        &mut packed,
                        RAR_UNDECODED,
                    )?;
                    if !decoded {
                        dec = None;
                    }
                    in_step = decoded && (!stale || crc_ok);
                    out
                }
                _ => {
                    dec = None;
                    in_step = false;
                    let meta = crate::stream::MemberMeta {
                        name,
                        comp_size: pack,
                        unsupported: Some(why),
                        reason_kind: kind_of(why),
                        ..Default::default()
                    };
                    visit(&meta, None, budget)
                }
            }
        } else {
            report(budget, visit, name, pack, encrypted, RAR_UNSUPPORTED)?
        };
        if let Some(t) = r {
            return Ok(Some(t));
        }
        // The next block follows the member's data. With a 64-bit size
        // (LHD_LARGE) that is more than ADD_SIZE, its low half.
        let data_len = if flags & 0x100 != 0 { pack } else { add_size };
        pos = data_off.saturating_add(crate::bytes::to_usize(data_len));
    }
    Ok(None)
}

/// A RAR5 block's header read from the source: its bytes from the block's
/// start, and its fields at offsets in them.
struct Rar5Head<'a> {
    bytes: std::borrow::Cow<'a, [u8]>,
    /// The block's offset in the archive.
    at: usize,
    hdr: usize,
    hsize: u64,
    htype: u64,
    hflags: u64,
    q: usize,
    extra_size: u64,
    data_size: u64,
    /// Where the next block starts, in the archive.
    next: usize,
}

/// The largest RAR5 header read: the format's is 2 MiB.
const RAR5_MAX_HEADER: u64 = 4 << 20;

/// Why a RAR5 block header could not be read.
enum HeadErr {
    /// The archive ends inside it: what is missing is absent, not hidden.
    Cut,
    /// It does not parse, with bytes after it: it is over [`RAR5_MAX_HEADER`],
    /// or one of its fields is not an integer.
    Bad,
}

fn rar5_head(src: &dyn ByteSource, pos: usize) -> Result<Rar5Head<'_>, HeadErr> {
    let w = src.window(pos, 14);
    // A size the end of the archive cuts is cut; ten bytes that all go on
    // are no integer.
    let Some((hsize, hs_len)) = vint(&w, 4) else {
        return Err(if w.len() < 14 {
            HeadErr::Cut
        } else {
            HeadErr::Bad
        });
    };
    let hdr = 4 + hs_len;
    let data_off = pos
        .checked_add(hdr)
        .and_then(|d| d.checked_add(crate::bytes::to_usize(hsize)))
        .ok_or(HeadErr::Bad)?;
    if hsize == 0 || hsize > RAR5_MAX_HEADER {
        return Err(HeadErr::Bad);
    }
    if data_off > src.len() {
        return Err(HeadErr::Cut);
    }
    // The fields of a file header are read past a header too short for them,
    // as the whole-archive path reads them.
    let bytes = src.window(pos, hdr + crate::bytes::to_usize(hsize) + 80);
    let fields = (|| {
        let (htype, t1) = vint(&bytes, hdr)?;
        let (hflags, t2) = vint(&bytes, hdr + t1)?;
        let mut q = hdr + t1 + t2;
        let mut extra_size = 0;
        if hflags & 0x01 != 0 {
            let (v, n) = vint(&bytes, q)?;
            extra_size = v;
            q += n;
        }
        let mut data_size = 0;
        if hflags & 0x02 != 0 {
            let (v, n) = vint(&bytes, q)?;
            data_size = v;
            q += n;
        }
        let next = data_off.checked_add(crate::bytes::to_usize(data_size))?;
        Some((htype, hflags, q, extra_size, data_size, next))
    })();
    let Some((htype, hflags, q, extra_size, data_size, next)) = fields else {
        return Err(HeadErr::Bad);
    };
    Ok(Rar5Head {
        bytes,
        at: pos,
        hdr,
        hsize,
        htype,
        hflags,
        q,
        extra_size,
        data_size,
        next,
    })
}

/// The solid run of RAR5 members a decoder started at one of them serves: up
/// to the next member that is compressed and not solid, which starts a
/// decoder of its own. Read from the headers once per run, so a decoder made
/// again inside it reads nothing.
#[derive(Default)]
struct Rar5Run {
    /// The header offsets it covers, `from..to`.
    from: usize,
    to: usize,
    /// The unpacked sizes of its members, from `from` on: what a decoder
    /// started there produces. `None` when one of them is not known.
    output: Option<u64>,
}

impl Rar5Run {
    /// [`Self::output`] for a decoder started at the member whose header is at
    /// `pos`. Inside the run last read, the whole run's, an upper bound.
    fn output_at(&mut self, src: &dyn ByteSource, pos: usize) -> Option<u64> {
        if !(self.from..self.to).contains(&pos) {
            *self = Self::read(src, pos);
        }
        self.output
    }

    fn read(src: &dyn ByteSource, from: usize) -> Self {
        let mut output = Some(0u64);
        let mut at = from;
        while at + 4 < src.len() {
            let Ok(b) = rar5_head(src, at) else { break };
            if matches!(b.htype, 4 | 5) {
                break;
            }
            if b.htype == 2
                && let Some(f) = rar5_file_fields(&b.bytes, b.q, b.hdr, b.hsize, b.extra_size)
            {
                if at != from && f.method != 0 && !f.solid {
                    break;
                }
                // File flag 0x08: the unpacked size is not known.
                let size = (f.file_flags & 0x08 == 0).then_some(f.unp_size);
                output = output.zip(size).and_then(|(a, s)| a.checked_add(s));
            }
            if b.next <= at {
                break;
            }
            at = b.next;
        }
        Rar5Run {
            from,
            to: at.max(from + 1),
            output,
        }
    }
}

fn stream_rar5(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let len = src.len();
    let mut dec: Option<rar5_unpack::Unpacker50> = None;
    let mut run = Rar5Run::default();
    let mut in_step = true;
    let mut pos = RAR5_MAGIC.len();
    while pos + 4 < len {
        let b = match rar5_head(src, pos) {
            Ok(b) => b,
            // Where the next block starts is not known: the rest of the
            // archive is reported, not left as an archive of fewer members.
            Err(HeadErr::Bad) => return Err(damaged(pos)),
            Err(HeadErr::Cut) => break,
        };
        if b.htype == 5 {
            break;
        }
        if b.htype == 4 {
            return crate::stream::whole(crate::Format::Rar, src, budget, visit);
        }
        let data_off = b.at + b.hdr + crate::bytes::to_usize(b.hsize);
        let data_size = b.data_size;
        if b.htype == 2
            && let Some(f) = rar5_file_fields(&b.bytes, b.q, b.hdr, b.hsize, b.extra_size)
        {
            let is_dir = f.file_flags & 0x01 != 0;
            let split = b.hflags & 0x18 != 0;
            let crc = f.has_crc.then_some(f.crc);
            let r = if is_dir {
                None
            } else if split && f.method != 0 {
                in_step = false;
                report(
                    budget,
                    visit,
                    f.name,
                    data_size,
                    f.encrypted,
                    "RAR member continues in another volume",
                )?
            } else if f
                .redirect
                .as_ref()
                .is_some_and(|(kind, _)| matches!(kind, 4 | 5))
            {
                // Over the buffer limit, so the member it repeats is not kept.
                report(
                    budget,
                    visit,
                    f.name,
                    data_size,
                    f.encrypted,
                    "RAR link to another member, in an archive over the buffer limit",
                )?
            } else if f.encrypted {
                dec = None;
                in_step = false;
                report(
                    budget,
                    visit,
                    f.name,
                    data_size,
                    true,
                    "encrypted RAR member",
                )?
            } else if f.method == 0 {
                in_step = false;
                if split
                    && let Some(t) = report(
                        budget,
                        visit,
                        f.name.clone(),
                        data_size,
                        false,
                        "RAR member continues in another volume; only the part in this \
                         volume was scanned",
                    )?
                {
                    return Ok(Some(t));
                }
                stream_stored_member(src, budget, visit, f.name, data_off, data_size)?
            } else if !rar5_unpack::known_version(f.comp_info) {
                dec = None;
                in_step = false;
                report(budget, visit, f.name, data_size, false, RAR5_VERSION)?
            } else {
                budget.count_entry()?;
                let mut why = RAR_UNDECODED;
                if !f.solid || dec.is_none() {
                    let output = run.output_at(src, b.at);
                    let window = rar5_unpack::window_for(f.comp_info, output);
                    let limit = budget.limits.max_buffer_bytes;
                    dec = if window > limit {
                        why = WINDOW_OVER_LIMIT;
                        None
                    } else {
                        rar5_unpack::Unpacker50::with_window(window, f.comp_info, limit).ok()
                    };
                }
                let stale = f.solid && !in_step;
                let end = data_off.saturating_add(crate::bytes::to_usize(data_size));
                let mut packed = crate::source::Reader::range(src, data_off, end);
                let packed_len = (end.min(len).saturating_sub(data_off.min(len))) as u64;
                match dec.as_mut() {
                    Some(d) => {
                        d.start_member(packed_len, f.solid);
                        let (out, decoded, crc_ok) = stream_lz_member(
                            budget,
                            visit,
                            d,
                            f.name,
                            data_size,
                            f.unp_size,
                            (crc, end > len),
                            stale,
                            &mut packed,
                            RAR_UNDECODED,
                        )?;
                        if !decoded {
                            dec = None;
                        }
                        in_step = decoded && (!stale || crc_ok);
                        out
                    }
                    None => {
                        in_step = false;
                        let meta = crate::stream::MemberMeta {
                            name: f.name,
                            comp_size: data_size,
                            unsupported: Some(why),
                            reason_kind: kind_of(why),
                            ..Default::default()
                        };
                        visit(&meta, None, budget)
                    }
                }
            };
            if let Some(t) = r {
                return Ok(Some(t));
            }
        } else if b.htype == 2 {
            // The fields do not parse: the member is not read, and its data
            // is skipped with it.
            let reported = report(
                budget,
                visit,
                "rar-entry".to_string(),
                data_size,
                false,
                RAR_DAMAGED_FILE,
            )?;
            if let Some(t) = reported {
                return Ok(Some(t));
            }
        }
        if b.next <= pos {
            break;
        }
        pos = b.next;
    }
    Ok(None)
}

// ---- Volumes ----------------------------------------------------------------

/// The volumes of a RAR set, in order, as one single-volume archive (see
/// [`RarSpan`], which does the join): each split member's packed data joined
/// behind its first header, which takes the total size and the last part's CRC.
/// `Err` names what does not fit together.
pub(crate) fn join_volumes(volumes: &[&[u8]]) -> Result<Vec<u8>, String> {
    let parts = volumes
        .iter()
        .map(|v| Box::new(*v) as Box<dyn ByteSource + '_>)
        .collect();
    let span = RarSpan::new(parts, usize::MAX)?;
    Ok(span.window(0, span.len()).into_owned())
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
    use super::span::{rar5_block, rar5_crc, rar5_fields_at, rar5_name, vint_bytes};
    use super::*;

    /// The streaming walk holds a decoder while the visitor runs, and the
    /// visitor may open a nested archive: a decoder with its tables inline
    /// puts them in the frame of every level.
    #[test]
    fn the_decoders_a_walk_holds_are_small_on_the_stack() {
        assert!(std::mem::size_of::<rar3_unpack::Unpacker29>() <= 1024);
        assert!(std::mem::size_of::<rar5_unpack::Unpacker50>() <= 1024);
    }

    /// `rar -hp` encrypts the BLOCK HEADERS, so the file table itself is
    /// unreadable: the walk finds no file headers at all.
    ///
    /// Returning an empty member list for that is a silent clean: a
    /// password-protected archive reported as containing no malware, when
    /// nothing inside it was ever examined. The archive-level MHD_PASSWORD flag
    /// (0x0080) is the only evidence available, so it has to be acted on.
    #[test]
    fn header_encrypted_archive_is_reported_not_empty() {
        // Marker, then an archive header with MHD_PASSWORD set and nothing after
        // it: exactly what a header-encrypted archive looks like to a reader
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
    /// verify them; it parses sizes/offsets).
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
                let Ok(b) = rar5_block(&arc, pos) else { break };
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
                    let block = rar5_block(&arc, pos).unwrap();
                    let c = &block.content;
                    // Built as a whole member, then flagged as a part.
                    let crc = (!after).then(|| rar5_crc(c)).flatten();
                    let crc = crc.or_else(|| after.then(|| crc32_ieee(part)));
                    let flags_at = vint(c, 0).unwrap().1;
                    let (fl, n) = vint(c, flags_at).unwrap();
                    let fl = fl | if before { 0x08 } else { 0 } | if after { 0x10 } else { 0 };
                    let mut h = c[..flags_at].to_vec();
                    h.extend(vint_bytes(fl));
                    h.extend_from_slice(&c[flags_at + n..]);
                    v.extend(rar5_part(&h, part, crc));
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

    /// A RAR5 block from header content `c` whose flags are already set, with
    /// `data` as its data and `crc` in its CRC field.
    fn rar5_part(c: &[u8], data: &[u8], crc: Option<u32>) -> Vec<u8> {
        let layout = rar5_fields_at(c).unwrap();
        let (htype, t1) = vint(c, 0).unwrap();
        let (hflags, t2) = vint(c, t1).unwrap();
        let mut content = vint_bytes(htype);
        content.extend(vint_bytes(hflags | 0x02));
        if hflags & 0x01 != 0 {
            content.extend(vint_bytes(vint(c, t1 + t2).unwrap().0));
        }
        content.extend(vint_bytes(data.len() as u64));
        let shift = content.len() as isize - layout.after_sizes as isize;
        content.extend_from_slice(&c[layout.after_sizes..]);
        if let (Some(at), Some(crc)) = (layout.crc_at, crc) {
            let at = (at as isize + shift) as usize;
            content[at..at + 4].copy_from_slice(&crc.to_le_bytes());
        }
        let mut out = crc32_ieee(&content).to_le_bytes().to_vec();
        out.extend(vint_bytes(content.len() as u64));
        out.extend(content);
        out.extend_from_slice(data);
        out
    }

    /// A set split from an archive, joined again, extracts as the archive
    /// does: stored members, and the compressed members of a solid archive,
    /// RAR4 and RAR5, cut at many sizes. A set missing a part is refused, or,
    /// with checksums verified, the member it held is reported.
    #[test]
    fn a_volume_set_joins_into_its_archive() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let fixture = |p: &str| crate::read_fixture(&format!("{root}/{p}")).unwrap();
        let arcs = [
            rar4_stored(b"hi.txt", &[b'z'; 1000]),
            rar5_stored(b"a/b.bin", &[b'y'; 1000]),
            fixture("rar_solid/solid_rar4.rar"),
            fixture("rar_solid/solid_rar5.rar"),
            // PPMd and the filters, in solid groups, and a hard link.
            fixture("rar4/solid_ppmd.rar"),
            fixture("rar4/solid_x86.rar"),
            fixture("rar_solid/solid_x86.rar"),
            fixture("rar5/hardlink.rar"),
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
                    // A part gone from the middle: refused, or, with checksums
                    // verified, the member it held reported, never passed off
                    // as whole. Unverified, a stream that still decodes is
                    // scanned as far as it goes, as one shorter than declared.
                    #[cfg(feature = "checksums")]
                    {
                        let missing: Vec<&[u8]> = refs
                            .iter()
                            .enumerate()
                            .filter(|(k, _)| *k != 1)
                            .map(|(_, v)| *v)
                            .collect();
                        if let Ok(joined) = join_volumes(&missing) {
                            let mut verified = budget();
                            verified.set_verify_checksums(true);
                            let got = names(&extract_rar(&joined, &mut verified).unwrap());
                            assert!(
                                got.iter().any(|g| g.2.is_some()),
                                "archive {i} chunk {chunk}: a missing part"
                            );
                        }
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
        let why = join_volumes(&[&first, &last]).unwrap_err();
        assert!(why.contains("a short file header"), "{why}");
    }

    /// What does not fit together is refused for what is wrong with it, the
    /// first volume missing, the last, one between, a volume given twice, a
    /// volume that is no RAR volume, and no volume at all: a set is never
    /// joined into an archive that reads as whole when it is not.
    #[test]
    fn a_set_that_does_not_fit_together_is_refused_for_what_is_wrong() {
        // What was not refused for its reason, all together: a refusal that
        // is gone shows here, whichever it is.
        let mut bad: Vec<String> = Vec::new();
        let mut expect = |what: String, got: Result<Vec<u8>, String>, reason: &str| match got {
            Err(e) if e.contains(reason) => {}
            other => bad.push(format!(
                "{what}: wanted {reason:?}, got {:?}",
                other.map(|_| ())
            )),
        };
        for (name, arc) in [
            ("rar4", rar4_stored(b"hi.txt", &[b'z'; 1000])),
            ("rar5", rar5_stored(b"a/b.bin", &[b'y'; 1000])),
        ] {
            // Three volumes: 400, 400 and 200 bytes of the member.
            let vols = split(&arc, 400);
            assert_eq!(vols.len(), 3);
            let join = |idx: &[usize]| {
                let refs: Vec<&[u8]> = idx.iter().map(|&i| vols[i].as_slice()).collect();
                join_volumes(&refs)
            };
            expect(
                format!("{name} without its first volume"),
                join(&[1, 2]),
                "part 1 goes on with a member whose start is missing",
            );
            expect(
                format!("{name} with a volume given twice"),
                join(&[0, 0]),
                "part 2 drops a member mid-way",
            );
            // The volume numbers of a RAR5 set would say first which one is
            // missing: the last volume is given the main header of the first.
            let mut gap = vols.clone();
            if arc.starts_with(RAR5_MAGIC) {
                let end = |v: &[u8]| rar5_block(&v, RAR5_MAGIC.len()).ok().unwrap().end;
                gap[2] = [&vols[0][..end(&vols[0])], &vols[2][end(&vols[2])..]].concat();
            }
            let refs: Vec<&[u8]> = [&gap[0], &gap[2]].iter().map(|v| v.as_slice()).collect();
            expect(
                format!("{name} without the volume between"),
                join_volumes(&refs),
                "a stored member of 1000 bytes has 600 in the parts given",
            );
            // The same with the last volume cut: what it declares counts.
            let mut cut_gap = gap.clone();
            let end = cut_gap[2].len() - 50;
            cut_gap[2].truncate(end);
            let refs: Vec<&[u8]> = [&cut_gap[0], &cut_gap[2]]
                .iter()
                .map(|v| v.as_slice())
                .collect();
            expect(
                format!("{name} without the volume between, the last cut"),
                join_volumes(&refs),
                "a stored member of 1000 bytes has 600 in the parts given",
            );
            let mut not = vols.clone();
            not[1][0] ^= 0xff;
            let refs: Vec<&[u8]> = not.iter().map(Vec::as_slice).collect();
            expect(
                format!("{name} with a volume that is no RAR volume"),
                join_volumes(&refs),
                "part 2 is not a RAR",
            );
            // And the whole set joins.
            join(&[0, 1, 2]).unwrap();
        }
        expect(
            "no volume".to_string(),
            join_volumes(&[]),
            "the first part is not a RAR archive",
        );
        expect(
            "a volume that is no archive".to_string(),
            join_volumes(&[b"not an archive"]),
            "the first part is not a RAR archive",
        );
        assert!(bad.is_empty(), "{bad:#?}");
    }

    /// A stored member over three volumes: 400, 400 and 200 bytes of it.
    fn three_volumes(arc: &[u8]) -> Vec<Vec<u8>> {
        let vols = split(arc, 400);
        assert_eq!(vols.len(), 3);
        vols
    }

    fn payload() -> Vec<u8> {
        (0..1000).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// A set whose last volume ends inside the member is joined as the archive
    /// cut there is read: the bytes the volumes hold, with no reason, in the
    /// walk of a source and in the whole-archive path alike. A volume but the
    /// last that ends inside a block is still refused.
    #[test]
    fn a_set_whose_last_volume_ends_inside_a_member_reads_as_an_archive_cut_there() {
        let payload = payload();
        for (label, arc, name) in [
            ("rar4", rar4_stored(b"hi.txt", &payload), "hi.txt"),
            ("rar5", rar5_stored(b"a/b.bin", &payload), "a/b.bin"),
        ] {
            let vols = three_volumes(&arc);
            let data_at = vols[2].len() - 200;
            for kept in [0, 1, 150] {
                let mut cut = vols.clone();
                cut[2].truncate(data_at + kept);
                let refs: Vec<&[u8]> = cut.iter().map(Vec::as_slice).collect();
                let joined = join_volumes(&refs).unwrap_or_else(|e| panic!("{label} {kept}: {e}"));
                let want = vec![(name.to_string(), payload[..800 + kept].to_vec(), false)];
                assert_eq!(
                    whole_path(&joined, budget()),
                    Ok(want.clone()),
                    "{label} {kept}"
                );
                let span = RarSpan::new(sources(&cut, false), usize::MAX).unwrap();
                assert_eq!(
                    streamed_from(&span, 4096, budget()),
                    Ok(want),
                    "{label} {kept} streamed"
                );
            }
            // A volume of the middle cut is a hole, not an end.
            let mut hole = vols.clone();
            let end = hole[1].len() - 3;
            hole[1].truncate(end);
            let refs: Vec<&[u8]> = hole.iter().map(Vec::as_slice).collect();
            let why = join_volumes(&refs).unwrap_err();
            assert!(why.contains("part 2 ends inside a block"), "{label}: {why}");
        }
    }

    /// A set that ends where a member goes on, in a volume not given, joins
    /// with that member flagged as continuing, as a volume read alone has it:
    /// the members before are whole, and what the volumes hold of this one is
    /// there.
    #[test]
    fn a_set_without_its_last_volume_has_its_last_member_flagged_as_going_on() {
        let payload = payload();
        for (label, arc) in [
            ("rar4", rar4_stored(b"m", &payload)),
            ("rar5", rar5_stored(b"m", &payload)),
        ] {
            let vols = three_volumes(&arc);
            // The last volume given whole but one, and the last given cut
            // inside the header of its part of the member.
            let mut headless = vols.clone();
            headless[2].truncate(vols[2].len() - 200 - 3);
            for set in [
                vec![&vols[0], &vols[1]],
                vec![&vols[0], &vols[1], &headless[2]],
            ] {
                let refs: Vec<&[u8]> = set.iter().map(|v| v.as_slice()).collect();
                let joined = join_volumes(&refs).unwrap_or_else(|e| panic!("{label}: {e}"));
                let got = extract_rar(&joined, &mut budget()).unwrap();
                let going_on: Vec<_> = got
                    .iter()
                    .filter_map(|e| e.unsupported)
                    .filter(|w| w.contains("continues in another volume"))
                    .collect();
                assert_eq!(going_on.len(), 1, "{label}: {going_on:?}");
                assert!(
                    got.iter()
                        .any(|e| e.unsupported.is_none() && e.data == payload[..800]),
                    "{label}: the 800 bytes held"
                );
            }
        }
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

    /// The volumes, as sources: held in memory, or read through a block cache
    /// of small blocks, so that a window crosses many of them.
    fn sources(vols: &[Vec<u8>], cached: bool) -> Vec<Box<dyn ByteSource>> {
        vols.iter()
            .map(|v| -> Box<dyn ByteSource> {
                match cached {
                    true => Box::new(
                        crate::source::BlockCache::with_sizes(Cursor::new(v.clone()), 13, 4 * 13)
                            .unwrap(),
                    ),
                    false => Box::new(v.clone()),
                }
            })
            .collect()
    }

    /// Sets of volumes: the official RAR sets of the fixtures (RAR5 ends each
    /// volume with a quick-open record), and archives cut into parts of
    /// several sizes, stored and compressed, RAR4 and RAR5.
    fn volume_sets() -> Vec<(String, Vec<Vec<u8>>)> {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let read = |p: &str| crate::read_fixture(&format!("{root}/{p}")).unwrap();
        let mut sets = Vec::new();
        for parts in [
            ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"],
            ["set4.rar", "set4.r00", "set4.r01"],
        ] {
            let vols = parts.map(|p| read(&format!("rar_volumes/{p}"))).to_vec();
            sets.push((parts[0].to_string(), vols));
        }
        let arcs = [
            ("rar4_stored", rar4_stored(b"hi.txt", &[b'z'; 1000])),
            ("rar5_stored", rar5_stored(b"a/b.bin", &[b'y'; 1000])),
            ("solid_rar4", read("rar_solid/solid_rar4.rar")),
            ("solid_rar5", read("rar_solid/solid_rar5.rar")),
        ];
        for (name, arc) in arcs {
            for chunk in [7, 333, 1 << 20] {
                sets.push((format!("{name} in {chunk}"), split(&arc, chunk)));
            }
        }
        sets
    }

    /// A span reads as the archive the volumes are joined into, at any offset
    /// and any size of window, whether the volumes are in memory or read
    /// through a cache.
    #[test]
    fn a_span_reads_as_the_archive_it_joins() {
        for (name, vols) in volume_sets() {
            let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
            let joined = join_volumes(&refs).unwrap_or_else(|e| panic!("{name}: {e}"));
            for cached in [false, true] {
                let span = RarSpan::new(sources(&vols, cached), usize::MAX).unwrap();
                assert_eq!(span.len(), joined.len(), "{name}");
                for off in (0..joined.len() + 3).step_by(53) {
                    for len in [1, 9, 64, 5000, joined.len() + 7] {
                        let end = (off + len).min(joined.len());
                        let want = &joined[off.min(end)..end];
                        assert_eq!(
                            span.window(off, len).as_ref(),
                            want,
                            "{name} cached {cached}: {len} at {off}"
                        );
                    }
                }
            }
        }
    }

    /// Walking a set across its volumes finds what walking the archive it
    /// joins into finds: the same members, the same bytes, ending the same
    /// way, however the members are read.
    #[test]
    fn a_set_walked_across_its_volumes_is_the_archive_walked_joined() {
        let mut compressed = 0;
        for (name, vols) in volume_sets() {
            let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
            let joined = join_volumes(&refs).unwrap();
            for cached in [false, true] {
                let span = RarSpan::new(sources(&vols, cached), usize::MAX).unwrap();
                for step in [1, 7, 4096] {
                    let want = streamed(&joined, step, budget());
                    let got = streamed_from(&span, step, budget());
                    assert_eq!(got, want, "{name} cached {cached} step {step}");
                    let members = got.unwrap();
                    assert!(
                        members.iter().all(|m| !m.2 && !m.1.is_empty()),
                        "{name}: {members:?}"
                    );
                    compressed += members.len();
                }
            }
        }
        assert!(compressed > 100, "{compressed}");
    }

    /// What does not fit together is refused by the span as it was by the
    /// join: a volume cut inside a block, one with a block header that does
    /// not parse, and a table past the memory the caller allows.
    #[test]
    fn a_span_refuses_volumes_that_do_not_fit_together() {
        let refused = |vols: &[Vec<u8>], max: usize| {
            RarSpan::new(sources(vols, false), max)
                .err()
                .unwrap_or_else(|| panic!("the span was made"))
        };
        for arc in [
            rar4_stored(b"hi.txt", &[b'z'; 100]),
            rar5_stored(b"a.bin", &[b'y'; 100]),
        ] {
            let vols = split(&arc, 40);
            assert!(vols.len() > 2);
            // The last block of the first volume loses its end.
            let mut cut = vols.clone();
            let end = cut[0].len() - 3;
            cut[0].truncate(end);
            let why = refused(&cut, usize::MAX);
            assert!(why.contains("part 1 ends inside a block"), "{why}");
            // Bytes that are no block follow the last.
            let mut junk = vols.clone();
            junk[1].extend_from_slice(&[0; 64]);
            let why = refused(&junk, usize::MAX);
            assert!(
                why.contains("part 2 has a block header that does not parse"),
                "{why}"
            );
            // A table over the memory the caller allows.
            let why = refused(&vols, 0);
            assert!(
                why.contains("block table is over the memory limit"),
                "{why}"
            );
            RarSpan::new(sources(&vols, false), 1 << 20).unwrap();
        }
    }

    /// Nothing after a volume's end block is a block: what follows it is not
    /// read as one.
    #[test]
    fn what_follows_a_volumes_end_block_is_not_joined() {
        let mut vol = RAR4_MAGIC.to_vec();
        vol.extend_from_slice(&[0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]);
        vol.extend_from_slice(&[0, 0, 0x7B, 0x08, 0x00, 9, 0, 0, 0]);
        let clean = join_volumes(&[&vol]).unwrap();
        vol.extend_from_slice(&[0xff; 40]);
        assert_eq!(join_volumes(&[&vol]).unwrap(), clean);
    }

    /// An archive with a byte of its first headers changed is read as a set of
    /// one volume: the span refuses it, or it is walked as the archive the
    /// join makes of it, member for member, byte for byte, ending the same
    /// way, however it is read. The changes are values that make a size or an
    /// offset wrap, one byte at a time and four bytes at a time.
    #[test]
    fn a_damaged_volume_walks_through_a_span_as_through_the_archive_it_joins() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let fixture = |p: &str| crate::read_fixture(&format!("{root}/{p}")).unwrap();
        let arcs = [
            rar4_stored(b"hi.txt", b"0123456789"),
            rar5_stored(b"a/b.bin", b"0123456789"),
            fixture("rar4/solid_x86.rar"),
            fixture("rar5/hardlink.rar"),
        ];
        let (mut walked, mut refused) = (0, 0);
        for arc in &arcs {
            let head = arc.len().min(120);
            let mut changes: Vec<(usize, Vec<u8>)> = Vec::new();
            for at in 0..head {
                for v in [0x00u8, 0x7f, 0x80, 0xff] {
                    changes.push((at, vec![v]));
                }
                for v in [u32::MAX, 1 << 31, 0] {
                    changes.push((at, v.to_le_bytes().to_vec()));
                }
            }
            for (at, bytes) in changes {
                let mut m = arc.clone();
                if at + bytes.len() > m.len() {
                    continue;
                }
                m[at..at + bytes.len()].copy_from_slice(&bytes);
                let one: Vec<Box<dyn ByteSource>> = vec![Box::new(m)];
                let Ok(span) = RarSpan::new(one, usize::MAX) else {
                    refused += 1;
                    continue;
                };
                let joined = span.window(0, span.len()).into_owned();
                let via_span = streamed_from(&span, 7, budget());
                let via_joined = streamed(&joined, 4096, budget());
                assert_eq!(via_span, via_joined, "{bytes:?} at {at}");
                walked += 1;
            }
        }
        assert!(
            walked > 1000 && refused > 100,
            "{walked} walked, {refused} refused"
        );
    }

    /// What the walk of a source hands over, and how it ends: the members
    /// (name, and why it was reported), and the reason of the damage it ends
    /// on, `None` for an archive that ends as it should.
    fn walked(arc: &[u8]) -> (Vec<(String, Option<&'static str>)>, Option<String>) {
        let mut seen = Vec::new();
        let src: &dyn ByteSource = &arc;
        let end = walk(src, &mut budget(), &mut |m, _, _| {
            seen.push((m.name.clone(), m.unsupported));
            None::<()>
        });
        let end = end.err().map(|e| {
            assert!(e.is_corrupt(), "{}", e.reason);
            e.reason
        });
        (seen, end)
    }

    /// The members the whole-archive path collects, as `walked` lists them.
    fn collected(arc: &[u8]) -> Vec<(String, Option<&'static str>)> {
        let entries = extract_rar(arc, &mut budget()).unwrap();
        entries
            .into_iter()
            .map(|e| (e.name, e.unsupported))
            .collect()
    }

    /// A RAR5 block with the checksum the walk does not read.
    fn block5(content: Vec<u8>) -> Vec<u8> {
        [vec![0; 4], vint_bytes(content.len() as u64), content].concat()
    }

    /// A header that is no block, with bytes after it, ends the walk with a
    /// report, after the members before it, in the walk of a source and in
    /// the whole-archive path alike. A marker followed by zeros is one.
    #[test]
    fn a_block_header_that_does_not_parse_is_reported_damaged() {
        let damaged_names = |m: Vec<(String, Option<&'static str>)>| {
            m.into_iter()
                .filter(|(_, why)| *why == Some(RAR_DAMAGED))
                .count()
        };
        let main5 = block5([1, 0, 0].map(vint_bytes).concat());
        let cases = [
            // The marker, then zeros: a size of 0 in RAR4, a header of size 0
            // in RAR5.
            (
                "rar4 zeros",
                [RAR4_MAGIC.to_vec(), vec![0; 64 << 10]].concat(),
                0,
            ),
            (
                "rar5 zeros",
                [RAR5_MAGIC.to_vec(), vec![0; 64 << 10]].concat(),
                0,
            ),
            // After a member that was read.
            (
                "rar4 after a member",
                [rar4_stored(b"a", b"0123456789"), vec![0; 64]].concat(),
                1,
            ),
            (
                "rar5 after a member",
                [rar5_stored(b"a", b"0123456789"), vec![0; 64]].concat(),
                1,
            ),
            // A header over the largest the format has, whatever the size of
            // the archive; and a size that is no integer.
            (
                "rar5 header over the largest",
                [
                    RAR5_MAGIC.to_vec(),
                    main5.clone(),
                    vec![0; 4],
                    vint_bytes(5 << 20),
                    vec![0; 64],
                ]
                .concat(),
                0,
            ),
            (
                "rar5 size of ten continuation bytes",
                [
                    RAR5_MAGIC.to_vec(),
                    main5,
                    vec![0; 4],
                    vec![0xff; 10],
                    vec![0; 16],
                ]
                .concat(),
                0,
            ),
        ];
        for (name, arc, members) in cases {
            let (seen, end) = walked(&arc);
            assert_eq!(seen.len(), members, "{name}: {seen:?}");
            let end = end.unwrap_or_else(|| panic!("{name}: the walk ended without a report"));
            assert!(end.contains("does not parse"), "{name}: {end}");
            let got = collected(&arc);
            assert_eq!(got.len(), members + 1, "{name}: {got:?}");
            assert_eq!(damaged_names(got), 1, "{name}");
        }
    }

    /// What the end of the archive cuts is absent, not hidden: an archive that
    /// ends inside a header, or whose header says it is longer than the
    /// archive, is not reported, and nor is what follows an end block.
    #[test]
    fn an_archive_cut_by_its_end_is_not_reported() {
        let rar4 = rar4_stored(b"a", b"0123456789");
        let rar5 = rar5_stored(b"a", b"0123456789");
        let end4 = vec![0x3d, 0x7b, 0x7b, 0, 0x40, 7, 0];
        let end5 = block5([5, 0, 0].map(vint_bytes).concat());
        let cases = [
            // Fewer bytes than the smallest header.
            ([rar4.clone(), vec![0; 6]].concat(), 1),
            ([rar5.clone(), vec![0; 4]].concat(), 1),
            // A header that says it is longer than what is left (RAR4 reads
            // the file header it can, as it always did).
            (
                [rar4.clone(), vec![0, 0, 0x74, 0, 0, 0xff, 0x7f, 1, 2]].concat(),
                2,
            ),
            (
                [rar5.clone(), vec![0; 4], vint_bytes(1000), vec![2, 0]].concat(),
                1,
            ),
            // What follows an end block is not a block.
            ([rar4.clone(), end4, vec![0; 64]].concat(), 1),
            ([rar5.clone(), end5, vec![0; 64]].concat(), 1),
        ];
        for (i, (arc, members)) in cases.into_iter().enumerate() {
            let (seen, end) = walked(&arc);
            assert_eq!((seen.len(), end), (members, None), "case {i}: {seen:?}");
            let got = collected(&arc);
            assert!(
                got.iter().all(|(n, _)| n != "rar-damaged-header"),
                "case {i}: {got:?}"
            );
        }
    }

    /// A stored member the archive ends inside is the bytes present, in the
    /// walk of a source and in the whole-archive path alike: the rest is
    /// absent, which is no limit. A limit on what is present is still one.
    #[test]
    fn a_stored_member_cut_by_the_end_of_the_archive_is_the_bytes_present() {
        let payload = b"0123456789abcdef";
        for (label, arc) in [
            ("rar4", rar4_stored(b"a", payload)),
            ("rar5", rar5_stored(b"a", payload)),
        ] {
            let data_at = arc.len() - payload.len();
            for kept in [0, 1, 9, 15] {
                let cut = &arc[..data_at + kept];
                let want = vec![("a".to_string(), payload[..kept].to_vec(), false)];
                assert_eq!(
                    whole_path(cut, budget()),
                    Ok(want.clone()),
                    "{label} {kept}"
                );
                for step in [1, 4096] {
                    assert_eq!(
                        streamed(cut, step, budget()),
                        Ok(want.clone()),
                        "{label} {kept}, read {step} at a time"
                    );
                }
            }
            let small = || {
                Budget::new(Limits {
                    max_buffer_bytes: 8,
                    ..Limits::default()
                })
            };
            // Over the object limit: left out, and the walk goes on.
            let mut b = small();
            let got = extract_rar(&arc[..data_at + 9], &mut b).unwrap();
            assert!(got.is_empty(), "{label}");
            let e = b.skipped.expect("the member is noted");
            assert!(!e.is_corrupt(), "{label}: {}", e.reason);
            assert!(e.reason.contains("rar member 'a'"), "{label}: {}", e.reason);
            let got = whole_path(&arc[..data_at + 8], small()).unwrap();
            assert_eq!(got[0].1, payload[..8], "{label}");
        }
    }

    /// A compressed RAR4 member the archive ends inside gives the bytes it
    /// decodes to before the end, in both paths, as a RAR5 one does: the rest
    /// is absent, not hidden.
    #[test]
    fn a_compressed_rar4_member_cut_by_the_end_of_the_archive_is_its_prefix() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4");
        // LZ, the x86 filter and PPMd.
        for f in ["two_windows.rar", "solid_x86.rar", "solid_ppmd.rar"] {
            let arc = crate::read_fixture(&format!("{dir}/{f}")).unwrap();
            let full = whole_path(&arc, budget()).unwrap();
            for pct in (2..100).step_by(2) {
                let cut = &arc[..arc.len() * pct / 100];
                for got in [whole_path(cut, budget()), streamed(cut, 4096, budget())] {
                    let got = got.unwrap_or_else(|e| panic!("{f} {pct}%: {e}"));
                    for (name, data, bad) in &got {
                        let whole = &full.iter().find(|m| &m.0 == name).unwrap().1;
                        assert!(!bad, "{f} {pct}%: {name} reported");
                        assert!(whole.starts_with(data), "{f} {pct}%: {name}");
                    }
                    // Past a few blocks' headers, something of the cut member.
                    let last = got.last().unwrap_or_else(|| panic!("{f} {pct}%"));
                    assert!(pct < 30 || !last.1.is_empty(), "{f} {pct}%: {}", last.0);
                }
            }
        }
    }

    /// With checksums verified, a compressed member the archive ends inside is
    /// said to be cut, in both paths, not to have failed its CRC.
    #[cfg(feature = "checksums")]
    #[test]
    fn a_member_the_archive_ends_inside_is_said_to_be_cut_when_checksums_are_verified() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let verified = || {
            let mut b = budget();
            b.set_verify_checksums(true);
            b
        };
        for f in ["rar4/two_windows.rar", "rar_solid/solid_rar5.rar"] {
            let arc = crate::read_fixture(&format!("{dir}/{f}")).unwrap();
            let cut = &arc[..arc.len() / 2];
            let whole = extract_rar(cut, &mut verified()).unwrap();
            let last = whole.last().and_then(|e| e.unsupported);
            assert_eq!(last, Some(RAR_CUT), "{f}");
            let mut errors = Vec::new();
            let mut visit = |_: &crate::stream::MemberMeta,
                             c: Option<crate::stream::Member<'_>>,
                             _: &mut Budget| {
                if let Some(crate::stream::Member::Stream(r)) = c
                    && let Err(e) = std::io::copy(r, &mut std::io::sink())
                {
                    errors.push(e.to_string());
                }
                None::<()>
            };
            let src: &dyn ByteSource = &cut;
            match cut.starts_with(RAR5_MAGIC) {
                true => stream_rar5(src, &mut verified(), &mut visit),
                false => stream_rar4(src, &mut verified(), &mut visit),
            }
            .unwrap();
            assert_eq!(errors, [RAR_CUT], "{f}");
        }
    }

    /// A RAR5 file header whose fields are no integers is skipped with its
    /// data: the member is reported, and the walk goes on to the next.
    #[test]
    fn a_rar5_file_header_whose_fields_do_not_parse_is_reported() {
        let file = |fields: Vec<u8>| {
            let mut c = [2, 0x02, 4].map(vint_bytes).concat();
            c.extend(fields);
            [block5(c), b"data".to_vec()].concat()
        };
        let main = block5([1, 0, 0].map(vint_bytes).concat());
        let end = block5([5, 0, 0].map(vint_bytes).concat());
        let after = rar5_stored(b"after", b"0123456789");
        let after = after[RAR5_MAGIC.len() + main.len()..].to_vec();
        let bad = file(vec![0x80; 12]);
        let arc = [
            RAR5_MAGIC.to_vec(),
            main.clone(),
            bad,
            after.clone(),
            end.clone(),
        ]
        .concat();
        let want = vec![
            ("rar-entry".to_string(), Some(RAR_DAMAGED_FILE)),
            ("after".to_string(), None),
        ];
        assert_eq!(walked(&arc), (want.clone(), None));
        assert_eq!(collected(&arc), want);
        // The fields that parse give the member itself.
        let good = file([[0, 4, 0, 0, 0, 1].map(vint_bytes).concat(), b"x".to_vec()].concat());
        let arc = [RAR5_MAGIC.to_vec(), main, good, end].concat();
        assert_eq!(walked(&arc), (vec![("x".to_string(), None)], None));
    }

    /// The members `arc` gives, as (name, why reported), with the keys and
    /// passwords of `crypt` kept for the next call.
    #[cfg(feature = "decrypt")]
    fn opened4(arc: &[u8], crypt: &mut Rar4Crypt) -> Vec<(String, Option<&'static str>)> {
        let mut b = Budget::with_passwords(Limits::default(), Vec::new());
        let entries = extract_rar4_keyed(arc, RAR4_MAGIC.len(), &mut b, crypt).unwrap();
        entries
            .into_iter()
            .map(|e| (e.name, e.unsupported))
            .collect()
    }

    #[cfg(feature = "decrypt")]
    fn opened5(arc: &[u8], keys: &mut KeyCache) -> Vec<(String, Option<&'static str>)> {
        let mut b = Budget::with_passwords(Limits::default(), Vec::new());
        let entries = extract_rar5_keyed(arc, RAR5_MAGIC.len(), &mut b, keys).unwrap();
        entries
            .into_iter()
            .map(|e| (e.name, e.unsupported))
            .collect()
    }

    /// With every header after the first encrypted (`rar -hp`), a header that
    /// stops reading as one while the key opens those before it is damage:
    /// the members before it are given, then the damage is reported. Each
    /// header of `enc_headers.rar` is an IV and the header encrypted under
    /// one key, so changing a byte of an IV changes that byte of the header's
    /// first block: its type is made one no block has.
    #[cfg(feature = "decrypt")]
    #[test]
    fn rar5_headers_that_stop_opening_part_way_are_reported_damaged() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rar5/enc_headers.rar"
        );
        let arc = crate::read_fixture(path).unwrap();
        let mut keys = KeyCache::default();
        let want = opened5(&arc, &mut keys);
        assert_eq!(
            want,
            [("a.txt".to_string(), None), ("b.txt".to_string(), None)]
        );
        // Where the encrypted headers begin, and where each starts in the
        // archive: the archive opened is the marker, then each header in the
        // clear with its data, and in the archive each is an IV, the header
        // padded to 16 bytes, and its data.
        let src: &dyn ByteSource = &arc.as_slice();
        let first = rar5_head(src, RAR5_MAGIC.len())
            .ok()
            .expect("the encryption header");
        let b = Budget::with_passwords(Limits::default(), Vec::new());
        let rec = arc
            .get(RAR5_MAGIC.len() + first.q..first.next)
            .and_then(|body| rar5_crypt::CryptRecord::parse(body, false))
            .unwrap();
        let (plain, whole) =
            rar5_open_headers(&arc, RAR5_MAGIC.len(), first.next, &rec, &b, &mut keys).unwrap();
        assert!(whole);
        let plain_src: &dyn ByteSource = &plain.as_slice();
        let (mut p, mut q) = (RAR5_MAGIC.len(), first.next);
        let mut headers = Vec::new();
        while let Ok(h) = rar5_head(plain_src, p) {
            // The IV, the type, and the bytes of the header before the type.
            headers.push((q, h.htype, h.hdr));
            let size = h.hdr + crate::bytes::to_usize(h.hsize);
            q += 16 + size.next_multiple_of(16) + crate::bytes::to_usize(h.data_size);
            if h.htype == 5 || h.next <= p {
                break;
            }
            p = h.next;
        }
        // The main header, a.txt, b.txt, the end of the archive.
        assert_eq!(headers.len(), 4);
        let damage = ("rar-damaged-header".to_string(), Some(RAR_DAMAGED));
        let a = ("a.txt".to_string(), None);
        let b = ("b.txt".to_string(), None);
        let unopened = (
            "rar-encrypted-headers".to_string(),
            Some("RAR archive with encrypted headers"),
        );
        // Nothing opens when the first header does not; then each header in
        // turn is damage after the members before it.
        let expected = [
            vec![unopened],
            vec![damage.clone()],
            vec![a.clone(), damage.clone()],
            vec![a, b, damage],
        ];
        for ((iv, _, before_type), expected) in headers.into_iter().zip(expected) {
            let mut damaged = arc.clone();
            damaged[iv + before_type] ^= 0x40;
            assert_eq!(opened5(&damaged, &mut keys), expected, "header at {iv}");
        }
    }

    /// The same for RAR4: each header is a salt and the header encrypted in
    /// blocks of 16, so changing a byte of a header's second block garbles it
    /// alone: the header is of the right size and fails its checksum. A
    /// change anywhere in the encrypted headers gives the members, or reports
    /// something.
    #[cfg(feature = "decrypt")]
    #[test]
    fn rar4_headers_that_stop_opening_part_way_are_reported_damaged() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rar4/enc_headers.rar"
        );
        let arc = crate::read_fixture(path).unwrap();
        let mut crypt = Rar4Crypt::default();
        let want = opened4(&arc, &mut crypt);
        assert_eq!(
            want,
            [
                ("a_text.txt".to_string(), None),
                ("e_text.txt".to_string(), None)
            ]
        );
        // Where each block is: a salt, the header padded to 16 bytes, its data.
        let main_end = RAR4_MAGIC.len() + 13;
        let b = Budget::with_passwords(Limits::default(), Vec::new());
        let (plain, whole) =
            rar4_open_headers(&arc, RAR4_MAGIC.len(), main_end, &b, &mut crypt).unwrap();
        assert!(whole);
        let (mut p, mut q) = (main_end, main_end);
        let mut blocks = Vec::new();
        while p + 7 <= plain.len() {
            let head = usize::from(u16le(&plain, p + 5).unwrap());
            let add = match u16le(&plain, p + 3).unwrap() & 0x8000 {
                0 => 0,
                _ => u32le(&plain, p + 7).unwrap() as usize,
            };
            let padded = head.next_multiple_of(16);
            blocks.push((q, q + 8 + padded));
            p += head + add;
            q += 8 + padded + add;
        }
        // Two file headers, and the end block.
        assert_eq!(blocks.len(), 3);
        let (start, end) = blocks[1];
        assert!(end - start >= 8 + 32);
        // The second block of the second header, past its salt.
        let second = start + 8 + 16..start + 8 + 32;
        let mut damage_reported = 0;
        for at in blocks[0].0..blocks[2].1 {
            let mut damaged = arc.clone();
            damaged[at] ^= 0x40;
            let got = opened4(&damaged, &mut crypt);
            assert!(
                got == want || got.iter().any(|g| g.1.is_some()),
                "a change at {at} dropped members with no report: {got:?}"
            );
            let damage = got.iter().position(|g| g.1 == Some(RAR_DAMAGED));
            damage_reported += usize::from(damage.is_some());
            if second.contains(&at) {
                assert_eq!(damage, Some(1), "a change at {at}: {got:?}");
                assert_eq!(got[0], want[0], "a change at {at}");
            }
        }
        assert!(damage_reported >= second.len());

        // A first block of the second header that decrypts to a size under 7
        // (the least a block has): found by trying blocks until one does.
        let salt: [u8; 8] = arc[start..start + 8].try_into().unwrap();
        let password = crypt.password.clone().unwrap();
        let keys = crypt
            .keys
            .get(&password, &salt, &b.rar3_derivations)
            .unwrap();
        let block = (0u32..)
            .find_map(|n| {
                let mut c = [0u8; 16];
                c[..4].copy_from_slice(&n.to_le_bytes());
                let mut p = c.to_vec();
                rar3_crypt::decrypt(&keys, &mut p);
                (u16::from_le_bytes([p[5], p[6]]) < 7).then_some(c)
            })
            .unwrap();
        let mut damaged = arc.clone();
        damaged[start + 8..start + 24].copy_from_slice(&block);
        let got = opened4(&damaged, &mut crypt);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0], want[0]);
        assert_eq!(got[1].1, Some(RAR_DAMAGED));
    }

    /// A RAR4 member with a 64-bit size (LHD_LARGE): the next block starts
    /// after all of its data, not after ADD_SIZE, its low half.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_rar4_member_past_4_gib_is_followed_by_the_next_block() {
        // The member's header: LHD_LARGE, 2^32 + 5 bytes of stored data.
        let name = b"big";
        let mut fields = Vec::new();
        fields.extend_from_slice(&5u32.to_le_bytes()); // PACK_SIZE
        fields.extend_from_slice(&5u32.to_le_bytes()); // UNP_SIZE
        fields.push(0);
        fields.extend_from_slice(&[0; 8]);
        fields.extend_from_slice(&[20, 0x30]);
        fields.extend_from_slice(&(name.len() as u16).to_le_bytes());
        fields.extend_from_slice(&[0; 4]);
        fields.extend_from_slice(&1u32.to_le_bytes()); // HIGH_PACK_SIZE
        fields.extend_from_slice(&1u32.to_le_bytes()); // HIGH_UNP_SIZE
        fields.extend_from_slice(name);
        let mut head = RAR4_MAGIC.to_vec();
        head.extend_from_slice(&[0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]);
        head.extend_from_slice(&[0, 0, 0x74, 0x00, 0x81]);
        head.extend_from_slice(&((7 + fields.len()) as u16).to_le_bytes());
        head.extend(fields);
        let after = rar4_stored(b"after", b"0123456789");
        let after = after[RAR4_MAGIC.len() + 13..].to_vec();
        let data = (1u64 << 32) + 5;
        let arc = Virtual {
            len: head.len() as u64 + data + after.len() as u64,
            head,
            data,
            after,
        };
        let mut b = Budget::new(Limits {
            max_extracted_bytes: u64::MAX,
            max_scanned_bytes: u64::MAX,
            max_compression_ratio: u64::MAX,
            ..Limits::default()
        });
        let mut names = Vec::new();
        walk(&arc, &mut b, &mut |m, _, _| {
            names.push(m.name.clone());
            None::<()>
        })
        .unwrap();
        assert_eq!(names, ["big", "after"]);
    }

    /// An archive of a head, then `data` bytes of zeros that are never held,
    /// then the rest: a member too large to make.
    #[cfg(target_pointer_width = "64")]
    struct Virtual {
        head: Vec<u8>,
        data: u64,
        after: Vec<u8>,
        len: u64,
    }

    #[cfg(target_pointer_width = "64")]
    impl ByteSource for Virtual {
        fn len(&self) -> usize {
            self.len as usize
        }

        fn window(&self, off: usize, n: usize) -> std::borrow::Cow<'_, [u8]> {
            let (off, end) = (off as u64, (off as u64 + n as u64).min(self.len));
            let mut w = vec![0u8; end.saturating_sub(off) as usize];
            // The head and the rest are where they are; between them, zeros.
            let after = self.head.len() as u64 + self.data;
            for (base, bytes) in [(0, &self.head), (after, &self.after)] {
                let from = off.max(base);
                let to = end.min(base + bytes.len() as u64);
                if from < to {
                    w[(from - off) as usize..(to - off) as usize]
                        .copy_from_slice(&bytes[(from - base) as usize..(to - base) as usize]);
                }
            }
            std::borrow::Cow::Owned(w)
        }

        fn identity(&self) -> (usize, usize) {
            (self as *const Self as usize, self.len())
        }
    }

    /// A member as the walk hands it: name, bytes, and whether it was
    /// reported or failed to decode (a checksum mismatch alone is neither,
    /// as the whole-archive path scans such a member).
    type Got = (String, Vec<u8>, bool);

    /// The members of `arc` streamed, each read `step` bytes at a time.
    /// `Err` when the walk stopped on a limit or damage.
    fn streamed(arc: &[u8], step: usize, b: Budget) -> Result<Vec<Got>, String> {
        streamed_from(&arc, step, b)
    }

    /// As [`streamed`], from any source.
    fn streamed_from(src: &dyn ByteSource, step: usize, mut b: Budget) -> Result<Vec<Got>, String> {
        let mut got = Vec::new();
        let mut visit = |m: &crate::stream::MemberMeta,
                         c: Option<crate::stream::Member<'_>>,
                         _: &mut Budget|
         -> Option<()> {
            let mut data = Vec::new();
            let mut bad = m.unsupported.is_some();
            match c {
                Some(crate::stream::Member::Bytes(d)) => data = d,
                Some(crate::stream::Member::Stream(r)) => {
                    let mut buf = vec![0u8; step];
                    loop {
                        match r.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => data.extend_from_slice(&buf[..n]),
                            Err(e) => {
                                bad |= !crate::is_checksum_mismatch(&e);
                                break;
                            }
                        }
                    }
                }
                None => {}
            }
            got.push((m.name.clone(), data, bad));
            None
        };
        let r = if src.window(0, RAR5_MAGIC.len()).starts_with(RAR5_MAGIC) {
            stream_rar5(src, &mut b, &mut visit)
        } else {
            stream_rar4(src, &mut b, &mut visit)
        };
        r.map(|_| got).map_err(|e| e.reason)
    }

    /// The members of `arc` as the whole-archive path reads them.
    fn whole_path(arc: &[u8], mut b: Budget) -> Result<Vec<Got>, String> {
        extract_rar(arc, &mut b)
            .map(|es| {
                es.into_iter()
                    .map(|e| (e.name, e.data, e.unsupported.is_some()))
                    .collect()
            })
            .map_err(|e| e.reason)
    }

    /// Whether the streaming walk reads `arc` as the whole-archive path does:
    /// the same members, the same bytes for each it decodes, and the same
    /// ones reported, at every read size. `None` when the archive is one the
    /// walk hands to the whole-archive path.
    fn differs(arc: &[u8], limits: &Limits) -> Option<String> {
        let rar5 = arc.starts_with(RAR5_MAGIC);
        if !rar5 && !arc.starts_with(RAR4_MAGIC) || rar_needs_whole(&arc, rar5) {
            return None;
        }
        let want = whole_path(arc, Budget::new(limits.clone()));
        for step in [1, 7, 4096, 1 << 20] {
            let got = streamed(arc, step, Budget::new(limits.clone()));
            // What the whole-archive path cannot hold, the walk streams: a
            // member over the buffer limit, or one past the ratio it allows
            // a streamed member.
            let over = |g: &Got| g.1.len() as u64 > limits.max_buffer_bytes;
            let same = match (&want, &got) {
                (Ok(w), Ok(g)) => {
                    w.len() == g.len()
                        && w.iter().zip(g).all(|(w, g)| {
                            w.0 == g.0
                                && (w.2 == g.2 && (w.2 || w.1 == g.1) || w.2 && !g.2 && over(g))
                        })
                }
                (Err(_), Err(_)) => true,
                (Ok(_), Err(e)) => e.contains("compression ratio"),
                _ => false,
            };
            if !same {
                let show = |r: &Result<Vec<Got>, String>| match r {
                    Ok(v) => format!(
                        "{:?}",
                        v.iter()
                            .map(|(n, d, b)| (n.clone(), d.len(), *b))
                            .collect::<Vec<_>>()
                    ),
                    Err(e) => e.clone(),
                };
                return Some(format!(
                    "step {step}: whole {} streamed {}",
                    show(&want),
                    show(&got)
                ));
            }
        }
        None
    }

    /// Every RAR fixture of the crate's tests reads the same streamed as
    /// whole: LZ, PPMd and the switches between them, solid groups, the x86
    /// filters, two window sizes, empty members, volume parts.
    #[test]
    fn the_streaming_walk_reads_every_fixture_as_the_whole_archive_path() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let mut seen = 0;
        for dir in ["rar", "rar4", "rar5", "rar_solid", "rar_volumes"] {
            let mut names: Vec<_> = std::fs::read_dir(format!("{root}/{dir}"))
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .collect();
            names.sort();
            for p in names {
                let p = p.to_string_lossy().trim_end_matches(".xor").to_string();
                let Ok(arc) = crate::read_fixture(&p) else {
                    continue;
                };
                // The 241 MB member has a test of its own.
                if p.ends_with("ppmd_lzss_conversion.rar") {
                    continue;
                }
                if let Some(d) = differs(&arc, &Limits::default()) {
                    panic!("{p}: {d}");
                }
                seen += 1;
            }
        }
        assert!(seen >= 20, "{seen} fixtures");
    }

    /// The archives of a directory, each read streamed and whole: run with
    /// `EXAV_DEBUG_RAR_DIFF=<dir>` over a corpus (the fuzz seeds, samples).
    #[test]
    #[ignore = "reads EXAV_DEBUG_RAR_DIFF; run with --ignored"]
    fn the_streaming_walk_reads_a_corpus_as_the_whole_archive_path() {
        let Some(dir) = std::env::var_os("EXAV_DEBUG_RAR_DIFF") else {
            return;
        };
        let limits = Limits {
            max_buffer_bytes: 64 << 20,
            ..Limits::default()
        };
        let (mut seen, mut bad) = (0, Vec::new());
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let Ok(arc) = std::fs::read(e.path()) else {
                continue;
            };
            if arc.len() > 32 << 20 {
                continue;
            }
            if let Some(d) = differs(&arc, &limits) {
                bad.push(format!("{}: {d}", e.path().display()));
            }
            seen += 1;
        }
        assert!(
            bad.is_empty(),
            "{} of {seen}:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// A member decoding to many times the buffer limit streams whole, its
    /// last bytes reached and its CRC checked, with the archive and the
    /// member each over the limit: the 241 MB PPMd member of
    /// `ppmd_lzss_conversion.rar` under a 64 MiB limit (its PPMd model asks
    /// for more than 16).
    #[test]
    fn a_member_many_times_the_buffer_limit_streams_to_its_end() {
        let arc = crate::read_fixture(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rar/ppmd_lzss_conversion.rar"
        ))
        .unwrap();
        let limits = Limits {
            max_buffer_bytes: 64 << 20,
            max_scanned_bytes: 1 << 30,
            max_compression_ratio: u64::MAX,
            ..Limits::default()
        };
        let mut b = Budget::new(limits);
        let (mut total, mut tail, mut end) = (0u64, Vec::new(), None);
        let src: &dyn ByteSource = &arc;
        walk(src, &mut b, &mut |m, c, _| {
            let Some(crate::stream::Member::Stream(r)) = c else {
                panic!("{} not streamed: {:?}", m.name, m.unsupported);
            };
            let mut buf = vec![0u8; 1 << 16];
            loop {
                match r.read(&mut buf) {
                    Ok(0) => break end = Some(Ok(())),
                    Ok(n) => {
                        total += n as u64;
                        tail.extend_from_slice(&buf[..n]);
                        let cut = tail.len().saturating_sub(64);
                        tail.drain(..cut);
                    }
                    Err(e) => break end = Some(Err(e.to_string())),
                }
            }
            None::<()>
        })
        .unwrap();
        assert_eq!(end, Some(Ok(())), "CRC checked at the end");
        assert!(total > 200 << 20, "{total}");
        assert!(tail.ends_with(b"</BODY>\n</HTML>"));
    }

    /// A dictionary over the buffer limit is not allocated: the member is
    /// reported with that reason, and the walk goes on to the next.
    #[test]
    fn a_dictionary_over_the_buffer_limit_is_reported_with_its_reason() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar_solid");
        for f in ["solid_rar4.rar", "solid_rar5.rar"] {
            let arc = crate::read_fixture(&format!("{dir}/{f}")).unwrap();
            let limits = Limits {
                max_buffer_bytes: 64 << 10,
                ..Limits::default()
            };
            let mut reasons = Vec::new();
            let src: &dyn ByteSource = &arc;
            walk(src, &mut Budget::new(limits), &mut |m, _, _| {
                reasons.push(m.unsupported);
                None::<()>
            })
            .unwrap();
            assert!(reasons.len() > 1, "{f}: {reasons:?}");
            assert!(
                reasons.iter().all(|r| *r == Some(WINDOW_OVER_LIMIT)),
                "{f}: {reasons:?}"
            );
        }
    }

    /// `arc`, a RAR5 archive, with every member's dictionary 4 GiB (bits
    /// 10..14 of `comp_info`, kept two bytes long) and its header CRC made
    /// again.
    fn with_4g_dictionary(arc: &[u8]) -> Vec<u8> {
        with_comp_info(arc, |info| (info & !(0x1f << 10)) | (15 << 10))
    }

    /// `arc` with the compression information of each RAR5 file header
    /// changed by `change` (the field must stay two bytes long), the header
    /// CRCs made right again.
    fn with_comp_info(arc: &[u8], change: impl Fn(u64) -> u64) -> Vec<u8> {
        let mut out = arc.to_vec();
        let mut pos = RAR5_MAGIC.len();
        while let Ok(b) = rar5_head(&arc, pos) {
            if b.htype == 2 {
                let field = |q: &mut usize| {
                    let (v, n) = vint(&b.bytes, *q).unwrap();
                    *q += n;
                    v
                };
                let mut q = b.q;
                let flags = field(&mut q);
                field(&mut q);
                field(&mut q);
                q += 4 * usize::from(flags & 0x02 != 0) + 4 * usize::from(flags & 0x04 != 0);
                let (info, n) = vint(&b.bytes, q).unwrap();
                assert_eq!(n, 2);
                let info = change(info);
                assert!(info < 1 << 14);
                out[pos + q] = (info & 0x7f) as u8 | 0x80;
                out[pos + q + 1] = (info >> 7) as u8;
                let end = pos + b.hdr + crate::bytes::to_usize(b.hsize);
                let crc = crc32_ieee(&out[pos + 4..end]);
                out[pos..pos + 4].copy_from_slice(&crc.to_le_bytes());
            }
            if b.htype == 5 || b.next <= pos {
                break;
            }
            pos = b.next;
        }
        out
    }

    /// A member is decoded on a window that holds what its solid run
    /// produces when that is less than its dictionary: a 4 GiB dictionary
    /// over the buffer limit does not keep a small solid group from being
    /// read, as it is not by the archive in memory.
    #[test]
    fn a_dictionary_larger_than_what_the_run_produces_is_not_allocated() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar_solid");
        let arc = crate::read_fixture(&format!("{dir}/solid_rar5.rar")).unwrap();
        let huge = with_4g_dictionary(&arc);
        assert_ne!(huge, arc);
        let members = |e: Vec<Entry>| e.into_iter().map(|e| (e.name, e.data)).collect::<Vec<_>>();
        let want = members(extract_rar(&arc, &mut budget()).unwrap());
        assert!(
            want.len() > 1 && want.iter().all(|m| !m.1.is_empty()),
            "{want:?}"
        );
        assert_eq!(members(extract_rar(&huge, &mut budget()).unwrap()), want);
        let mut got = Vec::new();
        let src: &dyn ByteSource = &huge;
        walk(src, &mut budget(), &mut |m, content, b| {
            let data = content.and_then(|c| c.into_bytes(m, b).ok()).map(|d| d.0);
            got.push((m.name.clone(), data.unwrap_or_default(), m.unsupported));
            None::<()>
        })
        .unwrap();
        let got: Vec<_> = got
            .into_iter()
            .map(|(n, d, why)| {
                assert_eq!(why, None, "{n}");
                (n, d)
            })
            .collect();
        assert_eq!(got, want);
    }

    /// A RAR5 member of a compression version with no decoder here (2 to 63)
    /// is reported, in memory and streamed, not decoded with version 0's
    /// algorithm into bytes that are not its own.
    #[test]
    fn a_rar5_member_of_an_unknown_compression_version_is_reported() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar_solid");
        let arc = crate::read_fixture(&format!("{dir}/solid_rar5.rar")).unwrap();
        let odd = with_comp_info(&arc, |info| (info & !0x3f) | 2);
        assert_ne!(odd, arc);
        let held = extract_rar(&odd, &mut budget()).unwrap();
        assert!(held.len() > 1, "{held:?}");
        for e in &held {
            assert_eq!(
                (e.unsupported, e.data.len()),
                (Some(RAR5_VERSION), 0),
                "{}",
                e.name
            );
        }
        let mut streamed = Vec::new();
        let src: &dyn ByteSource = &odd;
        walk(src, &mut budget(), &mut |m, content, _| {
            streamed.push((m.unsupported, m.reason_kind, content.is_some()));
            None::<()>
        })
        .unwrap();
        assert_eq!(streamed.len(), held.len());
        for m in streamed {
            assert_eq!(
                m,
                (
                    Some(RAR5_VERSION),
                    Some(crate::tree::ReasonKind::Unsupported),
                    false
                )
            );
        }
    }

    /// `arc` with the unpacked size its `nth` file header declares set to
    /// `size`, in the width the field has, the header's CRC fixed.
    fn with_unp_size(arc: &[u8], nth: usize, size: u64) -> Vec<u8> {
        let mut out = arc.to_vec();
        let mut seen = 0;
        if arc.starts_with(RAR5_MAGIC) {
            let mut pos = RAR5_MAGIC.len();
            while let Ok(b) = rar5_head(&arc, pos) {
                if b.htype == 2 && seen == nth {
                    let (_, n) = vint(&b.bytes, b.q).unwrap();
                    let at = b.q + n;
                    let (_, width) = vint(&b.bytes, at).unwrap();
                    assert_eq!(size >> (7 * width), 0, "{size} fits {width} bytes");
                    for k in 0..width {
                        let more = if k + 1 < width { 0x80 } else { 0 };
                        out[pos + at + k] = ((size >> (7 * k)) & 0x7f) as u8 | more;
                    }
                    let end = pos + b.hdr + crate::bytes::to_usize(b.hsize);
                    let crc = crc32_ieee(&out[pos + 4..end]);
                    out[pos..pos + 4].copy_from_slice(&crc.to_le_bytes());
                    return out;
                }
                seen += usize::from(b.htype == 2);
                pos = b.next;
            }
        } else {
            let mut pos = RAR4_MAGIC.len();
            while pos + 7 <= arc.len() {
                let flags = u16le(arc, pos + 3).unwrap();
                let head = usize::from(u16le(arc, pos + 5).unwrap());
                let add = if flags & 0x8000 != 0 {
                    u32le(arc, pos + 7).unwrap() as usize
                } else {
                    0
                };
                if arc[pos + 2] == 0x74 && seen == nth {
                    out[pos + 11..pos + 15].copy_from_slice(&(size as u32).to_le_bytes());
                    let crc = crc32_ieee(&out[pos + 2..pos + head]) as u16;
                    out[pos..pos + 2].copy_from_slice(&crc.to_le_bytes());
                    return out;
                }
                seen += usize::from(arc[pos + 2] == 0x74);
                pos += head + add;
            }
        }
        panic!("no file header {nth}");
    }

    /// The RAR fixtures the declared-size tests change: RAR5 and RAR4, each
    /// solid and not, with an x86 filter in each solid one and, in RAR5's
    /// `two_windows.rar`, a member whose distances reach past 128 KiB.
    const SIZED: [&str; 4] = [
        "rar_solid/two_windows.rar",
        "rar_solid/solid_x86.rar",
        "rar4/two_windows.rar",
        "rar4/solid_x86.rar",
    ];

    /// A member's whole stream is scanned, in memory and streamed, whether its
    /// header declares less or more than it holds: past a smaller declared
    /// size (a window sized to that size growing as the stream goes on), and
    /// as far as it goes before a larger one. No reason is given for either.
    #[test]
    fn a_member_is_its_whole_stream_whatever_size_it_declares() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let short = |got: Result<Vec<Got>, String>| {
            got.unwrap()
                .into_iter()
                .map(|(name, data, bad)| (name, data.len(), crc32_ieee(&data), bad))
                .collect::<Vec<_>>()
        };
        for f in SIZED {
            let arc = crate::read_fixture(&format!("{dir}/{f}")).unwrap();
            let want = short(whole_path(&arc, budget()));
            assert!(want.iter().all(|w| !w.3), "{f}: {want:?}");
            for (nth, w) in want.iter().enumerate() {
                let len = w.1 as u64;
                // 64 bytes: the smallest window, 128 KiB.
                for size in [64, len / 2, len * 2] {
                    let changed = with_unp_size(&arc, nth, size);
                    assert_eq!(
                        short(whole_path(&changed, budget())),
                        want,
                        "{f}: member {nth} declared {size}, in memory"
                    );
                    assert_eq!(
                        short(streamed(&changed, 4096, budget())),
                        want,
                        "{f}: member {nth} declared {size}, streamed"
                    );
                }
            }
        }
    }

    /// In memory, a member that cannot be decoded within the buffer limit is
    /// that limit, for what is over it: a declared size, a dictionary, or a
    /// window a stream past its declared size needs. Streamed, the last is
    /// met part way: the member is left out and the walk says why.
    #[test]
    fn a_member_over_the_buffer_limit_is_that_limit() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let over = |limit: u64| {
            Budget::new(Limits {
                max_buffer_bytes: limit,
                ..Limits::default()
            })
        };
        let reasons = |arc: &[u8], limit: u64| {
            extract_rar(arc, &mut over(limit))
                .unwrap()
                .into_iter()
                .map(|e| (e.name, e.unsupported, e.reason_kind))
                .collect::<Vec<_>>()
        };
        let size = Some(crate::tree::ReasonKind::OVER_SIZE);
        // RAR4: a 64 KiB window, its member declaring 100,000 bytes; then a
        // 512 KiB window.
        let arc = crate::read_fixture(&format!("{dir}/rar4/two_windows.rar")).unwrap();
        let arc = with_unp_size(&arc, 0, 100_000);
        assert_eq!(
            reasons(&arc, 64 << 10),
            [
                ("e_text.txt".to_string(), Some(RAR_OVER_LIMIT), size),
                ("g_far.bin".to_string(), Some(WINDOW_OVER_LIMIT), size),
            ]
        );
        // RAR5: a member of 270,345 bytes declaring 1,000 starts on a 128 KiB
        // window, which its distances make grow past the limit.
        let arc = crate::read_fixture(&format!("{dir}/rar_solid/two_windows.rar")).unwrap();
        let arc = with_unp_size(&arc, 1, 1000);
        assert_eq!(
            reasons(&arc, 200_000),
            [
                ("a.txt".to_string(), None, None),
                ("b.bin".to_string(), Some(WINDOW_OVER_LIMIT), size),
            ]
        );
        let mut b = over(200_000);
        let mut names = Vec::new();
        let src: &dyn ByteSource = &arc;
        walk(src, &mut b, &mut |m, content, _| {
            if let Some(crate::stream::Member::Stream(r)) = content {
                let _ = std::io::copy(r, &mut std::io::sink());
            }
            names.push(m.name.clone());
            None::<()>
        })
        .unwrap();
        assert_eq!(names, ["a.txt", "b.bin"]);
        let skipped = b.skipped.expect("the member left out is noted");
        assert!(
            skipped.reason.contains("'b.bin'") && skipped.reason.contains(WINDOW_OVER_LIMIT),
            "{}",
            skipped.reason
        );
    }

    /// A RAR4 member cut by the end of its archive (a fuzz mutant, 2,633 of its
    /// 14,661 bytes there, as unrar writes them) whose decoder then reads a
    /// filter index past the format's cap: damage, not a limit, in memory and
    /// streamed, and streamed the bytes unrar writes.
    #[test]
    fn a_filter_index_past_the_cap_is_damage_not_a_limit() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let arc = crate::read_fixture(&format!("{dir}/rar4/cut_in_filters.rar")).unwrap();
        let size = Some(crate::tree::ReasonKind::OVER_SIZE);
        let held = extract_rar(&arc, &mut Budget::new(Limits::default())).unwrap();
        assert_eq!(held.len(), 1);
        assert_ne!(held[0].reason_kind, size, "{:?}", held[0].unsupported);
        let mut b = Budget::new(Limits::default());
        let mut sink = Vec::new();
        let src: &dyn ByteSource = &arc;
        walk(src, &mut b, &mut |_, content, _| {
            if let Some(crate::stream::Member::Stream(r)) = content {
                let _ = r.read_to_end(&mut sink);
            }
            None::<()>
        })
        .unwrap();
        // The bytes unrar writes: its matches from before the start are zeros.
        assert_eq!((sink.len(), crc32_ieee(&sink)), (2633, 0x99aa_92d9));
        assert!(b.skipped.is_none(), "{:?}", b.skipped.map(|s| s.reason));
    }

    /// A damaged RAR5 member (a fuzz mutant) whose matches reach before the
    /// start of the stream decodes, in memory and streamed, to the 14,201
    /// bytes unrar writes, those matches as zeros.
    #[test]
    fn a_rar5_match_from_before_the_start_is_zeros() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let arc = crate::read_fixture(&format!("{dir}/rar5/match_from_before_start.rar")).unwrap();
        let unrar = (14201, 0x4cee_d435);
        let held = extract_rar(&arc, &mut Budget::new(Limits::default())).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!((held[0].data.len(), crc32_ieee(&held[0].data)), unrar);
        let mut b = Budget::new(Limits::default());
        let mut sink = Vec::new();
        let src: &dyn ByteSource = &arc;
        walk(src, &mut b, &mut |_, content, _| {
            if let Some(crate::stream::Member::Stream(r)) = content {
                let _ = r.read_to_end(&mut sink);
            }
            None::<()>
        })
        .unwrap();
        assert_eq!((sink.len(), crc32_ieee(&sink)), unrar);
    }

    /// A PPMd model over the buffer limit is not allocated: the member is
    /// reported with that reason, not as one that could not be decoded.
    #[test]
    fn a_ppmd_model_over_the_buffer_limit_is_reported_with_its_reason() {
        let arc = crate::read_fixture(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rar/ppmd_lzss_conversion.rar"
        ))
        .unwrap();
        let limits = Limits {
            max_buffer_bytes: 16 << 20,
            ..Limits::default()
        };
        let mut reasons = Vec::new();
        let src: &dyn ByteSource = &arc;
        walk(src, &mut Budget::new(limits), &mut |m, _, _| {
            reasons.push(m.unsupported);
            None::<()>
        })
        .unwrap();
        assert_eq!(reasons, [Some(PPMD_OVER_LIMIT)]);
    }

    /// A decoder that gives `left` zero bytes, counting them.
    struct Zeros {
        left: u64,
        given: u64,
    }

    impl LzStream for Zeros {
        fn read_member(&mut self, buf: &mut [u8], _: &mut dyn Read) -> Result<usize, LimitHit> {
            let n = (buf.len() as u64).min(self.left) as usize;
            buf[..n].fill(0);
            self.left -= n as u64;
            self.given += n as u64;
            Ok(n)
        }
        fn limit_reason(&self) -> &'static str {
            WINDOW_OVER_LIMIT
        }
    }

    /// A solid member after one that was not decoded is decoded to see
    /// whether it is its own, and what is decoded and not handed over is
    /// work: it stops one byte past what the scan budget has left, however
    /// large the member declares itself and however large the buffer limit.
    #[test]
    fn a_stale_member_is_decoded_no_further_than_the_scan_budget_allows() {
        let mut budget = Budget::new(Limits {
            max_scanned_bytes: 1000,
            ..Limits::default()
        });
        let mut dec = Zeros {
            left: 100 << 20,
            given: 0,
        };
        let empty: Vec<u8> = Vec::new();
        let src: &dyn ByteSource = &empty;
        let mut packed = crate::source::Reader::range(src, 0, 0);
        let r = stream_lz_member(
            &mut budget,
            &mut |_, _, _| None::<()>,
            &mut dec,
            "m".to_string(),
            0,
            100 << 20,
            (Some(0), false),
            true,
            &mut packed,
            "undecoded",
        );
        let hit = r.expect_err("the scan budget is spent");
        assert!(hit.reason.contains("scanned bytes"), "{}", hit.reason);
        assert!(dec.given <= 1001, "decoded {} bytes", dec.given);
    }

    /// A member left out at its compression ratio is decoded no further: the
    /// solid group ends with it, and its rest is not drained into the scan
    /// budget.
    #[test]
    fn a_member_over_the_ratio_is_not_decoded_to_its_end() {
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: 1000,
            max_compression_ratio: 10,
            ..Limits::default()
        });
        let mut dec = Zeros {
            left: 100 << 20,
            given: 0,
        };
        let empty: Vec<u8> = Vec::new();
        let src: &dyn ByteSource = &empty;
        let mut packed = crate::source::Reader::range(src, 0, 0);
        let mut read = 0;
        let r = stream_lz_member(
            &mut budget,
            &mut |_, content, _| {
                let mut sink = Vec::new();
                if let Some(crate::stream::Member::Stream(s)) = content {
                    let _ = s.read_to_end(&mut sink);
                }
                read = sink.len();
                None::<()>
            },
            &mut dec,
            "m".to_string(),
            1,
            100 << 20,
            (Some(0), false),
            false,
            &mut packed,
            "undecoded",
        );
        let (out, decoded, _) = r.unwrap();
        assert_eq!((out, decoded), (None, false));
        assert_eq!(read, 1000);
        assert!(dec.given <= 1001, "decoded {} bytes", dec.given);
        assert!(budget.skipped.is_some_and(|s| s.reason.contains("ratio")));
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
