#![allow(unused_imports)]
#![cfg_attr(
    not(feature = "decrypt"),
    allow(dead_code, unused_mut, unreachable_code)
)]
#[cfg(feature = "decrypt")]
use super::zip_crypto;
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// The encryption scheme + real (post-decrypt) compression method of an
/// encrypted ZIP member, plus the raw stored bytes.
pub struct EncryptedMember {
    pub raw: Vec<u8>,
    /// `None` = legacy PKWARE ZipCrypto; `Some(strength)` = WinZip AES
    /// (strength 1=AES-128, 2=AES-192, 3=AES-256).
    pub aes_strength: Option<u8>,
    /// Real compression method of the *decrypted* payload (0 = Store, 8 = Deflate).
    pub method: u16,
    /// High byte of the member's DOS mod-time, the ZipCrypto password-check byte
    /// for streaming (data-descriptor) archives — Info-ZIP `zip`'s default. `None`
    /// if the header carried no timestamp. Ignored for AES.
    pub dos_time_hi: Option<u8>,
}

/// Classify an error from the `zip` crate for one member.
///
/// Only a genuine I/O failure is a budget stop. A codec we have no decoder for,
/// or a header that doesn't parse, is not: the member is present and simply
/// unread, which is `UNSCANNABLE`. The distinction decides what happens next —
/// a `corrupt` stop lets [`extract_zip`] fall through to the local-header
/// salvage, while a budget stop aborts the archive and, with it, the container
/// holding it.
///
/// That containing scan is the reason this matters beyond the wording. A Word
/// document with an embedded ZIP whose central directory points outside the
/// carved slice raises `InvalidArchive` on entry 0; classifying it as a budget
/// stop propagated out of the ZIP, out of the OLE walk, and made the whole
/// document `LIMITS-EXCEEDED` — so its macro artifacts were never scanned and
/// every `Target:2` `Doc.*` signature was skipped on a document that carried a
/// live VBA project.
pub(crate) fn zip_entry_error(i: usize, e: &::zip::result::ZipError) -> LimitHit {
    let msg = format!("zip entry {i}: {e}");
    match e {
        ::zip::result::ZipError::Io(_) => LimitHit::new(msg),
        _ => LimitHit::corrupt(msg),
    }
}

/// Read the raw stored bytes of an encrypted member and classify its encryption
/// scheme + underlying compression method. For WinZip AES the member's
/// `compression()` is the `AesCrypto` wrapper, so the *real* method comes from
/// the 0x9901 AES extra field (parsed from the member's local extra data).
pub fn read_encrypted_member(
    file: &mut ::zip::read::ZipFile<'_, impl Read>,
    max_buffer: u64,
) -> Result<EncryptedMember, std::io::Error> {
    // The `zip` crate models a WinZip-AES member's `compression()` as a special
    // `Aes` method and stores the real method in the 0x9901 extra field.
    let (aes_strength, method) = parse_aes_extra(file.extra_data())
        .map(|(s, m)| (Some(s), m))
        .unwrap_or((None, compression_to_u16(file.compression())));
    // High byte of the 16-bit DOS mod-time — the ZipCrypto check byte for
    // data-descriptor archives (captured before the body is consumed).
    let dos_time_hi = file.last_modified().map(|dt| (dt.timepart() >> 8) as u8);
    // Bound the whole-member ciphertext read by the global peak-buffer limit;
    // the declared member size is attacker-controlled.
    let mut raw = Vec::new();
    (&mut *file)
        .take(max_buffer.saturating_add(1))
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > max_buffer {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted ZIP member exceeds max-buffer",
        ));
    }
    Ok(EncryptedMember {
        raw,
        aes_strength,
        method,
        dos_time_hi,
    })
}

/// Map the crate's `CompressionMethod` to the ZIP numeric method code we need
/// for post-decrypt decompression. Only Store/Deflate are decoded; anything else
/// is reported as Store (the bytes are passed through and scanned raw).
pub fn compression_to_u16(m: ::zip::CompressionMethod) -> u16 {
    match m {
        ::zip::CompressionMethod::Stored => 0,
        ::zip::CompressionMethod::Deflated => 8,
        _ => 0xffff,
    }
}

/// The ZIP numeric method code for a `CompressionMethod`, preserving the codec
/// identity (LZMA/BZIP2/ZSTD/XZ/PPMd) so [`decode_zip_raw`] can pick the right
/// decoder (APPNOTE 4.4.5).
// `CompressionMethod::Unsupported` is deprecated in the `zip` crate, but it is
// the only way to recover the raw method number for a codec the crate can't
// decode — which is exactly what we need to route to our own decoders.
#[allow(deprecated)]
pub(crate) fn zip_method_code(m: &::zip::CompressionMethod) -> u16 {
    use ::zip::CompressionMethod as C;
    // With only the `deflate-flate2` feature the crate collapses every codec it
    // can't handle (LZMA 14, BZIP2 12, ZSTD 93, XZ 95, PPMd 98, …) into
    // `Unsupported(code)`, so the real method number comes through there.
    match m {
        C::Stored => 0,
        C::Deflated => 8,
        C::Unsupported(n) => *n,
        _ => 0xffff,
    }
}

/// Decode a ZIP member the `zip` crate itself can't (LZMA/BZIP2/ZSTD/XZ) from its
/// RAW compressed bytes, using exav's own decoders — so a payload hidden behind a
/// codec the crate lacks is still extracted and scanned. `usz` is the header's
/// declared uncompressed size (LZMA needs it as the decode target; memory is
/// still bounded by `cap`). Returns `None` when the method isn't decodable in this
/// build; the caller then emits an `unsupported` member — never a silent clean.
#[allow(unused_variables)]
pub(crate) fn decode_zip_raw(
    method: u16,
    raw: &[u8],
    usz: u64,
    cap: u64,
) -> Option<(Vec<u8>, bool)> {
    match method {
        // Method 9 = Deflate64 ("enhanced deflate"): deflate with a 64 KiB
        // window, length code 285 redefined to take 16 extra bits (lengths up to
        // 65538), and distance codes 30/31 made valid (14 extra bits, distances
        // up to 64 KiB). Produced by 7-Zip (`-mm=Deflate64`) and by Windows'
        // own compressed-folder writer, and decoded by ClamAV — so a payload
        // behind it must not hide. The member bytes are a raw stream (no
        // wrapper), exactly like method 8.
        9 => bounded_read(
            deflate64::Deflate64Decoder::with_buffer(Cursor::new(raw)),
            cap,
        )
        .ok(),
        // APPNOTE 5.8.8: 2-byte version, 2-byte props-size (=5), then the 5-byte
        // LZMA properties (1 lc/lp/pb byte + 4-byte dict size), then the stream.
        #[cfg(feature = "lzip")]
        14 => {
            if raw.len() < 9 {
                return None;
            }
            let props = raw[4];
            let dict =
                crate::bounded_dict(u32::from_le_bytes([raw[5], raw[6], raw[7], raw[8]]), cap);
            let reader = lzma_rust2::LzmaReader::new_with_props(
                Cursor::new(&raw[9..]),
                usz,
                props,
                dict,
                None,
            )
            .ok()?;
            bounded_read(reader, cap).ok()
        }
        #[cfg(feature = "bzip2")]
        12 => bounded_read(bzip2_rs::DecoderReader::new(Cursor::new(raw)), cap).ok(),
        #[cfg(feature = "zstd")]
        93 => {
            let d = ruzstd::decoding::StreamingDecoder::new(Cursor::new(raw)).ok()?;
            bounded_read(d, cap).ok()
        }
        // Method 95 = XZ: the raw member bytes are a complete .xz stream.
        #[cfg(feature = "xz")]
        95 => super::xz::decode_xz(raw, cap).ok(),
        // Method 98 = PPMd var.H — the SAME variant 7z uses, so it reuses the
        // in-tree PPMd7 decoder. ZIP packs the model parameters into a 2-byte
        // little-endian header at the front of the member data (APPNOTE 5.9)
        // instead of carrying them in coder properties as 7z does.
        #[cfg(feature = "sevenz")]
        98 => {
            let (order, mem_size, body) = zip_ppmd_params(raw)?;
            let rd =
                super::sevenz::decode::Ppmd7ZReader::new(Cursor::new(body), order, mem_size, cap)
                    .ok()?;
            bounded_read(rd, cap).ok()
        }
        _ => None,
    }
}

/// Split a ZIP method-98 (PPMd) member into its model parameters and payload.
///
/// APPNOTE 5.9: a 2-byte little-endian word precedes the data — order in bits
/// 0-3 (biased by 1), model memory in MB in bits 4-11 (biased by 1), and the
/// restoration method in bits 12-15. Only the parameters matter here; the
/// restoration method is a property of the encoder's model resets, which the
/// decoder follows from the stream itself.
fn zip_ppmd_params(raw: &[u8]) -> Option<(u32, u32, &[u8])> {
    let w = u16::from_le_bytes([*raw.first()?, *raw.get(1)?]);
    let order = (w & 0x0f) as u32 + 1;
    let mem_mb = ((w >> 4) & 0xff) as u32 + 1;
    // Guard the shift as well as the decoder's own range check: 256 MB is the
    // format's maximum and already far past anything legitimate.
    if !(2..=64).contains(&order) || mem_mb > 256 {
        return None;
    }
    Some((order, mem_mb << 20, raw.get(2..)?))
}

/// Parse the WinZip-AES 0x9901 extra field: `len(2)=7, ver(2), "AE"(2),
/// strength(1), method(2)`. Returns `(strength, real_method)`.
pub(crate) fn parse_aes_extra(extra: Option<&[u8]>) -> Option<(u8, u16)> {
    let mut data = extra?;
    while data.len() >= 4 {
        let id = u16::from_le_bytes([data[0], data[1]]);
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let body = data.get(4..4 + len)?;
        if id == 0x9901 && body.len() >= 7 {
            let strength = body[4];
            let method = u16::from_le_bytes([body[5], body[6]]);
            return Some((strength, method));
        }
        data = &data[4 + len..];
    }
    None
}

/// Passwords exav tries automatically on an encrypted ZIP after the caller/DB
/// pool: the well-known malware-distribution conventions. A password-protected
/// dropper is a classic scanner-evasion trick, so cracking these zero-config
/// matters (mirrors the Office `VelvetSweatshop` default).
#[cfg(feature = "decrypt")]
const DEFAULT_ZIP_PASSWORDS: &[&str] = &["infected", "virus", "malware", "password", "123456"];

/// Try each pool password against the encrypted member; on the first that
/// decrypts (verifier/MAC for AES, CRC check byte for ZipCrypto), decompress per
/// the real method and return the plaintext. `None` if no password worked.
#[cfg(feature = "decrypt")]
pub fn decrypt_zip_member(
    enc: &EncryptedMember,
    crc: u32,
    budget: &mut Budget,
) -> Result<Option<Vec<u8>>, LimitHit> {
    // ZipCrypto's one-byte password check compares against the CRC-32 high byte,
    // or — for streaming (data-descriptor) archives, where the CRC wasn't known
    // at encryption time — the DOS mod-time high byte. We don't know which the
    // writer used, so accept either candidate; the full-payload CRC check below
    // is the real gate for the common Store/Deflate members.
    //
    // Both candidates are offered because writers do differ and the header
    // does not say which was used — a data-descriptor archive can still carry a
    // real CRC here, so neither candidate can be ruled out from the header alone.
    // Narrowing to one on that guess breaks archives that decrypt correctly today.
    //
    // The cost is a 2-in-256 false-accept rate per candidate password, and that
    // is not theoretical — the built-in `123456` matched the check byte of a
    // member whose password it was not, on a live sample. What makes it harmless
    // is the recovery below: a candidate whose plaintext fails to decompress is
    // treated as the wrong password and the next one is tried, rather than the
    // garbage being raised as an error that discards the whole archive.
    let mut check_bytes = [(crc >> 24) as u8; 2];
    let check_bytes: &[u8] = match enc.dos_time_hi {
        Some(t) => {
            check_bytes[1] = t;
            &check_bytes
        }
        None => &check_bytes[..1],
    };
    // Candidate passwords: the caller/DB pool first, then exav's built-in list of
    // passwords commonly used by malware-distribution ZIPs (the AV-sharing
    // convention "infected", etc.) so a password-protected dropper is cracked with
    // no configuration — mirroring the Office `VelvetSweatshop` default. Built into
    // an owned list so it doesn't borrow `budget` across the mutable `reserve()`.
    let mut candidates: Vec<Vec<u8>> = budget
        .passwords
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();
    candidates.extend(DEFAULT_ZIP_PASSWORDS.iter().map(|p| p.as_bytes().to_vec()));
    for pw in &candidates {
        let decrypted = match enc.aes_strength {
            Some(s) => zip_crypto::decrypt_aes(&enc.raw, s, pw),
            None => zip_crypto::decrypt_zipcrypto(&enc.raw, pw, check_bytes),
        };
        let Some(decrypted) = decrypted else { continue };
        // Decompress the decrypted payload per its real method, bounded.
        let cap = budget.reserve()?;
        let out = match enc.method {
            0 => {
                let take = (decrypted.len() as u64).min(cap) as usize;
                if decrypted.len() as u64 > cap {
                    return Err(LimitHit::new("decrypted zip member exceeds budget".into()));
                }
                decrypted[..take].to_vec()
            }
            8 => {
                // A failed inflate here means WRONG PASSWORD, not a broken
                // archive. The check byte is a single byte, so a candidate has a
                // 1-in-256 chance of being accepted by a password that is not the
                // real one — and that is not theoretical: on a live sample the
                // built-in `123456` matched the check byte of a member whose real
                // password was something else. Raising the resulting garbage as an
                // error aborted the ENTIRE archive, so one unlucky guess cost
                // every member and the real payload was never scanned.
                //
                // Try the next candidate instead, exactly as the CRC mismatch
                // below already does; the pool is only exhausted when every
                // candidate has failed.
                let Ok((buf, truncated)) = bounded_read(
                    flate2::read::DeflateDecoder::new(Cursor::new(&decrypted[..])),
                    cap,
                ) else {
                    continue;
                };
                if truncated {
                    return Err(LimitHit::new("decrypted zip member exceeds budget".into()));
                }
                buf
            }
            // A method we don't decode: hand back the decrypted (still-compressed)
            // bytes so name/size sigs and any embedded plaintext still match.
            _ => {
                if decrypted.len() as u64 > cap {
                    return Err(LimitHit::new("decrypted zip member exceeds budget".into()));
                }
                decrypted
            }
        };
        // Legacy ZipCrypto accepts on a single CRC byte (1/256 false-accept).
        // Validate the decompressed plaintext against the central-directory
        // CRC-32; on mismatch the password was wrong (or the member is corrupt),
        // so keep trying other passwords rather than handing back garbage that
        // would then be scanned as if it were the real cleartext. AES is already
        // authenticated by its verifier + HMAC, so this guards ZipCrypto only;
        // methods we don't decompress here can't be CRC-checked and fall through.
        if enc.aes_strength.is_none()
            && matches!(enc.method, 0 | 8)
            && zip_crypto::crc32_ieee(&out) != crc
        {
            continue;
        }
        return Ok(Some(out));
    }
    Ok(None)
}

pub(crate) fn extract_zip<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Normal pass: everything the central directory references. If the central
    // directory itself is unparseable (corrupt / forged / truncated — a `corrupt`
    // stop), don't give up: fall through to the raw local-header scan below, which
    // needs no central directory and salvages whatever members are still present.
    // Genuine budget stops from a member we already began extracting propagate.
    match extract_zip_from(Cursor::new(data), budget, &mut *visit) {
        Ok(Some(r)) => return Ok(Some(r)),
        Ok(None) => {}
        Err(e) if !e.corrupt => return Err(e),
        Err(_) => {}
    }
    // Dual indexing: a forged ZIP can hide a member by leaving it OUT of the
    // central directory (which the `zip` crate reads) while its Local File Header
    // + data still sit in the file — the OS/target still extracts it. Scan the raw
    // bytes for local headers the central directory doesn't cover and extract
    // those too, so a member hidden this way is still scanned. This is also the
    // salvage path when the central directory is unparseable.
    scan_orphan_locals(data, budget, visit)
}

/// Extract ZIP members present as Local File Headers but NOT listed in the
/// central directory (a central/local mismatch used to hide payloads). See
/// APPNOTE 4.3.7 for the local header layout.
fn scan_orphan_locals<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Local-header offsets the central directory already covered.
    let mut known = std::collections::HashSet::new();
    if let Ok(mut zip) = ::zip::ZipArchive::new(Cursor::new(data)) {
        for i in 0..zip.len() {
            if let Ok(f) = zip.by_index_raw(i) {
                known.insert(f.header_start() as usize);
            }
        }
    }
    // No separate cap on the number of orphans: `parse_local_member` charges
    // each one to `budget.count_entry()`, so the archive-wide `max_members` limit
    // bounds this the same way it bounds the central-directory path — and
    // exceeding it raises `LimitHit` (→ `LIMITS-EXCEEDED`) rather than quietly
    // leaving the rest of the members unscanned. An arbitrary cap here would
    // silently truncate: a damaged JAR with a few hundred members is ordinary.
    let mut pos = 0usize;
    while pos + LFH_LEN <= data.len() {
        let Some(rel) = memfind(&data[pos..], b"PK\x03\x04") else {
            break;
        };
        let off = pos + rel;
        pos = off + 4;
        if known.contains(&off) {
            continue;
        }
        // Only structurally credible headers count as members: `PK\x03\x04` is
        // four bytes and occurs by chance, and treating a chance hit as a member
        // would report ordinary files unscannable.
        if !plausible_local_header(data, off) {
            continue;
        }
        if let Some(entry) = parse_local_member(data, off, budget)? {
            if let Some(r) = visit(entry, budget) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}

/// Byte length of a ZIP local file header before the name/extra fields
/// (APPNOTE 4.3.7).
const LFH_LEN: usize = 30;

/// ZIP compression methods defined by APPNOTE 4.4.5. Used as a plausibility
/// signal, so it lists methods exav cannot decode as well as those it can.
const KNOWN_METHODS: &[u16] = &[
    0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 16, 18, 19, 93, 95, 96, 97, 98, 99,
];

/// Flag bits APPNOTE 4.4.4 leaves unused or reserved (7-10, 12, 14, 15). A real
/// writer leaves them clear, so a hit that sets one is almost certainly noise.
const RESERVED_FLAG_BITS: u16 = 0b1101_0111_1000_0000;

/// How many local file records in this ZIP **overlap** another one.
///
/// A well-formed ZIP lays its local records out end to end. Overlapping records
/// are a parser-confusion technique: two readers disagree about where a member
/// starts, so the archive shows one file to the scanner and a different one to
/// the tool that opens it. ClamAV alerts on this
/// (`Heuristics.Zip.OverlappingFiles`) and it is on by default there.
///
/// Only records whose extent is *known* are counted. A member using a trailing
/// data descriptor declares its compressed size as zero in the header, so its
/// end is not knowable until the stream is walked — counting those would
/// invent overlaps on ordinary streamed archives.
pub fn overlapping_local_records(data: &[u8]) -> usize {
    /// Bit 3: sizes are deferred to a trailing data descriptor.
    const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
    /// Bound the scan so a hostile file cannot make this quadratic-expensive.
    const MAX_RECORDS: usize = 4096;

    // Only records THIS archive declares are candidates. The technique being
    // detected needs two readers to disagree about the same archive, which needs
    // both records to be reachable from its central directory — so a byte
    // sequence that is not declared here cannot be half of the confusion.
    //
    // Scanning the whole file instead reports ordinary build output as an attack.
    // A nested archive stored uncompressed (method 0) puts its own local headers
    // physically inside the outer member's extent, and every one then looks like
    // a top-level record overlapping its neighbour. That is how Android app
    // bundles and shaded JARs are built: `assets/base.apk`, `META-INF/jars/*.jar`
    // and an embedded `python-3.10.11-embed-win32.zip` all measured 6 to 794
    // "overlaps" against a threshold of 5, on files that are entirely benign.
    //
    // With NO central directory there is nothing to filter against, so every
    // plausible header is a candidate as before. That is the safe way round: the
    // false positives all come from ordinary archives, which by construction have
    // a readable central directory (a jar, apk or xlsx without one would not open
    // in the tool that produced it), while a bare pile of local records carrying
    // no directory is not something a normal writer emits.
    let declared: Option<std::collections::HashSet<usize>> =
        ::zip::ZipArchive::new(Cursor::new(data)).ok().map(|mut z| {
            (0..z.len())
                .filter_map(|i| z.by_index_raw(i).ok().map(|f| f.header_start() as usize))
                .collect()
        });

    let mut extents: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0usize;
    while pos + LFH_LEN <= data.len() && extents.len() < MAX_RECORDS {
        let Some(rel) = memfind(&data[pos..], b"PK\x03\x04") else {
            break;
        };
        let off = pos + rel;
        pos = off + 4;
        if declared.as_ref().is_some_and(|d| !d.contains(&off))
            || !plausible_local_header(data, off)
        {
            continue;
        }
        let h = &data[off..off + LFH_LEN];
        let flags = u16::from_le_bytes([h[6], h[7]]);
        if flags & FLAG_DATA_DESCRIPTOR != 0 {
            continue; // extent unknown by construction
        }
        let comp = u32::from_le_bytes([h[18], h[19], h[20], h[21]]) as usize;
        let name_len = u16::from_le_bytes([h[26], h[27]]) as usize;
        let extra_len = u16::from_le_bytes([h[28], h[29]]) as usize;
        let Some(end) = LFH_LEN
            .checked_add(name_len)
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comp))
            .and_then(|n| off.checked_add(n))
        else {
            continue;
        };
        if end > data.len() || end <= off {
            continue;
        }
        extents.push((off, end));
    }

    // Sort by start, then count records that begin before the previous one ends.
    extents.sort_unstable();
    let mut overlapping = 0usize;
    let mut furthest_end = 0usize;
    for (start, end) in extents {
        if start < furthest_end {
            overlapping += 1;
        }
        furthest_end = furthest_end.max(end);
    }
    overlapping
}

/// Does the `PK\x03\x04` at `off` look like a genuine local file header rather
/// than a chance byte sequence? Checks the fields a real writer must fill in
/// consistently; deliberately strict, because every false positive here becomes
/// a spurious `UNSCANNABLE` on an otherwise ordinary file.
fn plausible_local_header(data: &[u8], off: usize) -> bool {
    let Some(h) = data.get(off..off + LFH_LEN) else {
        return false;
    };
    let version = u16::from_le_bytes([h[4], h[5]]);
    let flags = u16::from_le_bytes([h[6], h[7]]);
    let method = u16::from_le_bytes([h[8], h[9]]);
    let name_len = u16::from_le_bytes([h[26], h[27]]) as usize;
    let extra_len = u16::from_le_bytes([h[28], h[29]]) as usize;
    // "Version needed to extract" is a spec version ×10; 6.3 is the current top.
    if version > 63 {
        return false;
    }
    if flags & RESERVED_FLAG_BITS != 0 {
        return false;
    }
    // A path, not arbitrary bytes: non-empty, within the APPNOTE limit, present
    // in the file, and free of NULs (which no ZIP path may contain).
    if name_len == 0 || name_len > 4096 {
        return false;
    }
    let Some(name) = data.get(off + LFH_LEN..off + LFH_LEN + name_len) else {
        return false;
    };
    if name.contains(&0) {
        return false;
    }
    // An unrecognised compression method makes the header *less* credible, but it
    // is not on its own disqualifying — and treating it as disqualifying is worse
    // than the false positives it prevents. A packer that stamps a nonsense method
    // (47506) on a member gets that member dropped by every reader gating on the
    // method, and a dropped member is a silent clean: the archive scans without
    // anyone looking inside it. So an unknown method is accepted when the name
    // corroborates the header instead. A chance `PK\x03\x04` is not followed by a
    // readable path, which is what makes the name a usable substitute signal.
    // `parse_local_member` then reports such a member unsupported rather than
    // pretending to decode it.
    if !KNOWN_METHODS.contains(&method)
        && !std::str::from_utf8(name).is_ok_and(|s| !s.chars().any(char::is_control))
    {
        return false;
    }
    data.len() >= off + LFH_LEN + name_len + extra_len
}

/// Find the first occurrence of `needle` in `hay`.
fn memfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// CRC-32 (IEEE), as ZIP records it. Duplicated here rather than reached for in
/// `zip_crypto` because that module is gated on the `decrypt` feature, while the
/// false-encryption-flag check runs in every build — including the ZIP-only one.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Whether a member whose "encrypted" bit is set in fact decodes as cleartext.
///
/// Verified by CRC-32 over the decoded bytes, so a `true` here is proof rather
/// than a guess: no key stream produces output matching the CRC the header
/// itself declares. Used to defeat the APK packer trick of flagging every
/// member encrypted (Android ignores the bit) purely to make scanners decline.
///
/// Conservative in both directions — it only ever *reduces* the number of
/// members treated as encrypted, and when it declines the member is still
/// reported, never silently dropped.
fn encryption_flag_is_a_lie(
    data: &[u8],
    data_start: usize,
    comp: usize,
    method: u16,
    flags: u16,
    crc: u32,
) -> bool {
    // Bit 3 puts the real CRC in a trailing data descriptor, leaving this field
    // zero — nothing to check against, so the flag stands.
    if flags & 0x08 != 0 || crc == 0 {
        return false;
    }
    // The probe decodes before any budget is reserved, so bound it. A member
    // larger than this stays reported-as-encrypted rather than scanned, which is
    // the safe direction: visible, not silent.
    const PROBE_MAX: usize = 64 << 20;
    if comp > PROBE_MAX {
        return false;
    }
    let Some(raw) = data.get(data_start..data_start + comp) else {
        return false;
    };
    let plain = match method {
        0 => raw.to_vec(),
        8 => {
            let mut out = Vec::new();
            if bounded_read_salvage(
                flate2::read::DeflateDecoder::new(Cursor::new(raw)),
                PROBE_MAX as u64,
                true,
            )
            .map(|(o, truncated)| {
                out = o;
                truncated
            })
            .unwrap_or(true)
            {
                return false;
            }
            out
        }
        // Anything else we would not decode even in the clear.
        _ => return false,
    };
    crc32_ieee(&plain) == crc
}

/// The plaintext of a member flagged encrypted whose bytes are in fact
/// cleartext, or `None` when the flag is telling the truth.
///
/// Proof, not inference: the returned bytes reproduce the CRC-32 the member's
/// own header declares. Only ever *reduces* the set of members treated as
/// encrypted; when it declines, the member is still reported as before.
///
/// Not gated on `decrypt`: no cipher is involved — the point is that these bytes
/// were never encrypted.
pub(crate) fn cleartext_despite_flag(enc: &EncryptedMember, crc: u32) -> Option<Vec<u8>> {
    // A real AES member carries the 0x9901 extra field, which no cleartext
    // member has any reason to; and with no CRC there is nothing to check.
    if crc == 0 || enc.aes_strength.is_some() {
        return None;
    }
    let plain = match enc.method {
        0 => enc.raw.clone(),
        8 => {
            let mut out = Vec::new();
            flate2::read::DeflateDecoder::new(Cursor::new(&enc.raw[..]))
                .read_to_end(&mut out)
                .ok()?;
            out
        }
        _ => return None,
    };
    (crc32_ieee(&plain) == crc).then_some(plain)
}

/// Parse one Local File Header at `off` (already vetted by
/// [`plausible_local_header`]) and extract its member.
///
/// A member this function cannot decode is reported as an
/// [`Entry::unsupported`], never dropped: the header is credible, so the bytes
/// *are* a member the target will extract, and omitting it would let the file be
/// reported clean on a scan that never looked inside it. `Ok(None)` is returned
/// only for a directory entry, which carries no content by definition.
fn parse_local_member(
    data: &[u8],
    off: usize,
    budget: &mut Budget,
) -> Result<Option<Entry>, LimitHit> {
    let h = match data.get(off..off + LFH_LEN) {
        Some(h) => h,
        None => return Ok(None),
    };
    let flags = u16::from_le_bytes([h[6], h[7]]);
    let method = u16::from_le_bytes([h[8], h[9]]);
    let comp = u32::from_le_bytes([h[18], h[19], h[20], h[21]]) as usize;
    let usz = u32::from_le_bytes([h[22], h[23], h[24], h[25]]) as u64;
    let name_len = u16::from_le_bytes([h[26], h[27]]) as usize;
    let extra_len = u16::from_le_bytes([h[28], h[29]]) as usize;
    let name = String::from_utf8_lossy(
        data.get(off + LFH_LEN..off + LFH_LEN + name_len)
            .unwrap_or(&[]),
    )
    .into_owned();

    // A trailing '/' with no content is a directory entry: nothing at all to
    // scan, so skipping it hides nothing.
    if comp == 0 && name.ends_with('/') {
        return Ok(None);
    }

    let report = |reason: &'static str, encrypted: bool, budget: &mut Budget| {
        budget.count_entry()?;
        Ok(Some(Entry::unsupported(
            name.clone(),
            comp as u64,
            encrypted,
            reason,
        )))
    };

    let data_start = off + LFH_LEN + name_len + extra_len;
    // Bit 0: the member is encrypted. The orphan path has no central-directory
    // CRC to drive the ZipCrypto password check, so report it rather than guess.
    //
    // But the flag is checkable, not merely trustworthy, and on a live corpus it
    // lies: Android's ZIP reader ignores bit 0, so APK packers set it on *every*
    // member to make analysis tools refuse an archive the platform installs
    // happily. A member reported PASSWORD-PROTECTED is a member never scanned,
    // which is precisely the outcome the packer is buying. So before believing
    // the bit, try decoding the member as cleartext: a CRC-32 match over the
    // result proves the bytes were never encrypted, whatever the header claims.
    if flags & 0x01 != 0 {
        let crc = u32::from_le_bytes([h[14], h[15], h[16], h[17]]);
        if !encryption_flag_is_a_lie(data, data_start, comp, method, flags, crc) {
            return report("encrypted zip member (orphan local header)", true, budget);
        }
    }
    // Bit 3: the sizes live in a data descriptor AFTER the member data, so the
    // local header alone doesn't say where the member ends. Recover the extent
    // rather than declining to scan — on a live corpus this was the single
    // largest source of `UNSCANNABLE`, i.e. the most content exav was choosing
    // not to look at.
    let comp = if flags & 0x08 != 0 && comp == 0 {
        match deferred_member_size(data, data_start, method) {
            Some(c) => c,
            None => {
                return report(
                    "streaming zip member with unrecoverable size (orphan local header)",
                    false,
                    budget,
                )
            }
        }
    } else {
        comp
    };
    let raw = match data.get(data_start..data_start + comp) {
        Some(r) => r,
        // The declared extent runs past EOF: the archive is truncated, so those
        // bytes are ABSENT from the file rather than hidden in it. Whatever does
        // exist is still covered by the outer raw scan, so this is not a coverage
        // gap and must not be reported as one — exav scans for malware, it is not
        // a file-integrity validator. See docs/QUIRKS.md.
        None => return Ok(None),
    };
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let out = match method {
        // Stored. The deflate arm below already refuses to hand back a prefix;
        // this one clamped to the cap and returned it as a complete member, so
        // an oversized stored orphan was silently truncated. Same treatment.
        0 if comp as u64 > cap => {
            return Ok(Some(Entry::unsupported(
                name,
                comp as u64,
                false,
                "orphan zip member exceeds size budget",
            )))
        }
        0 => raw.get(..comp).unwrap_or(raw).to_vec(),
        8 => {
            // Salvage the bytes decoded before any corruption rather than
            // dropping the whole member: this is a best-effort recovery of a
            // malformed archive, and the payload a signature matches may sit in
            // the valid prefix (matching clamd, which scans partial inflate).
            let (o, truncated) = bounded_read_salvage(
                flate2::read::DeflateDecoder::new(Cursor::new(raw)),
                cap,
                true,
            )
            .map_err(|e| LimitHit::corrupt(format!("orphan zip inflate: {e}")))?;
            // Over the per-member cap. Yield metadata-only rather than the
            // prefix (which would read as a complete member) and rather than
            // aborting, so the remaining orphans are still scanned — the same
            // shape the central-directory path uses for an oversized member.
            if truncated {
                return Ok(Some(Entry::unsupported(
                    name,
                    comp as u64,
                    false,
                    "orphan zip member exceeds size budget",
                )));
            }
            o
        }
        _ => match decode_zip_raw(method, raw, usz, cap) {
            Some((o, false)) => o,
            // Either a codec exav has no decoder for, or one whose stream was
            // truncated. Both leave content unexamined.
            _ => {
                return Ok(Some(Entry::unsupported(
                    name,
                    comp as u64,
                    false,
                    "unsupported zip compression method (orphan local header)",
                )))
            }
        },
    };
    ratio_guard(comp as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(Some(Entry {
        comp_size: comp as u64,
        encrypted: false,
        unsupported: None,
        name,
        data: out,
    }))
}

/// Recover the compressed length of a member whose local header deferred its
/// sizes to a trailing data descriptor (general-purpose flag bit 3).
///
/// Two independent routes, in order of reliability:
///
///  1. **The data descriptor's own signature.** APPNOTE 4.3.9.3 makes the
///     `PK\x07\x08` marker optional but near-universal in practice; the
///     compressed size is the second `u32` after it. Accepted only when that
///     size actually points back at this member's data, which rejects a marker
///     that belongs to some later member.
///  2. **The next header.** Failing that, the member data runs up to the next
///     local file header or the start of the central directory.
///
/// `None` when neither route lands, in which case the caller reports the member
/// rather than dropping it.
fn deferred_member_size(data: &[u8], data_start: usize, method: u16) -> Option<usize> {
    let tail = data.get(data_start..)?;
    // Route 1: a data descriptor whose declared size is self-consistent.
    let mut from = 0usize;
    while let Some(rel) = memfind(&tail[from..], b"PK\x07\x08") {
        let sig = from + rel;
        // signature(4) + crc(4) + compressed(4) + uncompressed(4)
        if let Some(f) = tail.get(sig + 8..sig + 12) {
            let declared = u32::from_le_bytes([f[0], f[1], f[2], f[3]]) as usize;
            if declared == sig {
                return Some(declared);
            }
        }
        from = sig + 4;
        if from >= tail.len() {
            break;
        }
    }
    // Route 2: run to whatever header comes next. Only safe for a codec that
    // tolerates trailing bytes — deflate stops at its own end-of-stream marker,
    // whereas a stored member would silently absorb the descriptor and the next
    // header into its content.
    if method != 8 {
        return None;
    }
    let next = [&b"PK\x03\x04"[..], &b"PK\x01\x02"[..], &b"PK\x05\x06"[..]]
        .iter()
        .filter_map(|sig| memfind(tail, sig))
        .min()
        .unwrap_or(tail.len());
    (next > 0).then_some(next)
}

/// Stream a ZIP from any seekable reader, invoking `visit` per file member. With
/// a range-backed reader (e.g. HTTP) this reads only the central directory and
/// the members it actually decompresses, rather than the whole archive.
pub fn extract_zip_from<Rd: Read + Seek, R>(
    reader: Rd,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // A failure to open the archive means the central directory is unparseable
    // (corrupt/forged/truncated), NOT a resource limit — mark it `corrupt` so the
    // caller salvages via the local-header scan and the verdict is `Unscannable`,
    // never `LimitsExceeded`.
    let mut zip =
        ::zip::ZipArchive::new(reader).map_err(|e| LimitHit::corrupt(format!("zip: {e}")))?;
    for i in 0..zip.len() {
        // Count every central-directory entry, including directories, so a
        // directory-only archive cannot iterate past the file-count budget.
        budget.count_entry()?;
        // Peek the member with the RAW reader first: it never invokes the crate's
        // decryptor, so it succeeds for encrypted members too (which `by_index`
        // would reject — we build `zip` WITHOUT `aes-crypto`, the feature that
        // pulls `getrandom`). For an encrypted member we decrypt the raw bytes
        // ourselves; for a cleartext one we re-open with the decompressing reader.
        // One member whose header will not parse costs ONLY that member. Giving up
        // on the archive here loses every member after it twice over: this walk
        // abandons them, and the local-header salvage in `extract_zip` then skips
        // them as already covered, because their directory records parsed fine and
        // put them in its `known` set. Neither pass scans them and neither reports
        // them, so a payload in member 3 rides out behind one bad pointer in
        // member 1 and the file comes back merely unreadable instead of infected.
        let mut file = match zip.by_index_raw(i) {
            Ok(f) => f,
            Err(e) => {
                let hit = zip_entry_error(i, &e);
                // A real I/O failure is not this member's problem — the source
                // itself is gone, so there is nothing to keep walking for.
                if !hit.corrupt {
                    return Err(hit);
                }
                // Named by index: the name lives in the directory record we just
                // failed to follow, so there is nothing more honest to call it.
                let e = Entry::unsupported(
                    format!("zip entry {i}"),
                    0,
                    false,
                    "ZIP member header will not parse",
                );
                if let Some(r) = visit(e, budget) {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        // `is_file()` is false purely because the name ends in '/', and a JAR
        // packer buys exactly that: `kingDavid/9.class/` holds a real
        // deflate-compressed class, which the JVM loads by name while every ZIP
        // tool discards it as a folder (`unzip`, python's `extractall` and this
        // crate all agree — and all agree wrongly). Skip only what really
        // carries nothing: a "directory" with content is content.
        if !file.is_file() && file.compressed_size() == 0 {
            continue;
        }
        let name = file.name().to_string();
        let comp = file.compressed_size();
        // Codec + declared uncompressed size, captured from the raw header so we
        // can decode methods the `zip` crate lacks (LZMA/BZIP2/ZSTD) ourselves.
        let method = zip_method_code(&file.compression());
        let usz = file.size();

        // Encrypted member: try the password pool, decrypt+decompress on success,
        // else emit a metadata-only `PasswordProtected` signal.
        if file.encrypted() {
            // Without the `decrypt` feature there is no cipher stack compiled in,
            // so an encrypted member is reported as unsupported (never decrypted,
            // never silently clean) — the same as an encrypted member with no
            // password supplied.
            // The false-flag check still runs: it decrypts nothing, only proves
            // by CRC-32 that the bytes were never ciphertext.
            #[cfg(not(feature = "decrypt"))]
            {
                let crc = file.crc32();
                let plain = read_encrypted_member(&mut file, budget.limits.max_buffer_bytes)
                    .ok()
                    .and_then(|enc| cleartext_despite_flag(&enc, crc));
                drop(file);
                if let Some(plain) = plain {
                    let size = plain.len() as u64;
                    if size <= budget.reserve()? {
                        budget.commit(size);
                        if let Some(r) = visit(Entry::new(name, plain), budget) {
                            return Ok(Some(r));
                        }
                        continue;
                    }
                }
                let e = Entry::unsupported(name, comp, true, "encrypted ZIP member");
                if let Some(r) = visit(e, budget) {
                    return Ok(Some(r));
                }
                continue;
            }
            #[cfg(feature = "decrypt")]
            {
                let crc = file.crc32();
                let enc = match read_encrypted_member(&mut file, budget.limits.max_buffer_bytes) {
                    Ok(e) => e,
                    Err(_) => {
                        drop(file);
                        let e = Entry::unsupported(name, comp, true, "encrypted ZIP member");
                        if let Some(r) = visit(e, budget) {
                            return Ok(Some(r));
                        }
                        continue;
                    }
                };
                drop(file);
                // The bit can lie, and on live APKs it does: the packer sets it
                // on every member because Android's ZIP reader ignores it, so
                // scanners decline an archive the platform installs happily.
                // A CRC-32 match over a plain decode proves the bytes were never
                // encrypted — no key stream reproduces the header's own checksum.
                if let Some(plain) = cleartext_despite_flag(&enc, crc) {
                    let size = plain.len() as u64;
                    if size <= budget.reserve()? {
                        budget.commit(size);
                        if let Some(r) = visit(Entry::new(name, plain), budget) {
                            return Ok(Some(r));
                        }
                        continue;
                    }
                }
                match decrypt_zip_member(&enc, crc, budget)? {
                    Some(plain) => {
                        budget.commit(plain.len() as u64);
                        // Decrypted, so the content is here AND the member was
                        // encrypted. Both are true and both are reported: the
                        // plaintext gets scanned for real signatures, and
                        // `--alert-encrypted` still sees the encryption. Clearing
                        // the flag here is what made cracking a password erase the
                        // report of there having been one.
                        let entry = Entry {
                            comp_size: comp,
                            encrypted: true,
                            unsupported: None,
                            name,
                            data: plain,
                        };
                        if let Some(r) = visit(entry, budget) {
                            return Ok(Some(r));
                        }
                    }
                    None => {
                        let e = Entry::unsupported(name, comp, true, "encrypted ZIP member");
                        if let Some(r) = visit(e, budget) {
                            return Ok(Some(r));
                        }
                    }
                }
            }
            continue;
        }
        // A member too large to decompress within budget would otherwise abort
        // the whole archive — and ClamAV reads `.cdb` member metadata
        // (name/size/encryption) from the header WITHOUT decompressing, so
        // aborting here is a false-negative on name/size-based container sigs
        // (e.g. a fake `…pdf.exe` dropper). Instead yield a metadata-only member
        // (flagged Unscannable, empty data) so `.cdb` still matches and the rest
        // of the archive is still scanned.
        let mut oversized = |budget: &mut Budget, reason: &'static str| -> Option<R> {
            visit(
                Entry::unsupported(name.clone(), comp, false, reason),
                budget,
            )
        };
        let cap = match budget.reserve() {
            Ok(c) => c,
            Err(_) => {
                drop(file);
                if let Some(r) = oversized(budget, "archive member exceeds size budget") {
                    return Ok(Some(r));
                }
                continue;
            }
        };

        // Codec the `zip` crate can't decode (LZMA/BZIP2/ZSTD/…): decode the raw
        // bytes with exav's own decoders so the payload isn't hidden behind an
        // unsupported method. A decode we can't do (or an unknown codec) yields a
        // metadata-only unsupported member and the archive keeps going — one bad
        // member never aborts the whole ZIP.
        let (buf, truncated) = if method != 0 && method != 8 {
            let (raw, _) = bounded_read(&mut file, budget.limits.max_buffer_bytes)
                .map_err(|e| LimitHit::new(format!("zip raw read: {e}")))?;
            drop(file);
            match decode_zip_raw(method, &raw, usz, cap) {
                Some(out) => out,
                None => {
                    if let Some(r) = oversized(budget, "archive member: unsupported ZIP codec") {
                        return Ok(Some(r));
                    }
                    continue;
                }
            }
        } else {
            // Store/Deflate: re-open with the decompressing reader (the raw reader
            // returns still-compressed bytes).
            drop(file);
            let mut file = match zip.by_index(i) {
                Ok(f) => f,
                Err(_) => {
                    if let Some(r) = oversized(budget, "archive member: ZIP decode failed") {
                        return Ok(Some(r));
                    }
                    continue;
                }
            };
            let r = bounded_read_salvage(&mut file, cap, !budget.should_verify_checksums())
                .map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
            drop(file);
            r
        };
        if truncated {
            if let Some(r) = oversized(budget, "archive member exceeds size budget") {
                return Ok(Some(r));
            }
            continue;
        }
        // `comp` is attacker-controlled; the absolute caps above are the real
        // bound. The ratio check is only a fast reject when comp is plausible.
        ratio_guard(comp, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        // Compressed size is meaningful for `.cdb` `FileSizeInContainer`.
        let entry = Entry {
            comp_size: comp,
            encrypted: false,
            unsupported: None,
            name,
            data: buf,
        };
        if let Some(r) = visit(entry, budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Lazy, seekable ZIP reader: yields one [`Entry`] at a time so a range-backed
/// reader (e.g. an HTTP range request over a remote ZIP) only fetches the
/// member currently being read, and the caller can stop early — e.g. on the
/// first detection — without touching later members. This is the seekable
/// counterpart to [`extract`], which buffers everything.
pub struct ZipMembers<R: Read + Seek> {
    zip: ::zip::ZipArchive<R>,
    next: usize,
    /// The bytes the central directory does not account for, with where each
    /// run starts. Read at `open` and walked once the directory's own members
    /// are exhausted. Empty for a well-formed archive.
    unclaimed: Vec<(u64, Vec<u8>)>,
    /// Where each hidden member's header sits, as `(run, offset in run)`.
    ///
    /// These take indices straight after the directory's own, so a hidden member
    /// is addressable exactly like a listed one — `list` reports it, `extract`
    /// takes its index, and the two agree.
    orphans: Vec<(usize, usize)>,
    /// The hidden-member search hit its cap with space still unexamined, so the
    /// member list may be short. Reported as a member of its own rather than
    /// left for the caller to not notice.
    search_truncated: bool,
}

/// The byte ranges between the members the central directory claims, up to the
/// directory itself.
///
/// A member the directory omits lies in the space between the ones it names, so
/// those are the only places worth reading. On a well-formed archive, where the
/// members are laid out end to end, this is empty and costs nothing.
fn unclaimed_spans<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
) -> (Vec<(u64, u64)>, std::collections::HashSet<u64>) {
    let cd = zip.central_directory_start();
    let mut claimed: Vec<(u64, u64)> = Vec::with_capacity(zip.len());
    let mut known = std::collections::HashSet::with_capacity(zip.len());
    for i in 0..zip.len() {
        if let Ok(f) = zip.by_index_raw(i) {
            let start = f.header_start();
            known.insert(start);
            // A member using a trailing data descriptor declares no data start,
            // so its extent is not knowable here. Claiming only the header
            // under-counts, which opens a gap that gets read and found to hold
            // this same member — which `known` is what rejects.
            let end = f
                .data_start()
                .map_or(start, |d| d.saturating_add(f.compressed_size()));
            claimed.push((start, end.min(cd)));
        }
    }
    claimed.sort_unstable();

    let mut gaps = Vec::new();
    // From zero, not from the first claimed member: a member spliced in AHEAD
    // of everything the directory names lies before all of them.
    let mut at = 0u64;
    for (start, end) in claimed {
        if start > at {
            gaps.push((at, start));
        }
        at = at.max(end);
    }
    if cd > at {
        gaps.push((at, cd));
    }
    // A local header is 30 bytes; nothing shorter can hold one.
    gaps.retain(|(a, b)| b - a >= LFH_LEN as u64);
    (gaps, known)
}

/// Name, sizes and encryption flag from a local file header, WITHOUT
/// decompressing anything.
///
/// Finding a hidden member and reading it are separate jobs, and only the first
/// is needed to say the member is there. Keeping them separate is what lets a
/// listing account for the whole archive at the cost of a header parse.
///
/// `None` for a directory entry, which has nothing to scan.
fn local_header_info(data: &[u8], off: usize) -> Option<(String, u64, u64, bool)> {
    let h = data.get(off..off + LFH_LEN)?;
    let flags = u16::from_le_bytes([h[6], h[7]]);
    let method = u16::from_le_bytes([h[8], h[9]]);
    let crc = u32::from_le_bytes([h[14], h[15], h[16], h[17]]);
    let comp = u64::from(u32::from_le_bytes([h[18], h[19], h[20], h[21]]));
    let usz = u64::from(u32::from_le_bytes([h[22], h[23], h[24], h[25]]));
    let name_len = usize::from(u16::from_le_bytes([h[26], h[27]]));
    let extra_len = usize::from(u16::from_le_bytes([h[28], h[29]]));
    let name =
        String::from_utf8_lossy(data.get(off + LFH_LEN..off + LFH_LEN + name_len)?).into_owned();
    if comp == 0 && name.ends_with('/') {
        return None;
    }

    // The encryption bit is checkable, not merely trustworthy, and extraction
    // checks it: APK packers set it on every member to make analysis tools
    // refuse an archive Android installs happily. Reporting the bit at face
    // value here would have a listing say PASSWORD-PROTECTED where extraction
    // finds cleartext — the same archive described two ways depending on which
    // call was made. The check runs over bytes already in hand.
    let encrypted = flags & 0x01 != 0 && {
        let data_start = off + LFH_LEN + name_len + extra_len;
        !encryption_flag_is_a_lie(data, data_start, comp as usize, method, flags, crc)
    };
    Some((name, comp, usz, encrypted))
}

/// Where in the unclaimed runs each hidden member's header sits.
///
/// Computed once at `open` from bytes already read, so a listing and an
/// extraction agree about which members exist and in what order.
fn find_orphans(
    unclaimed: &[(u64, Vec<u8>)],
    known: &std::collections::HashSet<u64>,
) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (span, (start, buf)) in unclaimed.iter().enumerate() {
        let mut at = 0usize;
        while at + LFH_LEN <= buf.len() {
            let Some(rel) = memfind(&buf[at..], b"PK\x03\x04") else {
                break;
            };
            let off = at + rel;
            at = off + 4;
            if known.contains(&(start + off as u64)) {
                continue;
            }
            // `PK\x03\x04` is four bytes and turns up by chance inside
            // compressed data, so only a structurally credible header counts.
            if !plausible_local_header(buf, off) {
                continue;
            }
            if local_header_info(buf, off).is_some() {
                out.push((span, off));
            }
        }
    }
    out
}

/// Read the given ranges, capped in total by [`MAX_ORPHAN_SCAN`].
///
/// Runs of bytes the central directory does not claim, each with the absolute
/// offset it starts at.
type UnclaimedRuns = Vec<(u64, Vec<u8>)>;

/// The `bool` is true when the cap stopped the search with ranges still
/// unexamined. It has to be carried out rather than swallowed: a search that
/// stops early and says nothing reports fewer members than the archive holds,
/// which is the same wrong answer as not searching at all.
fn read_spans<R: Read + Seek>(
    reader: &mut R,
    spans: &[(u64, u64)],
    cap: u64,
) -> Result<(UnclaimedRuns, bool), LimitHit> {
    let mut out = Vec::new();
    let mut spent = 0u64;
    for (i, &(start, end)) in spans.iter().enumerate() {
        let want = (end - start).min(cap.saturating_sub(spent));
        if want < LFH_LEN as u64 {
            // Out of budget with ranges left, as against having reached the end
            // of a list whose last entries were too small to hold a header.
            let left = spans[i..].iter().any(|(a, b)| b - a >= LFH_LEN as u64);
            return Ok((out, left));
        }
        spent += want;
        reader
            .seek(std::io::SeekFrom::Start(start))
            .map_err(|e| LimitHit::corrupt(format!("zip: seek: {e}")))?;
        let mut buf = vec![0u8; want as usize];
        let mut got = 0usize;
        while got < buf.len() {
            match reader.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => return Err(LimitHit::corrupt(format!("zip: read: {e}"))),
            }
        }
        buf.truncate(got);
        out.push((start, buf));
    }
    Ok((out, false))
}

/// How many bytes of unaccounted-for space a seekable ZIP will read looking for
/// members the central directory omits.
///
/// The buffered path has the whole archive already and scans all of it. This one
/// exists precisely so a large archive is never read whole, so the search is
/// bounded — an archive whose directory declares one small member and leaves
/// gigabytes unclaimed would otherwise turn opening it into a full read.
const MAX_ORPHAN_SCAN: u64 = 16 * 1024 * 1024;

impl<R: Read + Seek> ZipMembers<R> {
    /// Open a seekable ZIP (reads only the central directory, and whatever
    /// space that directory leaves unaccounted for).
    pub fn open(reader: R) -> Result<Self, LimitHit> {
        let mut zip =
            ::zip::ZipArchive::new(reader).map_err(|e| LimitHit::new(format!("zip: {e}")))?;
        let (gaps, known) = unclaimed_spans(&mut zip);
        if gaps.is_empty() {
            // The common case: members laid out end to end, nothing to look for
            // and nothing extra read.
            return Ok(Self {
                zip,
                next: 0,
                unclaimed: Vec::new(),
                orphans: Vec::new(),
                search_truncated: false,
            });
        }
        // `ZipArchive` lends out no reader, so the only way to read elsewhere in
        // the file is to take it back and reopen after. That costs a second
        // parse of the central directory, which is why it is skipped entirely
        // when there is nothing to scan.
        let mut r = zip.into_inner();
        let (unclaimed, search_truncated) = read_spans(&mut r, &gaps, MAX_ORPHAN_SCAN)?;
        let zip = ::zip::ZipArchive::new(r).map_err(|e| LimitHit::new(format!("zip: {e}")))?;
        let orphans = find_orphans(&unclaimed, &known);
        Ok(Self {
            zip,
            next: 0,
            unclaimed,
            orphans,
            search_truncated,
        })
    }

    /// The name the truncated-search marker carries, in both the listing and the
    /// extraction, so the two agree about it as they do about real members.
    const TRUNCATED_MARKER: &'static str = "<hidden-member search stopped at its limit>";

    /// Metadata for the members the central directory omits.
    ///
    /// Header parses only — nothing is decompressed, so a listing costs the same
    /// whether an archive hides members or not.
    fn orphan_infos(&self) -> Vec<crate::MemberInfo> {
        let base = self.zip.len();
        self.orphans
            .iter()
            .enumerate()
            .filter_map(|(n, &(span, off))| {
                let (_, buf) = self.unclaimed.get(span)?;
                let (name, comp, usz, encrypted) = local_header_info(buf, off)?;
                Some(crate::MemberInfo {
                    name,
                    index: base + n,
                    compressed_size: comp,
                    uncompressed_size: usz,
                    encrypted,
                })
            })
            .collect()
    }

    /// Extract the `n`th member the central directory omits.
    fn extract_orphan(&mut self, n: usize, budget: &mut Budget) -> Result<Option<Entry>, LimitHit> {
        // The index just past the last hidden member is the marker, when the
        // search stopped early. It carries no data — its whole content is the
        // statement that the list may be short.
        if self.search_truncated && n == self.orphans.len() {
            budget.count_entry()?;
            return Ok(Some(Entry::unsupported(
                Self::TRUNCATED_MARKER.to_string(),
                0,
                false,
                "the search for members hidden from the central directory \
                 reached its size limit with space left unexamined",
            )));
        }
        let Some(&(span, off)) = self.orphans.get(n) else {
            return Ok(None);
        };
        let Some((_, buf)) = self.unclaimed.get(span) else {
            return Ok(None);
        };
        parse_local_member(buf, off, budget)
    }

    /// Number of members, including the ones the central directory omits and the
    /// marker for a search that stopped early — the same count `list_entries`
    /// returns, so an index below it is addressable.
    pub fn len(&self) -> usize {
        self.zip.len() + self.orphans.len() + usize::from(self.search_truncated)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pre-parsed member metadata from the central directory. Directories are
    /// included (with `uncompressed_size` 0). No member data is decompressed.
    pub fn list_entries(&mut self) -> Vec<crate::MemberInfo> {
        let mut out = Vec::with_capacity(self.zip.len());
        for i in 0..self.zip.len() {
            if let Ok(file) = self.zip.by_index_raw(i) {
                out.push(crate::MemberInfo {
                    name: file.name().to_string(),
                    index: i,
                    compressed_size: file.compressed_size(),
                    uncompressed_size: file.size(),
                    encrypted: file.encrypted(),
                });
            }
        }
        // The members the directory does not mention. Leaving them out would
        // make a listing say the archive holds less than it does — and a member
        // hidden this way is hidden on purpose.
        out.extend(self.orphan_infos());
        if self.search_truncated {
            out.push(crate::MemberInfo {
                name: Self::TRUNCATED_MARKER.to_string(),
                index: out.len(),
                compressed_size: 0,
                uncompressed_size: 0,
                encrypted: false,
            });
        }
        out
    }

    /// Read and decompress the next *file* member under `budget`; `None` when
    /// the archive is exhausted. Directories are skipped (but still counted
    /// toward the file-count budget).
    pub fn next_member(&mut self, budget: &mut Budget) -> Option<Result<Entry, LimitHit>> {
        while self.next < self.zip.len() {
            let i = self.next;
            self.next += 1;
            if let Err(h) = budget.count_entry() {
                return Some(Err(h));
            }
            match self.extract_entry(i, budget) {
                Ok(Some(e)) => return Some(Ok(e)),
                Ok(None) => continue,
                Err(h) => return Some(Err(h)),
            }
        }
        // A member can be present as a local header and left OUT of the central
        // directory, which hides it from every reader that walks the directory
        // alone — while the tool that opens the archive extracts it anyway. So
        // the walk continues past the directory into what it did not claim.
        while self.next < self.len() {
            let n = self.next - self.zip.len();
            self.next += 1;
            if let Err(h) = budget.count_entry() {
                return Some(Err(h));
            }
            match self.extract_orphan(n, budget) {
                Ok(Some(e)) => return Some(Ok(e)),
                Ok(None) => continue,
                Err(h) => return Some(Err(h)),
            }
        }
        None
    }

    /// Extract a specific member by index. Returns `Ok(None)` for directories.
    pub(crate) fn extract_entry(
        &mut self,
        i: usize,
        budget: &mut Budget,
    ) -> Result<Option<Entry>, LimitHit> {
        // Indices past the directory's own address the members it omits, which
        // `list_entries` reports at exactly these positions.
        if let Some(n) = i.checked_sub(self.zip.len()) {
            return self.extract_orphan(n, budget);
        }
        // Peek with the RAW reader: it never invokes the crate decryptor,
        // so it succeeds for encrypted members too (we build `zip` WITHOUT
        // `aes-crypto`). Cleartext members are re-opened decompressing below.
        let mut file = self
            .zip
            .by_index_raw(i)
            .map_err(|e| zip_entry_error(i, &e))?;
        if !file.is_file() {
            return Ok(None);
        }
        let name = file.name().to_string();
        let comp = file.compressed_size();
        // Encrypted member: try the password pool; on success yield the
        // decrypted+decompressed bytes, else a metadata-only encrypted
        // member so the caller surfaces PasswordProtected (never a panic
        // or an abort that would mask later members).
        if file.encrypted() {
            // See the buffered walker: the false-flag check is cipher-free.
            #[cfg(not(feature = "decrypt"))]
            {
                let crc = file.crc32();
                let plain = read_encrypted_member(&mut file, budget.limits.max_buffer_bytes)
                    .ok()
                    .and_then(|enc| cleartext_despite_flag(&enc, crc));
                drop(file);
                if let Some(plain) = plain {
                    let size = plain.len() as u64;
                    if size <= budget.reserve()? {
                        budget.commit(size);
                        return Ok(Some(Entry {
                            comp_size: comp,
                            encrypted: false,
                            unsupported: None,
                            name,
                            data: plain,
                        }));
                    }
                }
                return Ok(Some(Entry::unsupported(
                    name,
                    comp,
                    true,
                    "encrypted ZIP member",
                )));
            }
            #[cfg(feature = "decrypt")]
            {
                let crc = file.crc32();
                let enc = match read_encrypted_member(&mut file, budget.limits.max_buffer_bytes) {
                    Ok(e) => e,
                    Err(_) => {
                        return Ok(Some(Entry::unsupported(
                            name,
                            comp,
                            true,
                            "encrypted ZIP member",
                        )))
                    }
                };
                drop(file);
                // Disprove the flag before spending password attempts on it —
                // same check the buffered walker runs, for the same reason.
                if let Some(plain) = cleartext_despite_flag(&enc, crc) {
                    let size = plain.len() as u64;
                    if size <= budget.reserve()? {
                        budget.commit(size);
                        return Ok(Some(Entry {
                            comp_size: comp,
                            encrypted: false,
                            unsupported: None,
                            name,
                            data: plain,
                        }));
                    }
                }
                return match decrypt_zip_member(&enc, crc, budget)? {
                    Some(plain) => {
                        budget.commit(plain.len() as u64);
                        // Decrypted: content AND encryption both reported. See the
                        // matching site in the buffered walker.
                        Ok(Some(Entry {
                            comp_size: comp,
                            encrypted: true,
                            unsupported: None,
                            name,
                            data: plain,
                        }))
                    }
                    None => Ok(Some(Entry::unsupported(
                        name,
                        comp,
                        true,
                        "encrypted ZIP member",
                    ))),
                };
            }
        }
        // Cleartext member: re-open decompressing so `bounded_read` yields
        // the *decompressed* content.
        drop(file);
        let mut file = self.zip.by_index(i).map_err(|e| zip_entry_error(i, &e))?;
        // A member too large for the budget yields a metadata-only member
        // (Unscannable, empty data) rather than aborting the archive walk,
        // so name/size `.cdb` sigs still match and later members are scanned.
        let cap = match budget.reserve() {
            Ok(c) => c,
            Err(_) => {
                return Ok(Some(Entry::unsupported(
                    name,
                    comp,
                    false,
                    "archive member exceeds size budget",
                )))
            }
        };
        let (buf, truncated) =
            bounded_read_salvage(&mut file, cap, !budget.should_verify_checksums())
                .map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
        if truncated {
            return Ok(Some(Entry::unsupported(
                name,
                comp,
                false,
                "archive member exceeds size budget",
            )));
        }
        ratio_guard(comp, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        Ok(Some(Entry {
            comp_size: comp,
            encrypted: false,
            unsupported: None,
            name,
            data: buf,
        }))
    }
}

#[cfg(test)]
mod orphan_scan_tests {
    use super::*;

    /// A search that runs out of budget has to SAY so.
    ///
    /// Stopping quietly means the member list is short and nothing marks it as
    /// short — a hidden member goes unreported and the caller reads the result
    /// as the whole archive, which is exactly what an archive built this way is
    /// after. The distinction that matters is "out of budget with space left"
    /// against "reached the end of the list", and only the first is truncation.
    #[test]
    fn a_capped_search_reports_that_it_stopped() {
        let blob = vec![0u8; 4096];

        // Two ranges worth looking at, and only enough budget for the first.
        let spans = [(0u64, 1024u64), (2048, 3072)];
        let (read, truncated) =
            read_spans(&mut Cursor::new(blob.clone()), &spans, 1024).expect("reads");
        assert_eq!(read.len(), 1, "the second range was not read");
        assert!(truncated, "stopped with a range left and did not say so");

        // Enough for both: no truncation, even though the budget is now spent.
        let (read, truncated) =
            read_spans(&mut Cursor::new(blob.clone()), &spans, 2048).expect("reads");
        assert_eq!(read.len(), 2);
        assert!(!truncated, "claimed truncation having read every range");

        // A trailing range too small to hold a header is not truncation: there
        // was never anything there to find.
        let spans = [(0u64, 1024u64), (2048, 2048 + 8)];
        let (_, truncated) = read_spans(&mut Cursor::new(blob), &spans, 1024).expect("reads");
        assert!(
            !truncated,
            "a sub-header-sized tail is not a stopped search"
        );
    }
}

#[cfg(test)]
mod zip_ppmd_tests {
    use super::*;

    /// APPNOTE 5.9 packs the PPMd model parameters into the two bytes that
    /// precede the stream. Getting the bias or the bit split wrong silently
    /// builds the wrong model and decodes garbage, so pin the arithmetic.
    #[test]
    fn ppmd_params_follow_appnote_biases() {
        // order in bits 0-3 (+1), memory MB in bits 4-11 (+1).
        // w = 0x0107 -> order 8, mem 17 MB.
        let raw = [0x07u8, 0x01, 0xAA, 0xBB];
        let (order, mem, body) = zip_ppmd_params(&raw).expect("valid params");
        assert_eq!(order, 8);
        assert_eq!(mem, 17 << 20);
        assert_eq!(
            body,
            &[0xAA, 0xBB],
            "the payload starts after the 2-byte header"
        );
    }

    #[test]
    fn ppmd_params_reject_out_of_range_models() {
        // order field 0 -> order 1, below PPMd7's minimum of 2.
        assert!(zip_ppmd_params(&[0x00, 0x00, 0x00]).is_none());
        // Too short to carry the header at all.
        assert!(zip_ppmd_params(&[0x07]).is_none());
        assert!(zip_ppmd_params(&[]).is_none());
    }

    /// The wiring must be *reached* for method 98, and a payload it cannot
    /// decode must fail visibly rather than be dropped. (A real PPMd-compressed
    /// fixture would need a PPMd encoder, which isn't available here; the
    /// decoder itself is covered by the 7z tests that share it.)
    #[test]
    fn ppmd_member_with_undecodable_payload_does_not_silently_vanish() {
        let mut budget = Budget::new(Limits::default());
        let cap = budget.reserve().unwrap();
        // Valid parameter header, garbage stream.
        let raw = [0x07u8, 0x01, 0xde, 0xad, 0xbe, 0xef];
        assert!(
            decode_zip_raw(98, &raw, 64, cap).is_none(),
            "a corrupt PPMd stream must decode to nothing, so the caller reports it"
        );
    }
}
