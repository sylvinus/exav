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
        C::Shrink => 1,
        C::Reduce(n) => 1 + u16::from(*n),
        C::Implode => 6,
        C::Deflated => 8,
        C::Unsupported(n) => *n,
        _ => 0xffff,
    }
}

/// Whether the `zip` crate itself decodes `method`: Store, Deflate, and the
/// PKZIP 1.x methods. Other codecs go to [`raw_decoder`].
fn crate_decodes(method: u16) -> bool {
    matches!(method, 0..=6 | 8)
}

/// Shrink, Reduce and Implode (methods 1-6) are decoded whole by the `zip`
/// crate: it reads the compressed bytes whole, then reserves the declared
/// size for the output. Both sizes come from the archive, so both have to fit
/// the buffer limit before the member is opened.
fn decoded_whole_too_big(method: u16, comp: u64, size: u64, max_buffer: u64) -> bool {
    (1..=6).contains(&method) && comp.max(size) > max_buffer
}

/// Why [`raw_decoder`] gave no decoder for a member.
pub(crate) enum RawRefusal {
    /// No decoder for this method in this build, or its header is malformed.
    Unsupported(&'static str),
    /// Decoding needs more memory than `--max-object-bytes` allows.
    TooBig,
}

/// A decoder, over a member's RAW compressed bytes, for a method the `zip`
/// crate itself can't decode, using exav's own decoders, so a payload behind
/// a codec the crate lacks is still scanned. The member is decoded as it is
/// read. `usz` is the declared uncompressed size (LZMA's decode target).
/// `max_buffer` bounds what a decoder allocates up front.
#[allow(unused_variables, unused_mut)]
pub(crate) fn raw_decoder<'a, R: Read + 'a>(
    method: u16,
    mut raw: R,
    usz: u64,
    max_buffer: u64,
) -> Result<Box<dyn Read + 'a>, RawRefusal> {
    const MALFORMED: RawRefusal = RawRefusal::Unsupported("malformed zip member header");
    match method {
        // Method 9 = Deflate64 ("enhanced deflate"): deflate with a 64 KiB
        // window, length code 285 redefined to take 16 extra bits (lengths up to
        // 65538), and distance codes 30/31 made valid (14 extra bits, distances
        // up to 64 KiB). Produced by 7-Zip (`-mm=Deflate64`) and by Windows'
        // own compressed-folder writer, and decoded by ClamAV. The member bytes
        // are a raw stream (no wrapper), exactly like method 8.
        9 => Ok(Box::new(deflate64::Deflate64Decoder::new(raw))),
        // APPNOTE 5.8.8: 2-byte version, 2-byte props-size (=5), then the 5-byte
        // LZMA properties (1 lc/lp/pb byte + 4-byte dict size), then the stream.
        #[cfg(feature = "lzip")]
        14 => {
            let mut hdr = [0u8; 9];
            raw.read_exact(&mut hdr).map_err(|_| MALFORMED)?;
            let declared = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
            // The dictionary is allocated up front. One larger than the output
            // is never consulted, so the output size bounds it for free; past
            // that, it is memory this scan may not claim.
            if u64::from(declared).min(usz) > max_buffer {
                return Err(RawRefusal::TooBig);
            }
            let dict = crate::bounded_dict(declared, usz);
            lzma_rust2::LzmaReader::new_with_props(raw, usz, hdr[4], dict, None)
                .map(|r| Box::new(r) as Box<dyn Read + 'a>)
                .map_err(|_| MALFORMED)
        }
        #[cfg(feature = "bzip2")]
        12 => Ok(Box::new(super::bzip2_rs::DecoderReader::new(raw))),
        #[cfg(feature = "zstd")]
        93 => ruzstd::decoding::StreamingDecoder::new(raw)
            .map(|r| Box::new(r) as Box<dyn Read + 'a>)
            .map_err(|_| MALFORMED),
        // Method 95 = XZ: the raw member bytes are a complete .xz stream.
        #[cfg(feature = "xz")]
        95 => Ok(Box::new(super::xz::XzReader::new(raw))),
        // Method 98 = PPMd var.H, the variant 7z uses, so it reuses the in-tree
        // PPMd7 decoder. ZIP packs the model parameters into a 2-byte
        // little-endian header at the front of the member data (APPNOTE 5.9)
        // instead of carrying them in coder properties as 7z does.
        #[cfg(feature = "sevenz")]
        98 => {
            let mut hdr = [0u8; 2];
            raw.read_exact(&mut hdr).map_err(|_| MALFORMED)?;
            let (order, mem_size) = zip_ppmd_params(hdr).ok_or(MALFORMED)?;
            match super::sevenz::decode::Ppmd7ZReader::new(raw, order, mem_size, max_buffer) {
                Ok(r) => Ok(Box::new(r)),
                Err(e) if e.is_corrupt() => Err(MALFORMED),
                Err(_) => Err(RawRefusal::TooBig),
            }
        }
        _ => Err(RawRefusal::Unsupported(
            "unsupported zip compression method",
        )),
    }
}

/// [`raw_decoder`] over bytes in hand, read whole up to `cap`. `None` when
/// there is no decoder or decoding failed; the flag is set when the member
/// is larger than `cap`.
pub(crate) fn decode_zip_raw(
    method: u16,
    raw: &[u8],
    usz: u64,
    cap: u64,
) -> Option<(Vec<u8>, bool)> {
    match raw_decoder(method, raw, usz, cap) {
        Ok(r) => bounded_read(r, cap).ok(),
        Err(RawRefusal::TooBig) => Some((Vec::new(), true)),
        Err(RawRefusal::Unsupported(_)) => None,
    }
}

/// A ZIP method-98 (PPMd) member's model parameters, from its 2-byte header.
///
/// APPNOTE 5.9: a little-endian word precedes the data: order in bits 0-3
/// (biased by 1), model memory in MB in bits 4-11 (biased by 1), and the
/// restoration method in bits 12-15. Only the parameters matter here; the
/// restoration method is a property of the encoder's model resets, which the
/// decoder follows from the stream itself.
fn zip_ppmd_params(hdr: [u8; 2]) -> Option<(u32, u32)> {
    let w = u16::from_le_bytes(hdr);
    let order = (w & 0x0f) as u32 + 1;
    let mem_mb = ((w >> 4) & 0xff) as u32 + 1;
    // Guard the shift as well as the decoder's own range check: 256 MB is the
    // format's maximum and already far past anything legitimate.
    if !(2..=64).contains(&order) || mem_mb > 256 {
        return None;
    }
    Some((order, mem_mb << 20))
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
        Err(e) if !e.is_corrupt() => return Err(e),
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
pub fn overlapping_local_records(data: &dyn crate::source::ByteSource) -> usize {
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
        ::zip::ZipArchive::new(crate::source::Reader::new(data))
            .ok()
            .map(|mut z| {
                (0..z.len())
                    .filter_map(|i| z.by_index_raw(i).ok().map(|f| f.header_start() as usize))
                    .collect()
            });

    let mut extents: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0usize;
    while pos + LFH_LEN <= data.len() && extents.len() < MAX_RECORDS {
        let Some(off) = data.find(b"PK\x03\x04", pos, data.len()) else {
            break;
        };
        pos = off + 4;
        if declared.as_ref().is_some_and(|d| !d.contains(&off)) {
            continue;
        }
        // The header and its name: all `plausible_header_at` reads.
        let h = data.window(off, LFH_LEN + MAX_NAME);
        if !plausible_header_at(&h, data.len() - off) {
            continue;
        }
        let h = &h[..LFH_LEN];
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

/// Whether `data` holds a ZIP with a consistent central directory: an
/// end-of-central-directory record, and every directory entry pointing at a
/// local header with the same name. Offsets may count from the archive or from
/// an earlier start, as they do in an archive appended to another file. ZIP64
/// is not followed, so answers `false`.
pub fn directory_is_consistent(data: &[u8]) -> bool {
    const EOCD_LEN: usize = 22;
    const CDH_LEN: usize = 46;
    let u16_at = |p: usize| {
        data.get(p..p + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let u32_at = |p: usize| {
        data.get(p..p + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let tail = data.len().saturating_sub(EOCD_LEN + usize::from(u16::MAX));
    let Some(eocd) = data[tail..]
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .map(|p| tail + p)
    else {
        return false;
    };
    let (Some(entries), Some(cd_size), Some(cd_off)) =
        (u16_at(eocd + 10), u32_at(eocd + 12), u32_at(eocd + 16))
    else {
        return false;
    };
    if entries == 0 || entries == 0xffff || cd_size == 0xffff_ffff || cd_off == 0xffff_ffff {
        return false;
    }
    let Some(cd_start) = eocd.checked_sub(cd_size) else {
        return false;
    };
    // Where offset 0 of the archive's own numbering sits in `data`.
    let base = cd_start as i64 - cd_off as i64;
    let mut p = cd_start;
    for _ in 0..entries {
        if data.get(p..p + 4) != Some(b"PK\x01\x02") {
            return false;
        }
        let (Some(n), Some(e), Some(c), Some(local)) = (
            u16_at(p + 28),
            u16_at(p + 30),
            u16_at(p + 32),
            u32_at(p + 42),
        ) else {
            return false;
        };
        let Some(name) = data.get(p + CDH_LEN..p + CDH_LEN + n) else {
            return false;
        };
        let Ok(lo) = usize::try_from(base + local as i64) else {
            return false;
        };
        if data.get(lo..lo + 4) != Some(b"PK\x03\x04")
            || u16_at(lo + 26) != Some(n)
            || data.get(lo + LFH_LEN..lo + LFH_LEN + n) != Some(name)
        {
            return false;
        }
        p += CDH_LEN + n + e + c;
    }
    p == eocd
}

/// Does the `PK\x03\x04` at `off` look like a genuine local file header rather
/// than a chance byte sequence? Checks the fields a real writer must fill in
/// consistently; deliberately strict, because every false positive here becomes
/// a spurious `UNSCANNABLE` on an otherwise ordinary file.
fn plausible_local_header(data: &[u8], off: usize) -> bool {
    data.get(off..)
        .is_some_and(|rest| plausible_header_at(rest, rest.len()))
}

/// Longest local-header name taken for a real one.
const MAX_NAME: usize = 4096;

/// [`plausible_local_header`] given `rest`, the bytes from the header on (at
/// least `LFH_LEN + MAX_NAME` of them, or up to the end of the archive), and
/// `left`, how many bytes the archive holds from the header on.
fn plausible_header_at(rest: &[u8], left: usize) -> bool {
    let Some(h) = rest.get(..LFH_LEN) else {
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
    if name_len == 0 || name_len > MAX_NAME {
        return false;
    }
    let Some(name) = rest.get(LFH_LEN..LFH_LEN + name_len) else {
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
    left >= LFH_LEN + name_len + extra_len
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
            match bounded_read_salvage(crate::inflate::Inflate::new(raw), PROBE_MAX as u64, true) {
                Ok(s) if !s.over_cap => s.data,
                _ => return false,
            }
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
    let (out, part_way) = match method {
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
        0 => (raw.get(..comp).unwrap_or(raw).to_vec(), false),
        8 => {
            // Salvage the bytes decoded before any corruption rather than
            // dropping the whole member: this is a best-effort recovery of a
            // malformed archive, and the payload a signature matches may sit in
            // the valid prefix (matching clamd, which scans partial inflate).
            let s = bounded_read_salvage(crate::inflate::Inflate::new(raw), cap, true)
                .map_err(|e| LimitHit::corrupt(format!("orphan zip inflate: {e}")))?;
            // Over the per-member cap. Yield metadata-only rather than the
            // prefix (which would read as a complete member) and rather than
            // aborting, so the remaining orphans are still scanned — the same
            // shape the central-directory path uses for an oversized member.
            if s.over_cap {
                return Ok(Some(Entry::unsupported(
                    name,
                    comp as u64,
                    false,
                    "orphan zip member exceeds size budget",
                )));
            }
            (s.data, s.undecoded)
        }
        _ => match decode_zip_raw(method, raw, usz, cap) {
            Some((o, false)) => (o, false),
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
        unsupported: part_way.then_some(PART_WAY),
        name,
        data: out,
    }))
}

/// Why a ZIP member's entry holds only part of its content.
const PART_WAY: &str =
    "zip member failed to decode part way; the bytes before the failure were scanned";

/// A cleartext member's content. Stored and deflated members are decoded here
/// rather than by the crate: its deflate reader drops what it decoded in the
/// call that meets damage, and its CRC-32 failure is not told apart from
/// damage. Other codecs go through the crate as before.
pub(crate) fn member_reader<'a, R: Read + Seek>(
    zip: &'a mut ::zip::ZipArchive<R>,
    i: usize,
) -> ::zip::result::ZipResult<Box<dyn Read + 'a>> {
    use crate::inflate::{CrcCheck, Inflate};
    use ::zip::CompressionMethod as C;
    let method = zip.by_index_raw(i)?.compression();
    if !matches!(method, C::Stored | C::Deflated) {
        return Ok(Box::new(zip.by_index(i)?));
    }
    let raw = zip.by_index_raw(i)?;
    let crc = raw.crc32();
    Ok(if method == C::Stored {
        Box::new(CrcCheck::new(raw, crc))
    } else {
        Box::new(CrcCheck::new(Inflate::new(BufReader::new(raw)), crc))
    })
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
                if !hit.is_corrupt() {
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
        let (buf, truncated, part_way) = if !crate_decodes(method) {
            let (raw, _) = bounded_read(&mut file, budget.limits.max_buffer_bytes)
                .map_err(|e| LimitHit::new(format!("zip raw read: {e}")))?;
            drop(file);
            match decode_zip_raw(method, &raw, usz, cap) {
                Some((out, truncated)) => (out, truncated, false),
                None => {
                    if let Some(r) = oversized(budget, "archive member: unsupported ZIP codec") {
                        return Ok(Some(r));
                    }
                    continue;
                }
            }
        } else {
            // Re-open with the decoding reader (the raw reader returns
            // still-compressed bytes).
            drop(file);
            if decoded_whole_too_big(method, comp, usz, cap) {
                if let Some(r) = oversized(budget, "archive member exceeds size budget") {
                    return Ok(Some(r));
                }
                continue;
            }
            let mut file = match member_reader(&mut zip, i) {
                Ok(f) => f,
                Err(_) => {
                    if let Some(r) = oversized(budget, "archive member: ZIP decode failed") {
                        return Ok(Some(r));
                    }
                    continue;
                }
            };
            let s = bounded_read_salvage(&mut file, cap, !budget.should_verify_checksums())
                .map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
            drop(file);
            (s.data, s.over_cap, s.undecoded)
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
            unsupported: part_way.then_some(PART_WAY),
            name,
            data: buf,
        };
        if let Some(r) = visit(entry, budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
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

/// Walk a ZIP off its source. Only the central directory and the members
/// actually read are fetched. A cleartext member is handed over as the
/// crate's decompressing reader, so a member decompressing to any size is
/// never held. An encrypted member is decrypted whole (decryption needs the
/// full ciphertext), bounded by the buffer limit.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::stream::{emit_entry, emit_stream, whole, MemberMeta};
    // A forged or corrupt central directory (a bad CDFH offset in the EOCD,
    // say) makes the seekable walk impossible, but the members' local file
    // headers are still in the file. Fall back to reading the archive whole
    // and the local-header salvage, so a malformed archive still has its
    // members scanned rather than being written off (matching clamd).
    let mut zip = match ::zip::ZipArchive::new(crate::source::Reader::new(src)) {
        Ok(z) => z,
        Err(_) => return whole(Format::Zip, src, budget, visit),
    };
    // A member left unread for a limit is reported after the rest are scanned.
    let mut deferred = None;
    for i in 0..zip.len() {
        budget.count_entry()?;
        // Peek metadata with the RAW reader: it never invokes the crate
        // decryptor, so it succeeds for encrypted members too.
        // A member whose header will not parse costs only itself (the same
        // guard as in `extract_zip_from`). Abandoning the walk here would
        // strand every later member: the salvage pass skips them as already
        // covered, so a payload behind one bad directory pointer would never
        // be scanned.
        if let Err(e) = zip.by_index_raw(i).map(|_| ()) {
            let hit = zip_entry_error(i, &e);
            if !hit.is_corrupt() {
                return Err(hit);
            }
            let meta = MemberMeta {
                name: format!("zip entry {i}"),
                comp_size: 0,
                size: None,
                encrypted: false,
                unsupported: Some("ZIP member header will not parse"),
            };
            if let Some(t) = visit(&meta, None, budget) {
                return Ok(Some(t));
            }
            continue;
        }
        let (name, is_file, encrypted, comp, size, method) = {
            let f = zip.by_index_raw(i).map_err(|e| zip_entry_error(i, &e))?;
            (
                f.name().to_string(),
                f.is_file(),
                f.encrypted(),
                f.compressed_size(),
                f.size(),
                zip_method_code(&f.compression()),
            )
        };
        // `is_file()` is false purely because the name ends in '/'. A JAR packer
        // buys exactly that: `kingDavid/9.class/` holds a real deflate-compressed
        // class that the JVM loads by name, while every ZIP tool discards it as a
        // folder. Skip only what carries nothing at all: a "directory" with
        // content is content. (The same guard lives in `extract_zip_from`.)
        if !is_file && comp == 0 {
            continue; // directory: counted toward the file budget above, skipped
        }
        let meta = MemberMeta {
            name,
            comp_size: comp,
            size: Some(size),
            encrypted,
            unsupported: None,
        };
        if encrypted {
            if let Some(t) = walk_encrypted(&mut zip, i, meta, budget, visit)? {
                return Ok(Some(t));
            }
            continue;
        }
        let max_buffer = budget.limits.max_buffer_bytes;
        if decoded_whole_too_big(method, comp, size, max_buffer) {
            deferred.get_or_insert_with(|| {
                LimitHit::new(format!(
                    "zip member '{}' is decoded whole and is larger than \
                     --max-object-bytes {max_buffer}",
                    meta.name
                ))
            });
            continue;
        }
        // A codec the `zip` crate lacks fails here rather than in our own
        // decoder, so fall back to the raw bytes and decode them ourselves,
        // as `extract_zip_from` does. Probe first so the borrow of `zip` ends
        // before the fallback needs it.
        let decodable = zip.by_index(i).is_ok();
        let mut file = match decodable {
            true => member_reader(&mut zip, i).map_err(|e| zip_entry_error(i, &e))?,
            false => {
                let out = walk_raw_decode(&mut zip, i, meta, budget, visit, &mut deferred)?;
                if let Some(t) = out {
                    return Ok(Some(t));
                }
                continue;
            }
        };
        if let Some(t) = emit_stream(&meta, &mut file, budget, visit)? {
            return Ok(Some(t));
        }
    }
    // Members left out of the central directory while their local headers and
    // data stay in the file, which is what the target extracts.
    for entry in hidden_members(zip, budget)? {
        if let Some(t) = emit_entry(entry, budget, visit)? {
            return Ok(Some(t));
        }
    }
    deferred.map_or(Ok(None), Err)
}

/// Decode a member the `zip` crate refused, from its RAW bytes, using exav's own
/// codec set, as it is read. The member is visited once: decoded, or as a
/// marker saying why it could not be. A decoder needing more memory than the
/// buffer limit leaves the member unread, and the limit goes in `deferred`
/// for the walk to report once the other members are scanned.
fn walk_raw_decode<R: Read + Seek, T>(
    zip: &mut ::zip::ZipArchive<R>,
    i: usize,
    mut meta: crate::stream::MemberMeta,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
    deferred: &mut Option<LimitHit>,
) -> Result<Option<T>, LimitHit> {
    let cap = budget.limits.max_buffer_bytes;
    let f = match zip.by_index_raw(i) {
        Ok(f) => f,
        Err(_) => {
            meta.unsupported = Some("ZIP member header will not parse");
            return Ok(visit(&meta, None, budget));
        }
    };
    let method = zip_method_code(&f.compression());
    let usz = f.size();
    match raw_decoder(method, f, usz, cap) {
        Ok(mut r) => crate::stream::emit_stream(&meta, &mut r, budget, visit),
        Err(RawRefusal::Unsupported(reason)) => {
            meta.unsupported = Some(reason);
            Ok(visit(&meta, None, budget))
        }
        Err(RawRefusal::TooBig) => {
            deferred.get_or_insert_with(|| {
                LimitHit::new(format!(
                    "zip member '{}' needs more memory to decode than \
                     --max-object-bytes {cap}",
                    meta.name
                ))
            });
            Ok(None)
        }
    }
}

/// One encrypted ZIP member: try the password pool and hand over the
/// plaintext on success, else a metadata-only unsupported member, so the
/// caller reports it without masking later members.
fn walk_encrypted<R: Read + Seek, T>(
    zip: &mut ::zip::ZipArchive<R>,
    i: usize,
    meta: crate::stream::MemberMeta,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::stream::{emit_bytes, MemberMeta};
    let unsupported_meta = MemberMeta {
        encrypted: true,
        unsupported: Some("encrypted ZIP member"),
        ..meta.clone()
    };
    // Disprove the flag BEFORE any `decrypt` gating: the check decrypts nothing,
    // it proves by CRC-32 that these bytes were never ciphertext.
    let max_buffer = budget.limits.max_buffer_bytes;
    let (crc, enc) = {
        let mut f = zip.by_index_raw(i).map_err(|e| zip_entry_error(i, &e))?;
        let crc = f.crc32();
        match read_encrypted_member(&mut f, max_buffer) {
            Ok(e) => (crc, e),
            Err(_) => return Ok(visit(&unsupported_meta, None, budget)),
        }
    };
    // The bit can lie: an APK packer sets it on every member because
    // Android's ZIP reader ignores it, buying a PASSWORD-PROTECTED report on
    // an archive the platform installs happily. A CRC-32 match over a plain
    // decode proves the bytes were never encrypted.
    if let Some(plain) = cleartext_despite_flag(&enc, crc) {
        budget.commit(plain.len() as u64);
        let meta = MemberMeta {
            encrypted: false,
            ..meta
        };
        return emit_bytes(&meta, Some(plain), budget, visit);
    }
    // Actually encrypted. Without the `decrypt` feature there is no cipher
    // stack compiled in, so report it: never decrypted, never silently clean.
    #[cfg(not(feature = "decrypt"))]
    {
        Ok(visit(&unsupported_meta, None, budget))
    }
    #[cfg(feature = "decrypt")]
    {
        match decrypt_zip_member(&enc, crc, budget)? {
            Some(plain) => {
                budget.commit(plain.len() as u64);
                // Decrypted: the plaintext is scanned AND the member is still
                // reported as having been encrypted.
                emit_bytes(&meta, Some(plain), budget, visit)
            }
            None => Ok(visit(&unsupported_meta, None, budget)),
        }
    }
}

/// The members `zip`'s central directory omits, decoded, for a walk that has
/// already been through the ones it lists.
///
/// The streaming counterpart of the buffered path's orphan scan, over the same
/// bounded search [`ZipMembers`] uses: only the space the directory leaves
/// unaccounted for is read, up to [`MAX_ORPHAN_SCAN`], and a search that stops
/// there yields a member saying so.
pub(crate) fn hidden_members<Rd: Read + Seek>(
    mut zip: ::zip::ZipArchive<Rd>,
    budget: &mut Budget,
) -> Result<Vec<Entry>, LimitHit> {
    let (gaps, known) = unclaimed_spans(&mut zip);
    if gaps.is_empty() {
        return Ok(Vec::new());
    }
    let mut reader = zip.into_inner();
    let (unclaimed, truncated) = read_spans(&mut reader, &gaps, MAX_ORPHAN_SCAN)?;
    let mut out = Vec::new();
    for (span, off) in find_orphans(&unclaimed, &known) {
        if let Some(entry) = parse_local_member(&unclaimed[span].1, off, budget)? {
            out.push(entry);
        }
    }
    if truncated {
        budget.count_entry()?;
        out.push(Entry::unsupported(
            HIDDEN_SEARCH_TRUNCATED.to_string(),
            0,
            false,
            "the search for members hidden from the central directory \
             reached its size limit with space left unexamined",
        ));
    }
    Ok(out)
}

/// The member that says the search for hidden members stopped at its limit.
const HIDDEN_SEARCH_TRUNCATED: &str = "<hidden-member search stopped at its limit>";

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
mod directory_tests {
    use super::*;
    use std::io::Write;

    fn two_member_zip() -> Vec<u8> {
        let mut z = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in ["a.txt", "b.txt"] {
            z.start_file(name, ::zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(b"hello").unwrap();
        }
        z.finish().unwrap().into_inner()
    }

    /// Add `by` to the directory offset and to every entry's local offset,
    /// as `zip -A` does after prepending `by` bytes.
    fn shift_offsets(zip: &mut [u8], by: u32) {
        let eocd = zip.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap();
        let entries: Vec<usize> = zip
            .windows(4)
            .enumerate()
            .filter(|(_, w)| *w == b"PK\x01\x02")
            .map(|(p, _)| p + 42)
            .collect();
        for p in std::iter::once(eocd + 16).chain(entries) {
            let v = u32::from_le_bytes(zip[p..p + 4].try_into().unwrap()) + by;
            zip[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
    }

    #[test]
    fn an_appended_archive_is_consistent_under_either_numbering() {
        let zip = two_member_zip();
        assert!(directory_is_consistent(&zip));
        let prefix = [0x42u8; 100];
        assert!(directory_is_consistent(&[&prefix[..], &zip[..]].concat()));
        let mut shifted = zip.clone();
        shift_offsets(&mut shifted, 100);
        assert!(directory_is_consistent(
            &[&prefix[..], &shifted[..]].concat()
        ));
    }

    #[test]
    fn a_directory_that_does_not_match_its_members_is_not_consistent() {
        let zip = two_member_zip();
        let cd = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        assert!(!directory_is_consistent(&zip[..cd]));
        let mut renamed = zip.clone();
        renamed[cd + 46] = b'z';
        assert!(!directory_is_consistent(&renamed));
        assert!(!directory_is_consistent(b"xxPK\x03\x04garbage"));
        assert!(!directory_is_consistent(b""));
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
        let (order, mem) = zip_ppmd_params([0x07, 0x01]).expect("valid params");
        assert_eq!(order, 8);
        assert_eq!(mem, 17 << 20);
    }

    #[test]
    fn ppmd_params_reject_out_of_range_models() {
        // order field 0 -> order 1, below PPMd7's minimum of 2.
        assert!(zip_ppmd_params([0x00, 0x00]).is_none());
        // Too short to carry the header at all.
        for raw in [&[0x07u8][..], &[]] {
            assert!(decode_zip_raw(98, raw, 64, 1 << 20).is_none());
        }
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
