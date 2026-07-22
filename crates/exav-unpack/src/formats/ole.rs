#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// OLE2 / Compound File Binary (legacy Office, MSI): emit every stream so the
/// engine can match on macro/object/shellcode content.
pub(crate) fn extract_ole(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    match cfb::CompoundFile::open(Cursor::new(data)) {
        Ok(comp) => collect_ole_entries(comp, data.len() as u64, budget),
        // A strict CFB reader rejects compound files that violate the spec — most
        // commonly a broken red-black-tree sibling ordering in the directory (e.g.
        // `_VBA_PROJECT` sorted before `dir`), which many real Office documents and
        // malware carry. The streams are still readable; fall back to a lenient flat
        // directory walk (ClamAV-style) so we scan the content instead of returning
        // "not fully scanned". Only surface the error if it is not a compound file.
        Err(e) => match lenient_cfb_streams(data, budget.limits.max_buffer_bytes) {
            Some(streams) => assemble_ole_entries(streams, data.len() as u64, budget),
            None => Err(LimitHit::new(format!("ole: {e}"))),
        },
    }
}

/// Open a CFB compound file over a **seekable source** (the reader-based
/// streaming path): the whole `.doc`/`.xls`/`.msi` file is never buffered — cfb
/// walks the FAT chains with seeks, and each stream is read on demand. Returns
/// the same members as [`extract_ole`].
///
/// Staged: the unpack-layer capability is ready, but core routing is gated on the
/// streamed member-scan path replicating OLE-specific handling (VBA-macro
/// heuristics + textual-type forcing) — see the module notes — so it is not yet
/// called. Wiring it without that would risk false positives on benign macros.
#[allow(dead_code)]
pub(crate) fn stream_ole_entries<R: Read + Seek>(
    mut source: R,
    budget: &mut Budget,
) -> Result<Vec<Entry>, LimitHit> {
    let total = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("ole: {e}")))?;
    source
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("ole: {e}")))?;
    let comp = cfb::CompoundFile::open(source).map_err(|e| LimitHit::new(format!("ole: {e}")))?;
    collect_ole_entries(comp, total, budget)
}

/// Walk every stream of a compound file and emit it as an [`Entry`], handling MSI
/// name decompression, `.doc`/`.xls`/OOXML encryption detection, and VBA-macro
/// artifact synthesis. Shared by the buffered ([`extract_ole`]) and seekable
/// ([`stream_ole_entries`]) entry points. `total_len` is the container size (used
/// only for the encrypted-member size field).
fn collect_ole_entries<R: Read + Seek>(
    mut comp: cfb::CompoundFile<R>,
    total_len: u64,
    budget: &mut Budget,
) -> Result<Vec<Entry>, LimitHit> {
    let paths: Vec<std::path::PathBuf> = comp
        .walk()
        .filter(|e| e.is_stream())
        .map(|e| e.path().to_path_buf())
        .collect();

    // Detect MSI database: decompress each stream name and check for `_Tables`.
    let msi = is_msi_database(&paths);

    // Encrypted Office document. A password-protected OOXML file
    // (`.docx`/`.xlsx`/`.pptx`) is wrapped in an OLE2/CFB container holding the
    // MS-OFFCRYPTO `EncryptionInfo` + `EncryptedPackage` streams (the real ZIP is
    // AES-encrypted inside `EncryptedPackage`). Try to DECRYPT (standard ECB and
    // agile AES-CBC) with the default `VelvetSweatshop`/empty password + the caller
    // pool so the real content is scanned; if that fails (wrong password) we still
    // surface an encrypted member — never a silent clean.
    let stream_named = |want: &str| -> Option<std::path::PathBuf> {
        paths
            .iter()
            .find(|p| {
                p.file_name()
                    .map(|s| s.to_string_lossy().eq_ignore_ascii_case(want))
                    .unwrap_or(false)
            })
            .cloned()
    };
    if let (Some(info_p), Some(pkg_p)) = (
        stream_named("EncryptionInfo"),
        stream_named("EncryptedPackage"),
    ) {
        let mut read_full = |p: &std::path::Path| -> Option<Vec<u8>> {
            let s = comp.open_stream(p).ok()?;
            bounded_read(s, budget.limits.max_buffer_bytes)
                .ok()
                .map(|(b, _)| b)
        };
        #[cfg(feature = "decrypt")]
        let decrypted = match (read_full(&info_p), read_full(&pkg_p)) {
            (Some(info), Some(pkg)) => {
                super::ole_crypto::try_decrypt_ooxml(&info, &pkg, &budget.passwords)
            }
            _ => None,
        };
        #[cfg(not(feature = "decrypt"))]
        let decrypted: Option<Vec<u8>> = None;
        budget.count_entry()?;
        return match decrypted {
            Some(zip) => {
                budget.commit(zip.len() as u64);
                // Emit the recovered OOXML .zip so the ZIP path scans its parts.
                Ok(vec![Entry::new("EncryptedPackage.zip".to_string(), zip)])
            }
            None => Ok(vec![Entry::unsupported(
                "EncryptedPackage".to_string(),
                total_len,
                true,
                "encrypted Office document",
            )]),
        };
    }

    // Legacy `.doc`/`.xls`: the encryption bit lives in the stream's header.
    // Word's FIB sets `fEncrypted` (0x0100) in the 16-bit flags word at offset
    // 0x0A of the `WordDocument` stream; Excel marks it with a `FilePass` (0x2F)
    // record near the start of the `Workbook`/`Book` stream. Detect either — and
    // for Excel additionally try to DECRYPT (RC4-basic, incl. the default
    // `VelvetSweatshop` password) so the real content is scanned instead of being
    // reported password-protected. When decryption succeeds the plaintext stream
    // is substituted into the loop below; when it fails (wrong scheme / password)
    // we surface an encrypted member — never a silent clean.
    let mut decrypted_workbook: Option<(std::path::PathBuf, Vec<u8>)> = None;
    if let Some(p) = paths.iter().find(|p| {
        let n = p
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        n == "worddocument" || n == "workbook" || n == "book"
    }) {
        let is_word = p
            .file_name()
            .map(|s| s.to_string_lossy().eq_ignore_ascii_case("worddocument"))
            .unwrap_or(false);
        if let Ok(s) = comp.open_stream(p) {
            // Read the whole stream (Excel decryption needs it all); bounded by
            // the peak-buffer cap.
            let (wb, truncated) = bounded_read(s, budget.limits.max_buffer_bytes)
                .map_err(|e| LimitHit::new(format!("ole read: {e}")))?;
            let encrypted = if is_word {
                wb.len() >= 12 && (u16::from_le_bytes([wb[10], wb[11]]) & 0x0100) != 0
            } else {
                xls_has_filepass(&wb)
            };
            if encrypted {
                let decrypted = if !is_word && !truncated {
                    #[cfg(feature = "decrypt")]
                    {
                        super::ole_crypto::try_decrypt_workbook(&wb, &budget.passwords)
                    }
                    #[cfg(not(feature = "decrypt"))]
                    {
                        None
                    }
                } else {
                    None
                };
                match decrypted {
                    Some(dec) => decrypted_workbook = Some((p.clone(), dec)),
                    None => {
                        budget.count_entry()?;
                        return Ok(vec![Entry::unsupported(
                            p.to_string_lossy().into_owned(),
                            total_len,
                            true,
                            "encrypted Office document",
                        )]);
                    }
                }
            }
        }
    }

    let mut entries = Vec::new();
    for p in &paths {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        // Use the decrypted plaintext for the Workbook/Book stream if we cracked it.
        let (buf, truncated) = match &decrypted_workbook {
            Some((wp, dec)) if wp == p => (dec.clone(), dec.len() as u64 > cap),
            _ => {
                let stream = comp
                    .open_stream(p)
                    .map_err(|e| LimitHit::new(format!("ole stream: {e}")))?;
                bounded_read(stream, cap).map_err(|e| LimitHit::new(format!("ole read: {e}")))?
            }
        };
        if truncated {
            return Err(LimitHit::new("ole stream exceeds budget".to_string()));
        }
        budget.commit(buf.len() as u64);

        // MSI compresses OLE2 stream names to fit longer names into the
        // 31-char OLE2 limit. Decompress if this is an MSI database.
        let name = if msi {
            let full = p.to_string_lossy();
            decompress_msi_name(&full)
        } else {
            p.to_string_lossy().into_owned()
        };
        // A stream we DECRYPTED carries its plaintext and stays marked encrypted.
        // Both facts are true: the content is available to scan, and the document
        // was protected. Reporting only the content is what let a document exav
        // opened with the `VelvetSweatshop` default password come back with no
        // mention of encryption at all — 552 files, 6.3% of a corpus.
        let was_decrypted = matches!(&decrypted_workbook, Some((wp, _)) if wp == p);
        let mut entry = Entry::new(name, buf);
        entry.encrypted = was_decrypted;
        entries.push(entry);
    }

    append_ole10native_payloads(&mut entries, budget);
    // Before the macro pass: an embedded storage can itself hold the VBA
    // project, and the artifacts are synthesised from whatever is present.
    append_ppt_embedded_storages(&mut entries, budget);
    append_macro_artifacts(&mut entries, budget);
    Ok(entries)
}

/// Carve the payload out of every `\x01Ole10Native` stream and append it.
///
/// `Ole10Native` is how Office stores a "Package" embedded object — the thing you
/// get by dropping a file onto a document. The stream is NOT the file: it opens
/// with an embedded-object header (a 4-byte total size, a 2-byte flag, then three
/// NUL-terminated strings — label, original path, temp path — and a 4-byte
/// payload size) and only then the bytes themselves.
///
/// Nothing looked past that header, and the format sniffer only ever inspects
/// offset 0, so an embedded executable or compound file was invisible. Measured:
/// 13 corpus documents carried an encrypted OLE2 this way that exav never saw,
/// and the detection was already correct once the payload was carved by hand.
/// It is a routine malware-delivery shape, so the value is well beyond those 13.
fn append_ole10native_payloads(entries: &mut Vec<Entry>, budget: &mut Budget) {
    let mut carved: Vec<Entry> = Vec::new();
    for e in entries.iter() {
        // Stream names arrive as paths (`/\x01Ole10Native`), and the `\x01`
        // prefix marks the stream as an OLE-reserved one; match on the leaf with
        // both stripped.
        let leaf = e
            .name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&e.name)
            .trim_start_matches('\u{1}');
        if !leaf.eq_ignore_ascii_case("Ole10Native") {
            continue;
        }
        let Some(payload) = ole10native_payload(&e.data) else {
            continue;
        };
        if budget.count_entry().is_err() {
            break;
        }
        let Ok(cap) = budget.reserve() else { break };
        if payload.len() as u64 > cap {
            continue;
        }
        budget.commit(payload.len() as u64);
        carved.push(Entry::new(format!("{leaf}-payload"), payload.to_vec()));
    }
    entries.extend(carved);
}

/// Inflate every object PowerPoint 97 embedded in its own record stream and
/// append it.
///
/// A `.ppt` is a compound file, but its interesting content is not in the
/// streams — it is in a *record tree* inside the single `PowerPoint Document`
/// stream. An embedded object (a VBA project, or any OLE object dropped into a
/// slide) lives there as an `RT_ExternalOleObjectStg` record holding a whole
/// compound file, usually deflated. Emitting the streams alone stops at the
/// container: the object is present, readable, and invisible.
///
/// Measured: three corpus documents where `clamd` reported
/// `Heuristics.OLE2.ContainsMacros.VBA` and exav said nothing. Their CFB
/// directory has five streams and no VBA storage; the macro project is a
/// 10,752-byte compound file deflated inside one of these records, and exav's
/// own OLE reader decompresses the module source from it once it is handed over.
/// The value is wider than macros — *any* embedded object was unreachable.
fn append_ppt_embedded_storages(entries: &mut Vec<Entry>, budget: &mut Budget) {
    let mut carved: Vec<Entry> = Vec::new();
    for e in entries.iter() {
        let leaf = e.name.rsplit(['/', '\\']).next().unwrap_or(&e.name);
        if !leaf.eq_ignore_ascii_case("PowerPoint Document") {
            continue;
        }
        for (i, blob) in ppt_embedded_storages(&e.data, budget)
            .into_iter()
            .enumerate()
        {
            if budget.count_entry().is_err() {
                break;
            }
            budget.commit(blob.len() as u64);
            carved.push(Entry::new(format!("ppt-embedded-{i}"), blob));
        }
    }
    entries.extend(carved);
}

/// Walk a `PowerPoint Document` record tree and return the payload of every
/// `RT_ExternalOleObjectStg` record, inflating the compressed form.
///
/// A record header is `[verInstance:u16][type:u16][length:u32]`. The low nibble
/// of `verInstance` is the version, and `0xF` marks a *container* whose body is
/// more records — so a container is descended into rather than skipped, which is
/// how a record nested three levels down is reached at all. The instance (the
/// high twelve bits) selects the storage form: `0` is stored, `1` is
/// `[uncompressedSize:u32]` followed by a zlib stream.
fn ppt_embedded_storages(stream: &[u8], budget: &mut Budget) -> Vec<Vec<u8>> {
    /// `RT_ExternalOleObjectStg`.
    const EXT_OLE_OBJ_STG: u16 = 0x1011;
    /// A record tree deep enough to need more steps than this is malformed, and
    /// bounding the walk is cheaper than reasoning about whether it can loop.
    const MAX_RECORDS: usize = 100_000;

    let mut out = Vec::new();
    let mut off = 0usize;
    for _ in 0..MAX_RECORDS {
        let Some(hdr) = stream.get(off..off + 8) else {
            break;
        };
        let ver_instance = u16::from_le_bytes([hdr[0], hdr[1]]);
        let rec_type = u16::from_le_bytes([hdr[2], hdr[3]]);
        let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        // A container's body is more records, so step *into* it.
        if ver_instance & 0x0f == 0x0f {
            off += 8;
            continue;
        }
        if rec_type == EXT_OLE_OBJ_STG {
            if let Some(body) = stream.get(off + 8..off + 8 + len) {
                if let Some(blob) = ppt_storage_payload(ver_instance >> 4, body, budget) {
                    out.push(blob);
                }
            }
        }
        // `len` is attacker-controlled; a wrapping step would walk the stream
        // again from the top.
        match off.checked_add(8).and_then(|o| o.checked_add(len)) {
            Some(next) if next > off => off = next,
            _ => break,
        }
    }
    out
}

/// One storage record's bytes: stored as-is, or inflated, bounded by the budget.
fn ppt_storage_payload(instance: u16, body: &[u8], budget: &mut Budget) -> Option<Vec<u8>> {
    let cap = budget.reserve().ok()?;
    if instance == 0 {
        // Stored. The record is the compound file.
        return (body.len() as u64 <= cap).then(|| body.to_vec());
    }
    // Compressed: a declared size then a zlib stream. The declared size is a
    // hint from the file, so it is not trusted for allocation — the read is
    // bounded by the budget and salvages a truncated tail, which is how a
    // deliberately-truncated object still gets scanned rather than dropped.
    let deflated = body.get(4..)?;
    let (data, _truncated) = bounded_read_salvage(
        flate2::read::ZlibDecoder::new(Cursor::new(deflated)),
        cap,
        true,
    )
    .ok()?;
    (!data.is_empty()).then_some(data)
}

/// The payload bytes inside an `Ole10Native` stream, or `None` when the header
/// does not hold together.
///
/// Layout ([MS-OLEDS] 2.3.6): `NativeDataSize` u32, `Flags` u16, then `Label`,
/// `FileName` and `Reserved`/temp path as NUL-terminated byte strings, then
/// `NativeDataSize2` u32 and the data. The strings are attacker-controlled, so
/// every step is bounds-checked and the declared size is clamped to what is
/// actually present rather than trusted.
fn ole10native_payload(data: &[u8]) -> Option<&[u8]> {
    let mut p = 4usize + 2; // total size + flags
    for _ in 0..3 {
        let rel = data.get(p..)?.iter().position(|&b| b == 0)?;
        p += rel + 1;
    }
    let size_bytes = data.get(p..p + 4)?;
    let size =
        u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]) as usize;
    p += 4;
    let avail = data.len().checked_sub(p)?;
    let take = size.min(avail);
    (take > 0).then(|| &data[p..p + take])
}

/// Synthesize VBA/XLM macro text artifacts from the extracted OLE streams and
/// append them to `entries`. Shared by the strict cfb path ([`collect_ole_entries`])
/// and the lenient fallback ([`assemble_ole_entries`]).
///
/// If the document carries a VBA project, decompress its macros and emit two text
/// artifacts: the `REM`-headed dump (code-lowercased, for `Doc.*` macro sigs) and
/// the raw original-case source (for `Target:2` OLE sigs like `Attribute VB_Name
/// =`/`CreateObject`). Excel 4.0 (XLM) macros live in a BIFF macro sheet, not a
/// VBA project, so they evade VBA-only detection — surface an `xlm_macro` artifact
/// when the workbook carries a macro sheet.
fn append_macro_artifacts(entries: &mut Vec<Entry>, budget: &mut Budget) {
    // Compute both macro artifacts while `streams` (which borrows `entries`) is
    // alive, *before* pushing anything back into `entries`.
    let (vba_arts, xlm_art) = {
        let streams: Vec<(String, &[u8])> = entries
            .iter()
            .map(|e| (e.name.clone(), e.data.as_slice()))
            .collect();
        let vba = super::vba::build_artifacts(&streams, budget.limits.max_buffer_bytes);
        let xlm = super::xlm::xlm_macro_artifact(&streams);
        (vba, xlm)
    };

    if let Some((dump, raw)) = vba_arts {
        for (name, art) in [("vba_project", dump), ("vba_project_raw", raw)] {
            push_artifact(entries, budget, name, art);
        }
    }

    if let Some(art) = xlm_art {
        push_artifact(entries, budget, "xlm_macro", art);
    }
}

/// Append one macro artifact, or say why it could not be appended.
///
/// Dropping the artifact quietly would be worst here of anywhere: the artifact
/// *is* the decompressed macro source, so losing it leaves the document scanned
/// as an opaque OLE container, coming back clean. A budget that is exhausted, or
/// an artifact bigger than the per-member cap, surfaces as a limit rather than
/// as nothing.
fn push_artifact(entries: &mut Vec<Entry>, budget: &mut Budget, name: &str, art: Vec<u8>) {
    // Nothing to scan: no macro of this kind in the document.
    if art.is_empty() {
        return;
    }
    let size = art.len() as u64;
    if budget.count_entry().is_err() {
        entries.push(Entry::unsupported(
            name.to_string(),
            size,
            false,
            "macro source not scanned: the archive-wide file count was exhausted",
        ));
        return;
    }
    // `reserve` failing is a limit, not an absence — treating it as a cap of
    // zero silently discarded every artifact.
    let Ok(cap) = budget.reserve() else {
        entries.push(Entry::unsupported(
            name.to_string(),
            size,
            false,
            "macro source not scanned: the extraction budget was exhausted",
        ));
        return;
    };
    if size > cap {
        entries.push(Entry::unsupported(
            name.to_string(),
            size,
            false,
            "macro source exceeds the per-member size budget",
        ));
        return;
    }
    budget.commit(size);
    entries.push(Entry::new(name.to_string(), art));
}

// ---------------------------------------------------------------------------
// Lenient (fault-tolerant) Compound File Binary reader
// ---------------------------------------------------------------------------
//
// Clean-room implementation of the [MS-CFB] container just far enough to
// recover stream *contents* from a compound file whose directory red-black tree
// is malformed (bad sibling ordering, adjacent red nodes, etc.). A strict reader
// aborts on such files; here we ignore the tree structure entirely and walk the
// directory sectors as a flat array of 128-byte entries, following the FAT and
// mini-FAT sector chains to reassemble each stream. Written purely from the
// public [MS-CFB] specification.

const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// Highest value that names a real sector; everything above is a sentinel
/// (`FREESECT`/`ENDOFCHAIN`/`FATSECT`/`DIFSECT`/`NOSTREAM`).
const CFB_MAXREGSECT: u32 = 0xFFFF_FFFA;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// Parse a Compound File Binary tolerantly, returning `(stream leaf name, bytes)`
/// for every directory entry marked as a stream. Returns `None` if `data` is not
/// a compound file (bad signature / too small) so the caller can report the
/// original strict-parse error instead of masking a genuine non-OLE input.
///
/// `cap` bounds the bytes read for any single stream (the peak-buffer limit).
/// Each stream comes back as `(name, bytes, truncated)`. The flag matters: the
/// readers below stop at `cap`, and a prefix delivered as a whole stream would
/// hide whatever sits past it.
fn lenient_cfb_streams(data: &[u8], cap: u64) -> Option<Vec<(String, Vec<u8>, bool)>> {
    if data.len() < 512 || data[..8] != CFB_SIGNATURE {
        return None;
    }
    let sector_shift = le16(data, 30);
    if !(7..=24).contains(&sector_shift) {
        return None;
    }
    let sector_size = 1usize << sector_shift; // v3 = 512, v4 = 4096
    let mini_shift = le16(data, 32);
    if !(3..=12).contains(&mini_shift) {
        return None;
    }
    let mini_sector_size = 1usize << mini_shift; // normally 64
    let v4 = le16(data, 26) >= 4;
    let first_dir = le32(data, 48);
    let mini_cutoff = le32(data, 56) as u64; // normally 4096
    let first_minifat = le32(data, 60);
    let first_difat = le32(data, 68);

    let entries_per_sector = sector_size / 4;
    // Upper bound on how many sectors any chain can traverse (loop guard).
    let max_sectors = data.len() / sector_size + 2;

    let read_sector = |s: u32| -> Option<&[u8]> {
        // Sector N begins at byte offset (N + 1) * sector_size (the header
        // occupies the first sector regardless of version).
        let off = (s as usize).checked_add(1)?.checked_mul(sector_size)?;
        data.get(off..off.checked_add(sector_size)?)
    };

    // --- Assemble the DIFAT (list of FAT sector numbers) ---------------------
    let mut fat_sectors: Vec<u32> = Vec::new();
    for i in 0..109 {
        let v = le32(data, 76 + i * 4);
        if v <= CFB_MAXREGSECT {
            fat_sectors.push(v);
        }
    }
    let mut difat = first_difat;
    let mut guard = 0;
    while difat <= CFB_MAXREGSECT && guard < max_sectors {
        guard += 1;
        let Some(sec) = read_sector(difat) else { break };
        for i in 0..entries_per_sector - 1 {
            let v = le32(sec, i * 4);
            if v <= CFB_MAXREGSECT {
                fat_sectors.push(v);
            }
        }
        difat = le32(sec, (entries_per_sector - 1) * 4);
        if fat_sectors.len() > max_sectors {
            break;
        }
    }

    // --- Build the FAT -------------------------------------------------------
    let mut fat: Vec<u32> = Vec::with_capacity(fat_sectors.len() * entries_per_sector);
    for &fs in &fat_sectors {
        match read_sector(fs) {
            Some(sec) => {
                for i in 0..entries_per_sector {
                    fat.push(le32(sec, i * 4));
                }
            }
            None => break,
        }
    }
    if fat.is_empty() {
        return None;
    }

    // Follow a FAT sector chain, bounded to avoid cycles on corrupt tables.
    let follow = |start: u32| -> Vec<u32> {
        let mut out = Vec::new();
        let mut cur = start;
        while cur <= CFB_MAXREGSECT && (cur as usize) < fat.len() && out.len() < max_sectors {
            out.push(cur);
            cur = fat[cur as usize];
        }
        out
    };
    let read_fat_stream = |start: u32, size: u64| -> Vec<u8> {
        let need = size.min(cap) as usize;
        let mut out = Vec::with_capacity(need.min(1 << 20));
        for s in follow(start) {
            if out.len() >= need {
                break;
            }
            if let Some(sec) = read_sector(s) {
                let take = sec.len().min(need - out.len());
                out.extend_from_slice(&sec[..take]);
            }
        }
        out.truncate(need);
        out
    };

    // --- Directory sectors (flat array of 128-byte entries) ------------------
    let mut dir = Vec::new();
    for s in follow(first_dir) {
        if let Some(sec) = read_sector(s) {
            dir.extend_from_slice(sec);
        }
    }
    let n_entries = dir.len() / 128;
    if n_entries == 0 {
        return None;
    }

    // Root entry (object type 5) anchors the mini stream.
    let mut root_start = 0u32;
    let mut root_size = 0u64;
    for i in 0..n_entries {
        let e = &dir[i * 128..i * 128 + 128];
        if e[66] == 5 {
            root_start = le32(e, 116);
            root_size = if v4 {
                le64(e, 120)
            } else {
                le32(e, 120) as u64
            };
            break;
        }
    }
    let mini_stream = read_fat_stream(root_start, root_size);

    // --- Mini-FAT ------------------------------------------------------------
    let mut minifat: Vec<u32> = Vec::new();
    for s in follow(first_minifat) {
        if let Some(sec) = read_sector(s) {
            for i in 0..entries_per_sector {
                minifat.push(le32(sec, i * 4));
            }
        }
        if minifat.len() > max_sectors * entries_per_sector {
            break;
        }
    }
    let read_mini_stream = |start: u32, size: u64| -> Vec<u8> {
        let need = size.min(cap) as usize;
        let mut out = Vec::with_capacity(need.min(1 << 16));
        let mut cur = start;
        let mut steps = 0;
        while cur <= CFB_MAXREGSECT && (cur as usize) < minifat.len() && out.len() < need {
            steps += 1;
            if steps > minifat.len() + 1 {
                break; // cycle guard
            }
            let off = (cur as usize) * mini_sector_size;
            if let Some(chunk) = mini_stream.get(off..off + mini_sector_size) {
                let take = chunk.len().min(need - out.len());
                out.extend_from_slice(&chunk[..take]);
            }
            cur = minifat[cur as usize];
        }
        out.truncate(need);
        out
    };

    // --- Collect every stream entry ------------------------------------------
    let mut streams = Vec::new();
    for i in 0..n_entries {
        let e = &dir[i * 128..i * 128 + 128];
        if e[66] != 2 {
            continue; // only streams (2); skip storage (1)/root (5)/unallocated (0)
        }
        let name_len = le16(e, 64) as usize;
        let name = cfb_entry_name(&e[..64], name_len);
        if name.is_empty() {
            // A nameless stream entry (malformed directory). Its sectors are
            // stored UNCOMPRESSED inside this same file, so the caller's raw
            // pattern scan already covers those bytes — skipping the member here
            // loses the name/size metadata for `.cdb` matching, not the content,
            // so nothing goes unscanned by skipping it here.
            continue;
        }
        let start = le32(e, 116);
        let size = if v4 {
            le64(e, 120)
        } else {
            le32(e, 120) as u64
        };
        let bytes = if size < mini_cutoff {
            read_mini_stream(start, size)
        } else {
            read_fat_stream(start, size)
        };
        // Both readers stop at `cap`. Compare what came back with what the
        // directory entry declared: short means the budget cut the stream, and
        // the caller has to be told, because a prefix handed over as a whole
        // stream is a payload past the cap that nothing ever scanned and
        // nothing ever reported.
        let truncated = (bytes.len() as u64) < size;
        streams.push((name, bytes, truncated));
        if streams.len() >= 4096 {
            break;
        }
    }
    if streams.is_empty() {
        return None;
    }
    Some(streams)
}

/// Decode a directory entry name: `name_len` bytes of UTF-16LE from a 64-byte
/// field, including the terminating NUL (so the character count is
/// `name_len / 2 - 1`).
fn cfb_entry_name(raw: &[u8], name_len: usize) -> String {
    let chars = (name_len / 2).saturating_sub(1).min(32);
    let mut u16s = Vec::with_capacity(chars);
    for i in 0..chars {
        u16s.push(le16(raw, i * 2));
    }
    String::from_utf16_lossy(&u16s)
}

/// Build the OLE [`Entry`] list from an already-extracted stream set (each a leaf
/// name with its raw bytes). Mirrors the tail of [`collect_ole_entries`] but
/// operates purely in memory, so it serves the lenient fallback path. Handles MSI
/// name decompression, OOXML/legacy encryption detection + decryption, and VBA/XLM
/// macro artifacts.
fn assemble_ole_entries(
    streams: Vec<(String, Vec<u8>, bool)>,
    total_len: u64,
    budget: &mut Budget,
) -> Result<Vec<Entry>, LimitHit> {
    let leaf = |n: &str| -> String { n.rsplit(['/', '\\']).next().unwrap_or(n).to_string() };
    let find = |want: &str| -> Option<&Vec<u8>> {
        streams
            .iter()
            .find(|(n, _, _)| leaf(n).eq_ignore_ascii_case(want))
            .map(|(_, d, _)| d)
    };

    let msi = streams.iter().any(|(n, _, _)| {
        let d = decompress_msi_name(&leaf(n));
        d == "_Tables" || d == "!_Tables"
    });

    // OOXML encrypted container: decrypt the standard scheme or surface an
    // encrypted member — never a silent clean.
    if let (Some(info), Some(pkg)) = (find("EncryptionInfo"), find("EncryptedPackage")) {
        #[cfg(feature = "decrypt")]
        let decrypted = super::ole_crypto::try_decrypt_ooxml(
            info.as_slice(),
            pkg.as_slice(),
            &budget.passwords,
        );
        #[cfg(not(feature = "decrypt"))]
        let decrypted: Option<Vec<u8>> = None;
        budget.count_entry()?;
        return match decrypted {
            Some(zip) => {
                budget.commit(zip.len() as u64);
                Ok(vec![Entry::new("EncryptedPackage.zip".to_string(), zip)])
            }
            None => Ok(vec![Entry::unsupported(
                "EncryptedPackage".to_string(),
                total_len,
                true,
                "encrypted Office document",
            )]),
        };
    }

    // Legacy `.doc`/`.xls` encryption.
    let mut decrypted_workbook: Option<(String, Vec<u8>)> = None;
    if let Some((wname, wb, _)) = streams.iter().find(|(n, _, _)| {
        let l = leaf(n).to_ascii_lowercase();
        l == "worddocument" || l == "workbook" || l == "book"
    }) {
        let is_word = leaf(wname).eq_ignore_ascii_case("worddocument");
        let encrypted = if is_word {
            wb.len() >= 12 && (u16::from_le_bytes([wb[10], wb[11]]) & 0x0100) != 0
        } else {
            xls_has_filepass(wb)
        };
        if encrypted {
            let decrypted = if !is_word {
                #[cfg(feature = "decrypt")]
                {
                    super::ole_crypto::try_decrypt_workbook(wb, &budget.passwords)
                }
                #[cfg(not(feature = "decrypt"))]
                {
                    None
                }
            } else {
                None
            };
            match decrypted {
                Some(dec) => decrypted_workbook = Some((wname.clone(), dec)),
                None => {
                    budget.count_entry()?;
                    return Ok(vec![Entry::unsupported(
                        leaf(wname),
                        total_len,
                        true,
                        "encrypted Office document",
                    )]);
                }
            }
        }
    }

    let mut entries = Vec::new();
    for (name, data, truncated) in streams {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let buf = match &decrypted_workbook {
            Some((wn, dec)) if *wn == name => dec.clone(),
            _ => data,
        };
        if buf.len() as u64 > cap {
            return Err(LimitHit::new("ole stream exceeds budget".to_string()));
        }
        budget.commit(buf.len() as u64);
        let out_name = if msi {
            decompress_msi_name(&leaf(&name))
        } else {
            leaf(&name)
        };
        // A stream the reader had to cut short is reported alongside the part
        // that fits, the same way an over-budget safetensors header is. Handing
        // back only the prefix would let a payload past the cap go unscanned
        // with nothing said about it.
        if truncated {
            entries.push(Entry::unsupported(
                out_name.clone(),
                buf.len() as u64,
                false,
                "stream exceeds the per-member size budget; only its head was read",
            ));
        }
        // Decrypted streams stay marked encrypted — same rule as the strict path
        // above, applied here too because the lenient fallback is the one a
        // malformed compound file actually takes.
        let was_decrypted = matches!(&decrypted_workbook, Some((wn, _)) if *wn == name);
        let mut entry = Entry::new(out_name, buf);
        entry.encrypted = was_decrypted;
        entries.push(entry);
    }

    append_ole10native_payloads(&mut entries, budget);
    // Before the macro pass: an embedded storage can itself hold the VBA
    // project, and the artifacts are synthesised from whatever is present.
    append_ppt_embedded_storages(&mut entries, budget);
    append_macro_artifacts(&mut entries, budget);
    Ok(entries)
}

/// True if an Excel BIFF8 `Workbook`/`Book` stream is encrypted: a `FilePass`
/// record (type 0x002F) appears as (or near) the first record after the opening
/// `BOF` (0x0809). BIFF records are `[type:u16][len:u16][body]`.
fn xls_has_filepass(head: &[u8]) -> bool {
    // Expect a BOF first.
    if head.len() < 4 || u16::from_le_bytes([head[0], head[1]]) != 0x0809 {
        return false;
    }
    let mut pos = 0usize;
    // Walk a handful of records; FilePass is the first record after BOF when set.
    for _ in 0..8 {
        if pos + 4 > head.len() {
            break;
        }
        let rectype = u16::from_le_bytes([head[pos], head[pos + 1]]);
        let reclen = u16::from_le_bytes([head[pos + 2], head[pos + 3]]) as usize;
        if rectype == 0x002F {
            return true;
        }
        pos += 4 + reclen;
    }
    false
}

/// Check if an OLE2 compound file is an MSI database by testing whether any
/// stream name decompresses to `_Tables` (WiX uses `!_Tables` prefix).
fn is_msi_database(paths: &[std::path::PathBuf]) -> bool {
    paths.iter().any(|p| {
        p.file_name()
            .map(|s| {
                let d = decompress_msi_name(&s.to_string_lossy());
                d == "_Tables" || d == "!_Tables"
            })
            .unwrap_or(false)
    })
}

/// Decompress an MSI-compressed OLE2 stream name.
///
/// The Windows Installer compresses OLE2 stream names to fit longer table names
/// into the 31-character OLE2 directory entry limit (doubling capacity to ~63).
/// This undocumented algorithm encodes characters using UTF-16 code points:
///
/// - 0x3800..0x4800: encodes **two** characters via bit packing:
///   `code[(cp - 0x3800) & 0x3F]` and `code[((cp - 0x3800) >> 6) & 0x3F]`
/// - 0x4800..=0x4840: encodes **one** character: `code[cp - 0x4800]`
/// - All other code points pass through unchanged.
///
/// The code table is `0-9 A-Z a-z . _ !` (65 entries; index 64 = `!` can only
/// appear as a single-char encoding since 6-bit indices max at 63).
pub(crate) fn decompress_msi_name(name: &str) -> String {
    const CODE: &[u8; 65] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._!";
    let mut result = String::with_capacity(name.len());
    for c in name.chars() {
        let cp = c as u32;
        if (0x3800..0x4800).contains(&cp) {
            let v = cp - 0x3800;
            let lo = (v & 0x3F) as usize;
            let hi = ((v >> 6) & 0x3F) as usize;
            if lo < CODE.len() {
                result.push(CODE[lo] as char);
            }
            if hi < CODE.len() {
                result.push(CODE[hi] as char);
            }
        } else if (0x4800..=0x4840).contains(&cp) {
            let idx = (cp - 0x4800) as usize;
            if idx < CODE.len() {
                result.push(CODE[idx] as char);
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::decompress_msi_name;

    #[test]
    fn decompress_single_char_encoding() {
        // U+4840 = 0x4800 + 64 = CODE[64] = '!'
        assert_eq!(decompress_msi_name("\u{4840}"), "!");
    }

    #[test]
    fn decompress_pair_encoding() {
        // 'F' = index 15, 'i' = index 44
        // packed = 0x3800 + 15 + (44 << 6) = 0x3800 + 15 + 2816 = 0x430F
        assert_eq!(decompress_msi_name("\u{430F}"), "Fi");
    }

    #[test]
    fn decompress_passthrough_for_ascii() {
        assert_eq!(decompress_msi_name("WordDocument"), "WordDocument");
        assert_eq!(
            decompress_msi_name("\x05DigitalSignature"),
            "\x05DigitalSignature"
        );
    }

    #[test]
    fn decompress_known_exclamation_file() {
        // !File = '!' (U+4840) + 'Fi' (U+430F) + 'le' (U+422F)
        let compressed = "\u{4840}\u{430F}\u{422F}";
        assert_eq!(decompress_msi_name(compressed), "!File");
    }
}

#[cfg(test)]
mod macro_artifact_tests {
    use super::*;
    use crate::Limits;

    /// Every path out of [`push_artifact`] must either deliver the artifact or
    /// say why it could not.
    ///
    /// This is the VBA/XLM macro *source*, so a quiet drop leaves the document
    /// scanned as an opaque OLE container and reported clean with its macros
    /// never examined. The case is reachable in the ordinary way: VBA
    /// decompression expands, and `vba_project` concatenates every module, so a
    /// document whose raw streams all fit the per-member cap can still produce
    /// an artifact that does not.
    #[test]
    fn an_artifact_is_delivered_or_explained_but_never_dropped() {
        // Comfortably within budget: delivered.
        let mut b = Budget::new(Limits::default());
        let mut e = Vec::new();
        push_artifact(&mut e, &mut b, "vba_project", vec![b'x'; 1000]);
        assert_eq!(e.len(), 1);
        assert!(e[0].unsupported.is_none() && e[0].data.len() == 1000);

        // Larger than the per-member cap: reported, not dropped.
        let mut b = Budget::new(Limits {
            max_buffer_bytes: 16,
            ..Limits::default()
        });
        let mut e = Vec::new();
        push_artifact(&mut e, &mut b, "vba_project", vec![b'x'; 1000]);
        assert_eq!(e.len(), 1, "an oversized artifact must still be reported");
        assert!(
            e[0].unsupported.is_some(),
            "and reported as unreadable, not handed over"
        );
        assert_eq!(
            e[0].comp_size, 1000,
            "with its real size, so the report is actionable"
        );
    }

    #[test]
    fn an_absent_macro_is_not_reported() {
        // No macro of this kind in the document: nothing to scan, nothing to say.
        let mut b = Budget::new(Limits::default());
        let mut e = Vec::new();
        push_artifact(&mut e, &mut b, "xlm_macro", Vec::new());
        assert!(e.is_empty());
    }
}
