#![allow(unused_imports)]
use super::cfb::{self, Compound};
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// OLE2 / Compound File Binary (legacy Office, MSI): emit every stream so the
/// engine can match on macro/object/shellcode content.
///
/// The reader is lenient: a compound file whose directory tree is out of order
/// (e.g. `_VBA_PROJECT` sorted before `dir`), which many real Office documents
/// and malware carry, is read as well as a clean one, so its content is scanned
/// instead of the file being reported as not fully scanned.
pub(crate) fn extract_ole(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let comp = Compound::open(data)
        .ok_or_else(|| LimitHit::new("ole: not a compound file".to_string()))?;
    collect_ole_entries(&comp, data.len() as u64, budget)
}

/// Walk every stream of a compound file and emit it as an [`Entry`], handling MSI
/// name decompression, `.doc`/`.xls`/OOXML encryption detection, and VBA-macro
/// artifact synthesis. `total_len` is the container size (used only for the
/// encrypted-member size field).
fn collect_ole_entries(
    comp: &Compound<'_>,
    total_len: u64,
    budget: &mut Budget,
) -> Result<Vec<Entry>, LimitHit> {
    // A stream entry with no name (a malformed directory) has its sectors
    // inside this same file, uncompressed, where the raw scan of the caller
    // covers them: skipping it loses the name and size, not the content.
    let streams: Vec<cfb::StreamInfo<'_>> = comp.streams().filter(|s| !s.name.is_empty()).collect();

    // Detect MSI database: decompress each stream name and check for `_Tables`.
    let msi = is_msi_database(&streams);

    // Encrypted Office document. A password-protected OOXML file
    // (`.docx`/`.xlsx`/`.pptx`) is wrapped in an OLE2/CFB container holding the
    // MS-OFFCRYPTO `EncryptionInfo` + `EncryptedPackage` streams (the real ZIP is
    // AES-encrypted inside `EncryptedPackage`). Try to DECRYPT (standard ECB and
    // agile AES-CBC) with the default `VelvetSweatshop`/empty password + the caller
    // pool so the real content is scanned; if that fails (wrong password) we still
    // surface an encrypted member — never a silent clean.
    let stream_named = |want: &str| -> Option<&cfb::StreamInfo<'_>> {
        streams.iter().find(|s| s.name.eq_ignore_ascii_case(want))
    };
    // Without `decrypt` there is nothing to hand the streams to, and the
    // member is reported unsupported below without either being read.
    #[cfg_attr(not(feature = "decrypt"), allow(unused_variables))]
    if let (Some(info_s), Some(pkg_s)) = (
        stream_named("EncryptionInfo"),
        stream_named("EncryptedPackage"),
    ) {
        #[cfg(feature = "decrypt")]
        let decrypted = {
            let cap = budget.limits.max_buffer_bytes;
            let info = comp.read(info_s.index, cap);
            let pkg = comp.read(pkg_s.index, cap);
            super::ole_crypto::try_decrypt_ooxml(&info.data, &pkg.data, &budget.passwords)
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

    let mut entries = Vec::new();
    for s in &streams {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let read = comp.read(s.index, cap);
        // A prefix handed over as a whole stream would be a payload past the
        // cap that nothing scanned and nothing reported.
        if read.truncated {
            return Err(LimitHit::new("ole stream exceeds budget".to_string()));
        }
        let (buf, was_decrypted) = match legacy_encryption(s.path, read.data.into_owned(), budget) {
            Legacy::Plain(b) => (b, false),
            Legacy::Decrypted(b) => (b, true),
            Legacy::Locked => {
                entries.push(Entry::unsupported(
                    s.path.to_string(),
                    total_len,
                    true,
                    "encrypted Office document",
                ));
                continue;
            }
        };
        budget.commit(buf.len() as u64);

        // MSI compresses OLE2 stream names to fit longer names into the
        // 31-char OLE2 limit. Decompress if this is an MSI database.
        let name = if msi {
            decompress_msi_name(s.path)
        } else {
            s.path.to_string()
        };
        // A stream we DECRYPTED carries its plaintext and stays marked encrypted.
        // Both facts are true: the content is available to scan, and the document
        // was protected. Reporting only the content is what let a document exav
        // opened with the `VelvetSweatshop` default password come back with no
        // mention of encryption at all — 552 files, 6.3% of a corpus.
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
        for (i, (blob, why)) in ppt_embedded_storages(&e.data, budget)
            .into_iter()
            .enumerate()
        {
            if budget.count_entry().is_err() {
                break;
            }
            budget.commit(blob.len() as u64);
            let mut entry = Entry::new(format!("ppt-embedded-{i}"), blob);
            entry.unsupported = why;
            carved.push(entry);
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
fn ppt_embedded_storages(
    stream: &[u8],
    budget: &mut Budget,
) -> Vec<(Vec<u8>, Option<&'static str>)> {
    /// `RT_ExternalOleObjectStg`.
    const EXT_OLE_OBJ_STG: u16 = 0x1011;
    /// A record tree deep enough to need more steps than this is malformed, and
    /// bounding the walk is cheaper than reasoning about whether it can loop.
    const MAX_RECORDS: usize = 100_000;

    let mut out = Vec::new();
    let mut off = 0usize;
    for _ in 0..MAX_RECORDS {
        let Some(hdr) = crate::bytes::at(stream, off, 8) else {
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
        if rec_type == EXT_OLE_OBJ_STG
            && let Some(body) = crate::bytes::at(stream, off + 8, len)
            && let Some(blob) = ppt_storage_payload(ver_instance >> 4, body, budget)
        {
            out.push(blob);
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

/// One storage record's bytes: stored as-is, or inflated, bounded by the
/// budget, and why they are not the whole storage when they are not.
fn ppt_storage_payload(
    instance: u16,
    body: &[u8],
    budget: &mut Budget,
) -> Option<(Vec<u8>, Option<&'static str>)> {
    const OVER: &str = "embedded PowerPoint storage exceeds the per-member budget";
    const BROKEN: &str = "embedded PowerPoint storage could not be decompressed";
    const PART_WAY: &str = "embedded PowerPoint storage failed to decompress part way; \
                            the bytes before the failure were scanned";
    let cap = budget.reserve().ok()?;
    if instance == 0 {
        // Stored. The record is the compound file.
        return Some(if body.len() as u64 <= cap {
            (body.to_vec(), None)
        } else {
            (Vec::new(), Some(OVER))
        });
    }
    // Compressed: a declared size then a zlib stream. The declared size is a
    // hint from the file, so it is not trusted for allocation — the read is
    // bounded by the budget and salvages a truncated tail, which is how a
    // deliberately-truncated object still gets scanned rather than dropped.
    let deflated = body.get(4..)?;
    let Some(zlib) = crate::inflate::zlib_body(deflated) else {
        return Some((Vec::new(), Some(BROKEN)));
    };
    let s = bounded_read_salvage(zlib, cap, true).ok()?;
    let why = match (s.over_cap, s.undecoded, s.data.is_empty()) {
        (true, _, _) => Some(OVER),
        (_, true, true) => Some(BROKEN),
        (_, true, false) => Some(PART_WAY),
        // Nothing decoded and nothing left undecoded: an empty storage.
        (_, false, true) => return None,
        (_, false, false) => None,
    };
    Some((s.data, why))
}

/// The payload bytes inside an `Ole10Native` stream, or `None` when the header
/// does not hold together.
///
/// Layout: `NativeDataSize` u32, `Flags` u16, then `Label` and `FileName` as
/// NUL-terminated byte strings. Office then writes a reserved u32, the temp
/// path as a u32 length and that many bytes, and the data's u32 size; some
/// writers give the temp path as a bare NUL-terminated string instead. The
/// strings are attacker-controlled, so every step is bounds-checked and the
/// declared size is clamped to what is actually present rather than trusted.
fn ole10native_payload(data: &[u8]) -> Option<&[u8]> {
    let le32 = |p: usize| {
        crate::bytes::at(data, p, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let past_string = |p: usize| Some(p + data.get(p..)?.iter().position(|&b| b == 0)? + 1);
    let names = past_string(past_string(4 + 2)?)?;
    // A reserved word then a counted, NUL-terminated temp path, all of the
    // data after it; read so only when every part of that holds.
    let counted = le32(names + 4)
        .filter(|&len| len > 0)
        .and_then(|len| (names + 8).checked_add(len))
        .filter(|&at| data.get(at - 1) == Some(&0))
        .filter(|&at| le32(at).is_some_and(|size| size > 0 && size <= data.len() - at - 4));
    let at = match counted {
        Some(at) => at,
        None => past_string(names)?,
    };
    let size = le32(at)?;
    let start = at + 4;
    let take = size.min(data.len().checked_sub(start)?);
    (take > 0).then(|| &data[start..start + take])
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

/// A stream after the legacy `.doc`/`.xls` encryption check.
enum Legacy {
    Plain(Vec<u8>),
    #[cfg_attr(not(feature = "decrypt"), allow(dead_code))]
    Decrypted(Vec<u8>),
    /// Encrypted, and no password or scheme exav has opens it.
    Locked,
}

/// Check the stream at `path` for legacy Office encryption, and decrypt an
/// Excel workbook with the default `VelvetSweatshop` or a pool password.
///
/// Word sets `fEncrypted` (0x0100) in the flags word at offset 0x0A of
/// `WordDocument`; Excel puts a `FilePass` record after the `BOF` of a
/// `Workbook`/`Book` stream. Every such stream is checked, an embedded
/// workbook's as well as the document's own. The encryption covers that
/// stream alone: the VBA project and the other streams are in the clear.
fn legacy_encryption(path: &str, data: Vec<u8>, budget: &Budget) -> Legacy {
    let leaf = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let is_word = leaf.eq_ignore_ascii_case("worddocument");
    let is_excel = leaf.eq_ignore_ascii_case("workbook") || leaf.eq_ignore_ascii_case("book");
    let encrypted = if is_word {
        data.len() >= 12 && (u16::from_le_bytes([data[10], data[11]]) & 0x0100) != 0
    } else {
        is_excel && xls_has_filepass(&data)
    };
    if !encrypted {
        return Legacy::Plain(data);
    }
    #[cfg(feature = "decrypt")]
    if is_excel && let Some(dec) = super::ole_crypto::try_decrypt_workbook(&data, &budget.passwords)
    {
        return Legacy::Decrypted(dec);
    }
    #[cfg(not(feature = "decrypt"))]
    let _ = budget;
    Legacy::Locked
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
fn is_msi_database(streams: &[cfb::StreamInfo<'_>]) -> bool {
    streams.iter().any(|s| {
        let d = decompress_msi_name(s.name);
        d == "_Tables" || d == "!_Tables"
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

    /// A storage record hands over its bytes, and says so whenever they are
    /// not all of it.
    #[test]
    fn a_ppt_storage_says_when_it_is_not_whole() {
        use std::io::Write;
        let compressed = |payload: &[u8]| {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(payload).unwrap();
            let mut body = (payload.len() as u32).to_le_bytes().to_vec();
            body.extend(e.finish().unwrap());
            body
        };
        let mut b = Budget::new(Limits::default());

        let intact = compressed(b"storage");
        let got = ppt_storage_payload(1, &intact, &mut b).unwrap();
        assert_eq!(got, (b"storage".to_vec(), None));

        let mut bad_adler = intact.clone();
        let n = bad_adler.len();
        bad_adler[n - 1] ^= 1;
        let got = ppt_storage_payload(1, &bad_adler, &mut b).unwrap();
        assert_eq!(got, (b"storage".to_vec(), None));

        // Damaged after a long run of content: that run, and a reason.
        let content: Vec<u8> = (0..20_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&content).unwrap();
        e.flush().unwrap();
        let mut damaged = vec![0, 0, 0, 0, 0x78, 0x9c];
        damaged.extend_from_slice(e.get_ref());
        damaged.extend_from_slice(&[0x06, 0x5a, 0x5a]);
        let (data, why) = ppt_storage_payload(1, &damaged, &mut b).unwrap();
        assert_eq!(data, content);
        assert!(why.is_some_and(|w| w.contains("part way")), "{why:?}");

        let (data, why) = ppt_storage_payload(1, b"\0\0\0\0not zlib", &mut b).unwrap();
        assert!(data.is_empty() && why.is_some());

        let mut small = Budget::new(Limits {
            max_buffer_bytes: 4,
            ..Limits::default()
        });
        let (data, why) = ppt_storage_payload(0, b"stored storage", &mut small).unwrap();
        assert!(data.is_empty() && why.is_some());
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
