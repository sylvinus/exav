#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// OLE2 / Compound File Binary (legacy Office, MSI): emit every stream so the
/// engine can match on macro/object/shellcode content.
pub(crate) fn extract_ole(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let comp = cfb::CompoundFile::open(Cursor::new(data))
        .map_err(|e| LimitHit::new(format!("ole: {e}")))?;
    collect_ole_entries(comp, data.len() as u64, budget)
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

    // Encrypted Office document detection. A password-protected OOXML file
    // (`.docx`/`.xlsx`/`.pptx`) is wrapped in an OLE2/CFB container holding the
    // MS-OFFCRYPTO `EncryptionInfo` + `EncryptedPackage` streams (the real ZIP is
    // AES-encrypted inside `EncryptedPackage`). We don't decrypt it (the agile
    // KDF needs a full MS-OFFCRYPTO implementation) — but we must not treat the
    // ciphertext streams as clean. Emit an encrypted signal → `PasswordProtected`.
    let has_encrypted_package = paths.iter().any(|p| {
        let n = p
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        n == "encryptedpackage" || n == "encryptioninfo"
    });
    if has_encrypted_package {
        budget.count_entry()?;
        return Ok(vec![Entry::unsupported(
            "EncryptedPackage".to_string(),
            total_len,
            true,
            "encrypted Office document",
        )]);
    }

    // Legacy `.doc`/`.xls`: the encryption bit lives in the stream's header.
    // Word's FIB sets `fEncrypted` (0x0100) in the 16-bit flags word at offset
    // 0x0A of the `WordDocument` stream; Excel marks it with a `FilePass` (0x2F)
    // record near the start of the `Workbook`/`Book` stream. Detect either.
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
        if let Ok(mut s) = comp.open_stream(p) {
            let mut head = [0u8; 8192];
            let n = read_fill(&mut s, &mut head);
            let head = &head[..n];
            let encrypted = if is_word {
                head.len() >= 12 && (u16::from_le_bytes([head[10], head[11]]) & 0x0100) != 0
            } else {
                xls_has_filepass(head)
            };
            if encrypted {
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

    let mut entries = Vec::new();
    for p in &paths {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let stream = comp
            .open_stream(p)
            .map_err(|e| LimitHit::new(format!("ole stream: {e}")))?;
        let (buf, truncated) =
            bounded_read(stream, cap).map_err(|e| LimitHit::new(format!("ole read: {e}")))?;
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
        entries.push(Entry::new(name, buf));
    }

    // If the document carries a VBA project, decompress its macros and emit two
    // text artifacts: the `REM`-headed dump (code-lowercased, for
    // `Doc.*` macro sigs) and the raw original-case source (for `Target:2` OLE
    // sigs like `Attribute VB_Name =`/`CreateObject`).
    // Compute both macro artifacts while `streams` (which borrows `entries`) is
    // alive, *before* pushing anything back into `entries`.
    let (vba_arts, xlm_art) = {
        let streams: Vec<(String, &[u8])> = entries
            .iter()
            .map(|e| (e.name.clone(), e.data.as_slice()))
            .collect();
        let vba = super::vba::build_artifacts(&streams, budget.limits.max_buffer_bytes());
        let xlm = super::xlm::xlm_macro_artifact(&streams);
        (vba, xlm)
    };

    // Emit the VBA-project text artifacts (macro dump + raw original-case source).
    if let Some((dump, raw)) = vba_arts {
        for (name, art) in [("vba_project", dump), ("vba_project_raw", raw)] {
            if art.is_empty() || budget.count_entry().is_err() {
                continue;
            }
            let cap = budget.reserve().unwrap_or(0);
            if (art.len() as u64) <= cap {
                budget.commit(art.len() as u64);
                entries.push(Entry::new(name.to_string(), art));
            }
        }
    }

    // Excel 4.0 (XLM) macros live in a BIFF macro sheet, not a VBA project, so
    // they evade VBA-only macro detection. Surface an `xlm_macro` artifact when
    // the workbook carries a macro sheet, mirroring the VBA path.
    if let Some(art) = xlm_art {
        if !art.is_empty() && budget.count_entry().is_ok() {
            let cap = budget.reserve().unwrap_or(0);
            if (art.len() as u64) <= cap {
                budget.commit(art.len() as u64);
                entries.push(Entry::new("xlm_macro".to_string(), art));
            }
        }
    }
    Ok(entries)
}

/// Read up to `buf.len()` bytes, returning how many were filled (handles short
/// reads from the CFB stream reader).
fn read_fill<R: Read>(r: &mut R, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    n
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
