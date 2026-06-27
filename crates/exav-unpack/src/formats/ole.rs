#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// OLE2 / Compound File Binary (legacy Office, MSI): emit every stream so the
/// engine can match on macro/object/shellcode content.
pub(crate) fn extract_ole(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(data))
        .map_err(|e| LimitHit::new(format!("ole: {e}")))?;
    let paths: Vec<std::path::PathBuf> = comp
        .walk()
        .filter(|e| e.is_stream())
        .map(|e| e.path().to_path_buf())
        .collect();

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
            data.len() as u64,
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
                    data.len() as u64,
                    true,
                    "encrypted Office document",
                )]);
            }
        }
    }

    let mut entries = Vec::new();
    for p in paths {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let stream = comp
            .open_stream(&p)
            .map_err(|e| LimitHit::new(format!("ole stream: {e}")))?;
        let (buf, truncated) =
            bounded_read(stream, cap).map_err(|e| LimitHit::new(format!("ole read: {e}")))?;
        if truncated {
            return Err(LimitHit::new("ole stream exceeds budget".to_string()));
        }
        budget.commit(buf.len() as u64);
        entries.push(Entry::new(p.to_string_lossy().into_owned(), buf));
    }

    // If the document carries a VBA project, decompress its macros and emit two
    // text artifacts: the ClamAV-style `REM`-headed dump (code-lowercased, for
    // `Doc.*` macro sigs) and the raw original-case source (for `Target:2` OLE
    // sigs like `Attribute VB_Name =`/`CreateObject`).
    let streams: Vec<(String, &[u8])> = entries
        .iter()
        .map(|e| (e.name.clone(), e.data.as_slice()))
        .collect();
    if let Some((dump, raw)) = super::vba::build_artifacts(&streams) {
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
