#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// True if a `sevenz-rust2` error indicates the archive/member is AES-encrypted
/// (password required / wrong password / the AES256-SHA256 method, which is
/// `UnsupportedCompressionMethod` because the `aes256` feature is OFF — see the
/// crate note in `Cargo.toml`: enabling it pulls `getrandom`, which the default
/// build forbids).
fn is_encryption_error(e: &sevenz_rust2::Error) -> bool {
    use sevenz_rust2::Error;
    match e {
        Error::PasswordRequired | Error::MaybeBadPassword(_) => true,
        // AES256-SHA256 method id is `06f10701`; without the `aes256` feature the
        // decoder rejects it as an unsupported method.
        Error::UnsupportedCompressionMethod(m) => {
            let m = m.to_ascii_lowercase();
            m.contains("06f10701") || m.contains("aes")
        }
        _ => false,
    }
}

/// 7-Zip: decode each entry's stream into a budgeted buffer. Uses the
/// pure-Rust `sevenz-rust2` reader (LZMA/LZMA2/PPMd/BCJ/Copy).
///
/// Encryption: exav builds `sevenz-rust2` WITHOUT its `aes256` feature (it pulls
/// `getrandom`, forbidden in the default build), so AES-encrypted 7z content is
/// DETECTED but not decrypted — an encrypted member (or a header-encrypted
/// archive that won't open) is surfaced as `Entry::unsupported(encrypted=true)`
/// → `PasswordProtected`, never silently clean. This is the one format below the
/// ZIP decryptors in capability; decrypting it is a follow-up (it needs a pure
/// AES-CBC + SHA-256-KDF path mirroring `zip_crypto`, plus the 7z folder coder
/// chain). The password pool is threaded but not yet consumed here.
pub(crate) fn extract_7z<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    use sevenz_rust2::{ArchiveReader, Password};
    let mut reader = match ArchiveReader::new(Cursor::new(data), Password::empty()) {
        Ok(r) => r,
        Err(e) if is_encryption_error(&e) => {
            // Header-encrypted (`-mhe`) archive: the whole directory is encrypted,
            // so we can't even enumerate members. Emit one encrypted signal.
            budget.count_entry()?;
            let entry =
                Entry::unsupported("7z-encrypted".to_string(), 0, true, "encrypted 7z archive");
            return Ok(visit(entry, budget));
        }
        Err(e) => return Err(LimitHit::new(format!("7z: {e}"))),
    };
    let mut limit: Option<LimitHit> = None;
    // Stash an early-stop value from the visitor (the closure must return a bool,
    // so the visitor's `Some(r)` is carried out here).
    let mut stop: Option<R> = None;
    // `for_each_entries` streams each entry's decompressed bytes; we cap each to
    // the remaining budget and stop (return Ok(false)) on a bound or once the
    // visitor asks to — so later members are never decompressed.
    let r = reader.for_each_entries(|entry, rd| {
        if entry.is_directory() {
            return Ok(true);
        }
        if let Err(h) = budget.count_entry() {
            limit = Some(h);
            return Ok(false);
        }
        let cap = match budget.reserve() {
            Ok(c) => c,
            Err(h) => {
                limit = Some(h);
                return Ok(false);
            }
        };
        let (buf, truncated) = match bounded_read(rd, cap) {
            Ok(x) => x,
            Err(e) => {
                limit = Some(LimitHit::new(format!("7z read: {e}")));
                return Ok(false);
            }
        };
        if truncated {
            limit = Some(LimitHit::new("7z member exceeds budget".to_string()));
            return Ok(false);
        }
        budget.commit(buf.len() as u64);
        if let Some(r) = visit(Entry::new(entry.name().to_string(), buf), budget) {
            stop = Some(r);
            return Ok(false);
        }
        Ok(true)
    });
    if let Some(h) = limit {
        return Err(h);
    }
    if stop.is_some() {
        return Ok(stop);
    }
    // A plaintext-header archive with AES-encrypted member streams: the header
    // enumerates fine but decoding the encrypted stream fails. Surface it as an
    // encrypted (PasswordProtected) signal rather than a hard error.
    if let Err(e) = r {
        if is_encryption_error(&e) {
            budget.count_entry()?;
            let entry =
                Entry::unsupported("7z-encrypted".to_string(), 0, true, "encrypted 7z member");
            return Ok(visit(entry, budget));
        }
        return Err(LimitHit::new(format!("7z: {e}")));
    }
    Ok(None)
}
