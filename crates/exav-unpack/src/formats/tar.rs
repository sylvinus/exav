#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// True when an I/O error means the input simply ran out (a truncated stream),
/// as opposed to structurally invalid data. The `tar` crate surfaces the
/// end-of-input case both as `UnexpectedEof` and as a generic-kind error whose
/// message names it, so check both.
pub(crate) fn is_truncation(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof || {
        let m = e.to_string();
        m.contains("unexpected EOF") || m.contains("unexpected end")
    }
}

pub(crate) fn extract_tar<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut archive = ::tar::Archive::new(Cursor::new(data));
    let iter = archive
        .entries()
        .map_err(|e| LimitHit::new(format!("tar: {e}")))?;
    for entry in iter {
        budget.count_entry()?;
        let mut entry = match entry {
            Ok(e) => e,
            // A truncated tar: the stream ran out mid-header / mid-skip. The
            // entries before the cut were already yielded and scanned; the
            // missing tail is absent, not hidden. exav scans for malware, it is
            // not an integrity validator — stop cleanly rather than raising a
            // not-fully-scanned verdict on a damaged-but-recovered archive. (The
            // `tar` crate reports the mid-skip case with a generic error kind, so
            // match the message too.)
            Err(e) if is_truncation(&e) => return Ok(None),
            Err(e) => return Err(LimitHit::corrupt(format!("tar entry: {e}"))),
        };
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "tar-entry".to_string());
        let cap = budget.reserve()?;
        let (buf, truncated) =
            bounded_read(&mut entry, cap).map_err(|e| LimitHit::new(format!("tar read: {e}")))?;
        if truncated {
            return Err(LimitHit::new(format!("tar member '{name}' exceeds budget")));
        }
        budget.commit(buf.len() as u64);
        if let Some(r) = visit(Entry::new(name, buf), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}
