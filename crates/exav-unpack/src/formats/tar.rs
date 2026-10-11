//! tar: each member read off the source where it lies, a member the visitor
//! does not read skipped by seeking past it.
use std::io::{Seek, SeekFrom};

use crate::source::{ByteSource, Reader};
use crate::stream::{emit_stream, MemberMeta, Mtime, Visit};
use crate::{Budget, LimitHit};

pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = Reader::new(src);
    source
        .seek(SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("tar seek: {e}")))?;
    let mut archive = ::tar::Archive::new(source);
    let entries = archive
        .entries_with_seek()
        .map_err(|e| LimitHit::corrupt(format!("tar: {e}")))?;
    for entry in entries {
        budget.count_entry()?;
        let mut entry = match entry {
            Ok(e) => e,
            // A truncated archive: entries before the cut were already scanned,
            // and the missing tail is absent rather than hidden. exav scans for
            // malware, it is not an integrity validator.
            Err(e) if is_truncation(&e) => return Ok(None),
            Err(e) => return Err(LimitHit::corrupt(format!("tar entry: {e}"))),
        };
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "tar-entry".to_string());
        let size = entry.size();
        let header = entry.header();
        // The type bits `st_mode` has and a tar header keeps apart. A hard
        // link has neither a type of its own nor content here: no mode.
        let kind = match header.entry_type() {
            ::tar::EntryType::Regular | ::tar::EntryType::Continuous => Some(0o100000),
            ::tar::EntryType::Directory => Some(0o040000),
            ::tar::EntryType::Symlink => Some(0o120000),
            _ => None,
        };
        let symlink = header.entry_type() == ::tar::EntryType::Symlink;
        let meta = MemberMeta {
            name,
            comp_size: size,
            size: Some(size),
            mtime: header
                .mtime()
                .ok()
                .and_then(|t| i64::try_from(t).ok())
                .map(Mtime::Unix),
            mode: kind.and_then(|k| Some(k | (header.mode().ok()? & 0o7777))),
            link: symlink
                .then(|| entry.link_name().ok().flatten())
                .flatten()
                .map(|l| l.to_string_lossy().into_owned()),
            ..MemberMeta::default()
        };
        if let Some(t) = emit_stream(&meta, &mut entry, budget, visit)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

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
