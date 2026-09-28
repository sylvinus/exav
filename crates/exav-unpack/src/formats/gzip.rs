#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_gzip<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let s = gunzip(data, cap, budget).map_err(|e| LimitHit::new(format!("gzip: {e}")))?;
    if s.over_cap {
        return Err(LimitHit::new("gzip member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, s.data.len() as u64, budget)?;
    budget.commit(s.data.len() as u64);
    Ok(visit(gzip_entry(s), budget))
}

/// Decode every member of a gzip file, up to `cap` bytes. Every member, not
/// the first: a gzip file may be several concatenated members (RFC 1952
/// section 2.2) and the payload can live in a later one (observed: a 2-member
/// gz whose first member is a 1 KiB header and whose second holds the
/// malware). gzip, zcat and ClamAV all read them all.
///
/// Unless checksum verification is on, a decode error keeps what was decoded
/// before it, so a damaged or mis-summed file still has its content scanned.
pub(crate) fn gunzip<R: std::io::BufRead>(
    src: R,
    cap: u64,
    budget: &Budget,
) -> std::io::Result<Salvaged> {
    bounded_read_salvage(
        crate::inflate::Gunzip::new(src),
        cap,
        !budget.should_verify_checksums(),
    )
}

/// The entry for decoded gzip content, flagged when damage left part of it
/// undecoded.
pub(crate) fn gzip_entry(s: Salvaged) -> Entry {
    let mut e = Entry::new("gzip-content".to_string(), s.data);
    if s.undecoded {
        e.unsupported = Some(
            "gzip data failed to decode part way; the bytes before the failure \
             were scanned",
        );
    }
    e
}
