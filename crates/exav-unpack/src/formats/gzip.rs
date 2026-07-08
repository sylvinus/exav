#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_gzip<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // `MultiGzDecoder`, not `GzDecoder`: a gzip file may be several concatenated
    // members (RFC 1952 §2.2) and the payload can live in a later one. `GzDecoder`
    // stops after the first member — a real FN source (observed: a 2-member gz
    // whose first member is a 1 KiB header and whose second holds the malware).
    // gzip/zcat/ClamAV all concatenate every member.
    use flate2::read::MultiGzDecoder;
    budget.count_entry()?;
    let cap = budget.reserve()?;
    // Scan-everything default: salvage the decompressed bytes even if flate2
    // reports a trailing CRC-32/ISIZE mismatch, so a corrupted checksum can't
    // hide the payload from scanning (unless checksum verification is enabled).
    let salvage = !budget.should_verify_checksums();
    let (out, truncated) =
        bounded_read_salvage(MultiGzDecoder::new(Cursor::new(data)), cap, salvage)
            .map_err(|e| LimitHit::new(format!("gzip: {e}")))?;
    if truncated {
        return Err(LimitHit::new("gzip member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("gzip-content".to_string(), out), budget))
}
