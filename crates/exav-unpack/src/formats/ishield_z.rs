//! InstallShield Z — the older `.z` installer archive.
//!
//! Distinct from the `ISc(` InstallScript cabinet next door in
//! [`super::reported`], which stays recognised-but-unopened because its only
//! implementation is LGPL. This one has a permissively-licensed reader, so
//! there is no reason not to open it.
//!
//! Members are compressed with the **PKWARE Data Compression Library** codec
//! ("implode"), which is not the same as ZIP's method 8 deflate and not the
//! same as ZIP method 6 either; [`super::dcl_explode`] decodes it.
//!
//! The table of contents is read as `unshield` 0.2.0 (Aaron Griffith, MIT;
//! attributed in `NOTICE`) reads it, with two differences: every member is
//! listed in table order, where `unshield` keys them by path and keeps only
//! the last of two that share one, and a name that is not UTF-8 is read
//! lossily instead of failing the whole archive.
//!
//! Names come out as `path/name` and are used only for reporting and `.cdb`
//! matching — nothing here resolves one against a filesystem.

use crate::bytes::at;
use crate::{Budget, Entry, LimitHit, Sink};

/// Bound on the member walk; hitting it is reported, never a quiet stop.
const MAX_ENTRIES: usize = 20_000;

/// Where the first member's data begins, the end of the header.
const FILE_OFFSET: usize = 255;

pub(crate) fn is_ishield_z(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::IshieldZ)
}

/// A member's reported name. `path` is already the full path; only the
/// separator differs — InstallShield wrote backslashes — so it is normalised
/// to read like every other container's.
fn display_name(path: &str) -> String {
    path.replace('\\', "/").trim_matches('/').to_string()
}

struct Member {
    path: String,
    /// Where its compressed bytes start: members follow each other from
    /// [`FILE_OFFSET`] in table order.
    offset: usize,
    /// Its COMPRESSED size.
    size: usize,
}

enum Toc {
    Members(Vec<Member>),
    /// More members declared than [`MAX_ENTRIES`].
    TooMany,
}

/// The table of contents. `None` when it cannot be read.
///
/// The directory records come first, each with its member count, then the
/// member records, directory by directory. A record's `chunk` is its length:
/// a zero one makes every record read the same bytes again, so the member
/// count is summed and bounded before any member record is read.
fn read_toc(data: &[u8]) -> Option<Toc> {
    let u16at = |d: &[u8], o: usize| -> Option<usize> {
        Some(u16::from_le_bytes(at(d, o, 2)?.try_into().ok()?) as usize)
    };
    let u32at = |d: &[u8], o: usize| -> Option<usize> {
        let v = u32::from_le_bytes(at(d, o, 4)?.try_into().ok()?);
        Some(crate::bytes::to_usize(v as u64))
    };
    let string = |d: &[u8], o: usize, len: usize| -> Option<String> {
        Some(String::from_utf8_lossy(at(d, o, len)?).into_owned())
    };
    let toc = data.get(u32at(data, 41)?..u32at(data, 18)?)?;
    let mut next = 0usize;
    let mut dirs = Vec::new();
    let mut declared = 0usize;
    for _ in 0..u16at(data, 49)? {
        let files = u16at(toc, next)?;
        let chunk = u16at(toc, next.checked_add(2)?)?;
        let name_len = u16at(toc, next.checked_add(4)?)?;
        dirs.push((files, string(toc, next.checked_add(6)?, name_len)?));
        declared += files;
        next = next.checked_add(chunk)?;
    }
    if declared > MAX_ENTRIES {
        return Some(Toc::TooMany);
    }
    let mut members = Vec::with_capacity(declared);
    let mut offset = FILE_OFFSET;
    for (files, dir) in dirs {
        for _ in 0..files {
            let size = u32at(toc, next.checked_add(7)?)?;
            let chunk = u16at(toc, next.checked_add(23)?)?;
            let name_len = *toc.get(next.checked_add(29)?)? as usize;
            let name = string(toc, next.checked_add(30)?, name_len)?;
            let path = match dir.is_empty() {
                true => name,
                false => format!("{dir}\\{name}"),
            };
            members.push(Member { path, offset, size });
            next = next.checked_add(chunk)?;
            offset = offset.checked_add(size)?;
        }
    }
    Some(Toc::Members(members))
}

pub(crate) fn extract_ishield_z<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_ishield_z(data) {
        return Ok(None);
    }
    let members = match read_toc(data) {
        Some(Toc::Members(m)) => m,
        Some(Toc::TooMany) => {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    format!("<installshield-z-entries-beyond-{MAX_ENTRIES}>"),
                    0,
                    false,
                    "too many InstallShield Z members to walk them all",
                ),
                budget,
            ));
        }
        None => {
            // The header said InstallShield Z and its own arithmetic checked
            // out; failing to open now leaves every member unexamined, which
            // must not pass quietly.
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<installshield-z>".to_string(),
                    data.len() as u64,
                    false,
                    "InstallShield Z archive directory could not be read",
                ),
                budget,
            ));
        }
    };

    for m in members {
        let name = display_name(&m.path);
        let comp_size = m.size as u64;
        budget.count_entry()?;
        let cap = budget.reserve()?;
        // The table's size is the COMPRESSED length, so it cannot stand in
        // for the output size. What it does bound is the input: a member whose
        // compressed form is already over the cap cannot decode to anything
        // under it.
        if comp_size > cap {
            if let Some(r) = visit(
                Entry::unsupported(
                    name,
                    comp_size,
                    false,
                    "InstallShield Z member exceeds the per-member size budget",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }
        // The codec's matches run to 518 bytes, so a bounded input can expand
        // a few hundred times over: the member is decoded up to the cap, and an
        // over-cap result is still reported. Discarded bytes that nobody hears
        // about are the failure mode this crate exists to avoid.
        //
        // A member whose range runs past the file is decoded as far as the
        // file goes. What the codec decoded before a stream failed or ended
        // early is kept and scanned, and the member is reported.
        let raw = data.get(m.offset..).unwrap_or_default();
        let raw = &raw[..m.size.min(raw.len())];
        let range_cut = raw.len() < m.size;
        let s = super::dcl_explode::explode(raw, cap);
        if s.over_cap {
            if let Some(r) = visit(
                Entry::unsupported(
                    name,
                    comp_size,
                    false,
                    "InstallShield Z member decompressed past the per-member \
                     size budget",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }
        budget.commit(s.data.len() as u64);
        let mut e = Entry::new(name, s.data);
        e.comp_size = comp_size;
        if s.undecoded || s.cut_short || range_cut {
            e.unsupported = Some(
                "InstallShield Z member failed to decompress in full; the bytes \
                 before the failure were scanned",
            );
        }
        if let Some(r) = visit(e, budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}
