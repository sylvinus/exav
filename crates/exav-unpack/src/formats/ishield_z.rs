//! InstallShield Z — the older `.z` installer archive.
//!
//! Distinct from the `ISc(` InstallScript cabinet next door in
//! [`super::reported`], which stays recognised-but-unopened because its only
//! implementation is LGPL. This one has a permissively-licensed reader, so
//! there is no reason not to open it.
//!
//! Members are compressed with the **PKWARE Data Compression Library** codec
//! ("implode"), which is not the same as ZIP's method 8 deflate and not the
//! same as ZIP method 6 either. Decoding is delegated to `unshield` (MIT), whose
//! only real dependency is `explode` (MIT), a leaf DCL decoder.
//!
//! Names come out as `path/name` and are used only for reporting and `.cdb`
//! matching — nothing here resolves one against a filesystem.

use std::io::Cursor;

use crate::{Budget, Entry, LimitHit, Sink};

/// Bound on the member walk; hitting it is reported, never a quiet stop.
const MAX_ENTRIES: usize = 20_000;

pub(crate) fn is_ishield_z(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::IshieldZ)
}

/// A member's reported name. `FileInfo::path` is already the full path; only
/// the separator differs — InstallShield wrote backslashes — so it is
/// normalised to read like every other container's.
///
/// The archive is addressed by the raw `path` string, never by this.
fn display_name(path: &str) -> String {
    path.replace('\\', "/").trim_matches('/').to_string()
}

pub(crate) fn extract_ishield_z<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_ishield_z(data) {
        return Ok(None);
    }
    let mut archive = match unshield::Archive::new(Cursor::new(data)) {
        Ok(a) => a,
        Err(e) => {
            // The header said InstallShield Z and its own arithmetic checked
            // out; failing to open now leaves every member unexamined, which
            // must not pass quietly.
            let _ = e;
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

    // The listing is borrowed from the archive and `load` needs it mutably, so
    // the paths are taken first. This is a table of contents, not content: it is
    // bounded by `MAX_ENTRIES` and holds no member bytes.
    let mut listing: Vec<(String, usize)> = Vec::new();
    let mut truncated = false;
    for f in archive.list() {
        if listing.len() >= MAX_ENTRIES {
            truncated = true;
            break;
        }
        listing.push((f.path.clone(), f.size));
    }

    for (path, comp_size) in listing {
        let name = display_name(&path);
        budget.count_entry()?;
        let cap = budget.reserve()?;
        // `size` in the table of contents is the COMPRESSED length — that is
        // what `load_compressed` reads — so it cannot stand in for the output
        // size. What it does bound is the input: a member whose compressed form
        // is already over the cap cannot decode to anything under it.
        if comp_size as u64 > cap {
            if let Some(r) = visit(
                Entry::unsupported(
                    name,
                    comp_size as u64,
                    false,
                    "InstallShield Z member exceeds the per-member size budget",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }
        // Addressed by the raw path the listing gave; nothing constructs a name
        // of its own here.
        match archive.load(&path) {
            // `explode` returns a whole `Vec` with no cap of its own, so the
            // output is checked after the fact rather than while decoding. The
            // bound that makes this safe is the one above: the input is already
            // capped, and DCL implode's 4 KiB window cannot turn a bounded input
            // into an unbounded output. An over-cap result is still reported —
            // discarded bytes that nobody hears about are the failure mode this
            // crate exists to avoid.
            Ok(bytes) if bytes.len() as u64 > cap => {
                if let Some(r) = visit(
                    Entry::unsupported(
                        name,
                        comp_size as u64,
                        false,
                        "InstallShield Z member decompressed past the per-member \
                         size budget",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
            }
            Ok(bytes) => {
                budget.commit(bytes.len() as u64);
                let mut e = Entry::new(name, bytes);
                e.comp_size = comp_size as u64;
                if let Some(r) = visit(e, budget) {
                    return Ok(Some(r));
                }
            }
            Err(e) => {
                // One member exav cannot decode must not stop the rest.
                let _ = e;
                if let Some(r) = visit(
                    Entry::unsupported(
                        name,
                        comp_size as u64,
                        false,
                        "InstallShield Z member could not be decompressed",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
            }
        }
    }
    if truncated {
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
    Ok(None)
}
