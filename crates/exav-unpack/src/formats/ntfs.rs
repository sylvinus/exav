//! NTFS — walking the Master File Table.
//!
//! VHD and VHDX are Windows-native, so a disk image aimed at a Windows victim
//! holds NTFS. Reconstructing the guest disk gives a pile of sectors; carving
//! finds a file only where its magic starts a contiguous run, which leaves two
//! real gaps: a **fragmented** file is only fragments, and an **NTFS-compressed**
//! one is not in the image in plain form at all.
//!
//! This is deliberately not a filesystem driver. A scanner wants every file's
//! bytes, not a navigable tree, so it walks the MFT record by record instead of
//! descending directory indexes. That skips the index B-trees, the `$Upcase`
//! table and case-insensitive lookup entirely — and it picks up something a
//! directory walk cannot: a **deleted file whose MFT record still holds its data
//! runs**. A dropper that removed itself is still there to be scanned.
//!
//! ```text
//! boot sector      bytes/sector, sectors/cluster, where $MFT starts
//!   $MFT record 0  its own $DATA runs — the MFT itself can be fragmented
//!     FILE records $FILE_NAME for the name, $DATA for the bytes
//!       resident   the value sits inside the record
//!       non-resid. data runs: (length, signed LCN delta) pairs
//!       compressed LZNT1 over each compression unit
//! ```
//!
//! Implemented from Microsoft's published NTFS documentation. All fields are
//! **little-endian**. Decompression is delegated to the `lznt1` crate; nothing
//! else is.
//!
//! **What is verified, and what is not.** Resident files, single-run files and a
//! two-run file are checked byte-for-byte against `ntfscat` — the two-run volume
//! is a real one whose run list was split in half, and ntfs-3g reads the result
//! back to the same digest, so an independent implementation agrees the layout
//! is valid. Two paths are implemented but have no fixture behind them: extents
//! spread across MFT records via `$ATTRIBUTE_LIST`, and LZNT1 compression.
//! `mkntfs`/`ntfscp` cannot produce either, and a hand-built multi-record volume
//! was rejected by `ntfscat`, so it is not used as proof of anything. Closing
//! that needs a volume made by Windows — a heavily fragmented file, and one run
//! through `compact.exe`.
//!
//! Neither unproven path can quietly do harm: if the runs gathered fall short of
//! the size the record declares, the shortfall is reported *and* the bytes that
//! were read are still handed over, rather than a prefix being passed off as the
//! whole file.
//!
//! The volume is a `Read + Seek`, read where the walk goes: the boot sector, the
//! MFT record by record through `$MFT`'s own runs, and the runs of each file.
//! Only a file is ever held, bounded by the buffer limit.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use super::vol::{Attrs, Emit, Found, Next, Piece, Pieces, Plan, Vol, hand, read_file};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, Entry, LimitHit};

/// The OEM name every NTFS boot sector carries at offset 3.
/// Every MFT record starts with this.
const RECORD_MAGIC: &[u8; 4] = b"FILE";

/// Attribute type codes used here.
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

/// MFT record header flags.
const FLAG_IN_USE: u16 = 0x0001;
const FLAG_DIRECTORY: u16 = 0x0002;

/// Attribute header flags.
const ATTR_COMPRESSED: u16 = 0x0001;
const ATTR_ENCRYPTED: u16 = 0x4000;
const ATTR_SPARSE: u16 = 0x8000;

/// `$FILE_NAME` namespaces. The DOS 8.3 alias duplicates a name we already have.
const NAMESPACE_DOS: u8 = 2;

/// The low 48 bits of a file reference are the record number.
const RECORD_NUMBER_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Records 0..15 are the filesystem's own metadata — `$MFT`, `$LogFile`,
/// `$UpCase` and friends. They are skipped, and skipping them loses nothing: the
/// volume's raw bytes are pattern-scanned before this walk runs, so anything
/// hidden in `$BadClus` or the journal in plain form is already covered. What
/// the walk adds over that raw scan is reassembly and decompression, and neither
/// applies to metadata. Emitting them would spend the budget on megabytes of
/// `$LogFile` and `$UpCase` instead.
const FIRST_USER_RECORD: usize = 16;

/// Walk guards. Both are reported when hit, never a quiet stop.
const MAX_RECORDS: usize = 200_000;
const MAX_RUNS: usize = 65_536;

fn le_u16(d: &[u8], off: usize) -> u16 {
    crate::bytes::at(d, off, 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    crate::bytes::at(d, off, 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn le_u64(d: &[u8], off: usize) -> u64 {
    crate::bytes::at(d, off, 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0)
}

/// The geometry every offset in the volume is expressed in.
struct Geometry {
    cluster: usize,
    record_size: usize,
    mft_lcn: u64,
}

fn geometry(data: &[u8]) -> Option<Geometry> {
    let bytes_per_sector = le_u16(data, 11) as usize;
    let sectors_per_cluster = data.get(13).copied()? as usize;
    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        return None;
    }
    let cluster = bytes_per_sector.checked_mul(sectors_per_cluster)?;

    // A positive value counts clusters per record; a negative one is a power of
    // two in bytes, which is what every volume with a cluster over 1 KiB uses.
    let raw = data.get(0x40).copied()? as i8;
    let record_size = if raw > 0 {
        (raw as usize).checked_mul(cluster)?
    } else {
        1usize.checked_shl(raw.unsigned_abs().into())?
    };
    if !(256..=1 << 20).contains(&record_size) {
        return None;
    }
    Some(Geometry {
        cluster,
        record_size,
        mft_lcn: le_u64(data, 0x30),
    })
}

/// Undo the update-sequence fix-up.
///
/// NTFS replaces the last two bytes of every sector in a record with a sequence
/// number, keeping the originals in an array at the record's head. Skipping this
/// leaves two corrupted bytes per sector, which is subtle enough to produce
/// plausible-looking output rather than an error.
fn apply_fixups(rec: &mut [u8], sector: usize) -> bool {
    let usa_off = le_u16(rec, 4) as usize;
    let usa_count = le_u16(rec, 6) as usize;
    if usa_count == 0 || sector < 2 {
        return false;
    }
    let Some(usn) = crate::bytes::at(rec, usa_off, 2).map(<[u8]>::to_vec) else {
        return false;
    };
    // The first entry is the sequence number itself; the rest are replacements,
    // one per sector.
    for i in 1..usa_count {
        let Some(repl) = crate::bytes::at(rec, usa_off.saturating_add(i.saturating_mul(2)), 2)
            .map(<[u8]>::to_vec)
        else {
            return false;
        };
        let end = i.saturating_mul(sector);
        if end < 2 || end > rec.len() {
            return false;
        }
        // Every sector must currently carry the sequence number; if it does not,
        // this is not a coherent record.
        let at = end.saturating_sub(2);
        if rec[at..end] != usn[..] {
            return false;
        }
        rec[at..end].copy_from_slice(&repl);
    }
    true
}

/// One extent of a non-resident attribute: `lcn` is `None` for a sparse run,
/// which reads as zeroes.
#[derive(Clone)]
struct Run {
    lcn: Option<i64>,
    clusters: u64,
}

/// Decode a data-run list: each entry is a header nibble pair giving the byte
/// widths of a run length and a **signed** LCN delta from the previous run.
fn data_runs(d: &[u8]) -> Vec<Run> {
    let mut runs = Vec::new();
    let mut i = 0usize;
    let mut lcn: i64 = 0;
    while let Some(&hdr) = d.get(i) {
        if hdr == 0 || runs.len() >= MAX_RUNS {
            break;
        }
        i = i.saturating_add(1);
        let len_sz = (hdr & 0x0F) as usize;
        let off_sz = (hdr >> 4) as usize;
        if len_sz == 0 || len_sz > 8 || off_sz > 8 {
            break;
        }
        let Some(len_bytes) = crate::bytes::at(d, i, len_sz) else {
            break;
        };
        i = i.saturating_add(len_sz);
        let mut clusters: u64 = 0;
        for (k, &b) in len_bytes.iter().enumerate() {
            clusters |= u64::from(b) << k.saturating_mul(8);
        }

        if off_sz == 0 {
            // A sparse run: no clusters allocated, reads as zeroes.
            runs.push(Run {
                lcn: None,
                clusters,
            });
            continue;
        }
        let Some(off_bytes) = crate::bytes::at(d, i, off_sz) else {
            break;
        };
        i = i.saturating_add(off_sz);
        let mut delta: i64 = 0;
        for (k, &b) in off_bytes.iter().enumerate() {
            delta |= i64::from(b) << k.saturating_mul(8);
        }
        // Sign-extend from the width actually used (1..=8 bytes here).
        let bits = u32::try_from(off_sz.saturating_mul(8)).unwrap_or(64);
        if bits < 64 && delta & (1i64 << bits.saturating_sub(1)) != 0 {
            delta = delta.saturating_sub(1i64 << bits);
        }
        let Some(next) = lcn.checked_add(delta) else {
            break;
        };
        lcn = next;
        runs.push(Run {
            lcn: Some(lcn),
            clusters,
        });
    }
    runs
}

/// The stretches of a non-resident attribute: each run in order, a sparse one
/// zeros.
struct Runs {
    runs: std::vec::IntoIter<Run>,
    cluster: u64,
}

impl Plan for Runs {
    fn next(&mut self, _: &mut Vol) -> Next {
        let Some(r) = self.runs.next() else {
            return Next::End;
        };
        let len = r.clusters.saturating_mul(self.cluster);
        match r.lcn {
            None => Next::Piece(Piece::Zeros(len)),
            Some(lcn) => match u64::try_from(lcn)
                .ok()
                .and_then(|l| l.checked_mul(self.cluster))
            {
                Some(at) => Next::Piece(Piece::Disk(at, len)),
                None => Next::Broken,
            },
        }
    }
}

/// `visit`'s member `e`, held whole.
fn held<R>(visit: Emit<R>, e: Entry, budget: &mut Budget) -> Option<R> {
    visit(Found::Held(e), budget)
}

/// Read a non-resident attribute's bytes by following its runs. Short where
/// the runs stop being readable, and never longer than `real_size`, which the
/// caller has bounded: a sparse run is zeros held in memory.
fn read_runs(v: &mut Vol, runs: &[Run], cluster: usize, real_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(real_size.min(1 << 20));
    for r in runs {
        if out.len() >= real_size {
            break;
        }
        let want = crate::bytes::to_usize(r.clusters).saturating_mul(cluster);
        let take = want.min(real_size.saturating_sub(out.len()));
        match r.lcn {
            // Sparse: allocated but never written, so it reads as zeroes on the
            // victim's machine too.
            None => out.resize(out.len().saturating_add(take), 0),
            Some(lcn) if lcn >= 0 => {
                let start = (lcn as u64).saturating_mul(cluster as u64);
                // Past the end of the image: those bytes are absent rather
                // than hidden, so what exists still stands.
                if !v.append(start, take, &mut out) {
                    break;
                }
            }
            Some(_) => break,
        }
    }
    out.truncate(real_size);
    out
}

/// `len` bytes at `offset` of the attribute the runs describe, appended to
/// `out`. False when any of them is not readable.
fn read_runs_at(
    v: &mut Vol,
    runs: &[Run],
    cluster: usize,
    offset: u64,
    len: usize,
    out: &mut Vec<u8>,
) -> bool {
    let Some(end) = offset.checked_add(len as u64) else {
        return false;
    };
    let cl = cluster as u64;
    let mut pos = 0u64;
    for r in runs {
        if pos >= end {
            break;
        }
        let run_end = pos.saturating_add(r.clusters.saturating_mul(cl));
        if run_end > offset {
            let from = offset.max(pos);
            let take = crate::bytes::to_usize(end.min(run_end).saturating_sub(from));
            match r.lcn {
                None => out.resize(out.len().saturating_add(take), 0),
                Some(lcn) if lcn >= 0 => {
                    let host = (lcn as u64)
                        .saturating_mul(cl)
                        .saturating_add(from.saturating_sub(pos));
                    if !v.append(host, take, out) {
                        return false;
                    }
                }
                Some(_) => return false,
            }
        }
        pos = run_end;
    }
    pos >= end
}

/// `$MFT`, read a record at a time through its own runs: it can be
/// fragmented, so it cannot simply be read from its first cluster.
struct Mft {
    runs: Vec<Run>,
    /// Bytes of the table that are readable from its start.
    size: u64,
}

impl Mft {
    /// The table `rec0`, record 0, describes.
    fn open(rec0: &[u8], v: &mut Vol, geo: &Geometry) -> Option<Mft> {
        let mut off = le_u16(rec0, 20) as usize;
        while off.saturating_add(8) <= rec0.len() {
            let atype = le_u32(rec0, off);
            if atype == ATTR_END {
                break;
            }
            let alen = le_u32(rec0, off.saturating_add(4)) as usize;
            if alen < 16 || alen > rec0.len().saturating_sub(off) {
                break;
            }
            if atype == ATTR_DATA && rec0.get(off.saturating_add(8)).copied().unwrap_or(0) != 0 {
                let real_size = le_u64(rec0, off.saturating_add(0x30));
                let runs_off = off.saturating_add(le_u16(rec0, off.saturating_add(0x20)) as usize);
                let runs = data_runs(rec0.get(runs_off..off.saturating_add(alen)).unwrap_or(&[]));
                // The table cannot be larger than the volume it is in. It is
                // only as long as its runs can be read.
                let limit = real_size.min(v.len);
                let cl = geo.cluster as u64;
                let mut size = 0u64;
                for r in &runs {
                    if size >= limit {
                        break;
                    }
                    let take = r
                        .clusters
                        .saturating_mul(cl)
                        .min(limit.saturating_sub(size));
                    match r.lcn {
                        None => size = size.saturating_add(take),
                        Some(lcn) if lcn >= 0 => {
                            let start = (lcn as u64).saturating_mul(cl);
                            if start.checked_add(take).is_none_or(|e| e > v.len) {
                                break;
                            }
                            size = size.saturating_add(take);
                        }
                        Some(_) => break,
                    }
                }
                return (size > 0).then_some(Mft { runs, size });
            }
            off = off.saturating_add(alen);
        }
        None
    }

    /// Record `n`, as stored (the fix-ups not undone).
    fn record(&self, v: &mut Vol, geo: &Geometry, n: u64) -> Option<Vec<u8>> {
        let size = geo.record_size as u64;
        let at = n.checked_mul(size)?;
        if at.checked_add(size)? > self.size {
            return None;
        }
        let mut out = Vec::with_capacity(geo.record_size);
        read_runs_at(v, &self.runs, geo.cluster, at, geo.record_size, &mut out).then_some(out)
    }
}

/// Every extent of the unnamed `$DATA`, gathered across MFT records.
///
/// A file fragmented past what one record can describe has its run list split
/// over several records, listed in `$ATTRIBUTE_LIST`. That threshold is
/// **attacker-controlled** — fragment a file hard enough and it crosses — so
/// not following the list would hand an attacker a way to choose whether a file
/// gets read. Which is exactly the kind of gap worth closing rather than
/// reporting.
fn data_extents(
    list: &[u8],
    v: &mut Vol,
    mft: &Mft,
    geo: &Geometry,
    sector: usize,
) -> Result<Option<(Vec<Run>, usize)>, TooManyExtents> {
    let mut refs: Vec<(u64, u64)> = Vec::new(); // (starting VCN, MFT record)
    let mut i = 0usize;
    while i.saturating_add(26) <= list.len() {
        let atype = le_u32(list, i);
        let entry_len = le_u16(list, i.saturating_add(4)) as usize;
        if entry_len < 26 {
            break;
        }
        let name_len = list.get(i.saturating_add(6)).copied().unwrap_or(0);
        // Only the unnamed `$DATA`; a named one is an alternate stream.
        if atype == ATTR_DATA && name_len == 0 {
            // More references than any file has: a list made to cost, which is
            // not followed (the caller reports the file as not fully read).
            if refs.len() >= MAX_LIST_REFS {
                return Err(TooManyExtents);
            }
            let vcn = le_u64(list, i.saturating_add(8));
            // The low 48 bits of the file reference are the record number.
            let record = le_u64(list, i.saturating_add(16)) & RECORD_NUMBER_MASK;
            refs.push((vcn, record));
        }
        i = i.saturating_add(entry_len);
    }
    if refs.is_empty() {
        return Ok(None);
    }
    // An extent starts at one VCN, named once; the first of the entries that
    // name it (the sort is stable) is the one.
    refs.sort_by_key(|&(vcn, _)| vcn);
    refs.dedup_by_key(|&mut (vcn, _)| vcn);

    // The extents each record holds, found once however many entries name
    // the record: reading it for each entry costs the record's size each.
    type Extents = HashMap<u64, (usize, Vec<Run>)>;
    let mut records: HashMap<u64, Option<Extents>> = HashMap::new();
    let mut runs: Vec<Run> = Vec::new();
    let mut real_size = 0usize;
    for (vcn, record) in refs {
        let held = records.entry(record).or_insert_with(|| {
            let mut r = mft.record(v, geo, record)?;
            if r.get(0..4) != Some(RECORD_MAGIC.as_slice()) || !apply_fixups(&mut r, sector) {
                return None;
            }
            Some(extents_of(&r))
        });
        let Some((size, extent)) = held.as_ref().and_then(|h| h.get(&vcn)) else {
            continue;
        };
        // Only the extent starting at VCN 0 carries the true size.
        if vcn == 0 {
            real_size = *size;
        }
        // Each record can hold thousands of runs, and a list names thousands
        // of records: the runs of one file are bounded in all.
        if runs.len().saturating_add(extent.len()) > MAX_FILE_RUNS {
            return Err(TooManyExtents);
        }
        runs.extend(extent.iter().cloned());
    }
    if runs.is_empty() || real_size == 0 {
        return Ok(None);
    }
    Ok(Some((runs, real_size)))
}

/// The most `$DATA` entries of one attribute list that are followed. A file
/// with its runs in this many records has more than any volume this reads holds.
const MAX_LIST_REFS: usize = 1 << 16;

/// The most data runs of one file followed, over all its extents: a million is
/// a file in a million fragments, and 24 MB of runs.
const MAX_FILE_RUNS: usize = 1 << 20;

/// An attribute list that names more extents than [`MAX_LIST_REFS`], or more
/// runs than [`MAX_FILE_RUNS`].
struct TooManyExtents;

/// The unnamed non-resident `$DATA` attributes of an MFT record by the VCN each
/// starts at: its recorded size (the true one at VCN 0) and its runs. The first
/// attribute of a VCN is the one.
fn extents_of(r: &[u8]) -> HashMap<u64, (usize, Vec<Run>)> {
    let mut found = HashMap::new();
    let mut off = le_u16(r, 20) as usize;
    while off.saturating_add(8) <= r.len() {
        let atype = le_u32(r, off);
        if atype == ATTR_END {
            break;
        }
        let alen = le_u32(r, off.saturating_add(4)) as usize;
        if alen < 16 || alen > r.len().saturating_sub(off) {
            break;
        }
        let non_resident = r.get(off.saturating_add(8)).copied().unwrap_or(0) != 0;
        if atype == ATTR_DATA
            && r.get(off.saturating_add(9)).copied().unwrap_or(0) == 0
            && non_resident
        {
            let vcn = le_u64(r, off.saturating_add(16));
            found.entry(vcn).or_insert_with(|| {
                let size = crate::bytes::to_usize(le_u64(r, off.saturating_add(0x30)));
                let runs_off = off.saturating_add(le_u16(r, off.saturating_add(0x20)) as usize);
                let runs = data_runs(r.get(runs_off..off.saturating_add(alen)).unwrap_or(&[]));
                (size, runs)
            });
        }
        off = off.saturating_add(alen);
    }
    found
}

/// The `$ATTRIBUTE_LIST` value.
///
/// The list is normally resident, but a file fragmented hard enough pushes the
/// list itself out of the record — and that threshold is reachable on purpose.
/// So the non-resident form is followed too, by walking its own data runs.
/// Stopping at the resident case would leave the most fragmented files, which is
/// to say the ones someone took the trouble to fragment, unread.
fn find_attribute_list(rec: &[u8], v: &mut Vol, geo: &Geometry) -> Option<Vec<u8>> {
    let mut off = le_u16(rec, 20) as usize;
    while off.saturating_add(8) <= rec.len() {
        let atype = le_u32(rec, off);
        if atype == ATTR_END {
            break;
        }
        let alen = le_u32(rec, off.saturating_add(4)) as usize;
        if alen < 16 || alen > rec.len().saturating_sub(off) {
            break;
        }
        if atype == ATTR_ATTRIBUTE_LIST {
            let non_resident = rec.get(off.saturating_add(8)).copied().unwrap_or(0) != 0;
            if !non_resident {
                let vlen = le_u32(rec, off.saturating_add(16)) as usize;
                let voff = off.saturating_add(le_u16(rec, off.saturating_add(20)) as usize);
                return crate::bytes::at(rec, voff, vlen).map(<[u8]>::to_vec);
            }
            let real_size = crate::bytes::to_usize(le_u64(rec, off.saturating_add(0x30)));
            let runs_off = off.saturating_add(le_u16(rec, off.saturating_add(0x20)) as usize);
            let runs = data_runs(rec.get(runs_off..off.saturating_add(alen)).unwrap_or(&[]));
            // No table of this kind is larger than the volume, and a sparse run
            // costs memory for every zero it reads.
            let bound = crate::bytes::to_usize(v.len).min(v.max);
            let bytes = read_runs(v, &runs, geo.cluster, real_size.min(bound));
            // A list read short would silently drop the extents it names, so it
            // is treated as unusable rather than half-used.
            return (bytes.len() == real_size && real_size > 0).then_some(bytes);
        }
        off = off.saturating_add(alen);
    }
    None
}

/// A file found in the MFT.
struct File {
    name: String,
    data: Option<Vec<u8>>,
    /// Set when the bytes are present but exav could not read them.
    unreadable: Option<&'static str>,
    deleted: bool,
    /// The runs and the size of a file too long to hold, to be read as it goes.
    stream: Option<(Vec<Run>, u64)>,
}

/// Parse one MFT record into a file, or `None` when it holds nothing to scan.
fn parse_record(
    rec: &[u8],
    v: &mut Vol,
    mft: &Mft,
    geo: &Geometry,
    sector: usize,
    cap: usize,
) -> Option<File> {
    if rec.get(0..4) != Some(RECORD_MAGIC.as_slice()) {
        return None;
    }
    let flags = le_u16(rec, 22);
    if flags & FLAG_DIRECTORY != 0 {
        return None;
    }
    let deleted = flags & FLAG_IN_USE == 0;

    // An extension record belongs to the file its base reference names, which
    // lists it: it is not a file of its own.
    if le_u64(rec, 32) & RECORD_NUMBER_MASK != 0 {
        return None;
    }
    // The name is in this record, or, for a file fragmented hard enough to
    // have an attribute list, in an extension record the list names.
    // The attribute list is read once, for the name and for the data.
    let mut list: Option<Option<Vec<u8>>> = None;
    let name = record_name(rec).or_else(|| {
        let l = list
            .get_or_insert_with(|| find_attribute_list(rec, v, geo))
            .as_deref()?;
        name_from_extensions(l, v, mft, geo, sector)
    });
    let mut file: Option<File> = None;
    let mut off = le_u16(rec, 20) as usize;

    while off.saturating_add(8) <= rec.len() {
        let atype = le_u32(rec, off);
        if atype == ATTR_END {
            break;
        }
        let alen = le_u32(rec, off.saturating_add(4)) as usize;
        if alen < 16 || alen > rec.len().saturating_sub(off) {
            break;
        }
        let non_resident = rec.get(off.saturating_add(8)).copied().unwrap_or(0) != 0;
        let attr_flags = le_u16(rec, off.saturating_add(12));
        let name_len = rec.get(off.saturating_add(9)).copied().unwrap_or(0) as usize;

        // Only the unnamed `$DATA` attribute is the file's own content; a named
        // one is an alternate data stream.
        if atype == ATTR_DATA && name_len == 0 {
            if attr_flags & ATTR_ENCRYPTED != 0 {
                file = Some(File {
                    name: String::new(),
                    data: None,
                    unreadable: Some("EFS-encrypted NTFS file"),
                    deleted,
                    stream: None,
                });
            } else if !non_resident {
                let vlen = le_u32(rec, off.saturating_add(16)) as usize;
                let voff = off.saturating_add(le_u16(rec, off.saturating_add(20)) as usize);
                let bytes = crate::bytes::at(rec, voff, vlen).unwrap_or(&[]).to_vec();
                file = Some(File {
                    name: String::new(),
                    data: Some(bytes),
                    unreadable: None,
                    deleted,
                    stream: None,
                });
            } else {
                // A file fragmented past what one record can hold has its runs
                // split across several, listed in `$ATTRIBUTE_LIST`. Gather them
                // all; falling back to this record alone would return the first
                // extent and call it the whole file.
                let spread = list
                    .get_or_insert_with(|| find_attribute_list(rec, v, geo))
                    .as_deref()
                    .map_or(Ok(None), |l| data_extents(l, v, mft, geo, sector));
                let refused = spread.is_err();
                let spread = spread.ok().flatten();
                if refused || (le_u64(rec, off.saturating_add(16)) != 0 && spread.is_none()) {
                    // Only this extent is reachable. Report the shortfall, but
                    // still scan the part that is here.
                    let real_size = crate::bytes::to_usize(le_u64(rec, off.saturating_add(0x30)));
                    let runs_off =
                        off.saturating_add(le_u16(rec, off.saturating_add(0x20)) as usize);
                    let runs =
                        data_runs(rec.get(runs_off..off.saturating_add(alen)).unwrap_or(&[]));
                    let size = real_size.clamp(1, crate::bytes::to_usize(v.len).max(1));
                    let part = if size > cap {
                        Vec::new()
                    } else {
                        read_runs(v, &runs, geo.cluster, size)
                    };
                    file = Some(File {
                        name: String::new(),
                        data: Some(part),
                        unreadable: Some(if refused {
                            "NTFS file whose attribute list names more extents than exav \
                             follows; the extent that could be read was scanned"
                        } else {
                            "NTFS file whose data runs span MFT records exav could not follow; \
                             the extent that could be read was scanned"
                        }),
                        deleted,
                        stream: None,
                    });
                } else {
                    let (runs, real_size) = match spread {
                        Some(found) => found,
                        None => {
                            let real_size =
                                crate::bytes::to_usize(le_u64(rec, off.saturating_add(0x30)));
                            let runs_off =
                                off.saturating_add(le_u16(rec, off.saturating_add(0x20)) as usize);
                            (
                                data_runs(
                                    rec.get(runs_off..off.saturating_add(alen)).unwrap_or(&[]),
                                ),
                                real_size,
                            )
                        }
                    };
                    if real_size > cap && attr_flags & ATTR_COMPRESSED == 0 {
                        // Read as it goes, its holes zeros, where the volume
                        // gives it. Runs short of the declared size are
                        // reported before it, as for a file that is held.
                        let covered = runs.iter().fold(0u64, |n, r| {
                            n.saturating_add(r.clusters.saturating_mul(geo.cluster as u64))
                        });
                        file = Some(File {
                            name: String::new(),
                            data: None,
                            unreadable: (covered < real_size as u64).then_some(
                                "NTFS file whose data runs did not cover its declared size; \
                                 the part that could be read was scanned",
                            ),
                            deleted,
                            stream: Some((runs, real_size as u64)),
                        });
                    } else if real_size > cap {
                        file = Some(File {
                            name: String::new(),
                            data: None,
                            unreadable: Some("NTFS file exceeds the per-member size budget"),
                            deleted,
                            stream: None,
                        });
                    } else if attr_flags & ATTR_COMPRESSED != 0 {
                        // A compression unit is 2^4 clusters in practice.
                        let unit = Some(le_u16(rec, off.saturating_add(0x22)))
                            .filter(|&s| s <= 16)
                            .and_then(|s| 1usize.checked_shl(s.into()))
                            .and_then(|n| n.checked_mul(geo.cluster))
                            .filter(|&n| n <= cap);
                        // Stored compressed, so never more than the file's size
                        // plus a unit; a sparse run is not read past that.
                        let raw = match unit {
                            Some(u) => {
                                read_runs(v, &runs, geo.cluster, real_size.saturating_add(u))
                            }
                            None => Vec::new(),
                        };
                        file = Some(match unit.and_then(|u| decompress(&raw, u, real_size)) {
                            Some(d) => File {
                                name: String::new(),
                                data: Some(d),
                                unreadable: None,
                                deleted,
                                stream: None,
                            },
                            None => File {
                                name: String::new(),
                                data: None,
                                unreadable: Some("NTFS-compressed file that would not decompress"),
                                deleted,
                                stream: None,
                            },
                        });
                    } else if attr_flags & ATTR_SPARSE != 0 || runs.iter().any(|r| r.lcn.is_none())
                    {
                        // Sparse holes read as zeroes, which is what the victim
                        // sees too, so this is still the file.
                        file = Some(File {
                            name: String::new(),
                            data: Some(read_runs(v, &runs, geo.cluster, real_size)),
                            unreadable: None,
                            deleted,
                            stream: None,
                        });
                    } else {
                        let bytes = read_runs(v, &runs, geo.cluster, real_size);
                        // Short of the size the record declares. Passing that off
                        // as the file would be a silent truncation, so it is
                        // reported — *and* the bytes that were read are still
                        // handed over, because a prefix is content and a
                        // signature inside it should still fire. Reporting alone
                        // would be the floor, not the answer.
                        let short = bytes.len() != real_size;
                        file = Some(File {
                            name: String::new(),
                            data: Some(bytes),
                            unreadable: short.then_some(
                                "NTFS file whose data runs did not cover its declared size; \
                                 the part that could be read was scanned",
                            ),
                            deleted,
                            stream: None,
                        });
                    }
                }
            }
        }
        off = off.saturating_add(alen);
    }

    // A file with content and no name anywhere is still a file: the caller
    // names it by its record.
    let mut f = file?;
    f.name = name.unwrap_or_default();
    Some(f)
}

/// The name a resident `$FILE_NAME` attribute at `off` gives, unless it is the
/// DOS 8.3 alias, which names a file we already have under its real name.
fn file_name_attr(rec: &[u8], off: usize) -> Option<String> {
    let voff = off.saturating_add(le_u16(rec, off.saturating_add(20)) as usize);
    let nlen = rec.get(voff.saturating_add(0x40)).copied().unwrap_or(0) as usize;
    let namespace = rec.get(voff.saturating_add(0x41)).copied().unwrap_or(0);
    if namespace == NAMESPACE_DOS {
        return None;
    }
    let raw = crate::bytes::at(rec, voff.saturating_add(0x42), nlen.saturating_mul(2))?;
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// The longest name of the `$FILE_NAME` attributes in `rec`, which is the Win32
/// name over a POSIX alias of the same file.
fn record_name(rec: &[u8]) -> Option<String> {
    let mut name: Option<String> = None;
    let mut off = le_u16(rec, 20) as usize;
    while off.saturating_add(8) <= rec.len() {
        let atype = le_u32(rec, off);
        if atype == ATTR_END {
            break;
        }
        let alen = le_u32(rec, off.saturating_add(4)) as usize;
        if alen < 16 || alen > rec.len().saturating_sub(off) {
            break;
        }
        let non_resident = rec.get(off.saturating_add(8)).copied().unwrap_or(0) != 0;
        if atype == ATTR_FILE_NAME
            && !non_resident
            && let Some(n) = file_name_attr(rec, off)
            && name.as_ref().is_none_or(|old| n.len() > old.len())
        {
            name = Some(n);
        }
        off = off.saturating_add(alen);
    }
    name
}

/// The name of a file whose record has none because its `$FILE_NAME` is in an
/// extension record, which the `$ATTRIBUTE_LIST` names.
fn name_from_extensions(
    list: &[u8],
    v: &mut Vol,
    mft: &Mft,
    geo: &Geometry,
    sector: usize,
) -> Option<String> {
    let mut name: Option<String> = None;
    let mut i = 0usize;
    // A record is read once however many entries name it (each read costs the
    // record's size), and no more than [`MAX_LIST_REFS`] are.
    let mut read: std::collections::HashSet<u64> = std::collections::HashSet::new();
    // Bounded by the list, which is bounded by the volume.
    while i.saturating_add(26) <= list.len() {
        let entry_len = le_u16(list, i.saturating_add(4)) as usize;
        if entry_len < 26 {
            break;
        }
        if le_u32(list, i) == ATTR_FILE_NAME {
            let record = le_u64(list, i.saturating_add(16)) & RECORD_NUMBER_MASK;
            if read.len() >= MAX_LIST_REFS {
                break;
            }
            if read.insert(record)
                && let Some(mut r) = mft.record(v, geo, record)
                && r.get(0..4) == Some(RECORD_MAGIC.as_slice())
                && apply_fixups(&mut r, sector)
                && let Some(n) = record_name(&r)
                && name.as_ref().is_none_or(|old| n.len() > old.len())
            {
                name = Some(n);
            }
        }
        i = i.saturating_add(entry_len);
    }
    name
}

/// LZNT1 over a compressed attribute: the runs hold a sequence of compression
/// units, each of which is either a compressed block or stored verbatim.
fn decompress(raw: &[u8], unit_bytes: usize, real_size: usize) -> Option<Vec<u8>> {
    if unit_bytes == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(real_size);
    for chunk in raw.chunks(unit_bytes) {
        if out.len() >= real_size {
            break;
        }
        let mut unit = Vec::new();
        match lznt1::decompress(chunk, &mut unit) {
            Ok(()) => out.extend_from_slice(&unit),
            // A unit that did not compress is stored as-is.
            Err(_) => out.extend_from_slice(chunk),
        }
    }
    if out.len() < real_size {
        return None;
    }
    out.truncate(real_size);
    Some(out)
}

/// Walk a raw NTFS volume.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the NTFS volume `disk`, which is `len` bytes long, handing each file
/// to `visit`.
pub(crate) fn walk_volume<D: Read + Seek, R>(
    mut disk: D,
    len: u64,
    budget: &mut Budget,
    visit: Emit<R>,
) -> Result<Option<R>, LimitHit> {
    let mut v = Vol {
        disk: &mut disk,
        len,
        max: crate::bytes::to_usize(budget.limits().max_buffer_bytes),
    };
    if len < 512 {
        return Ok(None);
    }
    let mut boot = vec![0u8; 512];
    v.disk
        .seek(SeekFrom::Start(0))
        .and_then(|_| v.disk.read_exact(&mut boot))
        .map_err(|e| LimitHit::corrupt(format!("NTFS volume: {e}")))?;
    if !super::sniff::is(&boot, crate::Format::Ntfs) {
        return Ok(None);
    }
    let Some(geo) = geometry(&boot) else {
        budget.count_entry()?;
        return Ok(held(
            visit,
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                len,
                false,
                "implausible NTFS geometry",
            ),
            budget,
        ));
    };

    // Record 0 is `$MFT` itself, and its `$DATA` gives the runs of the whole
    // table — which can be fragmented, so the MFT cannot simply be read
    // linearly from its first cluster.
    let mft_start = geo.mft_lcn.saturating_mul(geo.cluster as u64);
    let Some(mut rec0) = v.at(mft_start, geo.record_size) else {
        budget.count_entry()?;
        return Ok(held(
            visit,
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                len,
                false,
                "NTFS master file table lies outside the image",
            ),
            budget,
        ));
    };
    let sector = le_u16(&boot, 11) as usize;
    if !apply_fixups(&mut rec0, sector) || rec0.get(0..4) != Some(RECORD_MAGIC.as_slice()) {
        budget.count_entry()?;
        return Ok(held(
            visit,
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                len,
                false,
                "NTFS master file table record is not readable",
            ),
            budget,
        ));
    }
    let Some(mft) = Mft::open(&rec0, &mut v, &geo) else {
        budget.count_entry()?;
        return Ok(held(
            visit,
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                len,
                false,
                "NTFS master file table could not be read",
            ),
            budget,
        ));
    };

    let records = crate::bytes::to_usize(mft.size.checked_div(geo.record_size as u64).unwrap_or(0));
    let n = records.min(MAX_RECORDS);
    if records > MAX_RECORDS {
        budget.count_entry()?;
        if let Some(r) = held(
            visit,
            Entry::unsupported(
                format!("<ntfs-records-beyond-{MAX_RECORDS}>"),
                0,
                false,
                "too many MFT records to walk them all",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }

    for i in FIRST_USER_RECORD..n {
        let Some(mut rec) = mft.record(&mut v, &geo, i as u64) else {
            break;
        };
        if rec.get(0..4) != Some(RECORD_MAGIC.as_slice()) {
            continue; // an unused slot
        }
        // Past this point the slot carries the `FILE` magic, so a record IS here
        // and whatever it names is a file on the volume. Failing to read it is a
        // gap to report, not a slot to skip — an unused slot was already handled
        // above, and conflating the two hides real files.
        if !apply_fixups(&mut rec, sector) {
            budget.count_entry()?;
            if let Some(r) = held(
                visit,
                Entry::unsupported(
                    format!("<mft-record-{i}>"),
                    0,
                    false,
                    "NTFS MFT record failed its update-sequence fixups",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }
        let cap = crate::bytes::to_usize(budget.reserve()?);
        // `None` here means "not a user file with content" — a directory, or the
        // volume's own metadata — not a parse failure. Reporting it would flag
        // every healthy volume, which the reserved records 16..63 make loud.
        let Some(f) = parse_record(&rec, &mut v, &mft, &geo, sector, cap) else {
            continue;
        };
        // A deleted record's runs may since have been reused by another file, so
        // its bytes are marked rather than presented as that file's content.
        let base = if f.name.is_empty() {
            format!("<mft-record-{i}>")
        } else {
            f.name
        };
        let name = if f.deleted {
            format!("<deleted>/{base}")
        } else {
            base
        };
        // A file can be both partly readable and short: the report says what is
        // missing, and the bytes that exist are still scanned. Emitting only one
        // of the two would either hide the gap or throw away content.
        if let Some(why) = f.unreadable {
            budget.count_entry()?;
            if let Some(r) = held(
                visit,
                Entry::unsupported(name.clone(), 0, why.contains("encrypted"), why),
                budget,
            ) {
                return Ok(Some(r));
            }
        }
        if let Some(d) = f.data
            && !d.is_empty()
        {
            budget.count_entry()?;
            budget.commit(d.len() as u64);
            if let Some(r) = held(visit, Entry::new(name, d), budget) {
                return Ok(Some(r));
            }
        } else if let Some((runs, size)) = f.stream {
            budget.count_entry()?;
            let plan = Runs {
                runs: runs.into_iter(),
                cluster: geo.cluster as u64,
            };
            let got = read_file(&mut v, Pieces::new(plan, size), size, 0);
            if let Some(r) = hand(budget, &mut *visit, name, Attrs::default(), got) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A volume of 16 clusters of 4 bytes, each byte its own index.
    fn volume() -> Cursor<Vec<u8>> {
        Cursor::new((0..64u8).collect())
    }

    fn runs() -> Vec<Run> {
        vec![
            Run {
                lcn: Some(2),
                clusters: 2,
            },
            Run {
                lcn: None,
                clusters: 1,
            },
            Run {
                lcn: Some(8),
                clusters: 1,
            },
        ]
    }

    /// The attribute those runs describe, 16 bytes.
    fn attribute() -> Vec<u8> {
        let v: Vec<u8> = (0..64).collect();
        [&v[8..16], &[0; 4][..], &v[32..36]].concat()
    }

    fn range(vol: &mut Cursor<Vec<u8>>, runs: &[Run], at: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = Vol {
            len: vol.get_ref().len() as u64,
            disk: vol,
            max: usize::MAX,
        };
        let mut out = Vec::new();
        read_runs_at(&mut v, runs, 4, at, len, &mut out).then_some(out)
    }

    #[test]
    fn a_range_of_an_attribute_is_read_across_its_runs_and_holes() {
        let want = attribute();
        for (at, len) in [(0, 16), (3, 9), (8, 4), (11, 2), (12, 4), (15, 1), (16, 0)] {
            assert_eq!(
                range(&mut volume(), &runs(), at, len),
                Some(want[at as usize..at as usize + len].to_vec()),
                "({at}, {len})"
            );
        }
        // Past the end of the runs.
        assert_eq!(range(&mut volume(), &runs(), 14, 4), None);
        assert_eq!(range(&mut volume(), &runs(), u64::MAX - 2, 8), None);
    }

    #[test]
    fn a_range_is_none_where_a_run_is_not_readable() {
        let past = vec![Run {
            lcn: Some(15),
            clusters: 2,
        }];
        assert_eq!(range(&mut volume(), &past, 0, 4).map(|v| v.len()), Some(4));
        assert_eq!(range(&mut volume(), &past, 0, 8), None);
        let negative = vec![Run {
            lcn: Some(-1),
            clusters: 2,
        }];
        assert_eq!(range(&mut volume(), &negative, 0, 4), None);
        let top = vec![Run {
            lcn: Some(i64::MAX),
            clusters: u64::MAX,
        }];
        assert_eq!(range(&mut volume(), &top, 0, 4), None);
    }

    /// A read the volume cannot satisfy appends nothing, however much it asks.
    #[test]
    fn a_read_past_the_volume_appends_nothing_and_allocates_nothing() {
        let mut vol = volume();
        let mut v = Vol {
            len: 64,
            disk: &mut vol,
            max: usize::MAX,
        };
        let mut out = vec![9u8];
        assert!(!v.append(60, 5, &mut out));
        assert!(!v.append(0, usize::MAX, &mut out));
        assert!(!v.append(u64::MAX, 2, &mut out));
        assert_eq!(out, [9]);
        assert!(v.append(60, 4, &mut out));
        assert_eq!(out, [9, 60, 61, 62, 63]);
    }
}
