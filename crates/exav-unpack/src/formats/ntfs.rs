//! NTFS: walking the Master File Table.
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
//! table and case-insensitive lookup entirely, and it picks up something a
//! directory walk cannot: a **deleted file whose MFT record still holds its data
//! runs**. A dropper that removed itself is still there to be scanned.
//!
//! ```text
//! boot sector      bytes/sector, sectors/cluster, where $MFT starts
//!   $MFT record 0  its own $DATA runs (the MFT itself can be fragmented)
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
//! two-run file are checked byte-for-byte against `ntfscat`: the two-run volume
//! is a real one whose run list was split in half, and ntfs-3g reads the result
//! back to the same digest, so an independent implementation agrees the layout
//! is valid. Two paths are implemented but have no fixture behind them: extents
//! spread across MFT records via `$ATTRIBUTE_LIST`, and LZNT1 compression.
//! `mkntfs`/`ntfscp` cannot produce either, and a hand-built multi-record volume
//! was rejected by `ntfscat`, so it is not used as proof of anything. Closing
//! that needs a volume made by Windows: a heavily fragmented file, and one run
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
use std::io::SeekFrom;

use super::vol::{
    Attrs, Emit, Fill, Found, Next, Piece, Pieces, Plan, STEP, Step, Vol, hand, read_file,
};
use crate::source::ByteSource;
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

/// `$FILE_NAME` namespaces. The DOS 8.3 alias duplicates a name we already have.
const NAMESPACE_DOS: u8 = 2;

/// The low 48 bits of a file reference are the record number.
const RECORD_NUMBER_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Records 0..15 are the filesystem's own metadata (`$MFT`, `$LogFile`,
/// `$UpCase` and friends). They are skipped, and skipping them loses nothing: the
/// volume's raw bytes are pattern-scanned before this walk runs, so anything
/// hidden in `$BadClus` or the journal in plain form is already covered. What
/// the walk adds over that raw scan is reassembly and decompression, and neither
/// applies to metadata. Emitting them would spend the budget on megabytes of
/// `$LogFile` and `$UpCase` instead.
const FIRST_USER_RECORD: usize = 16;

/// The most runs read from one run list.
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
fn held(visit: Emit, e: Entry, budget: &mut Budget) -> Option<crate::Stop> {
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
    /// Bytes the table is declared to have, no more than the volume has.
    declared: u64,
}

impl Mft {
    /// The table of `runs` that is `real_size` bytes long, in a volume of
    /// `volume` bytes. The table cannot be larger than the volume it is in,
    /// and it is only as long as its runs can be read.
    fn over(runs: Vec<Run>, real_size: u64, volume: u64, geo: &Geometry) -> Option<Mft> {
        let limit = real_size.min(volume);
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
                    if start.checked_add(take).is_none_or(|e| e > volume) {
                        break;
                    }
                    size = size.saturating_add(take);
                }
                Some(_) => break,
            }
        }
        (size > 0).then_some(Mft {
            runs,
            size,
            declared: limit,
        })
    }

    /// The table `rec0`, record 0, describes: the runs of its first extent.
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
                return Mft::over(runs, real_size, v.len, geo);
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
/// **attacker-controlled** (fragment a file hard enough and it crosses), so
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
/// list itself out of the record, and that threshold is reachable on purpose.
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
    /// The runs and the size of a file to be read as it goes: one too long to
    /// hold, or one stored compressed, with the clusters of its compression
    /// unit.
    stream: Option<(Vec<Run>, u64, Option<u64>)>,
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
    let mut several = false;
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
        // one is an alternate data stream. Windows reads the first of them, so
        // a second is not the file: it is said to be left out.
        if atype == ATTR_DATA && name_len == 0 && file.is_some() {
            several = true;
        } else if atype == ATTR_DATA && name_len == 0 {
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
                    if attr_flags & ATTR_COMPRESSED != 0 {
                        // Stored compressed: read a compression unit at a time,
                        // held when the file fits and read as it goes when not.
                        // A unit is 2^4 clusters in practice.
                        let unit = Some(le_u16(rec, off.saturating_add(0x22)))
                            .filter(|&s| s <= 16)
                            .and_then(|s| 1u64.checked_shl(s.into()))
                            .filter(|&n| n.saturating_mul(geo.cluster as u64) <= v.max as u64);
                        file = Some(match unit {
                            _ if real_size == 0 => File {
                                name: String::new(),
                                data: Some(Vec::new()),
                                unreadable: None,
                                deleted,
                                stream: None,
                            },
                            Some(u) => File {
                                name: String::new(),
                                data: None,
                                unreadable: None,
                                deleted,
                                stream: Some((runs, real_size as u64, Some(u))),
                            },
                            None => File {
                                name: String::new(),
                                data: None,
                                unreadable: Some(
                                    "NTFS-compressed file whose compression unit is over \
                                     the buffer limit",
                                ),
                                deleted,
                                stream: None,
                            },
                        });
                    } else if real_size > cap {
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
                            stream: Some((runs, real_size as u64, None)),
                        });
                    } else {
                        // Sparse holes read as zeroes, which is what the victim
                        // sees too, so they are still the file; but runs that
                        // stop short of the size are not, holes or not.
                        let bytes = read_runs(v, &runs, geo.cluster, real_size);
                        // Short of the size the record declares. Passing that off
                        // as the file would be a silent truncation, so it is
                        // reported, *and* the bytes that were read are still
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
    if several && f.unreadable.is_none() {
        f.unreadable = Some(
            "NTFS record with several unnamed data attributes: the first, which Windows \
             reads, was scanned and the others were not",
        );
    }
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

/// A file stored compressed, produced a compression unit at a time. The
/// clusters a unit has allocated tell how it is stored, as they do on Windows:
/// all of them, it is stored as it is; none, it is a hole; fewer than the unit
/// has (the rest sparse), it is LZNT1 and decodes to the unit's size. Whether
/// the bytes of a unit decode is not what decides.
struct Compressed {
    runs: std::vec::IntoIter<Run>,
    /// What is left of the run the last unit ended in.
    rest: Option<Run>,
    cluster: u64,
    /// Clusters in a unit.
    unit: u64,
    /// Bytes of the file not yet produced.
    left: u64,
    holes: u64,
    packed: Vec<u8>,
}

impl Compressed {
    fn new(runs: Vec<Run>, cluster: u64, unit: u64, size: u64) -> Self {
        Compressed {
            runs: runs.into_iter(),
            rest: None,
            cluster,
            unit,
            left: size,
            holes: 0,
            packed: Vec::new(),
        }
    }

    /// Up to `want` clusters of the runs that follow, as runs of their own
    /// pushed to `pieces`; how many there were.
    fn take(&mut self, want: u64, pieces: &mut Vec<Run>) -> u64 {
        let mut left = want;
        while left > 0 {
            let Some(r) = self.rest.take().or_else(|| self.runs.next()) else {
                break;
            };
            let n = r.clusters.min(left);
            if n == 0 {
                continue;
            }
            pieces.push(Run {
                lcn: r.lcn,
                clusters: n,
            });
            left = left.saturating_sub(n);
            if r.clusters > n {
                self.rest = Some(Run {
                    lcn: r
                        .lcn
                        .map(|l| l.saturating_add(i64::try_from(n).unwrap_or(i64::MAX))),
                    clusters: r.clusters.saturating_sub(n),
                });
            }
        }
        want.saturating_sub(left)
    }

    /// The clusters of the whole units of a hole that the next run goes on
    /// with, to be produced with the unit just taken, up to a step.
    fn more_hole(&mut self) -> u64 {
        if self.rest.is_none() {
            self.rest = self.runs.next();
        }
        let unit_bytes = self.unit.saturating_mul(self.cluster).max(1);
        let most = (STEP as u64).checked_div(unit_bytes).unwrap_or(0);
        match &self.rest {
            Some(Run {
                lcn: None,
                clusters,
            }) => {
                let units = clusters.checked_div(self.unit).unwrap_or(0);
                let k = units.min(most.saturating_sub(1));
                let used = k.saturating_mul(self.unit);
                if used > 0 {
                    self.rest = Some(Run {
                        lcn: None,
                        clusters: clusters.saturating_sub(used),
                    });
                }
                used
            }
            _ => 0,
        }
    }
}

const RUNS_END: &str = "NTFS compressed file whose runs end before its size";
const CLUSTERS_CUT: &str = "NTFS compressed file with clusters that are not all in the volume";
const NOT_DECOMPRESSED: &str = "NTFS compressed file with a unit that did not decompress";

impl Fill for Compressed {
    fn holes(&self) -> u64 {
        self.holes
    }

    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step {
        if self.left == 0 {
            return Step::End;
        }
        let mut pieces = Vec::new();
        let got = self.take(self.unit, &mut pieces);
        // The runs end before the file does.
        if got == 0 {
            return Step::Broken(RUNS_END);
        }
        let allocated = pieces
            .iter()
            .filter(|r| r.lcn.is_some())
            .fold(0u64, |n, r| n.saturating_add(r.clusters));
        let unit_bytes = crate::bytes::to_usize(self.unit.saturating_mul(self.cluster));
        let base = out.len();
        let give = if allocated == 0 {
            // A hole, and as many whole units of the same one as fit a step.
            let more = if got == self.unit {
                self.more_hole()
            } else {
                0
            };
            let bytes = got.saturating_add(more).saturating_mul(self.cluster);
            let give = bytes.min(self.left);
            out.resize(base.saturating_add(crate::bytes::to_usize(give)), 0);
            self.holes = self.holes.saturating_add(give);
            give
        } else if allocated == self.unit {
            // Stored as it is.
            for r in &pieces {
                if !read_cluster_run(v, r, self.cluster, out) {
                    out.truncate(base);
                    return Step::Broken(CLUSTERS_CUT);
                }
            }
            let give = (out.len().saturating_sub(base) as u64).min(self.left);
            out.truncate(base.saturating_add(crate::bytes::to_usize(give)));
            give
        } else {
            // LZNT1, over the clusters allocated.
            self.packed.clear();
            for r in pieces.iter().filter(|r| r.lcn.is_some()) {
                if !read_cluster_run(v, r, self.cluster, &mut self.packed) {
                    return Step::Broken(CLUSTERS_CUT);
                }
            }
            let mut plain = Vec::new();
            if lznt1::decompress(&self.packed, &mut plain).is_err() {
                return Step::Broken(NOT_DECOMPRESSED);
            }
            plain.resize(unit_bytes, 0);
            let give = (unit_bytes as u64).min(self.left);
            out.extend_from_slice(&plain[..crate::bytes::to_usize(give)]);
            give
        };
        self.left = self.left.saturating_sub(give);
        Step::More
    }
}

/// The clusters of run `r`, which is not a hole, appended to `out`.
fn read_cluster_run(v: &mut Vol, r: &Run, cluster: u64, out: &mut Vec<u8>) -> bool {
    let (Some(at), Some(len)) = (
        r.lcn
            .and_then(|l| u64::try_from(l).ok())
            .and_then(|l| l.checked_mul(cluster)),
        r.clusters.checked_mul(cluster),
    ) else {
        return false;
    };
    v.append(at, crate::bytes::to_usize(len), out)
}

/// Walk a raw NTFS volume.
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    super::volumes::walk_source(src, budget, visit, walk_volume)
}

/// Walk the NTFS volume `disk`, which is `len` bytes long, handing each file
/// to `visit`.
pub(crate) fn walk_volume(
    disk: &mut dyn super::vol::Disk,
    len: u64,
    budget: &mut Budget,
    visit: Emit,
) -> crate::Extracted {
    let mut v = Vol {
        disk,
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
    // table, which can be fragmented, so the MFT cannot simply be read
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
    // A table fragmented past what its record holds has the rest of its runs
    // in the records its attribute list names, which the first extent is where
    // to find. Records past the first extent are files like the others.
    let listed = find_attribute_list(&rec0, &mut v, &geo);
    let mft = match listed
        .as_deref()
        .map(|l| data_extents(l, &mut v, &mft, &geo, sector))
    {
        Some(Ok(Some((runs, real_size)))) => {
            Mft::over(runs, real_size as u64, len, &geo).unwrap_or(mft)
        }
        _ => mft,
    };
    if listed.is_some() && mft.size < mft.declared {
        budget.count_entry()?;
        if let Some(r) = held(
            visit,
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                len,
                false,
                "NTFS master file table not fully mapped: the records past what it maps \
                 were not walked",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }

    let records = crate::bytes::to_usize(mft.size.checked_div(geo.record_size as u64).unwrap_or(0));

    // Each record of the table is one member, used or not, and the members a
    // record yields are not counted again: the limit is on the records read,
    // so a table that declares more than `max_members` ends the walk with the
    // limit, as one entry too many does in any container.
    for i in FIRST_USER_RECORD..records {
        budget.count_entry()?;
        let Some(mut rec) = mft.record(&mut v, &geo, i as u64) else {
            break;
        };
        if rec.get(0..4) != Some(RECORD_MAGIC.as_slice()) {
            continue; // an unused slot
        }
        // Past this point the slot carries the `FILE` magic, so a record IS here
        // and whatever it names is a file on the volume. Failing to read it is a
        // gap to report, not a slot to skip: an unused slot was already handled
        // above, and conflating the two hides real files.
        if !apply_fixups(&mut rec, sector) {
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
        // `None` here means "not a user file with content" (a directory, or the
        // volume's own metadata), not a parse failure. Reporting it would flag
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
        if let Some(why) = f.unreadable
            && let Some(r) = held(
                visit,
                Entry::unsupported(name.clone(), 0, why.contains("encrypted"), why),
                budget,
            )
        {
            return Ok(Some(r));
        }
        if let Some(d) = f.data
            && !d.is_empty()
        {
            budget.commit(d.len() as u64);
            if let Some(r) = held(visit, Entry::new(name, d), budget) {
                return Ok(Some(r));
            }
        } else if let Some((runs, size, unit)) = f.stream {
            let cluster = geo.cluster as u64;
            let got = match unit {
                // Held when it fits what a member may hold, as a file is.
                Some(unit) => read_file(
                    &mut v,
                    Compressed::new(runs, cluster, unit, size),
                    size,
                    cap as u64,
                ),
                None => {
                    let plan = Runs {
                        runs: runs.into_iter(),
                        cluster,
                    };
                    read_file(&mut v, Pieces::new(plan, size), size, 0)
                }
            };
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

    /// A volume of 64 clusters of 16 bytes holding a file of compression units
    /// of 4 clusters, one of each way a unit is stored, with the file as
    /// Windows reads it and the runs that describe it:
    ///
    /// 0. compressed, in the fewest clusters, the rest of the unit sparse;
    /// 1. stored as it is, in four clusters, its bytes a valid LZNT1 chunk, an
    ///    end marker and then the payload;
    /// 2. a hole of four clusters;
    /// 3. compressed to fewer bytes than a unit (zeros after them);
    /// 4. a hole of sixteen clusters, four units;
    /// 5. stored as it is, the last unit, the file ending inside it.
    fn compressed_file() -> (Vec<u8>, Vec<Run>, Vec<u8>) {
        const UNIT: usize = 64;
        let mut disk = vec![0u8; 16 * 64];
        let mut file = Vec::new();
        let mut runs = Vec::new();
        let clusters = |bytes: usize| bytes.div_ceil(16) as u64;
        let place = |disk: &mut Vec<u8>, at: u64, bytes: &[u8]| {
            let from = at as usize * 16;
            disk[from..from + bytes.len()].copy_from_slice(bytes);
        };
        let repetitive =
            |word: &[u8], n: usize| -> Vec<u8> { word.iter().cycle().take(n).copied().collect() };

        let plain = repetitive(b"compressible ", UNIT);
        let mut packed = Vec::new();
        lznt1::compress(&plain, &mut packed);
        assert!(clusters(packed.len()) < 4);
        place(&mut disk, 2, &packed);
        runs.push(Run {
            lcn: Some(2),
            clusters: clusters(packed.len()),
        });
        runs.push(Run {
            lcn: None,
            clusters: 4 - clusters(packed.len()),
        });
        file.extend_from_slice(&plain);

        let mut raw = Vec::new();
        lznt1::compress(&repetitive(b"benign ", 28), &mut raw);
        raw.extend_from_slice(&[0, 0]);
        raw.extend_from_slice(b"PAYLOAD-AFTER-THE-END-MARKER");
        raw.resize(UNIT, b'#');
        place(&mut disk, 8, &raw);
        runs.push(Run {
            lcn: Some(8),
            clusters: 4,
        });
        file.extend_from_slice(&raw);

        runs.push(Run {
            lcn: None,
            clusters: 4,
        });
        file.extend_from_slice(&[0; UNIT]);

        let short = repetitive(b"short unit ", 40);
        let mut packed = Vec::new();
        lznt1::compress(&short, &mut packed);
        assert!(clusters(packed.len()) < 4);
        place(&mut disk, 20, &packed);
        runs.push(Run {
            lcn: Some(20),
            clusters: clusters(packed.len()),
        });
        runs.push(Run {
            lcn: None,
            clusters: 4 - clusters(packed.len()),
        });
        file.extend_from_slice(&short);
        file.resize(file.len() + UNIT - short.len(), 0);

        runs.push(Run {
            lcn: None,
            clusters: 16,
        });
        file.extend_from_slice(&[0; 4 * UNIT]);

        let last = repetitive(b"last unit, stored. ", UNIT);
        place(&mut disk, 40, &last);
        runs.push(Run {
            lcn: Some(40),
            clusters: 4,
        });
        // The file ends 10 bytes into the last unit's final cluster.
        file.extend_from_slice(&last[..UNIT - 10]);
        (disk, runs, file)
    }

    /// What `read_file` gives of the file: the bytes, the bytes of holes among
    /// them, whether it came as a stream, and whether it was whole.
    fn read_compressed(cap: u64, runs: Vec<Run>, size: u64) -> (Vec<u8>, u64, bool, bool) {
        use crate::formats::vol::Got;
        let (disk, ..) = compressed_file();
        let mut cursor = Cursor::new(disk);
        let mut v = Vol {
            len: cursor.get_ref().len() as u64,
            disk: &mut cursor,
            max: usize::MAX,
        };
        match read_file(&mut v, Compressed::new(runs, 16, 4, size), size, cap) {
            Got::Whole(d) => (d, 0, false, true),
            Got::Partial(d, _) => (d, 0, false, false),
            Got::Stream(mut r, _, holes) => {
                let mut d = Vec::new();
                let whole = r.read_to_end(&mut d).is_ok();
                (d, holes.get(), true, whole)
            }
            _ => panic!("neither held nor read as it goes"),
        }
    }

    /// Every unit is what its allocation says: a stored unit that starts like
    /// LZNT1 is the bytes it holds, a hole is a whole unit of zeros (the next
    /// units are not moved up), and a unit that decodes to less is padded to
    /// its size.
    #[test]
    fn a_compressed_file_is_read_by_the_clusters_each_unit_has_allocated() {
        let (_, runs, file) = compressed_file();
        let size = file.len() as u64;
        // Held, and read as it goes: the same bytes.
        let (held, _, streamed, whole) = read_compressed(size, runs.clone(), size);
        assert!(whole && !streamed);
        assert!(held == file, "held");
        let (went, holes, streamed, whole) = read_compressed(100, runs, size);
        assert!(whole && streamed);
        assert!(went == file, "read as it goes");
        // The hole of unit 2 and the four units of the hole, and the sparse
        // parts of the compressed units that are not read at all.
        assert_eq!(holes, 5 * 64);
    }

    /// A unit that is stored and whose bytes are a valid LZNT1 chunk and an end
    /// marker is not decoded: that is what the old rule, "does it decode",
    /// turned into the short benign text.
    #[test]
    fn a_stored_unit_that_starts_like_lznt1_is_not_decoded() {
        let (_, runs, file) = compressed_file();
        let (got, ..) = read_compressed(u64::MAX, runs, file.len() as u64);
        let marker = b"PAYLOAD-AFTER-THE-END-MARKER";
        assert!(got.windows(marker.len()).any(|w| w == marker));
    }

    /// The run list `runs` as an MFT record holds it: lengths of a byte, offsets
    /// of two bytes, holes with none.
    fn encoded(runs: &[Run]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0i64;
        for r in runs {
            match r.lcn {
                None => out.extend_from_slice(&[0x01, r.clusters as u8]),
                Some(lcn) => {
                    out.extend_from_slice(&[0x21, r.clusters as u8]);
                    out.extend_from_slice(&((lcn - at) as i16).to_le_bytes());
                    at = lcn;
                }
            }
        }
        out.push(0);
        out
    }

    /// A record with one non-resident `$DATA` attribute, `flags` and a
    /// compression unit of 2^`unit` clusters.
    fn record(runs: &[Run], size: u64, flags: u16, unit: u16) -> Vec<u8> {
        let mut rec = vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[20..22].copy_from_slice(&0x38u16.to_le_bytes());
        rec[22..24].copy_from_slice(&1u16.to_le_bytes());
        let list = encoded(runs);
        let len = (0x48 + list.len()).next_multiple_of(8);
        let a = 0x38;
        rec[a..a + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        rec[a + 4..a + 8].copy_from_slice(&(len as u32).to_le_bytes());
        rec[a + 8] = 1;
        rec[a + 12..a + 14].copy_from_slice(&flags.to_le_bytes());
        rec[a + 0x20..a + 0x22].copy_from_slice(&0x48u16.to_le_bytes());
        rec[a + 0x22..a + 0x24].copy_from_slice(&unit.to_le_bytes());
        rec[a + 0x30..a + 0x38].copy_from_slice(&size.to_le_bytes());
        rec[a + 0x48..a + 0x48 + list.len()].copy_from_slice(&list);
        rec[a + len..a + len + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        rec
    }

    /// The record of a compressed file is read by the unit it names, held or
    /// read as it goes, whatever its size against what a member may hold.
    #[test]
    fn a_record_of_a_compressed_file_is_read_through_its_units() {
        let (disk, runs, file) = compressed_file();
        let size = file.len() as u64;
        let geo = Geometry {
            cluster: 16,
            record_size: 1024,
            mft_lcn: 0,
        };
        let mft = Mft {
            runs: Vec::new(),
            size: 0,
            declared: 0,
        };
        for cap in [10, usize::MAX] {
            let mut cursor = Cursor::new(disk.clone());
            let mut v = Vol {
                len: disk.len() as u64,
                disk: &mut cursor,
                max: usize::MAX,
            };
            let rec = record(&runs, size, ATTR_COMPRESSED, 2);
            let f = parse_record(&rec, &mut v, &mft, &geo, 512, cap).expect("a file");
            assert!(f.data.is_none() && f.unreadable.is_none(), "cap {cap}");
            let (stream_runs, n, unit) = f.stream.expect("read through its units");
            assert_eq!((n, unit), (size, Some(4)), "cap {cap}");
            let fill = Compressed::new(stream_runs, 16, 4, n);
            let got = match read_file(&mut v, fill, n, u64::MAX) {
                crate::formats::vol::Got::Whole(d) => d,
                _ => panic!("cap {cap}: not held"),
            };
            assert!(got == file, "cap {cap}");
        }
        // A unit over the buffer limit is reported, not read.
        let mut cursor = Cursor::new(disk.clone());
        let mut v = Vol {
            len: disk.len() as u64,
            disk: &mut cursor,
            max: 32,
        };
        let rec = record(&runs, size, ATTR_COMPRESSED, 2);
        let f = parse_record(&rec, &mut v, &mft, &geo, 512, usize::MAX).expect("a file");
        assert!(f.stream.is_none() && f.unreadable.is_some_and(|r| r.contains("compression unit")));
    }

    /// A resident, unnamed attribute of type `kind` holding `value`.
    fn resident(kind: u32, value: &[u8]) -> Vec<u8> {
        let len = (24 + value.len()).next_multiple_of(8);
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&kind.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        a[20..22].copy_from_slice(&24u16.to_le_bytes());
        a[24..24 + value.len()].copy_from_slice(value);
        a
    }

    /// Windows reads the first unnamed `$DATA` of a record. The file is that
    /// one, and a record with another says it left it out, as it is in no
    /// other pass.
    #[test]
    fn the_first_of_two_unnamed_data_attributes_is_the_file_and_the_other_is_said() {
        let parse = |values: &[&[u8]]| {
            let mut rec = vec![0u8; 1024];
            rec[0..4].copy_from_slice(b"FILE");
            rec[20..22].copy_from_slice(&0x38u16.to_le_bytes());
            rec[22..24].copy_from_slice(&1u16.to_le_bytes());
            let mut at = 0x38;
            for value in values {
                let a = resident(ATTR_DATA, value);
                rec[at..at + a.len()].copy_from_slice(&a);
                at += a.len();
            }
            rec[at..at + 4].copy_from_slice(&ATTR_END.to_le_bytes());
            let geo = Geometry {
                cluster: 16,
                record_size: 1024,
                mft_lcn: 0,
            };
            let mft = Mft {
                runs: Vec::new(),
                size: 0,
                declared: 0,
            };
            let mut cursor = Cursor::new(vec![0u8; 64]);
            let mut v = Vol {
                len: 64,
                disk: &mut cursor,
                max: usize::MAX,
            };
            parse_record(&rec, &mut v, &mft, &geo, 512, usize::MAX).expect("a file")
        };
        let f = parse(&[b"first, as Windows reads it", b"second, not read"]);
        assert_eq!(f.data.as_deref(), Some(&b"first, as Windows reads it"[..]));
        assert!(f.unreadable.is_some_and(|r| r.contains("several unnamed")));
        let f = parse(&[b"alone"]);
        assert_eq!(f.data.as_deref(), Some(&b"alone"[..]));
        assert!(f.unreadable.is_none());
    }

    /// A non-resident unnamed `$DATA` attribute whose first VCN is `first`.
    fn extent(runs: &[Run], first: u64, size: u64) -> Vec<u8> {
        let list = encoded(runs);
        let len = (0x48 + list.len()).next_multiple_of(8);
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[8] = 1;
        a[16..24].copy_from_slice(&first.to_le_bytes());
        a[0x20..0x22].copy_from_slice(&0x48u16.to_le_bytes());
        a[0x30..0x38].copy_from_slice(&size.to_le_bytes());
        a[0x48..0x48 + list.len()].copy_from_slice(&list);
        a
    }

    /// An MFT record of `attrs` with its update sequence in place.
    fn mft_record(attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut rec = vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[20..22].copy_from_slice(&0x38u16.to_le_bytes());
        rec[22..24].copy_from_slice(&1u16.to_le_bytes());
        let mut at = 0x38;
        for a in attrs {
            rec[at..at + a.len()].copy_from_slice(a);
            at += a.len();
        }
        rec[at..at + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        for end in [0x30, 510, 1022] {
            rec[end..end + 2].copy_from_slice(&[1, 0]);
        }
        rec
    }

    /// A volume of 100 clusters of 512 bytes whose `$MFT` is in two extents of
    /// 20 records each, the second named by the attribute list of record 0 and
    /// described in record 15. Record 30, in the second extent, is a file.
    fn split_mft_volume() -> Vec<u8> {
        let mut disk = vec![0u8; 512 * 100];
        disk[3..11].copy_from_slice(b"NTFS    ");
        disk[11..13].copy_from_slice(&512u16.to_le_bytes());
        disk[13] = 1;
        disk[0x30..0x38].copy_from_slice(&2u64.to_le_bytes());
        disk[0x40] = 0xF6;
        disk[510..512].copy_from_slice(&[0x55, 0xAA]);
        let first = [Run {
            lcn: Some(2),
            clusters: 40,
        }];
        let second = [Run {
            lcn: Some(50),
            clusters: 40,
        }];
        let mut list = Vec::new();
        for (vcn, record) in [(0u64, 0u64), (40, 15)] {
            let mut e = vec![0u8; 32];
            e[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
            e[4..6].copy_from_slice(&32u16.to_le_bytes());
            e[7] = 26;
            e[8..16].copy_from_slice(&vcn.to_le_bytes());
            e[16..24].copy_from_slice(&record.to_le_bytes());
            list.extend_from_slice(&e);
        }
        let mut put = |at: usize, rec: &[u8]| disk[at..at + rec.len()].copy_from_slice(rec);
        put(
            2 * 512,
            &mft_record(&[resident(0x20, &list), extent(&first, 0, 40960)]),
        );
        put(2 * 512 + 15 * 1024, &mft_record(&[extent(&second, 40, 0)]));
        put(
            50 * 512 + 10 * 1024,
            &mft_record(&[resident(ATTR_DATA, b"payload in the second extent")]),
        );
        disk
    }

    /// Each member of the volume `disk`: name, bytes, why not whole.
    fn walked(disk: Vec<u8>) -> Vec<(String, Vec<u8>, Option<&'static str>)> {
        let len = disk.len() as u64;
        let mut budget = crate::Budget::new(crate::Limits::default());
        let mut got = Vec::new();
        walk_volume(
            &mut Cursor::new(disk),
            len,
            &mut budget,
            &mut |f: Found<'_>, _: &mut Budget| {
                let e = f.whole();
                got.push((e.name, e.data, e.unsupported));
                None
            },
        )
        .unwrap();
        got
    }

    /// The records of a `$MFT` past its first extent are files too: the
    /// extents are found through the attribute list of record 0. When they
    /// cannot be, the volume says the table was not walked to its end.
    #[test]
    fn a_master_file_table_in_two_extents_is_walked_to_its_end() {
        let got = walked(split_mft_volume());
        let names: Vec<&String> = got.iter().map(|g| &g.0).collect();
        let file = got
            .iter()
            .find(|g| g.0 == "<mft-record-30>")
            .unwrap_or_else(|| panic!("{names:?}"));
        assert_eq!(file.1, b"payload in the second extent");
        assert!(got.iter().all(|g| g.2.is_none()), "{names:?}");

        let mut broken = split_mft_volume();
        broken[2 * 512 + 15 * 1024..2 * 512 + 16 * 1024].fill(0);
        let got = walked(broken);
        assert!(
            got.iter()
                .any(|g| g.2.is_some_and(|r| r.contains("not fully mapped")))
        );
        assert!(!got.iter().any(|g| g.0 == "<mft-record-30>"));
    }

    /// A unit whose clusters do not decode, a file whose runs end before it
    /// does, and a compression unit that is not the one the runs were cut
    /// by, are each not whole: never a short file passed off as the file.
    #[test]
    fn a_compressed_file_the_volume_does_not_give_is_not_whole() {
        let (_, runs, file) = compressed_file();
        let size = file.len() as u64;
        // The first unit's compressed clusters are garbage.
        let (mut bad, ..) = compressed_file();
        bad[2 * 16..2 * 16 + 4].copy_from_slice(&[0xFF, 0xBF, 1, 2]);
        let mut cursor = Cursor::new(bad);
        let mut v = Vol {
            len: cursor.get_ref().len() as u64,
            disk: &mut cursor,
            max: usize::MAX,
        };
        let got = read_file(
            &mut v,
            Compressed::new(runs.clone(), 16, 4, size),
            size,
            u64::MAX,
        );
        assert!(
            matches!(&got, crate::formats::vol::Got::Partial(_, why) if why.contains("did not decompress")),
            "a unit that does not decompress"
        );
        // Runs that end before the size does.
        let (_, _, _, whole) = read_compressed(u64::MAX, runs[..4].to_vec(), size);
        assert!(!whole);
        let (_, _, _, whole) = read_compressed(100, runs[..4].to_vec(), size);
        assert!(!whole);
    }

    /// Why a compressed file breaks, held and read as it goes: the reason of
    /// the held file, and the error that ends the read of the other.
    fn why_it_breaks(runs: Vec<Run>, size: u64) -> (String, String) {
        use crate::formats::vol::Got;
        let (disk, ..) = compressed_file();
        let mut said = Vec::new();
        for cap in [u64::MAX, 100] {
            let mut cursor = Cursor::new(disk.clone());
            let mut v = Vol {
                len: cursor.get_ref().len() as u64,
                disk: &mut cursor,
                max: usize::MAX,
            };
            said.push(
                match read_file(
                    &mut v,
                    Compressed::new(runs.clone(), 16, 4, size),
                    size,
                    cap,
                ) {
                    Got::Partial(_, why) => why.to_string(),
                    Got::Stream(mut r, ..) => r
                        .read_to_end(&mut Vec::new())
                        .err()
                        .map_or_else(|| "whole".to_string(), |e| e.to_string()),
                    _ => "whole".to_string(),
                },
            );
        }
        (said[0].clone(), said[1].clone())
    }

    /// Each way a compressed file breaks has its own reason, held or read as it
    /// goes.
    #[test]
    fn a_compressed_file_that_breaks_says_why() {
        let (_, runs, file) = compressed_file();
        let size = file.len() as u64;
        // The runs end before the size does.
        let (held, went) = why_it_breaks(runs[..4].to_vec(), size);
        assert!(held.contains("runs end before its size"), "{held}");
        assert_eq!(held, went);
        // A compressed unit (the first run) and a stored one (the third) whose
        // clusters are not in the volume.
        for unit in [0, 2] {
            let mut gone = runs.clone();
            gone[unit] = Run {
                lcn: Some(1 << 20),
                clusters: gone[unit].clusters,
            };
            let (held, went) = why_it_breaks(gone, size);
            assert!(
                held.contains("not all in the volume"),
                "unit {unit}: {held}"
            );
            assert_eq!(held, went, "unit {unit}");
        }
    }
}
