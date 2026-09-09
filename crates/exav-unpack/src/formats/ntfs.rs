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

use crate::{Budget, Entry, LimitHit, Sink};

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
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn le_u64(d: &[u8], off: usize) -> u64 {
    d.get(off..off + 8)
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
        1usize.checked_shl((-raw) as u32)?
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
    let Some(usn) = rec.get(usa_off..usa_off + 2).map(<[u8]>::to_vec) else {
        return false;
    };
    // The first entry is the sequence number itself; the rest are replacements,
    // one per sector.
    for i in 1..usa_count {
        let Some(repl) = rec
            .get(usa_off + i * 2..usa_off + i * 2 + 2)
            .map(<[u8]>::to_vec)
        else {
            return false;
        };
        let end = i * sector;
        if end < 2 || end > rec.len() {
            return false;
        }
        // Every sector must currently carry the sequence number; if it does not,
        // this is not a coherent record.
        if rec[end - 2..end] != usn[..] {
            return false;
        }
        rec[end - 2..end].copy_from_slice(&repl);
    }
    true
}

/// One extent of a non-resident attribute: `lcn` is `None` for a sparse run,
/// which reads as zeroes.
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
        i += 1;
        let len_sz = (hdr & 0x0F) as usize;
        let off_sz = (hdr >> 4) as usize;
        if len_sz == 0 || len_sz > 8 || off_sz > 8 {
            break;
        }
        let Some(len_bytes) = d.get(i..i + len_sz) else {
            break;
        };
        i += len_sz;
        let mut clusters: u64 = 0;
        for (k, &b) in len_bytes.iter().enumerate() {
            clusters |= (b as u64) << (k * 8);
        }

        if off_sz == 0 {
            // A sparse run: no clusters allocated, reads as zeroes.
            runs.push(Run {
                lcn: None,
                clusters,
            });
            continue;
        }
        let Some(off_bytes) = d.get(i..i + off_sz) else {
            break;
        };
        i += off_sz;
        let mut delta: i64 = 0;
        for (k, &b) in off_bytes.iter().enumerate() {
            delta |= (b as i64) << (k * 8);
        }
        // Sign-extend from the width actually used.
        let bits = off_sz * 8;
        if bits < 64 && delta & (1i64 << (bits - 1)) != 0 {
            delta -= 1i64 << bits;
        }
        lcn += delta;
        runs.push(Run {
            lcn: Some(lcn),
            clusters,
        });
    }
    runs
}

/// Read a non-resident attribute's bytes by following its runs.
fn read_runs(volume: &[u8], runs: &[Run], cluster: usize, real_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(real_size.min(1 << 20));
    for r in runs {
        if out.len() >= real_size {
            break;
        }
        let want = (r.clusters as usize).saturating_mul(cluster);
        let take = want.min(real_size - out.len());
        match r.lcn {
            // Sparse: allocated but never written, so it reads as zeroes on the
            // victim's machine too.
            None => out.resize(out.len() + take, 0),
            Some(lcn) if lcn >= 0 => {
                let start = (lcn as usize).saturating_mul(cluster);
                match volume.get(start..start + take) {
                    Some(s) => out.extend_from_slice(s),
                    // Past the end of the image: those bytes are absent rather
                    // than hidden, so what exists still stands.
                    None => break,
                }
            }
            Some(_) => break,
        }
    }
    out.truncate(real_size);
    out
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
    rec: &[u8],
    volume: &[u8],
    mft: &[u8],
    geo: &Geometry,
    sector: usize,
) -> Option<(Vec<Run>, usize)> {
    // The list itself is an attribute, resident or not.
    let list = find_attribute_list(rec, volume, geo)?;
    let mut refs: Vec<(u64, u64)> = Vec::new(); // (starting VCN, MFT record)
    let mut i = 0usize;
    while i + 26 <= list.len() {
        let atype = le_u32(&list, i);
        let entry_len = le_u16(&list, i + 4) as usize;
        if entry_len < 26 {
            break;
        }
        let name_len = list.get(i + 6).copied().unwrap_or(0);
        // Only the unnamed `$DATA`; a named one is an alternate stream.
        if atype == ATTR_DATA && name_len == 0 {
            let vcn = le_u64(&list, i + 8);
            // The low 48 bits of the file reference are the record number.
            let record = le_u64(&list, i + 16) & 0x0000_FFFF_FFFF_FFFF;
            refs.push((vcn, record));
        }
        i += entry_len;
    }
    if refs.is_empty() {
        return None;
    }
    refs.sort_by_key(|&(vcn, _)| vcn);

    let mut runs: Vec<Run> = Vec::new();
    let mut real_size = 0usize;
    for (vcn, record) in refs {
        let at = (record as usize).checked_mul(geo.record_size)?;
        let Some(slice) = mft.get(at..at + geo.record_size) else {
            continue;
        };
        let mut r = slice.to_vec();
        if r.get(0..4) != Some(RECORD_MAGIC.as_slice()) || !apply_fixups(&mut r, sector) {
            continue;
        }
        let mut off = le_u16(&r, 20) as usize;
        while off + 8 <= r.len() {
            let atype = le_u32(&r, off);
            if atype == ATTR_END {
                break;
            }
            let alen = le_u32(&r, off + 4) as usize;
            if alen < 16 || off + alen > r.len() {
                break;
            }
            let non_resident = r.get(off + 8).copied().unwrap_or(0) != 0;
            if atype == ATTR_DATA
                && r.get(off + 9).copied().unwrap_or(0) == 0
                && non_resident
                && le_u64(&r, off + 16) == vcn
            {
                // Only the extent starting at VCN 0 carries the true size.
                if vcn == 0 {
                    real_size = le_u64(&r, off + 0x30) as usize;
                }
                let runs_off = off + le_u16(&r, off + 0x20) as usize;
                runs.extend(data_runs(r.get(runs_off..off + alen).unwrap_or(&[])));
                break;
            }
            off += alen;
        }
    }
    if runs.is_empty() || real_size == 0 {
        return None;
    }
    Some((runs, real_size))
}

/// The `$ATTRIBUTE_LIST` value.
///
/// The list is normally resident, but a file fragmented hard enough pushes the
/// list itself out of the record — and that threshold is reachable on purpose.
/// So the non-resident form is followed too, by walking its own data runs.
/// Stopping at the resident case would leave the most fragmented files, which is
/// to say the ones someone took the trouble to fragment, unread.
fn find_attribute_list(rec: &[u8], volume: &[u8], geo: &Geometry) -> Option<Vec<u8>> {
    let mut off = le_u16(rec, 20) as usize;
    while off + 8 <= rec.len() {
        let atype = le_u32(rec, off);
        if atype == ATTR_END {
            break;
        }
        let alen = le_u32(rec, off + 4) as usize;
        if alen < 16 || off + alen > rec.len() {
            break;
        }
        if atype == ATTR_ATTRIBUTE_LIST {
            let non_resident = rec.get(off + 8).copied().unwrap_or(0) != 0;
            if !non_resident {
                let vlen = le_u32(rec, off + 16) as usize;
                let voff = off + le_u16(rec, off + 20) as usize;
                return rec.get(voff..voff + vlen).map(<[u8]>::to_vec);
            }
            let real_size = le_u64(rec, off + 0x30) as usize;
            let runs_off = off + le_u16(rec, off + 0x20) as usize;
            let runs = data_runs(rec.get(runs_off..off + alen).unwrap_or(&[]));
            let bytes = read_runs(volume, &runs, geo.cluster, real_size);
            // A list read short would silently drop the extents it names, so it
            // is treated as unusable rather than half-used.
            return (bytes.len() == real_size && real_size > 0).then_some(bytes);
        }
        off += alen;
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
}

/// Parse one MFT record into a file, or `None` when it holds nothing to scan.
fn parse_record(
    rec: &[u8],
    volume: &[u8],
    mft: &[u8],
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

    let mut name: Option<String> = None;
    let mut file: Option<File> = None;
    let mut off = le_u16(rec, 20) as usize;

    while off + 8 <= rec.len() {
        let atype = le_u32(rec, off);
        if atype == ATTR_END {
            break;
        }
        let alen = le_u32(rec, off + 4) as usize;
        if alen < 16 || off + alen > rec.len() {
            break;
        }
        let non_resident = rec.get(off + 8).copied().unwrap_or(0) != 0;
        let attr_flags = le_u16(rec, off + 12);
        let name_len = rec.get(off + 9).copied().unwrap_or(0) as usize;

        if atype == ATTR_FILE_NAME && !non_resident {
            let voff = off + le_u16(rec, off + 20) as usize;
            let nlen = rec.get(voff + 0x40).copied().unwrap_or(0) as usize;
            let namespace = rec.get(voff + 0x41).copied().unwrap_or(0);
            // The DOS 8.3 alias names a file we already have under its real name.
            if namespace != NAMESPACE_DOS {
                if let Some(raw) = rec.get(voff + 0x42..voff + 0x42 + nlen * 2) {
                    let units: Vec<u16> = raw
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .copied()
                        .map(u16::from_le_bytes)
                        .collect();
                    let n = String::from_utf16_lossy(&units);
                    // Prefer the longest, which is the Win32 name over a POSIX
                    // alias of the same file.
                    if name.as_ref().is_none_or(|old| n.len() > old.len()) {
                        name = Some(n);
                    }
                }
            }
        }

        // Only the unnamed `$DATA` attribute is the file's own content; a named
        // one is an alternate data stream.
        if atype == ATTR_DATA && name_len == 0 {
            if attr_flags & ATTR_ENCRYPTED != 0 {
                file = Some(File {
                    name: String::new(),
                    data: None,
                    unreadable: Some("EFS-encrypted NTFS file"),
                    deleted,
                });
            } else if !non_resident {
                let vlen = le_u32(rec, off + 16) as usize;
                let voff = off + le_u16(rec, off + 20) as usize;
                let bytes = rec.get(voff..voff + vlen).unwrap_or(&[]).to_vec();
                file = Some(File {
                    name: String::new(),
                    data: Some(bytes),
                    unreadable: None,
                    deleted,
                });
            } else {
                // A file fragmented past what one record can hold has its runs
                // split across several, listed in `$ATTRIBUTE_LIST`. Gather them
                // all; falling back to this record alone would return the first
                // extent and call it the whole file.
                let spread = data_extents(rec, volume, mft, geo, sector);
                if le_u64(rec, off + 16) != 0 && spread.is_none() {
                    // Only this extent is reachable. Report the shortfall, but
                    // still scan the part that is here.
                    let real_size = le_u64(rec, off + 0x30) as usize;
                    let runs_off = off + le_u16(rec, off + 0x20) as usize;
                    let runs = data_runs(rec.get(runs_off..off + alen).unwrap_or(&[]));
                    let part = read_runs(volume, &runs, geo.cluster, real_size.max(1));
                    file = Some(File {
                        name: String::new(),
                        data: Some(part),
                        unreadable: Some(
                            "NTFS file whose data runs span MFT records exav could not follow; \
                             the extent that could be read was scanned",
                        ),
                        deleted,
                    });
                } else {
                    let (runs, real_size) = match spread {
                        Some(v) => v,
                        None => {
                            let real_size = le_u64(rec, off + 0x30) as usize;
                            let runs_off = off + le_u16(rec, off + 0x20) as usize;
                            (
                                data_runs(rec.get(runs_off..off + alen).unwrap_or(&[])),
                                real_size,
                            )
                        }
                    };
                    if real_size > cap {
                        file = Some(File {
                            name: String::new(),
                            data: None,
                            unreadable: Some("NTFS file exceeds the per-member size budget"),
                            deleted,
                        });
                    } else if attr_flags & ATTR_COMPRESSED != 0 {
                        let unit = 1usize << le_u16(rec, off + 0x22);
                        let raw = read_runs(volume, &runs, geo.cluster, usize::MAX);
                        file = Some(match decompress(&raw, unit * geo.cluster, real_size) {
                            Some(d) => File {
                                name: String::new(),
                                data: Some(d),
                                unreadable: None,
                                deleted,
                            },
                            None => File {
                                name: String::new(),
                                data: None,
                                unreadable: Some("NTFS-compressed file that would not decompress"),
                                deleted,
                            },
                        });
                    } else if attr_flags & ATTR_SPARSE != 0 || runs.iter().any(|r| r.lcn.is_none())
                    {
                        // Sparse holes read as zeroes, which is what the victim
                        // sees too, so this is still the file.
                        file = Some(File {
                            name: String::new(),
                            data: Some(read_runs(volume, &runs, geo.cluster, real_size)),
                            unreadable: None,
                            deleted,
                        });
                    } else {
                        let bytes = read_runs(volume, &runs, geo.cluster, real_size);
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
                        });
                    }
                }
            }
        }
        off += alen;
    }

    let mut f = file?;
    f.name = name?;
    Some(f)
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

pub(crate) fn extract_ntfs<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !super::sniff::is(data, crate::Format::Ntfs) {
        return Ok(None);
    }
    let Some(geo) = geometry(data) else {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                data.len() as u64,
                false,
                "implausible NTFS geometry",
            ),
            budget,
        ));
    };

    // Record 0 is `$MFT` itself, and its `$DATA` gives the runs of the whole
    // table — which can be fragmented, so the MFT cannot simply be read
    // linearly from its first cluster.
    let mft_start = (geo.mft_lcn as usize).saturating_mul(geo.cluster);
    let Some(first) = data.get(mft_start..mft_start + geo.record_size) else {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                data.len() as u64,
                false,
                "NTFS master file table lies outside the image",
            ),
            budget,
        ));
    };
    let mut rec0 = first.to_vec();
    let sector = le_u16(data, 11) as usize;
    if !apply_fixups(&mut rec0, sector) || rec0.get(0..4) != Some(RECORD_MAGIC.as_slice()) {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                data.len() as u64,
                false,
                "NTFS master file table record is not readable",
            ),
            budget,
        ));
    }
    let mft = mft_bytes(&rec0, data, &geo);
    if mft.is_empty() {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<ntfs-volume>".to_string(),
                data.len() as u64,
                false,
                "NTFS master file table could not be read",
            ),
            budget,
        ));
    }

    let n = (mft.len() / geo.record_size).min(MAX_RECORDS);
    if mft.len() / geo.record_size > MAX_RECORDS {
        budget.count_entry()?;
        if let Some(r) = visit(
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
        let at = i * geo.record_size;
        let Some(slice) = mft.get(at..at + geo.record_size) else {
            break;
        };
        if slice.get(0..4) != Some(RECORD_MAGIC.as_slice()) {
            continue; // an unused slot
        }
        // Past this point the slot carries the `FILE` magic, so a record IS here
        // and whatever it names is a file on the volume. Failing to read it is a
        // gap to report, not a slot to skip — an unused slot was already handled
        // above, and conflating the two hides real files.
        let mut rec = slice.to_vec();
        if !apply_fixups(&mut rec, sector) {
            budget.count_entry()?;
            if let Some(r) = visit(
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
        let cap = budget.reserve()? as usize;
        // `None` here means "not a user file with content" — a directory, or the
        // volume's own metadata — not a parse failure. Reporting it would flag
        // every healthy volume, which the reserved records 16..63 make loud.
        let Some(f) = parse_record(&rec, data, &mft, &geo, sector, cap) else {
            continue;
        };
        // A deleted record's runs may since have been reused by another file, so
        // its bytes are marked rather than presented as that file's content.
        let name = if f.deleted {
            format!("<deleted>/{}", f.name)
        } else {
            f.name
        };
        // A file can be both partly readable and short: the report says what is
        // missing, and the bytes that exist are still scanned. Emitting only one
        // of the two would either hide the gap or throw away content.
        if let Some(why) = f.unreadable {
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(name.clone(), 0, why.contains("encrypted"), why),
                budget,
            ) {
                return Ok(Some(r));
            }
        }
        if let Some(d) = f.data {
            if !d.is_empty() {
                budget.count_entry()?;
                budget.commit(d.len() as u64);
                if let Some(r) = visit(Entry::new(name, d), budget) {
                    return Ok(Some(r));
                }
            }
        }
    }
    Ok(None)
}

/// The whole MFT, gathered by following `$MFT`'s own data runs.
fn mft_bytes(rec0: &[u8], volume: &[u8], geo: &Geometry) -> Vec<u8> {
    let mut off = le_u16(rec0, 20) as usize;
    while off + 8 <= rec0.len() {
        let atype = le_u32(rec0, off);
        if atype == ATTR_END {
            break;
        }
        let alen = le_u32(rec0, off + 4) as usize;
        if alen < 16 || off + alen > rec0.len() {
            break;
        }
        if atype == ATTR_DATA && rec0.get(off + 8).copied().unwrap_or(0) != 0 {
            let real_size = le_u64(rec0, off + 0x30) as usize;
            let runs_off = off + le_u16(rec0, off + 0x20) as usize;
            let runs = data_runs(rec0.get(runs_off..off + alen).unwrap_or(&[]));
            return read_runs(volume, &runs, geo.cluster, real_size);
        }
        off += alen;
    }
    Vec::new()
}
