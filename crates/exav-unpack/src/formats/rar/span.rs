//! The volumes of a RAR set, read as the one archive they were cut from.
//!
//! A member split across volumes has a file header in each, flagged as
//! continuing from the previous volume and/or in the next, with that volume's
//! share of the packed data after it. Every part's header carries the CRC-32 of
//! that part's packed data, except the last, whose CRC is the whole unpacked
//! file's (RARLAB's technote). Joined, the shares are the member's whole packed
//! stream, which the single-volume reader then decodes as it decodes any other.
//!
//! [`RarSpan`] joins them without copying: the archive is a table of pieces,
//! each a range of a volume or a few bytes of its own (the marker, the header
//! of a split member with its sizes and CRC rewritten, the end block), and the
//! volumes are read where they lie.

use super::{RAR4_MAGIC, RAR5_MAGIC, RAR5_MAX_HEADER, crc32_ieee, u16le, u32le, vint};
use crate::source::ByteSource;
use std::borrow::Cow;

/// The `part` of a piece whose bytes are the table's own.
const LITERAL: u32 = u32::MAX;

/// A stretch of the joined archive, up to the start of the next piece.
#[derive(Clone, Copy)]
struct Piece {
    /// Where it starts in the joined archive.
    start: u64,
    /// The volume its bytes are in, or [`LITERAL`].
    part: u32,
    /// Where they start in that volume, or in the table's literals.
    from: u64,
}

/// Pieces under construction.
#[derive(Default)]
struct Pieces {
    list: Vec<Piece>,
    lits: Vec<u8>,
    len: u64,
}

impl Pieces {
    /// Memory the table takes.
    fn bytes(&self) -> usize {
        self.list.len() * size_of::<Piece>() + self.lits.len()
    }

    /// Bytes of the table's own.
    fn lit(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.list.last().is_none_or(|p| p.part != LITERAL) {
            self.list.push(Piece {
                start: self.len,
                part: LITERAL,
                from: self.lits.len() as u64,
            });
        }
        self.lits.extend_from_slice(bytes);
        self.len += bytes.len() as u64;
    }

    /// `len` bytes of volume `part` from `from`.
    fn range(&mut self, part: usize, from: u64, len: u64) {
        if len == 0 {
            return;
        }
        // `RarSpan::new` refuses a set of `LITERAL` parts or more.
        let part = part as u32;
        let joins = self
            .list
            .last()
            .is_some_and(|p| p.part == part && p.from + (self.len - p.start) == from);
        if !joins {
            self.list.push(Piece {
                start: self.len,
                part,
                from,
            });
        }
        self.len += len;
    }

    /// `other` after the pieces held.
    fn append(&mut self, other: Pieces) {
        let (base, lits) = (self.len, self.lits.len() as u64);
        for p in other.list {
            self.list.push(Piece {
                start: base + p.start,
                part: p.part,
                from: if p.part == LITERAL {
                    p.from + lits
                } else {
                    p.from
                },
            });
        }
        self.lits.extend_from_slice(&other.lits);
        self.len += other.len;
    }
}

/// A member whose parts are still being gathered: its first header and where
/// the packed data is so far.
struct Pending {
    header: Vec<u8>,
    data: Pieces,
}

/// How the parts of a member end in the volumes given.
enum Ending {
    /// Its last part is there: the CRC its header records, and the bytes of
    /// the data that header declares and the last volume ends before.
    Done { crc: Option<u32>, missing: u64 },
    /// It goes on in a volume that is not there.
    GoesOn,
}

/// The state of a join: the archive so far, the member whose parts are being
/// gathered, and the service blocks met meanwhile, which go after it.
struct Join {
    out: Pieces,
    pending: Option<Pending>,
    deferred: Pieces,
    /// The last volume ends inside a block: nothing may follow the pieces, or
    /// it would be read as the data that block says it has.
    cut: bool,
    max: usize,
}

impl Join {
    fn new(max: usize) -> Self {
        Join {
            out: Pieces::default(),
            pending: None,
            deferred: Pieces::default(),
            cut: false,
            max,
        }
    }

    /// Whether the tables, the ones being built included, are within the
    /// memory the caller allows.
    fn check(&self) -> Result<(), String> {
        let pending = self
            .pending
            .as_ref()
            .map_or(0, |p| p.data.bytes() + p.header.len());
        if self.out.bytes() + self.deferred.bytes() + pending > self.max {
            return Err(
                "the volumes' block table is over the memory limit (--max-object-bytes)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// The volumes of a RAR set, in order, read as the one single-volume archive
/// that [`crate::walk`] reads as [`crate::Format::Rar`]: each split member's
/// packed data follows its first header, which takes the total size and the
/// last part's CRC. Read one volume at a time, a member split across volumes
/// is reported unreadable.
pub struct RarSpan<'a> {
    parts: Vec<Box<dyn ByteSource + 'a>>,
    pieces: Pieces,
}

impl<'a> RarSpan<'a> {
    /// The volumes, in order (`x.part1.rar` first, or `x.rar`, `x.r00`, ...).
    /// `Err` names what does not fit together: a volume that is not the one its
    /// place says, a member whose start is missing, a volume but the last that
    /// ends inside a block, or one with a block header that does not parse.
    ///
    /// The last volume may end inside a block, as a single archive may. A
    /// member whose last part it cuts is read as far as the volume goes, as a
    /// cut archive's is. A member that goes on in a volume not given stays
    /// flagged as continuing, as in a volume read alone.
    ///
    /// The span keeps a table of pieces, each a stretch of one volume or a few
    /// bytes of its own (a rewritten header); `max_table_bytes` is the most it
    /// may take. Volumes that together are longer than `usize` is wide can
    /// address are refused, not cut.
    pub fn new(
        parts: Vec<Box<dyn ByteSource + 'a>>,
        max_table_bytes: usize,
    ) -> Result<RarSpan<'a>, String> {
        if parts.len() >= LITERAL as usize {
            return Err("too many parts".to_string());
        }
        let pieces = Self::join(&parts, max_table_bytes).map_err(|e| {
            // A failed read shows up as a header cut short: name the failure.
            match parts.iter().find_map(|p| p.read_error()) {
                Some(why) => format!("a part could not be read: {why}"),
                None => e,
            }
        })?;
        if usize::try_from(pieces.len).is_err() {
            return Err("the volumes together are too long to be addressed".to_string());
        }
        Ok(RarSpan { parts, pieces })
    }

    fn join(parts: &[Box<dyn ByteSource + 'a>], max_table_bytes: usize) -> Result<Pieces, String> {
        match parts.first().map(|p| p.window(0, RAR5_MAGIC.len())) {
            Some(h) if h.starts_with(RAR5_MAGIC) => join5(parts, max_table_bytes),
            Some(h) if h.starts_with(RAR4_MAGIC) => join4(parts, max_table_bytes),
            _ => Err("the first part is not a RAR archive".to_string()),
        }
    }
}

impl ByteSource for RarSpan<'_> {
    fn len(&self) -> usize {
        usize::try_from(self.pieces.len).unwrap_or(usize::MAX)
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let total = self.pieces.len;
        let off = off as u64;
        let end = off.saturating_add(len as u64).min(total);
        if off >= end {
            return Cow::Borrowed(&[]);
        }
        let list = &self.pieces.list;
        // The list starts at 0, so a piece starts at or before `off`.
        let mut i = list.partition_point(|p| p.start <= off) - 1;
        let mut joined = Vec::new();
        let mut at = off;
        while at < end {
            let p = list[i];
            let stop = list.get(i + 1).map_or(total, |n| n.start).min(end);
            let n = (stop - at) as usize;
            let from = (p.from + (at - p.start)) as usize;
            let w: Cow<'_, [u8]> = if p.part == LITERAL {
                Cow::Borrowed(&self.pieces.lits[from..from + n])
            } else {
                self.parts[p.part as usize].window(from, n)
            };
            if at == off && stop == end {
                return w;
            }
            if joined.capacity() == 0 {
                joined.reserve(crate::cap_prealloc((end - off) as usize));
            }
            joined.extend_from_slice(&w);
            if w.len() < n {
                break;
            }
            at = stop;
            i += 1;
        }
        Cow::Owned(joined)
    }

    fn read_error(&self) -> Option<String> {
        self.parts.iter().find_map(|p| p.read_error())
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.len())
    }
}

// ---- RAR4 -------------------------------------------------------------------

fn join4(parts: &[Box<dyn ByteSource + '_>], max: usize) -> Result<Pieces, String> {
    let mut j = Join::new(max);
    j.out.lit(RAR4_MAGIC);
    for (k, v) in parts.iter().enumerate() {
        if !v.window(0, RAR4_MAGIC.len()).starts_with(RAR4_MAGIC) {
            return Err(format!("part {} is not a RAR4 volume", k + 1));
        }
        // The last volume may end inside a block: what is missing is absent.
        let last = k + 1 == parts.len();
        let size = v.len();
        let mut pos = RAR4_MAGIC.len();
        while pos < size {
            // The fields of a file header are read past a header too short for
            // them, as the walk reads them.
            let w = v.window(pos, 40);
            let (Some(flags), Some(head_size)) = (u16le(&w, 3), u16le(&w, 5)) else {
                if last {
                    j.cut = true;
                    break;
                }
                return Err(format!("part {} ends inside a block", k + 1));
            };
            let (htype, head_size) = (w[2], usize::from(head_size));
            if head_size < 7 {
                return Err(format!(
                    "part {} has a block header that does not parse",
                    k + 1
                ));
            }
            let mut add = if flags & 0x8000 != 0 {
                u64::from(u32le(&w, 7).unwrap_or(0))
            } else {
                0
            };
            if htype == 0x74 && flags & 0x100 != 0 {
                add |= u64::from(u32le(&w, 32).unwrap_or(0)) << 32;
            }
            let declared = pos
                .checked_add(head_size)
                .and_then(|e| e.checked_add(usize::try_from(add).ok()?));
            let (end, missing) = match declared {
                Some(e) if e <= size => (e, 0),
                Some(e) if last && pos + head_size <= size => (size, (e - size) as u64),
                Some(_) if last => {
                    j.cut = true;
                    break;
                }
                _ => return Err(format!("part {} ends inside a block", k + 1)),
            };
            if missing > 0 {
                // With a member waiting for its parts, the block the volume
                // ends inside can only be its next part.
                if j.pending.is_some() && !(htype == 0x74 && flags & 0x01 != 0) {
                    return Err(format!("part {} ends inside a block", k + 1));
                }
                j.cut = true;
            }
            let len = (end - pos) as u64;
            // A volume's end block may record its number (EARC_VOLNUMBER,
            // after the data CRC when EARC_DATACRC is set): it must be where
            // it is given.
            if htype == 0x7B && flags & 0x0008 != 0 {
                let at = 7 + if flags & 0x0002 != 0 { 4 } else { 0 };
                if let Some(n) = u16le(&w, at).filter(|_| at + 2 <= head_size)
                    && usize::from(n) != k
                {
                    return Err(format!(
                        "part {} is volume {} of its set",
                        k + 1,
                        usize::from(n) + 1
                    ));
                }
            }
            match htype {
                // The archive header once; each volume's end marker never.
                0x73 if k == 0 => j.out.range(0, pos as u64, len),
                0x73 | 0x7B => {}
                0x74 => {
                    let (before, after) = (flags & 0x01 != 0, flags & 0x02 != 0);
                    let data_at = pos + head_size;
                    let data_len = (end - data_at) as u64;
                    match (before, &mut j.pending) {
                        (false, None) if after => {
                            let mut data = Pieces::default();
                            data.range(k, data_at as u64, data_len);
                            j.pending = Some(Pending {
                                header: v.window(pos, head_size).into_owned(),
                                data,
                            });
                        }
                        (false, None) => j.out.range(k, pos as u64, len),
                        (true, Some(p)) => p.data.range(k, data_at as u64, data_len),
                        (false, Some(_)) => {
                            return Err(format!("part {} drops a member mid-way", k + 1));
                        }
                        (true, None) => {
                            return Err(format!(
                                "part {} goes on with a member whose start is missing",
                                k + 1
                            ));
                        }
                    }
                    if before && !after {
                        let p = j.pending.take().expect("a split member was pending");
                        let crc = Some(u32le(&w, 16).unwrap_or(0));
                        let (header, data) = rar4_member(p, Ending::Done { crc, missing })?;
                        j.out.lit(&header);
                        j.out.append(data);
                    }
                }
                _ => j.out.range(k, pos as u64, len),
            }
            j.check()?;
            // Nothing after the end block is a block.
            if htype == 0x7B {
                break;
            }
            pos = end;
        }
    }
    if let Some(p) = j.pending.take() {
        // The set ends inside a member, which goes on in a volume not given:
        // its header says so, and it is read as a member that continues.
        let (header, data) = rar4_member(p, Ending::GoesOn)?;
        j.out.lit(&header);
        j.out.append(data);
    }
    if !j.cut {
        // ENDARC: CRC, type 0x7B, flags, size 7.
        j.out.lit(&[0x3d, 0x7b, 0x7b, 0x00, 0x40, 0x07, 0x00]);
    }
    Ok(j.out)
}

/// A RAR4 member's header, and its data, from its parts: as a whole member
/// when its last part is there, else still flagged as going on.
fn rar4_member(p: Pending, ending: Ending) -> Result<(Vec<u8>, Pieces), String> {
    let Pending { mut header, data } = p;
    let h = &mut header;
    // The smallest block head is 7 bytes, and a split member's has fields up to byte 20.
    if h.len() < 20 {
        return Err("a short file header".to_string());
    }
    let mut flags = u16::from_le_bytes([h[3], h[4]]);
    let large = flags & 0x100 != 0;
    let unp = u64::from(u32le(h, 11).unwrap_or(0))
        | if large {
            u64::from(u32le(h, 36).unwrap_or(0)) << 32
        } else {
            0
        };
    let total = match ending {
        Ending::Done { crc, missing } => {
            let total = data.len.saturating_add(missing);
            // A stored member's data is its content, so a part missing from
            // between the ones given shows as a size the header does not
            // record. (A volume missing from a set that records volume
            // numbers is refused by the join; without them, a compressed
            // member fails its CRC once decoded, which is reported only when
            // checksums are verified.)
            if h.get(25) == Some(&0x30) && unp != total {
                return Err(format!(
                    "a stored member of {unp} bytes has {total} in the parts given"
                ));
            }
            flags &= !0x03;
            h[16..20].copy_from_slice(&crc.unwrap_or(0).to_le_bytes());
            total
        }
        Ending::GoesOn => data.len,
    };
    h[3..5].copy_from_slice(&flags.to_le_bytes());
    h[7..11].copy_from_slice(&(total as u32).to_le_bytes());
    match (flags & 0x100 != 0, h.len() >= 40) {
        (true, true) => h[32..36].copy_from_slice(&((total >> 32) as u32).to_le_bytes()),
        _ if total > u64::from(u32::MAX) => {
            return Err("a member past 4 GiB with no 64-bit size".to_string());
        }
        _ => {}
    }
    Ok((header, data))
}

// ---- RAR5 -------------------------------------------------------------------

pub(super) fn vint_bytes(mut x: u64) -> Vec<u8> {
    let mut o = Vec::new();
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            o.push(b);
            return o;
        }
        o.push(b | 0x80);
    }
}

/// One RAR5 block: its header content, where its data starts and ends, and
/// its type and flags.
pub(super) struct Rar5Block<'a> {
    /// The header content: from the header type to the end of the header.
    pub(super) content: Cow<'a, [u8]>,
    pub(super) data_off: usize,
    pub(super) htype: u64,
    pub(super) hflags: u64,
    pub(super) end: usize,
    /// Bytes of the data the volume ends before: 0 unless the block was read
    /// with `cut_ok`.
    pub(super) missing: u64,
}

const PARSE: &str = "has a block header that does not parse";
const CUT: &str = "ends inside a block";

/// The block at `pos`, or why it does not parse.
#[cfg(test)]
pub(super) fn rar5_block(v: &dyn ByteSource, pos: usize) -> Result<Rar5Block<'_>, &'static str> {
    rar5_block_in(v, pos, false)
}

/// [`rar5_block`]. With `cut_ok` (the last volume of a set), a block whose
/// header is whole and whose data goes past the end of the volume is read as
/// far as the volume goes, with the rest in `missing`; `CUT` is then only for a
/// header the volume ends inside.
fn rar5_block_in(
    v: &dyn ByteSource,
    pos: usize,
    cut_ok: bool,
) -> Result<Rar5Block<'_>, &'static str> {
    let w = v.window(pos, 14);
    let Some((hsize, n)) = vint(&w, 4) else {
        return Err(if cut_ok && w.len() < 14 { CUT } else { PARSE });
    };
    if hsize == 0 || hsize > RAR5_MAX_HEADER {
        return Err(PARSE);
    }
    let hdr = pos + 4 + n;
    let data_off = hdr + hsize as usize;
    if data_off > v.len() {
        return Err(CUT);
    }
    let content = v.window(hdr, hsize as usize);
    if content.len() < hsize as usize {
        return Err(CUT);
    }
    let (htype, t1) = vint(&content, 0).ok_or(PARSE)?;
    let (hflags, t2) = vint(&content, t1).ok_or(PARSE)?;
    let mut q = t1 + t2;
    if hflags & 0x01 != 0 {
        q += vint(&content, q).ok_or(PARSE)?.1;
    }
    let data_size = if hflags & 0x02 != 0 {
        vint(&content, q).ok_or(PARSE)?.0
    } else {
        0
    };
    let room = (v.len() - data_off) as u64;
    let (end, missing) = match usize::try_from(data_size)
        .ok()
        .and_then(|d| data_off.checked_add(d))
        .filter(|&e| e <= v.len())
    {
        Some(e) => (e, 0),
        None if cut_ok => (v.len(), data_size - room),
        None => return Err(CUT),
    };
    Ok(Rar5Block {
        content,
        data_off,
        htype,
        hflags,
        end,
        missing,
    })
}

fn join5(parts: &[Box<dyn ByteSource + '_>], max: usize) -> Result<Pieces, String> {
    let mut j = Join::new(max);
    j.out.lit(RAR5_MAGIC);
    for (k, v) in parts.iter().enumerate() {
        if !v.window(0, RAR5_MAGIC.len()).starts_with(RAR5_MAGIC) {
            return Err(format!("part {} is not a RAR5 volume", k + 1));
        }
        // The last volume may end inside a block: what is missing is absent.
        let last = k + 1 == parts.len();
        let mut pos = RAR5_MAGIC.len();
        while pos < v.len() {
            let b = match rar5_block_in(&**v, pos, last) {
                Ok(b) => b,
                Err(CUT) if last => {
                    j.cut = true;
                    break;
                }
                Err(e) => return Err(format!("part {} {e}", k + 1)),
            };
            if b.missing > 0 {
                // With a member waiting for its parts, the block the volume
                // ends inside can only be its next part.
                if j.pending.is_some() && !(matches!(b.htype, 2 | 3) && b.hflags & 0x08 != 0) {
                    return Err(format!("part {} {CUT}", k + 1));
                }
                j.cut = true;
            }
            let len = (b.end - pos) as u64;
            // A volume past the first records its number: it must be where
            // it is given.
            if b.htype == 1
                && k > 0
                && let Some(n) = rar5_volume_number(&b.content)
                && n != k as u64
            {
                return Err(format!(
                    "part {} is volume {} of its set",
                    k + 1,
                    n.saturating_add(1)
                ));
            }
            match b.htype {
                1 if k == 0 => j.out.range(0, pos as u64, len),
                1 | 5 => {}
                // The quick-open record each volume ends with caches that
                // volume's headers at offsets in it: it has no place in the
                // joined archive.
                3 if b.hflags & 0x18 == 0 && rar5_name(&b.content) == Some(b"QO") => {}
                2 | 3 => {
                    let (before, after) = (b.hflags & 0x08 != 0, b.hflags & 0x10 != 0);
                    let (data_at, data_len) = (b.data_off as u64, (b.end - b.data_off) as u64);
                    match (before, &mut j.pending) {
                        (false, None) if after => {
                            let mut data = Pieces::default();
                            data.range(k, data_at, data_len);
                            j.pending = Some(Pending {
                                header: b.content.to_vec(),
                                data,
                            });
                        }
                        (false, None) => j.out.range(k, pos as u64, len),
                        (true, Some(p)) => p.data.range(k, data_at, data_len),
                        (false, Some(_)) if b.htype == 3 && !after => {
                            j.deferred.range(k, pos as u64, len)
                        }
                        (false, Some(_)) => {
                            return Err(format!("part {} drops a member mid-way", k + 1));
                        }
                        (true, None) => {
                            return Err(format!(
                                "part {} goes on with a member whose start is missing",
                                k + 1
                            ));
                        }
                    }
                    if before && !after {
                        let p = j.pending.take().expect("a split member was pending");
                        let crc = rar5_crc(&b.content);
                        let ending = Ending::Done {
                            crc,
                            missing: b.missing,
                        };
                        let (header, data) = rar5_member(p, ending)?;
                        let deferred = std::mem::take(&mut j.deferred);
                        // A member cut short takes what follows it as data.
                        if b.missing > 0 {
                            j.out.append(deferred);
                            j.out.lit(&header);
                            j.out.append(data);
                        } else {
                            j.out.lit(&header);
                            j.out.append(data);
                            j.out.append(deferred);
                        }
                    }
                }
                _ => j.out.range(k, pos as u64, len),
            }
            j.check()?;
            // Nothing after the end block is a block.
            if b.htype == 5 {
                break;
            }
            pos = b.end;
        }
    }
    if let Some(p) = j.pending.take() {
        // The set ends inside a member, which goes on in a volume not given:
        // its header says so, and it is read as a member that continues.
        let (header, data) = rar5_member(p, Ending::GoesOn)?;
        j.out.lit(&header);
        j.out.append(data);
        let deferred = std::mem::take(&mut j.deferred);
        j.out.append(deferred);
    }
    if !j.cut {
        // End of archive: type 5, no flags, no end-of-archive flags.
        let content = [vint_bytes(5), vint_bytes(0), vint_bytes(0)].concat();
        j.out.lit(&crc32_ieee(&content).to_le_bytes());
        j.out.lit(&vint_bytes(content.len() as u64));
        j.out.lit(&content);
    }
    Ok(j.out)
}

/// The volume number a RAR5 main header records (1 for the second volume),
/// when it records one.
fn rar5_volume_number(c: &[u8]) -> Option<u64> {
    let (_, t1) = vint(c, 0)?;
    let (hflags, t2) = vint(c, t1)?;
    let mut q = t1 + t2;
    if hflags & 0x01 != 0 {
        q += vint(c, q)?.1;
    }
    if hflags & 0x02 != 0 {
        q += vint(c, q)?.1;
    }
    let (archive_flags, n) = vint(c, q)?;
    (archive_flags & 0x02 != 0)
        .then(|| vint(c, q + n).map(|v| v.0))
        .flatten()
}

/// The name in a RAR5 file or service header's content.
pub(super) fn rar5_name(c: &[u8]) -> Option<&[u8]> {
    let f = rar5_fields_at(c)?;
    let (file_flags, n) = vint(c, f.after_sizes)?;
    let mut q = f.after_sizes + n;
    q += vint(c, q)?.1; // unpacked size
    q += vint(c, q)?.1; // attributes
    q += if file_flags & 0x02 != 0 { 4 } else { 0 } + if file_flags & 0x04 != 0 { 4 } else { 0 };
    q += vint(c, q)?.1; // compression information
    q += vint(c, q)?.1; // host OS
    let (len, n) = vint(c, q)?;
    crate::bytes::at(c, q.checked_add(n)?, usize::try_from(len).ok()?)
}

/// The data CRC a RAR5 file block records, when it records one.
pub(super) fn rar5_crc(c: &[u8]) -> Option<u32> {
    let f = rar5_fields_at(c)?;
    f.crc_at.map(|at| u32le(c, at).unwrap_or(0))
}

/// Where the parts of a RAR5 file header content are.
pub(super) struct Rar5Layout {
    /// Where the file fields start: after the extra-area and data sizes.
    pub(super) after_sizes: usize,
    /// Where the data CRC is, when the header has one.
    pub(super) crc_at: Option<usize>,
}

pub(super) fn rar5_fields_at(c: &[u8]) -> Option<Rar5Layout> {
    let (_, t1) = vint(c, 0)?;
    let (hflags, t2) = vint(c, t1)?;
    let mut q = t1 + t2;
    if hflags & 0x01 != 0 {
        q += vint(c, q)?.1;
    }
    if hflags & 0x02 != 0 {
        q += vint(c, q)?.1;
    }
    let after_sizes = q;
    let (file_flags, n) = vint(c, q)?;
    q += n;
    q += vint(c, q)?.1; // unpacked size
    q += vint(c, q)?.1; // attributes
    if file_flags & 0x02 != 0 {
        q += 4; // mtime
    }
    let crc_at = (file_flags & 0x04 != 0).then_some(q);
    Some(Rar5Layout {
        after_sizes,
        crc_at,
    })
}

/// A RAR5 member's block header, and its data, from its parts. A member whose
/// last part is there has the first header with the split flags off, the
/// total data size, and the last part's CRC; one that goes on has the flag
/// for it and the size of the data held.
fn rar5_member(p: Pending, ending: Ending) -> Result<(Vec<u8>, Pieces), String> {
    let c = &p.header;
    let bad = || "a short file header".to_string();
    let layout = rar5_fields_at(c).ok_or_else(bad)?;
    let (file_flags, n) = vint(c, layout.after_sizes).ok_or_else(bad)?;
    let (unp, n2) = vint(c, layout.after_sizes + n).ok_or_else(bad)?;
    let mut q = layout.after_sizes + n + n2;
    q += vint(c, q).ok_or_else(bad)?.1;
    q += if file_flags & 0x02 != 0 { 4 } else { 0 } + if file_flags & 0x04 != 0 { 4 } else { 0 };
    let (comp_info, _) = vint(c, q).ok_or_else(bad)?;
    let (total, crc, split) = match ending {
        Ending::Done { crc, missing } => {
            let total = p.data.len.saturating_add(missing);
            // As for RAR4: a stored member's size shows a missing part.
            if (comp_info >> 7) & 0x7 == 0 && file_flags & 0x08 == 0 && unp != total {
                return Err(format!(
                    "a stored member of {unp} bytes has {total} in the parts given"
                ));
            }
            (total, crc, 0x00)
        }
        Ending::GoesOn => (p.data.len, None, 0x10),
    };
    let (htype, t1) = vint(c, 0).ok_or_else(bad)?;
    let (hflags, t2) = vint(c, t1).ok_or_else(bad)?;
    let mut content = vint_bytes(htype);
    content.extend(vint_bytes((hflags & !0x18) | split | 0x02));
    if hflags & 0x01 != 0 {
        let (extra, _) = vint(c, t1 + t2).ok_or_else(bad)?;
        content.extend(vint_bytes(extra));
    }
    content.extend(vint_bytes(total));
    let shift = content.len() as isize - layout.after_sizes as isize;
    content.extend_from_slice(&c[layout.after_sizes..]);
    if let (Some(at), Some(crc)) = (layout.crc_at, crc) {
        let at = (at as isize + shift) as usize;
        content[at..at + 4].copy_from_slice(&crc.to_le_bytes());
    }
    let mut header = crc32_ieee(&content).to_le_bytes().to_vec();
    header.extend(vint_bytes(content.len() as u64));
    header.extend(content);
    Ok((header, p.data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Budget, Limits};
    use std::cell::Cell;
    use std::io::Read;
    use std::rc::Rc;

    /// A volume that is `head`, then zeros up to `len` bytes, made as it is
    /// read, and the widest window asked of it.
    struct Sparse {
        head: Vec<u8>,
        len: usize,
        widest: Rc<Cell<usize>>,
    }

    impl ByteSource for Sparse {
        fn len(&self) -> usize {
            self.len
        }

        fn window(&self, off: usize, n: usize) -> Cow<'_, [u8]> {
            let end = off.saturating_add(n).min(self.len);
            if off >= end {
                return Cow::Owned(Vec::new());
            }
            self.widest.set(self.widest.get().max(end - off));
            let mut w = vec![0u8; end - off];
            if off < self.head.len() {
                let k = (self.head.len() - off).min(w.len());
                w[..k].copy_from_slice(&self.head[off..off + k]);
            }
            Cow::Owned(w)
        }

        fn identity(&self) -> (usize, usize) {
            (self as *const Self as usize, self.len)
        }
    }

    /// The volumes of a RAR5 set holding one stored member of zeros, `share`
    /// bytes of it in each of `parts`.
    fn volumes(parts: usize, share: usize, widest: &Rc<Cell<usize>>) -> Vec<Box<dyn ByteSource>> {
        let block = |content: Vec<u8>| {
            // The checksum is not read by the walk or the join.
            [vec![0; 4], vint_bytes(content.len() as u64), content].concat()
        };
        (0..parts)
            .map(|k| {
                let (before, after) = (k > 0, k + 1 < parts);
                let mut head = RAR5_MAGIC.to_vec();
                let mut main = [1, 0, if before { 3 } else { 1 }].map(vint_bytes).concat();
                if before {
                    main.extend(vint_bytes(k as u64));
                }
                head.extend(block(main));
                let flags = 0x02 | if before { 0x08 } else { 0 } | if after { 0x10 } else { 0 };
                let mut file = [2, flags, share as u64].map(vint_bytes).concat();
                // File flags, unpacked size, attributes, stored, host OS.
                file.extend(
                    [0, parts as u64 * share as u64, 0, 0, 0]
                        .map(vint_bytes)
                        .concat(),
                );
                file.extend(vint_bytes(3));
                file.extend_from_slice(b"big");
                head.extend(block(file));
                let len = head.len() + share;
                Box::new(Sparse {
                    head,
                    len,
                    widest: widest.clone(),
                }) as Box<dyn ByteSource>
            })
            .collect()
    }

    /// A member of hundreds of megabytes across three volumes is read to its
    /// end through the span, which holds a few headers and asks the volumes
    /// for no more than a window at a time.
    #[test]
    fn a_member_across_volumes_is_read_holding_only_windows() {
        let (parts, share) = (3, 128 << 20);
        let widest = Rc::new(Cell::new(0));
        let span = RarSpan::new(volumes(parts, share, &widest), 1 << 20).unwrap();
        assert!(span.pieces.bytes() < 1024, "{} bytes", span.pieces.bytes());
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: u64::MAX,
            max_scanned_bytes: u64::MAX,
            max_compression_ratio: u64::MAX,
            ..Limits::default()
        });
        let mut total = 0u64;
        super::super::walk(&span, &mut budget, &mut |m, c, _| {
            assert_eq!(m.name, "big");
            let Some(crate::stream::Member::Stream(r)) = c else {
                panic!("not streamed: {:?}", m.unsupported);
            };
            let mut buf = vec![0u8; 1 << 16];
            loop {
                match r.read(&mut buf).unwrap() {
                    0 => break,
                    n => total += n as u64,
                }
            }
            None::<()>
        })
        .unwrap();
        assert_eq!(total, parts as u64 * share as u64);
        assert!(
            widest.get() <= crate::source::CHUNK,
            "a window of {} bytes",
            widest.get()
        );
    }

    /// Volumes that together are longer than `usize` can address are refused,
    /// not cut where the address space ends.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn volumes_longer_than_the_address_space_are_refused() {
        let widest = Rc::new(Cell::new(0));
        let why = RarSpan::new(volumes(2, 3 << 30, &widest), 1 << 20)
            .err()
            .expect("the span was made");
        assert!(why.contains("too long"), "{why}");
    }

    /// RAR4 volumes of one member of method 0x33, `share` bytes of it in each
    /// (so that its size is not checked against the data, as a stored
    /// member's is), with the 64-bit size fields of LHD_LARGE when `large`.
    #[cfg(target_pointer_width = "64")]
    fn volumes4(parts: usize, share: usize, large: bool) -> Vec<Box<dyn ByteSource>> {
        let widest = Rc::new(Cell::new(0));
        (0..parts)
            .map(|k| {
                let (before, after) = (k > 0, k + 1 < parts);
                let mut head = RAR4_MAGIC.to_vec();
                head.extend_from_slice(&[0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]);
                let flags: u16 = 0x8000
                    | if large { 0x100 } else { 0 }
                    | if before { 0x01 } else { 0 }
                    | if after { 0x02 } else { 0 };
                let mut fields = (share as u32).to_le_bytes().to_vec();
                fields.extend_from_slice(&0u32.to_le_bytes()); // UNP_SIZE
                fields.push(0); // HOST_OS
                fields.extend_from_slice(&[0; 8]); // FILE_CRC, FTIME
                fields.extend_from_slice(&[29, 0x33]); // UNP_VER, METHOD
                fields.extend_from_slice(&3u16.to_le_bytes()); // NAME_SIZE
                fields.extend_from_slice(&[0; 4]); // ATTR
                if large {
                    fields.extend_from_slice(&[0; 8]); // HIGH_PACK, HIGH_UNP
                }
                fields.extend_from_slice(b"big");
                head.extend_from_slice(&[0, 0, 0x74]);
                head.extend_from_slice(&flags.to_le_bytes());
                head.extend_from_slice(&((7 + fields.len()) as u16).to_le_bytes());
                head.extend(fields);
                let len = head.len() + share;
                Box::new(Sparse {
                    head,
                    len,
                    widest: widest.clone(),
                }) as Box<dyn ByteSource>
            })
            .collect()
    }

    /// A member that comes to more than 4 GiB over its volumes needs the
    /// 64-bit size fields to say so: without them the join is refused, not
    /// written with a size that wrapped.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_member_past_4_gib_needs_its_64_bit_size_fields() {
        let share = 3usize << 30;
        let why = RarSpan::new(volumes4(2, share, false), 1 << 20)
            .err()
            .expect("the span was made");
        assert!(
            why.contains("a member past 4 GiB with no 64-bit size"),
            "{why}"
        );
        // With the fields the header written for the joined member has the
        // 6 GiB in two halves, and the archive is its parts and the headers.
        let span = RarSpan::new(volumes4(2, share, true), 1 << 20).unwrap();
        let header = span.window(RAR4_MAGIC.len() + 13, 43);
        assert_eq!(u32le(&header, 7), Some(0x8000_0000), "low half of the size");
        assert_eq!(u32le(&header, 32), Some(1), "high half of the size");
        assert_eq!(span.len(), 7 + 13 + 43 + 2 * share + 7);
    }

    /// A RAR5 block with the checksum the join does not read.
    fn block5(content: Vec<u8>) -> Vec<u8> {
        [vec![0; 4], vint_bytes(content.len() as u64), content].concat()
    }

    /// A service block named `name`, with no data.
    fn service(name: &[u8]) -> Vec<u8> {
        // Type, no flags; then file flags, unpacked size, attributes,
        // compression information, host OS and the name.
        let mut c = [3, 0, 0, 0, 0, 0, 0, name.len() as u64]
            .map(vint_bytes)
            .concat();
        c.extend_from_slice(name);
        block5(c)
    }

    /// A stored member `name` of 20 bytes, `data` of them in this block.
    fn member(name: &[u8], flags: u64, data: &[u8]) -> Vec<u8> {
        let mut c = [2, 0x02 | flags, data.len() as u64]
            .map(vint_bytes)
            .concat();
        c.extend([0, 20, 0, 0, 0, name.len() as u64].map(vint_bytes).concat());
        c.extend_from_slice(name);
        [block5(c), data.to_vec()].concat()
    }

    /// The main header of volume `k` of a RAR5 set.
    fn main_header(k: u64) -> Vec<u8> {
        let mut c = [1, 0, if k > 0 { 3 } else { 1 }].map(vint_bytes).concat();
        if k > 0 {
            c.extend(vint_bytes(k));
        }
        [RAR5_MAGIC.to_vec(), block5(c)].concat()
    }

    fn sources(vols: Vec<Vec<u8>>) -> Vec<Box<dyn ByteSource>> {
        vols.into_iter()
            .map(|v| Box::new(v) as Box<dyn ByteSource>)
            .collect()
    }

    /// `n` pairs of a service block the join keeps (`CMT`) and one it drops
    /// (`QO`, which each volume ends with), so that the kept ones do not run
    /// together into one piece of the table. After a member that goes on in
    /// the next volume, when `split`: the join holds them until it ends.
    fn interleaved(n: usize, split: bool) -> Vec<Vec<u8>> {
        let mut first = main_header(0);
        if split {
            first.extend(member(b"mem", 0x10, &[b'a'; 10]));
        }
        for _ in 0..n {
            first.extend(service(b"CMT"));
            first.extend(service(b"QO"));
        }
        match split {
            true => vec![
                first,
                [main_header(1), member(b"mem", 0x08, &[b'b'; 10])].concat(),
            ],
            false => vec![first],
        }
    }

    /// The memory limit of the table is what the blocks the join keeps take,
    /// and what it holds back until a member ends takes as much, besides the
    /// header of the member it waits for: each is counted, as soon as it is
    /// held and not once the member has ended. The volume after the member
    /// is wrong (it says it is the sixth), so a limit that is not reached
    /// before it shows as that error.
    #[test]
    fn the_table_counts_the_blocks_kept_the_blocks_held_back_and_the_pending_header() {
        let refused = |vols: Vec<Vec<u8>>, max: usize| RarSpan::new(sources(vols), max).err();
        let table = "block table is over the memory limit";
        let wrong = "part 2 is volume 6 of its set";

        // 2000 pairs: some 48 KB of pieces, which 16 KB do not hold.
        let why = refused(interleaved(2000, false), 16 << 10).expect("kept: the span was made");
        assert!(why.contains(table), "kept: {why}");
        assert_eq!(refused(interleaved(2000, false), 1 << 20), None);

        let mut held = interleaved(2000, true);
        held[1] = [main_header(5), member(b"mem", 0x08, &[b'b'; 10])].concat();
        let why = refused(held.clone(), 16 << 10).expect("held back: the span was made");
        assert!(why.contains(table), "held back: {why}");
        let why = refused(held, 1 << 20).expect("held back: the second volume is wrong");
        assert!(why.contains(wrong), "held back: {why}");

        // A member whose name is 100 KB has a header of 100 KB, held until
        // its last part comes.
        let name = vec![b'n'; 100_000];
        let set = |second: u64| {
            vec![
                [main_header(0), member(&name, 0x10, &[b'a'; 10])].concat(),
                [main_header(second), member(&name, 0x08, &[b'b'; 10])].concat(),
            ]
        };
        let why = refused(set(5), 50_000).expect("pending: the span was made");
        assert!(why.contains(table), "pending: {why}");
        let why = refused(set(5), 200_000).expect("pending: the second volume is wrong");
        assert!(why.contains(wrong), "pending: {why}");
        assert_eq!(refused(set(1), 200_000), None);
    }
}
