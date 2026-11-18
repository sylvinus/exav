//! CHM (Microsoft Compiled HTML Help, `.chm`) reader.
//!
//! A CHM is the ITSS container Windows Help ships a website in: HTML topics,
//! scripts, images and embedded objects in one file. A `.chm` can start a
//! script or carry a dropper, so every file it lists is handed over to be
//! scanned.
//!
//! Layout (all integers little-endian), from the public ITSS format; the
//! LZX is decoded by the `lzxd` crate, which the cabinet reader uses too:
//!
//! ```text
//! ITSF header @0        magic "ITSF", version, then a header-section table:
//!   +0x38 u64 OffsetHS0  header section 0 (has the total file length)
//!   +0x48 u64 OffsetHS1  header section 1, the ITSP directory
//!   +0x58 u64 OffsetCS0  content section 0 base (v3; v1 and v2 derive it)
//! ITSP directory (HS1)  magic "ITSP":
//!   +0x10 u32 chunk_size, +0x2c u32 num_chunks; the chunks start 0x54 bytes
//!   after HS1. Listing chunks (PMGL) hold the entries, index chunks (PMGI)
//!   are skipped. A PMGL chunk has its entries from +0x14 and the number of
//!   them in its last u16; an entry is ENCINT name_len, name, ENCINT
//!   section, ENCINT offset, ENCINT length.
//! ```
//!
//! A listed file is in one of two content sections:
//! - section 0: stored, at `content-section-0 + offset`, and read where it
//!   lies;
//! - section 1: a range of the one LZX stream in
//!   `::DataSpace/Storage/MSCompressed/Content`. `ControlData` gives the
//!   window size and the reset interval, and the reset table the place of
//!   each 32 KiB frame in the packed stream.
//!
//! Nothing is read whole. The directory is read a chunk at a time into an
//! index of the files (at most `max_members + 1` of them), and the files are
//! handed over in the order they lie in their section, so the LZX stream is
//! decoded once, front to back, restarting where a reset interval begins.
//! What is held is the index, the decoder's window, one frame, and the
//! packed bytes of the frame being decoded.
//!
//! The input is untrusted: every offset and length is checked against the
//! source, and what cannot be read is reported rather than skipped.

use crate::bytes::to_usize;
use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_range, emit_stream};
use crate::{Budget, LimitHit};
use lzxd::{Lzxd, WindowSize};
use std::borrow::Cow;
use std::io::{self, Read};

/// One LZX frame decodes to this many bytes.
const FRAME: u64 = 0x8000;

/// The most packed bytes one frame is handed. A frame of 32 KiB packs to at
/// most about 70 KiB (every symbol at its longest code), so a table that
/// gives a frame more than this is wrong.
const PACKED_FRAME_MAX: u64 = 4 * FRAME;

/// System files needed for LZX decoding.
const CONTENT_NAME: &[u8] = b"::DataSpace/Storage/MSCompressed/Content";
const CONTROL_NAME: &[u8] = b"::DataSpace/Storage/MSCompressed/ControlData";
const SPANINFO_NAME: &[u8] = b"::DataSpace/Storage/MSCompressed/SpanInfo";
const RTABLE_NAME: &[u8] = b"::DataSpace/Storage/MSCompressed/Transform/\
{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";

const PAST_THE_END: &str = "CHM entry runs past the end of the file";
const NOT_DECODABLE: &str = "CHM LZX decode failed";
const OUTSIDE_STREAM: &str = "CHM entry lies outside the compressed stream";
const UNKNOWN_SECTION: &str = "CHM unknown section";
const BAD_HEADER: &str = "CHM header or directory damaged; its files are not listed";
const BAD_LISTING: &str = "CHM directory damaged; the files after the damage are not listed";

// ---- little-endian readers over a slice, None past its end -------------------

fn u16at(d: &[u8], p: usize) -> Option<u16> {
    crate::bytes::at(d, p, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32at(d: &[u8], p: usize) -> Option<u32> {
    crate::bytes::at(d, p, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64at(d: &[u8], p: usize) -> Option<u64> {
    crate::bytes::at(d, p, 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read an ENCINT (big-endian base-128, high bit = continuation) from `d` at
/// `*pos`, advancing `*pos`. Bounded to `end` and to 9 bytes so hostile data
/// can neither run off the buffer nor spin. `None` on truncation.
fn read_encint(d: &[u8], pos: &mut usize, end: usize) -> Option<u64> {
    let mut result: u64 = 0;
    for _ in 0..9 {
        if *pos >= end {
            return None;
        }
        let c = d[*pos];
        *pos += 1;
        result = (result << 7) | u64::from(c & 0x7f);
        if c & 0x80 == 0 {
            return Some(result);
        }
    }
    None
}

// ---- the ITSF header and the directory ----------------------------------------

/// Where the directory and content section 0 are in the source.
struct Itss {
    sec0: u64,
    dir_start: u64,
    chunk_size: u64,
    num_chunks: u64,
}

/// Parse the ITSF header and the ITSP header. `None` when the file is not a
/// structurally valid CHM.
fn parse_itss(src: &dyn ByteSource) -> Option<Itss> {
    let len = src.len() as u64;
    let head = src.window(0, 0x60);
    if !head.starts_with(b"ITSF") {
        return None;
    }
    let off_hs1 = u64at(&head, 0x38 + 0x10)?;
    if off_hs1 >= len {
        return None;
    }
    // OffsetCS0 is in v3; for v1 and v2 it follows the directory.
    let version = u32at(&head, 0x04)?;
    let mut sec0 = u64at(&head, 0x38 + 0x20).unwrap_or(0);
    let itsp = src.window(to_usize(off_hs1), 0x54);
    if !itsp.starts_with(b"ITSP") {
        return None;
    }
    let chunk_size = u64::from(u32at(&itsp, 0x10)?);
    let num_chunks = u64::from(u32at(&itsp, 0x2c)?);
    // A chunk is read whole, so its size is bounded.
    if !(8..=0x40000).contains(&chunk_size) || num_chunks == 0 {
        return None;
    }
    let dir_start = off_hs1.checked_add(0x54)?;
    // The product is below 2^50.
    let dir_end = dir_start.checked_add(chunk_size * num_chunks)?;
    if dir_end > len {
        return None;
    }
    if version < 3 {
        sec0 = dir_end;
    }
    if sec0 > len {
        return None;
    }
    Some(Itss {
        sec0,
        dir_start,
        chunk_size,
        num_chunks,
    })
}

/// A file of content section 0 as the listing places it.
#[derive(Clone, Copy)]
struct Span {
    offset: u64,
    length: u64,
}

/// A file of the listing, as kept until it is handed over.
struct Listed {
    section: u64,
    offset: u64,
    length: u64,
    /// The directory chunk it is in, and where its name lies in the chunk.
    chunk: u32,
    name_at: u32,
    name_len: u32,
}

#[derive(Default)]
struct Listing {
    content: Option<Span>,
    control: Option<Span>,
    reset: Option<Span>,
    span_info: Option<Span>,
    files: Vec<Listed>,
    /// A chunk could not be read, or an entry of one could not: the files
    /// after it are not in the list.
    damaged: bool,
}

/// Read the whole directory, a chunk at a time: the system files LZX decoding
/// needs, and up to `cap` of the other files. System files (`::...`) and
/// files with no length are not files to hand over. Of a system file named
/// twice, the last wins.
fn list(src: &dyn ByteSource, it: &Itss, cap: usize) -> Listing {
    let mut l = Listing::default();
    let chunk_size = to_usize(it.chunk_size);
    for cn in 0..it.num_chunks {
        // Inside the source: the directory was checked to fit.
        let at = it.dir_start + cn * it.chunk_size;
        let chunk = src.window(to_usize(at), chunk_size);
        if chunk.len() < chunk_size {
            l.damaged = true;
            break;
        }
        // Only PMGL chunks hold entries; PMGI chunks are an index of them.
        if &chunk[0..4] != b"PMGL" {
            continue;
        }
        // The entry count is the last u16 of the chunk; entries are read up
        // to it.
        let end = chunk_size - 2;
        let Some(count) = u16at(&chunk, end) else {
            l.damaged = true;
            continue;
        };
        let mut p = 0x14usize;
        for _ in 0..count {
            let Some(name_len) = read_encint(&chunk, &mut p, end).map(to_usize) else {
                l.damaged = true;
                break;
            };
            if name_len > end.saturating_sub(p) {
                l.damaged = true;
                break;
            }
            let name_at = p;
            let name = &chunk[p..p + name_len];
            p += name_len;
            let (Some(section), Some(offset), Some(length)) = (
                read_encint(&chunk, &mut p, end),
                read_encint(&chunk, &mut p, end),
                read_encint(&chunk, &mut p, end),
            ) else {
                l.damaged = true;
                break;
            };
            let span = Span { offset, length };
            match name {
                CONTENT_NAME => l.content = Some(span),
                CONTROL_NAME => l.control = Some(span),
                RTABLE_NAME => l.reset = Some(span),
                SPANINFO_NAME => l.span_info = Some(span),
                n if n.starts_with(b"::") || length == 0 => {}
                _ if l.files.len() >= cap => {}
                // The sizes of a chunk are below 2^18 and its number below 2^32.
                _ => l.files.push(Listed {
                    section,
                    offset,
                    length,
                    chunk: cn as u32,
                    name_at: name_at as u32,
                    name_len: name_len as u32,
                }),
            }
        }
    }
    l
}

/// The name of a listed file, read again from its chunk.
fn name_of(src: &dyn ByteSource, it: &Itss, f: &Listed) -> String {
    let at = it.dir_start + u64::from(f.chunk) * it.chunk_size + u64::from(f.name_at);
    let raw = src.window(to_usize(at), f.name_len as usize);
    String::from_utf8_lossy(&raw).into_owned()
}

// ---- the LZX stream ----------------------------------------------------------

/// A section 0 file, if all of it lies in the source: its place there.
fn placed(src: &dyn ByteSource, sec0: u64, s: Span) -> Option<(u64, u64)> {
    let at = sec0.checked_add(s.offset)?;
    let end = at.checked_add(s.length)?;
    (end <= src.len() as u64).then_some((at, s.length))
}

/// LZX parameters carried by `ControlData`: the window and how many frames
/// make a reset interval.
fn parse_control(blob: &[u8]) -> Option<(WindowSize, u64)> {
    // u32 length, u32 "LZXC", u32 version, u32 reset interval, u32 window...
    if u32at(blob, 0x04)? != 0x4358_5A4C {
        return None;
    }
    let (reset_interval, window_size) = match u32at(blob, 0x08)? {
        1 => (u64::from(u32at(blob, 0x0c)?), u64::from(u32at(blob, 0x10)?)),
        2 => (
            u64::from(u32at(blob, 0x0c)?) * FRAME,
            u64::from(u32at(blob, 0x10)?) * FRAME,
        ),
        _ => return None,
    };
    let window = match window_size {
        0x0_8000 => WindowSize::KB32,
        0x1_0000 => WindowSize::KB64,
        0x2_0000 => WindowSize::KB128,
        0x4_0000 => WindowSize::KB256,
        0x8_0000 => WindowSize::KB512,
        0x10_0000 => WindowSize::MB1,
        0x20_0000 => WindowSize::MB2,
        _ => return None,
    };
    // A whole number of frames, at least one; anything else is read as one
    // frame.
    let frames = if reset_interval == 0 || reset_interval % FRAME != 0 {
        1
    } else {
        reset_interval / FRAME
    };
    Some((window, frames))
}

/// The reset table: the decoded length of the stream, and the place of each
/// entry in the source, which is read when it is needed.
struct ResetTable {
    uncomp_len: u64,
    /// Where entry 0 is in the source, the size of an entry (4 or 8) and
    /// how many there are.
    at: u64,
    size: u64,
    count: u64,
}

/// The reset table file at `at`, `len` bytes long, in the source.
fn parse_reset_table(src: &dyn ByteSource, at: u64, len: u64) -> Option<ResetTable> {
    let head = src.window(to_usize(at), 0x18);
    let count = u64::from(u32at(&head, 0x04)?);
    let size = u64::from(u32at(&head, 0x08)?);
    let table_off = u64::from(u32at(&head, 0x0c)?);
    let uncomp_len = u64at(&head, 0x10)?;
    if size != 4 && size != 8 {
        return None;
    }
    // Every entry the table declares is inside the file.
    if table_off.checked_add(count.checked_mul(size)?)? > len {
        return None;
    }
    Some(ResetTable {
        uncomp_len,
        at: at.checked_add(table_off)?,
        size,
        count,
    })
}

impl ResetTable {
    fn entry(&self, src: &dyn ByteSource, i: u64) -> Option<u64> {
        if i >= self.count {
            return None;
        }
        // Inside the source: the table was checked to fit.
        let at = self.at + i * self.size;
        let w = src.window(to_usize(at), to_usize(self.size));
        if self.size == 8 {
            u64at(&w, 0)
        } else {
            u32at(&w, 0).map(u64::from)
        }
    }
}

/// The LZX stream of section 1, decoded a frame at a time.
///
/// LZX in CHM is framed: the stream is padded to a whole number of 32 KiB
/// frames, so every frame decodes to exactly `FRAME` bytes and the decoder is
/// always asked for that many. It is reset at the start of each reset
/// interval, and carries its state through the frames of one, each read from
/// the packed offset the reset table gives it. A table with fewer entries
/// than frames gives only where each interval starts, so then only the first
/// frame of each can be found.
struct LzxStream<'a> {
    src: &'a dyn ByteSource,
    /// The packed stream: its place in the source, cut at the source's end.
    packed_at: u64,
    packed_len: u64,
    table: ResetTable,
    /// The table has an entry for every frame.
    per_frame: bool,
    window: WindowSize,
    /// Frames in a reset interval, at least one.
    interval: u64,
    /// Frames the decoded length covers.
    frames: u64,
    dec: Option<Lzxd>,
    /// The interval `dec` is in, and the next frame it will decode.
    dec_interval: Option<u64>,
    next: u64,
    /// The last frame decoded.
    buf: Vec<u8>,
    buf_frame: Option<u64>,
    /// The frame at which decoding failed, and its interval: that frame and
    /// those after it in the interval cannot be had.
    failed: Option<(u64, u64)>,
}

/// The stream of section 1, if the system files that describe it are all
/// there and sound.
fn lzx_stream<'a>(src: &'a dyn ByteSource, sec0: u64, l: &Listing) -> Option<LzxStream<'a>> {
    let content = l.content?;
    let packed_at = sec0.checked_add(content.offset)?;
    let avail = (src.len() as u64).checked_sub(packed_at)?;
    let (cat, clen) = placed(src, sec0, l.control?)?;
    let control = src.window(to_usize(cat), to_usize(clen.min(0x20)));
    let (window, interval) = parse_control(&control)?;
    // The reset table gives the frame offsets and the true decoded length;
    // SpanInfo gives the length alone.
    let table = l
        .reset
        .and_then(|s| placed(src, sec0, s))
        .and_then(|(at, len)| parse_reset_table(src, at, len))
        .or_else(|| {
            let (at, _) = placed(src, sec0, l.span_info?)?;
            let uncomp_len = u64at(&src.window(to_usize(at), 8), 0)?;
            Some(ResetTable {
                uncomp_len,
                at: 0,
                size: 8,
                count: 0,
            })
        })?;
    let frames = table.uncomp_len.div_ceil(FRAME);
    if frames == 0 {
        return None;
    }
    Some(LzxStream {
        src,
        packed_at,
        packed_len: content.length.min(avail),
        per_frame: table.count >= frames,
        table,
        window,
        interval,
        frames,
        dec: None,
        dec_interval: None,
        next: 0,
        buf: Vec::new(),
        buf_frame: None,
        failed: None,
    })
}

impl<'a> LzxStream<'a> {
    /// Whether `[offset, offset + len)` lies in the decoded stream.
    fn covers(&self, offset: u64, len: u64) -> bool {
        offset
            .checked_add(len)
            .is_some_and(|end| end <= self.frames.saturating_mul(FRAME))
    }

    /// Where frame `f` starts in the packed stream.
    fn start_of(&self, f: u64) -> Option<u64> {
        let o = if f == 0 && self.table.count == 0 {
            Some(0)
        } else if self.per_frame {
            self.table.entry(self.src, f)
        } else if f.is_multiple_of(self.interval) {
            self.table.entry(self.src, f / self.interval)
        } else {
            None
        };
        o.filter(|&o| o <= self.packed_len)
    }

    /// The packed bytes of frame `f`: up to where the next frame starts when
    /// the table has every frame, else up to the end of the stream; and never
    /// more than a frame can pack to.
    fn packed(&self, f: u64) -> Option<Cow<'a, [u8]>> {
        let from = self.start_of(f)?;
        let to = if self.per_frame {
            self.start_of(f + 1).filter(|&t| t >= from)
        } else {
            None
        };
        let to = to
            .unwrap_or(self.packed_len)
            .min(from.saturating_add(PACKED_FRAME_MAX));
        Some(
            self.src
                .window(to_usize(self.packed_at + from), to_usize(to - from)),
        )
    }

    fn blocked(&self, f: u64) -> bool {
        self.failed
            .is_some_and(|(interval, first)| interval == f / self.interval && f >= first)
    }

    fn failure(f: u64) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("CHM LZX frame {f} cannot be decoded"),
        )
    }

    /// Decode frame `f` into `buf`. It must be the next frame of the decoder,
    /// or the first of an interval, which resets it.
    fn decode(&mut self, f: u64) -> io::Result<()> {
        let interval = f / self.interval;
        if self.blocked(f) {
            return Err(Self::failure(f));
        }
        if f.is_multiple_of(self.interval) {
            self.dec = Some(Lzxd::new(self.window));
            self.dec_interval = Some(interval);
            self.next = f;
        }
        let ready = self.dec_interval == Some(interval) && self.next == f;
        let packed = if ready { self.packed(f) } else { None };
        if let (Some(packed), Some(dec)) = (packed, self.dec.as_mut())
            && let Ok(out) = dec.decompress_next(&packed, FRAME as usize)
            && out.len() as u64 == FRAME
        {
            self.buf.clear();
            self.buf.extend_from_slice(out);
            self.buf_frame = Some(f);
            self.next = f + 1;
            return Ok(());
        }
        self.buf_frame = None;
        self.failed = Some((interval, f));
        Err(Self::failure(f))
    }

    /// Get the decoder ready to give frame `frame` as its next: frames of its
    /// reset interval before it are decoded and dropped, and a decoder that
    /// is in another interval, or past the frame, restarts at the start of
    /// this one. What is dropped is charged to the scan budget, which bounds
    /// the work a table or a listing can ask for.
    fn position(&mut self, frame: u64, budget: &mut Budget) -> Result<(), LimitHit> {
        if self.buf_frame == Some(frame) || self.blocked(frame) {
            return Ok(());
        }
        let interval = frame / self.interval;
        let from = if self.dec_interval == Some(interval) && self.next <= frame {
            self.next
        } else {
            let first = interval * self.interval;
            self.dec = None;
            self.dec_interval = None;
            self.buf_frame = None;
            self.next = first;
            first
        };
        let skip = frame - from;
        if skip > 0 {
            budget.charge_scan(skip.saturating_mul(FRAME))?;
            for f in from..frame {
                if self.decode(f).is_err() {
                    break;
                }
            }
        }
        Ok(())
    }
}

/// A file of section 1, read from the decoder a frame at a time.
struct PackedFile<'s, 'a> {
    lzx: &'s mut LzxStream<'a>,
    pos: u64,
    end: u64,
}

impl Read for PackedFile<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.pos >= self.end {
            return Ok(0);
        }
        let f = self.pos / FRAME;
        if self.lzx.buf_frame != Some(f) {
            self.lzx.decode(f)?;
        }
        let at = self.pos % FRAME;
        let n = (out.len() as u64).min(FRAME - at).min(self.end - self.pos) as usize;
        out[..n].copy_from_slice(&self.lzx.buf[at as usize..at as usize + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

// ---- handing the files over ----------------------------------------------------

/// A member with its content out of reach, reported.
fn report(
    meta: &MemberMeta,
    reason: &'static str,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Option<()> {
    let m = MemberMeta {
        unsupported: Some(reason),
        ..meta.clone()
    };
    visit(&m, None, budget)
}

/// A file of section 0, read where it lies. A file that runs past the end of
/// the source is handed over as far as it goes, and reported.
fn emit_stored(
    src: &dyn ByteSource,
    it: &Itss,
    f: &Listed,
    name: String,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let at = it.sec0.checked_add(f.offset);
    let have = at
        .map_or(0, |a| (src.len() as u64).saturating_sub(a))
        .min(f.length);
    let mut meta = MemberMeta {
        name,
        comp_size: f.length,
        size: Some(f.length),
        unsupported: (have < f.length).then_some(PAST_THE_END),
        ..MemberMeta::default()
    };
    let Some(at) = at.filter(|_| have > 0) else {
        return Ok(visit(&meta, None, budget));
    };
    let mut rd = Reader::range(src, to_usize(at), to_usize(at + have));
    emit_range(&mut meta, (at, f.length), &mut rd, budget, visit)
}

/// A file of section 1, decoded as it is read.
fn emit_packed(
    lzx: Option<&mut LzxStream<'_>>,
    f: &Listed,
    name: String,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let meta = MemberMeta {
        name,
        comp_size: f.length,
        size: Some(f.length),
        ..MemberMeta::default()
    };
    let Some(lzx) = lzx else {
        return Ok(report(&meta, NOT_DECODABLE, budget, visit));
    };
    if !lzx.covers(f.offset, f.length) {
        return Ok(report(&meta, OUTSIDE_STREAM, budget, visit));
    }
    lzx.position(f.offset / FRAME, budget)?;
    let mut rd = PackedFile {
        lzx,
        pos: f.offset,
        end: f.offset + f.length,
    };
    emit_stream(&meta, &mut rd, budget, visit)
}

/// The report of a header or a directory that could not be read: files are
/// in the container and not listed.
fn emit_damaged(
    src: &dyn ByteSource,
    reason: &'static str,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    budget.count_entry()?;
    let meta = MemberMeta {
        name: "chm-directory".to_string(),
        comp_size: src.len() as u64,
        unsupported: Some(reason),
        ..MemberMeta::default()
    };
    Ok(visit(&meta, None, budget))
}

pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    if !src.window(0, 4).starts_with(b"ITSF") {
        return Ok(None);
    }
    let Some(it) = parse_itss(src) else {
        return emit_damaged(src, BAD_HEADER, budget, visit);
    };
    // One more than the members a scan may count: past it the walk ends with
    // the member limit, so a longer list is never needed.
    let cap = usize::try_from(budget.limits().max_members.saturating_add(1)).unwrap_or(usize::MAX);
    let mut listing = list(src, &it, cap);
    // In the order they lie in their section: the LZX stream is then decoded
    // once, and stored files are read front to back.
    listing.files.sort_by_key(|f| (f.section, f.offset));
    let mut lzx = lzx_stream(src, it.sec0, &listing);
    for f in &listing.files {
        budget.count_entry()?;
        let name = name_of(src, &it, f);
        let stopped = match f.section {
            0 => emit_stored(src, &it, f, name, budget, visit)?,
            1 => emit_packed(lzx.as_mut(), f, name, budget, visit)?,
            _ => {
                let meta = MemberMeta {
                    name,
                    comp_size: f.length,
                    size: Some(f.length),
                    ..MemberMeta::default()
                };
                report(&meta, UNKNOWN_SECTION, budget, visit)
            }
        };
        if stopped.is_some() {
            return Ok(stopped);
        }
    }
    if listing.damaged {
        return emit_damaged(src, BAD_LISTING, budget, visit);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, Limits, extract};

    fn names(blob: &[u8]) -> Vec<(String, Option<&'static str>)> {
        let mut budget = Budget::new(Limits::default());
        extract(Format::Chm, &blob, &mut budget)
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.unsupported))
            .collect()
    }

    #[test]
    fn non_chm_input_yields_nothing() {
        assert!(names(b"not a chm file at all").is_empty());
    }

    #[test]
    fn truncated_itsf_is_reported() {
        // Just the magic, nothing else: every read after it must bail.
        let got = names(b"ITSF");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "chm-directory");
        assert!(got[0].1.is_some());
    }

    #[test]
    fn random_bytes_after_magic_do_not_panic() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"ITSF");
        for i in 0..4096u32 {
            blob.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        // Must not panic; the header is not a valid one, which is reported.
        assert!(names(&blob).iter().all(|(_, u)| u.is_some()));
    }

    #[test]
    fn read_encint_roundtrips_and_is_bounded() {
        // 0x1234 -> 0xA4,0x34 (big-endian base-128 with continuation bit).
        let buf = [0xA4u8, 0x34];
        let mut p = 0;
        assert_eq!(read_encint(&buf, &mut p, buf.len()), Some(0x1234));
        assert_eq!(p, 2);
        // All-continuation bytes must terminate (never spin / overrun).
        let bad = [0x80u8; 16];
        let mut p = 0;
        assert_eq!(read_encint(&bad, &mut p, bad.len()), None);
    }

    // CHM fixtures live under tests/fixtures/chm and are exercised by the
    // integration tests in tests/suites/chm.rs.

    /// The list of files stops at `cap`, and the system files that follow it
    /// in the directory are still found: the tables of the stream are needed
    /// however long the list is.
    #[test]
    fn the_list_of_files_is_cut_at_the_cap_and_the_system_files_are_kept() {
        let path = format!(
            "{}/tests/fixtures/chm/benign-lzx.chm",
            env!("CARGO_MANIFEST_DIR")
        );
        let blob = std::fs::read(path).unwrap();
        let it = parse_itss(&blob).unwrap();
        let all = list(&blob, &it, usize::MAX);
        assert!(all.files.len() > 2);
        let cut = list(&blob, &it, 2);
        assert_eq!(cut.files.len(), 2);
        assert!(cut.content.is_some() && cut.control.is_some() && cut.reset.is_some());
        assert!(!cut.damaged);
    }

    /// A crafted ITSF whose HS1 (ITSP) offset is `u64::MAX` must bail via the
    /// `off_hs1 >= len` guard rather than overflow any offset sum.
    #[test]
    fn hostile_hs1_offset_is_reported() {
        let mut d = vec![0u8; 0x200];
        d[0..4].copy_from_slice(b"ITSF");
        d[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        d[0x48..0x50].copy_from_slice(&u64::MAX.to_le_bytes()); // OffsetHS1
        let got = names(&d);
        assert_eq!(got.len(), 1);
        assert!(got[0].1.is_some());
    }

    /// Valid ITSF+ITSP magic but hostile directory geometry (`chunk_size` and
    /// `num_chunks` both `u32::MAX`) must be rejected without overflow or an
    /// out-of-bounds read.
    #[test]
    fn hostile_itsp_geometry_is_reported() {
        let hs1 = 0x60usize;
        let mut d = vec![0u8; 0x200];
        d[0..4].copy_from_slice(b"ITSF");
        d[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        d[0x48..0x50].copy_from_slice(&(hs1 as u64).to_le_bytes());
        d[hs1..hs1 + 4].copy_from_slice(b"ITSP");
        d[hs1 + 0x10..hs1 + 0x14].copy_from_slice(&u32::MAX.to_le_bytes()); // chunk_size
        d[hs1 + 0x2c..hs1 + 0x30].copy_from_slice(&u32::MAX.to_le_bytes()); // num_chunks
        assert_eq!(names(&d).len(), 1);

        // Also a well-formed geometry whose extent overruns the file.
        d[hs1 + 0x10..hs1 + 0x14].copy_from_slice(&0x1000u32.to_le_bytes());
        d[hs1 + 0x2c..hs1 + 0x30].copy_from_slice(&50u32.to_le_bytes());
        assert_eq!(names(&d).len(), 1);
    }

    /// A valid PMGL chunk whose first entry declares a hostile ENCINT name length
    /// (larger than the chunk) must stop cleanly, never slice out of bounds.
    #[test]
    fn hostile_entry_name_len_no_panic() {
        let chunk_size = 0x40usize;
        let hs1 = 0x60usize;
        let dir_start = hs1 + 0x54;
        let total = dir_start + chunk_size + 0x100;
        let mut d = vec![0u8; total];
        d[0..4].copy_from_slice(b"ITSF");
        d[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        d[0x48..0x50].copy_from_slice(&(hs1 as u64).to_le_bytes());
        d[0x58..0x60].copy_from_slice(&(total as u64).to_le_bytes()); // sec0 base
        d[hs1..hs1 + 4].copy_from_slice(b"ITSP");
        d[hs1 + 0x10..hs1 + 0x14].copy_from_slice(&(chunk_size as u32).to_le_bytes());
        d[hs1 + 0x2c..hs1 + 0x30].copy_from_slice(&1u32.to_le_bytes());
        // PMGL chunk with entry count 1 and a hostile name_len encint (0x81 0x00 = 128).
        d[dir_start..dir_start + 4].copy_from_slice(b"PMGL");
        let end = dir_start + chunk_size - 2;
        d[end..end + 2].copy_from_slice(&1u16.to_le_bytes());
        d[dir_start + 0x14] = 0x81;
        d[dir_start + 0x15] = 0x00;
        // The listing is damaged, which is reported: no file is named.
        let got = names(&d);
        assert_eq!(got.len(), 1);
        assert!(got[0].1.is_some());
    }

    /// An entry count past the entries a listing chunk holds runs the reader
    /// off the end of its entries. The files before that point are still
    /// extracted, and the damage is reported; the whole CHM used to come back
    /// as nothing at all.
    #[test]
    fn a_listing_chunk_with_too_many_entries_keeps_the_files_before_it() {
        let path = format!(
            "{}/tests/fixtures/chm/benign-lzx.chm",
            env!("CARGO_MANIFEST_DIR")
        );
        let blob = std::fs::read(path).unwrap();
        let mut budget = Budget::new(Limits::default());
        let want = extract(Format::Chm, &blob, &mut budget).unwrap();
        assert!(!want.is_empty());
        assert!(want.iter().all(|e| e.unsupported.is_none()));

        let hs1 = u64at(&blob, 0x48).unwrap() as usize;
        let chunk_size = u32at(&blob, hs1 + 0x10).unwrap() as usize;
        let num_chunks = u32at(&blob, hs1 + 0x2c).unwrap() as usize;
        let dir_start = hs1 + 0x54;
        let mut bad = blob.clone();
        let mut hit = false;
        for cn in 0..num_chunks {
            let cs = dir_start + cn * chunk_size;
            if &bad[cs..cs + 4] == b"PMGL" {
                let end = cs + chunk_size - 2;
                bad[end..end + 2].copy_from_slice(&u16::MAX.to_le_bytes());
                hit = true;
            }
        }
        assert!(hit, "the sample has a listing chunk");
        let mut budget = Budget::new(Limits::default());
        let got = extract(Format::Chm, &bad, &mut budget).unwrap();
        for w in &want {
            assert!(
                got.iter().any(|g| g.name == w.name && g.data == w.data),
                "{} kept",
                w.name
            );
        }
        assert!(got.iter().any(|g| g.unsupported.is_some()));
    }
}
