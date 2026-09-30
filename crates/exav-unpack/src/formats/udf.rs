//! UDF — the filesystem on DVDs, Blu-rays, and any `.iso` a modern tool writes.
//!
//! Windows and macOS both mount a UDF image on double-click, and 7-Zip opens
//! one, so it is as plausible a delivery container as ISO 9660 — which it has
//! largely replaced. Most `.iso` files carry **both** filesystems ("UDF bridge")
//! over the same extents, but a UDF-only image is perfectly ordinary, and there
//! the ISO 9660 walk finds nothing at all.
//!
//! Implemented from ECMA-167 and the OSTA UDF specification. All fields are
//! **little-endian**. The path from the start of the image to a file's bytes is
//! long:
//!
//! ```text
//! Anchor Volume Descriptor Pointer  (sector 256)
//!   -> Main Volume Descriptor Sequence
//!        -> Partition Descriptor   (where the partition starts)
//!        -> Logical Volume Descriptor (block size, partition maps, File Set)
//!   -> File Set Descriptor         -> root directory ICB
//!   -> File Entry                  -> allocation descriptors -> the bytes
//! ```
//!
//! Every address is a block in a partition named by a partition map. UDF 2.50
//! and later keep the tree in a **metadata partition**, whose blocks are the
//! content of a metadata file recorded in a plain partition (or of its mirror,
//! when that file cannot be read). Sparable and virtual partitions are not read
//! and are reported where the tree needs them.
//!
//! Called from the ISO extractor rather than dispatched on its own, so that a
//! bridge image is walked through both filesystems with a shared set of already
//! emitted extents — the two trees name the same blocks, so files are not
//! scanned twice.
//!
//! One walk serves both the in-memory image ([`extract_udf`]) and a seekable
//! source ([`stream_udf`]): it reads the image through [`Image`] and hands each
//! file over as the runs of bytes it occupies, which the two drivers either
//! copy out or stream.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};

use crate::stream::{emit_stream, MemberMeta, Visit};
use crate::{Budget, LimitHit};

/// UDF descriptors are addressed in 2048-byte sectors regardless of the logical
/// block size the volume declares.
const SECTOR: u64 = 2048;

/// The Anchor Volume Descriptor Pointer is required at sector 256; the
/// specification also allows copies at the last sector and 256 before it.
const ANCHOR_SECTOR: u64 = 256;

/// Descriptor tag identifiers used here.
const TAG_ANCHOR: u16 = 2;
const TAG_PARTITION: u16 = 5;
const TAG_LOGICAL_VOLUME: u16 = 6;
const TAG_TERMINATING: u16 = 8;
const TAG_FILE_SET: u16 = 256;
const TAG_FILE_IDENTIFIER: u16 = 257;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;

/// ICB `FileType` values that name something with bytes to scan.
const FILE_TYPE_DIRECTORY: u8 = 4;
const FILE_TYPE_FILE: u8 = 5;

/// `FileCharacteristics` bit 1: the entry is a directory; bit 3: it is the
/// parent (`..`) back-pointer.
const FID_DIRECTORY: u8 = 1 << 1;
const FID_PARENT: u8 = 1 << 3;

/// Allocation-descriptor kinds, from the low three bits of the ICB flags.
const AD_SHORT: u16 = 0;
const AD_LONG: u16 = 1;
const AD_EXTENDED: u16 = 2;
/// The file's bytes are stored inside the File Entry itself.
const AD_IN_ICB: u16 = 3;

/// Extent kinds, from the top two bits of an allocation descriptor's length.
const EXTENT_RECORDED: u32 = 0;
/// The descriptor points at a continuation of the descriptor list.
const EXTENT_CONTINUATION: u32 = 3;

/// Bounds on the walk. Each is reported when hit: a cap that stops quietly
/// leaves the rest of the image unenumerated while the file still reads clean.
const MAX_DIRS: usize = 4096;
const MAX_EXTENTS: usize = 8192;
/// Allocation-descriptor bytes read for one entry, continuations included. A
/// real list fits in a block; this is room for `MAX_EXTENTS` long ones several
/// times over.
const MAX_AD_BYTES: u64 = 1 << 20;

/// Bytes of a Logical Volume Descriptor the walk reads: the fixed part and the
/// most partition maps it looks at (64, of at most 255 bytes each).
const LVD_READ: usize = 440 + 64 * 256;
/// Bytes of a File Entry the walk reads: the fixed part of the larger, Extended
/// File Entry, up to its two length fields.
const FE_READ: usize = 216;

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

/// Does the Volume Recognition Sequence declare a UDF filesystem? The sequence
/// starts at sector 16 and each entry is a 2048-byte descriptor whose identifier
/// sits at offset 1.
pub(crate) fn has_udf(data: &[u8]) -> bool {
    (16..32).any(|s| {
        let o = (s * SECTOR + 1) as usize;
        matches!(data.get(o..o + 5), Some(b"NSR02") | Some(b"NSR03"))
    })
}

/// Bytes [`has_udf`] looks at.
const RECOGNITION_END: usize = (32 * SECTOR) as usize + 6;

/// A UDF name is OSTA CS0: a leading byte says whether the rest is 8-bit or
/// UTF-16BE.
fn decode_name(raw: &[u8]) -> String {
    match raw.split_first() {
        Some((8, rest)) => rest.iter().map(|&c| c as char).collect(),
        Some((16, rest)) => {
            let units: Vec<u16> = rest
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_be_bytes)
                .collect();
            String::from_utf16_lossy(&units)
        }
        // An empty or unmarked identifier; keep whatever bytes are there rather
        // than dropping the entry.
        _ => String::from_utf8_lossy(raw).into_owned(),
    }
}

/// Random access to the image being walked.
trait Image {
    fn len(&self) -> u64;
    /// Up to `len` bytes at `off`, fewer where the image ends.
    fn read(&mut self, off: u64, len: usize) -> Result<Cow<'_, [u8]>, LimitHit>;
}

impl Image for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read(&mut self, off: u64, len: usize) -> Result<Cow<'_, [u8]>, LimitHit> {
        let data: &[u8] = self;
        let start = usize::try_from(off).map_or(data.len(), |o| o.min(data.len()));
        let end = start.saturating_add(len).min(data.len());
        Ok(Cow::Borrowed(&data[start..end]))
    }
}

struct Seekable<'a, R> {
    src: &'a mut R,
    len: u64,
}

impl<R: Read + Seek> Image for Seekable<'_, R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read(&mut self, off: u64, len: usize) -> Result<Cow<'_, [u8]>, LimitHit> {
        // Clamped first: `read_at` allocates what it is asked for.
        let avail = self.len.saturating_sub(off);
        let len = len.min(usize::try_from(avail).unwrap_or(usize::MAX));
        crate::read_at(&mut *self.src, off, len).map(Cow::Owned)
    }
}

/// Why the walk cannot go on: a structure that does not hold up, which is
/// reported as unreadable, or a read of the source that failed.
enum Stop {
    Bad(&'static str),
    Io(LimitHit),
}

impl From<LimitHit> for Stop {
    fn from(e: LimitHit) -> Self {
        Stop::Io(e)
    }
}

/// A logical block in the partition a partition reference (the index of a
/// partition map) names.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Addr {
    lbn: u32,
    part: u16,
}

/// How one partition reference turns into image offsets.
enum Map {
    /// Blocks one after another from byte `start` of the image.
    Physical { number: u16, start: u64 },
    /// A UDF 2.50 metadata partition: its blocks are the metadata file's
    /// content, listed as runs of the image with the file offset each starts at.
    Metadata(Vec<(u64, Run)>),
    /// A partition the walk cannot follow, and why.
    Unreadable(&'static str),
}

/// Where the file data lives and how it is addressed.
struct Volume {
    /// Logical block size, in bytes.
    block_size: u64,
    /// By partition reference.
    maps: Vec<Map>,
    /// Where the File Set Descriptor is.
    fsd: Addr,
}

impl Volume {
    /// The runs of the image holding `len` bytes from `addr`. `None` when its
    /// partition cannot be followed, or the range runs past the metadata file.
    fn locate(&self, addr: Addr, len: u64) -> Option<Vec<Run>> {
        let off = (addr.lbn as u64) * self.block_size;
        match self.maps.get(addr.part as usize)? {
            Map::Physical { start, .. } => Some(vec![Run {
                at: Some(start + off),
                len,
            }]),
            Map::Metadata(runs) => {
                let end = off + len;
                let mut pos = off;
                let mut i = runs.partition_point(|(s, r)| s + r.len <= pos);
                let mut out = Vec::new();
                while pos < end {
                    let (s, r) = runs.get(i)?;
                    let skip = pos - s;
                    let take = (r.len - skip).min(end - pos);
                    out.push(Run {
                        at: r.at.map(|a| a + skip),
                        len: take,
                    });
                    pos += take;
                    i += 1;
                }
                Some(out)
            }
            Map::Unreadable(_) => None,
        }
    }

    /// Image offset of the block at `addr`, when it was written.
    fn at(&self, addr: Addr) -> Option<u64> {
        self.locate(addr, 1)?.first()?.at
    }
}

/// The ICB file types of a metadata partition's metadata file and its mirror.
const FILE_TYPE_METADATA: u8 = 250;
const FILE_TYPE_METADATA_MIRROR: u8 = 251;

/// Read the Anchor, the Main Volume Descriptor Sequence, the partitions it
/// names and how each is addressed. `Stop::Bad` carries a reason to report
/// rather than a reason to stay quiet.
fn volume(img: &mut dyn Image) -> Result<Volume, Stop> {
    let sectors = img.len() / SECTOR;
    let mut anchor = None;
    for s in [
        ANCHOR_SECTOR,
        sectors.saturating_sub(1),
        sectors.saturating_sub(257),
    ] {
        let d = img.read(s * SECTOR, 24)?;
        if le_u16(&d, 0) == TAG_ANCHOR {
            // The anchor's first field is the extent holding the descriptor
            // sequence.
            anchor = Some((le_u32(&d, 16) as u64, le_u32(&d, 20) as u64));
            break;
        }
    }
    let (mvds_len, mvds_loc) =
        anchor.ok_or(Stop::Bad("UDF image has no anchor volume descriptor"))?;

    // Partition number and first sector of each Partition Descriptor.
    let mut partitions: Vec<(u16, u64)> = Vec::new();
    let mut lvd: Option<u64> = None;
    for i in 0..(mvds_len / SECTOR).min(sectors) {
        let o = mvds_loc.saturating_add(i).saturating_mul(SECTOR);
        let d = img.read(o, 192)?;
        match le_u16(&d, 0) {
            TAG_PARTITION if partitions.len() < 64 => {
                partitions.push((le_u16(&d, 22), le_u32(&d, 188) as u64));
            }
            TAG_LOGICAL_VOLUME => lvd = Some(o),
            TAG_TERMINATING => break,
            _ => {}
        }
    }
    if partitions.is_empty() {
        return Err(Stop::Bad(
            "UDF volume descriptor sequence names no partition",
        ));
    }
    let lvd = lvd.ok_or(Stop::Bad(
        "UDF volume descriptor sequence names no logical volume",
    ))?;
    let d = img.read(lvd, LVD_READ)?.into_owned();

    let block_size = le_u32(&d, 212) as u64;
    if block_size == 0 || !block_size.is_power_of_two() || block_size > 1 << 16 {
        return Err(Stop::Bad("implausible UDF logical block size"));
    }
    // `LogicalVolumeContentsUse` is a long_ad naming the File Set Descriptor:
    // its extent length, then a block and a partition reference.
    let fsd = Addr {
        lbn: le_u32(&d, 248 + 4),
        part: le_u16(&d, 248 + 8),
    };

    // Partition maps translate a partition reference into a partition. Type 1
    // names a partition directly. Of the type 2 kinds, the metadata partition
    // is read through its metadata file once the plain partitions are known;
    // the virtual and sparable ones are not read, and saying so is all a map
    // of theirs does here.
    let map_count = le_u32(&d, 268) as usize;
    let mut maps = Vec::new();
    // Partition reference, partition number, then metadata file and mirror.
    let mut metadata: Vec<(usize, u16, [u32; 2])> = Vec::new();
    let mut at = 440;
    for _ in 0..map_count.min(64) {
        let kind = d.get(at).copied().unwrap_or(0);
        let len = d.get(at + 1).copied().unwrap_or(0) as usize;
        if len == 0 {
            break;
        }
        let m = d.get(at..at + len).unwrap_or(&[]);
        let ident = m.get(5..28).unwrap_or(&[]);
        let ident = &ident[..ident.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1)];
        maps.push(match (kind, ident) {
            (1, _) => {
                let number = le_u16(m, 4);
                match partitions.iter().find(|(n, _)| *n == number) {
                    Some(&(_, start)) => Map::Physical {
                        number,
                        start: start * SECTOR,
                    },
                    None => {
                        Map::Unreadable("UDF partition map names a partition not in this volume")
                    }
                }
            }
            (2, b"*UDF Metadata Partition") => {
                metadata.push((maps.len(), le_u16(m, 38), [le_u32(m, 40), le_u32(m, 44)]));
                Map::Unreadable("UDF metadata partition names a partition not in this volume")
            }
            (2, b"*UDF Sparable Partition") => {
                Map::Unreadable("UDF sparable partitions are not supported")
            }
            (2, b"*UDF Virtual Partition") => {
                Map::Unreadable("UDF virtual partitions are not supported")
            }
            _ => Map::Unreadable("UDF partition map of a kind exav does not know"),
        });
        at += len;
    }

    let mut vol = Volume {
        block_size,
        maps,
        fsd,
    };
    for (index, number, files) in metadata {
        let physical = vol
            .maps
            .iter()
            .position(|m| matches!(m, Map::Physical { number: n, .. } if *n == number));
        if let Some(physical) = physical {
            vol.maps[index] = metadata_map(img, &vol, physical as u16, files)?;
        }
    }
    if let Some(Map::Unreadable(reason)) = vol.maps.get(fsd.part as usize) {
        return Err(Stop::Bad(reason));
    }
    Ok(vol)
}

/// The map of a metadata partition over the plain partition `physical`, from
/// the File Entry of its metadata file, or of the mirror when that one cannot
/// be read, as the Linux kernel does.
fn metadata_map(
    img: &mut dyn Image,
    vol: &Volume,
    physical: u16,
    files: [u32; 2],
) -> Result<Map, LimitHit> {
    for (lbn, file_type) in files
        .into_iter()
        .zip([FILE_TYPE_METADATA, FILE_TYPE_METADATA_MIRROR])
    {
        let addr = Addr {
            lbn,
            part: physical,
        };
        let Some(fe) = vol.at(addr) else {
            continue;
        };
        let fe_head = img.read(fe, FE_READ)?.into_owned();
        let Some(layout) = layout(img, vol, fe, physical, &fe_head, file_type)? else {
            continue;
        };
        let mut start = 0;
        let runs = layout
            .runs
            .into_iter()
            .map(|r| {
                let s = start;
                start += r.len;
                (s, r)
            })
            .collect();
        return Ok(Map::Metadata(runs));
    }
    Ok(Map::Unreadable(
        "UDF metadata partition: neither its metadata file nor the mirror could be read",
    ))
}

/// One allocation descriptor: where an extent is and whether its bytes were
/// actually written.
struct Extent {
    kind: u32,
    length: u32,
    addr: Addr,
}

/// Read a File Entry's allocation descriptors, following continuations.
/// `part` is the partition the entry is recorded in, which a short_ad's
/// position refers to; a long_ad names its own. `None` when the descriptors use
/// a form exav does not read. The flag is false when a cap, or a continuation
/// in a partition the walk cannot follow, stopped the list before its end.
fn extents(
    img: &mut dyn Image,
    vol: &Volume,
    part: u16,
    ad_kind: u16,
    ad_area: u64,
    ad_len: u64,
) -> Result<Option<(Vec<Extent>, bool)>, LimitHit> {
    let size = match ad_kind {
        AD_SHORT => 8,
        AD_LONG => 16,
        _ => return Ok(None),
    };
    let mut out = Vec::new();
    let (mut area, mut len) = (ad_area, ad_len);
    let mut ad_bytes = MAX_AD_BYTES;
    // Bounded because a malformed continuation can point back at itself.
    for _ in 0..MAX_EXTENTS {
        let span = len.min(ad_bytes);
        ad_bytes -= span;
        let ads = img.read(area, span as usize)?;
        let mut consumed = 0u64;
        let mut next: Option<(Addr, u64)> = None;
        while consumed + size <= span {
            if out.len() == MAX_EXTENTS {
                return Ok(Some((out, false)));
            }
            let o = consumed as usize;
            consumed += size;
            let raw_len = le_u32(&ads, o);
            let kind = raw_len >> 30;
            let length = raw_len & 0x3FFF_FFFF;
            let addr = Addr {
                lbn: le_u32(&ads, o + 4),
                part: if ad_kind == AD_LONG {
                    le_u16(&ads, o + 8)
                } else {
                    part
                },
            };
            if kind == EXTENT_CONTINUATION {
                next = Some((addr, length as u64));
                break;
            }
            if length == 0 {
                continue;
            }
            out.push(Extent { kind, length, addr });
        }
        match next {
            // The continuation extent begins with its own tag; the descriptors
            // follow it.
            Some((addr, l)) => {
                let Some(off) = vol.at(addr) else {
                    return Ok(Some((out, false)));
                };
                area = off.saturating_add(24);
                len = l.saturating_sub(24);
            }
            None => return Ok(Some((out, span == len))),
        }
    }
    Ok(Some((out, false)))
}

/// A stretch of a file's bytes: `len` bytes at image offset `at`, or `len`
/// zeroes where the extent was allocated but never written.
struct Run {
    at: Option<u64>,
    len: u64,
}

/// Where a File Entry's bytes lie.
struct Layout {
    runs: Vec<Run>,
    size: u64,
    /// False when a cap stopped the extent list before its end.
    complete: bool,
}

/// Where a File Entry's allocation descriptors start, and how many bytes of them
/// there are. The Extended File Entry puts the two lengths 40 bytes later.
fn ad_area(fe_head: &[u8], fe: u64) -> (u64, u64) {
    let extended = le_u16(fe_head, 0) == TAG_EXTENDED_FILE_ENTRY;
    let base = if extended { 208 } else { 168 };
    let ea_len = le_u32(fe_head, base) as u64;
    let ad_len = le_u32(fe_head, base + 4) as u64;
    (fe + base as u64 + 8 + ea_len, ad_len)
}

/// The **absolute sector** of a file's first recorded extent, used to recognise a
/// file the ISO 9660 walk already emitted. That walk keys on the ISO LBA, so the
/// partition-relative logical block has to be resolved to the same address space
/// or every bridged file would be emitted twice. `None` for a file stored inside
/// its own entry, which has no extent to share.
fn first_extent_sector(
    img: &mut dyn Image,
    vol: &Volume,
    fe: u64,
    part: u16,
    fe_head: &[u8],
    ad_kind: u16,
) -> Result<Option<u64>, LimitHit> {
    if ad_kind == AD_IN_ICB {
        return Ok(None);
    }
    let (ad_area, ad_len) = ad_area(fe_head, fe);
    let Some((exts, _)) = extents(img, vol, part, ad_kind, ad_area, ad_len)? else {
        return Ok(None);
    };
    Ok(exts
        .into_iter()
        .find(|e| e.kind == EXTENT_RECORDED)
        .and_then(|e| vol.at(e.addr))
        .map(|at| at / SECTOR))
}

/// Where the bytes of the file or directory whose File Entry is at image offset
/// `fe`, in partition `part`, lie. `None` when the entry is not of the expected
/// type or cannot be read; the caller has already decided whether that is worth
/// reporting.
fn layout(
    img: &mut dyn Image,
    vol: &Volume,
    fe: u64,
    part: u16,
    fe_head: &[u8],
    want_type: u8,
) -> Result<Option<Layout>, LimitHit> {
    let tag = le_u16(fe_head, 0);
    if tag != TAG_FILE_ENTRY && tag != TAG_EXTENDED_FILE_ENTRY {
        return Ok(None);
    }
    if fe_head.get(16 + 11).copied() != Some(want_type) {
        return Ok(None);
    }
    let info_len = le_u64(fe_head, 56);
    let ad_kind = le_u16(fe_head, 16 + 18) & 7;
    let (ad_area, ad_len) = ad_area(fe_head, fe);

    if ad_kind == AD_IN_ICB {
        // The bytes sit where the descriptors would be.
        let n = ad_len.min(info_len);
        if ad_area.saturating_add(n) > img.len() {
            return Ok(None);
        }
        return Ok(Some(Layout {
            runs: vec![Run {
                at: Some(ad_area),
                len: n,
            }],
            size: n,
            complete: true,
        }));
    }

    let Some((exts, complete)) = extents(img, vol, part, ad_kind, ad_area, ad_len)? else {
        return Ok(None);
    };
    let mut runs = Vec::new();
    let mut size = 0u64;
    'extents: for e in exts {
        if size >= info_len {
            break;
        }
        let want = (e.length as u64).min(info_len - size);
        if e.kind != EXTENT_RECORDED {
            // Allocated but never written: it reads as zeroes on the victim's
            // machine too, so there is nothing hidden here.
            runs.push(Run {
                at: None,
                len: want,
            });
            size += want;
            continue;
        }
        // Several pieces when the extent is in a metadata partition whose file
        // is itself split.
        let Some(pieces) = vol.locate(e.addr, want) else {
            return Ok(None);
        };
        for piece in pieces {
            // A piece running past the end means the image is truncated: the
            // declared bytes are absent rather than hidden, and what exists is
            // still scanned.
            if piece
                .at
                .is_some_and(|at| at.saturating_add(piece.len) > img.len())
            {
                break 'extents;
            }
            size += piece.len;
            runs.push(piece);
        }
    }
    Ok(Some(Layout {
        runs,
        size,
        complete,
    }))
}

/// Copy a file's runs out of the image. The caller bounds their total.
fn read_runs(img: &mut dyn Image, runs: &[Run]) -> Result<Vec<u8>, LimitHit> {
    let mut out = Vec::new();
    for r in runs {
        match r.at {
            None => out.resize(out.len() + r.len as usize, 0),
            Some(at) => out.extend_from_slice(&img.read(at, r.len as usize)?),
        }
    }
    Ok(out)
}

/// A file's runs read in order, for the streamed walk.
struct RunReader<'a> {
    img: &'a mut dyn Image,
    runs: std::vec::IntoIter<Run>,
    cur: Option<Run>,
}

impl Read for RunReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match &mut self.cur {
                Some(run) if run.len > 0 => {
                    let want = (buf.len() as u64).min(run.len) as usize;
                    let n = match run.at {
                        None => {
                            buf[..want].fill(0);
                            want
                        }
                        Some(at) => {
                            let got = self
                                .img
                                .read(at, want)
                                .map_err(|e| io::Error::other(e.reason))?;
                            buf[..got.len()].copy_from_slice(&got);
                            run.at = Some(at + got.len() as u64);
                            got.len()
                        }
                    };
                    // A source that ended early: the rest of the file is absent.
                    if n == 0 {
                        return Ok(0);
                    }
                    run.len -= n as u64;
                    return Ok(n);
                }
                _ => match self.runs.next() {
                    Some(run) => self.cur = Some(run),
                    None => return Ok(0),
                },
            }
        }
    }
}

/// Something the walk found.
enum Item {
    File {
        path: String,
        size: u64,
        runs: Vec<Run>,
    },
    /// Content that exists in the image and that the walk could not reach.
    Unreadable {
        path: String,
        size: u64,
        reason: &'static str,
    },
}

/// Receives each [`Item`] with the image it lies in; `Some` stops the walk.
type Emit<'e, T> = &'e mut dyn FnMut(&mut dyn Image, Item) -> Result<Option<T>, LimitHit>;

/// A file or directory found in the tree.
struct Node {
    name: String,
    icb: Addr,
}

/// Walk the UDF tree, handing every file, and everything that could not be
/// read, to `sink`. `max_dir` bounds the bytes of one directory held at once.
fn walk<T>(
    img: &mut dyn Image,
    max_dir: u64,
    seen_extents: &mut HashSet<u64>,
    sink: Emit<'_, T>,
) -> Result<Option<T>, LimitHit> {
    macro_rules! emit {
        ($item:expr) => {
            if let Some(t) = sink(&mut *img, $item)? {
                return Ok(Some(t));
            }
        };
    }
    let unreadable =
        |path: String, size: u64, reason: &'static str| Item::Unreadable { path, size, reason };

    let vol = match volume(img) {
        Ok(v) => v,
        Err(Stop::Io(e)) => return Err(e),
        // The image says it is UDF; failing to read its structures leaves
        // every file in it unexamined, which must not pass quietly.
        Err(Stop::Bad(reason)) => {
            return sink(img, unreadable("<udf-volume>".to_string(), 0, reason));
        }
    };

    let fsd = match vol.at(vol.fsd) {
        Some(at) => img.read(at, 410)?.into_owned(),
        None => Vec::new(),
    };
    if le_u16(&fsd, 0) != TAG_FILE_SET {
        return sink(
            img,
            unreadable(
                "<udf-volume>".to_string(),
                0,
                "UDF file set descriptor is not where the volume says it is",
            ),
        );
    }
    // `RootDirectoryICB` is a long_ad at offset 400.
    let root = Addr {
        lbn: le_u32(&fsd, 400 + 4),
        part: le_u16(&fsd, 400 + 8),
    };

    let mut queue = vec![Node {
        name: String::new(),
        icb: root,
    }];
    let mut walked = 0usize;
    let mut visited_icbs: HashSet<Addr> = HashSet::new();

    while let Some(dir) = queue.pop() {
        walked += 1;
        if walked > MAX_DIRS {
            emit!(unreadable(
                format!("<udf-directories-beyond-{MAX_DIRS}>"),
                0,
                "too many UDF directories to walk them all",
            ));
            break;
        }
        // A directory tree that loops back on itself would otherwise be walked
        // until the cap, hiding the rest of the image behind the budget.
        if !visited_icbs.insert(dir.icb) {
            continue;
        }
        let dir_layout = match vol.at(dir.icb) {
            Some(fe) => {
                let fe_head = img.read(fe, FE_READ)?.into_owned();
                layout(img, &vol, fe, dir.icb.part, &fe_head, FILE_TYPE_DIRECTORY)?
            }
            None => None,
        };
        let body = match dir_layout {
            Some(l) if l.size <= max_dir => {
                if !l.complete {
                    emit!(unreadable(
                        dir.name.clone(),
                        0,
                        "UDF directory has more extents than exav follows; \
                         the entries past them were not examined",
                    ));
                }
                read_runs(img, &l.runs)?
            }
            Some(_) => {
                emit!(unreadable(
                    dir.name.clone(),
                    0,
                    "UDF directory is larger than the buffer limit, so its \
                     contents were not examined",
                ));
                continue;
            }
            None => {
                // The directory's own extents could not be read, so everything
                // under it is invisible to this walk, not absent from the
                // image. Skipping quietly would hide a whole subtree.
                emit!(unreadable(
                    dir.name.clone(),
                    0,
                    "UDF directory could not be read, so its contents were not examined",
                ));
                continue;
            }
        };
        for child in read_fids(&body, &dir.name) {
            if child.is_dir {
                queue.push(Node {
                    name: child.path,
                    icb: child.icb,
                });
                continue;
            }
            let Some(fe) = vol.at(child.icb) else {
                emit!(unreadable(
                    child.path,
                    0,
                    "UDF file entry is in a partition exav cannot read",
                ));
                continue;
            };
            let fe_head = img.read(fe, FE_READ)?.into_owned();
            let tag = le_u16(&fe_head, 0);
            if tag != TAG_FILE_ENTRY && tag != TAG_EXTENDED_FILE_ENTRY {
                // The entry names an ICB that is not a file entry — a strategy
                // exav does not follow. The bytes are in the image; exav just
                // cannot find them.
                emit!(unreadable(
                    child.path,
                    0,
                    "UDF file entry uses an ICB strategy exav does not follow",
                ));
                continue;
            }
            let declared = le_u64(&fe_head, 56);
            let ad_kind = le_u16(&fe_head, 16 + 18) & 7;
            if ad_kind == AD_EXTENDED {
                emit!(unreadable(
                    child.path,
                    declared,
                    "UDF extended allocation descriptors are not read",
                ));
                continue;
            }
            // Deduplicate against the ISO 9660 walk of the same image: a bridge
            // image's two trees point at the same blocks.
            let part = child.icb.part;
            if let Some(s) = first_extent_sector(img, &vol, fe, part, &fe_head, ad_kind)? {
                if !seen_extents.insert(s) {
                    continue;
                }
            }
            let Some(l) = layout(img, &vol, fe, part, &fe_head, FILE_TYPE_FILE)? else {
                // The directory names this file, so it exists; its extents just
                // did not resolve. Report it rather than let the name vanish.
                emit!(unreadable(
                    child.path,
                    declared,
                    "UDF file content could not be read",
                ));
                continue;
            };
            let path = child.path;
            emit!(Item::File {
                path: path.clone(),
                size: l.size,
                runs: l.runs,
            });
            if !l.complete {
                emit!(unreadable(
                    path,
                    declared,
                    "UDF file has more extents than exav follows; the rest of it \
                     was not examined",
                ));
            }
        }
    }
    Ok(None)
}

/// The UDF tree of a seekable image, each file streamed from its runs. A no-op
/// when the image carries no UDF recognition sequence.
pub(crate) fn stream_udf<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: Visit<T>,
    seen_extents: &mut HashSet<u64>,
) -> Result<Option<T>, LimitHit> {
    let head = crate::read_at(source, 0, RECOGNITION_END)?;
    if !has_udf(&head) {
        return Ok(None);
    }
    let len = source
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("udf: {e}")))?;
    let max_dir = budget.limits.max_buffer_bytes;
    let mut img = Seekable { src: source, len };
    walk(&mut img, max_dir, seen_extents, &mut |img, item| {
        budget.count_entry()?;
        match item {
            Item::Unreadable { path, size, reason } => {
                let meta = MemberMeta {
                    name: path,
                    comp_size: size,
                    size: Some(size),
                    encrypted: false,
                    unsupported: Some(reason),
                };
                Ok(visit(&meta, None, budget))
            }
            Item::File { path, size, runs } => {
                let meta = MemberMeta {
                    name: path,
                    comp_size: size,
                    size: Some(size),
                    encrypted: false,
                    unsupported: None,
                };
                let mut reader = RunReader {
                    img,
                    runs: runs.into_iter(),
                    cur: None,
                };
                emit_stream(&meta, &mut reader, budget, &mut *visit)
            }
        }
    })
}

struct Fid {
    path: String,
    icb: Addr,
    is_dir: bool,
}

/// Walk the File Identifier Descriptors in a directory's bytes.
fn read_fids(dir: &[u8], parent: &str) -> Vec<Fid> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 38 <= dir.len() {
        if le_u16(dir, p) != TAG_FILE_IDENTIFIER {
            break;
        }
        let characteristics = dir.get(p + 18).copied().unwrap_or(0);
        let name_len = dir.get(p + 19).copied().unwrap_or(0) as usize;
        // The ICB field is a long_ad: extent length, then block and partition.
        let icb = Addr {
            lbn: le_u32(dir, p + 24),
            part: le_u16(dir, p + 28),
        };
        let impl_len = le_u16(dir, p + 36) as usize;
        let name_at = p + 38 + impl_len;
        let total = 38 + impl_len + name_len;

        // `..` carries no name and points back up the tree.
        if characteristics & FID_PARENT == 0 && name_len > 0 {
            if let Some(raw) = dir.get(name_at..name_at + name_len) {
                let name = decode_name(raw);
                let path = if parent.is_empty() {
                    name
                } else {
                    format!("{parent}/{name}")
                };
                out.push(Fid {
                    path,
                    icb,
                    is_dir: characteristics & FID_DIRECTORY != 0,
                });
            }
        }
        // Descriptors are padded to a four-byte boundary.
        let step = total.div_ceil(4) * 4;
        if step == 0 {
            break;
        }
        p += step;
    }
    out
}
