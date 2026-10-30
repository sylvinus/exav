//! The directories of a TIFF-structured file (TIFF 6.0, the DNG
//! specification, Exif), read for the tags that locate a preview. Every
//! offset and count is checked against the data; the number of directories,
//! of entries and of values are capped, and a directory is read once.

/// Directories read from one file.
const MAX_IFDS: usize = 64;
/// How deep SubIFD and Exif pointers nest from the first directory.
const MAX_DEPTH: usize = 3;
/// Entries read from one directory.
const MAX_ENTRIES: usize = 1024;
/// SubIFD pointers followed from one tag.
const MAX_SUBIFDS: usize = 16;
/// Strips or tiles listed by one directory.
const MAX_CHUNKS: usize = 1 << 16;

/// The byte order and first directory of a TIFF-structured file.
#[derive(Clone, Copy, Debug)]
pub(super) struct Header {
    pub le: bool,
    /// 42 in a TIFF; the variants Olympus and Panasonic put there.
    pub magic: u16,
    pub first_ifd: usize,
}

fn u16_at(d: &[u8], at: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = d.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

fn u32_at(d: &[u8], at: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = d.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

/// The header at `data[0]`, whatever the magic number: the caller says which
/// are accepted.
pub(super) fn header(data: &[u8]) -> Option<Header> {
    let le = match data.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    Some(Header {
        le,
        magic: u16_at(data, 2, le)?,
        first_ifd: u32_at(data, 4, le)? as usize,
    })
}

/// The tags the readers use. Others are skipped.
mod tag {
    pub const SUBFILE_TYPE: u16 = 0xFE;
    pub const WIDTH: u16 = 0x100;
    pub const HEIGHT: u16 = 0x101;
    pub const BITS: u16 = 0x102;
    pub const COMPRESSION: u16 = 0x103;
    pub const PHOTOMETRIC: u16 = 0x106;
    pub const MAKE: u16 = 0x10F;
    pub const STRIP_OFFSETS: u16 = 0x111;
    pub const ORIENTATION: u16 = 0x112;
    pub const SAMPLES: u16 = 0x115;
    pub const STRIP_COUNTS: u16 = 0x117;
    pub const PLANAR: u16 = 0x11C;
    pub const SUB_IFDS: u16 = 0x14A;
    pub const TILE_OFFSETS: u16 = 0x144;
    pub const TILE_COUNTS: u16 = 0x145;
    pub const JPEG_OFFSET: u16 = 0x201;
    pub const JPEG_LENGTH: u16 = 0x202;
    pub const CFA_REPEAT_DIM: u16 = 0x828D;
    pub const CFA_PATTERN: u16 = 0x828E;
    pub const EXIF_IFD: u16 = 0x8769;
    pub const DNG_VERSION: u16 = 0xC612;
    pub const DNG_PRIVATE_DATA: u16 = 0xC634;
}

/// One directory, with the tags that matter.
#[derive(Clone, Debug, Default)]
pub(super) struct Ifd {
    pub subfile_type: Option<u32>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bits: Vec<u32>,
    pub compression: Option<u32>,
    pub photometric: Option<u32>,
    pub samples: Option<u32>,
    pub planar: Option<u32>,
    pub orientation: Option<u32>,
    /// Strips or tiles: offset and byte count of each.
    pub chunks: Vec<(u32, u32)>,
    /// The strips or tiles of this directory could not be listed.
    pub chunks_lost: bool,
    pub tiled: bool,
    /// JPEGInterchangeFormat and its length.
    pub jpeg: Option<(u32, u32)>,
    /// The first bytes of the Make string.
    pub make: Vec<u8>,
    /// Holds a colour filter array tag or the DNG version.
    pub cfa: bool,
    pub dng: bool,
    /// DNGPrivateData, which Sony also writes in its ARW and SR2 files.
    pub private_data: bool,
    /// Has a SubIFDs tag.
    pub sub_ifds: bool,
}

/// Every directory reached from the first.
#[derive(Debug)]
pub(super) struct Scan {
    pub le: bool,
    /// The first directory first.
    pub ifds: Vec<Ifd>,
}

/// Where the value of an entry is: inline in the entry, or at an offset.
struct Entry {
    tag: u16,
    typ: u16,
    count: u32,
    /// Offset of the entry's four value bytes.
    field: usize,
}

fn type_size(typ: u16) -> Option<usize> {
    Some(match typ {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 | 16 => 8,
        _ => return None,
    })
}

impl Entry {
    /// The value bytes, if they lie inside the data.
    fn bytes<'a>(&self, d: &'a [u8], le: bool) -> Option<&'a [u8]> {
        let size = type_size(self.typ)?.checked_mul(self.count as usize)?;
        let at = if size <= 4 {
            self.field
        } else {
            u32_at(d, self.field, le)? as usize
        };
        d.get(at..at.checked_add(size)?)
    }

    /// Up to `max` integers of a BYTE, SHORT or LONG entry; `None` when the
    /// entry has more or is of another type.
    fn ints(&self, d: &[u8], le: bool, max: usize) -> Option<Vec<u32>> {
        if self.count as usize > max {
            return None;
        }
        let b = self.bytes(d, le)?;
        Some(match self.typ {
            1 => b.iter().map(|&v| u32::from(v)).collect(),
            3 => b
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| {
                    u32::from(if le {
                        u16::from_le_bytes(c)
                    } else {
                        u16::from_be_bytes(c)
                    })
                })
                .collect(),
            4 | 13 => b
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&c| {
                    if le {
                        u32::from_le_bytes(c)
                    } else {
                        u32::from_be_bytes(c)
                    }
                })
                .collect(),
            _ => return None,
        })
    }

    fn int(&self, d: &[u8], le: bool) -> Option<u32> {
        self.ints(d, le, 1)?.first().copied()
    }
}

/// The directories of a TIFF-structured file whose header is `header`, from
/// the first one. A directory that cannot be read ends its own branch only.
pub(super) fn scan(data: &[u8], header: Header) -> Scan {
    let mut ifds: Vec<Ifd> = Vec::new();
    let mut seen: Vec<usize> = Vec::new();
    let mut todo = vec![(header.first_ifd, 0usize)];
    // Depth first, so that the first directory is first and a chain follows it.
    while let Some((at, depth)) = todo.pop() {
        if ifds.len() == MAX_IFDS {
            break;
        }
        if seen.contains(&at) {
            continue;
        }
        seen.push(at);
        let Some((ifd, next, pointers)) = read_ifd(data, header.le, at) else {
            continue;
        };
        ifds.push(ifd);
        // Pushed in reverse: the next directory of the chain is read before
        // what hangs off this one.
        if depth < MAX_DEPTH {
            for p in pointers.into_iter().rev() {
                todo.push((p, depth + 1));
            }
        }
        if next != 0 {
            todo.push((next as usize, depth));
        }
    }
    Scan {
        le: header.le,
        ifds,
    }
}

/// One directory at `at`: its tags, the offset of the next directory, and the
/// SubIFD and Exif directories it points to.
fn read_ifd(d: &[u8], le: bool, at: usize) -> Option<(Ifd, u32, Vec<usize>)> {
    let count = usize::from(u16_at(d, at, le)?);
    let entries_at = at.checked_add(2)?;
    // An entry table past the end of the data is as unreadable as one that
    // holds too many entries.
    if count > MAX_ENTRIES || entries_at.checked_add(count * 12)? > d.len() {
        return None;
    }
    let next = u32_at(d, entries_at + count * 12, le).unwrap_or(0);
    let mut ifd = Ifd::default();
    let mut pointers = Vec::new();
    let (mut offsets, mut counts): (Option<Vec<u32>>, Option<Vec<u32>>) = (None, None);
    let (mut tile_offsets, mut tile_counts): (Option<Vec<u32>>, Option<Vec<u32>>) = (None, None);
    let (mut jpeg_offset, mut jpeg_length) = (None, None);
    for k in 0..count {
        let e = entries_at + k * 12;
        let entry = Entry {
            tag: u16_at(d, e, le)?,
            typ: u16_at(d, e + 2, le)?,
            count: u32_at(d, e + 4, le)?,
            field: e + 8,
        };
        match entry.tag {
            tag::SUBFILE_TYPE => ifd.subfile_type = entry.int(d, le),
            tag::WIDTH => ifd.width = entry.int(d, le),
            tag::HEIGHT => ifd.height = entry.int(d, le),
            tag::BITS => ifd.bits = entry.ints(d, le, 8).unwrap_or_default(),
            tag::COMPRESSION => ifd.compression = entry.int(d, le),
            tag::PHOTOMETRIC => ifd.photometric = entry.int(d, le),
            tag::SAMPLES => ifd.samples = entry.int(d, le),
            tag::PLANAR => ifd.planar = entry.int(d, le),
            tag::ORIENTATION => ifd.orientation = entry.int(d, le),
            tag::MAKE => {
                if entry.typ == 2 {
                    ifd.make = entry
                        .bytes(d, le)
                        .map(|b| b.iter().take(32).copied().collect())
                        .unwrap_or_default();
                }
            }
            tag::STRIP_OFFSETS => {
                offsets = entry.ints(d, le, MAX_CHUNKS);
                ifd.chunks_lost |= offsets.is_none();
            }
            tag::STRIP_COUNTS => {
                counts = entry.ints(d, le, MAX_CHUNKS);
                ifd.chunks_lost |= counts.is_none();
            }
            tag::TILE_OFFSETS => {
                ifd.tiled = true;
                tile_offsets = entry.ints(d, le, MAX_CHUNKS);
                ifd.chunks_lost |= tile_offsets.is_none();
            }
            tag::TILE_COUNTS => {
                tile_counts = entry.ints(d, le, MAX_CHUNKS);
                ifd.chunks_lost |= tile_counts.is_none();
            }
            tag::JPEG_OFFSET => jpeg_offset = entry.int(d, le),
            tag::JPEG_LENGTH => jpeg_length = entry.int(d, le),
            tag::CFA_REPEAT_DIM | tag::CFA_PATTERN => ifd.cfa = true,
            tag::DNG_VERSION => ifd.dng = true,
            tag::DNG_PRIVATE_DATA => ifd.private_data = true,
            tag::SUB_IFDS => {
                ifd.sub_ifds = true;
                if let Some(v) = entry.ints(d, le, MAX_SUBIFDS) {
                    pointers.extend(v.into_iter().map(|p| p as usize));
                }
            }
            tag::EXIF_IFD => {
                if let Some(p) = entry.int(d, le) {
                    pointers.push(p as usize);
                }
            }
            _ => {}
        }
    }
    ifd.jpeg = jpeg_offset.zip(jpeg_length);
    let (offsets, counts) = if ifd.tiled {
        (tile_offsets, tile_counts)
    } else {
        (offsets, counts)
    };
    match (offsets, counts) {
        (Some(o), Some(c)) if o.len() == c.len() => ifd.chunks = o.into_iter().zip(c).collect(),
        // A single strip may leave its length out.
        (Some(o), None) if o.len() == 1 && !ifd.tiled => ifd.chunks = vec![(o[0], 0)],
        (None, None) => {}
        _ => ifd.chunks_lost = true,
    }
    Some((ifd, next, pointers))
}

/// The orientation (1 to 8) in the first directory of the TIFF structure
/// that starts at `data[0]`.
pub(super) fn orientation(data: &[u8]) -> Option<u8> {
    let h = header(data)?;
    if h.magic != 42 {
        return None;
    }
    let (ifd, _, _) = read_ifd(data, h.le, h.first_ifd)?;
    ifd.orientation
        .and_then(|o| u8::try_from(o).ok())
        .filter(|o| (1..=8).contains(o))
}
