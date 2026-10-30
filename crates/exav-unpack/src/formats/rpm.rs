//! RPM packages: the install scripts and the payload.
//!
//! An RPM is a 96-byte lead, a signature header, the package's header (both
//! "header structures": a magic, an entry count, a size of data, the entries,
//! then the data) and the payload, a compressed cpio archive. The payload comes
//! out as one member, named for its format and compressor, which the scanner
//! opens in turn (gzip, xz, zstd, bzip2 or lzma, then cpio). The scripts that
//! run as root when a package is installed, removed or updated sit in the
//! header's data; each comes out as a member of its own, so signatures see them
//! as text. Integers are big-endian.
//!
//! Every count and offset is checked against the file before it is used; the
//! header data is read whole, up to a fixed bound.

use crate::*;
use std::io::{Read, Seek, SeekFrom};

const LEAD: u64 = 96;
const HEADER_MAGIC: [u8; 4] = [0x8E, 0xAD, 0xE8, 0x01];
/// Signature type of a lead that is followed by a signature header.
const HEADER_SIGNATURE: u16 = 5;
/// The most entries a header may have (rpm's own bound).
const MAX_ENTRIES: u32 = 0xFFFF;
/// The most data a header is read with. Real packages have a few megabytes at
/// most (a kernel's file list).
const MAX_DATA: u32 = 64 << 20;
/// The most strings of one script array taken (triggers).
const MAX_STRINGS: u32 = 4096;
/// The most script members of a package.
const MAX_SCRIPTS: usize = 4096;

const TAG_PAYLOAD_FORMAT: u32 = 1124;
const TAG_PAYLOAD_COMPRESSOR: u32 = 1125;
const STRING: u32 = 6;
const STRING_ARRAY: u32 = 8;

/// Header tags whose value is a script, and the member each is given.
const SCRIPTS: &[(u32, &str)] = &[
    (1023, "scripts/prein"),
    (1024, "scripts/postin"),
    (1025, "scripts/preun"),
    (1026, "scripts/postun"),
    (1079, "scripts/verify"),
    (1151, "scripts/pretrans"),
    (1152, "scripts/posttrans"),
    (5020, "scripts/preuntrans"),
    (5021, "scripts/postuntrans"),
    (1065, "scripts/trigger"),
    (5016, "scripts/filetrigger"),
    (5026, "scripts/transfiletrigger"),
];

struct Entry {
    tag: u32,
    kind: u32,
    offset: u32,
    count: u32,
}

/// A header structure: its entries, its data and where it ends.
struct Header {
    entries: Vec<Entry>,
    data: Vec<u8>,
    /// Where the data starts in the file.
    data_at: u64,
    end: u64,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn read_at<R: Read + Seek>(r: &mut R, at: u64, n: usize) -> Result<Vec<u8>, LimitHit> {
    let mut out = vec![0u8; n];
    r.seek(SeekFrom::Start(at))
        .and_then(|_| r.read_exact(&mut out))
        .map_err(|e| LimitHit::corrupt(format!("rpm: {e}")))?;
    Ok(out)
}

fn read_header<R: Read + Seek>(r: &mut R, at: u64, total: u64) -> Result<Header, LimitHit> {
    let h = read_at(r, at, 16)?;
    if h[..4] != HEADER_MAGIC {
        return Err(LimitHit::corrupt(
            "rpm: no header structure where one belongs".to_string(),
        ));
    }
    let (count, size) = (be32(&h, 8), be32(&h, 12));
    if count > MAX_ENTRIES || size > MAX_DATA {
        return Err(LimitHit::corrupt(
            "rpm: header counts past the limits".to_string(),
        ));
    }
    // Nothing is allocated for a count the file is too short to hold.
    let data_at = at + 16 + u64::from(count) * 16;
    if data_at + u64::from(size) > total {
        return Err(LimitHit::corrupt("rpm: header cut short".to_string()));
    }
    let table = read_at(r, at + 16, count as usize * 16)?;
    let entries = table
        .as_chunks::<16>()
        .0
        .iter()
        .map(|e| Entry {
            tag: be32(e, 0),
            kind: be32(e, 4),
            offset: be32(e, 8),
            count: be32(e, 12),
        })
        .collect();
    Ok(Header {
        entries,
        data: read_at(r, data_at, size as usize)?,
        data_at,
        end: data_at + u64::from(size),
    })
}

impl Header {
    /// The NUL-terminated string at `offset` of the data, `(offset, length)`.
    fn string_at(&self, offset: usize) -> Option<(usize, usize)> {
        let rest = self.data.get(offset..)?;
        Some((offset, rest.iter().position(|&b| b == 0)?))
    }

    fn string_of(&self, tag: u32) -> Option<&str> {
        let e = self
            .entries
            .iter()
            .find(|e| e.tag == tag && e.kind == STRING)?;
        let (at, n) = self.string_at(e.offset as usize)?;
        std::str::from_utf8(&self.data[at..at + n]).ok()
    }
}

/// The name of the payload: what it is (`cpio`) and how it is compressed.
fn payload_name(h: &Header) -> String {
    let format = match h.string_of(TAG_PAYLOAD_FORMAT) {
        Some("cpio") | None => ".cpio",
        Some(_) => "",
    };
    let compressor = match h.string_of(TAG_PAYLOAD_COMPRESSOR) {
        Some("gzip") => ".gz",
        Some("bzip2") => ".bz2",
        Some("xz") => ".xz",
        Some("lzma") => ".lzma",
        Some("zstd") => ".zst",
        _ => "",
    };
    format!("payload{format}{compressor}")
}

/// Walk a package: its scripts, then its payload, each read from where it lies.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let members = stream_offsets(&mut source)?;
    crate::stream::stream_stored(&mut source, budget, visit, members)
}

pub(crate) fn stream_offsets<R: Read + Seek>(
    source: &mut R,
) -> Result<Vec<crate::stream::Region>, LimitHit> {
    use crate::stream::Region;
    let total = source
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("rpm: {e}")))?;
    let lead = read_at(source, 0, LEAD as usize)?;
    if u16::from_be_bytes([lead[78], lead[79]]) != HEADER_SIGNATURE {
        // RPM 2's signature is a bare block that is not read here.
        return Ok(vec![Region::Unwalked(
            "rpm".into(),
            "an RPM of the old kind, with no signature header",
        )]);
    }
    let signature = read_header(source, LEAD, total)?;
    // The package header follows the signature header, from the next multiple of 8.
    let header = read_header(source, signature.end.next_multiple_of(8), total)?;

    let mut regions = Vec::new();
    'scripts: for &(tag, name) in SCRIPTS {
        for e in header.entries.iter().filter(|e| e.tag == tag) {
            let strings = match e.kind {
                STRING => 1,
                STRING_ARRAY => e.count.min(MAX_STRINGS),
                _ => continue,
            };
            let mut at = e.offset as usize;
            for i in 0..strings {
                // Entries may share their strings: the members are bounded
                // here, before anything is built for each.
                if regions.len() >= MAX_SCRIPTS {
                    regions.push(Region::Unwalked(
                        "scripts".into(),
                        "an RPM with more scripts than exav lists",
                    ));
                    break 'scripts;
                }
                let Some((start, n)) = header.string_at(at) else {
                    break;
                };
                if n > 0 {
                    let name = if e.kind == STRING {
                        name.to_string()
                    } else {
                        format!("{name}/{i}")
                    };
                    regions.push(Region::Member(
                        name,
                        header.data_at + start as u64,
                        n as u64,
                    ));
                }
                at = start + n + 1;
            }
        }
    }
    if header.end < total {
        regions.push(Region::Member(
            payload_name(&header),
            header.end,
            total - header.end,
        ));
    }
    Ok(regions)
}
