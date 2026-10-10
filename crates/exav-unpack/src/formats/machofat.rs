//! Mach-O universal ("fat") binary splitter.
//!
//! A fat binary concatenates several single-architecture Mach-O images behind a
//! small big-endian table of `(cputype, cpusubtype, offset, size, align)`
//! records. Malware ships fat binaries to carry, say, an x86_64 and an arm64
//! payload in one file; a scanner must look at every slice, because a detection
//! may only fire on one architecture's code. We carve each arch slice out as a
//! member so the engine re-dispatches it (each slice is itself a thin Mach-O, a
//! PE-carve target, a UPX stub, …).
//!
//! Header (all integers **big-endian**):
//!
//! ```text
//! u32 magic       0xCAFEBABE (FAT_MAGIC) | 0xCAFEBABF (FAT_MAGIC_64)
//! u32 nfat_arch   number of arch records
//! records, each:
//!   FAT_MAGIC    (20 bytes): u32 cputype, u32 cpusubtype, u32 offset, u32 size, u32 align
//!   FAT_MAGIC_64 (32 bytes): u32 cputype, u32 cpusubtype, u64 offset, u64 size, u32 align, u32 reserved
//! ```
//!
//! `0xCAFEBABE` is ALSO the Java `.class` magic, so detection is deliberately
//! strict: we only claim a fat binary when `nfat_arch` is small (`1..=64`), the
//! whole arch table is present, and every slice `[offset, offset+size)` lies
//! within the file. A `.class` file — whose bytes 4..8 are minor/major version
//! numbers and whose would-be "arch records" are constant-pool bytes — almost
//! never satisfies all three, so it is left to normal classification.
//!
//! Every field read is `get()`-guarded and every offset/size is validated
//! against the input length before slicing, so truncated or hostile input can
//! never panic or read out of bounds.

use crate::*;
use std::io::{Read, Seek, SeekFrom};

const FAT_MAGIC: u32 = 0xCAFE_BABE; // 32-bit arch records
const FAT_MAGIC_64: u32 = 0xCAFE_BABF; // 64-bit offset/size arch records

/// Upper bound on `nfat_arch`. Real universal binaries hold a handful of slices;
/// a large count is the tell of a `.class` file (or a crafted header) and is
/// rejected.
const MAX_ARCH: u32 = 64;

/// One validated architecture slice: byte range `[offset, offset+size)` known to
/// lie within the input.
struct Arch {
    offset: usize,
    size: usize,
}

/// Read a big-endian `u32` at `p`, `None` if out of bounds.
fn be_u32(data: &[u8], p: usize) -> Option<u32> {
    let b = crate::bytes::at(data, p, 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a big-endian `u64` at `p`, `None` if out of bounds.
fn be_u64(data: &[u8], p: usize) -> Option<u64> {
    let b = crate::bytes::at(data, p, 8)?;
    Some(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Parse and fully validate the fat header of a file of `total_len` bytes,
/// whose start is `data` (which must contain the whole arch table). Returns
/// the arch slices only when the input is a *plausible* universal binary (see
/// the module docs for the strictness rationale); returns `None` for anything
/// else, including a Java `.class` file that merely shares the `0xCAFEBABE`
/// magic.
fn parse_archs_len(data: &[u8], total_len: u64) -> Option<Vec<Arch>> {
    let magic = be_u32(data, 0)?;
    let is64 = match magic {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        _ => return None,
    };
    let nfat = be_u32(data, 4)?;
    if nfat == 0 || nfat > MAX_ARCH {
        return None;
    }
    let nfat = nfat as usize;
    let entry_size = if is64 { 32 } else { 20 };
    // The entire arch table must be present in the header we were given.
    let table_end = nfat.checked_mul(entry_size)?.checked_add(8)?;
    if table_end > data.len() {
        return None;
    }
    let len = total_len;
    let mut archs = Vec::with_capacity(nfat);
    for i in 0..nfat {
        let base = 8 + i * entry_size;
        // cputype (base+0) and cpusubtype (base+4) are not needed for carving.
        let (offset, size) = if is64 {
            (be_u64(data, base + 8)?, be_u64(data, base + 16)?)
        } else {
            (
                be_u32(data, base + 8)? as u64,
                be_u32(data, base + 12)? as u64,
            )
        };
        // Plausibility: the slice must lie wholly within the file. This is the
        // check that discriminates a real fat binary from a `.class` collision.
        let end = offset.checked_add(size)?;
        if offset > len || end > len {
            return None;
        }
        archs.push(Arch {
            offset: offset as usize,
            size: size as usize,
        });
    }
    Some(archs)
}

/// True when `data` is a plausible Mach-O universal binary (used by `detect`).
pub(crate) fn looks_like_machofat(p: &crate::Probe) -> bool {
    parse_archs_len(p.head, p.len as u64).is_some()
}

/// Walk a universal binary, each arch image streamed from where it lies.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let members = stream_offsets(&mut source)?;
    crate::stream::stream_stored(&mut source, budget, visit, members)
}

/// Parse arch slice offsets from a seekable source. The arch table is a bounded
/// header at the start; each arch image streams via seek+take. Returns
/// `(name, offset, size)` per arch, and none for an implausible fat binary
/// (a Java `.class` sharing the magic), which is then scanned as itself.
pub(crate) fn stream_offsets<R: Read + Seek>(
    source: &mut R,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let total_len = source
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("machofat: {e}")))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("machofat: {e}")))?;
    // The largest possible arch table: 8-byte header + MAX_ARCH * 32-byte records.
    let mut header = vec![0u8; 8 + MAX_ARCH as usize * 32];
    let n = crate::read_full(source, &mut header)?;
    header.truncate(n);
    let Some(archs) = parse_archs_len(&header, total_len) else {
        return Ok(Vec::new());
    };
    Ok(archs
        .iter()
        .enumerate()
        .map(|(i, a)| (format!("macho-arch-{i}"), a.offset as u64, a.size as u64))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 32-bit fat binary whose arch table points at `regions`, laid out
    /// contiguously right after the table.
    fn fat32(regions: &[&[u8]]) -> Vec<u8> {
        let n = regions.len();
        let table_end = 8 + n * 20;
        let mut offsets = Vec::new();
        let mut off = table_end;
        for r in regions {
            offsets.push(off);
            off += r.len();
        }
        let mut out = Vec::new();
        out.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        out.extend_from_slice(&(n as u32).to_be_bytes());
        for (i, r) in regions.iter().enumerate() {
            out.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
            out.extend_from_slice(&3u32.to_be_bytes()); // cpusubtype
            out.extend_from_slice(&(offsets[i] as u32).to_be_bytes());
            out.extend_from_slice(&(r.len() as u32).to_be_bytes());
            out.extend_from_slice(&12u32.to_be_bytes()); // align
        }
        for r in regions {
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn extracts_each_arch_slice() {
        let blob = fat32(&[b"first-arch-image", b"second::MALWARETEST::arch"]);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Machofat, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "macho-arch-0");
        assert_eq!(entries[0].data, b"first-arch-image");
        assert_eq!(entries[1].name, "macho-arch-1");
        assert!(entries
            .iter()
            .any(|e| e.data.windows(11).any(|w| w == b"MALWARETEST")));
    }

    #[test]
    fn java_class_is_not_misdetected() {
        // `.class`: CAFEBABE, then minor=0 / major=52 (Java 8) → nfat_arch reads
        // as 52, which is inside 1..=64 — the count check alone would pass. The
        // arch-table / offset-within-file checks must still reject it.
        let mut blob = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        blob.extend_from_slice(&[0xABu8; 200]); // constant pool: not valid arch records
        assert!(!looks_like_machofat(&crate::Probe::whole(&blob)));
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Machofat, &blob, &mut budget)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn truncated_and_garbage_do_not_panic() {
        let mut budget = Budget::new(Limits::default());
        // Too short for even the header.
        assert!(extract(Format::Machofat, b"\xCA\xFE", &mut budget)
            .unwrap()
            .is_empty());
        // Valid magic + count but a truncated arch table.
        let mut blob = FAT_MAGIC.to_be_bytes().to_vec();
        blob.extend_from_slice(&2u32.to_be_bytes());
        blob.extend_from_slice(&[0u8; 10]); // < 2 * 20 bytes of records
        assert!(extract(Format::Machofat, &blob, &mut budget)
            .unwrap()
            .is_empty());
        // Arch offset/size pointing past EOF must be rejected, not sliced.
        let mut blob = FAT_MAGIC.to_be_bytes().to_vec();
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes()); // cputype
        blob.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        blob.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // offset past EOF
        blob.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // size past EOF
        blob.extend_from_slice(&0u32.to_be_bytes()); // align
        assert!(extract(Format::Machofat, &blob, &mut budget)
            .unwrap()
            .is_empty());
    }
}
