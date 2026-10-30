//! decmpfs, the transparent compression macOS applies to files, decoded.
//!
//! A compressed file's data fork is empty. Its bytes are in the
//! `com.apple.decmpfs` attribute after a 16-byte header, or, for the types that
//! do not fit there, in the file's resource fork (an attribute of its own on
//! APFS, `com.apple.ResourceFork`). Both filesystems keep the same attribute
//! and the same fork, so one decoder serves `formats/hfsplus` and
//! `formats/apfs`.
//!
//! The header is little-endian: `cmpf`, the type, the uncompressed size. The
//! types and their layouts are the ones libarchive (zlib) and apfs-fuse
//! (the rest) read; Apple documents type 1 only.
//!
//! ```text
//! type  codec   payload
//!    1  none    attribute, as is
//!    3  zlib    attribute (a first byte of 0xFF marks stored bytes)
//!    7  LZVN    attribute (a first byte of 0x06 marks stored bytes)
//!    9  none    attribute, behind a 0xCC byte
//!   11  LZFSE   attribute
//!    4  zlib    resource fork: a table of (offset, length) per block
//!    8  LZVN    resource fork: a table of block offsets
//!   10  none    resource fork: as 8, a marker byte before each block
//!   12  LZFSE   resource fork: as 8
//! ```
//!
//! A file is cut in blocks of 64 KiB, each coded alone. Types 13 and 14
//! (LZBITMAP) and the dataless types, whose content is not on the volume,
//! are reported.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use super::vol::{Got, be32, le32, le64};

/// The attribute holding the header, and on APFS the one holding the fork.
pub(crate) const ATTR: &str = "com.apple.decmpfs";
pub(crate) const RESOURCE_FORK_ATTR: &str = "com.apple.ResourceFork";

/// The file flag (`UF_COMPRESSED`) that marks a compressed file. macOS reads
/// the attribute only where it is set, so it decides here too.
pub(crate) const COMPRESSED_FLAG: u32 = 0x20;

const MAGIC: u32 = 0x636d_7066; // "cmpf"
const HEADER: usize = 16;
const BLOCK: usize = 0x1_0000;

/// The header of a `com.apple.decmpfs` attribute.
pub(crate) struct Header {
    pub(crate) kind: u32,
    /// The size of the file once decompressed.
    pub(crate) size: u64,
}

pub(crate) fn header(attr: &[u8]) -> Option<Header> {
    (attr.len() >= HEADER && le32(attr, 0) == MAGIC).then(|| Header {
        kind: le32(attr, 4),
        size: le64(attr, 8),
    })
}

/// Whether a type keeps its bytes in the resource fork.
pub(crate) fn in_fork(kind: u32) -> bool {
    matches!(kind, 4 | 8 | 10 | 12 | 14)
}

/// The bytes of the file `attr` describes, at most `cap` of them. `fork` is
/// its resource fork, wanted by the types that keep their bytes there.
pub(crate) fn unpack(attr: &[u8], fork: Option<&[u8]>, cap: u64) -> Got<'static> {
    let Some(h) = header(attr) else {
        return Got::Why("compressed file (decmpfs) with a damaged attribute");
    };
    if h.size > cap {
        return Got::Big(h.size);
    }
    let size = crate::bytes::to_usize(h.size);
    let payload = attr.get(HEADER..).unwrap_or_default();
    if in_fork(h.kind) && fork.is_none() {
        return Got::Why("compressed file (decmpfs) whose resource fork is missing");
    }
    let fork = fork.unwrap_or_default();
    let out = match h.kind {
        1 => Some(payload.to_vec()),
        3 => zlib(payload, size),
        7 => lzvn(payload, size),
        9 => stored(payload, 0xCC),
        11 => lzfse(payload, size),
        4 => zlib_fork(fork, size),
        8 | 10 | 12 => offset_fork(h.kind, fork, size),
        _ => return Got::Why("compressed file (decmpfs) of a type exav does not read"),
    };
    match out {
        Some(bytes) if bytes.len() == size => Got::Whole(bytes),
        _ => Got::Why("compressed file (decmpfs) that did not decompress"),
    }
}

fn blocks(size: usize) -> usize {
    size.div_ceil(BLOCK)
}

/// The uncompressed length of block `k`, short only for the last.
fn block_len(size: usize, k: usize) -> usize {
    size.saturating_sub(k.saturating_mul(BLOCK)).min(BLOCK)
}

/// A block's coded bytes, none longer than a stored block (a marker and 64 KiB).
fn slice(fork: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    if len > BLOCK.saturating_add(1) {
        return None;
    }
    crate::bytes::at(fork, start, len)
}

/// Type 4: zlib blocks. The fork opens with the big-endian offset of its
/// resource data, which opens with a block count and a table of
/// (offset, length) pairs, both little-endian and from the count's place.
fn zlib_fork(fork: &[u8], size: usize) -> Option<Vec<u8>> {
    let table = crate::bytes::to_usize(u64::from(be32(fork, 0))).checked_add(4)?;
    let count = crate::bytes::to_usize(u64::from(le32(fork, table)));
    if count != blocks(size) {
        return None;
    }
    let mut out = Vec::with_capacity(crate::cap_prealloc(size));
    for k in 0..count {
        let entry = table.checked_add(4)?.checked_add(k.checked_mul(8)?)?;
        let at = crate::bytes::to_usize(u64::from(le32(fork, entry)));
        let len = crate::bytes::to_usize(u64::from(le32(fork, entry.checked_add(4)?)));
        let block = slice(fork, table.checked_add(at)?, len)?;
        out.extend_from_slice(&zlib(block, block_len(size, k))?);
    }
    Some(out)
}

/// Types 8, 10 and 12: the fork opens with the offsets of its blocks, one more
/// than there are blocks, each block running to the next offset.
fn offset_fork(kind: u32, fork: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(crate::cap_prealloc(size));
    for k in 0..blocks(size) {
        let at = k.checked_mul(4)?;
        let start = crate::bytes::to_usize(u64::from(le32(fork, at)));
        let end = crate::bytes::to_usize(u64::from(le32(fork, at.checked_add(4)?)));
        let block = slice(fork, start, end.checked_sub(start)?)?;
        let want = block_len(size, k);
        out.extend_from_slice(&match kind {
            8 => lzvn(block, want)?,
            10 => block.get(1..)?.to_vec(),
            _ => lzfse(block, want)?,
        });
    }
    Some(out)
}

/// zlib, or stored bytes behind a first byte whose low nibble is 0xF, which
/// no zlib stream opens with.
fn zlib(data: &[u8], size: usize) -> Option<Vec<u8>> {
    if data.first()? & 0x0f == 0x0f {
        return Some(data.get(1..)?.to_vec());
    }
    let s = crate::salvage(crate::inflate::zlib_body(data)?, size as u64);
    (!s.over_cap).then_some(s.data)
}

/// LZVN, or stored bytes behind 0x06, which is the end opcode and so opens no
/// coded block.
fn lzvn(data: &[u8], size: usize) -> Option<Vec<u8>> {
    if *data.first()? == 0x06 {
        return Some(data.get(1..)?.to_vec());
    }
    let s = super::lzfse::decode_lzvn(data, size as u64);
    (!s.over_cap && !s.undecoded && !s.cut_short).then_some(s.data)
}

fn lzfse(data: &[u8], size: usize) -> Option<Vec<u8>> {
    let s = super::lzfse::decode(data, size as u64);
    (!s.over_cap && !s.undecoded && !s.cut_short).then_some(s.data)
}

fn stored(data: &[u8], marker: u8) -> Option<Vec<u8>> {
    (*data.first()? == marker).then(|| data[1..].to_vec())
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::io::Write;

    fn attr(kind: u32, size: usize, payload: &[u8]) -> Vec<u8> {
        let mut a = b"fpmc".to_vec();
        a.extend_from_slice(&kind.to_le_bytes());
        a.extend_from_slice(&(size as u64).to_le_bytes());
        a.extend_from_slice(payload);
        a
    }

    fn deflated(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    fn lzfsed(data: &[u8]) -> Vec<u8> {
        let mut enc = Vec::new();
        lzfse_rust::encode_bytes(data, &mut enc).unwrap();
        enc
    }

    /// `data` as LZVN literals and the end opcode, built without the decoder.
    fn lzvned(data: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        for c in data.chunks(271) {
            match c.len() {
                1..=15 => p.push(0xe0 | c.len() as u8),
                n => p.extend_from_slice(&[0xe0, (n - 16) as u8]),
            }
            p.extend_from_slice(c);
        }
        p.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        p
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| b"the quick brown fox "[i % 20] ^ (i / 997) as u8 & 3)
            .collect()
    }

    fn bytes(u: Got) -> Vec<u8> {
        match u {
            Got::Whole(b) => b,
            Got::Why(why) => panic!("{why}"),
            _ => panic!("not whole"),
        }
    }

    fn why(u: Got) -> &'static str {
        match u {
            Got::Why(why) => why,
            Got::Big(_) => "over",
            _ => "bytes",
        }
    }

    #[test]
    fn the_attribute_types_decode() {
        let data = text(3000);
        for (kind, payload) in [
            (1, data.clone()),
            (3, deflated(&data)),
            (3, [&[0xff][..], &data].concat()),
            (7, lzvned(&data)),
            (7, [&[0x06][..], &data].concat()),
            (9, [&[0xcc][..], &data].concat()),
            (11, lzfsed(&data)),
        ] {
            let a = attr(kind, data.len(), &payload);
            assert_eq!(bytes(unpack(&a, None, 1 << 20)), data, "type {kind}");
        }
    }

    #[test]
    fn the_fork_types_decode_over_several_blocks() {
        // Two blocks, the second short.
        let data = text(70_000);
        let (a, b) = data.split_at(BLOCK);

        // Type 4: the fork's header says where the table is (here 0x100).
        let blocks = [deflated(a), deflated(b)];
        let mut fork = vec![0u8; 0x104];
        fork[..4].copy_from_slice(&0x100u32.to_be_bytes());
        fork.extend_from_slice(&2u32.to_le_bytes());
        let mut at = 4 + 2 * 8;
        for blk in &blocks {
            fork.extend_from_slice(&(at as u32).to_le_bytes());
            fork.extend_from_slice(&(blk.len() as u32).to_le_bytes());
            at += blk.len();
        }
        for blk in &blocks {
            fork.extend_from_slice(blk);
        }
        let got = unpack(&attr(4, data.len(), &[]), Some(&fork), 1 << 20);
        assert_eq!(bytes(got), data, "type 4");

        // Types 8, 10, 12: offsets, then the blocks. (A block of literals
        // alone would be longer than a block; the first is stored instead.)
        for (kind, enc) in [
            (8, [[&[0x06][..], a].concat(), lzvned(b)]),
            (10, [[&[0][..], a].concat(), [&[0][..], b].concat()]),
            (12, [lzfsed(a), lzfsed(b)]),
        ] {
            let mut fork = Vec::new();
            let mut at = 12;
            for blk in &enc {
                fork.extend_from_slice(&(at as u32).to_le_bytes());
                at += blk.len();
            }
            fork.extend_from_slice(&(at as u32).to_le_bytes());
            for blk in &enc {
                fork.extend_from_slice(blk);
            }
            let got = unpack(&attr(kind, data.len(), &[]), Some(&fork), 1 << 20);
            assert_eq!(bytes(got), data, "type {kind}");
        }
    }

    #[test]
    fn what_cannot_be_decoded_is_reported_not_guessed() {
        let data = text(100);
        let z = deflated(&data);

        // Over the cap, before anything is decoded.
        let a = attr(3, data.len(), &z);
        assert!(matches!(unpack(&a, None, 99), Got::Big(100)));
        assert!(matches!(unpack(&a, None, 100), Got::Whole(_)));

        // A size the stream does not give, either way.
        for size in [99, 101] {
            let a = attr(3, size, &z);
            assert!(
                why(unpack(&a, None, 1 << 20)).contains("did not decompress"),
                "size {size}"
            );
        }
        // A cut stream, a wrong marker, a missing fork, a type not read.
        let cut = attr(3, data.len(), &z[..z.len() / 2]);
        assert!(why(unpack(&cut, None, 1 << 20)).contains("did not decompress"));
        let marker = attr(9, 3, &[0xcd, 1, 2, 3]);
        assert!(why(unpack(&marker, None, 1 << 20)).contains("did not decompress"));
        let no_fork = attr(8, 10, &[]);
        assert!(why(unpack(&no_fork, None, 1 << 20)).contains("resource fork is missing"));
        for kind in [13, 14, 0x8000_0001, 99] {
            let a = attr(kind, 10, &[]);
            let fork = [0u8; 64];
            assert!(
                why(unpack(&a, Some(&fork), 1 << 20)).contains("type exav does not read"),
                "type {kind}"
            );
        }
        // Not the header.
        assert!(why(unpack(b"cmpf", None, 1 << 20)).contains("damaged"));
        let mut a = attr(1, 3, b"abc");
        a[0] = b'x';
        assert!(why(unpack(&a, None, 1 << 20)).contains("damaged"));
    }

    #[test]
    fn a_table_that_points_outside_the_fork_is_damage_not_a_panic() {
        let data = text(70_000);
        for kind in [4, 8, 10, 12] {
            for fork in [
                vec![],
                vec![0xff; 40],
                0x100u32.to_be_bytes().to_vec(),
                [0u8; 300].to_vec(),
                u32::MAX.to_le_bytes().repeat(40),
            ] {
                let got = unpack(&attr(kind, data.len(), &[]), Some(&fork), 1 << 20);
                assert!(
                    why(got).contains("did not decompress"),
                    "type {kind}, fork of {} bytes",
                    fork.len()
                );
            }
        }
    }
}
