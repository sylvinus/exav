//! RAR3 (unpack29) PPMd decompression tests.
//!
//! Fixtures are libarchive's BSD-2-Clause RAR test files (the same upstream this
//! crate ports for RAR3/RAR5 LZ):
//!
//! * `ppmd_lzss_conversion.rar` — a real RAR3 PPMd member that repeatedly
//!   switches between PPMd and LZSS mid-stream. Its stored FILE_CRC gives a
//!   byte-exact oracle for the whole decoder (model + RAR range coder + framing
//!   + escape handling + PPMd↔LZSS conversion + solid continuation). It unpacks
//!     to ~241 MB, so the byte-exact check is `#[ignore]`d by default; run it with
//!     `cargo test -p exav-unpack --no-default-features -- --ignored`.
//! * `ppmd_use_after_free*.rar` — crafted malformed PPMd inputs (libarchive
//!   crash-test corpus); they must fail gracefully without panicking.

use exav_unpack::{unpack29, Budget, Limits};

const RAR4_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

/// One RAR4 compressed file member: (packed, declared unpacked size, FILE_CRC,
/// window log2 bits).
struct Member {
    packed: Vec<u8>,
    unp: u64,
    crc: u32,
    win_bits: u32,
}

/// Parse the (single) compressed file member out of a RAR4 archive.
fn first_compressed_member(data: &[u8]) -> Option<Member> {
    if data.len() < 7 || &data[..7] != RAR4_MAGIC {
        return None;
    }
    let mut pos = 7usize;
    while pos + 7 <= data.len() {
        let flags = u16le(data, pos + 3)?;
        let head_size = u16le(data, pos + 5)? as usize;
        let htype = data[pos + 2];
        if head_size < 7 {
            break;
        }
        let add_size = if flags & 0x8000 != 0 {
            u32le(data, pos + 7).unwrap_or(0) as u64
        } else {
            0
        };
        if htype == 0x74 {
            let b = pos + 7;
            let pack = u32le(data, b).unwrap_or(0) as u64;
            let unp = u32le(data, b + 4).unwrap_or(0) as u64;
            let crc = u32le(data, b + 9).unwrap_or(0);
            let method = *data.get(b + 18).unwrap_or(&0xff);
            let win_bits = (((flags & 0xE0) >> 5) as u32) + 16;
            let data_off = pos + head_size;
            if method != 0x30 {
                let dend = (data_off + pack as usize).min(data.len());
                return Some(Member {
                    packed: data[data_off.min(data.len())..dend].to_vec(),
                    unp,
                    crc,
                    win_bits,
                });
            }
            pos = data_off + add_size as usize;
        } else {
            pos += head_size + add_size as usize;
        }
        if head_size == 0 && add_size == 0 {
            break;
        }
    }
    None
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/rar/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Byte-exact end-to-end validation of the RAR3 PPMd decoder against a real
/// RAR3 PPMd member (PPMd↔LZSS conversion), checked against the archive's
/// stored CRC-32. Heavy (~241 MB output); ignored by default.
#[test]
#[ignore = "decodes ~241 MB; run with --ignored"]
fn ppmd_lzss_conversion_crc() {
    let data = fixture("ppmd_lzss_conversion.rar");
    let m = first_compressed_member(&data).expect("compressed member");
    let mut budget = Budget::new(Limits {
        max_total_bytes: 1 << 31, // 2 GiB
        max_entry_bytes: 1 << 30, // 1 GiB
        max_ratio: u64::MAX,
        max_files: 1000,
        ..Default::default()
    });
    let out = unpack29(&m.packed, m.unp, m.win_bits, &mut budget).expect("decode");
    assert_eq!(out.len() as u64, m.unp, "decoded length");
    assert_eq!(crc32(&out), m.crc, "decoded CRC mismatch");
    // libarchive's reference tail assertion for this fixture.
    assert!(out.ends_with(b"</BODY>\n</HTML>"));
}
