//! RAR3 (unpack29) decompression CRC validation harness.
//!
//! For every RAR4-signature sample under `corpus/samples/_bulk/rar/*.bin` this
//! parses the RAR4 file blocks, decompresses each unpack29 LZ member through the
//! crate's `extract_rar`, and compares the output's CRC-32 against the
//! FILE_CRC stored in the file header.
//!
//! Run with: `cargo run -q -p exav-unpack --features rar5-crc-check --example rar3_check`
//!
//! These samples are LIVE MALWARE: they are only ever read and decompressed,
//! never executed.

use std::fs;
use std::path::Path;

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

/// (matched, mismatch, fail, stored, skipped_ppm_or_other)
fn check_archive(data: &[u8]) -> (u32, u32, u32, u32, u32) {
    let (mut matched, mut mismatch, mut fail, mut stored, mut skip) = (0, 0, 0, 0, 0);
    let mut pos = RAR4_MAGIC.len();
    while pos + 7 <= data.len() {
        let flags = match u16le(data, pos + 3) {
            Some(f) => f,
            None => break,
        };
        let head_size = match u16le(data, pos + 5) {
            Some(s) => s as usize,
            None => break,
        };
        let htype = data[pos + 2];
        if head_size < 7 {
            break;
        }
        let add_size = if flags & 0x8000 != 0 {
            u32le(data, pos + 7).unwrap_or(0) as u64
        } else {
            0
        };
        if htype == 0x7B {
            break;
        }
        if htype == 0x74 {
            let b = pos + 7;
            let pack = u32le(data, b).unwrap_or(0) as u64;
            let unp = u32le(data, b + 4).unwrap_or(0) as u64;
            let crc = u32le(data, b + 9).unwrap_or(0);
            let unp_ver = *data.get(b + 17).unwrap_or(&0);
            let method = *data.get(b + 18).unwrap_or(&0xff);
            let large = flags & 0x100 != 0;
            let (pack, unp) = if large {
                let hp = u32le(data, b + 25).unwrap_or(0) as u64;
                let hu = u32le(data, b + 29).unwrap_or(0) as u64;
                ((hp << 32) | pack, (hu << 32) | unp)
            } else {
                (pack, unp)
            };
            let is_dir = (flags & 0xE0) == 0xE0;
            let encrypted = flags & 0x04 != 0;
            let win_bits = (((flags & 0xE0) >> 5) as u32) + 16;
            let data_off = pos + head_size;
            if is_dir {
                // skip
            } else if method == 0x30 {
                stored += 1;
            } else if encrypted {
                skip += 1;
            } else if unp_ver == 29 && (0x31..=0x35).contains(&method) {
                let dend = (data_off + pack as usize).min(data.len());
                let packed = &data[data_off.min(data.len())..dend];
                let mut budget = exav_unpack::Budget::new(exav_unpack::Limits {
                    max_total_bytes: 2 * 1024 * 1024 * 1024,
                    max_entry_bytes: 512 * 1024 * 1024,
                    max_ratio: u64::MAX,
                    ..Default::default()
                });
                match exav_unpack::unpack29(packed, unp, win_bits, &mut budget) {
                    Ok(out) => {
                        if crc32(&out) == crc {
                            matched += 1;
                        } else {
                            mismatch += 1;
                        }
                    }
                    Err(_) => fail += 1,
                }
            } else {
                // older version (15/20/26) or PPMd-only — skipped
                skip += 1;
            }
            pos = data_off + add_size as usize;
        } else {
            pos += head_size + add_size as usize;
        }
        if add_size == 0 && head_size == 0 {
            break;
        }
    }
    (matched, mismatch, fail, stored, skip)
}

fn main() {
    let dir = Path::new("corpus/samples/_bulk/rar");
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("cannot read {}: {e}", dir.display());
            return;
        }
    };

    let (mut t_match, mut t_mis, mut t_fail, mut t_store, mut t_skip) = (0u32, 0, 0, 0, 0);
    let mut rar4_files = 0;
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().map(|e| e != "bin").unwrap_or(true) {
            continue;
        }
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.len() < 7 || &data[..7] != RAR4_MAGIC {
            continue;
        }
        rar4_files += 1;
        let (m, mis, f, s, sk) = check_archive(&data);
        t_match += m;
        t_mis += mis;
        t_fail += f;
        t_store += s;
        t_skip += sk;
        if mis > 0 || f > 0 {
            println!(
                "{}: match={m} MISMATCH={mis} fail={f} stored={s} skip={sk}",
                path.file_name().unwrap().to_string_lossy()
            );
        }
    }

    println!("\n=== RAR3 (unpack29) CRC validation summary ===");
    println!("RAR4 archives scanned : {rar4_files}");
    println!("compressed members OK : {t_match}");
    println!("CRC MISMATCH          : {t_mis}");
    println!("decode failures       : {t_fail}");
    println!("stored members        : {t_store}");
    println!("skipped (ppm/old/enc) : {t_skip}");
    let total = t_match + t_mis + t_fail;
    if total > 0 {
        println!(
            "CRC pass rate         : {:.1}% ({}/{})",
            100.0 * t_match as f64 / total as f64,
            t_match,
            total
        );
    }
}
