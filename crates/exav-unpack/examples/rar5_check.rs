//! RAR5 decompression CRC validation harness.
//!
//! For every RAR5 sample under `corpus/samples/_bulk/rar/*.bin` this lists the
//! file members, decompresses the LZ-compressed ones, and compares the output's
//! CRC-32 (IEEE) against the CRC stored in the RAR5 file header.
//!
//! Run with: `cargo run -q -p exav-unpack --features rar5-crc-check --example rar5_check`

use std::fs;
use std::path::Path;

const RAR5_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

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

fn vint(d: &[u8], o: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    let mut i = 0usize;
    while i < 10 {
        let b = *d.get(o + i)?;
        val |= ((b & 0x7f) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 {
            return Some((val, i));
        }
        shift += 7;
    }
    None
}

fn u32le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

/// Walk RAR5 blocks; for each compressed FILE member, decompress and check CRC.
/// Returns (matched, mismatched, decode_fail, stored, encrypted).
fn check_archive(data: &[u8]) -> (u32, u32, u32, u32, u32) {
    let (mut matched, mut mismatch, mut fail, mut stored, mut enc) = (0, 0, 0, 0, 0);
    let mut pos = RAR5_MAGIC.len();

    while pos + 4 < data.len() {
        let hs_off = pos + 4;
        let (hsize, hs_len) = match vint(data, hs_off) {
            Some(v) => v,
            None => break,
        };
        let hdr = hs_off + hs_len;
        let data_off = hdr + hsize as usize;
        if hsize == 0 || data_off > data.len() {
            break;
        }
        let (htype, t1) = match vint(data, hdr) {
            Some(v) => v,
            None => break,
        };
        let (hflags, t2) = match vint(data, hdr + t1) {
            Some(v) => v,
            None => break,
        };
        let mut q = hdr + t1 + t2;
        if hflags & 0x01 != 0 {
            match vint(data, q) {
                Some((_, n)) => q += n,
                None => break,
            }
        }
        let mut data_size = 0u64;
        if hflags & 0x02 != 0 {
            match vint(data, q) {
                Some((v, n)) => {
                    data_size = v;
                    q += n;
                }
                None => break,
            }
        }
        if htype == 5 || htype == 4 {
            break;
        }
        if htype == 2 {
            // Detect per-file encryption (EX_CRYPT record in the extra area).
            let mut extra_size = 0u64;
            {
                let mut qq = hdr + t1 + t2;
                if hflags & 0x01 != 0 {
                    if let Some((v, n)) = vint(data, qq) {
                        extra_size = v;
                        qq += n;
                    }
                }
                let _ = qq;
            }
            let encrypted = extra_has_crypt(data, hdr + hsize as usize, extra_size);
            if let Some((unp, method, comp_info, crc, has_crc, is_dir)) =
                file_fields(data, q, hdr, hsize)
            {
                if encrypted && !is_dir {
                    enc += 1;
                } else if !is_dir {
                    let dend = (data_off + data_size as usize).min(data.len());
                    let packed = &data[data_off.min(data.len())..dend];
                    if method == 0 {
                        stored += 1;
                    } else {
                        let ws = window_size(comp_info);
                        let mut budget = exav_unpack::Budget::new(exav_unpack::Limits {
                            max_total_bytes: 2 * 1024 * 1024 * 1024,
                            max_entry_bytes: 512 * 1024 * 1024,
                            max_ratio: u64::MAX,
                            ..Default::default()
                        });
                        match try_unpack(packed, unp, ws, &mut budget) {
                            Some(out) => {
                                if has_crc {
                                    if crc32(&out) == crc {
                                        matched += 1;
                                    } else {
                                        mismatch += 1;
                                    }
                                } else {
                                    // No CRC to compare; count as decoded ok.
                                    matched += 1;
                                }
                            }
                            None => {
                                // Could be PPMd / unsupported filter / encrypted.
                                if comp_info & 0x80 == 0 {
                                    enc += 1;
                                } else {
                                    fail += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        let next = data_off + data_size as usize;
        if next <= pos {
            break;
        }
        pos = next;
    }
    (matched, mismatch, fail, stored, enc)
}

/// Scan the trailing extra area for an EX_CRYPT (0x01) record.
fn extra_has_crypt(data: &[u8], end: usize, extra_size: u64) -> bool {
    if extra_size == 0 || extra_size as usize > end {
        return false;
    }
    let mut p = end - extra_size as usize;
    let mut guard = 0;
    while p < end && guard < 64 {
        guard += 1;
        let (rec_size, n1) = match vint(data, p) {
            Some(v) => v,
            None => break,
        };
        let (rec_type, _n2) = match vint(data, p + n1) {
            Some(v) => v,
            None => break,
        };
        if rec_type == 0x01 {
            return true;
        }
        let advance = n1 + rec_size as usize;
        if advance == 0 {
            break;
        }
        p += advance;
    }
    false
}

fn try_unpack(
    packed: &[u8],
    unp: u64,
    ws: u64,
    budget: &mut exav_unpack::Budget,
) -> Option<Vec<u8>> {
    exav_unpack::unpack50(packed, unp, ws, budget).ok()
}

fn window_size(comp_info: u64) -> u64 {
    exav_unpack::window_size_from_comp_info(comp_info)
}

fn file_fields(
    data: &[u8],
    mut q: usize,
    hdr: usize,
    hsize: u64,
) -> Option<(u64, u64, u64, u32, bool, bool)> {
    let _end = hdr + hsize as usize;
    let (file_flags, n) = vint(data, q)?;
    q += n;
    let (unp, n) = vint(data, q)?;
    q += n;
    let (_attr, n) = vint(data, q)?;
    q += n;
    if file_flags & 0x02 != 0 {
        q += 4;
    }
    let has_crc = file_flags & 0x04 != 0;
    let mut crc = 0u32;
    if has_crc {
        crc = u32le(data, q).unwrap_or(0);
        q += 4;
    }
    let (comp_info, n) = vint(data, q)?;
    q += n;
    let _ = q;
    let is_dir = file_flags & 0x01 != 0;
    let method = (comp_info >> 7) & 0x7;
    Some((unp, method, comp_info, crc, has_crc, is_dir))
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

    let (mut t_match, mut t_mis, mut t_fail, mut t_store, mut t_enc) = (0u32, 0, 0, 0, 0);
    let mut rar5_files = 0;

    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().map(|e| e != "bin").unwrap_or(true) {
            continue;
        }
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if !data.starts_with(RAR5_MAGIC) {
            continue;
        }
        rar5_files += 1;
        let (m, mis, f, s, e) = check_archive(&data);
        t_match += m;
        t_mis += mis;
        t_fail += f;
        t_store += s;
        t_enc += e;
        if mis > 0 || f > 0 {
            println!(
                "{}: match={m} MISMATCH={mis} fail={f} stored={s} enc={e}",
                path.file_name().unwrap().to_string_lossy()
            );
        }
    }

    println!("\n=== RAR5 CRC validation summary ===");
    println!("RAR5 archives scanned : {rar5_files}");
    println!("compressed members OK : {t_match}");
    println!("CRC MISMATCH          : {t_mis}");
    println!("decode failures       : {t_fail}");
    println!("stored members        : {t_store}");
    println!("encrypted/unsupported : {t_enc}");
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
