//! cpio archive extractor (RPM payloads, initramfs images).
//!
//! Supports the SVR4 "new ASCII" format (`070701`, and `070702` with CRC) and
//! the old POSIX "portable" format (`070707`, octal fields). Member data is
//! emitted for the engine to recurse into.

use crate::*;

const TRAILER: &str = "TRAILER!!!";

fn hex(field: &[u8]) -> usize {
    usize::from_str_radix(std::str::from_utf8(field).unwrap_or("0").trim(), 16).unwrap_or(0)
}
fn oct(field: &[u8]) -> usize {
    usize::from_str_radix(std::str::from_utf8(field).unwrap_or("0").trim(), 8).unwrap_or(0)
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub(crate) fn extract_cpio<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if data.starts_with(b"070701") || data.starts_with(b"070702") {
        extract_newc(data, budget, visit)
    } else if data.starts_with(b"070707") {
        extract_odc(data, budget, visit)
    } else if data.starts_with(&[0xc7, 0x71]) {
        extract_bin(data, budget, false, visit) // little-endian (0o070707 LE)
    } else if data.starts_with(&[0x71, 0xc7]) {
        extract_bin(data, budget, true, visit) // byte-swapped (big-endian writer)
    } else {
        Err(LimitHit::new("cpio: unknown format".to_string()))
    }
}

/// Old binary format: 26-byte header of 16-bit fields; 32-bit fields (mtime,
/// filesize) are stored most-significant-half first. Name and data are each
/// padded to an even byte boundary.
fn extract_bin<R>(
    data: &[u8],
    budget: &mut Budget,
    swap: bool,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let u16at = |p: usize, d: &[u8]| -> usize {
        let v = u16::from_le_bytes([d[p], d[p + 1]]);
        (if swap { v.swap_bytes() } else { v }) as usize
    };
    let mut pos = 0usize;
    while pos + 26 <= data.len() {
        let magic = u16at(pos, data);
        if magic != 0o070707 {
            break;
        }
        let namesize = u16at(pos + 20, data);
        let filesize = (u16at(pos + 22, data) << 16) | u16at(pos + 24, data);
        let name_start = pos + 26;
        let name_end = name_start.saturating_add(namesize).min(data.len());
        let name = String::from_utf8_lossy(&data[name_start..name_end])
            .trim_end_matches('\0')
            .to_string();
        if name == TRAILER {
            break;
        }
        // Clamp to EOF: `namesize` is attacker-controlled, so an oversized value
        // must not let `data_start` slice past the buffer (start > end panics).
        let data_start = name_start
            .saturating_add(namesize)
            .saturating_add(namesize & 1) // pad name to even
            .min(data.len());
        let data_end = data_start.saturating_add(filesize).min(data.len());
        if filesize > 0 {
            budget.count_entry()?;
            let cap = budget.reserve()?;
            if filesize as u64 > cap {
                return Err(LimitHit::new(format!("cpio member '{name}' exceeds budget")));
            }
            let member = data[data_start..data_end].to_vec();
            budget.commit(member.len() as u64);
            if let Some(r) = visit(Entry::new(name, member), budget) {
                return Ok(Some(r));
            }
        }
        pos = data_end + (filesize & 1); // pad data to even
    }
    Ok(None)
}

/// SVR4 "new ASCII": 110-byte header of 8-hex-digit fields, then name
/// (`namesize` bytes) and data (`filesize` bytes), each padded so the header+name
/// and the data each end on a 4-byte boundary.
fn extract_newc<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut pos = 0usize;
    while pos + 110 <= data.len() {
        let h = &data[pos..pos + 110];
        if &h[0..6] != b"070701" && &h[0..6] != b"070702" {
            break;
        }
        let filesize = hex(&h[54..62]);
        let namesize = hex(&h[94..102]);
        let name_start = pos + 110;
        let name_end = name_start.saturating_add(namesize).min(data.len());
        let name = String::from_utf8_lossy(&data[name_start..name_end])
            .trim_end_matches('\0')
            .to_string();
        if name == TRAILER {
            break;
        }
        // Clamp to EOF: an oversized `namesize` must not push `data_start` past
        // the buffer (start > end panics).
        let data_start = align4(name_start.saturating_add(namesize)).min(data.len());
        let data_end = data_start.saturating_add(filesize).min(data.len());
        if filesize > 0 {
            budget.count_entry()?;
            let cap = budget.reserve()?;
            if filesize as u64 > cap {
                return Err(LimitHit::new(format!("cpio member '{name}' exceeds budget")));
            }
            let member = data[data_start..data_end].to_vec();
            budget.commit(member.len() as u64);
            if let Some(r) = visit(Entry::new(name, member), budget) {
                return Ok(Some(r));
            }
        }
        pos = align4(data_end);
    }
    Ok(None)
}

/// Old POSIX "portable": 76-byte header of octal fields, no padding.
fn extract_odc<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut pos = 0usize;
    while pos + 76 <= data.len() {
        let h = &data[pos..pos + 76];
        if &h[0..6] != b"070707" {
            break;
        }
        let namesize = oct(&h[59..65]);
        let filesize = oct(&h[65..76]);
        let name_start = pos + 76;
        let name_end = name_start.saturating_add(namesize).min(data.len());
        let name = String::from_utf8_lossy(&data[name_start..name_end])
            .trim_end_matches('\0')
            .to_string();
        if name == TRAILER {
            break;
        }
        // Clamp to EOF: an oversized `namesize` must not push `data_start` past
        // the buffer (start > end panics).
        let data_start = name_start.saturating_add(namesize).min(data.len());
        let data_end = data_start.saturating_add(filesize).min(data.len());
        if filesize > 0 {
            budget.count_entry()?;
            let cap = budget.reserve()?;
            if filesize as u64 > cap {
                return Err(LimitHit::new(format!("cpio member '{name}' exceeds budget")));
            }
            let member = data[data_start..data_end].to_vec();
            budget.commit(member.len() as u64);
            if let Some(r) = visit(Entry::new(name, member), budget) {
                return Ok(Some(r));
            }
        }
        pos = data_end;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn newc_member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut hdr = format!("070701{:08x}", 0); // magic + ino
        for _ in 0..6 {
            hdr.push_str(&format!("{:08x}", 0)); // mode,uid,gid,nlink,mtime,filesize placeholder
        }
        // Rebuild precisely: fields after magic are
        // ino,mode,uid,gid,nlink,mtime,filesize,devmajor,devminor,rdevmajor,
        // rdevminor,namesize,check (13 × 8 hex).
        let name_z = format!("{name}\0");
        let fields = [
            0,
            0,
            0,
            0,
            1,
            0,
            data.len(),
            0,
            0,
            0,
            0,
            name_z.len(),
            0,
        ];
        let mut h = String::from("070701");
        for f in fields {
            h.push_str(&format!("{f:08x}"));
        }
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(name_z.as_bytes());
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn extracts_newc_member_and_trailer() {
        let mut arc = newc_member("hello.txt", b"world!");
        arc.extend_from_slice(&newc_member("TRAILER!!!", b""));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Cpio, &arc, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"world!");
    }
}
