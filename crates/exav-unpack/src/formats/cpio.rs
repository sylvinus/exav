//! cpio archive extractor (RPM payloads, initramfs images).
//!
//! Supports the SVR4 "new ASCII" format (`070701`, and `070702` with CRC) and
//! the old POSIX "portable" format (`070707`, octal fields). Member data is
//! emitted for the engine to recurse into.

use crate::*;
use std::io::{Read, Seek, SeekFrom};

const TRAILER: &str = "TRAILER!!!";

/// Bytes to which a name-read is capped (names are not attacker-sized payloads).
const MAX_NAME: u64 = 65536;

fn align4_u64(n: u64) -> u64 {
    (n + 3) & !3
}

/// Read a member name of `namesize` bytes at `off` (capped, `\0`-trimmed).
fn read_name<R: Read + Seek>(source: &mut R, off: u64, namesize: u64) -> Result<String, LimitHit> {
    let buf = crate::read_at(source, off, namesize.min(MAX_NAME) as usize)?;
    Ok(String::from_utf8_lossy(&buf)
        .trim_end_matches('\0')
        .to_string())
}

/// Walk a cpio archive, each member streamed from where it lies.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let members = stream_offsets(&mut source)?;
    crate::stream::stream_stored(&mut source, budget, visit, members)
}

/// Parse member offsets from a seekable source (reader-based streaming): walk the
/// cpio headers (newc/odc/old-binary) and return each file member as
/// `(name, data_offset, size)`. Mirrors [`extract_cpio`]'s boundaries but never
/// buffers member data.
pub(crate) fn stream_offsets<R: Read + Seek>(
    source: &mut R,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let mut magic = [0u8; 6];
    source
        .seek(SeekFrom::Start(0))
        .and_then(|_| source.read_exact(&mut magic))
        .map_err(|e| LimitHit::corrupt(format!("cpio: {e}")))?;
    if &magic == b"070701" || &magic == b"070702" {
        stream_walk(source, 110, Fields::Newc)
    } else if &magic == b"070707" {
        stream_walk(source, 76, Fields::Odc)
    } else if magic[0..2] == [0xc7, 0x71] {
        stream_walk(source, 26, Fields::Bin { swap: false })
    } else if magic[0..2] == [0x71, 0xc7] {
        stream_walk(source, 26, Fields::Bin { swap: true })
    } else {
        Err(LimitHit::new("cpio: unknown format".to_string()))
    }
}

enum Fields {
    Newc,
    Odc,
    Bin { swap: bool },
}

fn stream_walk<R: Read + Seek>(
    source: &mut R,
    hdr_len: usize,
    fields: Fields,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let mut out = Vec::new();
    let mut pos = 0u64;
    loop {
        let h = crate::read_at(source, pos, hdr_len)?;
        if h.len() < hdr_len {
            break;
        }
        let (namesize, filesize, magic_ok) = match &fields {
            Fields::Newc => (
                hex(&h[94..102]) as u64,
                hex(&h[54..62]) as u64,
                &h[0..6] == b"070701" || &h[0..6] == b"070702",
            ),
            Fields::Odc => (
                oct(&h[59..65]) as u64,
                oct(&h[65..76]) as u64,
                &h[0..6] == b"070707",
            ),
            Fields::Bin { swap } => {
                let u16at = |p: usize| -> u64 {
                    let v = u16::from_le_bytes([h[p], h[p + 1]]);
                    (if *swap { v.swap_bytes() } else { v }) as u64
                };
                (
                    u16at(20),
                    (u16at(22) << 16) | u16at(24),
                    u16at(0) == 0o070707,
                )
            }
        };
        if !magic_ok {
            break;
        }
        let name_start = pos + hdr_len as u64;
        let name = read_name(source, name_start, namesize)?;
        if name == TRAILER {
            break;
        }
        // Data start + next-header advance mirror the buffered extractor:
        // newc pads header+name and data to 4 bytes; odc has no padding; the old
        // binary format pads the name and the data to even boundaries.
        let (data_start, next) = match &fields {
            Fields::Newc => {
                let ds = align4_u64(name_start + namesize);
                (ds, align4_u64(ds + filesize))
            }
            Fields::Odc => {
                let ds = name_start + namesize;
                (ds, ds + filesize)
            }
            Fields::Bin { .. } => {
                let ds = name_start + namesize + (namesize & 1);
                (ds, ds + filesize + (filesize & 1))
            }
        };
        if filesize > 0 {
            out.push((name, data_start, filesize));
        }
        if next <= pos {
            break; // no forward progress → stop rather than loop
        }
        pos = next;
    }
    Ok(out)
}

fn hex(field: &[u8]) -> usize {
    usize::from_str_radix(std::str::from_utf8(field).unwrap_or("0").trim(), 16).unwrap_or(0)
}
fn oct(field: &[u8]) -> usize {
    usize::from_str_radix(std::str::from_utf8(field).unwrap_or("0").trim(), 8).unwrap_or(0)
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
        let fields = [0, 0, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, name_z.len(), 0];
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
