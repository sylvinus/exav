//! Unix `ar` archive extractor (`.a` static libraries, Debian `.deb` packages).
//!
//! `.deb` files are `ar` archives whose members are usually `control.tar.*` and
//! `data.tar.*`; emitting those members lets the engine recurse into them.

use crate::*;
use std::io::{Read, Seek, SeekFrom};

const MAGIC: &[u8] = b"!<arch>\n";

fn parse_decimal(field: &[u8]) -> u64 {
    let s = std::str::from_utf8(field).unwrap_or("").trim();
    s.parse().unwrap_or(0)
}

/// Parse member offsets from a seekable source (the reader-based streaming
/// path): walk the 60-byte headers, resolving GNU long names via the `//` string
/// table, and return each *file* member as `(name, data_offset, size)`. Symbol
/// tables are skipped. The string table is bounded by `max_buffer`. Mirrors the
/// boundary logic of [`extract_ar`], but never buffers member data.
pub(crate) fn stream_offsets<R: Read + Seek>(
    source: &mut R,
    max_buffer: u64,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let mut magic = [0u8; 8];
    source
        .seek(SeekFrom::Start(0))
        .and_then(|_| source.read_exact(&mut magic))
        .map_err(|e| LimitHit::corrupt(format!("ar: {e}")))?;
    if magic != MAGIC {
        return Err(LimitHit::new("ar: bad magic".to_string()));
    }
    let mut out = Vec::new();
    let mut name_table: Vec<u8> = Vec::new();
    let mut pos = MAGIC.len() as u64;
    loop {
        if source.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        let mut hdr = [0u8; 60];
        if source.read_exact(&mut hdr).is_err() {
            break;
        }
        if &hdr[58..60] != b"`\n" {
            break;
        }
        let size = parse_decimal(&hdr[48..58]);
        let body = pos + 60;
        let name = resolve_name(&hdr[0..16], &name_table);
        match name.as_str() {
            "//" => {
                if size > max_buffer {
                    return Err(LimitHit::new(
                        "ar name table exceeds max-buffer".to_string(),
                    ));
                }
                name_table = vec![0u8; size as usize];
                source.seek(SeekFrom::Start(body)).ok();
                source.read_exact(&mut name_table).ok();
            }
            "/" | "/SYM64/" | "__.SYMDEF" => {}
            _ => out.push((name, body, size)),
        }
        pos = body + size + (size & 1);
    }
    Ok(out)
}

pub(crate) fn extract_ar<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !data.starts_with(MAGIC) {
        return Err(LimitHit::new("ar: bad magic".to_string()));
    }
    let mut pos = MAGIC.len();
    // GNU long-name string table ("//" member), if present.
    let mut name_table: Vec<u8> = Vec::new();

    while pos + 60 <= data.len() {
        let hdr = &data[pos..pos + 60];
        if &hdr[58..60] != b"`\n" {
            break; // not a valid header; stop rather than misread
        }
        let raw_name = &hdr[0..16];
        let size = parse_decimal(&hdr[48..58]) as usize;
        let body = pos + 60;
        let end = body.saturating_add(size).min(data.len());
        let member = &data[body..end];

        let name = resolve_name(raw_name, &name_table);
        match name.as_str() {
            // GNU string table: holds long names referenced as "/<offset>".
            // Bounded by the global peak-buffer limit like any materialized blob.
            "//" => {
                if member.len() as u64 > budget.limits.max_buffer_bytes() {
                    return Err(LimitHit::new(
                        "ar name table exceeds max-buffer".to_string(),
                    ));
                }
                name_table = member.to_vec();
            }
            // Symbol tables, not file content.
            "/" | "/SYM64/" | "__.SYMDEF" => {}
            _ => {
                budget.count_entry()?;
                let cap = budget.reserve()?;
                if member.len() as u64 > cap {
                    return Err(LimitHit::new(format!("ar member '{name}' exceeds budget")));
                }
                budget.commit(member.len() as u64);
                if let Some(r) = visit(Entry::new(name, member.to_vec()), budget) {
                    return Ok(Some(r));
                }
            }
        }

        // Members are padded to an even byte boundary.
        pos = end + (size & 1);
    }
    Ok(None)
}

/// Resolve an `ar` member name, handling GNU (`/N` → string table) and BSD
/// (`#1/N` → name is the first N bytes of the data, not yet stripped here)
/// extended-name conventions. BSD long names are left as-is (best effort).
fn resolve_name(raw: &[u8], name_table: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(raw);
    let trimmed = trimmed.trim_end();
    if trimmed == "//" || trimmed == "/" {
        return trimmed.to_string();
    }
    // GNU long name: "/<offset>" into the string table.
    if let Some(rest) = trimmed.strip_prefix('/') {
        if let Ok(off) = rest.parse::<usize>() {
            if off < name_table.len() {
                let end = name_table[off..]
                    .iter()
                    .position(|&b| b == b'/' || b == b'\n')
                    .map(|p| off + p)
                    .unwrap_or(name_table.len());
                return String::from_utf8_lossy(&name_table[off..end]).into_owned();
            }
        }
    }
    // GNU short name: trailing '/'.
    trimmed.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_two_members() {
        // Build a minimal ar with two members "a.txt" (3 bytes, odd → padded)
        // and "b.bin" (2 bytes).
        let mut ar = Vec::new();
        ar.extend_from_slice(MAGIC);
        let member = |name: &str, data: &[u8], out: &mut Vec<u8>| {
            let mut hdr = [b' '; 60];
            let n = name.as_bytes();
            hdr[..n.len()].copy_from_slice(n);
            let size = format!("{}", data.len());
            hdr[48..48 + size.len()].copy_from_slice(size.as_bytes());
            hdr[58] = b'`';
            hdr[59] = b'\n';
            out.extend_from_slice(&hdr);
            out.extend_from_slice(data);
            if data.len() & 1 == 1 {
                out.push(b'\n'); // pad
            }
        };
        member("a.txt/", b"abc", &mut ar);
        member("b.bin/", b"XY", &mut ar);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Ar, &ar, &mut budget).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].data, b"abc");
        assert_eq!(entries[1].name, "b.bin");
        assert_eq!(entries[1].data, b"XY");
    }
}
