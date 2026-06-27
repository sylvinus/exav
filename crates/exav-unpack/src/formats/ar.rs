//! Unix `ar` archive extractor (`.a` static libraries, Debian `.deb` packages).
//!
//! `.deb` files are `ar` archives whose members are usually `control.tar.*` and
//! `data.tar.*`; emitting those members lets the engine recurse into them.

use crate::*;

const MAGIC: &[u8] = b"!<arch>\n";

fn parse_decimal(field: &[u8]) -> u64 {
    let s = std::str::from_utf8(field).unwrap_or("").trim();
    s.parse().unwrap_or(0)
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
            "//" => name_table = member.to_vec(),
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
