//! uuencode / Base64-uuencode (`begin` … `end`) decoder.
//!
//! Classic uuencode wraps a single file between a `begin <mode> <name>` line and
//! an `end` line; each data line is a length byte followed by 3-for-4 encoded
//! groups, every character being `(value & 0x3F) + 0x20` (with the historical
//! `` ` `` alias for a zero). The `begin-base64 <mode> <name>` variant (from
//! `sharutils`) carries a Base64 body terminated by a `====` line instead.
//!
//! A stream may concatenate several `begin`/`end` blocks; each becomes one
//! [`Entry`]. Bounds are clamped and the decoders never index past the input, so
//! hostile/truncated data cannot panic.

use crate::*;
use base64::Engine;

/// Decode one uuencode character: `(c - 0x20) & 0x3F`. The space alias `` ` ``
/// (0x60) and a literal space both map to 0.
#[inline]
fn dec(c: u8) -> u8 {
    c.wrapping_sub(0x20) & 0x3F
}

/// Decode one classic uuencode data line into `out` (bounded by the leading
/// length byte, and never reading past the line).
fn decode_uu_line(line: &[u8], out: &mut Vec<u8>) {
    if line.is_empty() {
        return;
    }
    let len = dec(line[0]) as usize; // declared output bytes on this line
    let body = &line[1..];
    let mut produced = 0usize;
    let mut i = 0usize;
    while produced < len {
        // Missing trailing characters (truncated line) decode as 0.
        let c0 = dec(*body.get(i).unwrap_or(&0x20));
        let c1 = dec(*body.get(i + 1).unwrap_or(&0x20));
        let c2 = dec(*body.get(i + 2).unwrap_or(&0x20));
        let c3 = dec(*body.get(i + 3).unwrap_or(&0x20));
        i += 4;
        if produced < len {
            out.push((c0 << 2) | (c1 >> 4));
            produced += 1;
        }
        if produced < len {
            out.push((c1 << 4) | (c2 >> 2));
            produced += 1;
        }
        if produced < len {
            out.push((c2 << 6) | c3);
            produced += 1;
        }
        if i > body.len() {
            break; // exhausted the line
        }
    }
}

/// Parse `<mode> <filename>` from the tail of a `begin`/`begin-base64` line,
/// returning a sanitized file name (basename only, non-empty).
fn parse_begin_name(rest: &[u8]) -> String {
    let s = String::from_utf8_lossy(rest);
    let s = s.trim();
    // Skip the octal mode field, keep the remainder as the name.
    let name = s
        .split_once(char::is_whitespace)
        .map(|(_, n)| n)
        .unwrap_or("");
    let name = name
        .trim()
        .trim_matches(|c| c == '/' || c == '\\' || c == '\0');
    // Basename only — an attacker-supplied path must not escape.
    let base = name.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if base.is_empty() {
        "uudecoded.bin".to_string()
    } else {
        base.to_string()
    }
}

/// Split `data` into lines, dropping the trailing `\r` of CRLF endings.
fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

pub(crate) fn extract_uuencode<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut it = lines(data).peekable();
    while let Some(line) = it.next() {
        let trimmed = trim_ascii_start(line);
        let (base64, rest) = if let Some(r) = trimmed.strip_prefix(b"begin-base64 ") {
            (true, r)
        } else if let Some(r) = trimmed.strip_prefix(b"begin ") {
            (false, r)
        } else {
            continue;
        };
        let name = parse_begin_name(rest);

        budget.count_entry()?;
        let cap = budget.reserve()?;
        let mut out = Vec::new();

        if base64 {
            // Collect Base64 body until a `====` terminator (or EOF), stripping
            // whitespace, then decode in one shot.
            let mut b64 = Vec::new();
            for body in it.by_ref() {
                let t = trim_ascii(body);
                if t.starts_with(b"====") {
                    break;
                }
                b64.extend(t.iter().filter(|b| !b.is_ascii_whitespace()));
                if b64.len() as u64 > cap.saturating_mul(2).saturating_add(64) {
                    return Err(LimitHit::new(format!(
                        "uuencode member '{name}' exceeds budget"
                    )));
                }
            }
            out = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| LimitHit::corrupt(format!("uuencode base64: {e}")))?;
            if out.len() as u64 > cap {
                return Err(LimitHit::new(format!(
                    "uuencode member '{name}' exceeds budget"
                )));
            }
        } else {
            // Classic body: decode each line until `end`, a blank/zero-length
            // line, or EOF.
            for body in it.by_ref() {
                let t = trim_ascii(body);
                if t == b"end" || t.is_empty() {
                    break;
                }
                // A single space / backtick line is the length-0 terminator.
                if dec(t[0]) == 0 {
                    // Could be a real 0-length data line before `end`; stop.
                    break;
                }
                decode_uu_line(t, &mut out);
                if out.len() as u64 > cap {
                    return Err(LimitHit::new(format!(
                        "uuencode member '{name}' exceeds budget"
                    )));
                }
            }
        }

        budget.commit(out.len() as u64);
        if let Some(r) = visit(Entry::new(name, out), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// True if `data` (leading whitespace skipped) opens a uuencode stream: a
/// `begin `/`begin-base64 ` line with a matching `end`/`====` terminator later.
/// Conservative — used by [`crate::detect`], which is the single source of truth.
pub(crate) fn looks_like_uuencode(data: &[u8]) -> bool {
    let head = trim_ascii_start(&data[..data.len().min(4096)]);
    let base64 = head.starts_with(b"begin-base64 ");
    if !base64 && !head.starts_with(b"begin ") {
        return false;
    }
    // Require a terminator so a stray "begin " prose line isn't claimed.
    lines(data).any(|l| {
        let t = trim_ascii(l);
        if base64 {
            t.starts_with(b"====")
        } else {
            t == b"end"
        }
    })
}

/// `[u8]::trim_ascii_start` is stable but re-implemented here to also cover the
/// combined trim below without pulling extra bounds churn.
fn trim_ascii_start(mut b: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = b {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn trim_ascii(mut b: &[u8]) -> &[u8] {
    b = trim_ascii_start(b);
    while let [rest @ .., last] = b {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference classic-uuencode encoder for the roundtrip test.
    fn uuencode(name: &str, data: &[u8]) -> Vec<u8> {
        let enc = |v: u8| -> u8 {
            let v = v & 0x3F;
            if v == 0 {
                b'`'
            } else {
                v + 0x20
            }
        };
        let mut out = format!("begin 644 {name}\n").into_bytes();
        for chunk in data.chunks(45) {
            out.push(enc(chunk.len() as u8));
            for grp in chunk.chunks(3) {
                let b0 = grp[0];
                let b1 = *grp.get(1).unwrap_or(&0);
                let b2 = *grp.get(2).unwrap_or(&0);
                out.push(enc(b0 >> 2));
                out.push(enc((b0 << 4) | (b1 >> 4)));
                out.push(enc((b1 << 2) | (b2 >> 6)));
                out.push(enc(b2));
            }
            out.push(b'\n');
        }
        out.extend_from_slice(b"`\nend\n");
        out
    }

    #[test]
    fn classic_uuencode_roundtrip() {
        let payload = b"MALWARETEST payload inside uuencode body 12345";
        let blob = uuencode("evil.bin", payload);
        assert!(looks_like_uuencode(&blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Uuencode, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "evil.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn base64_uuencode_roundtrip() {
        let payload = b"MALWARETEST base64 body";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let blob = format!("begin-base64 644 evil64.bin\n{b64}\n====\n").into_bytes();
        assert!(looks_like_uuencode(&blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Uuencode, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "evil64.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn truncated_line_does_not_panic() {
        // A `begin` with a bogus over-length line byte and no `end`.
        let blob = b"begin 644 x\nMtrunc\n".to_vec();
        let mut budget = Budget::new(Limits::default());
        // No terminator, so detection declines; extraction must not panic.
        let _ = extract(Format::Uuencode, &blob, &mut budget);
        assert!(!looks_like_uuencode(&blob));
    }
}
