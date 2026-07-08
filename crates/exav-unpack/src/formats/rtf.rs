//! RTF embedded-object extractor.
//!
//! Implemented from the public **Microsoft Rich Text Format (RTF) Specification**
//! (v1.9.1). An RTF file is a tree of brace-delimited groups containing control
//! words (`\word` + optional signed number + one optional delimiting space) and
//! control symbols (`\` + a single non-letter). An embedded OLE object is carried
//! as ASCII hex inside an `\objdata` destination (RTF §"Objects"); malware hides
//! droppers there (an OLE2/VBA document or a raw PE). We collect the hex bytes of
//! every `\objdata`/`\datastore` destination and emit the decoded object so the
//! engine can recurse into it.
//!
//! Hex digits inside the destination may be split across lines and interleaved
//! with control words; we decode only `[0-9a-fA-F]`, skip control sequences (so
//! their letters aren't misread as hex), and stop at the `}` closing the group.
//! Every read is bounds-checked; truncated/hostile RTF cannot panic (an
//! unterminated group runs to EOF, an odd trailing nibble is dropped).

use crate::*;

/// Numeric value of an ASCII hex digit, else `None`.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Consume the control word/symbol at `at` (a `\`). Returns its letter name
/// (empty for a control symbol) and the offset just past the token — including a
/// signed numeric parameter and one trailing delimiting space. Always advances.
fn control_token(data: &[u8], at: usize) -> (&[u8], usize) {
    let n = data.len();
    let mut i = at + 1;
    if i >= n {
        return (&[], n);
    }
    if !data[i].is_ascii_alphabetic() {
        return (&data[i..i], i + 1); // control symbol: backslash + one char
    }
    let name_start = i;
    while i < n && data[i].is_ascii_alphabetic() {
        i += 1;
    }
    let name = &data[name_start..i];
    if i < n && data[i] == b'-' {
        i += 1;
    }
    while i < n && data[i].is_ascii_digit() {
        i += 1;
    }
    if i < n && data[i] == b' ' {
        i += 1; // the single delimiting space belongs to the control word
    }
    (name, i)
}

/// Decode the hex payload of a destination whose data begins at `from`, tracking
/// group depth (starting at 1) and stopping at the closing `}`. Returns the
/// decoded bytes and the offset just past that `}` (or EOF).
fn decode_object(data: &[u8], from: usize) -> (Vec<u8>, usize) {
    let n = data.len();
    let mut i = from;
    let mut depth = 1i32;
    let mut hi: Option<u8> = None;
    let mut out = Vec::new();
    while i < n {
        match data[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    break;
                }
            }
            b'\\' => {
                let (_, next) = control_token(data, i);
                i = next;
            }
            other => {
                if let Some(v) = hex_nibble(other) {
                    match hi.take() {
                        None => hi = Some(v),
                        Some(h) => out.push((h << 4) | v),
                    }
                }
                i += 1;
            }
        }
    }
    (out, i)
}

pub(crate) fn extract_rtf<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !data.starts_with(b"{\\rtf") {
        return Ok(None);
    }
    let n = data.len();
    let mut i = 0usize;
    let mut index = 0usize;
    while i < n {
        if data[i] != b'\\' {
            i += 1;
            continue;
        }
        let (name, after) = control_token(data, i);
        if name == b"objdata" || name == b"datastore" {
            let (bytes, next) = decode_object(data, after);
            i = next;
            if bytes.is_empty() {
                continue;
            }
            budget.count_entry()?;
            let cap = budget.reserve()?;
            if bytes.len() as u64 > cap {
                return Err(LimitHit::new("rtf object exceeds budget".to_string()));
            }
            index += 1;
            budget.commit(bytes.len() as u64);
            if let Some(r) = visit(Entry::new(format!("rtf-object-{index}"), bytes), budget) {
                return Ok(Some(r));
            }
        } else {
            i = after;
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn extracts_single_object() {
        let payload = b"MALWARETEST-inside-rtf-object";
        let rtf = format!("{{\\rtf1\\ansi {{\\object\\objemb{{\\objdata {}}}}}}}", hex(payload));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, rtf.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "rtf-object-1");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn hex_split_with_control_words() {
        let mut payload = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        payload.extend_from_slice(b"MALWARETEST");
        let h = hex(&payload);
        let (a, b) = h.split_at(10);
        let rtf = format!("{{\\rtf1{{\\object{{\\objdata\n{a}\r\n\\par {b}\n}}}}}}");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, rtf.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn extracts_multiple() {
        let (p1, p2) = (b"FIRST-MALWARETEST", b"SECOND-DROPPER");
        let rtf = format!(
            "{{\\rtf1 {{\\object{{\\objdata {}}}}} text {{\\object{{\\objdata {}}}}}}}",
            hex(p1),
            hex(p2)
        );
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, rtf.as_bytes(), &mut budget).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, p1);
        assert_eq!(entries[1].data, p2);
    }

    #[test]
    fn odd_nibble_dropped() {
        let rtf = b"{\\rtf1{\\object{\\objdata 4142434}}}";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, rtf, &mut budget).unwrap();
        assert_eq!(entries[0].data, b"ABC");
    }

    #[test]
    fn truncated_no_panic() {
        let rtf = b"{\\rtf1{\\object{\\objdata 4d414c5741524554455354";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Rtf, rtf, &mut budget).unwrap();
        assert_eq!(entries[0].data, b"MALWARETEST");
    }

    #[test]
    fn empty_and_nonrtf() {
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Rtf, b"{\\rtf1{\\object{\\objdata }}}", &mut budget)
            .unwrap()
            .is_empty());
        assert!(extract(Format::Rtf, b"not rtf", &mut budget).unwrap().is_empty());
    }
}
