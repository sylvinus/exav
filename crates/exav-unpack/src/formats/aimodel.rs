//! AI-model supply-chain surfacer (Python **pickle** / **safetensors**).
//!
//! Machine-learning models ship as serialized blobs, and two of the most common
//! carriers are attacker-controllable:
//!
//! * **Python pickle** — the real threat. A pickle is a little stack-machine
//!   program; the `GLOBAL`/`STACK_GLOBAL` + `REDUCE` opcodes let a crafted
//!   pickle import an arbitrary callable (e.g. `os.system`, `subprocess.Popen`,
//!   `builtins.eval`) and call it with attacker-chosen arguments *at load time*.
//!   We **never execute** the pickle: we statically disassemble the opcode
//!   stream, and surface (1) every referenced global as `module\nname\n` and
//!   (2) every string/bytes literal operand. Signatures then match on the
//!   dangerous imports (`os\nsystem`, `posix\nsystem`, `subprocess\nPopen`, …)
//!   and on embedded command strings / base64 payloads.
//!
//! * **safetensors** — designed to be safe (tensors are opaque data), but the
//!   leading JSON header can carry a `__metadata__` map with attacker strings.
//!   We surface just that header as `safetensors-header`.
//!
//! Both walks are strictly bounds-checked and never panic on truncated or
//! hostile input: on any unknown opcode or short read we stop and emit what we
//! have collected so far.

//!
//! ## On the early exits in this module
//!
//! The `break`s in the opcode walk below stop *disassembly*, not scanning: a
//! truncated or malformed pickle stops being interpreted at that point. That is
//! safe rather than a silent skip, because the caller pattern-scans the raw
//! buffer before it ever asks for extraction (`member_content_scan` in
//! `exav-core`), so no byte goes unexamined — what is lost is the *surfaced*
//! opcode text, which only affects signatures written against the disassembled
//! form. Recorded here so the next reader can tell this apart from a member
//! being dropped, which would be a defect.
use crate::*;

/// A safetensors file starts with a little-endian `u64` header length; we only
/// scan this many bytes of the header for the mandatory `"` when sniffing.
const SAFETENSORS_SNIFF: usize = 4096;

/// Detect a pickle (protocol 2..5) or a safetensors file. Conservative: weak
/// proto-0/1 pickles are intentionally *not* sniffed here (their leading byte
/// carries no reliable magic), though `extract_aimodel` will still disassemble
/// them if routing sends them our way.
pub(crate) fn is_aimodel(data: &[u8]) -> bool {
    is_pickle(data) || is_safetensors(data)
}

/// Pickle protocol 2..5: `0x80` PROTO opcode followed by the protocol number.
fn is_pickle(data: &[u8]) -> bool {
    matches!(data.first(), Some(0x80)) && matches!(data.get(1), Some(0x02..=0x05))
}

/// safetensors sniff: `u64` LE header length `n` with `2 <= n`, `8 + n` in
/// bounds, the header opening with `{`, and a `"` within the first
/// `min(n, 4096)` header bytes.
fn is_safetensors(data: &[u8]) -> bool {
    if data.len() < 9 {
        return false;
    }
    let n = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    if n < 2 {
        return false;
    }
    // 8 + n must not overflow and must fit within the file.
    let end = match 8u64.checked_add(n) {
        Some(e) => e,
        None => return false,
    };
    if end > data.len() as u64 {
        return false;
    }
    if data.get(8) != Some(&b'{') {
        return false;
    }
    let scan = (n as usize).min(SAFETENSORS_SNIFF);
    // Header bytes are data[8..8+scan]; scan >= 1 since n >= 2.
    data[8..8 + scan].contains(&b'"')
}

pub(crate) fn extract_aimodel<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if is_pickle(data) || looks_like_pickle_opcodes(data) {
        return extract_pickle(data, budget, visit);
    }
    if is_safetensors(data) {
        return extract_safetensors(data, budget, visit);
    }
    Ok(None)
}

/// A loose fallback so proto-0/1 pickles that were routed here still get
/// disassembled: treat the input as a pickle if it is not a safetensors file.
fn looks_like_pickle_opcodes(data: &[u8]) -> bool {
    !data.is_empty() && !is_safetensors(data)
}

/// Emit the leading JSON header of a safetensors file as `safetensors-header`.
fn extract_safetensors<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Re-validate defensively (caller may route loosely).
    if data.len() < 9 {
        return Ok(None);
    }
    let n = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let end = match 8u64.checked_add(n) {
        Some(e) => e.min(data.len() as u64) as usize,
        None => data.len(),
    };
    if end <= 8 {
        return Ok(None);
    }
    let header = &data[8..end];

    budget.count_entry()?;
    let cap = budget.reserve()?;
    // The header is the model's JSON metadata, and what a rule looks for in it
    // can sit anywhere. Clamping to the budget and emitting the prefix as though
    // it were the header hides whatever falls past the cut, so an over-cap header
    // is reported — and the part that fits is still handed over, since a prefix
    // is content even when it is not all of it.
    if header.len() as u64 > cap {
        if let Some(r) = visit(
            Entry::unsupported(
                "safetensors-header".into(),
                header.len() as u64,
                false,
                "safetensors header exceeds the per-member size budget; \
                 the part that fits was scanned",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }
    let take = (header.len() as u64).min(cap) as usize;
    let member = header[..take].to_vec();
    budget.commit(member.len() as u64);
    if let Some(r) = visit(Entry::new("safetensors-header".into(), member), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

/// Statically disassemble the pickle opcode stream and collect referenced
/// globals + string/bytes literals into a single `pickle-imports` member.
/// Never executes anything; on any unknown opcode or short read the walk stops
/// and whatever was collected so far is emitted.
fn extract_pickle<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Hard cap on how much we buffer, so a hostile pickle full of giant string
    // literals can't blow memory before we hit the emit-time budget check.
    let cap = budget.reserve()?;
    let out = disassemble(data, cap);

    if out.is_empty() {
        return Ok(None);
    }

    budget.count_entry()?;
    if out.len() as u64 > cap {
        return Err(LimitHit::new("pickle imports exceed budget".to_string()));
    }
    budget.commit(out.len() as u64);
    if let Some(r) = visit(Entry::new("pickle-imports".into(), out), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

/// Walk the opcode stream, returning the collected globals + literals buffer.
/// `cap` bounds total collected output; once reached, the walk stops.
fn disassemble(data: &[u8], cap: u64) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    // Ring of the last two string/unicode/bytes literals pushed, so
    // STACK_GLOBAL can reconstruct `module\nname`.
    let mut prev1: Option<Vec<u8>> = None; // most recent
    let mut prev2: Option<Vec<u8>> = None; // one before that
    let cap = cap as usize;
    let mut i = 0usize;

    // Append `bytes` + `\n` to output, honoring the cap. Returns false if the
    // cap was reached (caller stops the walk).
    macro_rules! push_out {
        ($bytes:expr) => {{
            let b: &[u8] = $bytes;
            if out.len() >= cap {
                return out;
            }
            let room = cap - out.len();
            let take = b.len().min(room);
            out.extend_from_slice(&b[..take]);
            if out.len() < cap {
                out.push(b'\n');
            }
        }};
    }

    // Record a freshly-pushed string literal for later STACK_GLOBAL use and add
    // it to output.
    macro_rules! record_str {
        ($bytes:expr) => {{
            let v: Vec<u8> = $bytes;
            push_out!(&v);
            prev2 = prev1.take();
            prev1 = Some(v);
        }};
    }

    // Read a little-endian unsigned integer of `n` bytes starting at `i+1`;
    // returns None on short read.
    macro_rules! read_le {
        ($n:expr) => {{
            let n: usize = $n;
            match data.get(i + 1..i + 1 + n) {
                Some(s) => {
                    let mut val: u64 = 0;
                    for (k, &b) in s.iter().enumerate() {
                        val |= (b as u64) << (8 * k);
                    }
                    Some(val)
                }
                None => None,
            }
        }};
    }

    while i < data.len() {
        let op = data[i];
        match op {
            // PROTO: +1 operand byte.
            0x80 => {
                i += 2;
            }
            // FRAME: +8 operand bytes.
            0x95 => {
                i += 9;
            }
            // STOP.
            0x2e => break,

            // GLOBAL 'c': two newline-terminated lines (module, then name).
            0x63 => {
                let start = i + 1;
                let Some(nl1) = find_nl(data, start) else {
                    break;
                };
                let module = &data[start..nl1];
                let start2 = nl1 + 1;
                let Some(nl2) = find_nl(data, start2) else {
                    break;
                };
                let name = &data[start2..nl2];
                push_out!(module);
                push_out!(name);
                i = nl2 + 1;
            }

            // STACK_GLOBAL: pops two stack strings (module, name). Reconstruct
            // from the last two recorded string literals.
            0x93 => {
                let module = prev2.clone().unwrap_or_default();
                let name = prev1.clone().unwrap_or_default();
                push_out!(&module);
                push_out!(&name);
                i += 1;
            }

            // SHORT_BINSTRING 'U': 1-byte length + bytes.
            0x55 => {
                let Some(len) = read_le!(1) else { break };
                let s = i + 2;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }
            // BINSTRING 'T': 4-byte LE length + bytes.
            0x54 => {
                let Some(len) = read_le!(4) else { break };
                let s = i + 5;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }
            // STRING 'S': newline-terminated (repr-quoted) string.
            0x53 => {
                let start = i + 1;
                let Some(nl) = find_nl(data, start) else { break };
                let raw = &data[start..nl];
                record_str!(strip_quotes(raw));
                i = nl + 1;
            }

            // SHORT_BINUNICODE '\x8c': 1-byte len + utf8.
            0x8c => {
                let Some(len) = read_le!(1) else { break };
                let s = i + 2;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }
            // BINUNICODE 'X': 4-byte LE len + utf8.
            0x58 => {
                let Some(len) = read_le!(4) else { break };
                let s = i + 5;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }
            // BINUNICODE8 '\x8d': 8-byte LE len + utf8.
            0x8d => {
                let Some(len) = read_le!(8) else { break };
                let s = i + 9;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }
            // UNICODE 'V': newline-terminated.
            0x56 => {
                let start = i + 1;
                let Some(nl) = find_nl(data, start) else { break };
                record_str!(data[start..nl].to_vec());
                i = nl + 1;
            }

            // SHORT_BINBYTES 'C': 1-byte len + bytes.
            0x43 => {
                let Some(len) = read_le!(1) else { break };
                let s = i + 2;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }
            // BINBYTES 'B': 4-byte LE len + bytes.
            0x42 => {
                let Some(len) = read_le!(4) else { break };
                let s = i + 5;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }
            // BINBYTES8 '\x8e': 8-byte LE len + bytes.
            0x8e => {
                let Some(len) = read_le!(8) else { break };
                let s = i + 9;
                let Some(bytes) = data.get(s..s.saturating_add(len as usize)) else {
                    break;
                };
                record_str!(bytes.to_vec());
                i = s.saturating_add(len as usize);
            }

            // Ints / binints — skip operands only.
            0x4b => i += 2, // BININT1: +1
            0x4d => i += 3, // BININT2: +2
            0x4a => i += 5, // BININT: +4
            // LONG1 '\x8a': 1-byte len + bytes.
            0x8a => {
                let Some(len) = read_le!(1) else { break };
                // saturating: on a 32-bit target (wasm32) `i + 2 + len` could
                // overflow `usize` and panic under overflow-checks.
                i = i.saturating_add(2).saturating_add(len as usize);
                if i > data.len() {
                    break;
                }
            }
            // LONG4 '\x8b': 4-byte LE len + bytes.
            0x8b => {
                let Some(len) = read_le!(4) else { break };
                // saturating: `len` can be up to u32::MAX, so on a 32-bit target
                // `i + 5 + len` overflows `usize` and panics under overflow-checks.
                i = i.saturating_add(5).saturating_add(len as usize);
                if i > data.len() {
                    break;
                }
            }

            // Memo / put / get — skip operands.
            0x71 => i += 2, // BINPUT: +1
            0x72 => i += 5, // LONG_BINPUT: +4
            0x94 => i += 1, // MEMOIZE: +0
            0x68 => i += 2, // BINGET: +1
            0x6a => i += 5, // LONG_BINGET: +4

            // Opcodes with no operand.
            0x52 // REDUCE
            | 0x29 // EMPTY_TUPLE ')'
            | 0x5d // EMPTY_LIST ']'
            | 0x7d // EMPTY_DICT '}'
            | 0x85 // TUPLE1
            | 0x86 // TUPLE2
            | 0x87 // TUPLE3
            | 0x74 // TUPLE 't'
            | 0x65 // APPENDS 'e'
            | 0x61 // APPEND 'a'
            | 0x73 // SETITEM 's'
            | 0x75 // SETITEMS 'u'
            | 0x62 // BUILD 'b'
            | 0x30 // POP '0'
            | 0x32 // DUP '2'
            | 0x8f // EMPTY_SET
            | 0x90 // ADDITEMS
            | 0x91 // FROZENSET
            | 0x97 // NEXT_BUFFER
            | 0x98 // READONLY_BUFFER
            | 0x28 // MARK '('
            | 0x92 // NEWOBJ_EX
            | 0x81 // NEWOBJ
            | 0x88 // NEWTRUE
            | 0x89 // NEWFALSE
            | 0x4e // NONE 'N'
            | 0x31 // POP_MARK '1'
            => {
                i += 1;
            }

            // Unknown opcode: stop the walk (do not guess operand length).
            _ => break,
        }

        if out.len() >= cap {
            break;
        }
    }

    out
}

/// Find the index of the next `\n` at or after `start`, or None.
fn find_nl(data: &[u8], start: usize) -> Option<usize> {
    data.get(start..)
        .and_then(|s| s.iter().position(|&b| b == b'\n').map(|p| start + p))
}

/// Strip a single pair of surrounding ASCII quotes from a repr-quoted STRING
/// operand (e.g. `'os'` → `os`). Best-effort; returns the input unchanged if it
/// isn't quoted.
fn strip_quotes(raw: &[u8]) -> Vec<u8> {
    if raw.len() >= 2 {
        let first = raw[0];
        let last = raw[raw.len() - 1];
        if (first == b'\'' || first == b'"') && last == first {
            return raw[1..raw.len() - 1].to_vec();
        }
    }
    raw.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short_binunicode(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut v = vec![0x8c, bytes.len() as u8];
        v.extend_from_slice(bytes);
        v
    }

    #[test]
    fn global_reduce_pickle_surfaces_import_and_command() {
        // \x80\x04 + GLOBAL c posix\n system\n + SHORT_BINUNICODE "echo pwned"
        // + REDUCE + STOP.
        let mut pkl = vec![0x80, 0x04];
        pkl.push(0x63); // GLOBAL
        pkl.extend_from_slice(b"posix\n");
        pkl.extend_from_slice(b"system\n");
        pkl.extend_from_slice(&short_binunicode("echo pwned"));
        pkl.push(0x52); // REDUCE
        pkl.push(0x2e); // STOP

        assert!(is_aimodel(&pkl));

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::AiModel, &pkl, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "pickle-imports");
        let out = &entries[0].data;
        assert!(out.windows(5).any(|w| w == b"posix"), "posix not surfaced");
        assert!(
            out.windows(6).any(|w| w == b"system"),
            "system not surfaced"
        );
        assert!(
            out.windows(10).any(|w| w == b"echo pwned"),
            "command string not surfaced"
        );
    }

    #[test]
    fn stack_global_pickle_surfaces_import() {
        // \x80\x04 + SHORT_BINUNICODE "os" + SHORT_BINUNICODE "system"
        // + STACK_GLOBAL + STOP.
        let mut pkl = vec![0x80, 0x04];
        pkl.extend_from_slice(&short_binunicode("os"));
        pkl.extend_from_slice(&short_binunicode("system"));
        pkl.push(0x93); // STACK_GLOBAL
        pkl.push(0x2e); // STOP

        assert!(is_aimodel(&pkl));

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::AiModel, &pkl, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        let out = &entries[0].data;
        assert!(out.windows(2).any(|w| w == b"os"), "os not surfaced");
        assert!(
            out.windows(6).any(|w| w == b"system"),
            "system not surfaced"
        );
    }

    #[test]
    fn safetensors_header_surfaced() {
        let header = br#"{"__metadata__":{"x":"SAFETENSORS-MARKER"}}"#;
        let n = header.len() as u64;
        let mut data = n.to_le_bytes().to_vec();
        data.extend_from_slice(header);
        data.extend_from_slice(&[0u8; 16]); // opaque tensor bytes

        assert!(is_aimodel(&data));

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::AiModel, &data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "safetensors-header");
        assert!(
            entries[0]
                .data
                .windows(18)
                .any(|w| w == b"SAFETENSORS-MARKER"),
            "metadata marker not surfaced"
        );
    }

    #[test]
    fn truncated_pickle_does_not_panic() {
        // GLOBAL then a SHORT_BINUNICODE with a length byte but no data.
        let mut pkl = vec![0x80, 0x04];
        pkl.push(0x63);
        pkl.extend_from_slice(b"os\n");
        pkl.extend_from_slice(b"system\n");
        pkl.push(0x8c); // SHORT_BINUNICODE
        pkl.push(0x20); // claims 32 bytes...
        pkl.extend_from_slice(b"abc"); // ...but only 3 present, no STOP

        assert!(is_aimodel(&pkl));

        let mut budget = Budget::new(Limits::default());
        // Must not panic; emits at most what was parsed before the short read.
        let entries = extract(Format::AiModel, &pkl, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        let out = &entries[0].data;
        assert!(out.windows(2).any(|w| w == b"os"));
        assert!(out.windows(6).any(|w| w == b"system"));
        // The truncated string literal must not appear.
        assert!(!out.windows(3).any(|w| w == b"abc"));
    }

    #[test]
    fn non_aimodel_bytes_yield_nothing() {
        assert!(!is_aimodel(b"hello world, not a model"));
    }

    /// Regression (found by fuzzing): a length-prefixed opcode with a huge
    /// 8-byte length must not overflow `usize` when computing the slice end.
    /// BINUNICODE8 (0x8d) / BINBYTES8 (0x8e) carry a full u64 length.
    #[test]
    fn huge_length_prefix_does_not_overflow() {
        for opcode in [0x8du8, 0x8e] {
            let mut pkl = vec![0x80u8, 0x04, opcode];
            pkl.extend_from_slice(&u64::MAX.to_le_bytes()); // absurd length
            pkl.extend_from_slice(b"abc");
            let mut budget = Budget::new(Limits::default());
            // Must return cleanly (stop at the short read), never panic.
            let _ = extract(Format::AiModel, &pkl, &mut budget).unwrap();
        }
    }

    /// Regression: the LONG1 (0x8a) / LONG4 (0x8b) integer-skip opcodes compute
    /// the next cursor as `i + const + len`. LONG4 carries a 4-byte length up to
    /// `u32::MAX`; on a 32-bit target (wasm32) `i + 5 + len` overflows `usize`
    /// and panics under `overflow-checks`. Must return cleanly instead.
    #[test]
    fn long_opcode_huge_length_does_not_overflow() {
        // LONG4 with u32::MAX length.
        let mut pkl = vec![0x80u8, 0x04, 0x8b];
        pkl.extend_from_slice(&u32::MAX.to_le_bytes());
        pkl.extend_from_slice(b"abc");
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::AiModel, &pkl, &mut budget).unwrap();

        // LONG1 with 0xFF length.
        let mut pkl = vec![0x80u8, 0x04, 0x8a, 0xff];
        pkl.extend_from_slice(b"abc");
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::AiModel, &pkl, &mut budget).unwrap();
    }
}
