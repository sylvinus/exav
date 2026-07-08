//! Java `.class` constant-pool string surfacer.
//!
//! A compiled Java `.class` file begins with a fixed header
//! (`0xCAFEBABE`, `minor`/`major` version, `constant_pool_count`) followed by
//! the *constant pool* — a table that stores every class name, method name,
//! field name, type descriptor and string literal used by the class. All of
//! those human-readable names live in `CONSTANT_Utf8` entries, which is exactly
//! where a malware signature matches (e.g. a suspicious class/method name or an
//! embedded command string). This handler does **not** decode the full class
//! structure (methods, attributes, bytecode); it walks *only* the constant pool
//! and surfaces the concatenated `CONSTANT_Utf8` bytes as a single member so
//! signatures match inside `.class` files.
//!
//! # Robustness
//!
//! The crate is `#![forbid(unsafe_code)]` and this parser runs on hostile,
//! truncated and malformed input. Every read is bounds-checked; on any short or
//! invalid structure we stop parsing and emit whatever Utf8 bytes were collected
//! so far (or nothing). We never panic.

use crate::*;

/// The constant-pool tag for a UTF-8 string entry (JVM spec: `CONSTANT_Utf8`).
const TAG_UTF8: u8 = 1;

/// Surface every `CONSTANT_Utf8` entry of a Java `.class` file — concatenated
/// and newline-separated — as a single `java-class-strings` member. The output
/// is bounded by the budget cap as it is built. Truncated, malformed or hostile
/// input yields at most the bytes parsed before the fault, and never panics.
pub(crate) fn extract_javaclass<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Reserve the output budget up front so we can bound the collected Utf8
    // bytes as we walk the pool (mirrors pyc.rs: count_entry then reserve).
    budget.count_entry()?;
    let cap = budget.reserve()?;

    // Header: magic u32, minor u16, major u16, constant_pool_count u16 = 10 bytes.
    // A file shorter than the header cannot hold a constant pool: emit nothing.
    if data.len() < 10 {
        return Ok(None);
    }
    // We don't strictly require the 0xCAFEBABE magic to match (detection in
    // lib.rs already gated us here), but the pool count is what drives parsing.
    let pool_count = u16::from_be_bytes([data[8], data[9]]);
    // The pool is 1-indexed and holds `constant_pool_count - 1` entries. A count
    // of 0 (would underflow) or 1 (empty pool) means nothing to surface.
    if pool_count < 2 {
        return Ok(None);
    }
    let entries = pool_count - 1;

    let mut out: Vec<u8> = Vec::new();
    let mut pos = 10usize; // Cursor just past the header.
    let mut index: u16 = 1; // Current 1-indexed pool slot.

    'pool: while index <= entries {
        // Read the entry tag (1 byte).
        let tag = match data.get(pos) {
            Some(&t) => t,
            None => break, // Truncated before this entry: stop, emit so far.
        };
        pos += 1;

        // Number of trailing payload bytes for the fixed-size tags. Utf8 (1) is
        // variable-length and handled specially below; Long (5) and Double (6)
        // occupy two pool slots and so also need special index handling.
        let payload_len: usize = match tag {
            TAG_UTF8 => {
                // Utf8: u16 length, then `length` raw (modified-UTF-8) bytes.
                let len_bytes = match data.get(pos..pos + 2) {
                    Some(b) => b,
                    None => break, // Truncated length field.
                };
                let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
                pos += 2;
                let bytes = match data.get(pos..pos + len) {
                    Some(b) => b,
                    None => break, // Truncated string body.
                };
                pos += len;
                // Bound the running output by the reserved cap. If appending this
                // string (plus its newline separator) would exceed the cap, stop
                // and emit what we have — treat the cap as a hard limit.
                let projected = out.len() as u64 + bytes.len() as u64 + 1;
                if projected > cap {
                    break;
                }
                out.extend_from_slice(bytes);
                out.push(b'\n');
                index += 1;
                continue;
            }
            3 => 4,  // Integer
            4 => 4,  // Float
            5 => 8,  // Long — consumes two slots
            6 => 8,  // Double — consumes two slots
            7 => 2,  // Class
            8 => 2,  // String
            9 => 4,  // Fieldref
            10 => 4, // Methodref
            11 => 4, // InterfaceMethodref
            12 => 4, // NameAndType
            15 => 3, // MethodHandle
            16 => 2, // MethodType
            17 => 4, // Dynamic
            18 => 4, // InvokeDynamic
            19 => 2, // Module
            20 => 2, // Package
            // Unknown tag → malformed pool. Stop and emit what we collected.
            _ => break 'pool,
        };

        // Skip the fixed payload, bounds-checked.
        match data.get(pos..pos + payload_len) {
            Some(_) => pos += payload_len,
            None => break, // Truncated payload: stop, emit so far.
        }

        // Long and Double each occupy two constant-pool slots.
        if tag == 5 || tag == 6 {
            index = index.saturating_add(2);
        } else {
            index += 1;
        }
    }

    if out.is_empty() {
        return Ok(None);
    }
    budget.commit(out.len() as u64);
    if let Some(r) = visit(Entry::new("java-class-strings".into(), out), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push a `CONSTANT_Utf8` entry (tag 1, u16 length, raw bytes) into `buf`.
    fn push_utf8(buf: &mut Vec<u8>, s: &[u8]) {
        buf.push(TAG_UTF8);
        buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
        buf.extend_from_slice(s);
    }

    /// Build a minimal valid `.class`: header + a constant pool holding the
    /// given number of usable slots. Caller supplies the pool-entry bytes and
    /// the total slot count consumed (Long/Double count as two).
    fn build_class(pool_slots: u16, pool_bytes: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0xCAFEBABEu32.to_be_bytes()); // magic
        data.extend_from_slice(&0u16.to_be_bytes()); // minor
        data.extend_from_slice(&52u16.to_be_bytes()); // major (Java 8)
                                                      // constant_pool_count = slots + 1 (1-indexed, count is entries + 1).
        data.extend_from_slice(&(pool_slots + 1).to_be_bytes());
        data.extend_from_slice(pool_bytes);
        data
    }

    #[test]
    fn surfaces_utf8_including_marker_across_long_slot() {
        let mut pool = Vec::new();
        // Slot 1: Utf8 marker.
        push_utf8(&mut pool, b"EICAR-JAVA-MARKER");
        // Slots 2 & 3: Long (tag 5, 8 payload bytes) — consumes two slots.
        pool.push(5);
        pool.extend_from_slice(&0x0102030405060708u64.to_be_bytes());
        // Slot 4: another Utf8, to prove parsing resumed correctly after the
        // two-slot Long skip.
        push_utf8(&mut pool, b"java/lang/Runtime");

        // Total slots consumed: 1 (Utf8) + 2 (Long) + 1 (Utf8) = 4.
        let data = build_class(4, &pool);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::JavaClass, &data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "java-class-strings");
        assert!(
            entries[0]
                .data
                .windows(b"EICAR-JAVA-MARKER".len())
                .any(|w| w == b"EICAR-JAVA-MARKER"),
            "marker not surfaced from constant pool"
        );
        // Both Utf8 strings present, newline-separated.
        assert!(
            entries[0]
                .data
                .windows(b"java/lang/Runtime".len())
                .any(|w| w == b"java/lang/Runtime"),
            "post-Long Utf8 not surfaced (two-slot skip broken)"
        );
    }

    #[test]
    fn truncated_header_emits_nothing_and_does_not_panic() {
        let data = [0xCA, 0xFE, 0xBA]; // 3 bytes, < 10-byte header
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::JavaClass, &data, &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn pool_count_past_eof_does_not_panic() {
        // Claim 1000 pool slots but provide only one truncated Utf8 entry.
        let mut data = Vec::new();
        data.extend_from_slice(&0xCAFEBABEu32.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&52u16.to_be_bytes());
        data.extend_from_slice(&1001u16.to_be_bytes()); // count => 1000 entries
                                                        // One complete Utf8, then EOF mid-pool.
        push_utf8(&mut data, b"present");
        data.push(TAG_UTF8); // dangling tag, no length/body follows

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::JavaClass, &data, &mut budget).unwrap();
        // At most the one fully-parsed string is surfaced; no panic.
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .data
            .windows(b"present".len())
            .any(|w| w == b"present"));
    }

    #[test]
    fn unknown_tag_stops_parsing() {
        let mut pool = Vec::new();
        push_utf8(&mut pool, b"before");
        pool.push(200); // invalid tag
        push_utf8(&mut pool, b"after"); // must NOT be surfaced
        let data = build_class(3, &pool);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::JavaClass, &data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].data.windows(6).any(|w| w == b"before"));
        assert!(
            !entries[0].data.windows(5).any(|w| w == b"after"),
            "parsing should have stopped at the unknown tag"
        );
    }

    #[test]
    fn empty_pool_emits_nothing() {
        let data = build_class(0, &[]); // constant_pool_count == 1
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::JavaClass, &data, &mut budget).unwrap();
        assert!(entries.is_empty());
    }
}
