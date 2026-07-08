//! Python compiled-bytecode (`.pyc`) body surfacer.
//!
//! A `.pyc` file is a short, version-specific header followed by a *marshalled*
//! code object. That marshalled body holds the module's string constants
//! (`co_consts`) and the raw bytecode — which is exactly where an embedded
//! signature (e.g. a malicious string literal) lives. This handler does **not**
//! decode the marshal format; it simply surfaces the body bytes (everything past
//! the fixed header) as a single member so signatures match inside `.pyc` files.
//!
//! # Header size
//!
//! The pre-body header length depends on the Python version:
//!
//! * Python 3.7+  — 16 bytes: `magic`, `bit_field`, `mtime`, `source_size`
//! * Python 3.3–3.6 — 12 bytes: `magic`, `mtime`, `source_size`
//! * Python ≤ 3.2 — 8 bytes: `magic`, `mtime`
//!
//! Rather than parse the version out of the magic, we strip the largest common
//! header (16 bytes, the 3.7+ case). For older files a few extra header bytes
//! remain at the front of the body, which is harmless for substring scanning —
//! the marshalled `co_consts`/bytecode we care about always sit further in.
//!
//! Detection (in `lib.rs`, feature-gated) is deliberately conservative — the
//! `\r\n` at offset 2 is a weak magic — so this runs only after every strong
//! binary magic has been ruled out.

use crate::*;

/// Smallest safe header to strip before the marshalled body: the Python 3.7+
/// 16-byte header (`magic`, `bit_field`, `mtime`, `source_size`).
const PYC_HEADER_LEN: usize = 16;

/// Reader-based streaming: the single `pyc-code` member is the whole file past
/// the fixed header — streamed via seek+take with no buffering.
pub(crate) fn stream_offsets<R: std::io::Read + std::io::Seek>(
    source: &mut R,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let len = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("pyc: {e}")))?;
    if len <= PYC_HEADER_LEN as u64 {
        return Ok(Vec::new());
    }
    Ok(vec![(
        "pyc-code".to_string(),
        PYC_HEADER_LEN as u64,
        len - PYC_HEADER_LEN as u64,
    )])
}

/// Emit the marshalled code body of a `.pyc` file (the whole file minus the
/// fixed 16-byte header) as a single `pyc-code` member. Bounds-checked; a file
/// shorter than the header (or with an empty body) yields no members.
pub(crate) fn extract_pyc<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Too short to hold a header + body: emit nothing (no panic).
    if data.len() < PYC_HEADER_LEN {
        return Ok(None);
    }
    let body = &data[PYC_HEADER_LEN..];
    if body.is_empty() {
        return Ok(None);
    }
    budget.count_entry()?;
    let cap = budget.reserve()?;
    if body.len() as u64 > cap {
        return Err(LimitHit::new("pyc body exceeds budget".to_string()));
    }
    let member = body.to_vec();
    budget.commit(member.len() as u64);
    if let Some(r) = visit(Entry::new("pyc-code".into(), member), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_pyc_body_contains_signature() {
        // A real CPython `.pyc` whose source embedded the EICAR string in a
        // string literal; the marshalled body carries that literal verbatim.
        let data = include_bytes!("../../tests/fixtures/pyc/eicar.pyc");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pyc, data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "pyc-code");
        assert!(
            entries[0].data.windows(9).any(|w| w == b"X5O!P%@AP"),
            "EICAR signature not found in surfaced .pyc body"
        );
    }

    #[test]
    fn synthetic_header_plus_body_surfaces_body() {
        let mut data = vec![0u8; PYC_HEADER_LEN];
        // Fill in a plausible 3.11 magic (bytes[2..4] == "\r\n").
        data[0] = 0xF3;
        data[1] = 0x0D;
        data[2] = 0x0D;
        data[3] = 0x0A;
        data.extend_from_slice(b"MALWARETEST body");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pyc, &data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"MALWARETEST body");
    }

    #[test]
    fn too_short_emits_nothing_and_does_not_panic() {
        let data = [0xF3, 0x0D, 0x0D, 0x0A, 0x00, 0x00]; // 6 bytes, < header
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pyc, &data, &mut budget).unwrap();
        assert!(entries.is_empty());
    }
}
