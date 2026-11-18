//! Python compiled-bytecode (`.pyc`) body surfacer.
//!
//! A `.pyc` file is a short, version-specific header followed by a *marshalled*
//! code object. That marshalled body holds the module's string constants
//! (`co_consts`) and the raw bytecode, which is exactly where an embedded
//! signature (e.g. a malicious string literal) lives. This handler does **not**
//! decode the marshal format; it simply surfaces the body bytes (everything past
//! the fixed header) as a single member so signatures match inside `.pyc` files.
//!
//! # Header size
//!
//! The pre-body header length depends on the Python version:
//!
//! * Python 3.7+, 16 bytes: `magic`, `bit_field`, `mtime`, `source_size`
//! * Python 3.3–3.6, 12 bytes: `magic`, `mtime`, `source_size`
//! * Python ≤ 3.2, 8 bytes: `magic`, `mtime`
//!
//! Rather than parse the version out of the magic, we strip the largest common
//! header (16 bytes, the 3.7+ case). For older files a few extra header bytes
//! remain at the front of the body, which is harmless for substring scanning:
//! the marshalled `co_consts`/bytecode we care about always sit further in.
//!
//! Detection (in `lib.rs`, feature-gated) is [`is_pyc`]: `\r\n` at offset 2 is
//! a weak magic, so the two bytes before it must be a number CPython has
//! written.

use crate::*;

/// The magic numbers of CPython's `.pyc` files, as the little-endian number
/// in the first two bytes. Source: the table "Known values" in CPython's
/// `Lib/importlib/_bootstrap_external.py` (up to 3.13) and
/// `Include/internal/pycore_magic_number.h` (from 3.14). Python 1.5 to 2.2
/// have one number per release, 2.3 to 2.7 run from 62011 to 62211, and 3.0
/// on from 3000: 3.15 is at 3650 to 3666 and, since 3.11, release 3.n starts
/// at 2900 + 50n, so up to 3.21 they stay below 4000.
const MAGICS: [std::ops::RangeInclusive<u16>; 7] = [
    20121..=20121,
    50428..=50428,
    50823..=50823,
    60202..=60202,
    60717..=60717,
    62011..=62211,
    3000..=3999,
];

/// Whether `data` opens like a `.pyc`: a number CPython has written, `\r\n`,
/// and the rest of the 16-byte header.
pub(crate) fn is_pyc(data: &[u8]) -> bool {
    data.len() >= PYC_HEADER_LEN
        && data[2..4] == *b"\r\n"
        && MAGICS
            .iter()
            .any(|m| m.contains(&u16::from_le_bytes([data[0], data[1]])))
}

/// Smallest safe header to strip before the marshalled body: the Python 3.7+
/// 16-byte header (`magic`, `bit_field`, `mtime`, `source_size`).
const PYC_HEADER_LEN: usize = 16;

/// Walk a `.pyc`: its code object, streamed from where it lies.
pub(crate) fn walk(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let members = stream_offsets(&mut source)?;
    crate::stream::stream_stored_ranges(src, budget, visit, crate::stream::Region::list(members))
}

/// Reader-based streaming: the single `pyc-code` member is the whole file past
/// the fixed header, streamed via seek+take with no buffering.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_pyc_body_contains_signature() {
        // A real CPython `.pyc` whose source embedded the EICAR string in a
        // string literal; the marshalled body carries that literal verbatim.
        let data = crate::unmask_fixture(include_bytes!("../../tests/fixtures/pyc/eicar.pyc.xor"));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pyc, &data, &mut budget).unwrap();
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
