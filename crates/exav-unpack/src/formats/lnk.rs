//! Windows Shell Link (`.lnk`, MS-SHLLINK) string extractor.
//!
//! A `.lnk` shortcut is a small binary container. Malware routinely abuses it as
//! a first-stage dropper: the visible file looks like a document, but the
//! shortcut's *command-line arguments*, *target path*, *working directory* and
//! *icon location* carry a `powershell -enc …` / `cmd /c …` payload. Antivirus
//! engines (ClamAV among them) scan those human-readable strings, so we carve
//! them out and emit them as one text member for the engine to match against.
//!
//! Layout (all integers little-endian), per [MS-SHLLINK]:
//!
//! ```text
//! ShellLinkHeader (fixed 0x4C bytes):
//!   u32  HeaderSize = 0x0000004C
//!   u8[16] LinkCLSID = 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
//!   u32  LinkFlags        (bit flags, LSB-first — see below)
//!   … FileAttributes, timestamps, size, icon index, show cmd, hotkey, reserved …
//! [ if HasLinkTargetIDList ] u16 IDListSize, then IDListSize bytes (skipped)
//! [ if HasLinkInfo ]         u32 LinkInfoSize, then LinkInfoSize-4 bytes (skipped)
//! StringData — for each present flag, in this order:
//!   HasName, HasRelativePath, HasWorkingDir, HasArguments, HasIconLocation:
//!     u16  CountCharacters
//!     char[CountCharacters]   (2 bytes each if IsUnicode, else 1)
//! ```
//!
//! Every field read is bounds-checked and every declared size is clamped to the
//! bytes actually present, so a truncated or hostile shortcut (extremely common)
//! can never panic or read out of bounds — parsing simply stops at EOF.

use crate::*;

/// The fixed 20-byte prefix every `.lnk` begins with: `HeaderSize` (0x0000004C,
/// little-endian) followed by the 16-byte LinkCLSID. Used both for detection and
/// as a guard here.
const LNK_MAGIC: [u8; 20] = [
    0x4C, 0x00, 0x00, 0x00, // HeaderSize = 0x0000004C
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // LinkCLSID …
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// The `ShellLinkHeader` is always exactly this many bytes; `LinkFlags` lives at
/// offset 20 and the variable-length sections begin right after.
const HEADER_SIZE: usize = 0x4C;

// LinkFlags bits (LSB-first), MS-SHLLINK §2.1.1.
const HAS_LINK_TARGET_ID_LIST: u32 = 1 << 0;
const HAS_LINK_INFO: u32 = 1 << 1;
const HAS_NAME: u32 = 1 << 2;
const HAS_RELATIVE_PATH: u32 = 1 << 3;
const HAS_WORKING_DIR: u32 = 1 << 4;
const HAS_ARGUMENTS: u32 = 1 << 5;
const HAS_ICON_LOCATION: u32 = 1 << 6;
const IS_UNICODE: u32 = 1 << 7;

pub(crate) fn extract_lnk<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let len = data.len();
    // The whole 0x4C header (which contains LinkFlags at offset 20) must be
    // present. A shorter buffer is a truncated shortcut — yield nothing.
    if len < HEADER_SIZE || !data.starts_with(&LNK_MAGIC) {
        return Ok(None);
    }

    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let unicode = flags & IS_UNICODE != 0;

    let mut pos = HEADER_SIZE;

    // --- LinkTargetIDList: u16 IDListSize, then IDListSize bytes (skipped). ---
    // IDListSize counts only the IDList that follows, not the size field itself.
    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        if pos + 2 > len {
            return Ok(None); // truncated before the size field — nothing to read
        }
        let id_list_size = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos = pos.saturating_add(2).saturating_add(id_list_size).min(len);
    }

    // --- LinkInfo: u32 LinkInfoSize, then skip the whole block. ---
    // LinkInfoSize is the size of the *entire* LinkInfo structure including the
    // 4-byte size field, so we advance by exactly LinkInfoSize. Guard against a
    // malformed size < 4 (which would leave us mid-field) by consuming at least
    // the size field.
    if flags & HAS_LINK_INFO != 0 {
        if pos + 4 > len {
            return Ok(None); // truncated before the size field
        }
        let link_info_size =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos = pos.saturating_add(link_info_size.max(4)).min(len);
    }

    // --- StringData: each present field is a u16 count then that many chars. ---
    let mut strings: Vec<String> = Vec::new();
    for &bit in &[
        HAS_NAME,
        HAS_RELATIVE_PATH,
        HAS_WORKING_DIR,
        HAS_ARGUMENTS,
        HAS_ICON_LOCATION,
    ] {
        if flags & bit == 0 {
            continue;
        }
        if pos + 2 > len {
            break; // truncated before this string's count — stop
        }
        let count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        // Bytes this string occupies (u16 count caps this at 128 KiB, so there
        // is no oversized allocation to guard beyond clamping to EOF).
        let needed = if unicode {
            count.saturating_mul(2)
        } else {
            count
        };
        let avail = len - pos;
        let take = needed.min(avail);
        let s = if unicode {
            let units: Vec<u16> = data[pos..pos + take]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(&data[pos..pos + take]).into_owned()
        };
        strings.push(s);
        pos = pos.saturating_add(take).min(len);
        if take < needed {
            break; // string ran past EOF — clamp and stop
        }
    }

    if strings.is_empty() {
        return Ok(None);
    }

    // Emit one text member holding every extracted string joined by newlines, so
    // signatures can match the command line / target path / working dir / icon.
    let joined = strings.join("\n").into_bytes();
    budget.count_entry()?;
    let cap = budget.reserve()?;
    if joined.len() as u64 > cap {
        return Err(LimitHit::new("lnk strings exceed budget".to_string()));
    }
    budget.commit(joined.len() as u64);
    if let Some(r) = visit(Entry::new("lnk-strings".to_string(), joined), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ASCII `.lnk`: header + LinkFlags with HasRelativePath and
    /// HasArguments set, no TargetIDList/LinkInfo, then the two StringData fields
    /// (RelativePath precedes Arguments in the on-disk order).
    fn minimal_lnk() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&LNK_MAGIC); // HeaderSize + LinkCLSID (20 bytes)
        let flags = HAS_RELATIVE_PATH | HAS_ARGUMENTS;
        out.extend_from_slice(&flags.to_le_bytes()); // LinkFlags at offset 20
        out.resize(HEADER_SIZE, 0); // zero-fill the rest of the 0x4C header

        let rel: &[u8] = b".\\payload.exe";
        out.extend_from_slice(&(rel.len() as u16).to_le_bytes());
        out.extend_from_slice(rel);

        let args: &[u8] = b"/c powershell MALWARETEST -enc AAAA";
        out.extend_from_slice(&(args.len() as u16).to_le_bytes());
        out.extend_from_slice(args);
        out
    }

    #[test]
    fn extracts_arguments_string() {
        let blob = minimal_lnk();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Lnk, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "lnk-strings");
        let text = String::from_utf8_lossy(&entries[0].data);
        assert!(text.contains("MALWARETEST"), "got: {text}");
        assert!(text.contains("payload.exe"), "got: {text}");
    }

    #[test]
    fn eicar_fixture_yields_eicar_string() {
        // Real EICAR-in-a-shortcut sample: the EICAR test string lives in the
        // Name field (ASCII, IsUnicode not set).
        let blob = include_bytes!("../../tests/fixtures/lnk/eicar.lnk");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Lnk, blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        let text = String::from_utf8_lossy(&entries[0].data);
        assert!(text.contains("X5O!P%@AP"), "EICAR string not extracted");
    }

    #[test]
    fn real_samples_do_not_panic() {
        // Real in-the-wild malware shortcuts (Unicode, with TargetIDList +
        // LinkInfo). We only require that extraction terminates without a panic
        // or out-of-bounds read. The samples are real malware, so they are
        // gitignored (not committed) and read at runtime — the test skips any
        // that aren't present locally (fresh clone / CI). sha256 provenance is
        // in the dir's README.md.
        let names = [
            "real-malware-1.lnk",
            "real-malware-2.lnk",
            "real-malware-3.lnk",
        ];
        for name in names {
            let path = format!("{}/tests/fixtures/lnk/{name}", env!("CARGO_MANIFEST_DIR"));
            let Ok(blob) = std::fs::read(&path) else {
                continue;
            };
            let mut budget = Budget::new(Limits::default());
            // Must not panic; a well-formed sample yields at least one member.
            let _ = extract(Format::Lnk, &blob, &mut budget).unwrap();
        }
    }

    #[test]
    fn truncated_header_does_not_panic() {
        // Only the 20-byte magic is present — the full 0x4C header is missing.
        // Detection matches on the magic, but extraction must clamp and yield
        // nothing rather than read past the buffer.
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Lnk, &LNK_MAGIC, &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn oversized_string_count_is_clamped() {
        // A shortcut declaring a huge CountCharacters with almost no data must
        // clamp to EOF, not panic or allocate wildly.
        let mut blob = Vec::new();
        blob.extend_from_slice(&LNK_MAGIC);
        blob.extend_from_slice(&HAS_ARGUMENTS.to_le_bytes());
        blob.resize(HEADER_SIZE, 0);
        blob.extend_from_slice(&0xFFFFu16.to_le_bytes()); // claim 65535 chars
        blob.extend_from_slice(b"short"); // only 5 bytes present
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Lnk, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"short"); // clamped to EOF
    }
}
