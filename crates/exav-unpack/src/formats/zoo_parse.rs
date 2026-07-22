//! ZOO archive structures: the archive header and the directory-entry chain.
//!
//! Vendored and adapted from the `unarc-rs` crate (MIT OR Apache-2.0) — see
//! `NOTICE` — exactly as `formats/arj_parse/` was, and for the same reason:
//! depending on that crate directly drags in a second `zip` with its *default*
//! features, and Cargo's feature unification then turns on the `zip` crate's own
//! LZMA/bzip2/deflate64 decoders inside exav. Those bypass exav's per-member
//! budget, and the ZIP-codec suite caught it immediately.
//!
//! Adapted: exav's own error handling, the unused DOS timestamp and version
//! fields dropped, and the variable-length part of a directory entry (long
//! filename, directory name) actually read — upstream declares those fields and
//! never fills them.

/// Redundancy tag repeated at the start of the header and of every entry.
pub(crate) const ZOO_TAG: u32 = 0xFDC4_A7DC;
const TEXT: &[u8; 17] = b"ZOO 2.10 Archive.";
/// The header text field is padded to this length.
const SIZ_TEXT: usize = 20;
pub(crate) const ZOO_HEADER_SIZE: usize = SIZ_TEXT + 4 + 22;

/// Size of the DOS 8.3 filename field.
const FNAMESIZE: usize = 13;
pub(crate) const DIRENT_HEADER_SIZE: usize = 5   // tag + dir_type
    + 1                                          // compression method
    + 8                                          // offsets
    + 24                                         // through cmt_size
    + FNAMESIZE
    + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Stored,
    /// LZD — a 13-bit LZW variant, little-endian, 8-bit initial code size.
    Lzw,
    /// LZH — Rahul Dhesi's own, which is LHA's `lh5` on the wire despite
    /// sharing nothing else with LHA.
    Lh5,
    Unknown(u8),
}

impl From<u8> for Method {
    fn from(v: u8) -> Self {
        match v {
            0 => Method::Stored,
            1 => Method::Lzw,
            2 => Method::Lh5,
            _ => Method::Unknown(v),
        }
    }
}

fn u8_at(b: &[u8], off: usize) -> Option<u8> {
    b.get(off).copied()
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// A NUL-terminated name field, decoded lossily: a name that is not valid UTF-8
/// is still a name a `.cdb` signature may match on, and dropping it would lose
/// the member entirely.
fn name_at(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub(crate) struct Header {
    /// Where the directory-entry chain starts.
    pub start: u32,
}

impl Header {
    pub(crate) fn parse(b: &[u8]) -> Option<Header> {
        if !b.starts_with(TEXT) || u32_at(b, SIZ_TEXT)? != ZOO_TAG {
            return None;
        }
        Some(Header {
            start: u32_at(b, SIZ_TEXT + 4)?,
        })
    }
}

pub(crate) struct DirEntry {
    pub method: Method,
    /// Offset of the next directory entry; 0 ends the chain.
    pub next: u32,
    /// Offset of this member's data.
    pub offset: u32,
    pub crc16: u16,
    pub org_size: u32,
    pub size_now: u32,
    /// The DOS 8.3 name.
    pub name: String,
    /// Total length of the variable part that follows the fixed header.
    pub var_dir_len: u8,
    pub namlen: u8,
    pub dirlen: u8,
}

impl DirEntry {
    /// Parse the fixed part of a directory entry.
    pub(crate) fn parse(b: &[u8]) -> Option<DirEntry> {
        if u32_at(b, 0)? != ZOO_TAG {
            return None;
        }
        // 4: tag, 4: dir_type, 5: method, 6: next, 10: offset, 14: date/time,
        // 18: crc16, 20: org_size, 24: size_now, 28..31: versions/deleted/struc,
        // 32: comment, 36: cmt_size, 38: 8.3 name.
        //
        // The `deleted` byte at 30 is deliberately not read: ZOO leaves a
        // deleted member's bytes in the archive, and a scanner wants them. See
        // `formats/zoo.rs`.
        let name_off = 38;
        Some(DirEntry {
            method: Method::from(u8_at(b, 5)?),
            next: u32_at(b, 6)?,
            offset: u32_at(b, 10)?,
            crc16: u16_at(b, 18)?,
            org_size: u32_at(b, 20)?,
            size_now: u32_at(b, 24)?,
            name: name_at(b.get(name_off..name_off + FNAMESIZE)?),
            var_dir_len: u8_at(b, name_off + FNAMESIZE)?,
            namlen: u8_at(b, name_off + FNAMESIZE + 6)?,
            dirlen: u8_at(b, name_off + FNAMESIZE + 7)?,
        })
    }

    /// The member's full path, taking the long filename and directory name from
    /// `var` — the variable-length part that follows the fixed header — when
    /// they are there.
    ///
    /// Conservative by construction: anything that does not fit inside the
    /// declared `var_dir_len` falls back to the 8.3 name rather than reading
    /// whatever happens to be next in the file.
    pub(crate) fn path(&self, var: &[u8]) -> String {
        let n = self.namlen as usize;
        let d = self.dirlen as usize;
        let want = n + d;
        if want == 0 || want > var.len() || want > self.var_dir_len as usize {
            return self.name.clone();
        }
        let long = name_at(&var[..n]);
        let dir = name_at(&var[n..n + d]);
        let base = if long.is_empty() {
            self.name.clone()
        } else {
            long
        };
        if dir.is_empty() {
            base
        } else {
            format!("{}/{}", dir.trim_end_matches(['/', '\\']), base)
        }
    }
}

/// CRC-16/ARC over a member's decoded bytes — the check ZOO itself records, and
/// the only thing that says a decode was right rather than merely plausible.
pub(crate) fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_arc_matches_the_published_check_value() {
        // The CRC-16/ARC catalogue entry: "123456789" -> 0xBB3D. Without this
        // the CRC check below would happily "verify" every decode against a
        // wrong polynomial.
        assert_eq!(crc16_arc(b"123456789"), 0xBB3D);
    }

    #[test]
    fn a_variable_part_that_does_not_fit_falls_back_to_the_short_name() {
        let e = DirEntry {
            method: Method::Stored,
            next: 0,
            offset: 0,
            crc16: 0,
            org_size: 0,
            size_now: 0,
            name: "SHORT.TXT".to_string(),
            var_dir_len: 4,
            namlen: 200,
            dirlen: 200,
        };
        assert_eq!(
            e.path(b"tiny"),
            "SHORT.TXT",
            "a declared length longer than the data must not read past it"
        );
    }
}
