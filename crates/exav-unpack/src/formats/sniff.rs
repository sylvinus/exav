//! Container recognition — the single place a format is identified.
//!
//! Recognising a container and being able to open it are different questions,
//! so these live outside the per-format modules and outside their Cargo
//! features. When they were the same question a disabled format went
//! *undetected* rather than *unopenable*: a `.ace` in a build without `ace` got
//! a raw pattern scan over its compressed bytes, matched nothing, and came back
//! `OK`. Sniffing unconditionally lets [`crate::detect`] name it and the
//! dispatch report "format support not compiled in" instead.
//!
//! One entry point, [`is`], rather than a predicate per format: both callers ask
//! the same question — `detect` walking its precedence order, and each
//! extractor guarding its own entry — and a single `match` keeps them from
//! drifting apart.
//!
//! Everything here is a pure byte comparison, so it costs nothing and pulls no
//! dependency. Formats identified by a structural heuristic over a whole header
//! rather than a constant — `arc`, `fat`, `partition`, `sfx`, `dmg` — keep their
//! tests in their own modules and are not detected in a build that excludes
//! them.

use crate::{Format, Probe};

/// Does `data` look like `fmt`?
///
/// Answers only for the magic-number formats listed below; anything else is
/// `false`, because "not recognised by a magic" is not the same claim as "not
/// this format" and the structural sniffs own that answer.
pub(crate) fn is(data: &[u8], fmt: Format) -> bool {
    is_in(&Probe::whole(data), fmt)
}

/// [`is`] for the object `p` looks at.
pub(crate) fn is_in(p: &Probe, fmt: Format) -> bool {
    let d = p.head;
    match fmt {
        // `**ACE**` at offset 7 — after the header's CRC-16, size, type, flags.
        Format::Ace => d.get(7..14) == Some(b"**ACE**".as_slice()),

        // LZ4 frame, the pre-1.5 legacy frame, or a skippable frame
        // (`0x184D2A50`..`5F`), which Zstandard has as well: those that are
        // followed by a Zstandard frame are Zstandard's.
        Format::Lz4 => {
            d.len() > 7
                && (d.starts_with(&[0x04, 0x22, 0x4D, 0x18])
                    || d.starts_with(&[0x02, 0x21, 0x4C, 0x18])
                    || (d[0] & 0xF0 == 0x50
                        && d[1..4] == [0x2A, 0x4D, 0x18]
                        && !zstd_after_skippable(d)))
        }

        // The `conectix` footer cookie. A fixed-disk image carries only the
        // trailing copy, so the head alone is not enough to look for.
        Format::Vhd => {
            p.len >= 1024
                && (d.starts_with(b"conectix") || p.window(p.len - 512, 8).starts_with(b"conectix"))
        }

        // `compress(1)`: the magic plus a plausible maximum code width.
        Format::Lzw => {
            d.len() > 3 && d[..2] == [0x1F, 0x9D] && (9..=16).contains(&((d[2] & 0x1f) as u32))
        }

        // Classic StuffIt and StuffIt X. All at offset zero — these are
        // container magics, not markers that float.
        Format::StuffIt => [
            b"SIT!".as_slice(),
            b"SITD".as_slice(),
            b"StuffIt (c)".as_slice(),
            b"StuffIt!".as_slice(),
            b"StuffIt?".as_slice(),
        ]
        .iter()
        .any(|m| d.starts_with(m)),

        // An NTFS boot sector: OEM id, boot signature, and a real sector size.
        Format::Ntfs => {
            d.len() >= 512
                && d.get(3..11) == Some(b"NTFS    ".as_slice())
                && d.get(510..512) == Some(&[0x55, 0xAA][..])
                && matches!(u16::from_le_bytes([d[11], d[12]]), 512 | 1024 | 2048 | 4096)
        }

        // Long enough for its 72-byte header, and a version the format has.
        Format::Qcow2 => {
            d.len() > 72
                && d.starts_with(b"QFI\xfb")
                && matches!(u32::from_be_bytes([d[4], d[5], d[6], d[7]]), 2 | 3)
        }

        // A sparse VMDK, or the plain-text descriptor variant — whose extents
        // live in other files, so it is recognised in order to be reported.
        Format::Vmdk => {
            (d.len() > 512 && d.starts_with(b"KDMV")) || d.starts_with(b"# Disk DescriptorFile")
        }

        // Long enough to reach the second region table at 192 KiB.
        Format::Vhdx => d.len() > 192 * 1024 && d.starts_with(b"vhdxfile"),

        // Long enough for its 208-byte header.
        Format::Wim => d.len() > 208 && d.starts_with(b"MSWIM\0\0\0"),

        // The archive then carries `BLZ\x01` local headers and a `CLZ\x01`
        // central directory.
        Format::Alz => d.starts_with(b"ALZ\x01"),

        Format::Egg => d.starts_with(b"EGGA"),

        // HWP5 is an OLE2 compound file and reaches the OLE path instead, so
        // only v3 is named here.
        Format::Hwp3 => d.starts_with(b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05"),

        // Always a PE, carrying the loader magic or the setup-data string.
        Format::Inno => {
            d.starts_with(b"MZ") && {
                let w = &d[..d.len().min(4 * 1024 * 1024)];
                w.windows(6).any(|x| x == b"rDlPtS")
                    || w.windows(21).any(|x| x == b"Inno Setup Setup Data")
            }
        }

        // The installer's own header, then a fixed record 292 bytes on. The
        // string alone is far too common in an installer's resources to type on.
        Format::IshieldMsi => {
            const TAG: &[u8] = b"InstallShield\0";
            let w = &d[..d.len().min(4 * 1024 * 1024)];
            w.windows(TAG.len()).enumerate().any(|(i, x)| {
                x == TAG && {
                    let at = i + TAG.len() + 292;
                    crate::bytes::at(d, at, 8) == Some(&[0x06, 0, 0, 0, 0, 0, 0, 0][..])
                        // eight bytes of anything, then the trailing marker
                        && d.get(at + 16..at + 21) == Some(&[0, 0, 0, 0, 1][..])
                }
            })
        }

        Format::CryptFf => d.starts_with(&[0xB6, 0xB9, 0xAC, 0xAE, 0xFE, 0xFF, 0xFF, 0xFF]),

        // InstallShield's InstallScript cabinet — a different format from the
        // MSI variety above, and from Microsoft's own `.cab`.
        Format::IshieldCab => d.starts_with(b"ISc("),
        // The older InstallShield `.z` installer archive.
        //
        // The magic is confirmed against the header's own arithmetic rather
        // than against a version constant: the bytes at 4..12 are not a version
        // any reader validates, so pinning one would be a guess. `size` is the
        // archive's total length and the table of contents sits inside it, both
        // of which a coincidental byte-run will not satisfy.
        Format::IshieldZ => {
            let u16at = |o: usize| -> Option<u32> {
                Some(u16::from_le_bytes(crate::bytes::at(d, o, 2)?.try_into().ok()?) as u32)
            };
            let u32at = |o: usize| -> Option<u32> {
                Some(u32::from_le_bytes(
                    crate::bytes::at(d, o, 4)?.try_into().ok()?,
                ))
            };
            d.starts_with(&[0x13, 0x5D, 0x65, 0x8C])
                && (|| {
                    let files = u16at(12)?;
                    let size = u32at(18)?;
                    let toc = u32at(41)?;
                    let dirs = u16at(49)?;
                    Some(
                        files > 0
                            && dirs > 0
                            && toc >= 51
                            && toc < size
                            && size as u64 <= p.len as u64,
                    )
                })()
                .unwrap_or(false)
        }

        // The ext superblock begins at 1024; its magic is 16 bytes further in.
        // Nothing at offset 0 identifies the image, which is why an ext image
        // otherwise types as unknown and gets a raw scan.
        Format::Ext => d.get(1080..1082) == Some(&[0x53, 0xEF][..]),

        Format::Lrzip => d.starts_with(b"LRZI"),

        // ZOO's identifying tag is at 20, not 0 — the leading "ZOO ?.?? Archive."
        // text is conventional and may be anything. The version byte at 32 must
        // be non-zero, which is what keeps the 4-byte tag from matching noise.
        Format::Zoo => {
            d.get(20..24) == Some(&0xFDC4_A7DCu32.to_le_bytes()[..])
                && d.get(32).is_some_and(|&b| b > 0)
        }

        // AppleSingle (0x00051600) and AppleDouble (0x00051607) share a
        // container shape, so one type covers both.
        Format::AppleSingle => {
            d.starts_with(&[0x00, 0x05, 0x16, 0x00]) || d.starts_with(&[0x00, 0x05, 0x16, 0x07])
        }

        Format::Lzma => lzma_alone_header(d),

        // The lead: magic, then the major version of the format (1 to 4).
        // The superblock's magic, in either byte order, and its 96 bytes.
        Format::Squashfs => d.len() >= 96 && (d.starts_with(b"hsqs") || d.starts_with(b"sqsh")),

        // The superblock's magic, in either byte order, and the signature
        // after it, at the start or 512 bytes in (room for boot code).
        Format::Cramfs => [0usize, 512].iter().any(|&at| {
            d.get(at..at.saturating_add(32)).is_some_and(|h| {
                (h.starts_with(&[0x45, 0x3D, 0xCD, 0x28])
                    || h.starts_with(&[0x28, 0xCD, 0x3D, 0x45]))
                    && h.get(16..32) == Some(b"Compressed ROMFS".as_slice())
            })
        }),

        // The eight bytes the first line of a romfs image is, and the file
        // system's name after it.
        Format::Romfs => d.len() >= 32 && d.starts_with(b"-rom1fs-"),

        // The superblock is 1024 bytes in, with its magic first (little-endian).
        Format::Erofs => d.get(1024..1028) == Some(&[0xE2, 0xE1, 0xF5, 0xE0][..]),

        Format::Rpm => {
            d.len() >= 96 && d.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) && (1..=4).contains(&d[4])
        }

        _ => false,
    }
}

/// Whether the start of a file is the header of an LZMA-alone stream, as the xz
/// utilities decide it when they are not told: valid properties, a dictionary
/// size of the form 2^n or 2^n + 2^(n-1) (what the encoders write), a size that
/// is unknown or below 256 GiB, and the zero byte every range coder starts
/// with. A file that is not LZMA passes by chance about once in 10^10, which
/// matters because this runs against every file.
fn lzma_alone_header(d: &[u8]) -> bool {
    let Some(h) = d.get(..14) else {
        return false;
    };
    let dict = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
    let size = u64::from_le_bytes(h[5..13].try_into().unwrap());
    h[0] < 9 * 5 * 5
        && (dict == u32::MAX
            || (12..=31).any(|n| dict == 1 << n || (n > 12 && dict == (1 << n) + (1 << (n - 1)))))
        && (size == u64::MAX || size < 1 << 38)
        && h[13] == 0
}

/// Whether a file that is no other format is a ZIP that does not start with a
/// local header: behind a script line (a Python zipapp), padding or a stub, or
/// with the marker of a spanned archive in front. Readers find a ZIP by its end
/// record, so these open everywhere. The end record (and its comment) may be
/// followed by padding, the directory must end where it starts, and the first
/// entry's local header must be where its offset puts it, counted from the
/// archive's start or from the file's. ZIP64 is not followed.
#[cfg(feature = "zip")]
pub(crate) fn prefixed_zip(p: &Probe) -> bool {
    const EOCD: usize = 22;
    if p.len < EOCD + 30 {
        return false;
    }
    let from = p.len.saturating_sub(EOCD + usize::from(u16::MAX));
    let tail = p.window(from, p.len - from);
    let Some(rel) = tail.windows(4).rposition(|w| w == b"PK\x05\x06") else {
        return false;
    };
    let Some(end) = tail.get(rel..rel + EOCD) else {
        return false;
    };
    let eocd = from + rel;
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([end[at], end[at + 1]]));
    let u32_at = |at: usize| u32::from_le_bytes([end[at], end[at + 1], end[at + 2], end[at + 3]]);
    let (entries, cd_size, cd_off) = (u16_at(10), u32_at(12), u32_at(16));
    if eocd + EOCD + u16_at(20) > p.len
        || entries == 0
        || entries == 0xFFFF
        || cd_size == u32::MAX
        || cd_off == u32::MAX
    {
        return false;
    }
    let Some(cd_start) = eocd.checked_sub(cd_size as usize) else {
        return false;
    };
    let Some(prefix) = cd_start.checked_sub(cd_off as usize) else {
        return false;
    };
    let entry = p.window(cd_start, 46);
    if !entry.starts_with(b"PK\x01\x02") || entry.len() < 46 {
        return false;
    }
    let local = u32::from_le_bytes([entry[42], entry[43], entry[44], entry[45]]) as usize;
    p.window(prefix.saturating_add(local), 4)
        .starts_with(b"PK\x03\x04")
}

/// Whether `d` is skippable frames (`0x184D2A50`..`5F`, a length, that many
/// bytes) and then a Zstandard frame. A file may open with a skippable frame
/// and be LZ4 or Zstandard; only what follows says which.
pub(crate) fn zstd_after_skippable(d: &[u8]) -> bool {
    let mut rest = d;
    // A few frames is all a real file has; the bound keeps a long run cheap.
    for _ in 0..16 {
        match rest {
            [m, 0x2A, 0x4D, 0x18, a, b, c, e, tail @ ..] if m & 0xF0 == 0x50 => {
                let len = u32::from_le_bytes([*a, *b, *c, *e]) as usize;
                match tail.get(len..) {
                    Some(next) => rest = next,
                    None => return false,
                }
            }
            _ => return rest.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]),
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_skippable_frame_is_lz4_or_zstd_by_what_follows() {
        let skip = [&[0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0][..], b"xyz"].concat();
        let zstd = [&skip[..], &[0x28, 0xB5, 0x2F, 0xFD, 0, 0, 0, 0][..]].concat();
        let lz4 = [&skip[..], &[0x04, 0x22, 0x4D, 0x18, 0, 0, 0, 0][..]].concat();
        assert!(!is(&zstd, Format::Lz4));
        assert!(zstd_after_skippable(&zstd));
        assert!(is(&lz4, Format::Lz4));
        assert!(!zstd_after_skippable(&lz4));
        // Skippable frames and nothing after: LZ4 as before.
        let only = [&skip[..], &[0; 8][..]].concat();
        assert!(is(&only, Format::Lz4));
    }

    #[test]
    fn each_format_accepts_its_own_magic() {
        let cases: Vec<(Format, Vec<u8>)> = vec![
            (Format::Ace, [&[0u8; 7][..], b"**ACE**", &[0; 16]].concat()),
            (
                Format::Lz4,
                [&[0x04, 0x22, 0x4D, 0x18][..], &[0; 8]].concat(),
            ),
            (
                Format::Lz4,
                [&[0x02, 0x21, 0x4C, 0x18][..], &[0; 8]].concat(),
            ),
            (
                Format::Lz4,
                [&[0x50, 0x2A, 0x4D, 0x18][..], &[0; 8]].concat(),
            ),
            (Format::Lzw, b"\x1f\x9d\x90rest".to_vec()),
            (Format::StuffIt, b"SIT!rest".to_vec()),
            (
                Format::StuffIt,
                b"StuffIt (c)1997-2011 Smith Micro Software".to_vec(),
            ),
            (
                Format::Qcow2,
                [b"QFI\xfb\x00\x00\x00\x03".as_slice(), &[0; 128]].concat(),
            ),
            (Format::Vmdk, [b"KDMV".as_slice(), &[0; 600]].concat()),
            (Format::Vmdk, b"# Disk DescriptorFile\nversion=1".to_vec()),
            (
                Format::Vhdx,
                [b"vhdxfile".as_slice(), &vec![0u8; 200 * 1024]].concat(),
            ),
            (Format::Wim, [b"MSWIM\0\0\0".as_slice(), &[0; 256]].concat()),
            (Format::Alz, b"ALZ\x01rest".to_vec()),
            (Format::Egg, b"EGGA\x01\x00rest".to_vec()),
            (
                Format::Hwp3,
                b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05more".to_vec(),
            ),
            (
                Format::Inno,
                [b"MZ".as_slice(), &[0; 64], b"rDlPtS", &[0; 16]].concat(),
            ),
        ];
        for (fmt, blob) in cases {
            assert!(is(&blob, fmt), "{fmt:?} rejected its own magic");
        }

        let mut vhd = vec![0u8; 1024];
        vhd[512..520].copy_from_slice(b"conectix");
        assert!(is(&vhd, Format::Vhd), "the footer copy is authoritative");

        let mut ntfs = vec![0u8; 512];
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        ntfs[11..13].copy_from_slice(&1024u16.to_le_bytes());
        ntfs[510..512].copy_from_slice(&[0x55, 0xAA]);
        assert!(is(&ntfs, Format::Ntfs));
    }

    /// These run against every file exav scans, so a false positive turns an
    /// ordinary document into a spurious UNSCANNABLE.
    #[test]
    fn ordinary_files_are_claimed_by_nothing() {
        for d in [
            &b""[..],
            &b"just some ordinary text\n"[..],
            &b"MZ\x90\x00\x03"[..],
            &b"\x7fELF\x02\x01\x01"[..],
            &b"PK\x03\x04"[..],
            &b"%PDF-1.7"[..],
        ] {
            for &fmt in crate::Format::ALL {
                assert!(!is(d, fmt), "{fmt:?} claimed {d:x?}");
            }
        }
    }

    #[test]
    fn near_misses_are_rejected() {
        assert!(!is(b"ALZ\x02other", Format::Alz));
        assert!(!is(b"EGG!", Format::Egg));
        assert!(!is(
            b"HWP Document File V5.00 \x1a\x01\x02\x03\x04\x05",
            Format::Hwp3
        ));
        assert!(!is(b"\x1f\x9d\xffrest", Format::Lzw), "width out of range");
        assert!(
            !is(&[&[0u8; 6][..], b"**ACE**"].concat(), Format::Ace),
            "magic at the wrong offset"
        );
        assert!(
            !is(
                &[b"QFI\xfb\x00\x00\x00\x09".as_slice(), &[0; 128]].concat(),
                Format::Qcow2
            ),
            "qcow version 9 does not exist"
        );
        // Right magic, too short to be the thing it claims.
        assert!(!is(b"vhdxfile", Format::Vhdx));
        assert!(!is(b"MSWIM\0\0\0", Format::Wim));
        assert!(!is(b"QFI\xfb", Format::Qcow2));
        assert!(!is(b"KDMV", Format::Vmdk));
    }

    fn lzma_header(props: u8, dict: u32, size: u64) -> Vec<u8> {
        let mut h = vec![props];
        h.extend_from_slice(&dict.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&[0, 1, 2]);
        h
    }

    #[test]
    fn a_header_of_lzma_utils_is_told() {
        let is_lzma = |h: &[u8]| is(h, Format::Lzma);
        // `lzma` writes 0x5D (lc 3, lp 0, pb 2) and a 2^n dictionary.
        assert!(is_lzma(&lzma_header(0x5D, 1 << 26, u64::MAX)));
        assert!(is_lzma(&lzma_header(0x5D, 3 << 23, 1234)));
        assert!(is_lzma(&lzma_header(0x5D, u32::MAX, 0)));
        // A properties byte past lc 8, lp 4, pb 4.
        assert!(!is_lzma(&lzma_header(225, 1 << 26, 1)));
        // A dictionary that is not 2^n or 2^n + 2^(n-1), or is below 4 KiB.
        assert!(!is_lzma(&lzma_header(0x5D, (1 << 26) + 1, 1)));
        assert!(!is_lzma(&lzma_header(0x5D, 1 << 11, 1)));
        // A size of 256 GiB or more that is not "unknown".
        assert!(!is_lzma(&lzma_header(0x5D, 1 << 26, 1 << 38)));
        // A range coder starts with a zero byte.
        let mut h = lzma_header(0x5D, 1 << 26, 1);
        h[13] = 1;
        assert!(!is_lzma(&h));
        assert!(!is_lzma(&h[..13]));
    }

    /// A format this module does not speak for must answer `false` rather than
    /// something accidental — the structural sniffs own those.
    #[test]
    fn structural_formats_are_not_claimed_here() {
        for fmt in [Format::Arc, Format::Fat, Format::Partition, Format::Dmg] {
            assert!(!is(b"anything at all, really", fmt), "{fmt:?}");
        }
    }
}
