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

use crate::Format;

/// Does `data` look like `fmt`?
///
/// Answers only for the magic-number formats listed below; anything else is
/// `false`, because "not recognised by a magic" is not the same claim as "not
/// this format" and the structural sniffs own that answer.
pub(crate) fn is(data: &[u8], fmt: Format) -> bool {
    let d = data;
    match fmt {
        // `**ACE**` at offset 7 — after the header's CRC-16, size, type, flags.
        Format::Ace => d.get(7..14) == Some(b"**ACE**".as_slice()),

        // LZ4 frame, the pre-1.5 legacy frame, or a skippable frame
        // (`0x184D2A50`..`5F`).
        Format::Lz4 => {
            d.len() > 7
                && (d.starts_with(&[0x04, 0x22, 0x4D, 0x18])
                    || d.starts_with(&[0x02, 0x21, 0x4C, 0x18])
                    || (d[0] & 0xF0 == 0x50 && d[1..4] == [0x2A, 0x4D, 0x18]))
        }

        // The `conectix` footer cookie. A fixed-disk image carries only the
        // trailing copy, so the head alone is not enough to look for.
        Format::Vhd => {
            d.len() >= 1024
                && (d.starts_with(b"conectix") || d[d.len() - 512..].starts_with(b"conectix"))
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
                    d.get(at..at + 8) == Some(&[0x06, 0, 0, 0, 0, 0, 0, 0][..])
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
                Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?) as u32)
            };
            let u32at = |o: usize| -> Option<u32> {
                Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
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
                            && size as u64 <= d.len() as u64,
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

        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A format this module does not speak for must answer `false` rather than
    /// something accidental — the structural sniffs own those.
    #[test]
    fn structural_formats_are_not_claimed_here() {
        for fmt in [Format::Arc, Format::Fat, Format::Partition, Format::Dmg] {
            assert!(!is(b"anything at all, really", fmt), "{fmt:?}");
        }
    }
}
