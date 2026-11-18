//! Container recognition: the single place a format is identified.
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
//! the same question (`detect` walking its precedence order, and each
//! extractor guarding its own entry), and a single `match` keeps them from
//! drifting apart.
//!
//! Everything here is a pure byte comparison, so it costs nothing and pulls no
//! dependency. Formats identified by a structural heuristic over a whole header
//! rather than a constant (`arc`, `fat`, `partition`, `sfx`, `dmg`) keep their
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

/// Which header an InstallShield installer starts with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IshieldHeader {
    /// `InstallShield\0`, records with a 260-byte name (InstallShield 2009 to 2011).
    Msi,
    /// `ISSetupStream\0`, records with a UTF-16 name (2015 and later).
    Stream,
}

/// Where the header of an InstallShield installer starts in `d`, in its first
/// 4 MiB, and which kind it is. The string alone is far too common in an
/// installer's resources to type on, so a header counts only with a record
/// that fits after it:
///
/// - `InstallShield\0`: 292 bytes on, the record of a file that is coded and
///   inflated (flags 6 and 0, then the inflate word);
/// - `ISSetupStream\0`: a count that is not zero, a type of 1 to 4, and a first
///   record whose name is an even number of bytes, up to 260 UTF-16 units of
///   printable characters, and whose flags are bits 1 to 4 only.
pub(crate) fn ishield_msi_at(d: &[u8]) -> Option<(usize, IshieldHeader)> {
    const TAG: &[u8] = b"InstallShield\0";
    const STREAM: &[u8] = b"ISSetupStream\0";
    let w = &d[..d.len().min(4 * 1024 * 1024)];
    let msi = memchr::memmem::find_iter(w, TAG)
        .find(|&i| {
            let at = i + TAG.len() + 292;
            crate::bytes::at(d, at, 8) == Some(&[0x06, 0, 0, 0, 0, 0, 0, 0][..])
                // eight bytes of anything, then the trailing marker
                && crate::bytes::at(d, at + 16, 5) == Some(&[0, 0, 0, 0, 1][..])
        })
        .map(|i| (i, IshieldHeader::Msi));
    let stream = memchr::memmem::find_iter(w, STREAM)
        .find(|&i| stream_header_holds(d, i))
        .map(|i| (i, IshieldHeader::Stream));
    match (msi, stream) {
        (Some(m), Some(s)) => Some(if m.0 <= s.0 { m } else { s }),
        (m, s) => m.or(s),
    }
}

/// Whether the `ISSetupStream\0` at `at` in `d` has the header and first record
/// of an installer.
fn stream_header_holds(d: &[u8], at: usize) -> bool {
    let Some(h) = crate::bytes::at(d, at, 46) else {
        return false;
    };
    let count = u16::from_le_bytes([h[14], h[15]]);
    let kind = u32::from_le_bytes([h[16], h[17], h[18], h[19]]);
    if count == 0 || !(1..=4).contains(&kind) {
        return false;
    }
    let skip = if kind == 4 { 24 } else { 0 };
    let Some(r) = crate::bytes::at(d, at + 46, 24 + skip) else {
        return false;
    };
    let name_len = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as usize;
    let flags = u32::from_le_bytes([r[4], r[5], r[6], r[7]]);
    if !(2..=520).contains(&name_len) || !name_len.is_multiple_of(2) || flags & !0x1e != 0 {
        return false;
    }
    let Some(name) = crate::bytes::at(d, at + 46 + 24 + skip, name_len) else {
        return false;
    };
    name.as_chunks::<2>()
        .0
        .iter()
        .all(|c| u16::from_le_bytes(*c) >= 0x20)
}

/// [`is`] for the object `p` looks at.
pub(crate) fn is_in(p: &Probe, fmt: Format) -> bool {
    let d = p.head;
    match fmt {
        // `**ACE**` at offset 7, after the header's CRC-16, size, type, flags.
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

        // Classic StuffIt and StuffIt X. All at offset zero: these are
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

        // A sparse VMDK, or the plain-text descriptor variant, whose extents
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

        // A PE whose resource RCDATA 11111 is a loader table, as Setup finds
        // it: wherever the executable has its resources, not within some
        // number of bytes of its start. Before 5.1.5, the table the header at
        // 0x30 points at.
        Format::Inno => {
            let window = |off, len| p.window(off, len);
            d.starts_with(b"MZ")
                && (crate::pe_resource::has_inno_loader(&window)
                    || crate::pe_resource::has_old_inno_loader(&window))
        }

        // The installer's own header, then a record that fits it: see
        // [`ishield_msi_at`].
        Format::IshieldMsi => ishield_msi_at(d).is_some(),

        Format::CryptFf => d.starts_with(&[0xB6, 0xB9, 0xAC, 0xAE, 0xFE, 0xFF, 0xFF, 0xFF]),

        // InstallShield's InstallScript cabinet: a different format from the
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

        // The ext superblock begins at 1024; its magic is 56 bytes further in.
        // Nothing at offset 0 identifies the image, which is why an ext image
        // otherwise types as unknown and gets a raw scan. Two bytes of magic
        // are not enough to type on: the fields around them are checked.
        Format::Ext => d
            .get(1024..2048)
            .is_some_and(super::ext_super::is_superblock),

        Format::Lha => lha_header(d),

        Format::Lrzip => d.starts_with(b"LRZI"),

        // ZOO's identifying tag is at 20, not 0: the leading "ZOO ?.?? Archive."
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

        Format::Lzma => lzma_alone_header(d) && starts_decodable(d),

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

/// Whether the start of a file is the first header of an LHA archive: a method
/// id between dashes (`-lh5-`, `-lzs-`, `-pm2-`), and the fields of the header
/// level in the byte at 20. Levels 0 and 1 give the size of the header and the
/// sum of its bytes, which must hold; levels 2 and 3 give its total, which the
/// chain of extended headers after the fixed part must end on. Layouts: the
/// LHA header documentation and delharc's parser (MIT).
fn lha_header(d: &[u8]) -> bool {
    if d.len() < 24
        || d[2] != b'-'
        || d[6] != b'-'
        || !matches!(d[3], b'l' | b'p')
        || !d[4..6].iter().all(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    let size = |at: usize, width: usize| {
        d.get(at..at + width).map(|b| {
            b.iter()
                .rev()
                .fold(0usize, |acc, &x| (acc << 8) | usize::from(x))
        })
    };
    // The end of the chain of extended headers that starts at `at`, the size
    // of the first one being `first`; each ends with the size of the next
    // (`width` bytes), and a size of zero ends the chain.
    let chain = |mut at: usize, mut next: usize, width: usize| {
        while next != 0 {
            let end = at.checked_add(next)?;
            if next <= width || end > d.len() {
                return None;
            }
            next = size(end - width, width)?;
            at = end;
        }
        Some(at)
    };
    match d[20] {
        level @ (0 | 1) => {
            let (header, name) = (usize::from(d[0]), usize::from(d[21]));
            let sized = if level == 0 {
                header == 22 + name
            } else {
                header >= 25 + name
            };
            sized
                && d.get(2..2 + header)
                    .is_some_and(|b| b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) == d[1])
        }
        2 => {
            let total = size(0, 2).unwrap_or(0);
            let end = size(24, 2).and_then(|first| chain(26, first, 2));
            total >= 26 && end.is_some_and(|e| e == total || e + 1 == total)
        }
        3 => {
            let total = size(24, 4).unwrap_or(0);
            let end = size(28, 4).and_then(|first| chain(32, first, 4));
            size(0, 2) == Some(4) && total >= 32 && end == Some(total)
        }
        _ => false,
    }
}

/// Whether the start of a file is the header of an LZMA-alone stream, as the xz
/// utilities decide it when they are not told: valid properties, a dictionary
/// size of the form 2^n or 2^n + 2^(n-1) (what the encoders write), a size that
/// is unknown or below 256 GiB, and the zero byte every range coder starts
/// with. A file of random bytes passes by chance about once in 2 * 10^18
/// (225/256 properties, 40 dictionary sizes in 2^32, 2^38 + 1 sizes in 2^64,
/// 1/256 for the zero byte), but this runs against every file, and data made
/// of small numbers passes far more often, so [`starts_decodable`] is asked
/// too.
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

/// Whether the start of a stream with an LZMA-alone header decodes. A build
/// without the decoder takes the header for enough.
#[cfg(feature = "lzma")]
fn starts_decodable(d: &[u8]) -> bool {
    super::lzmaalone::starts_decodable(d)
}

#[cfg(not(feature = "lzma"))]
fn starts_decodable(_: &[u8]) -> bool {
    true
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
    use crate::zip_end::{EndRecord, end_records};
    if p.len < EndRecord::LEN + 30 {
        return false;
    }
    let from = p.len.saturating_sub(EndRecord::LEN + usize::from(u16::MAX));
    let tail = p.window(from, p.len - from);
    let Some(end) = end_records(&tail, from as u64).next() else {
        return false;
    };
    if !end.has_directory() {
        return false;
    }
    let Some(cd_start) = (end.at as usize).checked_sub(end.size as usize) else {
        return false;
    };
    let Some(prefix) = cd_start.checked_sub(end.offset as usize) else {
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
            (Format::Inno, crate::pe_resource::tests::inno_stub(0x400)),
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
        // The loader table's magic in an executable that has no resource.
        assert!(!is(
            &[b"MZ".as_slice(), &[0; 64], b"rDlPtS", &[0; 16]].concat(),
            Format::Inno
        ));
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

    /// The string pool of an installer database with the code page 0: 16-bit
    /// lengths and use counts, which are small numbers.
    #[cfg(feature = "lzma")]
    fn string_pool() -> Vec<u8> {
        let mut pool = vec![0u8; 4];
        let mut x = 12345u32;
        for i in 0..100 {
            let (len, uses) = match i {
                0 => (4, 1),
                1 | 2 => (0, 0),
                _ => {
                    x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                    ((x >> 24) as u16 % 40 + 1, (x >> 16) as u16 % 7 + 1)
                }
            };
            pool.extend_from_slice(&len.to_le_bytes());
            pool.extend_from_slice(&uses.to_le_bytes());
        }
        pool
    }

    /// The table of upgrades of an installer database: a column of string
    /// indexes, then another.
    #[cfg(feature = "lzma")]
    const UPGRADE_TABLE: [u8; 32] = [
        0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x00, 0x80, 0x02, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00,
        0x2b, 0x00,
    ];

    /// Streams of an installer database carry a header that a stream of
    /// LZMA Utils can have; what they hold is not one.
    #[cfg(feature = "lzma")]
    #[test]
    fn the_streams_of_an_installer_database_are_not_lzma() {
        for (what, data) in [
            ("a string pool", string_pool()),
            ("a table", UPGRADE_TABLE.to_vec()),
        ] {
            assert!(lzma_alone_header(&data), "{what}: the header is taken");
            assert!(!is(&data, Format::Lzma), "{what}");
        }
    }

    /// A format this module does not speak for must answer `false` rather than
    /// something accidental: the structural sniffs own those.
    #[test]
    fn structural_formats_are_not_claimed_here() {
        for fmt in [Format::Arc, Format::Fat, Format::Partition, Format::Dmg] {
            assert!(!is(b"anything at all, really", fmt), "{fmt:?}");
        }
    }
}
