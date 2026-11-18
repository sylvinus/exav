//! What a file is, from its first bytes. The answers are exav's own: the
//! scanner's detection of containers, documents and drawings
//! ([`exav_unpack::detect`], which exav-core's `identify` wraps), of images
//! ([`exav_render::image`]) and of models (`is_ply`, `is_glb` and `is_ifc`,
//! each owned by its reader in exav-render), named in the content types the
//! viewer's matchers use. No signature is looked for here.
//!
//! Two rules of the viewer, on top of the scanner's detection:
//!
//! - A head that reads as text is typed only as RTF, DXF, a PLY or IFC header
//!   or a PDF that starts with its signature. Image signatures are two to four
//!   bytes (`BM`, `P1`), and the scanner takes a PDF header anywhere in the
//!   first kilobyte, so a note or a table that opens that way would otherwise
//!   be shown as an image or a PDF. A plain PNM, which is text, is told by its
//!   name.
//! - A format the viewer does not open as a file (an installer, a shortcut,
//!   bytecode, a filesystem image, a DMG, whose detection needs the end of the
//!   file) has no type: the name decides.

use std::borrow::Cow;

use exav_render::image::{self, raw};
use exav_render::{gltf, ifc, ply};
use exav_unpack::text::looks_text;
use exav_unpack::{ByteSource, Format, detect};

/// A file of `size` bytes of which only the first are known: the reads of
/// the detector past them come back empty, as they do at the end of a file.
struct Start<'a> {
    bytes: &'a [u8],
    size: usize,
}

impl ByteSource for Start<'_> {
    fn len(&self) -> usize {
        self.size
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let from = off.min(self.bytes.len());
        let to = from.saturating_add(len).min(self.bytes.len());
        Cow::Borrowed(&self.bytes[from..to])
    }

    fn identity(&self) -> (usize, usize) {
        (self.bytes.as_ptr() as usize, self.size)
    }
}

/// The content type of a file of `size` bytes that starts with `head`, or ""
/// when its first bytes prove none the viewer opens.
pub fn content_type(head: &[u8], size: usize) -> &'static str {
    let head = &head[..head.len().min(size)];
    let text = looks_text(head);
    let format = if head.len() == size {
        detect(&head)
    } else {
        detect(&Start { bytes: head, size })
    };
    if let Some(t) = format.and_then(container_type) {
        let signed = head.starts_with(b"%PDF-");
        let by_text =
            matches!(t, "application/rtf" | "image/vnd.dxf") || (t == "application/pdf" && signed);
        return if !text || by_text { t } else { "" };
    }
    // The headers of PLY and IFC are text: their checks name a whole line.
    if let Some(t) = model_type(head) {
        return t;
    }
    if text {
        return "";
    }
    image_type(head).unwrap_or("")
}

/// Every type [`content_type`] can give, for a test of the matchers that
/// claim them.
pub fn content_types() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = Format::ALL
        .iter()
        .filter_map(|&f| container_type(f))
        .collect();
    all.extend(image::Format::ALL.iter().filter_map(|&f| format_type(f)));
    all.extend(RAW.iter().map(|&k| raw_type(k)));
    all.extend(MODEL_TYPES);
    all.sort_unstable();
    all.dedup();
    all
}

/// The viewer's type for a format `exav_unpack::detect` names, or `None` for
/// one it does not open as a file.
fn container_type(f: Format) -> Option<&'static str> {
    Some(match f {
        Format::Zip => "application/zip",
        Format::Gzip => "application/gzip",
        Format::Tar => "application/x-tar",
        Format::Bzip2 => "application/x-bzip2",
        Format::Xz => "application/x-xz",
        Format::Cab => "application/vnd.ms-cab-compressed",
        Format::Chm => "application/vnd.ms-htmlhelp",
        // A compound file: a Word, Excel or PowerPoint document of 1997, a
        // Visio or Publisher file, an installer. The name says which.
        Format::Ole => "application/x-ole-storage",
        Format::Pdf => "application/pdf",
        Format::SevenZip => "application/x-7z-compressed",
        Format::Iso => "application/x-iso9660-image",
        Format::Lha => "application/x-lzh-compressed",
        Format::Rar => "application/x-rar-compressed",
        Format::Ar => "application/x-archive",
        Format::Cpio => "application/x-cpio",
        Format::Xar => "application/x-xar",
        Format::Vhd => "application/x-vhd",
        Format::Lzw => "application/x-compress",
        Format::Qcow2 => "application/x-qemu-disk",
        Format::Vmdk => "application/x-vmdk",
        Format::Vhdx => "application/x-vhdx",
        Format::Wim => "application/x-ms-wim",
        Format::Lz4 => "application/x-lz4",
        Format::Arc => "application/x-arc",
        Format::Alz => "application/x-alz",
        Format::Egg => "application/x-egg",
        Format::Zoo => "application/x-zoo",
        Format::Zstd => "application/zstd",
        Format::Lzip => "application/x-lzip",
        Format::Lzma => "application/x-lzma",
        Format::Rpm => "application/x-rpm",
        Format::Tnef => "application/vnd.ms-tnef",
        Format::Rtf => "application/rtf",
        Format::Dxf => "image/vnd.dxf",
        Format::Dwg => "image/vnd.dwg",
        _ => return None,
    })
}

/// The type of an image `exav_render::image::Format::detect` names.
fn format_type(f: image::Format) -> Option<&'static str> {
    use image::Format as F;
    Some(match f {
        F::Png => "image/png",
        F::Gif => "image/gif",
        F::Jpeg => "image/jpeg",
        F::Tiff => "image/tiff",
        F::Bmp => "image/bmp",
        F::Webp => "image/webp",
        F::Ico => "image/x-icon",
        F::Pnm => "image/x-portable-anymap",
        F::Qoi => "image/qoi",
        F::Dds => "image/vnd-ms.dds",
        F::Farbfeld => "image/x-farbfeld",
        F::Hdr => "image/vnd.radiance",
        F::Jpeg2000 => "image/jp2",
        F::Jbig2 => "image/x-jbig2",
        F::Jxl => "image/jxl",
        _ => return None,
    })
}

/// A camera RAW file that is not a TIFF underneath (`IIRO`, `FUJIFILM`...) is
/// told by `raw::detect`; a TIFF-structured one starts as a TIFF.
fn image_type(head: &[u8]) -> Option<&'static str> {
    match image::Format::detect(head) {
        Some(f) => format_type(f),
        None => raw::detect(head).map(raw_type),
    }
}

/// What the readers' own checks name.
const MODEL_TYPES: [&str; 3] = ["model/ply", "model/gltf-binary", "model/ifc"];

/// The type of a model whose reader says the head is its own.
fn model_type(head: &[u8]) -> Option<&'static str> {
    if ply::is_ply(head) {
        Some(MODEL_TYPES[0])
    } else if gltf::is_glb(head) {
        Some(MODEL_TYPES[1])
    } else if ifc::is_ifc(head) {
        Some(MODEL_TYPES[2])
    } else {
        None
    }
}

const RAW: [raw::Kind; 11] = [
    raw::Kind::Dng,
    raw::Kind::Cr2,
    raw::Kind::Cr3,
    raw::Kind::Crw,
    raw::Kind::Orf,
    raw::Kind::Rw2,
    raw::Kind::Raf,
    raw::Kind::X3f,
    raw::Kind::Mrw,
    raw::Kind::Iiq,
    raw::Kind::TiffEp,
];

fn raw_type(k: raw::Kind) -> &'static str {
    match k {
        raw::Kind::Dng => "image/x-adobe-dng",
        raw::Kind::Cr2 => "image/x-canon-cr2",
        raw::Kind::Cr3 => "image/x-canon-cr3",
        raw::Kind::Crw => "image/x-canon-crw",
        raw::Kind::Orf => "image/x-olympus-orf",
        raw::Kind::Rw2 => "image/x-panasonic-rw2",
        raw::Kind::Raf => "image/x-fuji-raf",
        raw::Kind::X3f => "image/x-sigma-x3f",
        raw::Kind::Mrw => "image/x-minolta-mrw",
        raw::Kind::Iiq => "image/x-phaseone-iiq",
        _ => "image/tiff",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A head of the parts end to end.
    fn head(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// What the first bytes of a file of that many bytes say, the file being
    /// those bytes.
    fn of(bytes: &[u8]) -> &'static str {
        content_type(bytes, bytes.len())
    }

    /// Formats the detector can name that the viewer does not open as a file,
    /// and why. A new format of exav-unpack is in neither this list nor the
    /// types until someone decides.
    const NOT_OPENED: &[Format] = &[
        // Recognised so that they are reported, not opened.
        Format::Email,
        Format::Ace,
        Format::StuffIt,
        Format::CryptFf,
        Format::Lrzip,
        // The detector needs the end of the file, and a reader the module does
        // not link (DMG), or a feature that brings a time library with it
        // (ARJ): both are told by their names.
        Format::Dmg,
        Format::Arj,
        // Installers, packers and bytecode: what is inside is the scanner's
        // business, not what a person opens to see.
        Format::Upx,
        Format::PePacked,
        Format::Nsis,
        Format::Sfx,
        Format::Autoit,
        Format::Inno,
        Format::IshieldMsi,
        Format::IshieldCab,
        Format::IshieldZ,
        Format::Machofat,
        Format::JavaClass,
        Format::Pyc,
        Format::AiModel,
        Format::Screnc,
        Format::Lnk,
        Format::OneNote,
        Format::Hwp3,
        Format::Swf,
        Format::Szdd,
        // Text wrapped in text.
        Format::Uuencode,
        Format::Xdp,
        Format::Binhex,
        Format::AppleSingle,
        // Filesystems and partition tables.
        Format::Fat,
        Format::Exfat,
        Format::Ntfs,
        Format::Ext,
        Format::Squashfs,
        Format::Cramfs,
        Format::Romfs,
        Format::Erofs,
        Format::Partition,
    ];

    #[test]
    fn every_format_has_a_type_or_a_reason_not_to() {
        for &f in Format::ALL {
            assert_ne!(
                container_type(f).is_some(),
                NOT_OPENED.contains(&f),
                "{f:?}: a type, or a line in NOT_OPENED"
            );
        }
    }

    #[test]
    fn every_image_format_has_a_type() {
        for &f in image::Format::ALL {
            assert!(format_type(f).is_some(), "{f:?}");
        }
        let raws: std::collections::BTreeSet<_> = RAW.iter().map(|&k| raw_type(k)).collect();
        assert_eq!(raws.len(), RAW.len());
    }

    #[test]
    fn the_types_are_listed_once_and_are_content_types() {
        let all = content_types();
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(all, sorted);
        assert!(all.len() > 40);
        for t in all {
            assert!(
                t.split_once('/')
                    .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty()),
                "{t}"
            );
        }
    }

    #[test]
    fn what_the_scanner_names_by_its_first_bytes() {
        let at = |n: usize, tail: &[u8]| head(&[&vec![0; n], tail]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("application/pdf", head(&[b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"])),
            ("application/zip", head(&[b"PK\x03\x04\x14\0\0\0\x08\0"])),
            ("application/zip", head(&[b"PK\x05\x06", &[0; 18]])),
            (
                "application/gzip",
                head(&[&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0]]),
            ),
            (
                "application/x-7z-compressed",
                head(&[b"7z\xbc\xaf\x27\x1c\0\x04"]),
            ),
            (
                "application/x-rar-compressed",
                head(&[b"Rar!\x1a\x07\x00\xcf\x90s\0"]),
            ),
            (
                "application/x-bzip2",
                head(&[b"BZh9\x31\x41\x59\x26\x53\x59", &[0; 4]]),
            ),
            (
                "application/x-xz",
                head(&[&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 4]]),
            ),
            (
                "application/zstd",
                head(&[&[0x28, 0xb5, 0x2f, 0xfd, 0x24, 0, 0, 0]]),
            ),
            (
                "application/x-lz4",
                head(&[&[0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0, 0, 0]]),
            ),
            ("application/x-lzip", head(&[b"LZIP", &[1, 12, 0, 0]])),
            (
                "application/x-rpm",
                head(&[&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0], &[0; 100]]),
            ),
            (
                "application/x-compress",
                head(&[&[0x1f, 0x9d, 0x90, 0, 0, 0, 0, 0]]),
            ),
            ("application/x-tar", at(257, b"ustar\x0000")),
            (
                "application/vnd.ms-cab-compressed",
                head(&[b"MSCF", &[0; 12]]),
            ),
            (
                "application/vnd.ms-htmlhelp",
                head(&[b"ITSF", &[3, 0, 0, 0], &[0; 20]]),
            ),
            (
                "application/x-archive",
                head(&[b"!<arch>\n", b"debian-binary   ", &[0; 8]]),
            ),
            (
                "application/x-cpio",
                head(&[b"070701", b"00000001", &[0; 8]]),
            ),
            (
                "application/x-xar",
                head(&[b"xar!", &[0, 0x1c, 0, 1], &[0; 20]]),
            ),
            (
                "application/vnd.ms-tnef",
                head(&[&[0x78, 0x9f, 0x3e, 0x22, 1, 0]]),
            ),
            (
                "application/x-ole-storage",
                head(&[&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], &[0; 100]]),
            ),
            (
                "application/rtf",
                head(&[b"{\\rtf1\\ansi\\deff0 {\\fonttbl}"]),
            ),
            (
                "image/vnd.dxf",
                head(&[b"  0\r\nSECTION\r\n  2\r\nHEADER\r\n"]),
            ),
            (
                "image/png",
                head(&[&[0x89], b"PNG\r\n\x1a\n", &[0, 0, 0, 13], b"IHDR"]),
            ),
            (
                "image/jpeg",
                head(&[&[0xff, 0xd8, 0xff, 0xe0, 0, 0x10], b"JFIF\0"]),
            ),
            ("image/gif", head(&[b"GIF89a", &[1, 0, 1, 0, 0x80, 0, 0]])),
            (
                "image/webp",
                head(&[b"RIFF", &[0x24, 0, 0, 0], b"WEBPVP8 "]),
            ),
            ("image/tiff", head(&[b"II*\0", &[8, 0, 0, 0, 0, 0]])),
            ("image/tiff", head(&[b"MM\0*", &[0, 0, 0, 8, 0, 0]])),
            (
                "image/bmp",
                head(&[b"BM", &[0x36, 0x10, 0x0e, 0], &[0; 20]]),
            ),
            (
                "image/x-icon",
                head(&[&[0, 0, 1, 0, 1, 0, 16, 16], &[0; 20]]),
            ),
            (
                "image/qoi",
                head(&[b"qoif", &[0, 0, 0, 1, 0, 0, 0, 1, 3, 0]]),
            ),
            (
                "image/vnd-ms.dds",
                head(&[b"DDS ", &[124, 0, 0, 0], &[0; 20]]),
            ),
            (
                "image/x-farbfeld",
                head(&[b"farbfeld", &[0, 0, 0, 1, 0, 0, 0, 1], &[0; 8]]),
            ),
            (
                "image/vnd.radiance",
                head(&[b"#?RADIANCE\n", &[2, 2, 0, 8], &[0xff; 20]]),
            ),
            (
                "image/jp2",
                head(&[
                    &[0, 0, 0, 0x0c],
                    b"jP  ",
                    &[0x0d, 0x0a, 0x87, 0x0a],
                    &[0; 8],
                ]),
            ),
            (
                "image/jp2",
                head(&[&[0xff, 0x4f, 0xff, 0x51, 0, 0x2f], &[0; 20]]),
            ),
            (
                "image/x-jbig2",
                head(&[&[0x97], b"JB2", &[0x0d, 0x0a, 0x1a, 0x0a, 1], &[0; 8]]),
            ),
            (
                "image/jxl",
                head(&[
                    &[0, 0, 0, 0x0c],
                    b"JXL ",
                    &[0x0d, 0x0a, 0x87, 0x0a],
                    &[0; 8],
                ]),
            ),
            ("image/jxl", head(&[&[0xff, 0x0a, 0x4c, 0xb7, 0, 0]])),
            (
                "image/x-olympus-orf",
                head(&[b"IIRO", &[8, 0, 0, 0], &[0; 20]]),
            ),
            (
                "image/x-panasonic-rw2",
                head(&[b"IIU", &[0, 8, 0, 0, 0], &[0; 20]]),
            ),
            (
                "image/x-fuji-raf",
                head(&[b"FUJIFILMCCD-RAW 0201FF129504", &[0; 20]]),
            ),
            (
                "image/x-sigma-x3f",
                head(&[b"FOVb", &[2, 0, 2, 0], &[0; 20]]),
            ),
            (
                "image/x-canon-crw",
                head(&[b"II", &[0x1a, 0, 0, 0], b"HEAPCCDR", &[0; 20]]),
            ),
            (
                "image/x-minolta-mrw",
                head(&[&[0], b"MRM", &[0, 1, 0, 0], &[0; 20]]),
            ),
            (
                "image/x-canon-cr3",
                head(&[
                    &[0, 0, 0, 0x18],
                    b"ftyp",
                    b"crx ",
                    &[0, 0, 0, 1],
                    b"crx ",
                    &[0; 20],
                ]),
            ),
        ];
        for (want, bytes) in &cases {
            assert_eq!(of(bytes), *want, "{:?}", &bytes[..bytes.len().min(16)]);
        }
        for (want, bytes) in &cases {
            // The same in a file that goes on.
            assert_eq!(
                content_type(bytes, bytes.len() + 5_000_000),
                *want,
                "{want} in a long file"
            );
        }
    }

    #[test]
    fn a_model_is_typed_by_the_check_of_its_reader_text_headers_included() {
        let ifc = b"ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n";
        let cases: [(&str, &[u8]); 4] = [
            ("model/ply", b"ply\nformat ascii 1.0\nend_header\n"),
            ("model/ply", b"ply\r\nformat binary_little_endian 1.0\r\n"),
            ("model/gltf-binary", b"glTF\x02\0\0\0\x20\0\0\0"),
            ("model/ifc", ifc),
        ];
        for (expected, bytes) in cases {
            assert_eq!(of(bytes), expected, "{bytes:?}");
            assert!(content_types().contains(&expected));
        }
        // Words that open like a header, and a STEP file of another schema.
        assert_eq!(of(b"ply\nplums are good\n"), "");
        assert_eq!(of(b"glTF\x01\0\0\0"), "");
        assert_eq!(
            of(b"ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('AP214'));\nENDSEC;\nDATA;\n"),
            ""
        );
    }

    #[test]
    fn a_version_id_alone_is_not_a_drawing() {
        // The detector checks the header that follows; real drawings are in
        // the fixtures.
        for v in ["AC1015", "AC1018", "AC1021", "AC1032"] {
            let mut dwg = v.as_bytes().to_vec();
            dwg.resize(200, 0);
            assert_eq!(of(&dwg), "", "{v}");
        }
    }

    #[test]
    fn a_note_that_starts_like_a_signature_is_a_note() {
        for text in [
            "BM is a name and this is a note about it\n",
            "P1,Alice,12\nP2,Bob,13\n",
            "P3\n2 2\n255\n0 0 0 255 255 255\n",
            "BZh is the bzip2 header\n",
            "LZIP is a format\n",
            "xar! is a shout\n",
            "MSCF is a type\n",
            "MSWIM is a word\n",
            "ITSF is not it\n",
            "-lh5- at the front\n",
            "II* is a TIFF header\n",
            "GIF89a is a header\n",
            "qoif is a format\n",
            "#?RADIANCE is a header\n",
            "070701,Alice,12\n070702,Bob,13\n",
            "!<arch>\nis how an ar file starts\n",
            "Hello, this is a note.\n",
        ] {
            assert_eq!(of(text.as_bytes()), "", "{text}");
        }
        assert_eq!(of(b""), "");
    }

    #[test]
    fn a_pdf_header_types_text_only_at_its_start() {
        assert_eq!(of(b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n"), "application/pdf");
        // Text that mentions the header is text.
        assert_eq!(of(b"Notes\nif (head.startsWith(\"%PDF-1.\")) {}\n"), "");
        // A binary file with the header after some bytes is a PDF, as to the
        // scanner.
        let mut junk = vec![0x80u8; 40];
        junk.extend_from_slice(b"%PDF-1.7\n");
        junk.extend_from_slice(&[0; 20]);
        assert_eq!(of(&junk), "application/pdf");
    }

    #[test]
    fn a_text_head_is_typed_as_rtf_or_a_drawing_only() {
        assert_eq!(of(b"{\\rtf1 hello}"), "application/rtf");
        assert_eq!(
            of(b"0\nSECTION\n2\nENTITIES\n0\nENDSEC\n0\nEOF\n"),
            "image/vnd.dxf"
        );
        // The same bytes at the start of a longer file.
        assert_eq!(content_type(b"%PDF-1.4\nabc", 1_000_000), "application/pdf");
    }

    /// The two bytes of an ext superblock do not retype a document or a
    /// drawing that its first bytes name.
    #[test]
    fn the_bytes_of_an_ext_superblock_do_not_retype_a_document_or_a_drawing() {
        let mut rtf = b"{\\rtf1 hello ".to_vec();
        rtf.resize(2000, b'.');
        rtf[1080..1082].copy_from_slice(&[0x53, 0xEF]);
        assert_eq!(content_type(&rtf, rtf.len()), "application/rtf");
        let mut dxf = b"0\nSECTION\n2\nENTITIES\n0\nENDSEC\n0\nEOF\n".to_vec();
        dxf.resize(2000, b'\n');
        dxf[1080..1082].copy_from_slice(&[0x53, 0xEF]);
        assert_eq!(content_type(&dxf, dxf.len()), "image/vnd.dxf");
    }

    #[test]
    fn a_head_longer_than_the_file_is_the_file() {
        let png = head(&[&[0x89], b"PNG\r\n\x1a\n", &[0, 0, 0, 13], b"IHDR"]);
        assert_eq!(content_type(&png, png.len()), "image/png");
        assert_eq!(content_type(&png, 8), "image/png");
        // A file of seven bytes is not a PNG, whatever follows in the head.
        assert_eq!(content_type(&png, 7), "");
        assert_eq!(content_type(&png, 0), "");
    }

    /// A stored ZIP of one member, after `prefix` bytes that no offset counts.
    fn zip_after(prefix: usize) -> Vec<u8> {
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        let mut z = vec![0x80u8; prefix];
        // The local header of "a", holding "x".
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&le16(10));
        z.extend_from_slice(&[0; 8]);
        z.extend_from_slice(&[le32(0), le32(1), le32(1)].concat());
        z.extend_from_slice(&[le16(1), le16(0)].concat());
        z.extend_from_slice(b"ax");
        let cd = z.len() - prefix;
        // Its directory entry.
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[le16(20), le16(10)].concat());
        z.extend_from_slice(&[0; 8]);
        z.extend_from_slice(&[le32(0), le32(1), le32(1)].concat());
        z.extend_from_slice(&[le16(1), le16(0), le16(0), le16(0), le16(0)].concat());
        z.extend_from_slice(&[le32(0), le32(0)].concat());
        z.push(b'a');
        let size = (z.len() - prefix - cd) as u32;
        // The end record.
        z.extend_from_slice(b"PK\x05\x06");
        z.extend_from_slice(&[le16(0), le16(0), le16(1), le16(1)].concat());
        z.extend_from_slice(&[le32(size), le32(cd as u32)].concat());
        z.extend_from_slice(&le16(0));
        z
    }

    #[test]
    fn the_end_of_a_file_is_not_guessed() {
        // A ZIP behind padding is found by its end record: when the file is in
        // the head, not from the start of a longer one.
        let z = zip_after(3000);
        assert_eq!(of(&z), "application/zip");
        assert_eq!(content_type(&z[..2048], z.len()), "");
        // And a stream is typed by its first bytes whatever the length.
        let bz = head(&[b"BZh9\x31\x41\x59\x26\x53\x59", &[0; 100]]);
        assert_eq!(
            content_type(&bz[..20], bz.len() * 1000),
            "application/x-bzip2"
        );
    }

    /// A fixed VHD has its cookie in the last 512 bytes only: the last bytes
    /// of a head are not the end of a longer file.
    #[test]
    fn the_last_bytes_of_a_head_are_not_the_end_of_a_longer_file() {
        let mut h = vec![0x80u8; 2000];
        h[2000 - 512..2000 - 512 + 8].copy_from_slice(b"conectix");
        h[5] = 0;
        assert_eq!(of(&h), "application/x-vhd");
        assert_eq!(content_type(&h, 5_000_000), "");
    }

    /// Every file of a directory, its subdirectories too.
    fn files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                files(&p, out);
            } else {
                out.push(p);
            }
        }
    }

    /// The fixtures of exav-unpack and exav-render: real archives, images and
    /// documents, some of them damaged on purpose.
    fn fixtures() -> Vec<std::path::PathBuf> {
        let mut all = Vec::new();
        for d in [
            "../exav-unpack/tests/fixtures",
            "../exav-render/tests/fixtures",
        ] {
            files(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(d),
                &mut all,
            );
        }
        all
    }

    /// What a file's name says it is, for the ones that name one type.
    const BY_EXTENSION: &[(&str, &str)] = &[
        ("7z", "application/x-7z-compressed"),
        ("rar", "application/x-rar-compressed"),
        ("xz", "application/x-xz"),
        ("gz", "application/gzip"),
        ("bz2", "application/x-bzip2"),
        ("Z", "application/x-compress"),
        ("lz4", "application/x-lz4"),
        ("lz", "application/x-lzip"),
        ("lzma", "application/x-lzma"),
        ("cab", "application/vnd.ms-cab-compressed"),
        ("chm", "application/vnd.ms-htmlhelp"),
        ("arc", "application/x-arc"),
        ("alz", "application/x-alz"),
        ("egg", "application/x-egg"),
        ("zoo", "application/x-zoo"),
        ("rpm", "application/x-rpm"),
        ("cpio", "application/x-cpio"),
        ("wim", "application/x-ms-wim"),
        ("iso", "application/x-iso9660-image"),
        ("zip", "application/zip"),
        ("pdf", "application/pdf"),
        ("rtf", "application/rtf"),
        ("xls", "application/x-ole-storage"),
        ("ppt", "application/x-ole-storage"),
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("tif", "image/tiff"),
        ("jp2", "image/jp2"),
        ("j2k", "image/jp2"),
        ("jb2", "image/x-jbig2"),
        ("jxl", "image/jxl"),
        ("dwg", "image/vnd.dwg"),
        ("orf", "image/x-olympus-orf"),
        ("rw2", "image/x-panasonic-rw2"),
        ("raf", "image/x-fuji-raf"),
        ("x3f", "image/x-sigma-x3f"),
        ("mrw", "image/x-minolta-mrw"),
        ("cr3", "image/x-canon-cr3"),
    ];

    /// Real files are typed as their name says, or not at all (a fixture may
    /// be damaged on purpose), never as something else; and each kind has one
    /// that is typed.
    #[test]
    fn real_files_are_typed_as_their_name_says() {
        let mut typed = std::collections::BTreeMap::<&str, (usize, usize)>::new();
        for path in fixtures() {
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            let Some(&(ext, want)) = BY_EXTENSION.iter().find(|(e, _)| *e == ext) else {
                continue;
            };
            let data = std::fs::read(&path).unwrap();
            let got = content_type(&data[..data.len().min(64 * 1024)], data.len());
            assert!(
                got.is_empty() || got == want,
                "{}: {got}, not {want}",
                path.display()
            );
            let n = typed.entry(ext).or_default();
            n.0 += 1;
            n.1 += usize::from(got == want);
        }
        for (ext, _) in BY_EXTENSION {
            let (all, right) = typed.get(ext).copied().unwrap_or_default();
            assert!(right > 0, ".{ext}: none of {all} typed");
        }
    }

    /// The order of the two detectors only matters for a file both would
    /// claim: there is none among the fixtures.
    #[test]
    fn no_fixture_is_claimed_by_both_detectors() {
        for path in fixtures() {
            let data = std::fs::read(&path).unwrap();
            let head = &data[..data.len().min(64 * 1024)];
            let container = detect(&head).and_then(container_type);
            if container.is_some() && !looks_text(head) {
                assert_eq!(image_type(head), None, "{}: {container:?}", path.display());
            }
        }
    }

    /// A head cut anywhere, of a file as long as it is or longer, is typed
    /// without a panic (which, in the module, is a trap), and a file that fits
    /// in the head is typed as the same bytes alone.
    #[test]
    fn a_head_cut_anywhere_is_typed_without_a_panic() {
        let cuts = [
            0usize, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 16, 17, 31, 32, 33, 63, 64, 100, 255, 256,
            257, 258, 262, 263, 511, 512, 513, 1023, 1024, 1025, 4096, 32767, 32768, 32769, 32773,
            32774, 65536,
        ];
        let mut n = 0;
        for path in fixtures() {
            let data = std::fs::read(&path).unwrap();
            for cut in cuts {
                let head = &data[..data.len().min(cut)];
                for size in [head.len(), data.len(), data.len() * 3 + 7, usize::MAX] {
                    let t = content_type(head, size);
                    if size == head.len() {
                        assert_eq!(
                            t,
                            content_type(&data[..head.len()], head.len()),
                            "{}",
                            path.display()
                        );
                    }
                    n += 1;
                }
            }
        }
        assert!(n > 10_000, "{n}");
    }

    /// Random heads that start like a signature, of a file of any size.
    #[test]
    fn random_heads_are_typed_without_a_panic() {
        let magics: Vec<Vec<u8>> = vec![
            b"PK\x03\x04".to_vec(),
            b"PK\x05\x06".to_vec(),
            b"%PDF-1.".to_vec(),
            vec![0x1f, 0x8b, 8, 0],
            b"BZh9\x31\x41\x59\x26\x53\x59".to_vec(),
            b"MSCF".to_vec(),
            b"ITSF".to_vec(),
            b"vhdxfile".to_vec(),
            b"conectix".to_vec(),
            b"KDMV".to_vec(),
            b"QFI\xfb".to_vec(),
            b"MSWIM\0\0\0".to_vec(),
            b"AC1021".to_vec(),
            b"AC1018".to_vec(),
            b"  0\nSECTION\n".to_vec(),
            b"AutoCAD Binary DXF\r\n\x1a\0".to_vec(),
            b"II*\0".to_vec(),
            vec![0xff, 0xd8, 0xff],
            vec![0xff, 0x4f, 0xff, 0x51],
            b"MZ".to_vec(),
            b"CD001".to_vec(),
            vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 600) as usize;
            let mut head: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if next() % 4 != 0 {
                let m = &magics[(next() % magics.len() as u64) as usize];
                let at = if next() % 3 == 0 {
                    (next() % 300) as usize
                } else {
                    0
                };
                if head.len() < at + m.len() {
                    head.resize(at + m.len(), 0);
                }
                head[at..at + m.len()].copy_from_slice(m);
            }
            let size = match next() % 3 {
                0 => head.len(),
                1 => head.len() + (next() % 100_000) as usize,
                _ => (next() % (1 << 40)) as usize,
            };
            content_type(&head, size);
        }
    }
}
