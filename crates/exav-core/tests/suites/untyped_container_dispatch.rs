//! Containers with no ClamAV `CL_TYPE_*` of their own must still be extracted.
//!
//! The scanner normally reaches an extractor through the file's [`FileType`],
//! but a handful of formats (Unix `compress` and the disk images) have no
//! ClamAV type to map to and so are typed `Unknown`. Nothing then dispatches
//! them, and the file is reported clean on the strength of a raw pattern scan
//! that cannot see compressed content. That is a silent clean, the worst
//! failure mode a scanner has, and it is invisible in the unpack crate's own
//! tests because the extractors themselves work fine.
//!
//! Both fixtures hide the payload behind real compression: the EICAR string
//! appears nowhere in their bytes (asserted below), so a verdict of `Infected`
//! can only come from the container actually being opened.

use exav_core::{ScanOptions, Scanner, Verdict, analyze};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn assert_found(name: &str) {
    let blob = fixture(name);
    assert!(
        !blob.windows(eicar().len()).any(|w| w == eicar()),
        "{name} must not expose the payload in its own bytes, or this test \
         would pass on the raw scan alone and prove nothing"
    );
    let db = Scanner::builtin();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "{name}: unexpected signature {signature}"
        ),
        other => panic!("{name}: the payload must be reached, got {other:?}"),
    }
}

#[test]
#[cfg(feature = "lzw")]
fn a_unix_compress_stream_is_decompressed_and_scanned() {
    // Produced by ncompress 5.0 (`compress -c`), not by any encoder of ours.
    assert_found("eicar.txt.Z");
}

#[test]
#[cfg(feature = "lzma")]
fn an_lzma_alone_stream_is_decompressed_and_scanned() {
    // `xz --format=lzma`: no magic number, found by the header's own rules.
    assert_found("eicar.txt.lzma");
}

#[test]
#[cfg(feature = "rpm")]
fn an_rpm_payload_is_decompressed_and_scanned() {
    // A package whose gzip cpio payload holds the EICAR file (`make.py` in
    // exav-unpack's rpm fixtures).
    assert_found("eicar.rpm");
}

#[test]
#[cfg(feature = "diskimage")]
fn a_compressed_qcow2_is_reconstructed_and_scanned() {
    // `qemu-img convert -c`: every cluster deflated.
    assert_found("compressed.qcow2");
}

#[test]
#[cfg(feature = "inno")]
fn an_installer_embedded_in_an_executable_is_not_reported_clean() {
    // The second shape of the same routing bug. An installer *is* an executable,
    // so `identify` answers `Pe` (correctly, the PE signature scan has to run)
    // and no type maps an executable to a container. So the extractor was
    // never reached.
    //
    // Embedded-archive carving covers the case where the appended data is a
    // recognisable archive, but not where it is the installer's own format:
    // NSIS's compressed blocks and Inno Setup's chunked LZMA look like nothing
    // in particular, so nothing is carved and the file scans clean with every
    // packaged file unexamined. Verified against a real Inno Setup 6.2.2
    // installer, which reported `OK` before this.
    //
    // Synthetic here rather than a shipped installer: the routing is what is
    // under test, and a real one would mean committing a multi-megabyte binary.
    // The executable has the loader table in its resources, as Setup looks for
    // it, and nothing else of an installer; and it has them far enough into
    // the file that detection cannot be reading them as part of its start.
    let db = Scanner::builtin();
    for resources_at in [0x400, 5 << 20] {
        let pe = inno_stub(resources_at);
        match analyze(&db, &pe, &ScanOptions::default()).verdict {
            Verdict::Unscannable { reason } => assert!(
                reason.to_lowercase().contains("inno"),
                "the reason should name what could not be read, got {reason:?}"
            ),
            other => {
                panic!(
                    "an installer whose payload exav cannot read must not be clean, \
                     resources at {resources_at}: {other:?}"
                )
            }
        }
    }
}

fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

/// A PE32 whose one resource is RCDATA 11111, a loader table of Inno Setup
/// with no setup data behind it, at `raw` bytes into the file.
fn inno_stub(raw: usize) -> Vec<u8> {
    let tree = 88;
    let mut table = b"rDlPtS\xcd\xe6\xd7{\x0b*".to_vec();
    table.resize(44, 0);
    let size = tree + table.len();
    let mut f = vec![0u8; raw + size];
    put(&mut f, 0, b"MZ");
    put(&mut f, 0x3c, &0x40u32.to_le_bytes());
    put(&mut f, 0x40, b"PE\0\0");
    put(&mut f, 0x44, &0x14cu16.to_le_bytes());
    put(&mut f, 0x46, &1u16.to_le_bytes());
    put(&mut f, 0x54, &0xe0u16.to_le_bytes());
    let opt = 0x58;
    put(&mut f, opt, &0x10bu16.to_le_bytes());
    put(&mut f, opt + 92, &16u32.to_le_bytes());
    put(&mut f, opt + 96 + 16, &0x1000u32.to_le_bytes());
    put(&mut f, opt + 96 + 20, &(size as u32).to_le_bytes());
    let section = opt + 0xe0;
    put(&mut f, section, b".rsrc");
    put(&mut f, section + 8, &(size as u32).to_le_bytes());
    put(&mut f, section + 12, &0x1000u32.to_le_bytes());
    put(&mut f, section + 16, &(size as u32).to_le_bytes());
    put(&mut f, section + 20, &(raw as u32).to_le_bytes());
    // Three directories of one entry, an id: the type, the name, the language.
    let sub = 1u32 << 31;
    for (at, id, target) in [(0, 10, sub | 24), (24, 11111, sub | 48), (48, 0x409, 72)] {
        put(&mut f, raw + at + 14, &1u16.to_le_bytes());
        put(&mut f, raw + at + 16, &(id as u32).to_le_bytes());
        put(&mut f, raw + at + 20, &target.to_le_bytes());
    }
    put(&mut f, raw + 72, &(0x1000 + tree as u32).to_le_bytes());
    put(&mut f, raw + 76, &(table.len() as u32).to_le_bytes());
    put(&mut f, raw + tree, &table);
    f
}

/// An ASCII DXF is text to ClamAV and stays so here, but the object an
/// OLE2FRAME embeds is hex in it: only opening the drawing reaches the file
/// inside the compound file. The compound file is written by the `cfb`
/// crate, not by exav.
#[test]
#[cfg(any(feature = "dxf", feature = "all-formats"))]
fn a_file_inside_an_ole_object_inside_a_dxf_is_scanned() {
    use std::io::Write;
    let mut doc = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    doc.create_stream("/Ole10Native")
        .unwrap()
        .write_all(eicar())
        .unwrap();
    doc.flush().unwrap();
    let ole = doc.into_inner().into_inner();
    // AutoCAD's header before the compound file, then the 127-byte lines.
    let mut data = vec![0x80, 0x00, 0x55, 0x01, 0x00, 0x00, 0x00, 0x00];
    data.extend_from_slice(&ole);
    let mut dxf = String::from(
        "  0\nSECTION\n  2\nENTITIES\n  0\nOLE2FRAME\n  5\n2D\n100\nAcDbEntity\n  8\n0\n\
         100\nAcDbOle2Frame\n 70\n2\n 71\n2\n 72\n0\n",
    );
    dxf.push_str(&format!(" 90\n{}\n", data.len()));
    for line in data.chunks(127) {
        let hex: String = line.iter().map(|b| format!("{b:02X}")).collect();
        dxf.push_str(&format!("310\n{hex}\n"));
    }
    dxf.push_str("  1\nOLE\n  0\nENDSEC\n  0\nEOF\n");
    let blob = dxf.into_bytes();
    assert!(!blob.windows(eicar().len()).any(|w| w == eicar()));

    let db = Scanner::builtin();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("the file inside the drawing must be reached, got {other:?}"),
    }
}

/// The DWG versions of the converted fixtures in
/// `exav-unpack/tests/fixtures/dwg/`.
#[cfg(any(feature = "dwg", feature = "all-formats"))]
const DWG_VERSIONS: [&str; 8] = [
    "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018",
];

/// A fixture of `exav-unpack/tests/fixtures/dwg/`, gunzipped.
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn dwg_fixture(path: &str) -> Vec<u8> {
    use std::io::Read;
    let p = format!(
        "{}/../exav-unpack/tests/fixtures/dwg/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    let gz = exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut blob = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut blob)
        .expect("gzip");
    blob
}

/// A DWG of R12 or older is a drawing exav does not read: its contents
/// (compressed or not, nothing of it is examined beyond the raw scan) make
/// it `PARTIAL`, never clean. The drawing is the ODA File Converter's R12 DWG
/// of an ezdxf DXF (`exav-unpack/tests/fixtures/dwg/pre-r13/make.py`).
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn a_drawing_older_than_r13_is_not_clean() {
    let blob = dwg_fixture("pre-r13/R12.dwg.gz");
    let db = Scanner::builtin();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Unscannable { reason } => assert!(
            reason.contains("before R13"),
            "the reason should say why, got {reason:?}"
        ),
        other => panic!("an R12 drawing must not scan clean, got {other:?}"),
    }
}

/// An OLE2FRAME's embedded object is in a DWG's objects: only opening the
/// drawing reaches the file inside. The drawings are ODA File Converter
/// conversions of an ezdxf DXF (`exav-unpack/tests/fixtures/dwg/ole/make.py`)
/// to every version, the OLE object's stream a deflated ZIP of the test file
/// (so that no version shows it in the clear).
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn a_file_inside_an_ole_object_inside_a_dwg_is_scanned() {
    for v in DWG_VERSIONS {
        let blob = dwg_fixture(&format!("ole/{v}.dwg.gz"));
        assert!(!blob.windows(eicar().len()).any(|w| w == eicar()), "{v}");
        let db = Scanner::builtin();
        match analyze(&db, &blob, &ScanOptions::default()).verdict {
            Verdict::Infected { signature, .. } => assert!(
                signature.to_ascii_uppercase().contains("EICAR"),
                "{v}: unexpected signature {signature}"
            ),
            other => panic!("{v}: the file inside the drawing must be reached, got {other:?}"),
        }
    }
}

/// The two C4 DWG carriers, every version
/// (`exav-unpack/tests/fixtures/dwg/c4/`): an OLE2FRAME holding an Office
/// document whose `Macros/VBA` module is EICAR, compressed in the MS-OVBA
/// container so the signature is not in the clear; and an OLE2FRAME
/// Packager wrapping a ZIP of the test file. Only opening the drawing,
/// then the compound file, then the macro or the ZIP reaches it.
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn a_macro_and_a_packaged_file_inside_a_dwg_are_scanned() {
    for case in ["macros", "packager"] {
        for v in DWG_VERSIONS {
            let blob = dwg_fixture(&format!("c4/{case}/{v}.dwg.gz"));
            assert!(
                !blob.windows(eicar().len()).any(|w| w == eicar()),
                "{case} {v}: the signature must not be in the clear"
            );
            let db = Scanner::builtin();
            match analyze(&db, &blob, &ScanOptions::default()).verdict {
                Verdict::Infected { signature, .. } => assert!(
                    signature.to_ascii_uppercase().contains("EICAR"),
                    "{case} {v}: unexpected signature {signature}"
                ),
                other => panic!("{case} {v}: the embedded file must be reached, got {other:?}"),
            }
        }
    }
}

#[cfg(any(feature = "dwg", feature = "all-formats"))]
#[path = "../../../exav-unpack/tests/dwg_build/mod.rs"]
mod dwg_build;

/// A drawing that reads whole and holds nothing is clean: the builder's.
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn a_built_dwg_with_nothing_in_it_is_clean() {
    let db = Scanner::builtin();
    let blob = dwg_build::Drawing::standard().build().bytes;
    assert!(matches!(
        analyze(&db, &blob, &ScanOptions::default()).verdict,
        Verdict::Clean
    ));
}

/// A drawing whose VBA project is encrypted has code that was not examined:
/// `PASSWORD-PROTECTED`, as an encrypted member of any container is.
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn a_dwg_with_an_encrypted_vba_project_is_password_protected() {
    let mut project = vec![0u8; 16];
    project.extend_from_slice(&dwg_build::OLE2);
    project.extend_from_slice(b"the project");
    let mut section = dwg_build::Section::new("AcDb:VBAProject", &project);
    section.encrypted = 1;
    let mut drawing = dwg_build::Drawing::standard();
    drawing.sections.push(section);
    let db = Scanner::builtin();
    match analyze(&db, &drawing.build().bytes, &ScanOptions::default()).verdict {
        Verdict::PasswordProtected { reason } => {
            assert!(reason.contains("VBA project"), "got {reason:?}")
        }
        other => panic!("an encrypted VBA project must not scan clean, got {other:?}"),
    }
}

/// A page of the drawing that cannot be read holds objects that were not
/// examined: `UNSCANNABLE`, never clean. Each data page of the converted
/// drawings of `fixtures/dwg/ole/` is destroyed in turn (found by its header,
/// masked with its address, spec 4.6): the one holding the OLE2FRAME's
/// object takes the infection with it, and must not take the verdict.
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn a_dwg_with_a_page_that_cannot_be_read_is_not_clean() {
    for v in ["R2004", "R2010", "R2013", "R2018"] {
        let blob = dwg_fixture(&format!("ole/{v}.dwg.gz"));
        let db = Scanner::builtin();
        let (mut infected, mut unscannable) = (0, 0);
        for at in (0x100..blob.len() - 0x20).step_by(4) {
            let word = u32::from_le_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]]);
            // The page header's type, XORed with 0x4164536B and the address.
            if word ^ 0x4164_536B ^ (at as u32) != 0x4163_043B {
                continue;
            }
            let mut damaged = blob.clone();
            damaged[at] ^= 0xFF;
            match analyze(&db, &damaged, &ScanOptions::default()).verdict {
                Verdict::Infected { .. } => infected += 1,
                Verdict::Unscannable { .. } => unscannable += 1,
                other => panic!("{v}: the page at {at:#X} gone, got {other:?}"),
            }
        }
        assert!(infected > 0, "{v}: pages the infection does not depend on");
        assert!(unscannable > 0, "{v}: no page took the infection with it");
    }
}

/// A DWG keeps its preview bitmap without the 14-byte header of a BMP file
/// (ODA DWG specification 14.2); the member exav makes of it has one, so a
/// signature anchored on that header matches only when the drawing is
/// opened. The drawing is an R2000 file header and preview built here as
/// the specification lays them out.
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn the_preview_inside_a_dwg_is_scanned() {
    let mut f = b"AC1015".to_vec();
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 30, 0, 3, 0, 0, 0]);
    for n in 0..3u8 {
        f.push(n);
        f.extend_from_slice(&[0; 8]);
    }
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[
        0x95, 0xA0, 0x4E, 0x28, 0x99, 0x82, 0x1A, 0xE5, 0x5E, 0x41, 0xE0, 0x5F, 0x9D, 0x3A, 0x4D,
        0x00,
    ]);
    assert_dwg_preview_is_scanned(f);
}

/// The same from R2004 on, whose file header (specification 4.1) is the
/// version, the preview's address at 0x0D, and at 0x80 an encrypted block
/// starting with a file ID string.
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn the_preview_inside_an_r2004_dwg_is_scanned() {
    for version in [b"AC1018", b"AC1024", b"AC1027", b"AC1032"] {
        let mut f = vec![0u8; 0x100];
        f[..6].copy_from_slice(version);
        // The block is XORed with the sequence the specification's code
        // generates.
        let mut plain = [0u8; 0x6C];
        plain[..12].copy_from_slice(b"AcFssFcAJMB\0");
        let mut seed: u32 = 1;
        for (i, b) in plain.iter().enumerate() {
            seed = seed.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
            f[0x80 + i] = b ^ (seed >> 16) as u8;
        }
        assert_dwg_preview_is_scanned(f);
    }
}

/// The same in the ODA File Converter's drawings of every version
/// (`exav-unpack/tests/fixtures/dwg/preview/`, make.py there), whose preview
/// is a 4x2 24-bit bitmap: R2007's file header and pages are coded as no
/// other version's (specification 5).
#[test]
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn the_preview_inside_a_converted_dwg_is_scanned() {
    // `BM`, the file's size (14 + 40 + 24), two reserved words, where the
    // pixels start (14 + 40: no palette).
    let mut header = b"BM".to_vec();
    header.extend_from_slice(&78u32.to_le_bytes());
    header.extend_from_slice(&[0; 4]);
    header.extend_from_slice(&54u32.to_le_bytes());
    let hex: String = header.iter().map(|b| format!("{b:02x}")).collect();
    let mut b = exav_core::loader::Builder::new();
    b.add_named_bytes(
        "t.ndb",
        format!("Test.DwgPreview:0:0:{hex}\n").as_bytes(),
        true,
    );
    let db = b.build().expect("a one-signature database");
    for v in DWG_VERSIONS {
        let f = dwg_fixture(&format!("preview/{v}.dwg.gz"));
        assert!(!f.windows(header.len()).any(|w| w == header), "{v}");
        match analyze(&db, &f, &ScanOptions::default()).verdict {
            Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.DwgPreview"),
            other => panic!("{v}: the preview inside the drawing must be reached, got {other:?}"),
        }
    }
}

/// Put a preview holding a bitmap at the end of `f`, point 0x0D at it, and
/// scan the file with a signature on the BMP file header the member gets.
#[cfg(any(feature = "dwg", feature = "all-formats"))]
fn assert_dwg_preview_is_scanned(mut f: Vec<u8>) {
    // A 2x1 8-bit bitmap: BITMAPINFOHEADER, 256 palette entries, one row.
    let mut dib = Vec::new();
    dib.extend_from_slice(&40u32.to_le_bytes());
    dib.extend_from_slice(&2i32.to_le_bytes());
    dib.extend_from_slice(&1i32.to_le_bytes());
    dib.extend_from_slice(&1u16.to_le_bytes());
    dib.extend_from_slice(&8u16.to_le_bytes());
    dib.extend_from_slice(&[0; 24]);
    dib.extend_from_slice(&[0; 1024]);
    dib.extend_from_slice(&[1, 2, 0, 0]);

    let preview = f.len();
    f[0x0D..0x11].copy_from_slice(&(preview as u32).to_le_bytes());
    f.extend_from_slice(&[
        0x1F, 0x25, 0x6D, 0x07, 0xD4, 0x36, 0x28, 0x28, 0x9D, 0x57, 0xCA, 0x3F, 0x9D, 0x44, 0x10,
        0x2B,
    ]);
    f.extend_from_slice(&((1 + 9 + dib.len()) as u32).to_le_bytes());
    f.push(1);
    f.push(2);
    f.extend_from_slice(&((preview + 16 + 4 + 1 + 9) as u32).to_le_bytes());
    f.extend_from_slice(&(dib.len() as u32).to_le_bytes());
    f.extend_from_slice(&dib);
    f.extend_from_slice(&[
        0xE0, 0xDA, 0x92, 0xF8, 0x2B, 0xC9, 0xD7, 0xD7, 0x62, 0xA8, 0x35, 0xC0, 0x62, 0xBB, 0xEF,
        0xD4,
    ]);

    // The BMP file header: `BM`, the file's size, two reserved words, where
    // the pixels start.
    let mut header = b"BM".to_vec();
    header.extend_from_slice(&((14 + dib.len()) as u32).to_le_bytes());
    header.extend_from_slice(&[0; 4]);
    header.extend_from_slice(&(14 + 40 + 1024u32).to_le_bytes());
    assert!(!f.windows(header.len()).any(|w| w == header));
    let hex: String = header.iter().map(|b| format!("{b:02x}")).collect();
    let mut b = exav_core::loader::Builder::new();
    b.add_named_bytes(
        "t.ndb",
        format!("Test.DwgPreview:0:0:{hex}\n").as_bytes(),
        true,
    );
    let db = b.build().expect("a one-signature database");
    match analyze(&db, &f, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.DwgPreview"),
        other => panic!("the preview inside the drawing must be reached, got {other:?}"),
    }
}
