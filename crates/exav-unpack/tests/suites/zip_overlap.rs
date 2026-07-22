//! Overlapping ZIP local file records — the signal behind ClamAV's
//! `Heuristics.Zip.OverlappingFiles`, which is on by default there.
//!
//! A well-formed ZIP lays its local records out end to end. Overlapping them is
//! a parser-confusion technique: two readers disagree about where a member
//! starts, so the archive shows one file to the scanner and a different one to
//! whatever finally opens it. The point of the heuristic is that no honest
//! writer produces this.
//!
//! Both directions are pinned. A detector that fires on ordinary archives is
//! worse than none — every `.jar`, `.docx` and `.apk` is a ZIP.

use exav_unpack::overlapping_local_records;
use std::io::Write;

/// A normal archive, written by a real ZIP writer.
fn ordinary_zip(members: usize) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..members {
        z.start_file(
            format!("file{i}.txt"),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        z.write_all(format!("contents of member {i}\n").as_bytes())
            .unwrap();
    }
    z.finish().unwrap().into_inner()
}

/// Hand-build `n` local file records that all claim to extend past each other,
/// which is what a confusion attack looks like on the wire.
fn overlapping_zip(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        let name = format!("m{i}.txt");
        let payload = b"AAAAAAAAAAAAAAAA";
        // Declare a compressed size far larger than what follows, so this
        // record's extent runs over every record written after it.
        let declared = (payload.len() + 4096) as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags (no data descriptor)
        out.extend_from_slice(&0u16.to_le_bytes()); // method: store
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0x21u16.to_le_bytes()); // date (valid)
        out.extend_from_slice(&0u32.to_le_bytes()); // crc
        out.extend_from_slice(&declared.to_le_bytes()); // compressed size
        out.extend_from_slice(&declared.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(payload);
    }
    // Pad so every declared extent stays inside the file; a record running past
    // EOF is discarded as implausible rather than counted.
    out.resize(out.len() + 8192, 0);
    out
}

#[test]
fn an_ordinary_archive_has_no_overlaps() {
    for n in [1, 5, 20, 100] {
        assert_eq!(
            overlapping_local_records(&ordinary_zip(n)),
            0,
            "a {n}-member archive from a real writer must show no overlap; \
             firing here would flag every jar, docx and apk"
        );
    }
}

#[test]
fn overlapping_records_are_counted() {
    // Ten records that each claim to run over the ones after them.
    let n = overlapping_local_records(&overlapping_zip(10));
    assert!(
        n > 5,
        "overlapping records must be counted above ClamAV's threshold of 5; got {n}"
    );
}

#[test]
fn a_deferred_size_member_is_not_an_overlap() {
    // Bit 3 defers the sizes to a trailing data descriptor, so the record's end
    // is not knowable from the header. Guessing an extent here would invent
    // overlaps on ordinary streamed archives — the common shape for a ZIP
    // written to a pipe.
    let mut out = Vec::new();
    for i in 0..10 {
        let name = format!("s{i}.txt");
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0x0008u16.to_le_bytes()); // data-descriptor flag
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x21u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // size deferred
        out.extend_from_slice(&0u32.to_le_bytes()); // size deferred
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"payload-bytes");
    }
    assert_eq!(
        overlapping_local_records(&out),
        0,
        "deferred-size members have no known extent and must not be counted"
    );
}

#[test]
fn garbage_is_not_an_archive() {
    // `PK\x03\x04` is four bytes and occurs by chance. The plausibility gate has
    // to hold, or random binaries start reporting overlaps.
    let mut noise = Vec::new();
    for i in 0..2000u32 {
        noise.extend_from_slice(&i.wrapping_mul(2654435761).to_le_bytes());
    }
    assert_eq!(overlapping_local_records(&noise), 0);
}

/// A nested archive stored UNCOMPRESSED puts its own local headers physically
/// inside the outer member's extent. Every one of them used to be counted as a
/// top-level record overlapping its neighbour, so ordinary build output was
/// reported as a parser-confusion attack: Android app bundles (`assets/base.apk`)
/// and shaded JARs (`META-INF/jars/*.jar`) are built exactly this way, and
/// measured 6 to 794 "overlaps" against a threshold of 5.
#[test]
fn a_nested_stored_archive_is_not_an_overlap() {
    use std::io::Write;

    // The inner archive: deflated members, nothing remarkable.
    let mut inner = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..12 {
        inner
            .start_file(
                format!("cls{i}.class"),
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        inner.write_all(b"totally benign class data").unwrap();
    }
    let inner = inner.finish().unwrap().into_inner();

    // Stored, so the inner headers land verbatim inside the outer member.
    let mut outer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    outer
        .start_file(
            "META-INF/jars/dep.jar",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    outer.write_all(&inner).unwrap();
    let outer = outer.finish().unwrap().into_inner();

    assert_eq!(
        overlapping_local_records(&outer),
        0,
        "a stored nested archive is how jars and app bundles are built, not an attack"
    );
}
