//! ZIP members disguised so that ordinary tools decline to extract them, while
//! the platform that consumes the archive reads them happily. Both tricks below
//! came off live samples in a clamd differential run, where each cost a real
//! detection.
//!
//! Every case is asserted through [`extract`] and through a [`walk`] visitor
//! reading each member as it comes, the way the scanner does. The first fix for
//! the trailing-slash trick once landed in a second ZIP walker the scanner did
//! not use, and the sample still scanned clean; asserting on the walk the
//! scanner takes is what catches that.

use exav_unpack::{extract, walk, Budget, Entry, Format, Limits, Member, MemberMeta};

/// Bitwise CRC-32 (IEEE), so the fixtures carry real checksums without pulling a
/// dependency into the test.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Build a ZIP of STORED members: `(name, contents, general-purpose flags, crc)`.
/// The CRC is passed in rather than computed so a test can write a deliberately
/// wrong one (what a truly encrypted member looks like from outside).
fn zip_stored(members: &[(&str, &[u8], u16, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, flags, crc) in members {
        let off = out.len() as u32;
        let mut hdr = Vec::new();
        hdr.extend_from_slice(b"PK\x03\x04");
        hdr.extend_from_slice(&20u16.to_le_bytes()); // version needed
        hdr.extend_from_slice(&flags.to_le_bytes());
        hdr.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        hdr.extend_from_slice(&0u16.to_le_bytes()); // time
        hdr.extend_from_slice(&0u16.to_le_bytes()); // date
        hdr.extend_from_slice(&crc.to_le_bytes());
        hdr.extend_from_slice(&(data.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&(data.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&(name.len() as u16).to_le_bytes());
        hdr.extend_from_slice(&0u16.to_le_bytes()); // extra len
        hdr.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&off.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Members [`extract`] yields.
fn buffered(blob: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Zip, &blob, &mut budget).expect("extract")
}

/// Members a [`walk`] visitor sees, as `(name, contents)`. A member with no
/// content (nothing decodable) comes back empty.
fn streamed(blob: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut budget = Budget::new(Limits::default());
    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
    let _ = walk::<()>(
        Format::Zip,
        &blob,
        &mut budget,
        &mut |meta: &MemberMeta, content: Option<Member<'_>>, _b: &mut Budget| {
            let buf = match content {
                None => Vec::new(),
                Some(Member::Bytes(d)) => d,
                Some(Member::Stream(r)) => {
                    let mut d = Vec::new();
                    let _ = r.read_to_end(&mut d);
                    d
                }
            };
            seen.push((meta.name.clone(), buf));
            None
        },
    );
    seen
}

const PAYLOAD: &[u8] = b"payload-that-must-be-scanned";

/// A member whose name ends in '/' but which carries content is content.
///
/// From a live JAR: `kingDavid/9.class/` held a real compressed Java class. The
/// JVM loads it by name; `unzip`, python's `extractall` and the `zip` crate all
/// call it a directory and discard it, so the malware inside was never scanned.
#[test]
fn slash_named_member_with_content_is_extracted() {
    let blob = zip_stored(&[("pkg/9.class/", PAYLOAD, 0, crc32(PAYLOAD))]);

    let b = buffered(&blob);
    assert!(
        b.iter().any(|e| e.data == PAYLOAD),
        "buffered walker dropped a slash-named member that carries content: {:?}",
        b.iter()
            .map(|e| (&e.name, e.data.len()))
            .collect::<Vec<_>>()
    );

    let s = streamed(&blob);
    assert!(
        s.iter().any(|(_, d)| d == PAYLOAD),
        "streaming walker dropped a slash-named member that carries content: {s:?}"
    );
}

/// The converse: a real directory entry carries nothing, so it must still be
/// skipped. Emitting an empty member for every folder would be noise, and would
/// spend the entry budget that real members need.
#[test]
fn genuine_directory_entry_is_still_skipped() {
    let blob = zip_stored(&[
        ("pkg/", b"", 0, 0),
        ("pkg/real.txt", PAYLOAD, 0, crc32(PAYLOAD)),
    ]);

    let b = buffered(&blob);
    assert_eq!(
        b.iter().filter(|e| !e.data.is_empty()).count(),
        1,
        "expected exactly the one member with content"
    );
    assert!(!b.iter().any(|e| e.name == "pkg/"), "emitted a bare folder");

    let s = streamed(&blob);
    assert_eq!(
        s.iter().filter(|(_, d)| !d.is_empty()).count(),
        1,
        "streaming walker: expected exactly the one member with content: {s:?}"
    );
}

/// A member flagged encrypted whose bytes are in fact cleartext (proven by the
/// CRC-32 in its own header) must be scanned, not reported password-protected.
///
/// From live APKs: the packer sets bit 0 on *every* member (Android's ZIP reader
/// ignores it), so scanners decline an archive the platform installs happily.
/// Reporting it is not good enough here: the report is exactly what the packer
/// is buying.
#[test]
fn lying_encryption_flag_is_seen_through() {
    let blob = zip_stored(&[("classes.dex", PAYLOAD, 0x0001, crc32(PAYLOAD))]);

    let s = streamed(&blob);
    assert!(
        s.iter().any(|(_, d)| d == PAYLOAD),
        "streaming walker believed a false encryption flag: {s:?}"
    );

    let b = buffered(&blob);
    assert!(
        b.iter().any(|e| e.data == PAYLOAD),
        "buffered walker believed a false encryption flag: {:?}",
        b.iter()
            .map(|e| (&e.name, e.encrypted, e.unsupported))
            .collect::<Vec<_>>()
    );
}

/// Typing a ZIP that is not held in memory, then walking it without reading its
/// members, reads its start, directory and headers, not the members' bytes: a
/// listing over a network or browser reader must not fetch the whole archive.
#[test]
fn listing_a_zip_through_a_reader_skips_its_members() {
    use exav_unpack::source::BlockCache;
    use std::cell::Cell;
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::rc::Rc;

    struct Counting(Cursor<Vec<u8>>, Rc<Cell<usize>>);
    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1.set(self.1.get() + n);
            Ok(n)
        }
    }
    impl Seek for Counting {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(to)
        }
    }

    let (one, two) = (vec![1u8; 1 << 20], vec![2u8; 1 << 20]);
    let blob = zip_stored(&[
        ("one.bin", &one, 0, crc32(&one)),
        ("two.bin", &two, 0, crc32(&two)),
    ]);
    let read = Rc::new(Cell::new(0));
    let cache = BlockCache::new(Counting(Cursor::new(blob.clone()), read.clone())).unwrap();
    assert_eq!(exav_unpack::detect(&cache), Some(Format::Zip));
    let mut names = Vec::new();
    let walked = walk(
        Format::Zip,
        &cache,
        &mut Budget::new(Limits::default()),
        &mut |meta, _, _| {
            names.push(meta.name.clone());
            None::<()>
        },
    );
    assert!(walked.is_ok(), "{walked:?}");
    assert_eq!(names, ["one.bin", "two.bin"]);
    assert!(
        read.get() < blob.len() / 2,
        "listing read {} of the archive's {} bytes",
        read.get(),
        blob.len()
    );
}

/// The guard must not swing the other way: a member whose contents do NOT match
/// the declared CRC is truly encrypted (or corrupt), and is still reported
/// rather than handed over as though it were cleartext.
#[test]
fn real_encryption_is_still_reported() {
    // Plausible ciphertext: bytes that are not the payload, with the CRC of the
    // plaintext: exactly what a real encrypted member looks like from outside.
    let cipher = b"\x9f\x2a\x71\xc3\x04\xde\x88\x10\x55\xab\xcd\xef\x01\x23\x45\x67";
    let blob = zip_stored(&[("secret.bin", cipher, 0x0001, crc32(PAYLOAD))]);

    let b = buffered(&blob);
    assert!(
        b.iter().any(|e| e.encrypted || e.unsupported.is_some()),
        "a truly encrypted member was not surfaced: {:?}",
        b.iter()
            .map(|e| (&e.name, e.encrypted, e.unsupported))
            .collect::<Vec<_>>()
    );
    assert!(
        !b.iter().any(|e| e.data == PAYLOAD),
        "ciphertext was handed over as though it had decoded"
    );

    let s = streamed(&blob);
    assert!(
        !s.iter().any(|(_, d)| d == PAYLOAD),
        "streaming walker handed over ciphertext as though it had decoded: {s:?}"
    );
}
