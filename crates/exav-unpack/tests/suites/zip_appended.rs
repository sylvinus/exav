//! A ZIP whose offsets count from the archive's own start while bytes precede
//! it: a self-extractor's payload, or an archive appended to another file.

use exav_unpack::{walk, Budget, Format, Limits, Member, MemberMeta};
use std::io::Write;

fn zip_of(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file(name, zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(contents).unwrap();
    z.finish().unwrap().into_inner()
}

/// From a live installer: an executable embedding two JARs back to back, its
/// carved payload starting at an earlier `PK\x03\x04` in the code. Searching
/// from the second JAR's declared directory offset finds the first JAR's
/// directory, so every member was read at the wrong place and the file came out
/// `UNSCANNABLE`. There, the rest of the executable followed the second JAR.
#[test]
fn the_last_archive_is_read_from_its_own_directory() {
    let mut blob = vec![0x90u8; 200];
    blob.extend_from_slice(&zip_of("first.txt", b"the first archive"));
    blob.extend_from_slice(&zip_of("second.txt", b"payload-that-must-be-scanned"));
    let bare = blob.len();
    blob.resize(bare + 100_000, 0x90);
    for blob in [&blob[..bare], &blob[..]] {
        check_last_archive(blob);
    }
}

/// From a NuGet package in a live MSI: bytes between the last member and the
/// central directory that the directory's offset does not count, while the
/// members' offsets count from the start. `unzip` warns and reads it; every
/// member read at the shifted place and was reported `UNSCANNABLE`.
#[test]
fn bytes_before_the_directory_are_left_out() {
    let zip = zip_of("lib.dll", b"payload-that-must-be-scanned");
    let eocd = zip.len() - 22;
    let cd = u32::from_le_bytes(zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let mut blob = zip[..cd].to_vec();
    blob.extend_from_slice(&[0x5a; 4096]);
    blob.extend_from_slice(&zip[cd..]);
    let mut budget = Budget::new(Limits::default());
    let mut seen = Vec::new();
    let _ = walk::<()>(
        Format::Zip,
        &blob,
        &mut budget,
        &mut |meta: &MemberMeta, content: Option<Member<'_>>, _b: &mut Budget| {
            let mut d = Vec::new();
            if let Some(Member::Stream(r)) = content {
                let _ = r.read_to_end(&mut d);
            }
            seen.push((meta.name.clone(), meta.unsupported, d));
            None
        },
    );
    assert_eq!(
        seen,
        vec![(
            "lib.dll".to_string(),
            None,
            b"payload-that-must-be-scanned".to_vec()
        )]
    );
}

fn check_last_archive(blob: &[u8]) {
    let mut budget = Budget::new(Limits::default());
    let mut seen = Vec::new();
    let _ = walk::<()>(
        Format::Zip,
        &blob,
        &mut budget,
        &mut |meta: &MemberMeta, content: Option<Member<'_>>, _b: &mut Budget| {
            let mut d = Vec::new();
            match content {
                None => {}
                Some(Member::Bytes(b)) => d = b,
                Some(Member::Stream(r)) => {
                    let _ = r.read_to_end(&mut d);
                }
            }
            seen.push((meta.name.clone(), meta.unsupported, d));
            None
        },
    );
    assert!(
        seen.iter().all(|(_, unsupported, _)| unsupported.is_none()),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|(name, _, d)| name == "second.txt" && d == b"payload-that-must-be-scanned"),
        "{seen:?}"
    );
}
