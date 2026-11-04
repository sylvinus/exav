//! AppleSingle and AppleDouble: the forks come out as members, read where they
//! lie, and the `._name` files of a ZIP's `__MACOSX/` are opened, not
//! reported.

use exav_unpack::source::BlockCache;
use exav_unpack::{Budget, Format, Limits, Member, detect, walk};
use std::io::Cursor;

/// An AppleSingle (`double` false) or AppleDouble file of `entries`.
fn build(double: bool, entries: &[(u32, &[u8])]) -> Vec<u8> {
    let mut out = vec![0x00, 0x05, 0x16, if double { 0x07 } else { 0x00 }];
    out.extend_from_slice(&0x0002_0000u32.to_be_bytes());
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    let mut at = 26 + entries.len() * 12;
    for (id, data) in entries {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(at as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        at += data.len();
    }
    for (_, data) in entries {
        out.extend_from_slice(data);
    }
    out
}

/// `(name, bytes, unsupported)` of each member.
fn members(fmt: Format, src: &dyn exav_unpack::ByteSource) -> Vec<(String, Vec<u8>, bool)> {
    let mut budget = Budget::new(Limits::default());
    let mut out = Vec::new();
    walk(fmt, src, &mut budget, &mut |meta, content, _| {
        let bytes = match content {
            Some(Member::Bytes(b)) => b,
            Some(Member::Stream(r)) => {
                let mut b = Vec::new();
                r.read_to_end(&mut b).unwrap();
                b
            }
            None => Vec::new(),
        };
        out.push((meta.name.clone(), bytes, meta.unsupported.is_some()));
        None::<()>
    })
    .unwrap();
    out
}

fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        w.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn both_kinds_are_recognised() {
    assert_eq!(
        detect(&build(false, &[(1, b"x")])),
        Some(Format::AppleSingle)
    );
    assert_eq!(
        detect(&build(true, &[(2, b"x")])),
        Some(Format::AppleSingle)
    );
}

#[test]
fn the_forks_are_read_where_they_lie() {
    let f = build(
        false,
        &[
            (3, b"Report"),
            (1, b"data fork bytes"),
            (2, b"resource fork"),
        ],
    );
    let want = vec![
        ("Report".to_string(), b"data fork bytes".to_vec(), false),
        ("Report.rsrc".to_string(), b"resource fork".to_vec(), false),
    ];
    assert_eq!(members(Format::AppleSingle, &f), want);
    // Through a cache of tiny blocks, as a file on disk is read.
    let cached = BlockCache::with_sizes(Cursor::new(f), 16, 64).unwrap();
    assert_eq!(members(Format::AppleSingle, &cached), want);
}

#[cfg(feature = "zip")]
#[test]
fn a_fork_holding_an_archive_is_typed_as_that_archive() {
    let inner = zip_of(&[("a.txt", b"hello")]);
    let f = build(true, &[(9, &[0; 32]), (2, &inner)]);
    let got = members(Format::AppleSingle, &f);
    assert_eq!(got.len(), 1);
    assert_eq!(detect(&got[0].1), Some(Format::Zip));
}

#[cfg(feature = "zip")]
#[test]
fn the_macosx_files_of_a_zip_are_opened_not_reported() {
    let finder_only = build(true, &[(9, &[0; 32])]);
    let with_rsrc = build(true, &[(9, &[0; 32]), (2, b"icon resources")]);
    let z = zip_of(&[
        ("a.txt", b"text"),
        ("__MACOSX/._a.txt", &finder_only),
        ("__MACOSX/._b.txt", &with_rsrc),
    ]);
    let outer = members(Format::Zip, &z);
    assert_eq!(outer.len(), 3);
    let mut inner = Vec::new();
    for (name, bytes, _) in &outer[1..] {
        assert_eq!(detect(bytes), Some(Format::AppleSingle), "{name}");
        inner.extend(members(Format::AppleSingle, bytes));
    }
    assert_eq!(
        inner,
        vec![(
            "applefile.rsrc".to_string(),
            b"icon resources".to_vec(),
            false
        )]
    );
}
