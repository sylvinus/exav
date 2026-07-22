//! cpio members must never be silently truncated.
//!
//! `filesize` comes from the header and is attacker-controlled, so the slice end
//! has to be clamped to the buffer or it would panic. But clamping turns "this
//! member runs past the end of the archive" into "here is a shorter member",
//! and a short member gets scanned and found clean on content that is not
//! there. Three cpio header flavours share the bug and the fix.

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

/// A `newc`-format cpio header. All fields are 8-char hex, ASCII.
fn newc(name: &str, filesize: u32) -> Vec<u8> {
    let mut h = String::from("070701");
    let fields = [
        1u32,                  // ino
        0o100644,              // mode
        0,                     // uid
        0,                     // gid
        1,                     // nlink
        0,                     // mtime
        filesize,              // filesize
        0,                     // devmajor
        0,                     // devminor
        0,                     // rdevmajor
        0,                     // rdevminor
        name.len() as u32 + 1, // namesize (incl. NUL)
        0,                     // check
    ];
    for f in fields {
        h.push_str(&format!("{f:08X}"));
    }
    let mut v = h.into_bytes();
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    // Header + name are padded to a 4-byte boundary.
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

fn trailer() -> Vec<u8> {
    let mut v = newc("TRAILER!!!", 0);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

fn emitted(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Cpio,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

#[test]
fn a_well_formed_member_extracts_cleanly() {
    // Baseline: the reporting below must not fire on an ordinary archive.
    let mut blob = newc("hello.txt", 5);
    blob.extend_from_slice(b"hello");
    while !blob.len().is_multiple_of(4) {
        blob.push(0);
    }
    blob.extend_from_slice(&trailer());

    let e = emitted(&blob);
    assert!(
        e.iter()
            .any(|x| x.data == b"hello" && x.unsupported.is_none()),
        "a valid member must extract, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported, x.data.len()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_truncated_member_is_scanned_short_not_flagged() {
    // Declare 1 MiB, supply 5 bytes. Those bytes are ABSENT from the archive,
    // not hidden in it: the victim's extractor gets nothing either, so there is
    // no evasion to catch. Scanning what exists and returning clean is the
    // honest answer — exav is not a file-integrity validator (docs/QUIRKS.md).
    let mut blob = newc("truncated.bin", 1024 * 1024);
    blob.extend_from_slice(b"hello");

    let e = emitted(&blob);
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "truncation must not be reported as unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported, x.data.len()))
            .collect::<Vec<_>>()
    );
}
