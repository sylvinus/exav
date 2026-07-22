//! `max_members` must count *objects*, one apiece.
//!
//! The limit is the operator's guard against an archive with a million tiny
//! members, and it only means what it says if one member costs one. Counting
//! several per member cuts a scan short early — reporting LIMITS-EXCEEDED on an
//! archive that was well inside the configured bound, which looks like a
//! resource problem and is really an accounting one.
//!
//! Four traversals used to keep their own tallies. These tests pin the
//! arithmetic to the shape a caller can reason about: a flat archive costs its
//! member count, and nesting costs the members at each level and nothing more.

use exav_unpack::{extract, Budget, Format, Limits};
use std::io::Write;

/// Extract with `max_members` set to `cap`, and say whether the limit fired.
fn hits_limit(blob: &[u8], fmt: Format, cap: u64) -> bool {
    let mut budget = Budget::new(Limits {
        max_members: cap,
        ..Default::default()
    });
    extract(fmt, blob, &mut budget).is_err()
}

fn tar_of(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in members {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, &data[..]).unwrap();
    }
    b.into_inner().unwrap()
}

fn zip_of(name: &str, data: &[u8]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file(name, zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap().into_inner()
}

/// Ten members cost ten. Nine is one too few; ten is exactly enough.
#[test]
#[cfg(feature = "tar")]
fn a_flat_archive_costs_one_per_member() {
    let members: Vec<(&str, Vec<u8>)> = (0..10)
        .map(|i| ("m.txt", format!("member {i}").into_bytes()))
        .collect();
    let blob = tar_of(&members);

    assert!(hits_limit(&blob, Format::Tar, 9), "ten members fit under 9");
    assert!(
        !hits_limit(&blob, Format::Tar, 10),
        "ten members cost more than ten — the limit counts something other than objects"
    );
}

/// A member that is *itself* an archive still costs one.
///
/// This layer hands members out; it does not descend — the scanner does that,
/// and it charges the inner members as it goes. So the cost here is the member
/// count either way, and a container member must not be charged for what it
/// might contain.
#[test]
#[cfg(all(feature = "tar", feature = "zip"))]
fn a_member_that_is_itself_an_archive_still_costs_one() {
    let members: Vec<(&str, Vec<u8>)> = (0..5)
        .map(|i| {
            (
                "z.zip",
                zip_of("inner.txt", format!("inner {i}").as_bytes()),
            )
        })
        .collect();
    let blob = tar_of(&members);

    assert!(
        hits_limit(&blob, Format::Tar, 4),
        "five members fit under 4"
    );
    assert!(
        !hits_limit(&blob, Format::Tar, 5),
        "five archive members cost more than five"
    );
}
