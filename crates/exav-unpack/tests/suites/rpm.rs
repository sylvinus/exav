//! RPM packages: install scripts and payload as members.
//!
//! `tests/fixtures/rpm/hello.rpm` is built by `make.py` next to it, to the
//! layout of RPM's own file format (lead, signature header, header, payload);
//! the walker was also run over 155 packages from distributions' repositories.

use exav_unpack::{extract, Budget, Entry, Format, Limits};

fn hello() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/rpm/hello.rpm",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn members(blob: &[u8]) -> Result<Vec<Entry>, String> {
    extract(Format::Rpm, &blob, &mut Budget::new(Limits::default())).map_err(|e| e.reason)
}

#[test]
fn scripts_and_payload_are_members() {
    let blob = hello();
    assert_eq!(exav_unpack::detect(&blob), Some(Format::Rpm));
    let m = members(&blob).unwrap();
    let names: Vec<_> = m.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "scripts/prein",
            "scripts/postin",
            "scripts/trigger/0",
            "scripts/trigger/1",
            "payload.cpio.gz",
        ]
    );
    assert_eq!(m[0].data, b"echo prein");
    assert_eq!(m[1].data, b"#!/bin/sh\necho postin\n");
    assert_eq!(m[3].data, b"echo second trigger");
}

/// The payload is the package's files: gzip, then cpio.
#[cfg(all(feature = "gzip", feature = "cpio"))]
#[test]
fn the_payload_is_the_packages_files() {
    let payload = members(&hello()).unwrap().pop().unwrap();
    let mut b = Budget::new(Limits::default());
    let cpio = extract(Format::Gzip, &payload.data.as_slice(), &mut b).unwrap();
    assert_eq!(
        exav_unpack::detect(&cpio[0].data.as_slice()),
        Some(Format::Cpio)
    );
    let files = extract(Format::Cpio, &cpio[0].data.as_slice(), &mut b).unwrap();
    assert_eq!(files[0].name, "./usr/share/hello/hello.txt");
    assert_eq!(files[0].data, b"hello from an rpm\n");
}

/// A package cut short has the scripts and the start of its payload, or is
/// refused when its headers are cut; it is never taken for whole.
#[test]
fn a_cut_package_is_not_silently_whole() {
    let blob = hello();
    let payload_at = blob.len() - members(&blob).unwrap().pop().unwrap().data.len();
    let cut = members(&blob[..blob.len() - 5]).unwrap();
    assert_eq!(cut.last().unwrap().data.len(), blob.len() - 5 - payload_at);
    for n in [10, 96, 100, 120, payload_at - 8] {
        assert!(members(&blob[..n]).is_err(), "cut at {n}");
    }
}

/// A header's counts are the file's to claim: past the file, they are refused.
#[test]
fn counts_past_the_file_are_refused() {
    let mut blob = hello();
    // The signature header's entry count and data size, 96 + 8.
    blob[104..108].copy_from_slice(&0xFFFFu32.to_be_bytes());
    blob[108..112].copy_from_slice(&(60u32 << 20).to_be_bytes());
    assert!(members(&blob).is_err());
}

/// An RPM of the old kind (a signature that is not a header) is reported, not
/// read as if it had one.
#[test]
fn an_old_style_signature_is_reported() {
    let mut blob = hello();
    blob[78..80].copy_from_slice(&1u16.to_be_bytes());
    let m = members(&blob).unwrap();
    assert_eq!(m.len(), 1);
    assert!(m[0].unsupported.is_some());
}
