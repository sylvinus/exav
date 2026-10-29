//! `exav` must see the volumes of a RAR, ZIP or CAB set as the archive they are.
//!
//! Each volume holds part of a member, so a volume scanned alone shows nothing
//! of it. The ZIP fixture is `zip -0 -s 64k e.zip e.bin` of 70,000 bytes with
//! the EICAR line placed across the place the first part ends: neither part
//! holds it, and only the rejoined archive does. The cabinets are built here
//! with the line cut in the same way. The RAR sets are official RAR's, and
//! are found by the MD5 of the member split across all their volumes
//! (exav-core's `tests/fixtures/volumes`).

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

fn fixture(dir: &str, name: &str) -> Vec<u8> {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), dir, name].iter().collect();
    exav_core::unpack::read_fixture(&p.to_string_lossy())
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// `exav --json -d <empty> <targets>` -> the result objects, the summary dropped.
fn scan(db: &Path, targets: &[&Path]) -> Vec<serde_json::Value> {
    let out = exav()
        .arg("-d")
        .arg(db)
        .arg("--json")
        .args(targets)
        .output()
        .expect("run exav");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut objs: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e} on {l:?}")))
        .collect();
    objs.pop();
    objs
}

fn found<'a>(objs: &'a [serde_json::Value], file: &str) -> Option<&'a serde_json::Value> {
    objs.iter()
        .find(|o| o["status"] == "FOUND" && o["file"].as_str().unwrap_or("").ends_with(file))
}

fn zip_set(dir: &Path) {
    for n in ["e.z01", "e.zip"] {
        std::fs::write(dir.join(n), fixture("tests/fixtures/split", n)).unwrap();
    }
}

#[test]
fn a_split_zip_in_a_directory_is_rejoined_and_found() {
    let dir = TempDir::new().unwrap();
    zip_set(dir.path());
    let db = TempDir::new().unwrap();
    let objs = scan(db.path(), &[dir.path()]);
    let hit = found(&objs, "e.zip")
        .unwrap_or_else(|| panic!("the rejoined archive is not reported: {objs:#?}"));
    assert!(
        hit["signature"].as_str().unwrap_or("").contains("Eicar"),
        "{hit}"
    );
    // Nothing is reported FOUND for a fragment.
    assert!(found(&objs, "e.z01").is_none(), "{objs:#?}");
}

#[test]
fn a_part_named_alone_is_scanned_with_its_siblings() {
    let dir = TempDir::new().unwrap();
    zip_set(dir.path());
    let db = TempDir::new().unwrap();
    for part in ["e.z01", "e.zip"] {
        let objs = scan(db.path(), &[&dir.path().join(part)]);
        assert!(
            found(&objs, "e.zip").is_some(),
            "{part} named alone: {objs:#?}"
        );
    }
}

#[test]
fn parts_that_are_not_next_to_each_other_are_not_joined() {
    let db = TempDir::new().unwrap();
    let (a, b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    std::fs::write(
        a.path().join("e.z01"),
        fixture("tests/fixtures/split", "e.z01"),
    )
    .unwrap();
    std::fs::write(
        b.path().join("e.zip"),
        fixture("tests/fixtures/split", "e.zip"),
    )
    .unwrap();
    for dir in [a.path(), b.path()] {
        let objs = scan(db.path(), &[dir]);
        assert!(objs.iter().all(|o| o["status"] != "FOUND"), "{objs:#?}");
    }
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_not_a_part() {
    // The last part is a link to a file elsewhere: a name next to the scanned
    // file is not a licence to read what the link points at.
    let dir = TempDir::new().unwrap();
    let elsewhere = TempDir::new().unwrap();
    std::fs::write(
        elsewhere.path().join("target.zip"),
        fixture("tests/fixtures/split", "e.zip"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("e.z01"),
        fixture("tests/fixtures/split", "e.z01"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        elsewhere.path().join("target.zip"),
        dir.path().join("e.zip"),
    )
    .unwrap();
    let db = TempDir::new().unwrap();
    let objs = scan(db.path(), &[&dir.path().join("e.z01")]);
    assert!(objs.iter().all(|o| o["status"] != "FOUND"), "{objs:#?}");
}

/// A cabinet of one uncompressed folder.
fn cab(
    prev: Option<&str>,
    next: Option<&str>,
    index: u16,
    size: u32,
    place: u16,
    uncompressed: u16,
    payload: &[u8],
) -> Vec<u8> {
    let flags = u16::from(prev.is_some()) | (u16::from(next.is_some()) << 1);
    let mut links = Vec::new();
    for n in [prev, next].into_iter().flatten() {
        links.extend_from_slice(n.as_bytes());
        links.extend_from_slice(b"\0disk\0");
    }
    let mut file = Vec::new();
    file.extend_from_slice(&size.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&place.to_le_bytes());
    file.extend_from_slice(&[0x21, 0x5a, 0x00, 0x60, 0x20, 0x00]);
    file.extend_from_slice(b"eicar.com\0");
    let coff_files = 36 + links.len() + 8;
    let data_at = coff_files + file.len();
    let mut block = Vec::new();
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    block.extend_from_slice(&uncompressed.to_le_bytes());
    block.extend_from_slice(payload);
    let mut out = b"MSCF".to_vec();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&((data_at + block.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(coff_files as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3, 1]);
    for v in [1u16, 1, flags, 3, index] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend(links);
    out.extend_from_slice(&(data_at as u32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend(file);
    out.extend(block);
    out
}

#[test]
fn a_cab_set_is_rejoined_by_the_names_its_headers_give() {
    let eicar = exav_core::unpack::eicar();
    let cut = eicar.len() / 2;
    let one = cab(
        None,
        Some("disk2.cab"),
        0,
        eicar.len() as u32,
        0xFFFE,
        0,
        &eicar[..cut],
    );
    let two = cab(
        Some("disk1.cab"),
        None,
        1,
        eicar.len() as u32,
        0xFFFD,
        eicar.len() as u16,
        &eicar[cut..],
    );
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("disk1.cab"), &one).unwrap();
    std::fs::write(dir.path().join("disk2.cab"), &two).unwrap();
    let db = TempDir::new().unwrap();
    let objs = scan(db.path(), &[dir.path()]);
    assert!(found(&objs, "disk1.cab").is_some(), "{objs:#?}");
    // A neighbour under another name is not the cabinet the header names.
    let other = TempDir::new().unwrap();
    std::fs::write(other.path().join("disk1.cab"), &one).unwrap();
    std::fs::write(other.path().join("renamed.cab"), &two).unwrap();
    let objs = scan(db.path(), &[other.path()]);
    assert!(objs.iter().all(|o| o["status"] != "FOUND"), "{objs:#?}");
    assert!(
        objs.iter()
            .any(|o| o["status"] == "PARTIAL"
                && o["file"].as_str().unwrap_or("").ends_with("disk1.cab")),
        "{objs:#?}"
    );
}

#[test]
fn a_rar_set_is_rejoined_and_its_split_member_found() {
    let sets = [
        (
            "set5",
            ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"],
        ),
        ("set4", ["set4.rar", "set4.r00", "set4.r01"]),
    ];
    // The MD5 of `noise.bin`, which every volume of both sets holds part of.
    let db = TempDir::new().unwrap();
    std::fs::write(
        db.path().join("t.hdb"),
        "147b5c8ca1767bca1ef297b3024fb0dd:20000:Test.Noise\n",
    )
    .unwrap();
    for (set, parts) in sets {
        let dir = TempDir::new().unwrap();
        for p in parts {
            std::fs::write(
                dir.path().join(p),
                fixture("../exav-core/tests/fixtures/volumes", p),
            )
            .unwrap();
        }
        let objs = scan(db.path(), &[dir.path()]);
        let hit = found(&objs, &format!("{set}.rar")).unwrap_or_else(|| panic!("{set}: {objs:#?}"));
        assert!(
            hit["signature"]
                .as_str()
                .unwrap_or("")
                .contains("Test.Noise"),
            "{hit}"
        );
        // One of its volumes named alone finds it as well.
        let objs = scan(db.path(), &[&dir.path().join(parts[1])]);
        assert!(
            found(&objs, &format!("{set}.rar")).is_some(),
            "{set} by its second volume: {objs:#?}"
        );
    }
}
