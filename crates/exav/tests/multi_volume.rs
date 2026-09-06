//! `exav -r <dir>` must see a multi-volume archive as the archive it is.
//!
//! A set split across `big.zip.001`, `.002`, `.003` is one file cut at arbitrary
//! byte offsets. Scanned a file at a time — which is all a directory walk does —
//! no piece decodes and every line reads `OK`, so whatever the archive holds is
//! never looked at. The fixture below cuts the payload *through the middle of
//! the signature bytes*, so no individual part can match: only the rejoin can
//! find it, and these tests would pass on nothing less.

use std::process::Command;

// The binary's own temp-directory type, so the test suite needs no temp-file
// dependency either.
#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    // Deliberately the built-in EICAR-only baseline (empty `-d`); exav otherwise
    // refuses to run with no real database.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// A stored-only ZIP holding one member.
fn zip_with(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = crc32(data);
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    for v in [20u16, 0, 0, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let cd = out.len() as u32;
    let mut c = Vec::new();
    c.extend_from_slice(b"PK\x01\x02");
    for v in [20u16, 20, 0, 0, 0, 0] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c.extend_from_slice(&crc.to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(name.len() as u16).to_le_bytes());
    for _ in 0..4 {
        c.extend_from_slice(&0u16.to_le_bytes());
    }
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(name.as_bytes());
    let cl = c.len() as u32;
    out.extend_from_slice(&c);
    out.extend_from_slice(b"PK\x05\x06");
    for v in [0u16, 0, 1, 1] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&cl.to_le_bytes());
    out.extend_from_slice(&cd.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Write a byte-split set into `dir` and return the part filenames.
fn write_split_set(dir: &std::path::Path, stem: &str, n: usize, keep: &[usize]) -> Vec<String> {
    let blob = zip_with("payload.txt", EICAR);
    let each = blob.len().div_ceil(n);
    let mut names = Vec::new();
    for (i, chunk) in blob.chunks(each).enumerate() {
        if !keep.contains(&i) {
            continue;
        }
        let name = format!("{stem}.zip.{:03}", i + 1);
        std::fs::write(dir.join(&name), chunk).unwrap();
        names.push(name);
    }
    names
}

/// `exav -r --json <dir>` -> the result objects (the trailing summary dropped).
fn scan_dir_json(dir: &std::path::Path) -> Vec<serde_json::Value> {
    let db = TempDir::new().unwrap();
    let out = exav()
        .arg("-d")
        .arg(db.path())
        .arg("--json")
        .arg(dir)
        .output()
        .expect("run exav");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut objs: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e} on {l:?}")))
        .collect();
    objs.pop(); // the run summary
    objs
}

#[test]
fn a_split_archive_in_a_directory_is_rejoined_and_reported() {
    let dir = TempDir::new().unwrap();
    let parts = write_split_set(dir.path(), "payload", 3, &[0, 1, 2]);
    assert_eq!(parts.len(), 3);
    let objs = scan_dir_json(dir.path());

    // Every part scans clean on its own — that is what makes the rejoin the only
    // thing that can find this.
    let part_lines: Vec<_> = objs
        .iter()
        .filter(|o| {
            parts
                .iter()
                .any(|p| o["file"].as_str().unwrap_or("").ends_with(p))
        })
        .collect();
    assert_eq!(part_lines.len(), 3, "one line per file: {objs:#?}");
    assert!(
        part_lines.iter().all(|o| o["category"] == "clean"),
        "a fragment is not itself malware: {objs:#?}"
    );

    // And one more line, for the archive they make.
    let archive = objs
        .iter()
        .find(|o| o["file"].as_str().unwrap_or("").ends_with("payload.zip"))
        .unwrap_or_else(|| panic!("no line for the rejoined archive: {objs:#?}"));
    assert_eq!(archive["category"], "infected", "{objs:#?}");
}

#[test]
fn a_set_with_a_hole_is_reported_never_clean() {
    // Its bytes belong to an archive nothing can now read — not us, not the tool
    // that wrote it. Passing them over as clean would hide exactly that.
    let dir = TempDir::new().unwrap();
    write_split_set(dir.path(), "gap", 3, &[0, 2]);
    let objs = scan_dir_json(dir.path());
    let archive = objs
        .iter()
        .find(|o| o["file"].as_str().unwrap_or("").ends_with("gap.zip"))
        .unwrap_or_else(|| panic!("an incomplete set must be reported: {objs:#?}"));
    assert_eq!(archive["category"], "not-scanned", "{objs:#?}");
}

#[test]
fn a_lone_numbered_file_adds_no_line() {
    // Plenty of ordinary files end in `.001`. One part is not a set, and
    // flagging it would fire on all of them.
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("notes.dat.001"), b"nothing to see here").unwrap();
    let objs = scan_dir_json(dir.path());
    assert_eq!(objs.len(), 1, "exactly the one real file: {objs:#?}");
    assert_eq!(objs[0]["category"], "clean");
}

#[test]
fn parts_in_different_directories_are_not_one_set() {
    // Two unrelated files that happen to share a name. Splicing them would
    // concatenate bytes nothing ever wrote.
    let dir = TempDir::new().unwrap();
    for (sub, keep) in [("a", &[0usize][..]), ("b", &[1][..])] {
        let p = dir.path().join(sub);
        std::fs::create_dir_all(&p).unwrap();
        write_split_set(&p, "x", 2, keep);
    }
    let objs = scan_dir_json(dir.path());
    assert!(
        objs.iter().all(|o| o["category"] == "clean"),
        "nothing should have been joined across directories: {objs:#?}"
    );
}

#[test]
fn an_ordinary_directory_is_unaffected() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    std::fs::write(dir.path().join("bad.txt"), EICAR).unwrap();
    let objs = scan_dir_json(dir.path());
    assert_eq!(objs.len(), 2, "no extra lines: {objs:#?}");
    assert_eq!(
        objs.iter().filter(|o| o["category"] == "infected").count(),
        1
    );
}
