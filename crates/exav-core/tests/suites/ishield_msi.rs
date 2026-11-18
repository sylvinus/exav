//! The setup executable of InstallShield 2009 to 2011 carries the installer
//! MSI and its companion files after the executable, coded with a key made
//! from each file's name and inflated. clamscan opens it and scans the files
//! and what is inside the MSI; so does exav, in both modes.

use std::io::Write;

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};
use md5::{Digest, Md5};

const MIX: [u8; 4] = [0x13, 0x35, 0x86, 0x07];

/// `data` as an installer codes it, in blocks of 1024 bytes.
fn encode(name: &str, data: &[u8]) -> Vec<u8> {
    let key: Vec<u8> = name
        .bytes()
        .zip(MIX.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect();
    data.iter()
        .enumerate()
        .map(|(i, &b)| (key[(i % 1024) % key.len()] ^ !b).rotate_left(4))
        .collect()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// How a file is stored: coded in blocks and inflated, as the real ones are, or as it is.
#[derive(Clone, Copy)]
enum Stored {
    Packed,
    Plain,
}

/// A setup executable: a stub, the header, and a record and the data of each file.
fn setup(count: u16, files: &[(&str, &[u8], Stored)]) -> Vec<u8> {
    let mut out = b"MZ".to_vec();
    out.resize(0x1000, 0x90);
    out.extend_from_slice(b"InstallShield\0");
    out.extend_from_slice(&count.to_le_bytes());
    out.resize(0x1000 + 46, 0);
    for (name, data, stored) in files {
        let (flags, inflate, data) = match stored {
            Stored::Packed => (6u32, 1u8, encode(name, &zlib(data))),
            Stored::Plain => (0, 0, data.to_vec()),
        };
        let mut record = vec![0u8; 312];
        record[..name.len()].copy_from_slice(name.as_bytes());
        record[260..264].copy_from_slice(&flags.to_le_bytes());
        record[268..272].copy_from_slice(&(data.len() as u32).to_le_bytes());
        record[280] = inflate;
        out.extend_from_slice(&record);
        out.extend_from_slice(&data);
    }
    out
}

/// The same installer as InstallShield 2015 and later lays it out: the header
/// `ISSetupStream\0`, and UTF-16 names.
fn setup_stream(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"MZ".to_vec();
    out.resize(0x1000, 0x90);
    out.extend_from_slice(b"ISSetupStream\0");
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.resize(0x1000 + 46, 0);
    for (name, data) in files {
        let data = encode(name, &zlib(data));
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut attributes = vec![0u8; 24];
        attributes[..4].copy_from_slice(&(name.len() as u32).to_le_bytes());
        attributes[4..8].copy_from_slice(&6u32.to_le_bytes());
        attributes[10..14].copy_from_slice(&(data.len() as u32).to_le_bytes());
        attributes[22] = 1;
        out.extend_from_slice(&attributes);
        out.extend_from_slice(&name);
        out.extend_from_slice(&data);
    }
    out
}

/// A compound file standing for the installer MSI: one stream, as its tables are.
fn msi(stream: &[u8]) -> Vec<u8> {
    let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    let mut s = cf.create_stream("/Binary.Payload").unwrap();
    s.write_all(stream).unwrap();
    drop(s);
    cf.flush().unwrap();
    cf.into_inner().into_inner()
}

fn md5(data: &[u8]) -> String {
    Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn signature_on(data: &[u8], name: &str) -> Scanner {
    let mut b = loader::Builder::new();
    b.add_named_bytes(
        "a.hdb",
        format!("{}:{}:{name}\n", md5(data), data.len()).as_bytes(),
        true,
    );
    b.build().unwrap()
}

fn found(db: &Scanner, file: &[u8], opts: &ScanOptions) -> Option<String> {
    match analyze(db, file, opts).verdict {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

const STREAM: &[u8] = b"a stream of the installer database, long enough to be told from noise";
const INI: &[u8] = b"[Startup]\r\nProduct=Test\r\n";

fn installer() -> (Vec<u8>, Vec<u8>) {
    let msi = msi(STREAM);
    let exe = setup(
        3,
        &[
            ("Setup.msi", &msi, Stored::Packed),
            ("Setup.ini", INI, Stored::Plain),
            ("0x0409.ini", INI, Stored::Packed),
        ],
    );
    (exe, msi)
}

fn modes() -> [(&'static str, ScanOptions); 2] {
    [
        ("default", ScanOptions::default()),
        ("compat", ScanOptions::clamav_compat()),
    ]
}

/// A signature on the MSI, on a file beside it (stored as it is, and coded) and
/// on a stream inside the MSI is found, in both modes.
#[test]
fn the_files_of_a_setup_executable_and_what_is_in_its_msi_are_scanned() {
    let (exe, msi) = installer();
    for (mode, opts) in modes() {
        for (name, content) in [
            ("Sig.Msi", &msi[..]),
            ("Sig.Ini", INI),
            ("Sig.Stream", STREAM),
        ] {
            let db = signature_on(content, name);
            assert_eq!(found(&db, &exe, &opts).as_deref(), Some(name), "{mode}");
        }
    }
}

/// The setup executable of InstallShield 2015 and later is opened by default
/// and left as it is under `--clamav-compat`: clamscan 1.4.3 types it as a
/// plain executable and finds nothing in it.
#[test]
fn the_setup_executable_of_installshield_2015_is_opened_by_default_and_not_under_compat() {
    let msi = msi(STREAM);
    let exe = setup_stream(&[("Setup.msi", &msi), ("Setup.ini", INI)]);
    for (name, content) in [
        ("Sig.Msi", &msi[..]),
        ("Sig.Stream", STREAM),
        ("Sig.Ini", INI),
    ] {
        let db = signature_on(content, name);
        assert_eq!(
            found(&db, &exe, &ScanOptions::default()).as_deref(),
            Some(name)
        );
        assert_eq!(
            analyze(&db, &exe, &ScanOptions::clamav_compat()).verdict,
            Verdict::Clean,
            "{name}"
        );
    }
}

/// Nothing is found in a setup executable that holds nothing the signatures are for.
#[test]
fn a_setup_executable_with_nothing_in_it_is_clean() {
    let (exe, _) = installer();
    let db = signature_on(b"something else entirely", "Sig.Other");
    for (mode, opts) in modes() {
        assert_eq!(analyze(&db, &exe, &opts).verdict, Verdict::Clean, "{mode}");
    }
}

/// The tag in a resource, with no record after it, types nothing.
#[test]
fn the_tag_alone_does_not_make_a_setup_executable() {
    let mut exe = b"MZ".to_vec();
    exe.resize(0x1000, 0x90);
    exe.extend_from_slice(b"InstallShield\0 is a name in a resource");
    let db = signature_on(STREAM, "Sig.Stream");
    for (mode, opts) in modes() {
        assert_eq!(analyze(&db, &exe, &opts).verdict, Verdict::Clean, "{mode}");
    }
}

/// A file cut by the end of the executable, or a count the records do not
/// reach, is not a clean scan.
#[test]
fn a_setup_executable_that_is_cut_or_miscounted_is_not_clean() {
    let (exe, _) = installer();
    let db = signature_on(b"something else entirely", "Sig.Other");
    let cut = &exe[..exe.len() - 20];
    let mut miscounted = exe.clone();
    miscounted[0x1000 + 14..0x1000 + 16].copy_from_slice(&9u16.to_le_bytes());
    for (mode, opts) in modes() {
        for (what, file) in [("cut", cut), ("miscounted", &miscounted[..])] {
            match analyze(&db, file, &opts).verdict {
                Verdict::Unscannable { .. } => {}
                other => panic!("{mode} {what}: expected UNSCANNABLE, got {other:?}"),
            }
        }
    }
}
