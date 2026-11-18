//! End-to-end tests for the `exav-unpack` binary, whose command line is a
//! subset of `unzip`'s.
//!
//! This crate is a thin shell over the library, but the thin part is where the
//! only actually dangerous code lives: it is the one place in the project that
//! **writes attacker-named files to disk**. A member called `../../../etc/cron.d/x`
//! is ordinary in a hostile archive, and every extractor CVE of the last decade
//! is some version of honouring it. So the containment property gets tested
//! directly, not inferred from the shape of the code.
//!
//! What the command line prints and returns is checked against `unzip` itself
//! by a differential script; these tests hold the behaviour exav-unpack owns.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_exav-unpack");

/// A scratch directory unique to one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("exav-unpack-cli-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        Scratch(d)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }

    fn subdir(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Minimal stored-member ZIP (local headers only: exav reads those).
fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    zip_with(0, members)
}

/// A ZIP whose members claim compression `method`, their bytes as given.
fn zip_with(method: u16, members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (name, body) in members {
        v.extend_from_slice(b"PK\x03\x04");
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&method.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(body);
    }
    v
}

/// One tar entry: `(name, type, mode, mtime, link, body)`.
#[cfg(unix)]
type TarEntry<'a> = (&'a str, u8, u32, u64, &'a str, &'a [u8]);

/// A ustar archive of `entries`.
#[cfg(unix)]
fn tar_of(entries: &[TarEntry]) -> Vec<u8> {
    let mut v = Vec::new();
    for (name, kind, mode, mtime, link, body) in entries {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let octal = |h: &mut [u8; 512], at: usize, width: usize, n: u64| {
            let s = format!("{n:0w$o}\0", w = width - 1);
            h[at..at + width].copy_from_slice(s.as_bytes());
        };
        octal(&mut h, 100, 8, u64::from(*mode));
        octal(&mut h, 108, 8, 0);
        octal(&mut h, 116, 8, 0);
        octal(&mut h, 124, 12, body.len() as u64);
        octal(&mut h, 136, 12, *mtime);
        h[156] = *kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        v.extend_from_slice(&h);
        v.extend_from_slice(body);
        v.resize(v.len().div_ceil(512) * 512, 0);
    }
    v.resize(v.len() + 1024, 0);
    v
}

fn run(args: &[&str]) -> Output {
    run_in(None, args, b"")
}

/// The variables the limits fall back to. A run does not see the ones set in
/// the environment of whoever runs the tests.
const LIMIT_VARS: [&str; 9] = [
    "EXAV_MAX_EXTRACTED_BYTES",
    "EXAV_MAX_OBJECT_BYTES",
    "EXAV_MAX_MEMBERS",
    "EXAV_MAX_COMPRESSION_RATIO",
    "EXAV_MAX_UNPACK_DEPTH",
    "EXAV_OBJECT_CACHE_BYTES",
    "EXAV_OBJECT_CACHE_BLOCK_BYTES",
    "EXAV_SPILL_DIR",
    "EXAV_MAX_TOTAL_SPILL_BYTES",
];

/// Run with `vars` set in its environment.
fn run_env(vars: &[(&str, &str)], args: &[&str]) -> Output {
    run_full(None, vars, args, b"")
}

/// Run in `dir` (or here), with `stdin` as its input.
fn run_in(dir: Option<&Path>, args: &[&str], stdin: &[u8]) -> Output {
    run_full(dir, &[], args, stdin)
}

fn run_full(dir: Option<&Path>, vars: &[(&str, &str)], args: &[&str], stdin: &[u8]) -> Output {
    let mut c = Command::new(BIN);
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for var in LIMIT_VARS {
        c.env_remove(var);
    }
    c.envs(vars.iter().copied());
    if let Some(d) = dir {
        c.current_dir(d);
    }
    let mut child = c.spawn().expect("spawn exav-unpack");
    use std::io::Write;
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exited normally, not by signal")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Every regular file under `root`, as paths relative to it.
fn tree(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p.strip_prefix(root).unwrap_or(&p).to_path_buf());
            }
        }
    }
    out.sort();
    out
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn list_names_every_member_with_its_size() {
    let sc = Scratch::new("list");
    let f = sc.write(
        "a.zip",
        &zip_of(&[("one.txt", b"hello"), ("two.txt", b"worldly")]),
    );
    let o = run(&["-l", s(&f)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("Length      Date    Time    Name"), "{out:?}");
    assert!(
        out.contains("        5  ") && out.contains("   one.txt"),
        "{out:?}"
    );
    assert!(
        out.contains("       12                     2 files"),
        "{out:?}"
    );
    let o = run(&["-Z1", s(&f)]);
    assert_eq!(stdout(&o), "one.txt\ntwo.txt\n");
}

#[test]
fn list_writes_nothing_to_disk() {
    // `-l` is the "just tell me" mode; if it wrote files it would be a trap.
    let sc = Scratch::new("listclean");
    let f = sc.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    let before = tree(sc.path());
    let o = run(&["-l", s(&f)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(tree(sc.path()), before, "list must not create files");
}

#[test]
fn extract_writes_members_into_the_output_directory() {
    let sc = Scratch::new("extract");
    let f = sc.write(
        "a.zip",
        &zip_of(&[("one.txt", b"hello"), ("dir/two.txt", b"world")]),
    );
    let out_dir = sc.subdir("out");
    let o = run(&[s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("one.txt")).unwrap(), b"hello");
    assert_eq!(
        std::fs::read(out_dir.join("dir/two.txt")).unwrap(),
        b"world",
        "a nested member name creates the directory under the output root"
    );
    assert!(stdout(&o).contains(" extracting: "), "{}", stdout(&o));
}

#[test]
fn a_traversing_member_name_is_written_inside_the_output_directory() {
    // The zip-slip case. `../../../` components are dropped, not honoured, so
    // the file lands under the output root by its basename.
    let sc = Scratch::new("slip");
    let f = sc.write(
        "evil.zip",
        &zip_of(&[("../../../escaped.txt", b"pwned"), ("ok.txt", b"fine")]),
    );
    let out_dir = sc.subdir("out");
    let o = run(&[s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(
        std::fs::read(out_dir.join("escaped.txt")).unwrap(),
        b"pwned",
        "the member is still extracted, just contained"
    );
    assert!(
        !sc.path().join("escaped.txt").exists(),
        "escaped one level up"
    );
    assert!(
        !std::env::temp_dir().join("escaped.txt").exists(),
        "escaped two levels up"
    );
    for p in tree(out_dir.as_path()) {
        assert!(
            !p.to_string_lossy().contains(".."),
            "a '..' survived into the written path: {p:?}"
        );
    }
}

#[test]
fn an_absolute_member_name_is_rerooted_under_the_output_directory() {
    let sc = Scratch::new("absolute");
    let f = sc.write("evil.zip", &zip_of(&[("/etc/cron.d/backdoor", b"x")]));
    let out_dir = sc.subdir("out");
    let o = run(&[s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(
        out_dir.join("etc/cron.d/backdoor").exists(),
        "wrote: {:?}",
        tree(out_dir.as_path())
    );
    assert!(
        !Path::new("/etc/cron.d/backdoor").exists(),
        "an absolute member name must never reach the real path"
    );
}

/// A member the scan budget cuts is said to be cut in words, in every mode
/// that reads members, not by the reader's internal token.
#[test]
fn a_member_cut_by_the_scan_budget_is_said_so_in_words() {
    use std::io::Write;
    let sc = Scratch::new("budget-cut");
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    z.start_file("big.txt", deflated).unwrap();
    z.write_all(&vec![b'a'; 200 << 10]).unwrap();
    let f = sc.write("big.zip", &z.finish().unwrap().into_inner());
    let out_dir = sc.subdir("out");
    for mode in [vec!["-t"], vec!["-p"], vec!["-d", s(&out_dir)]] {
        let mut args = vec!["--max-extracted-bytes", "64K"];
        args.extend(mode.iter().copied());
        args.push(s(&f));
        let o = run(&args);
        // Test mode reports on stdout.
        let said = format!("{}{}", String::from_utf8_lossy(&o.stdout), stderr(&o));
        let said = said.trim_start_matches('a');
        assert!(!said.contains("exav:"), "{mode:?}: {said}");
        assert!(said.contains("member over its budget"), "{mode:?}: {said}");
        assert_ne!(code(&o), 0, "{mode:?}");
    }
}

/// A member the end of the archive cuts is an error, as tar and unzip report
/// one: the test says so, and what is there of it is extracted.
#[test]
#[cfg(unix)]
fn a_member_cut_by_the_end_of_the_archive_is_an_error() {
    let sc = Scratch::new("cut-member");
    let body = vec![b'x'; 2000];
    let mut tar = tar_of(&[("f.bin", b'0', 0o644, 0, "", &body)]);
    tar.truncate(512 + 700);
    let f = sc.write("cut.tar", &tar);
    let o = run(&["-t", s(&f)]);
    let said = format!("{}{}", stdout(&o), stderr(&o));
    assert!(
        said.contains("past the end of its 1212-byte container: only 700 bytes"),
        "{said}"
    );
    assert!(!said.contains("No errors detected"), "{said}");
    assert_ne!(code(&o), 0);
    let out_dir = sc.subdir("out");
    let o = run(&["-d", s(&out_dir), s(&f)]);
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("f.bin")).unwrap().len(), 700);
}

/// A reason quotes a member's name as a listing shows it, and a test that
/// met one does not end by saying that no error was detected.
#[test]
fn a_reason_quotes_a_hostile_name_as_shown_and_fails_the_test() {
    let sc = Scratch::new("hostile-reason");
    let name = format!("e\u{1b}[31m\u{202e}{}", "n".repeat(300));
    let body = [b'x'; 4096];
    // A method no ZIP specification defines is read as stored, held whole.
    let mut z = zip_with(77, &[(&name, &body)]);
    // A central directory, so that the archive is read where it lies.
    let at = z.len() as u32;
    let mut cd = b"PK\x01\x02".to_vec();
    cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&[0; 16]);
    cd.extend_from_slice(name.as_bytes());
    z.extend_from_slice(&cd);
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    z.extend_from_slice(&at.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    let f = sc.write("m.zip", &z);
    let o = run(&["--max-object-bytes", "1K", "-t", s(&f)]);
    let err = stderr(&o);
    assert!(err.contains("is larger than --max-object-bytes"), "{err}");
    assert!(!err.contains(['\u{1b}', '\u{202e}']), "{err:?}");
    let shown = format!("'e_[31m_{}'", "n".repeat(193));
    assert!(err.contains(&shown), "{err}");
    let out = stdout(&o);
    assert!(out.contains("At least one error was detected"), "{out}");
    assert_eq!(code(&o), 2);
}

#[test]
fn a_member_name_with_nothing_usable_left_is_skipped_and_reported() {
    // `../..` reduces to nothing. Silently dropping it would be a member the
    // user never learns about; the CLI names it and warns.
    let sc = Scratch::new("empty-name");
    let f = sc.write("evil.zip", &zip_of(&[("../..", b"x")]));
    let out_dir = sc.subdir("out");
    let o = run(&[s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 1, "a skipped member must not report success");
    assert!(
        stderr(&o).contains("unsafe member name"),
        "the skip must be explained: {}",
        stderr(&o)
    );
    assert_eq!(tree(out_dir.as_path()), Vec::<PathBuf>::new());
}

#[test]
fn extract_defaults_to_the_current_directory() {
    let sc = Scratch::new("cwd");
    let f = sc.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    let work = sc.subdir("work");
    let o = run_in(Some(&work), &[s(&f)], b"");
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(std::fs::read(work.join("one.txt")).unwrap(), b"hello");
}

#[test]
fn no_arguments_and_help_print_usage_and_succeed() {
    for args in [&[][..], &["-h"], &["--help"]] {
        let o = run(args);
        assert_eq!(code(&o), 0, "{args:?}");
        assert!(stdout(&o).contains("usage:"), "{args:?}: {}", stdout(&o));
    }
    for args in [&["-v"][..], &["--version"]] {
        let o = run(args);
        assert_eq!(code(&o), 0);
        assert_eq!(
            stdout(&o).trim(),
            format!("exav-unpack {}", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn an_unzip_option_outside_the_subset_is_refused() {
    let sc = Scratch::new("refused");
    let f = sc.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    for args in [
        &["-X", s(&f)][..],
        &["-a", s(&f)],
        &["-fo", s(&f)],
        &["-v", s(&f)],
        &["-Z", s(&f)],
        &["-k", s(&f)],
        &["-lt", s(&f)],
        &["-o"],
        &["--frobnicate", s(&f)],
        &["--max-size", "lots", s(&f)],
    ] {
        let o = run(args);
        assert_eq!(code(&o), 10, "{args:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("usage:"), "{args:?}");
    }
    let o = run(&["-X", s(&f)]);
    assert!(
        stderr(&o).contains("-X (owners and ACLs) is an unzip option"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn an_existing_file_is_kept_unless_overwrite_is_given() {
    let sc = Scratch::new("overwrite");
    let f = sc.write("a.zip", &zip_of(&[("one.txt", b"new")]));
    let out_dir = sc.subdir("out");
    std::fs::write(out_dir.join("one.txt"), b"mine").unwrap();
    // No answer to the prompt: "[N]one", a warning.
    let o = run(&[s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 1, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("replace "), "{}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("one.txt")).unwrap(), b"mine");
    let o = run(&["-n", s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("one.txt")).unwrap(), b"mine");
    let o = run_in(None, &[s(&f), "-d", s(&out_dir)], b"y\n");
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("one.txt")).unwrap(), b"new");
    std::fs::write(out_dir.join("one.txt"), b"mine").unwrap();
    let o = run(&["-o", s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("one.txt")).unwrap(), b"new");
}

/// A link already in the output directory, to a file or to a directory, never
/// takes a member outside it, even with `-o`; nor does a link in the archive.
#[cfg(unix)]
#[test]
fn nothing_is_written_through_a_link() {
    let sc = Scratch::new("links");
    let outside = sc.subdir("outside");
    std::fs::write(outside.join("victim.txt"), b"keep").unwrap();
    let out_dir = sc.subdir("out");
    std::os::unix::fs::symlink(outside.join("victim.txt"), out_dir.join("file.txt")).unwrap();
    std::os::unix::fs::symlink(&outside, out_dir.join("dir")).unwrap();
    let f = sc.write(
        "a.zip",
        &zip_of(&[("file.txt", b"evil"), ("dir/planted.txt", b"evil")]),
    );
    for extra in [&[][..], &["-o"][..]] {
        let o = run(&[extra, &[s(&f), "-d", s(&out_dir)]].concat());
        assert_ne!(code(&o), 0, "{extra:?}: {}", stderr(&o));
        assert_eq!(
            std::fs::read(outside.join("victim.txt")).unwrap(),
            b"keep",
            "{extra:?}"
        );
        assert!(!outside.join("planted.txt").exists(), "{extra:?}");
    }
    // A link member pointing out, then a member written "through" it.
    let t = sc.write(
        "links.tar",
        &tar_of(&[
            ("up", b'2', 0o777, 0, "../outside", b""),
            ("up/planted.txt", b'0', 0o644, 0, "", b"evil"),
        ]),
    );
    let fresh = sc.subdir("fresh");
    let o = run(&[s(&t), "-d", s(&fresh)]);
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("outside the extraction directory"),
        "{}",
        stderr(&o)
    );
    assert!(!outside.join("planted.txt").exists());
    assert!(!fresh.join("up").is_symlink());
}

/// Each link of a chain passes a check of its own words: `a -> .` stays, and
/// `b -> a/..` has one `..` against two components. Followed through `a`, `b` is
/// the directory above the root, and `c -> b/..` the one above that.
#[cfg(unix)]
#[test]
fn a_chain_of_links_does_not_walk_out_of_the_extraction_directory() {
    let sc = Scratch::new("link-chain");
    let t = sc.write(
        "chain.tar",
        &tar_of(&[
            ("a", b'2', 0o777, 0, ".", b""),
            ("b", b'2', 0o777, 0, "a/..", b""),
            ("c", b'2', 0o777, 0, "b/..", b""),
            ("d", b'2', 0o777, 0, "c/etc", b""),
            ("fine", b'2', 0o777, 0, "a/sub", b""),
        ]),
    );
    let fresh = sc.subdir("outer/root");
    let o = run(&[s(&t), "-d", s(&fresh)]);
    assert!(
        stderr(&o).contains("outside the extraction directory"),
        "{}",
        stderr(&o)
    );
    let root = std::fs::canonicalize(&fresh).unwrap();
    for name in ["a", "b", "c", "d", "fine"] {
        let l = fresh.join(name);
        if l.is_symlink() {
            let resolved = std::fs::canonicalize(&l).unwrap_or_else(|_| {
                // Dangling: judge it by where its parent's target would be.
                root.join(std::fs::read_link(&l).unwrap())
            });
            assert!(
                resolved.starts_with(&root) || name == "fine",
                "{name} leaves the root: {}",
                resolved.display()
            );
        }
    }
    assert!(
        !fresh.join("b").is_symlink(),
        "b -> a/.. is the directory above the root"
    );
    assert!(
        fresh.join("a").is_symlink(),
        "a link inside the root is still made"
    );
}

/// tar keeps what unzip restores: the time, the permission bits, the links.
#[cfg(unix)]
#[test]
fn times_modes_and_links_are_restored() {
    use std::os::unix::fs::PermissionsExt;
    let sc = Scratch::new("meta");
    let t = sc.write(
        "a.tar",
        &tar_of(&[
            ("bin/", b'5', 0o750, 1_600_000_000, "", b""),
            ("bin/run.sh", b'0', 0o755, 1_500_000_000, "", b"#!/bin/sh\n"),
            ("bin/sbit", b'0', 0o4755, 1_500_000_000, "", b"x"),
            ("bin/run", b'2', 0o777, 0, "run.sh", b""),
        ]),
    );
    let out = sc.subdir("out");
    let o = run(&[s(&t), "-d", s(&out)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let m = std::fs::metadata(out.join("bin/run.sh")).unwrap();
    assert_eq!(m.permissions().mode() & 0o7777, 0o755);
    let secs = |m: &std::fs::Metadata| {
        m.modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    assert_eq!(secs(&m), 1_500_000_000);
    let setuid = std::fs::metadata(out.join("bin/sbit")).unwrap();
    assert_eq!(
        setuid.permissions().mode() & 0o7777,
        0o755,
        "setuid is dropped, as unzip drops it without -K"
    );
    assert_eq!(
        std::fs::read_link(out.join("bin/run")).unwrap(),
        PathBuf::from("run.sh")
    );
    let d = std::fs::metadata(out.join("bin")).unwrap();
    assert_eq!(
        (d.permissions().mode() & 0o777, secs(&d)),
        (0o750, 1_600_000_000)
    );
    // -DD: no times at all; -D: none on directories.
    let out2 = sc.subdir("out2");
    run(&["-DD", s(&t), "-d", s(&out2)]);
    assert_ne!(
        secs(&std::fs::metadata(out2.join("bin/run.sh")).unwrap()),
        1_500_000_000
    );
}

#[test]
fn test_decodes_everything_and_writes_nothing() {
    let sc = Scratch::new("test");
    let good = sc.write("good.zip", &zip_of(&[("one.txt", b"hello")]));
    // Deflate-compressed by its header, but not deflate: it fails part way.
    let bad = sc.write("bad.zip", &zip_with(8, &[("broken.bin", &[0xff; 64])]));
    let before = tree(sc.path());
    let o = run(&["-t", s(&good)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(
        stdout(&o).contains("    testing: one.txt                  OK"),
        "{}",
        stdout(&o)
    );
    assert!(
        stdout(&o).contains("No errors detected in compressed data of"),
        "{}",
        stdout(&o)
    );
    let o = run(&["-t", s(&bad)]);
    assert_eq!(code(&o), 2, "stdout: {} stderr: {}", stdout(&o), stderr(&o));
    assert!(
        stdout(&o).contains("At least one error was detected in"),
        "{}",
        stdout(&o)
    );
    assert_eq!(tree(sc.path()), before, "test must not create files");
}

/// A member that decodes past the object limit to more than the ratio is left
/// out, and the members after it come out; `--max-compression-ratio off`
/// brings it out too.
#[test]
fn a_member_over_the_ratio_is_left_out_and_the_others_come_out() {
    use std::io::Write;
    let sc = Scratch::new("ratio");
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    z.start_file("zeros.bin", deflated).unwrap();
    z.write_all(&vec![0u8; 1 << 20]).unwrap();
    z.start_file("after.txt", deflated).unwrap();
    z.write_all(b"after the bomb").unwrap();
    let archive = sc.write("r.zip", &z.finish().unwrap().into_inner());
    let held = ["-p", "--max-object-bytes", "64K"];

    let mut args = held.to_vec();
    args.extend(["--max-compression-ratio", "100", s(&archive)]);
    let o = run(&args);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("compression ratio"), "{}", stderr(&o));
    assert!(
        stdout(&o).contains("after the bomb"),
        "{}",
        stdout(&o).len()
    );

    let mut args = held.to_vec();
    args.extend(["--max-compression-ratio", "off", s(&archive)]);
    let o = run(&args);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(o.stdout.len() > 1 << 20, "{}", o.stdout.len());
    assert!(stdout(&o).contains("after the bomb"));
}

/// A stream that fails to decode says why, as the reader said it: not that it
/// has "no content".
#[test]
fn a_stream_that_fails_to_decode_says_why() {
    let sc = Scratch::new("streamerr");
    // A gzip header, then bytes that are no deflate stream.
    let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    gz.extend_from_slice(&[0xff; 64]);
    let bare = sc.write("bad.gz", &gz);
    let zipped = sc.write("bad.zip", &zip_of(&[("inner.gz", &gz)]));
    for (args, what) in [
        (vec!["-r", "-t", s(&bare)], "a gzip"),
        (vec!["-r", "-t", s(&zipped)], "a gzip in a ZIP"),
    ] {
        let o = run(&args);
        assert_eq!(code(&o), 2, "{what}: {} {}", stdout(&o), stderr(&o));
        assert!(stdout(&o).contains("deflate"), "{what}: {}", stdout(&o));
        assert!(!stdout(&o).contains("no content"), "{what}: {}", stdout(&o));
    }
}

/// A 7z member that does not match the CRC in the header fails the test, as a
/// ZIP member does.
#[test]
fn a_7z_member_that_fails_its_crc_fails_the_test() {
    let mut arc = exav_unpack::read_fixture(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/7z/copy.7z"
    ))
    .unwrap();
    let sc = Scratch::new("sevenzcrc");
    let good = sc.write("good.7z", &arc);
    let o = run(&["-t", s(&good)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // A byte of the stored member (the packed data starts at 32).
    arc[32 + 3] ^= 0x20;
    let bad = sc.write("bad.7z", &arc);
    let o = run(&["-t", s(&bad)]);
    assert_eq!(code(&o), 2, "stdout: {} stderr: {}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("CRC-32 mismatch"), "{}", stdout(&o));
    assert!(
        stdout(&o).contains("At least one error was detected in"),
        "{}",
        stdout(&o)
    );
}

/// A ZIP of stored members, each ZipCrypto-encrypted with its password if it
/// has one.
fn zip_locked(members: &[(&str, &[u8], Option<&str>)]) -> Vec<u8> {
    use std::io::Write;
    use zip::unstable::write::FileOptionsExt;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, body, pw) in members {
        let mut opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        if let Some(pw) = pw {
            opts = opts.with_deprecated_encryption(pw.as_bytes()).unwrap();
        }
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn a_wrong_password_fails_the_run_only_when_nothing_else_came_out() {
    let sc = Scratch::new("badpw");
    let locked = sc.write(
        "locked.zip",
        &zip_locked(&[("a.txt", b"hello", Some("secret"))]),
    );
    let mixed = sc.write(
        "mixed.zip",
        &zip_locked(&[
            ("a.txt", b"hello", Some("secret")),
            ("b.txt", b"world", None),
        ]),
    );
    let out = sc.subdir("out");
    let o = run(&["-P", "wrong", s(&locked), "-d", s(&out)]);
    assert_eq!(code(&o), 82, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("   skipping: a.txt                   incorrect password"),
        "{}",
        stderr(&o)
    );
    let o = run(&["-P", "wrong", s(&mixed), "-d", s(&out)]);
    assert_eq!(code(&o), 1, "stderr: {}", stderr(&o));
    assert_eq!(std::fs::read(out.join("b.txt")).unwrap(), b"world");
    let o = run(&["-t", "-P", "wrong", s(&mixed)]);
    assert_eq!(code(&o), 1, "stdout: {}", stdout(&o));
    let want = "No errors detected in {} for the 1 file tested.\n1 file skipped because of incorrect password.\n";
    assert!(
        stdout(&o).ends_with(&want.replace("{}", s(&mixed))),
        "{}",
        stdout(&o)
    );
    let o = run(&["-t", "-P", "wrong", s(&locked)]);
    assert_eq!(code(&o), 82, "stdout: {}", stdout(&o));
    assert!(
        stdout(&o).contains("Caution:  zero files tested in"),
        "{}",
        stdout(&o)
    );
    let o = run(&["-t", "-P", "secret", s(&mixed)]);
    assert_eq!(code(&o), 0, "stdout: {}", stdout(&o));
    assert!(
        stdout(&o).contains("No errors detected in compressed data of"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn members_are_chosen_by_pattern_and_excluded() {
    let sc = Scratch::new("patterns");
    let f = sc.write(
        "a.zip",
        &zip_of(&[("a.txt", b"1"), ("b.log", b"2"), ("d/c.txt", b"3")]),
    );
    let out = sc.path().join("out");
    let o = run(&[s(&f), "*.txt", "-x", "d/*", "-d", s(&out)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(tree(&out), [PathBuf::from("a.txt")]);
    let o = run(&[s(&f), "nothere", "-d", s(&out)]);
    assert_eq!(code(&o), 11, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("caution: filename not matched:  nothere"),
        "{}",
        stderr(&o)
    );
    let o = run(&["-C", s(&f), "A.TXT", "-d", s(&sc.path().join("out2"))]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let o = run(&["-j", s(&f), "-d", s(&sc.path().join("out3"))]);
    assert_eq!(code(&o), 0);
    assert_eq!(
        tree(&sc.path().join("out3")),
        ["a.txt", "b.log", "c.txt"].map(PathBuf::from)
    );
    let o = run(&["-p", s(&f), "b.log", "a.txt"]);
    assert_eq!(stdout(&o), "12", "in archive order");
}

#[test]
fn a_wildcard_names_several_archives() {
    let sc = Scratch::new("several");
    sc.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    sc.write("b.zip", &zip_of(&[("two.txt", b"world")]));
    let out = sc.path().join("out");
    let o = run_in(Some(sc.path()), &["*.zip", "-d", s(&out)], b"");
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(
        tree(&out),
        [PathBuf::from("one.txt"), PathBuf::from("two.txt")]
    );
    assert!(
        stderr(&o).contains("2 archives were successfully processed."),
        "{}",
        stderr(&o)
    );
    // A second name is a member, as unzip has it.
    let o = run_in(Some(sc.path()), &["a.zip", "b.zip", "-d", "out4"], b"");
    assert_eq!(code(&o), 11, "stderr: {}", stderr(&o));
}

#[test]
fn a_split_archive_is_read_from_any_of_its_parts() {
    let sc = Scratch::new("split");
    let whole = zip_of(&[("one.txt", b"hello"), ("two.txt", b"world")]);
    let (a, b) = whole.split_at(whole.len() / 2);
    sc.write("set.zip.001", a);
    let second = sc.write("set.zip.002", b);
    let o = run(&["-Z1", s(&second)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(stdout(&o), "one.txt\ntwo.txt\n");
    // Parts elsewhere, or not named as a set, are given with --volume.
    let elsewhere = sc.subdir("elsewhere");
    let first = elsewhere.join("first.bin");
    std::fs::write(&first, a).unwrap();
    let rest = sc.write("rest.bin", b);
    let o = run(&["-Z1", s(&first), "--volume", s(&rest)]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(stdout(&o), "one.txt\ntwo.txt\n");
}

/// A ZIP written by `zip -s` reads from any of its parts, as the files it was
/// made of. Skipped where there is no `zip`.
#[test]
fn a_spanned_zip_is_read_from_any_part() {
    let sc = Scratch::new("zips");
    // Incompressible, so the set has three parts.
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let big: Vec<u8> = (0..300_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    sc.write("big.bin", &big);
    sc.write("small.txt", b"hello\n");
    let made = Command::new("zip")
        .args(["-q", "-s", "100k", "set.zip", "big.bin", "small.txt"])
        .current_dir(sc.path())
        .status();
    if !made.is_ok_and(|s| s.success()) {
        eprintln!("skipped: no zip");
        return;
    }
    assert!(sc.path().join("set.z02").is_file(), "zip made a set");
    for part in ["set.zip", "set.z01", "set.z02"] {
        let out = sc.path().join(format!("out-{part}"));
        let o = run(&["-q", s(&sc.path().join(part)), "-d", s(&out)]);
        assert_eq!(code(&o), 0, "{part}: {}", stderr(&o));
        assert_eq!(std::fs::read(out.join("big.bin")).unwrap(), big, "{part}");
        assert_eq!(
            std::fs::read(out.join("small.txt")).unwrap(),
            b"hello\n",
            "{part}"
        );
    }
    std::fs::remove_file(sc.path().join("set.z02")).unwrap();
    let o = run(&["-l", s(&sc.path().join("set.zip"))]);
    assert_ne!(code(&o), 0, "a part missing: {}", stdout(&o));
}

/// Sets written by official RAR (see `tests/suites/rar_solid.rs`), new-style
/// and old-style names, extract whole from whichever part is named.
#[test]
fn a_real_rar_volume_set_extracts_from_any_part() {
    use sha2::{Digest, Sha256};
    let hex = |b: &[u8]| {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    };
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar_volumes");
    for parts in [
        ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"],
        ["set4.rar", "set4.r00", "set4.r01"],
    ] {
        let sc = Scratch::new("realrar");
        for p in parts {
            sc.write(p, &std::fs::read(format!("{fixtures}/{p}")).unwrap());
        }
        for p in parts {
            let out = sc.subdir(&format!("out-{p}"));
            let o = run(&["-q", s(&sc.path().join(p)), "-d", s(&out)]);
            assert_eq!(code(&o), 0, "{p}: {}", stderr(&o));
            assert_eq!(
                hex(&std::fs::read(out.join("noise.bin")).unwrap()),
                "6987decf3255b53b0f8cf0da45aafacce4294578716058e11cd018a18e57035e",
                "{p}"
            );
            assert_eq!(
                hex(&std::fs::read(out.join("text.txt")).unwrap()),
                "306e49d40e25318b97ad7628011238f0ed6af09880396518cd5a8e1cbe7efe19",
                "{p}"
            );
        }
    }
}

/// A RAR set is read across its volumes, not joined in memory: a set of
/// 300 KB under a memory limit of 100 KB extracts all the same, where the set
/// used to be refused. Its member is stored, so that the dictionary a coded
/// member needs (256 KiB at the least) is not what the limit is met by.
#[test]
fn a_rar_volume_set_past_the_memory_limit_extracts() {
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    // Marker, an archive header, and a stored member whose size is in the
    // first field of its header.
    let mut arc = b"Rar!\x1a\x07\x00".to_vec();
    arc.extend_from_slice(&[0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]);
    let mut fields = (data.len() as u32).to_le_bytes().to_vec();
    fields.extend_from_slice(&(data.len() as u32).to_le_bytes());
    fields.push(0);
    fields.extend_from_slice(&[0; 8]);
    fields.extend_from_slice(&[20, 0x30]);
    fields.extend_from_slice(&7u16.to_le_bytes());
    fields.extend_from_slice(&[0; 4]);
    fields.extend_from_slice(b"big.bin");
    arc.extend_from_slice(&[0, 0, 0x74, 0, 0x80]);
    arc.extend_from_slice(&((7 + fields.len()) as u16).to_le_bytes());
    arc.extend(fields);
    arc.extend_from_slice(&data);

    let vols = rar4_volumes(&arc);
    assert!(vols.len() == 2 && vols.iter().map(Vec::len).sum::<usize>() > 300_000);
    let sc = Scratch::new("rarlimit");
    for (k, v) in vols.iter().enumerate() {
        sc.write(&format!("set.part{}.rar", k + 1), v);
    }
    let out = sc.subdir("out");
    let first = sc.path().join("set.part1.rar");
    let o = run(&["-q", "--max-memory", "100K", s(&first), "-d", s(&out)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(std::fs::read(out.join("big.bin")).unwrap() == data);
    // The same through caches of the least size, and of a share of a few
    // bytes a part with blocks far past it: the bytes are the same.
    let small: [&[&str]; 2] = [
        &[
            "--object-cache-bytes",
            "off",
            "--object-cache-block-bytes",
            "512",
        ],
        &["--object-cache-bytes=2", "--object-cache-block-bytes=1M"],
    ];
    for (k, flags) in small.iter().enumerate() {
        let out = sc.subdir(&format!("out{k}"));
        let mut args = vec!["-q", "--max-memory", "100K"];
        args.extend(*flags);
        args.extend([s(&first), "-d", s(&out)]);
        let o = run(&args);
        assert_eq!(code(&o), 0, "{flags:?}: {}", stderr(&o));
        assert!(
            std::fs::read(out.join("big.bin")).unwrap() == data,
            "{flags:?}"
        );
    }
}

/// The sizes of the cache over the archive are options of the command line, as
/// the scanner's are, and `off` is one of their values.
#[test]
fn the_object_cache_sizes_are_options_and_do_not_change_what_comes_out() {
    let sc = Scratch::new("cachesizes");
    let f = sc.write(
        "a.zip",
        &zip_of(&[("one.txt", b"hello"), ("two.txt", b"world")]),
    );
    let want = stdout(&run(&["-p", s(&f)]));
    assert!(want.contains("hello") && want.contains("world"), "{want}");
    for flags in [
        &["--object-cache-bytes", "off"][..],
        &["--object-cache-block-bytes", "1"],
        &["--object-cache-bytes=4K", "--object-cache-block-bytes=OFF"],
        &[
            "--object-cache-bytes",
            "64M",
            "--object-cache-block-bytes",
            "16M",
        ],
    ] {
        let mut args = vec!["-p"];
        args.extend(flags);
        args.push(s(&f));
        let o = run(&args);
        assert_eq!(code(&o), 0, "{flags:?}: {}", stderr(&o));
        assert_eq!(stdout(&o), want, "{flags:?}");
    }
    // A size that is none, and no size, are refused as the other options are.
    for bad in [
        vec!["--object-cache-bytes", "lots", s(&f)],
        vec!["--object-cache-block-bytes", "4MB", s(&f)],
        vec![s(&f), "--object-cache-bytes"],
    ] {
        let o = run(&bad);
        assert_eq!(code(&o), 10, "{bad:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("usage:"), "{bad:?}");
    }
    // The limits take `off` as the scanner's do, and the depth does not.
    let o = run(&["-p", "--max-memory", "off", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), want);
    assert_eq!(code(&run(&["--max-unpack-depth", "off", s(&f)])), 10);
    // The help names them.
    let help = stdout(&run(&["--help"]));
    for word in ["--object-cache-bytes", "--object-cache-block-bytes", "off"] {
        assert!(help.contains(word), "{word}: {help}");
    }
}

/// A RAR set reads from its first part, its members split across volumes
/// joined; parts named otherwise are given with `--volume`.
#[test]
fn a_rar_volume_set_is_read_whole() {
    let arc = exav_unpack::read_fixture(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rar_solid/solid_rar4.rar"
    ))
    .unwrap();
    let vols = rar4_volumes(&arc);
    assert!(vols.len() > 2, "the fixture split into a set");
    let sc = Scratch::new("rarset");
    for (k, v) in vols.iter().enumerate() {
        sc.write(&format!("set.part{}.rar", k + 1), v);
    }
    let whole = sc.write("whole.rar", &arc);
    let want = stdout(&run(&["-p", s(&whole)]));
    assert!(!want.is_empty());
    let o = run(&["-p", s(&sc.path().join("set.part1.rar"))]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), want);
    // Renamed parts, given one by one.
    let mut named = Vec::new();
    for (k, v) in vols.iter().enumerate() {
        named.push(sc.write(&format!("piece-{k}"), v));
    }
    let mut args = vec!["-p".to_string(), s(&named[0]).to_string()];
    for p in &named[1..] {
        args.extend(["--volume".to_string(), s(p).to_string()]);
    }
    let o = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), want);
}

/// `arc` (RAR4) with each member cut in two, a volume per cut, as RARLAB's
/// technote describes a set.
fn rar4_volumes(arc: &[u8]) -> Vec<Vec<u8>> {
    const MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
    let u16_at = |p: usize| u16::from_le_bytes([arc[p], arc[p + 1]]) as usize;
    let u32_at = |p: usize| u32::from_le_bytes(arc[p..p + 4].try_into().unwrap()) as usize;
    let crc = |d: &[u8]| {
        let mut c = !0u32;
        for &b in d {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = (c >> 1) ^ (0xEDB8_8320 & (c & 1).wrapping_neg());
            }
        }
        !c
    };
    let (mut vols, mut main) = (vec![MAGIC.to_vec()], Vec::new());
    let mut pos = MAGIC.len();
    while pos + 7 <= arc.len() {
        let (kind, flags, size) = (arc[pos + 2], u16_at(pos + 3), u16_at(pos + 5));
        let add = if flags & 0x8000 != 0 {
            u32_at(pos + 7)
        } else {
            0
        };
        let end = pos + size + add;
        match kind {
            0x73 => {
                main = arc[pos..end].to_vec();
                vols[0].extend_from_slice(&main);
            }
            0x74 => {
                let data = &arc[pos + size..end];
                let halves = [&data[..data.len() / 2], &data[data.len() / 2..]];
                for (j, half) in halves.iter().enumerate() {
                    let mut h = arc[pos..pos + size].to_vec();
                    let f = (flags | if j == 0 { 0x02 } else { 0x01 }) as u16;
                    h[3..5].copy_from_slice(&f.to_le_bytes());
                    h[7..11].copy_from_slice(&(half.len() as u32).to_le_bytes());
                    if j == 0 {
                        h[16..20].copy_from_slice(&crc(half).to_le_bytes());
                        vols.last_mut().unwrap().extend(h);
                    } else {
                        let mut v = MAGIC.to_vec();
                        v.extend_from_slice(&main);
                        v.extend(h);
                        vols.push(v);
                    }
                    vols.last_mut().unwrap().extend_from_slice(half);
                }
            }
            _ => {}
        }
        if end <= pos {
            break;
        }
        pos = end;
    }
    vols
}

#[test]
fn a_missing_archive_is_reported_with_unzips_status() {
    let o = run(&["-l", "/definitely/not/here.zip"]);
    assert_eq!(code(&o), 9, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("cannot find or open"), "{}", stderr(&o));
}

#[test]
fn an_archive_name_without_its_extension_is_found() {
    let sc = Scratch::new("ext");
    sc.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    let o = run_in(Some(sc.path()), &["-Z1", "a"], b"");
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(stdout(&o), "one.txt\n");
}

#[test]
fn an_unrecognised_format_fails_rather_than_reporting_an_empty_archive() {
    // An empty listing of a file that is not an archive would read as "opened
    // it, found nothing": the one answer that must never be guessed at.
    let sc = Scratch::new("unknown");
    let f = sc.write("notes.txt", b"just some text, definitely not an archive\n");
    let o = run(&["-Z1", s(&f)]);
    assert_eq!(code(&o), 9, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("not an archive"), "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// A gzip stream of `data`, in stored blocks.
fn gzip_of(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut blocks = data.chunks(60_000).peekable();
    if blocks.peek().is_none() {
        v.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(block) = blocks.next() {
        v.push(u8::from(blocks.peek().is_none()));
        v.extend_from_slice(&(block.len() as u16).to_le_bytes());
        v.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        v.extend_from_slice(block);
    }
    v.extend_from_slice(&crc32(data).to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v
}

/// A stored-member ZIP with its central directory, so that its members are the
/// ones the directory lists, and not also the local headers a stored ZIP
/// inside one holds.
fn zip_indexed(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = zip_of(members);
    let mut directory = Vec::new();
    let mut offset = 0u32;
    for (name, body) in members {
        directory.extend_from_slice(b"PK\x01\x02");
        directory.extend_from_slice(&20u16.to_le_bytes()); // made by
        directory.extend_from_slice(&20u16.to_le_bytes()); // needed
        directory.extend_from_slice(&[0; 2]); // flags
        directory.extend_from_slice(&[0; 2]); // stored
        directory.extend_from_slice(&[0; 4]); // time, date
        directory.extend_from_slice(&crc32(body).to_le_bytes());
        directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&[0; 8]); // extra, comment, disk, internal attributes
        directory.extend_from_slice(&[0; 4]); // external attributes
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
        offset += 30 + name.len() as u32 + body.len() as u32;
    }
    let at = v.len() as u32;
    v.extend_from_slice(&directory);
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&[0; 4]); // disk numbers
    v.extend_from_slice(&(members.len() as u16).to_le_bytes());
    v.extend_from_slice(&(members.len() as u16).to_le_bytes());
    v.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    v.extend_from_slice(&at.to_le_bytes());
    v.extend_from_slice(&[0; 2]); // comment
    v
}

/// A ZIP of a ZIP: `outer.zip` holds `inner.zip` (with `a.txt` and `dir/c.txt`)
/// and `b.txt`.
fn nested_zip() -> Vec<u8> {
    let inner = zip_indexed(&[("a.txt", b"alpha"), ("dir/c.txt", b"gamma")]);
    zip_indexed(&[("inner.zip", &inner), ("b.txt", b"beta")])
}

/// `-r` also opens the archives in the archive: a member that is one is
/// replaced by its own members, named down to them with `!`.
#[test]
fn recursive_lists_the_members_of_the_archives_inside() {
    let sc = Scratch::new("rlist");
    let f = sc.write("outer.zip", &nested_zip());
    // Without it, the inner archive is one more file.
    let o = run(&["-Z1", s(&f)]);
    assert_eq!(stdout(&o), "inner.zip\nb.txt\n", "{}", stderr(&o));
    for flag in ["-r", "--recursive"] {
        let o = run(&["-Z1", flag, s(&f)]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert_eq!(
            stdout(&o),
            "inner.zip!a.txt\ninner.zip!dir/c.txt\nb.txt\n",
            "{flag}"
        );
    }
    let o = run(&["-lr", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("   inner.zip!a.txt\n"), "{out}");
    assert!(out.contains("   inner.zip!dir/c.txt\n"), "{out}");
    assert!(out.contains("   b.txt\n"), "{out}");
    assert!(
        out.contains("       14                     3 files"),
        "{out}"
    );
    // The patterns of the command line match those names.
    let o = run(&["-Z1", "-r", s(&f), "inner.zip!*"]);
    assert_eq!(stdout(&o), "inner.zip!a.txt\ninner.zip!dir/c.txt\n");
    let o = run(&["-Z1", "-r", s(&f), "*", "-x", "*c.txt"]);
    assert_eq!(stdout(&o), "inner.zip!a.txt\nb.txt\n");
}

#[test]
fn recursive_tests_and_pipes_the_members_of_the_archives_inside() {
    let sc = Scratch::new("rpipe");
    let f = sc.write("outer.zip", &nested_zip());
    let o = run(&["-tr", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(
        out.contains("    testing: inner.zip!a.txt          OK\n"),
        "{out}"
    );
    assert!(
        out.contains("    testing: b.txt                    OK\n"),
        "{out}"
    );
    assert!(out.contains("No errors detected in"), "{out}");
    let o = run(&["-pr", s(&f), "inner.zip!a.txt", "b.txt"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "alphabeta");
}

#[test]
fn recursive_extracts_the_members_of_the_archives_inside_into_directories() {
    let sc = Scratch::new("rextract");
    let f = sc.write("outer.zip", &nested_zip());
    let out_dir = sc.subdir("out");
    let o = run(&["-r", s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("b.txt")).unwrap(), b"beta");
    // The inner archive is a directory of its members, not a file as well.
    assert_eq!(
        std::fs::read(out_dir.join("inner.zip/a.txt")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        std::fs::read(out_dir.join("inner.zip/dir/c.txt")).unwrap(),
        b"gamma"
    );
    assert!(out_dir.join("inner.zip").is_dir());
    // Junked paths keep the last name.
    let flat = sc.subdir("flat");
    let o = run(&["-rj", s(&f), "-d", s(&flat)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(tree(flat.as_path()).len(), 3, "{:?}", tree(flat.as_path()));
    assert_eq!(std::fs::read(flat.join("c.txt")).unwrap(), b"gamma");
}

/// What a name inside a nested archive can say stays under the extraction
/// directory, as a member's of the archive itself does.
#[test]
fn recursive_keeps_the_names_of_nested_members_under_the_extraction_directory() {
    let sc = Scratch::new("rslip");
    let inner = zip_indexed(&[("../../../escaped.txt", b"pwned"), ("/abs/x.txt", b"x")]);
    let f = sc.write("outer.zip", &zip_indexed(&[("in.zip", &inner)]));
    let out_dir = sc.subdir("out");
    let o = run(&["-r", s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        std::fs::read(out_dir.join("in.zip/escaped.txt")).unwrap(),
        b"pwned"
    );
    assert!(out_dir.join("in.zip/abs/x.txt").exists());
    assert!(!sc.path().join("escaped.txt").exists());
    // Nor does a name down there add a line to what is printed.
    let inner = zip_indexed(&[("x\nfake: OK", b"x")]);
    let f = sc.write("outer2.zip", &zip_indexed(&[("in\u{202e}.zip", &inner)]));
    let o = run(&["-Z1", "-r", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "in_.zip!x_fake: OK\n");
}

#[test]
fn recursive_goes_down_a_stream_and_names_it_for_what_it_is() {
    let sc = Scratch::new("rgz");
    let inner = zip_indexed(&[("deep.txt", b"deep")]);
    let f = sc.write("outer.zip", &zip_indexed(&[("x.gz", &gzip_of(&inner))]));
    let o = run(&["-Z1", "-r", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "x.gz!gzip-content!deep.txt\n");
}

/// A member that is an archive and gave no member is one more file, so that
/// it is not lost.
#[test]
fn recursive_keeps_an_archive_nothing_came_out_of_as_a_file() {
    let sc = Scratch::new("rempty");
    // The end of central directory record of a ZIP with no member.
    let mut empty = b"PK\x05\x06".to_vec();
    empty.extend_from_slice(&[0; 18]);
    let f = sc.write(
        "outer.zip",
        &zip_indexed(&[("empty.zip", &empty), ("b.txt", b"b")]),
    );
    let o = run(&["-Z1", "-r", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "empty.zip\nb.txt\n");
    let out_dir = sc.subdir("out");
    let o = run(&["-r", s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(std::fs::read(out_dir.join("empty.zip")).unwrap(), empty);
    // The archive itself is not a member of itself.
    let root = sc.write("root.zip", &empty);
    let o = run(&["-Z1", "-r", s(&root)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
}

/// The nesting `-r` opens is bounded, and an archive past it is a file and an
/// error, not a silent stop.
#[test]
fn recursive_stops_at_the_depth_limit_and_says_so() {
    let sc = Scratch::new("rdepth");
    let f = sc.write("outer.zip", &nested_zip());
    let o = run(&["-Z1", "-r", "--max-unpack-depth", "1", s(&f)]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert_eq!(stdout(&o), "inner.zip\nb.txt\n");
    assert!(
        stderr(&o).contains("inner.zip: recursion depth exceeds 1"),
        "{}",
        stderr(&o)
    );
    let o = run(&["-Z1", "-r", "--max-unpack-depth", "2", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "inner.zip!a.txt\ninner.zip!dir/c.txt\nb.txt\n");
    // 0 opens no archive, the one named included: it is the one file, and no
    // error.
    let o = run(&["-Z1", "-r", "--max-unpack-depth", "0", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "outer.zip\n");
    let out_dir = sc.subdir("out");
    let o = run(&["-r", "--max-unpack-depth", "0", s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        std::fs::read(out_dir.join("outer.zip")).unwrap(),
        nested_zip()
    );
}

/// A member of an archive inside that ends early is an error of the run, as one
/// of the archive itself is, and what was decoded is still written.
#[test]
fn recursive_reports_a_stream_that_ends_early() {
    let sc = Scratch::new("rcut");
    let text: Vec<u8> = (0..1000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut gz = gzip_of(&text);
    gz.truncate(gz.len() - 300);
    let f = sc.write("outer.zip", &zip_indexed(&[("cut.gz", &gz)]));
    let o = run(&["-tr", s(&f)]);
    assert_eq!(code(&o), 2, "{}{}", stdout(&o), stderr(&o));
    assert!(
        stdout(&o).contains("At least one error was detected in"),
        "{}",
        stdout(&o)
    );
    let out_dir = sc.subdir("out");
    let o = run(&["-r", s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 2, "{}{}", stdout(&o), stderr(&o));
    let written = std::fs::read(out_dir.join("cut.gz/gzip-content")).unwrap();
    assert!(
        !written.is_empty() && text.starts_with(&written),
        "{}",
        written.len()
    );
    // The same archive without -r: the member is the gzip, and is whole.
    let o = run(&["-t", s(&f)]);
    assert_eq!(code(&o), 0, "{}{}", stdout(&o), stderr(&o));
}

/// An archive over the limit, decoded as it is read, cannot be opened with
/// nowhere to put it: it is said, and the run exits with an error.
#[test]
fn recursive_says_an_archive_over_the_limit_cannot_be_opened() {
    let sc = Scratch::new("rbigarc");
    let filler: Vec<u8> = (0..100_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let inner = zip_indexed(&[("deep.txt", &filler)]);
    let f = sc.write("outer.zip", &zip_indexed(&[("big.gz", &gzip_of(&inner))]));
    let o = run(&[
        "-Z1",
        "-r",
        "--max-object-bytes",
        "64K",
        "--spill-dir",
        "off",
        s(&f),
    ]);
    assert_eq!(code(&o), 2, "{}{}", stdout(&o), stderr(&o));
    assert!(
        stderr(&o).contains("big.gz!gzip-content: ")
            && stderr(&o).contains("it is a container, and its members were not examined"),
        "{}",
        stderr(&o)
    );
    assert_eq!(stdout(&o), "", "nothing of it is listed as a file");
    // With room for it, it is opened.
    let o = run(&["-Z1", "-r", "--spill-dir", "off", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "big.gz!gzip-content!deep.txt\n");
}

/// The archive of `recursive_opens_an_archive_over_the_limit_through_a_spill_file`:
/// a gzip of a ZIP of 100,000 bytes, in a ZIP.
fn archive_in_a_gzip_in_a_zip() -> (Vec<u8>, Vec<u8>) {
    let filler: Vec<u8> = (0..100_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let inner = zip_indexed(&[("deep.txt", &filler)]);
    (zip_indexed(&[("big.gz", &gzip_of(&inner))]), filler)
}

/// An archive inside a member over the limit is opened through a spill file
/// when there is one, which is the default: listed, tested, piped and
/// extracted as one under the limit is.
#[test]
fn recursive_opens_an_archive_over_the_limit_through_a_spill_file() {
    let sc = Scratch::new("rspill");
    let (outer, filler) = archive_in_a_gzip_in_a_zip();
    let f = sc.write("outer.zip", &outer);
    let spill = sc.subdir("spill");
    for dir in [None, Some(s(&spill))] {
        let mut base = vec!["-r", "--max-object-bytes", "64K"];
        if let Some(dir) = dir {
            base.extend(["--spill-dir", dir]);
        }
        let with = |mode: &[&'static str], tail: &[&str]| -> Output {
            let mut args: Vec<&str> = mode.to_vec();
            args.extend(&base);
            args.push(s(&f));
            args.extend(tail);
            run(&args)
        };
        let o = with(&["-Z1"], &[]);
        assert_eq!(code(&o), 0, "{dir:?}: {}", stderr(&o));
        assert_eq!(stdout(&o), "big.gz!gzip-content!deep.txt\n", "{dir:?}");
        let o = with(&["-t"], &[]);
        assert_eq!(code(&o), 0, "{dir:?}: {}{}", stdout(&o), stderr(&o));
        assert!(
            stdout(&o).contains("big.gz!gzip-content!deep.txt") && stdout(&o).contains("OK"),
            "{dir:?}: {}",
            stdout(&o)
        );
        let o = with(&["-p"], &[]);
        assert_eq!(code(&o), 0, "{dir:?}: {}", stderr(&o));
        assert_eq!(stdout(&o).as_bytes(), &filler[..], "{dir:?}");
        let out_dir = sc.subdir("out");
        let o = with(&["-o"], &["-d", s(&out_dir)]);
        assert_eq!(code(&o), 0, "{dir:?}: {}{}", stdout(&o), stderr(&o));
        assert_eq!(
            std::fs::read(out_dir.join("big.gz/gzip-content/deep.txt")).unwrap(),
            filler,
            "{dir:?}"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
    // Nothing of the spill is left behind.
    assert_eq!(std::fs::read_dir(&spill).unwrap().count(), 0);
}

/// A spill past `--max-total-spill-bytes` is a container that was not opened, and
/// says so; `off` is no ceiling.
#[test]
fn recursive_says_a_container_past_the_spill_budget_was_not_opened() {
    let sc = Scratch::new("rspillmax");
    let (outer, _) = archive_in_a_gzip_in_a_zip();
    let f = sc.write("outer.zip", &outer);
    let o = run(&[
        "-Z1",
        "-r",
        "--max-object-bytes",
        "64K",
        "--max-total-spill-bytes",
        "10K",
        s(&f),
    ]);
    assert_eq!(code(&o), 2, "{}{}", stdout(&o), stderr(&o));
    assert!(
        stderr(&o).contains("big.gz!gzip-content: ") && stderr(&o).contains("spill budget"),
        "{}",
        stderr(&o)
    );
    assert_eq!(stdout(&o), "");
    for room in ["off", "0", "1M"] {
        let o = run(&[
            "-Z1",
            "-r",
            "--max-object-bytes",
            "64K",
            "--max-total-spill-bytes",
            room,
            s(&f),
        ]);
        assert_eq!(code(&o), 0, "{room}: {}", stderr(&o));
        assert_eq!(stdout(&o), "big.gz!gzip-content!deep.txt\n", "{room}");
    }
}

/// Each limit has a variable, named as the scanner names it, that does what
/// the option does, and the option wins over it.
#[test]
fn a_limit_is_read_from_its_variable_and_the_option_wins() {
    let sc = Scratch::new("limitvars");
    let (outer, _) = archive_in_a_gzip_in_a_zip();
    let big = sc.write("big.zip", &outer);
    let text = vec![b'x'; 5000];
    let one = sc.write("one.zip", &zip_of(&[("big.txt", &text)]));
    let three = sc.write(
        "three.zip",
        &zip_of(&[("a", b"1"), ("b", b"2"), ("c", b"3")]),
    );
    let nested = sc.write("nested.zip", &nested_zip());
    let spill = sc.subdir("spill");
    let (big, one, three, nested, spill) = (s(&big), s(&one), s(&three), s(&nested), s(&spill));
    // The variable, its value, the option that says the same, the arguments
    // it is tried with, and an option that undoes it.
    type Case<'a> = (&'a str, &'a str, [&'a str; 2], Vec<&'a str>, [&'a str; 2]);
    let cases: [Case; 6] = [
        (
            "EXAV_MAX_OBJECT_BYTES",
            "64K",
            ["--max-object-bytes", "64K"],
            vec!["-Z1", "-r", "--spill-dir", "off", big],
            ["--max-object-bytes", "1G"],
        ),
        (
            "EXAV_SPILL_DIR",
            "off",
            ["--spill-dir", "off"],
            vec!["-Z1", "-r", "--max-object-bytes", "64K", big],
            ["--spill-dir", spill],
        ),
        (
            "EXAV_MAX_TOTAL_SPILL_BYTES",
            "10K",
            ["--max-total-spill-bytes", "10K"],
            vec!["-Z1", "-r", "--max-object-bytes", "64K", big],
            ["--max-total-spill-bytes", "off"],
        ),
        (
            "EXAV_MAX_EXTRACTED_BYTES",
            "1K",
            ["--max-extracted-bytes", "1K"],
            vec!["-p", one],
            ["--max-extracted-bytes", "1M"],
        ),
        (
            "EXAV_MAX_MEMBERS",
            "1",
            ["--max-members", "1"],
            vec!["-Z1", three],
            ["--max-members", "10"],
        ),
        (
            "EXAV_MAX_UNPACK_DEPTH",
            "1",
            ["--max-unpack-depth", "1"],
            vec!["-Z1", "-r", nested],
            ["--max-unpack-depth", "2"],
        ),
    ];
    let same = |a: &Output, b: &Output, what: &str| {
        assert_eq!(code(a), code(b), "{what}: {}{}", stdout(a), stderr(a));
        assert_eq!(stdout(a), stdout(b), "{what}");
        assert_eq!(stderr(a), stderr(b), "{what}");
    };
    for (var, value, option, base, undo) in &cases {
        // The long options are read anywhere, the archive's name included.
        let with = |extra: &[&str], base: &[&str]| -> Output {
            let mut args: Vec<&str> = base.to_vec();
            args.extend(extra);
            run(&args)
        };
        let by_option = with(option, base);
        let by_variable = run_env(&[(*var, *value)], base);
        same(&by_variable, &by_option, var);
        // The test means something: the option changes the run.
        let plain = run(base);
        assert!(
            code(&plain) != code(&by_option)
                || stdout(&plain) != stdout(&by_option)
                || stderr(&plain) != stderr(&by_option),
            "{var}: the option changes nothing here"
        );
        // The option wins: the run is as with the option that undoes it.
        let undone = with(undo, base);
        let over = {
            let mut args: Vec<&str> = base.to_vec();
            args.extend(undo);
            run_env(&[(*var, *value)], &args)
        };
        same(&over, &undone, &format!("{var} against {undo:?}"));
    }
    // A value that is none is refused, naming the variable.
    for (var, bad) in [
        ("EXAV_MAX_OBJECT_BYTES", "lots"),
        ("EXAV_MAX_EXTRACTED_BYTES", "1MB"),
        ("EXAV_MAX_MEMBERS", "many"),
        ("EXAV_MAX_UNPACK_DEPTH", "off"),
        ("EXAV_OBJECT_CACHE_BYTES", "-1"),
        ("EXAV_OBJECT_CACHE_BLOCK_BYTES", "4MB"),
        ("EXAV_MAX_TOTAL_SPILL_BYTES", "huge"),
    ] {
        let o = run_env(&[(var, bad)], &["-Z1", three]);
        assert_eq!(code(&o), 10, "{var}={bad}: {}", stderr(&o));
        assert!(stderr(&o).contains(var), "{var}={bad}: {}", stderr(&o));
    }
    // The depth has no `off`, on the command line either.
    assert_eq!(code(&run(&["-Z1", three, "--max-unpack-depth", "off"])), 10);
    // `off` is no limit, in the variable as in the option.
    for (var, flag) in [
        ("EXAV_MAX_OBJECT_BYTES", "--max-object-bytes"),
        ("EXAV_MAX_EXTRACTED_BYTES", "--max-extracted-bytes"),
        ("EXAV_MAX_MEMBERS", "--max-members"),
        ("EXAV_MAX_TOTAL_SPILL_BYTES", "--max-total-spill-bytes"),
        ("EXAV_OBJECT_CACHE_BYTES", "--object-cache-bytes"),
        (
            "EXAV_OBJECT_CACHE_BLOCK_BYTES",
            "--object-cache-block-bytes",
        ),
    ] {
        let by_variable = run_env(&[(var, "off")], &["-Z1", three]);
        assert_eq!(code(&by_variable), 0, "{var}: {}", stderr(&by_variable));
        assert_eq!(stdout(&by_variable), "a\nb\nc\n", "{var}");
        let by_option = run(&["-Z1", three, flag, "off"]);
        same(&by_variable, &by_option, var);
    }
}

/// What a member that is decoded as it is read can be, when it is too long to
/// look at from its end, is not known: it is written as it is, and the run says
/// so.
#[test]
fn recursive_says_when_a_member_over_the_limit_could_not_be_checked() {
    let sc = Scratch::new("runchecked");
    let text: Vec<u8> = (0..(5u32 << 20)).map(|i| b'a' + (i % 26) as u8).collect();
    let f = sc.write("outer.zip", &zip_indexed(&[("big.gz", &gzip_of(&text))]));
    let o = run(&["-p", "-r", "--max-object-bytes", "64K", s(&f)]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(stdout(&o).as_bytes(), &text[..]);
    assert!(
        stderr(&o).contains("caution: big.gz!gzip-content: ")
            && stderr(&o).contains("was not checked"),
        "{}",
        stderr(&o)
    );
}

/// A member over the limit that is not an archive is written as it is
/// decoded, however large, and one that is an archive is opened.
#[test]
fn recursive_writes_a_member_over_the_limit_as_it_is_decoded() {
    let sc = Scratch::new("rbig");
    let text: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let f = sc.write("outer.zip", &zip_indexed(&[("big.gz", &gzip_of(&text))]));
    let o = run(&["-p", "-r", "--max-object-bytes", "64K", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o).as_bytes(), &text[..]);
}

/// What a name could do to a terminal is not printed: the characters that end
/// a line, move the cursor or reorder text are shown as `_`, and the patterns
/// still match the name as written.
#[test]
fn a_member_name_cannot_add_a_line_or_an_escape_to_the_output() {
    let sc = Scratch::new("shown");
    let f = sc.write(
        "evil.zip",
        &zip_of(&[
            ("a\nfake: OK.txt", b"1"),
            ("esc\x1b[31mred", b"2"),
            ("rtl\u{202e}gpj.exe", b"3"),
        ]),
    );
    for args in [&["-Z1"][..], &["-l"], &["-t"], &["-c"]] {
        let mut a = args.to_vec();
        a.push(s(&f));
        let o = run(&a);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        let out = stdout(&o);
        assert!(
            !out.contains('\x1b') && !out.contains('\u{202e}'),
            "{args:?}: {out:?}"
        );
        assert!(
            out.lines().all(|l| !l.starts_with("fake: OK")),
            "{args:?}: {out:?}"
        );
        assert!(out.contains("a_fake: OK.txt"), "{args:?}: {out:?}");
    }
    // The pattern is matched against the name as written.
    let o = run(&["-Z1", s(&f), "a?fake*"]);
    assert_eq!(stdout(&o), "a_fake: OK.txt\n");
    // On disk it is a plain name.
    let out_dir = sc.subdir("out");
    let o = run(&[s(&f), "-d", s(&out_dir)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        out_dir.join("a_fake: OK.txt").exists(),
        "{:?}",
        tree(out_dir.as_path())
    );
}

/// The exit status of a member that was not decoded is chosen by the kind of
/// its reason, not by the words the reader used for it.
#[test]
fn a_member_not_decoded_exits_by_the_kind_of_its_reason() {
    let sc = Scratch::new("kinds");
    // A compression method no decoder reads.
    let method = sc.write("method.zip", &zip_with(99, &[("m.bin", b"abc")]));
    let o = run(&["-t", s(&method)]);
    assert_eq!(code(&o), 81, "{}{}", stdout(&o), stderr(&o));
    assert!(
        stdout(&o).contains("unsupported zip compression method"),
        "{}",
        stdout(&o)
    );
    // Deflate that does not decode: damage, not a method.
    let bad = sc.write("bad.zip", &zip_with(8, &[("broken.bin", &[0xff; 64])]));
    let o = run(&["-t", s(&bad)]);
    assert_eq!(code(&o), 2, "{}{}", stdout(&o), stderr(&o));
    let o = run(&[s(&bad), "-d", s(&sc.subdir("out"))]);
    assert_eq!(code(&o), 2, "{}{}", stdout(&o), stderr(&o));
}

/// The same for a reader of its own: a ZOO member of a method zoo does not
/// define.
#[test]
fn a_zoo_member_of_an_unknown_method_exits_81() {
    let sc = Scratch::new("zoo-method");
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/zoo/store.zoo");
    let mut zoo = std::fs::read(path).unwrap();
    let start = u32::from_le_bytes(zoo[24..28].try_into().unwrap()) as usize;
    assert_eq!(zoo[start + 5], 0, "the first member is stored");
    zoo[start + 5] = 7;
    let f = sc.write("method.zoo", &zoo);
    let o = run(&["-t", s(&f)]);
    assert_eq!(code(&o), 81, "{}{}", stdout(&o), stderr(&o));
    assert!(
        stdout(&o).contains("compression method exav does not decode"),
        "{}",
        stdout(&o)
    );
}

/// An executable that is too large to look at for a packer is said not to have
/// been, not said to be no archive.
#[test]
fn an_executable_over_the_limit_is_not_checked_and_says_so() {
    let sc = Scratch::new("bigexe");
    let mut exe = b"MZ".to_vec();
    exe.resize(4000, 0);
    let f = sc.write("a.exe", &exe);
    for name in ["--max-object-bytes", "--max-memory"] {
        let o = run(&["-l", name, "100", "--object-cache-bytes", "off", s(&f)]);
        assert_eq!(code(&o), 9, "{name}: {}", stderr(&o));
        assert!(
            stderr(&o).contains("whether it is packed was not checked"),
            "{name}: {}",
            stderr(&o)
        );
    }
    // Within the limit it is looked at, and is no archive.
    let o = run(&["-l", s(&f)]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("not an archive"), "{}", stderr(&o));
}

/// A format that is read whole is refused over `--max-object-bytes`, however
/// large the object cache is: the archive is not held in memory past it.
#[test]
fn a_format_read_whole_over_the_object_limit_is_reported_whatever_the_cache() {
    let sc = Scratch::new("readwhole");
    let mut rtf = b"{\\rtf1\\ansi ".to_vec();
    rtf.extend(b"hello world \\par\n".repeat(8000));
    rtf.push(b'}');
    let f = sc.write("big.rtf", &rtf);
    let o = run(&["-Z1", "--max-object-bytes", "64K", s(&f)]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("over the 65536-byte buffer limit (--max-object-bytes)"),
        "{}",
        stderr(&o)
    );
    let o = run(&["-Z1", "--max-object-bytes", "1M", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

/// Parts are known by their file names, so two with one name are refused
/// rather than joined as one.
#[test]
fn two_parts_with_one_name_are_refused() {
    let sc = Scratch::new("samename");
    let a = sc.subdir("a");
    let b = sc.subdir("b");
    std::fs::write(a.join("x.7z.001"), b"first").unwrap();
    std::fs::write(b.join("x.7z.001"), b"second").unwrap();
    let o = run(&[
        "-l",
        s(&a.join("x.7z.001")),
        "--volume",
        s(&b.join("x.7z.001")),
    ]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("are both called x.7z.001"),
        "{}",
        stderr(&o)
    );
}

/// The limits have names as the scanner's, and the older names still work.
#[test]
fn the_limits_have_the_scanners_names_and_keep_the_old_ones() {
    let sc = Scratch::new("limitnames");
    let big = vec![b'x'; 5000];
    let f = sc.write("a.zip", &zip_of(&[("big.txt", &big)]));
    for (name, old) in [
        ("--max-extracted-bytes", "--max-size"),
        ("--max-object-bytes", "--max-memory"),
    ] {
        for flag in [name, old] {
            let o = run(&["-p", flag, "1K", s(&f)]);
            let o2 = run(&["-p", name, "1K", s(&f)]);
            assert_eq!(code(&o), code(&o2), "{flag}");
            assert_eq!(stdout(&o), stdout(&o2), "{flag}");
            let inline = format!("{flag}=1K");
            let o3 = run(&["-p", &inline, s(&f)]);
            assert_eq!(code(&o3), code(&o2), "{inline}");
            assert_eq!(stdout(&o3), stdout(&o2), "{inline}");
        }
    }
    // The extracted-bytes limit stops what is decoded; a high one does not.
    let o = run(&["-p", "--max-extracted-bytes", "1K", s(&f)]);
    assert_ne!(code(&o), 0, "{}", stdout(&o));
    let o = run(&["-p", "--max-size", "1K", s(&f)]);
    assert_ne!(code(&o), 0, "{}", stdout(&o));
    let o = run(&["-p", "--max-extracted-bytes", "1M", s(&f)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o).as_bytes(), &big[..]);
    let help = stdout(&run(&["--help"]));
    for word in [
        "--max-extracted-bytes",
        "--max-object-bytes",
        "--max-unpack-depth",
        "--recursive",
    ] {
        assert!(help.contains(word), "{word}: {help}");
    }
}

/// `exav-unpack -l archive | head` ends quietly, as every Unix filter does:
/// Rust ignores `SIGPIPE`, and `println!` panics on the `EPIPE` it gets back.
#[cfg(unix)]
#[test]
fn a_listing_into_a_closed_pipe_ends_quietly() {
    use std::io::Read;
    let sc = Scratch::new("closed-pipe");
    // Far more output than a pipe holds, so the program is still writing when
    // the reader goes away.
    let names: Vec<String> = (0..6000)
        .map(|i| format!("member-with-a-long-name-{i:05}.txt"))
        .collect();
    let members: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b""[..])).collect();
    let arc = sc.write("many.zip", &zip_of(&members));
    let mut cmd = Command::new(BIN);
    for var in LIMIT_VARS {
        cmd.env_remove(var);
    }
    let mut child = cmd
        .arg("-l")
        .arg(&arc)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // One byte read, then the pipe closed.
    let mut stdout = child.stdout.take().unwrap();
    let mut one = [0u8; 1];
    stdout.read_exact(&mut one).unwrap();
    drop(stdout);
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(!err.contains("panicked"), "{err}");
    assert!(!err.contains("failed printing"), "{err}");
    assert_ne!(status.code(), Some(101), "{err}");
}
