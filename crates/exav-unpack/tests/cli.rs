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
type TarEntry<'a> = (&'a str, u8, u32, u64, &'a str, &'a [u8]);

/// A ustar archive of `entries`.
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

/// Run in `dir` (or here), with `stdin` as its input.
fn run_in(dir: Option<&Path>, args: &[&str], stdin: &[u8]) -> Output {
    let mut c = Command::new(BIN);
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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

/// A RAR set reads from its first part, its members split across volumes
/// joined; parts named otherwise are given with `--volume`.
#[test]
fn a_rar_volume_set_is_read_whole() {
    let arc = std::fs::read(concat!(
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
