//! End-to-end tests for the `exav-unpack` binary.
//!
//! This crate is a thin shell over the library, but the thin part is where the
//! only actually dangerous code lives: it is the one place in the project that
//! **writes attacker-named files to disk**. A member called `../../../etc/cron.d/x`
//! is ordinary in a hostile archive, and every extractor CVE of the last decade
//! is some version of honouring it. So the containment property gets tested
//! directly, not inferred from the shape of the code.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

/// Minimal stored-member ZIP (local headers only — exav reads those).
fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (name, body) in members {
        v.extend_from_slice(b"PK\x03\x04");
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // stored
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

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn exav-unpack")
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

#[test]
fn list_names_every_member_with_its_size() {
    let s = Scratch::new("list");
    let f = s.write(
        "a.zip",
        &zip_of(&[("one.txt", b"hello"), ("two.txt", b"worldly")]),
    );
    let o = run(&["list", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("2 member(s):"), "{out:?}");
    assert!(out.contains("5  one.txt"), "{out:?}");
    assert!(out.contains("7  two.txt"), "{out:?}");
    // The detected format goes to stderr so `list` output stays pipeable.
    assert!(stderr(&o).contains("format: Zip"), "{}", stderr(&o));
}

#[test]
fn list_writes_nothing_to_disk() {
    // `list` is the "just tell me" mode; if it wrote files it would be a trap.
    let s = Scratch::new("listclean");
    let f = s.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    let before = tree(s.path());
    let o = run(&["list", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(tree(s.path()), before, "list must not create files");
}

#[test]
fn extract_writes_members_into_the_output_directory() {
    let s = Scratch::new("extract");
    let f = s.write(
        "a.zip",
        &zip_of(&[("one.txt", b"hello"), ("dir/two.txt", b"world")]),
    );
    let out_dir = s.subdir("out");
    let o = run(&["extract", f.to_str().unwrap(), out_dir.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(
        std::fs::read(out_dir.join("one.txt")).unwrap(),
        b"hello".to_vec()
    );
    assert_eq!(
        std::fs::read(out_dir.join("dir/two.txt")).unwrap(),
        b"world".to_vec(),
        "a nested member name creates the directory under the output root"
    );
}

#[test]
fn a_traversing_member_name_is_written_inside_the_output_directory() {
    // The zip-slip case. `../../../` components are dropped, not honoured, so
    // the file lands under the output root by its basename.
    let s = Scratch::new("slip");
    let f = s.write(
        "evil.zip",
        &zip_of(&[("../../../escaped.txt", b"pwned"), ("ok.txt", b"fine")]),
    );
    let out_dir = s.subdir("out");
    let o = run(&["extract", f.to_str().unwrap(), out_dir.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));

    assert_eq!(
        std::fs::read(out_dir.join("escaped.txt")).unwrap(),
        b"pwned".to_vec(),
        "the member is still extracted — just contained"
    );
    // Nothing above the output root: not in the scratch dir, not in its parent.
    assert!(
        !s.path().join("escaped.txt").exists(),
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
    let s = Scratch::new("absolute");
    let f = s.write("evil.zip", &zip_of(&[("/etc/cron.d/backdoor", b"x")]));
    let out_dir = s.subdir("out");
    let o = run(&["extract", f.to_str().unwrap(), out_dir.to_str().unwrap()]);
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
    // user never learns about; the CLI names it and fails.
    let s = Scratch::new("empty-name");
    let f = s.write("evil.zip", &zip_of(&[("../..", b"x")]));
    let out_dir = s.subdir("out");
    let o = run(&["extract", f.to_str().unwrap(), out_dir.to_str().unwrap()]);
    assert_ne!(code(&o), 0, "a skipped member must not report success");
    assert!(
        stderr(&o).contains("unsafe member name"),
        "the skip must be explained: {}",
        stderr(&o)
    );
    assert_eq!(tree(out_dir.as_path()), Vec::<PathBuf>::new());
}

#[test]
fn extract_defaults_to_the_current_directory() {
    let s = Scratch::new("cwd");
    let f = s.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    let work = s.subdir("work");
    let o = Command::new(BIN)
        .args(["extract", f.to_str().unwrap()])
        .current_dir(&work)
        .output()
        .expect("spawn");
    assert_eq!(
        o.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        std::fs::read(work.join("one.txt")).unwrap(),
        b"hello".to_vec()
    );
}

#[test]
fn no_arguments_prints_usage_and_exits_two() {
    let o = run(&[]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("usage:"), "{}", stderr(&o));
}

#[test]
fn an_unknown_subcommand_is_a_usage_error() {
    let s = Scratch::new("badsub");
    let f = s.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    let o = run(&["explode", f.to_str().unwrap()]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("usage:"), "{}", stderr(&o));
}

#[test]
fn too_many_arguments_to_list_is_a_usage_error() {
    // `list a b` must not silently ignore `b`.
    let s = Scratch::new("listargs");
    let f = s.write("a.zip", &zip_of(&[("one.txt", b"hello")]));
    let o = run(&["list", f.to_str().unwrap(), "extra"]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
}

#[test]
fn a_missing_file_is_reported_and_fails() {
    let o = run(&["list", "/definitely/not/here.zip"]);
    assert_eq!(code(&o), 1, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("cannot read"), "{}", stderr(&o));
}

#[test]
fn an_unrecognised_format_fails_rather_than_reporting_an_empty_archive() {
    // "0 member(s)" on a file that is not an archive would read as "opened it,
    // found nothing" — the one answer that must never be guessed at.
    let s = Scratch::new("unknown");
    let f = s.write("notes.txt", b"just some text, definitely not an archive\n");
    let o = run(&["list", f.to_str().unwrap()]);
    assert_eq!(code(&o), 1, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("unrecognised archive format"),
        "{}",
        stderr(&o)
    );
    assert_eq!(stdout(&o), "");
}
