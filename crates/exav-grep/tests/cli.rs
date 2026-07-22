//! End-to-end tests for the `exav-grep` binary.
//!
//! The library is unit-tested in `src/lib.rs`; what is only reachable through
//! the binary is the part a user actually depends on — **exit codes**, which
//! stream each kind of output goes to, and the flag wiring. In particular exit
//! code 3 ("no matches, but something could not be read") is this tool's whole
//! reason to differ from `grep`: a script that treats it as 1 concludes "not
//! present" about bytes nobody looked at.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_exav-grep");

/// A scratch directory unique to one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        // The pid keeps concurrent `cargo test` runs from colliding; `tag` keeps
        // tests within a run apart (libtest runs them on threads of one process).
        let d = std::env::temp_dir().join(format!("exav-grep-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        Scratch(d)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&p, bytes).expect("write fixture");
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

/// A ZIP holding one member with a compression method no engine implements: a
/// member that really exists and really cannot be read.
fn zip_with_undecodable_member() -> Vec<u8> {
    let name = "x.bin";
    let body: &[u8] = b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8";
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&99u16.to_le_bytes()); // not a real method
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(body);
    v
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn exav-grep")
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

#[test]
fn a_hit_inside_an_archive_exits_zero_and_shows_the_nesting_path() {
    let s = Scratch::new("hit");
    let f = s.write(
        "a.zip",
        &zip_of(&[("notes.txt", b"hello\nsecret sauce\nbye\n")]),
    );
    let o = run(&["-F", "secret", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    assert!(
        out.contains("a.zip!notes.txt:2:secret sauce"),
        "the nesting path and line number are the output's whole value: {out:?}"
    );
}

#[test]
fn no_match_in_a_fully_readable_input_exits_one() {
    let s = Scratch::new("nomatch");
    let f = s.write("a.zip", &zip_of(&[("notes.txt", b"hello\nbye\n")]));
    let o = run(&["-F", "absent", f.to_str().unwrap()]);
    assert_eq!(code(&o), 1, "stderr: {}", stderr(&o));
    assert_eq!(stdout(&o), "", "no matches means no stdout");
}

#[test]
fn no_match_plus_an_unreadable_member_exits_three_not_one() {
    // The distinction this tool exists to make. Exit 1 would tell a caller the
    // pattern is absent; it is only absent from the part that could be read.
    let s = Scratch::new("unreadable");
    let f = s.write("a.zip", &zip_with_undecodable_member());
    let o = run(&["-F", "anything", f.to_str().unwrap()]);
    assert_eq!(
        code(&o),
        3,
        "an incomplete search must not report as a clean miss. stderr: {}",
        stderr(&o)
    );
    let err = stderr(&o);
    assert!(
        err.contains("x.bin") && err.contains("could not read"),
        "the unreadable member must be named on stderr: {err:?}"
    );
    assert_eq!(stdout(&o), "", "diagnostics belong on stderr, not stdout");
}

#[test]
fn quiet_unreadable_silences_the_message_but_not_the_exit_code() {
    // Suppressing the noise must not suppress the fact. A caller that scripts on
    // the exit code still learns the search was incomplete.
    let s = Scratch::new("quiet");
    let f = s.write("a.zip", &zip_with_undecodable_member());
    let o = run(&["--quiet-unreadable", "-F", "anything", f.to_str().unwrap()]);
    assert_eq!(code(&o), 3);
    assert!(
        !stderr(&o).contains("could not read"),
        "stderr: {}",
        stderr(&o)
    );
}

#[test]
fn a_match_wins_over_an_unreadable_member() {
    // Both conditions at once: exit 0 (grep's contract for "found"), with the
    // unreadable member still reported on stderr so the caller knows the result
    // may be incomplete.
    let s = Scratch::new("both");
    let mut blob = zip_of(&[("ok.txt", b"needle here\n")]);
    blob.extend_from_slice(&zip_with_undecodable_member());
    let f = s.write("a.zip", &blob);
    let o = run(&["-F", "needle", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains("needle here"));
}

#[test]
fn files_with_matches_lists_each_path_once() {
    let s = Scratch::new("dashl");
    let f = s.write(
        "a.zip",
        &zip_of(&[
            ("one.txt", b"tok\ntok\ntok\n"),
            ("two.txt", b"nothing\n"),
            ("three.txt", b"tok\n"),
        ]),
    );
    let o = run(&["-l", "-F", "tok", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(lines.len(), 2, "one line per matching member: {lines:?}");
    assert!(lines.iter().any(|l| l.ends_with("a.zip!one.txt")));
    assert!(lines.iter().any(|l| l.ends_with("a.zip!three.txt")));
}

#[test]
fn count_reports_matching_members_not_matching_lines() {
    let s = Scratch::new("dashc");
    let f = s.write(
        "a.zip",
        &zip_of(&[("one.txt", b"tok\ntok\ntok\n"), ("two.txt", b"tok\n")]),
    );
    let o = run(&["-c", "-F", "tok", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(stdout(&o).trim(), "2");
}

#[test]
fn ignore_case_and_invert_are_wired_through() {
    let s = Scratch::new("flags");
    let f = s.write("a.zip", &zip_of(&[("f.txt", b"Alpha\nbeta\n")]));

    let o = run(&["-i", "-F", "ALPHA", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains("Alpha"));

    // Without -i the same pattern must miss, or -i proves nothing.
    let o = run(&["-F", "ALPHA", f.to_str().unwrap()]);
    assert_eq!(code(&o), 1);

    let o = run(&["-v", "-F", "Alpha", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains("beta"));
    assert!(
        !stdout(&o).contains("Alpha"),
        "-v must exclude the matching line: {:?}",
        stdout(&o)
    );
}

#[test]
fn fixed_strings_disables_regex_metacharacters() {
    // `a.c` as a regex matches "abc"; as a fixed string it must not.
    let s = Scratch::new("fixed");
    let f = s.write("a.zip", &zip_of(&[("f.txt", b"abc\n")]));
    assert_eq!(code(&run(&["a.c", f.to_str().unwrap()])), 0);
    assert_eq!(code(&run(&["-F", "a.c", f.to_str().unwrap()])), 1);
}

#[test]
fn context_flags_print_surrounding_lines() {
    let s = Scratch::new("context");
    let f = s.write(
        "a.zip",
        &zip_of(&[("f.txt", b"one\ntwo\nTARGET\nfour\nfive\n")]),
    );
    let o = run(&["-C", "1", "-F", "TARGET", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    // Context lines use `-` as the separator, matches use `:` — the same
    // convention grep uses, so downstream tooling can tell them apart.
    assert!(out.contains("-2-two"), "{out:?}");
    assert!(out.contains(":3:TARGET"), "{out:?}");
    assert!(out.contains("-4-four"), "{out:?}");
    assert!(!out.contains("one"), "one line either side only: {out:?}");
}

#[test]
fn max_count_stops_after_n_matches_per_member() {
    let s = Scratch::new("maxcount");
    let f = s.write("a.zip", &zip_of(&[("f.txt", b"tok\ntok\ntok\ntok\n")]));
    let o = run(&["-m", "2", "-F", "tok", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(stdout(&o).lines().count(), 2, "{:?}", stdout(&o));
}

#[test]
fn a_bad_regex_is_a_usage_error_not_a_miss() {
    // Exit 1 here would read as "searched, found nothing" for a search that
    // never ran.
    let o = run(&["(unclosed", "/dev/null"]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("bad pattern"), "{}", stderr(&o));
}

#[test]
fn a_directory_without_dash_r_is_an_error_and_dash_r_descends_it() {
    let s = Scratch::new("recurse");
    s.write("sub/a.zip", &zip_of(&[("f.txt", b"deep-token\n")]));
    let dir = s.path().to_str().unwrap();

    let o = run(&["-F", "deep-token", dir]);
    assert_eq!(code(&o), 2, "a silent skip would be the worst outcome");
    assert!(stderr(&o).contains("is a directory"), "{}", stderr(&o));

    let o = run(&["-r", "-F", "deep-token", dir]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains("a.zip!f.txt"), "{:?}", stdout(&o));
}

#[test]
fn an_unreadable_file_on_disk_is_an_io_error_not_a_miss() {
    let o = run(&["-F", "x", "/definitely/not/here.zip"]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(!stderr(&o).is_empty(), "the failure must be explained");
}

#[test]
fn a_plain_file_is_searched_without_needing_a_container() {
    let s = Scratch::new("plain");
    let f = s.write("notes.txt", b"alpha\nbravo\n");
    let o = run(&["-F", "bravo", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains(":2:bravo"), "{:?}", stdout(&o));
}

/// A directory the walk cannot enter is reported, and the run does not exit 1.
///
/// Exit 1 means "searched it, found nothing". For a subtree nobody could open,
/// that is a claim about content that was never read — and it is the answer a
/// script acts on. The crate already distinguishes this for members it cannot
/// decode (exit 3); the filesystem walk one level up has to agree, or the
/// distinction is defeated by a `chmod`.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_reported_and_does_not_exit_one() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("walkperm");
    s.write("open/plain.txt", b"nothing to see\n");
    s.write("locked/secret.txt", b"needle-in-here\n");
    let locked = s.path().join("locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    // Root ignores mode 0, and so does any environment that grants CAP_DAC_*.
    if std::fs::read_dir(&locked).is_ok() {
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
        eprintln!("skipped: this environment can read a mode-000 directory");
        return;
    }

    let o = run(&["-r", "-F", "needle-in-here", s.path().to_str().unwrap()]);
    let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));

    assert_ne!(
        code(&o),
        1,
        "exit 1 says the pattern is not present, but the directory holding it \
         was never opened.\nstdout: {}\nstderr: {}",
        stdout(&o),
        stderr(&o)
    );
    assert!(
        stderr(&o).contains("locked"),
        "the unreadable path must be named, or nobody can tell what was missed: {:?}",
        stderr(&o)
    );
}

/// The counterweight: a readable tree with no match still exits 1. Without this,
/// the test above is satisfied by a build that never returns 1 at all.
#[test]
fn a_readable_tree_with_no_match_still_exits_one() {
    let s = Scratch::new("walkok");
    s.write("sub/plain.txt", b"nothing to see\n");
    let o = run(&["-r", "-F", "needle-in-here", s.path().to_str().unwrap()]);
    assert_eq!(code(&o), 1, "stderr: {}", stderr(&o));
}

#[test]
fn a_binary_member_reports_that_it_matched_without_dumping_bytes() {
    let s = Scratch::new("binary");
    let mut body = b"prefix\x00\x00secret-token\x00\x00".to_vec();
    body.extend_from_slice(&[0u8; 32]);
    let f = s.write("a.zip", &zip_of(&[("blob.bin", &body)]));
    let o = run(&["-F", "secret-token", f.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("Binary file"), "{out:?}");
    assert!(out.contains("a.zip!blob.bin"), "{out:?}");
}
