//! End-to-end tests for the `exav-grep` binary.
//!
//! The library is unit-tested in `src/lib.rs`; what is only reachable through
//! the binary is the part a user actually depends on: **exit codes**, which
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

/// Minimal stored-member ZIP (local headers only; exav reads those).
fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (name, body) in members {
        v.extend(zip_member(0, name, body, body.len()));
    }
    v
}

/// A local header and the `body` of a ZIP member of `size` bytes once decoded,
/// stored (method 0) or deflated (method 8).
fn zip_member(method: u16, name: &str, body: &[u8], size: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&(size as u32).to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(body);
    v
}

/// A ZIP of `(method, name, body, size)` members, with its central directory,
/// so that it is read member by member as it is decoded.
fn zip_with_directory(members: &[(u16, &str, &[u8], usize)]) -> Vec<u8> {
    let (mut out, mut directory) = (Vec::new(), Vec::new());
    for (method, name, body, size) in members {
        let offset = out.len() as u32;
        out.extend(zip_member(*method, name, body, *size));
        directory.extend_from_slice(b"PK\x01\x02");
        directory.extend_from_slice(&20u16.to_le_bytes()); // made by
        directory.extend_from_slice(&20u16.to_le_bytes()); // needed to extract
        directory.extend_from_slice(&0u16.to_le_bytes()); // flags
        directory.extend_from_slice(&method.to_le_bytes());
        directory.extend_from_slice(&[0; 4]); // time and date
        directory.extend_from_slice(&0u32.to_le_bytes()); // CRC-32
        directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(*size as u32).to_le_bytes());
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&[0; 12]); // extra, comment, disk, attributes
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let (start, count) = (out.len() as u32, members.len() as u16);
    out.extend_from_slice(&directory);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A raw deflate stream of `1 + 258 * matches` zero bytes: one fixed-Huffman
/// block with a zero, then a match of 258 bytes back one byte, `matches` times.
/// About 158 bytes out for each one in.
fn deflated_zeros(matches: usize) -> Vec<u8> {
    let (mut out, mut acc, mut used) = (Vec::new(), 0u32, 0u32);
    // A Huffman code goes in from its most significant bit.
    let mut put = |code: u32, len: u32| {
        for i in (0..len).rev() {
            acc |= ((code >> i) & 1) << used;
            used += 1;
            if used == 8 {
                out.push(acc as u8);
                (acc, used) = (0, 0);
            }
        }
    };
    put(1, 1); // the last block
    put(0b10, 2); // of the fixed kind
    put(0x30, 8); // the literal 0
    for _ in 0..matches {
        put(0xC5, 8); // length 258
        put(0, 5); // distance 1
    }
    put(0, 7); // the end of the block
    if used > 0 {
        out.push(acc as u8);
    }
    out
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

/// The variables the limits fall back to. A run does not see the ones set in
/// the environment of whoever runs the tests.
const LIMIT_VARS: [&str; 7] = [
    "EXAV_MAX_OBJECT_BYTES",
    "EXAV_MAX_EXTRACTED_BYTES",
    "EXAV_MAX_MEMBERS",
    "EXAV_MAX_COMPRESSION_RATIO",
    "EXAV_MAX_UNPACK_DEPTH",
    "EXAV_SPILL_DIR",
    "EXAV_MAX_TOTAL_SPILL_BYTES",
];

fn run(args: &[&str]) -> Output {
    run_env(&[], args)
}

/// Run with `vars` set in its environment.
fn run_env(vars: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = Command::new(BIN);
    for var in LIMIT_VARS {
        c.env_remove(var);
    }
    c.args(args)
        .envs(vars.iter().copied())
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
    // Context lines use `-` as the separator, matches use `:`, the same
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
/// that is a claim about content that was never read, and it is the answer a
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

/// `zip_of` with a central directory, so that a member is read as it is
/// produced and one over `--max-object-bytes` is streamed.
fn zip_indexed(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = zip_of(members);
    let mut directory = Vec::new();
    let mut offset = 0u32;
    for (name, body) in members {
        directory.extend_from_slice(b"PK\x01\x02");
        directory.extend_from_slice(&[20, 0, 20, 0]); // made by, needed
        directory.extend_from_slice(&[0; 2 + 2 + 4 + 4]); // flags, stored, time, crc
        directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&[0; 8 + 4]); // extra, comment, disk, attributes
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
        offset += 30 + name.len() as u32 + body.len() as u32;
    }
    let at = v.len() as u32;
    v.extend_from_slice(&directory);
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&(members.len() as u16).to_le_bytes());
    v.extend_from_slice(&(members.len() as u16).to_le_bytes());
    v.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    v.extend_from_slice(&at.to_le_bytes());
    v.extend_from_slice(&[0; 2]);
    v
}

/// A gzip of `data` in stored blocks: its one member is a stream decoded as it
/// is read, with no place in its container.
fn gzip_of(data: &[u8]) -> Vec<u8> {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let mut blocks = data.chunks(65_535).peekable();
    while let Some(block) = blocks.next() {
        gz.push(u8::from(blocks.peek().is_none()));
        gz.extend_from_slice(&(block.len() as u16).to_le_bytes());
        gz.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        gz.extend_from_slice(block);
    }
    gz.extend_from_slice(&(!crc).to_le_bytes());
    gz.extend_from_slice(&(data.len() as u32).to_le_bytes());
    gz
}

/// A ZIP in a gzip in a ZIP, the inner one about 400 KB, with the pattern at
/// the end of its member. The inner ZIP is a stream decoded as it is read.
fn nested_zip(s: &Scratch) -> PathBuf {
    let mut log = Vec::new();
    for i in 0..10_000 {
        log.extend_from_slice(format!("line {i} of the log, nothing to see\n").as_bytes());
    }
    log.extend_from_slice(b"the needle is here\n");
    let inner = zip_indexed(&[("deep.txt", &log)]);
    s.write("o.zip", &zip_indexed(&[("inner.gz", &gzip_of(&inner))]))
}

/// A container in a member over `--max-object-bytes` is opened through a spill
/// file, and the sizes of both flags take the suffixes their help gives.
#[test]
fn the_size_flags_take_suffixes_and_off() {
    let s = Scratch::new("sizes");
    let f = nested_zip(&s);
    let f = f.to_str().unwrap();
    for spill in ["2G", "1m", "1048576", "off", "0"] {
        let o = run(&[
            "-F",
            "needle",
            "--max-object-bytes",
            "64K",
            "--max-total-spill-bytes",
            spill,
            f,
        ]);
        assert_eq!(
            code(&o),
            0,
            "--max-total-spill-bytes {spill}: {}",
            stderr(&o)
        );
        assert!(stdout(&o).contains("o.zip!inner.gz!gzip-content!deep.txt:10001:"));
    }
    // A budget under the inner zip: reported, not opened, and the suffix is
    // what sets its size.
    let o = run(&[
        "-F",
        "needle",
        "--max-object-bytes",
        "64K",
        "--max-total-spill-bytes",
        "100K",
        f,
    ]);
    assert_eq!(code(&o), 3, "{}", stderr(&o));
    assert!(stderr(&o).contains("spill budget"), "{}", stderr(&o));
    // The limit of what is held is read the same way: `off` holds it all.
    let o = run(&["-F", "needle", "--max-object-bytes", "off", f]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("o.zip!inner.gz!gzip-content!deep.txt:10001:"));
}

/// A spill directory whose name is not UTF-8 is accepted, by flag and by
/// variable, and the inner container is opened through a file there.
#[test]
fn a_spill_dir_that_is_not_utf8_is_accepted() {
    use std::os::unix::ffi::OsStrExt;
    let s = Scratch::new("spillbytes");
    let f = nested_zip(&s);
    let dir = s.path().join(std::ffi::OsStr::from_bytes(b"sp\xe9"));
    std::fs::create_dir_all(&dir).unwrap();
    let base = ["-F", "needle", "--max-object-bytes", "64K"];
    let go = |flag: bool| {
        let mut c = Command::new(BIN);
        for var in LIMIT_VARS {
            c.env_remove(var);
        }
        c.args(base);
        if flag {
            c.arg("--spill-dir").arg(&dir);
        } else {
            c.env("EXAV_SPILL_DIR", &dir);
        }
        c.arg(&f).output().expect("spawn exav-grep")
    };
    for flag in [true, false] {
        let o = go(flag);
        assert_eq!(code(&o), 0, "flag {flag}: {}", stderr(&o));
        assert!(stdout(&o).contains("o.zip!inner.gz!gzip-content!deep.txt:10001:"));
    }
    // Without a place to spill the same run is partial, so the directory is
    // what made it complete.
    let o = run(&[
        "-F",
        "needle",
        "--max-object-bytes",
        "64K",
        "--spill-dir",
        "off",
        f.to_str().unwrap(),
    ]);
    assert_eq!(code(&o), 3, "{}", stderr(&o));
}

/// Each limit has a variable, named as the scanner names it, that does what
/// the flag does, and the flag wins over it.
#[test]
fn a_limit_is_read_from_its_variable_and_the_flag_wins() {
    let s = Scratch::new("limitvars");
    let nested = nested_zip(&s);
    let two = s.write(
        "two.zip",
        &zip_of(&[("a.txt", b"nothing\n"), ("b.txt", b"the needle\n")]),
    );
    // A PDF whose one stream, 4 KB long, the extracted bytes count.
    let mut stream = vec![b'x'; 4096];
    stream.extend_from_slice(b"\nthe needle\n");
    let mut pdf = format!(
        "%PDF-1.4\n1 0 obj\n<< /Length {} >>\nstream\n",
        stream.len()
    )
    .into_bytes();
    pdf.extend_from_slice(&stream);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    let pdf = s.write("big.pdf", &pdf);
    let spill = s.path().join("spill");
    std::fs::create_dir_all(&spill).unwrap();
    // A member of 1 MB of zeros that deflate makes 158 times smaller, then one
    // with the needle.
    let ratio = zip_with_directory(&[
        (8, "zeros.bin", &deflated_zeros(4064), 1 + 258 * 4064),
        (0, "after.txt", b"the needle\n", 11),
    ]);
    let ratio = s.write("ratio.zip", &ratio);
    // An ext4 volume holding a sparse file of 48 MiB, mostly holes.
    let sparse = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/fs/ext4_sparse.img.gz"
    );
    let (nested, two, spill, pdf, ratio) = (
        nested.to_str().unwrap(),
        two.to_str().unwrap(),
        spill.to_str().unwrap(),
        pdf.to_str().unwrap(),
        ratio.to_str().unwrap(),
    );
    // The variable, its value, the flag that says the same, the arguments it
    // is tried with, and a flag that undoes it.
    type Case<'a> = (&'a str, &'a str, [&'a str; 2], Vec<&'a str>, [&'a str; 2]);
    let cases: [Case; 9] = [
        (
            "EXAV_MAX_MATCHER_BYTES",
            "4",
            ["--max-matcher-bytes", "4"],
            vec!["-F", "needle", two],
            ["--max-matcher-bytes", "off"],
        ),
        (
            "EXAV_MAX_HOLE_BYTES",
            "1M",
            ["--max-hole-bytes", "1M"],
            vec!["-F", "needle", sparse],
            ["--max-hole-bytes", "off"],
        ),
        (
            "EXAV_MAX_OBJECT_BYTES",
            "64K",
            ["--max-object-bytes", "64K"],
            vec!["-F", "needle", "--spill-dir", "off", nested],
            ["--max-object-bytes", "off"],
        ),
        (
            "EXAV_MAX_EXTRACTED_BYTES",
            "1K",
            ["--max-extracted-bytes", "1K"],
            vec!["-F", "needle", pdf],
            ["--max-extracted-bytes", "off"],
        ),
        (
            "EXAV_SPILL_DIR",
            "off",
            ["--spill-dir", "off"],
            vec!["-F", "needle", "--max-object-bytes", "64K", nested],
            ["--spill-dir", spill],
        ),
        (
            "EXAV_MAX_TOTAL_SPILL_BYTES",
            "100K",
            ["--max-total-spill-bytes", "100K"],
            vec!["-F", "needle", "--max-object-bytes", "64K", nested],
            ["--max-total-spill-bytes", "off"],
        ),
        (
            "EXAV_MAX_MEMBERS",
            "1",
            ["--max-members", "1"],
            vec!["-F", "needle", two],
            ["--max-members", "10"],
        ),
        (
            "EXAV_MAX_UNPACK_DEPTH",
            "1",
            ["--max-unpack-depth", "1"],
            vec!["-F", "needle", nested],
            ["--max-unpack-depth", "8"],
        ),
        (
            "EXAV_MAX_COMPRESSION_RATIO",
            "10",
            ["--max-compression-ratio", "10"],
            vec!["-F", "needle", "--max-object-bytes", "64K", ratio],
            ["--max-compression-ratio", "off"],
        ),
    ];
    let same = |a: &Output, b: &Output, what: &str| {
        assert_eq!(code(a), code(b), "{what}: {}{}", stdout(a), stderr(a));
        assert_eq!(stdout(a), stdout(b), "{what}");
        assert_eq!(stderr(a), stderr(b), "{what}");
    };
    for (var, value, flag, base, undo) in &cases {
        let with = |extra: &[&str]| -> Output {
            let mut args: Vec<&str> = base.to_vec();
            args.extend(extra);
            run(&args)
        };
        let by_flag = with(flag);
        let mut args: Vec<&str> = base.to_vec();
        let by_variable = run_env(&[(*var, *value)], &args);
        same(&by_variable, &by_flag, var);
        // The test means something: the flag changes the run.
        let plain = run(&args);
        assert!(
            code(&plain) != code(&by_flag)
                || stdout(&plain) != stdout(&by_flag)
                || stderr(&plain) != stderr(&by_flag),
            "{var}: the flag changes nothing here"
        );
        // The flag wins.
        args.extend(undo);
        same(
            &run_env(&[(*var, *value)], &args),
            &with(undo),
            &format!("{var} against {undo:?}"),
        );
    }
    // `off` is no limit for the count, and so is `0`; the depth has none.
    let o = run_env(&[("EXAV_MAX_MEMBERS", "off")], &["-F", "needle", two]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    for off in ["off", "0"] {
        for args in [[two, "--max-members"], [ratio, "--max-compression-ratio"]] {
            let o = run(&["-F", "needle", args[0], args[1], off]);
            assert_eq!(code(&o), 0, "{args:?} {off}: {}", stderr(&o));
            assert!(stderr(&o).is_empty(), "{args:?} {off}: {}", stderr(&o));
        }
    }
    let o = run_env(
        &[("EXAV_MAX_COMPRESSION_RATIO", "off")],
        &["-F", "needle", ratio],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    for (var, bad) in [
        ("EXAV_MAX_MEMBERS", "many"),
        ("EXAV_MAX_COMPRESSION_RATIO", "many"),
        ("EXAV_MAX_UNPACK_DEPTH", "off"),
        ("EXAV_MAX_OBJECT_BYTES", "12x"),
        ("EXAV_MAX_EXTRACTED_BYTES", "12x"),
        ("EXAV_MAX_TOTAL_SPILL_BYTES", "lots"),
    ] {
        let o = run_env(&[(var, bad)], &["-F", "needle", two]);
        assert_eq!(code(&o), 2, "{var}={bad}: {}", stderr(&o));
    }
    let o = run(&["-F", "needle", two, "--max-unpack-depth", "off"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
}

/// A file past `--max-object-bytes` is read through a cache the two cache
/// flags size, and the same answer comes out of any size of it, `off` and `0`
/// (the least) included.
#[test]
fn the_cache_flags_size_the_cache_of_an_object_read_in_place() {
    let s = Scratch::new("cache");
    let mut log = Vec::new();
    for i in 0..20_000 {
        log.extend_from_slice(format!("line {i} of the log, nothing to see\n").as_bytes());
    }
    log.extend_from_slice(b"the needle is here\n");
    let f = s.write("big.log", &log);
    let f = f.to_str().unwrap();
    for (bytes, block) in [("32M", "1M"), ("64K", "4K"), ("off", "off"), ("0", "1")] {
        let o = run(&[
            "-F",
            "needle",
            "--max-object-bytes",
            "64K",
            "--object-cache-bytes",
            bytes,
            "--object-cache-block-bytes",
            block,
            f,
        ]);
        assert_eq!(code(&o), 0, "{bytes} {block}: {}", stderr(&o));
        assert!(
            stdout(&o).ends_with(":20001:the needle is here\n"),
            "{}",
            stdout(&o)
        );
    }
    // The environment says the same, and a flag overrides it.
    let o = Command::new(env!("CARGO_BIN_EXE_exav-grep"))
        .args(["-F", "needle", "--max-object-bytes", "64K", f])
        .env("EXAV_OBJECT_CACHE_BYTES", "garbage")
        .output()
        .unwrap();
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("--object-cache-bytes"),
        "{}",
        stderr(&o)
    );
    let o = Command::new(env!("CARGO_BIN_EXE_exav-grep"))
        .args([
            "-F",
            "needle",
            "--max-object-bytes",
            "64K",
            "--object-cache-bytes",
            "1M",
            f,
        ])
        .env("EXAV_OBJECT_CACHE_BYTES", "garbage")
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

/// A size that is not one is a usage error that names the flag.
#[test]
fn a_bad_size_is_a_usage_error_naming_the_flag() {
    let s = Scratch::new("badsize");
    let f = s.write("a.txt", b"hello\n");
    for (flag, value) in [
        ("--max-total-spill-bytes", "2GB"),
        ("--max-total-spill-bytes", "lots"),
        ("--max-object-bytes", "12x"),
        ("--max-object-bytes", ""),
        ("--object-cache-bytes", "32MB"),
        ("--object-cache-block-bytes", "x"),
    ] {
        let o = run(&["-F", "hello", flag, value, f.to_str().unwrap()]);
        assert_eq!(code(&o), 2, "{flag} {value}");
        assert!(stderr(&o).contains(flag), "{}", stderr(&o));
    }
}
