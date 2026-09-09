//! exav is run against its own source tree and its own binary, and must find
//! nothing.
//!
//! A scanner is a file every other scanner reads. If the EICAR test string were
//! stored as a literal anywhere in this repository, it would travel into the
//! compiled binary, into the `.crate` tarballs on crates.io and into the
//! container image — and Defender, or whatever watches the machine running
//! `cargo add exav-core`, would quarantine all three. The failure looks like a
//! broken release, not like the test string it is, and it arrives on the day of
//! a release rather than in review. ClamAV keeps EICAR in a signature database
//! rather than in its binary for the same reason.
//!
//! So the bytes are assembled at run time (see `exav_unpack::eicar`) and this
//! test holds the property, in two passes:
//!
//! 1. **exav itself**, with the built-in EICAR-only baseline. This is the pass
//!    that matters, because it is the same judgement another scanner makes: it
//!    reads the compiled binary and every source file, through the same
//!    container-aware walk a real scan uses.
//! 2. **A plain substring search**, as a backstop. exav is the thing under test
//!    here, so a bug that stopped it detecting EICAR would also stop this file
//!    noticing — pass 1 would go quiet exactly when it should shout. `grep` has
//!    no such coupling: it cannot regress with the engine.
//!
//! Fixtures are deliberately out of scope. Several are archives built *around*
//! EICAR to prove detection works through gzip, qcow2, BinHex and the rest;
//! demanding they be clean would delete the tests. They are excluded from both
//! published crates instead (see the `exclude` keys), so nothing carrying the
//! string is ever shipped.

use std::path::{Path, PathBuf};
use std::process::Command;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    // The built-in EICAR-only baseline is exactly the signature set this test
    // wants: it detects the one string at issue and nothing else, so a finding
    // is unambiguous and no signature database has to be present.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<root>/crates/exav`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root above crates/exav")
        .to_path_buf()
}

/// Every file the repository actually publishes as source, from `git ls-files`.
///
/// Tracked files, not a directory walk: a walk also picks up build output, agent
/// worktrees under `.claude/` and local scratch directories, none of which this
/// project ships and any of which can hold an old copy carrying the literal. The
/// question here is what is *in the repository*, and git is what answers it.
///
/// Fixture trees are dropped for the reason in the module docs — they exist to
/// carry the string — as are binary extensions, leaving text a reviewer would
/// call source.
fn source_files(root: &Path) -> Vec<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .expect("run `git ls-files` — this test reads the tracked tree");
    assert!(
        out.status.success(),
        "`git ls-files` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let files: Vec<PathBuf> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| root.join(String::from_utf8_lossy(s).as_ref()))
        .filter(|p| {
            let rel = p.strip_prefix(root).unwrap_or(p);
            let in_fixtures = rel.components().any(|c| {
                matches!(
                    c.as_os_str().to_string_lossy().as_ref(),
                    "fixtures" | "test_data" | "testdata" | "corpus"
                )
            });
            let is_text = matches!(
                p.extension().and_then(|s| s.to_str()),
                Some("rs" | "py" | "sh" | "toml" | "md" | "mdx" | "yml" | "yaml" | "js" | "ts")
            );
            !in_fixtures && is_text
        })
        .collect();

    assert!(
        files.len() > 100,
        "only {} tracked source files — the listing is broken, and a broken \
         listing passes this test by checking nothing",
        files.len()
    );
    files
}

/// Pass 1: exav reads its own binary and its own source, and reports nothing.
#[test]
fn exav_finds_nothing_in_its_own_binary_and_source() {
    let root = repo_root();
    let mut files = source_files(&root);
    // The artifact that actually ships, and the one another scanner sees first.
    files.push(PathBuf::from(env!("CARGO_BIN_EXE_exav")));

    // Batched: the whole list at once can exceed the platform's argv limit, and
    // a scanner that failed to start would otherwise read as "found nothing".
    for batch in files.chunks(200) {
        let out = exav()
            .arg("--quiet")
            // The question is whether exav *detects* anything here, not whether
            // it can fully parse its own source. A parser's source tends to
            // carry its own format's markers — `formats/xdp.rs` is typed as an
            // XDP document and reported PARTIAL on the base64 that follows —
            // and that would fail this test for a reason having nothing to do
            // with what it is guarding. A detection still exits 1.
            .args(["--partial-as", "ok"])
            .args(batch)
            .output()
            .expect("run exav");
        let code = out.status.code();
        assert_eq!(
            code,
            Some(0),
            "exav reported something in its own tree (exit {code:?}):\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Pass 2: the backstop. `grep` cannot regress along with the engine.
#[test]
fn no_source_file_contains_the_test_string_as_a_literal() {
    // Built the same way the library builds it, so this file does not carry the
    // literal either — which is the property being tested.
    let needle = exav_core::unpack::eicar();

    let root = repo_root();
    let mut guilty: Vec<String> = Vec::new();
    for path in source_files(&root) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.windows(needle.len()).any(|w| w == needle) {
            guilty.push(path.display().to_string());
        }
    }
    assert!(
        guilty.is_empty(),
        "the EICAR string is stored as a literal in:\n  {}\n\nAssemble it at \
         run time instead — `exav_core::unpack::eicar()` — or every scanner \
         that reads this repository, its crates.io tarballs and its container \
         image will quarantine them.",
        guilty.join("\n  ")
    );
}
