//! Coarse correctness spot-check over a real corpus.
//!
//! For every rule file in `$EXAV_YARA_CORPUS` that exav compiles with ZERO
//! rejections *and* that yara-x also accepts, both engines are asked to scan
//! the same handful of byte inputs; the set of matching rule identifiers must be
//! identical. This confirms the coverage numbers aren't hiding silent
//! mis-compiles (a rule that "compiles" but matches differently).
//!
//! No-op unless `EXAV_YARA_CORPUS` points at a directory of `.yar`/`.yara`
//! files, so it never runs in the default `cargo test`, and skipped when the
//! `yr` binary is absent. See `yara_difftest.rs` for why yara-x is a program
//! here rather than a dependency.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const INPUTS: &[&[u8]] = &[
    b"",
    b"MZ\x00\x00PE\x00\x00this is a small pe-ish header with some ascii text inside it",
    b"\x7fELF\x02\x01\x01\x00 elf binary bytes and some strings like /bin/sh and cmd.exe",
    b"the quick brown fox jumps over the lazy dog 1234567890 http://example.com/path",
    b"powershell -enc SQBFAFgA cmd.exe /c whoami & net user administrator",
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\xff\xfe\xfd\xfc",
    include_bytes!("testdata/tiny_pe32.exe"),
];

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x == "yar" || x == "yara")
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

fn exav_set(rules: &exav_core::yara::Rules, data: &[u8]) -> BTreeSet<String> {
    rules
        .scan(data)
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect()
}

/// The oracle, invoked as a program rather than linked as a library — see
/// `yara_difftest.rs` for why.
fn yr_bin() -> String {
    std::env::var("EXAV_YR_BIN").unwrap_or_else(|_| "yr".to_string())
}

fn have_yr() -> bool {
    std::process::Command::new(yr_bin())
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Matching rule names from `yr scan`, or `None` when the oracle refused the
/// rule file. Refusal is expected on a real corpus — unknown external
/// variables and modules exav does not implement make it bail — and those
/// files are skipped rather than counted as disagreements.
fn yr_set(rules: &str, data: &[u8]) -> Option<BTreeSet<String>> {
    let dir = std::env::temp_dir().join(format!("exav-yr-cov-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let rule_path = dir.join("rules.yar");
    let data_path = dir.join("target.bin");
    std::fs::write(&rule_path, rules).ok()?;
    std::fs::write(&data_path, data).ok()?;
    let out = std::process::Command::new(yr_bin())
        .arg("scan")
        .arg(&rule_path)
        .arg(&data_path)
        .output()
        .ok()?;
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

#[test]
fn spot_check_real_corpus() {
    let Ok(dir) = std::env::var("EXAV_YARA_CORPUS") else {
        eprintln!("EXAV_YARA_CORPUS not set; skipping corpus spot-check");
        return;
    };
    if !have_yr() {
        eprintln!("`yr` (yara-x CLI) not on PATH; skipping corpus spot-check");
        return;
    }
    let mut files = Vec::new();
    collect(Path::new(&dir), &mut files);
    files.sort();

    let mut files_compared = 0usize;
    let mut rules_compared = 0usize;
    let mut inputs_checked = 0usize;
    let mut disagreements: Vec<String> = Vec::new();

    for path in &files {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };

        // Only fully-clean-in-exav files: then exav's rule set == the file's
        // full rule set, so any difference is a match-behaviour difference
        // rather than an artefact of one engine having compiled fewer rules.
        let mut c = exav_core::yara::Compiler::new();
        let rejected = c.add_source_lenient(&src);
        if !rejected.is_empty() {
            continue;
        }
        let exav = c.build();
        if exav.is_empty() {
            continue;
        }

        // The oracle must accept the whole file too. Unknown external
        // variables and unimplemented modules make it bail; those files are
        // skipped, which is fine for a sample.
        let Some(first) = yr_set(src.as_str(), INPUTS[0]) else {
            continue;
        };

        files_compared += 1;
        rules_compared += exav.len();

        for (n, input) in INPUTS.iter().enumerate() {
            inputs_checked += 1;
            let a = exav_set(&exav, input);
            let Some(b) = (if n == 0 {
                Some(first.clone())
            } else {
                yr_set(src.as_str(), input)
            }) else {
                continue;
            };
            if a != b {
                let only_exav: Vec<_> = a.difference(&b).cloned().collect();
                let only_yx: Vec<_> = b.difference(&a).cloned().collect();
                disagreements.push(format!(
                    "{}: exav-only={:?} yarax-only={:?} (input {} bytes)",
                    path.display(),
                    only_exav,
                    only_yx,
                    input.len()
                ));
            }
        }
    }

    eprintln!(
        "spot-check: {files_compared} files, {rules_compared} rules, {inputs_checked} scans, {} disagreements",
        disagreements.len()
    );
    for d in disagreements.iter().take(40) {
        eprintln!("  DISAGREE {d}");
    }

    assert!(
        disagreements.is_empty(),
        "{} match disagreements between exav and yara-x",
        disagreements.len()
    );
}
