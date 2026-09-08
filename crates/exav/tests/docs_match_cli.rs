//! The documented command line and the real one are the same command line.
//!
//! Every drift between them found so far was silent and reader-facing: a flag
//! renamed in the code and left standing in a table, a page telling an operator
//! to run something the binary rejects. Nothing else in the build compares the
//! two — the docs build checks links and frontmatter, not whether the commands
//! on the page can be typed — so this does.
//!
//! Skipped, not failed, when `www/` is absent: the published crate ships without
//! it, and a test that cannot see the docs has nothing to say about them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root above crates/exav")
        .to_path_buf()
}

/// Long flags the binary really has, from `--help`.
fn flags_in_help() -> BTreeSet<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_exav"))
        .arg("--help")
        .output()
        .expect("run exav --help");
    assert!(out.status.success(), "exav --help failed");
    let help = String::from_utf8_lossy(&out.stdout);
    let mut found = BTreeSet::new();
    for line in help.lines() {
        // The flag list is indented; prose mentions are not at line start.
        let t = line.trim_start();
        if line.len() == t.len() {
            continue;
        }
        for tok in t.split_whitespace().take(3) {
            if let Some(name) = tok.strip_prefix("--") {
                let name: String = name
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                    .collect();
                if !name.is_empty() {
                    found.insert(name);
                }
            }
        }
    }
    assert!(
        found.len() > 40,
        "parsed only {} flags from --help; the parser is broken, and a broken \
         parser passes this test by comparing nothing",
        found.len()
    );
    found
}

/// Every `--flag` mentioned anywhere in a docs file.
fn flags_in(path: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut found = BTreeSet::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == '-' && bytes[i + 1] == '-' && bytes[i + 2].is_ascii_lowercase() {
            let mut j = i + 2;
            let mut name = String::new();
            while j < bytes.len()
                && (bytes[j].is_ascii_lowercase() || bytes[j].is_ascii_digit() || bytes[j] == '-')
            {
                name.push(bytes[j]);
                j += 1;
            }
            let name = name.trim_end_matches('-').to_string();
            if !name.is_empty() {
                found.insert(name);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    found
}

/// Every flag exav really has is written down somewhere a reader can find it.
#[test]
fn every_flag_is_documented() {
    let root = repo_root();
    let cli = root.join("www/src/content/docs/reference/cli.md");
    if !cli.exists() {
        eprintln!("skipping: {} is absent", cli.display());
        return;
    }
    let documented = flags_in(&cli);
    let undocumented: Vec<_> = flags_in_help()
        .into_iter()
        .filter(|f| f != "help" && f != "version")
        .filter(|f| !documented.contains(f))
        .collect();
    assert!(
        undocumented.is_empty(),
        "these flags exist but are in no table on the CLI reference page:\n  {}\n\n\
         A flag nobody can find is a flag nobody uses — add it to \
         www/src/content/docs/reference/cli.md.",
        undocumented.join("\n  ")
    );
}

/// Every `exav …` command the docs tell a reader to type uses flags that exist.
///
/// Scoped to command lines, not prose: the pages legitimately name `clamscan`'s
/// flags, cargo's, 7-Zip's and `exav-grep`'s, and a test that cannot tell those
/// from exav's own would either cry wolf or be silenced into uselessness. What
/// a reader actually *types* is the part that can be wrong in a way that costs
/// them something.
#[test]
fn every_documented_exav_command_uses_real_flags() {
    let root = repo_root();
    let docs = root.join("www/src/content/docs");
    if !docs.exists() {
        eprintln!("skipping: {} is absent", docs.display());
        return;
    }
    let real = flags_in_help();

    let mut bad: Vec<String> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![docs.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if matches!(p.extension().and_then(|s| s.to_str()), Some("md" | "mdx")) {
                files.push(p);
            }
        }
    }
    files.push(root.join("README.md"));

    let mut commands = 0usize;
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // A command, not a sentence that opens with the binary's name.
            let Some(rest) = t.strip_prefix("exav ") else {
                continue;
            };
            if !rest.starts_with('-') && !rest.contains(" -") {
                continue;
            }
            // Some examples exist to show a command being REFUSED — the
            // migration guide demonstrates the error a renamed flag produces.
            // The refusal quoted underneath is the marker: it is what the reader
            // is being shown, so a command followed by one is meant to fail.
            let deliberate = lines
                .get(i + 1)
                .map(|n| {
                    let n = n.trim();
                    n.starts_with("# exav:") || n.starts_with("# error:")
                })
                .unwrap_or(false);
            if deliberate {
                continue;
            }
            commands += 1;
            for tok in rest.split_whitespace() {
                let Some(name) = tok.strip_prefix("--") else {
                    continue;
                };
                let name: String = name
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                    .collect();
                if name.is_empty() || real.contains(&name) {
                    continue;
                }
                bad.push(format!(
                    "{}: --{name}   in `{}`",
                    path.strip_prefix(&root).unwrap_or(&path).display(),
                    t.chars().take(70).collect::<String>()
                ));
            }
        }
    }
    assert!(
        commands > 20,
        "only {commands} exav command lines found in the docs; the scan is broken"
    );
    bad.sort();
    bad.dedup();
    assert!(
        bad.is_empty(),
        "the docs tell a reader to run a flag exav does not have:\n  {}\n\n\
         Either it was renamed and the page was not, or the page invented it. \
         Either way the reader gets exit 2.",
        bad.join("\n  ")
    );
}

/// The environment-variable spelling the CLI reference promises is the one the
/// binary reads: uppercase, dashes to underscores, `EXAV_` in front.
///
/// A variable that does not follow it is unreachable in practice — nobody looks
/// it up, they derive it from the flag.
#[test]
fn env_var_names_follow_the_documented_rule() {
    let out = Command::new(env!("CARGO_BIN_EXE_exav"))
        .arg("--help")
        .output()
        .expect("run exav --help");
    let help = String::from_utf8_lossy(&out.stdout);

    let mut current: Option<String> = None;
    let mut checked = 0usize;
    let mut wrong: Vec<String> = Vec::new();
    for line in help.lines() {
        let t = line.trim_start();
        if line.len() != t.len() {
            if let Some(rest) = t
                .split_whitespace()
                .next()
                .and_then(|s| s.strip_prefix("--"))
            {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                    .collect();
                if !name.is_empty() {
                    current = Some(name);
                }
            }
        }
        if let Some(rest) = t.strip_prefix("[env: ") {
            let got: String = rest
                .chars()
                .take_while(|c| *c != '=' && *c != ']')
                .collect();
            if let Some(flag) = current.take() {
                let want = format!("EXAV_{}", flag.to_uppercase().replace('-', "_"));
                checked += 1;
                if got != want {
                    wrong.push(format!("--{flag}: reads {got}, the rule says {want}"));
                }
            }
        }
    }
    assert!(
        checked > 40,
        "only {checked} flag/variable pairs parsed; the parser is broken"
    );
    assert!(
        wrong.is_empty(),
        "these variables do not match the rule the CLI reference states:\n  {}",
        wrong.join("\n  ")
    );
}
