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

/// Every `--flag` mentioned in one string. A trailing dash is dropped, so
/// `--max-` (how the prose names a family) yields `max`, not a flag.
fn flags_in_str(text: &str) -> BTreeSet<String> {
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

/// Every `--flag` mentioned anywhere in a docs file.
fn flags_in(path: &Path) -> BTreeSet<String> {
    flags_in_str(&std::fs::read_to_string(path).unwrap_or_default())
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

/// Every exav flag `--help` names in its own prose is a flag exav has.
///
/// The help text is where a rename goes stale invisibly: `--clamav-compat`
/// listed the flags it presets and kept naming one by its old spelling long
/// after the rename, and `--passwords` documented itself as `--password`. Both
/// read as instructions and both are refused when typed. `--help` is the one
/// reference nobody thinks to re-check, because it lives in the same file as the
/// flag it describes and looks like it must have been updated with it.
///
/// Only `--flag` tokens are considered, and only against exav's own set: the
/// help legitimately names `clamscan`'s (`[clamscan: --structured-cc-count]`),
/// `clamd.conf`'s and `c-icap.conf`'s settings, which are marked as such.
#[test]
fn the_help_text_only_names_flags_exav_has() {
    // Flags the help names on purpose that exav does not have. Each is either
    // another tool's, or a spelling being explained precisely because it is not
    // the one exav uses — the sentences would be wrong without them. Kept
    // explicit and short so adding one is a decision rather than a habit.
    const NOT_EXAVS: &[(&str, &str)] = &[
        ("features", "cargo's, in `--features http-update`"),
        ("alert-encrypted", "ClamAV's, named as ClamAV's"),
        ("alert-exceeds-max", "ClamAV's, named as ClamAV's"),
        (
            "max-depth",
            "what find/du/tree call directory depth, cited to explain the rename",
        ),
    ];

    let real = flags_in_help();
    let out = Command::new(env!("CARGO_BIN_EXE_exav"))
        .arg("--help")
        .output()
        .expect("run exav --help");
    let help = String::from_utf8_lossy(&out.stdout);

    let mut bad: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for line in help.lines() {
        // A flag's own definition line is where the truth is; the prose under it
        // is what goes stale. Both are indented, so tell them apart by the line
        // starting with the flag rather than mentioning one.
        let t = line.trim_start();
        if t.starts_with('-') {
            continue;
        }
        // A bracketed foreign reference names another tool's setting on purpose.
        if t.contains("[clamscan:") || t.contains("[clamd") || t.contains("[c-icap") {
            continue;
        }
        for tok in t.split_whitespace() {
            let tok = tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
            let Some(name) = tok.strip_prefix("--") else {
                continue;
            };
            let name: String = name
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect();
            // A trailing dash means a family, not a flag: `--max-` and `--icap-`
            // are how the prose refers to a group of them.
            if name.is_empty() || name.ends_with('-') {
                continue;
            }
            if NOT_EXAVS.iter().any(|(f, _)| *f == name) {
                continue;
            }
            checked += 1;
            if !real.contains(&name) {
                bad.push(format!(
                    "--{name}   in: {}",
                    t.chars().take(72).collect::<String>()
                ));
            }
        }
    }
    assert!(
        checked > 50,
        "only {checked} flag mentions found in the help prose; the scan is broken"
    );
    bad.sort();
    bad.dedup();
    assert!(
        bad.is_empty(),
        "the help text tells a reader to use a flag exav does not have:\n  {}\n\n\
         A rename has to reach the prose describing it, not only the flag itself.",
        bad.join("\n  ")
    );
}

/// Every exav flag named in a message the binary can print is a flag exav has.
///
/// `--help` is not the only place a flag name is written down. A runtime warning
/// told operators to "set a smaller `--max-memory`", a flag that has never
/// existed — and it fires on any host where the per-job budget exceeds RAM, so
/// it is one of the messages people see most. Advice naming a flag that does not
/// parse is worse than no advice: it reads as authoritative and costs a retry to
/// disprove.
///
/// Scans the source rather than the binary because these strings are only
/// reachable by provoking the condition, and there is no run in which all of
/// them are printed.
#[test]
fn every_flag_named_in_a_message_exists() {
    // Mentions that are not exav flags: another tool's, or a spelling discussed
    // precisely because exav does not use it. Short and explicit — each entry is
    // a decision, and the list not growing is the point.
    const NOT_EXAVS: &[&str] = &[
        // clamscan's, named in the flag-mapping hints and the matrix references.
        "recursive",
        "infected",
        "no-summary",
        "remove",
        "move",
        "copy",
        "max-filesize",
        "max-scansize",
        "max-recursion",
        "max-files",
        "suppress-ok-results",
        "allmatch",
        "file-list",
        "datadir",
        "tempdir",
        "statistics",
        "max-scantime",
        "fdpass",
        "stream",
        "detect-pua",
        "alert-broken",
        "alert-broken-media",
        "alert-macros",
        "alert-phishing-ssl",
        "alert-phishing-cloak",
        "alert-partition-intersection",
        "alert-encrypted",
        "alert-exceeds-max",
        "structured-ssn-count",
        "structured-cc-count",
        // cargo's.
        "features",
        "no-default-features",
        "release",
        "ignore-rust-version",
        // Docker's, in the advice that a HEALTHCHECK owns its own retrying.
        "retries",
        // Spellings named to explain why they are not the ones exav uses.
        "max-depth",
        "password",
    ];

    let real = flags_in_help();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                files.push(p);
            }
        }
    }
    assert!(!files.is_empty(), "no sources found; the scan is broken");

    let mut bad: Vec<String> = Vec::new();
    let mut checked: BTreeSet<String> = BTreeSet::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        // Tests enumerate the whole `clamscan` surface on purpose, and every one
        // of those is a flag exav does not have. Nothing below the test module
        // is a message anyone is shown. Matched on the module rather than on
        // `#[cfg(test)]` alone, which also sits on test-only helpers partway up
        // a file and would cut away everything under them.
        let code = match text.find("#[cfg(test)]\nmod tests") {
            Some(i) => &text[..i],
            None => &text[..],
        };
        // Comments are dropped and the rest is scanned whole. A doc comment
        // becomes the help text, which `the_help_text_only_names_flags_exav_has`
        // reads from the binary itself, and an ordinary comment is shown to
        // nobody; what is left is string literals, which is what gets printed.
        // Whole rather than line by line because any message long enough to
        // matter is a `\`-continued literal spanning several lines.
        let printed: String = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for name in flags_in_str(&printed) {
            if NOT_EXAVS.contains(&name.as_str()) {
                continue;
            }
            checked.insert(name.clone());
            if !real.contains(&name) {
                bad.push(format!(
                    "{}: --{name}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ));
            }
        }
    }
    // Named messages rather than a count: a threshold passes as soon as the
    // scan finds anything, and what matters is that it reaches the places a flag
    // name is actually printed — a refusal, a fallback warning, a missing-input
    // error. If one of these stops being mentioned, this test has stopped
    // reading the file it was written for.
    for expect in ["connect", "listen", "workers", "spill-dir"] {
        assert!(
            checked.contains(expect),
            "--{expect} is named in a message, and the scan did not see it; it is \
             reading the wrong thing. Found: {checked:?}"
        );
    }
    bad.sort();
    bad.dedup();
    assert!(
        bad.is_empty(),
        "these name a flag exav does not have:\n  {}\n\n\
         A message telling someone to pass a flag that will not parse is worse \
         than saying nothing.",
        bad.join("\n  ")
    );
}

/// Every `clamscan` flag the matrix marks **renamed** gets an error naming what
/// exav calls it.
///
/// `renamed` is the row where exav does the job under another spelling, so the
/// person typing it has a working command line and one lookup between them and
/// a working exav one. `clap` answers an unknown flag with `unexpected
/// argument`, which does not say a rename happened, let alone which. The
/// migration guide promises the error names the exav flag; this is what makes
/// that true for the whole column rather than the few flags someone got to.
#[test]
fn docs_name_the_exav_flag_for_every_renamed_clamscan_flag() {
    let matrix = repo_root().join("www/src/content/docs/reference/clamav-flag-matrix.md");
    if !matrix.exists() {
        eprintln!("skipping: {} is absent", matrix.display());
        return;
    }
    let text = std::fs::read_to_string(&matrix).expect("read the flag matrix");

    let mut renamed: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        if !line.trim_start().starts_with('|') {
            continue;
        }
        // A cell may carry an escaped pipe (`<N\|threads>`), which is not a
        // column break.
        let cells: Vec<&str> = line.split('|').collect();
        // | flag | meaning | exav | status | notes |  -> leading empty cell.
        if cells.len() < 5 || cells[4].trim() != "renamed" {
            continue;
        }
        // Every backticked spelling in the first column, long and short alike.
        for tok in cells[1].split('`').skip(1).step_by(2) {
            let name = tok
                .split(['=', '['])
                .next()
                .unwrap_or(tok)
                .trim()
                .to_string();
            if name.starts_with('-') {
                renamed.insert(name);
            }
        }
    }
    assert!(
        renamed.len() > 15,
        "parsed only {} renamed flags from the matrix; the parser is broken, and \
         a broken parser passes this test by checking nothing",
        renamed.len()
    );

    let mut silent: Vec<String> = Vec::new();
    for flag in &renamed {
        let out = Command::new(env!("CARGO_BIN_EXE_exav"))
            .arg(flag)
            .arg("/dev/null")
            .output()
            .expect("run exav");
        let said = String::from_utf8_lossy(&out.stderr);
        if !said.contains("is a clamscan flag") {
            silent.push(format!(
                "{flag}: {}",
                said.lines().next().unwrap_or("(no output)")
            ));
        }
    }
    assert!(
        silent.is_empty(),
        "the matrix calls these renamed, but exav does not say so when one is \
         used:\n  {}\n\nAdd them to `clamscan_flag_hint` in crates/exav/src/main.rs.",
        silent.join("\n  ")
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
