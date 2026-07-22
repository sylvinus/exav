//! Real-world YARA rule coverage harness.
//!
//! Walks every `.yar`/`.yara` file under a given directory, feeds each file's
//! source to a fresh [`exav_core::yara::Compiler::add_source_lenient`], and tallies:
//!
//!   * total rules declared,
//!   * rules that compiled clean,
//!   * rules rejected — grouped into NORMALIZED buckets (per-module, per-pe
//!     field, floatN reads, wide-on-regexp, bare regex, include, …),
//!   * files that failed to PARSE entirely (counted separately).
//!
//! It only COMPILES the rules to measure which constructs block them; nothing
//! is scanned or redistributed. One bad file never aborts the run.
//!
//! Run with:
//!   cargo run -p exav-core --features yara --example yara_coverage -- <dir> [--modules]
//!
//! `--modules` additionally prints the imported-module tally.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut dir: Option<PathBuf> = None;
    let mut show_modules = false;
    for a in args.by_ref() {
        match a.as_str() {
            "--modules" => show_modules = true,
            _ => dir = Some(PathBuf::from(a)),
        }
    }
    let dir = dir.unwrap_or_else(|| {
        eprintln!("usage: coverage <dir> [--modules]");
        std::process::exit(2);
    });

    let mut files = Vec::new();
    collect(&dir, &mut files);
    files.sort();

    // Tallies.
    let mut total_rules_declared = 0usize;
    let mut clean_rules = 0usize;
    let mut rejected_rules = 0usize;
    let mut buckets: BTreeMap<String, usize> = BTreeMap::new();
    let mut import_counts: BTreeMap<String, usize> = BTreeMap::new(); // module -> files importing
    let mut parse_failed_files = 0usize;
    let mut parse_failed_rules = 0usize;
    let mut files_seen = 0usize;
    let mut ext_idents: BTreeMap<String, usize> = BTreeMap::new();

    for path in &files {
        files_seen += 1;
        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let declared = count_declared_rules(&src);

        // Track imports (best-effort textual scan; independent of compile).
        for m in scan_imports(&src) {
            *import_counts.entry(m).or_default() += 1;
        }

        let mut compiler = exav_core::yara::Compiler::new();
        let rejected = compiler.add_source_lenient(&src);

        // Whole-file parse error: empty name means no rules could be recovered.
        if rejected.iter().any(|(name, _)| name.is_empty()) {
            parse_failed_files += 1;
            parse_failed_rules += declared;
            total_rules_declared += declared;
            *buckets
                .entry("PARSE ERROR (whole file)".to_string())
                .or_default() += declared;
            continue;
        }

        let compiled = compiler.build();
        let clean = compiled.len();
        clean_rules += clean;

        let mut rule_rejects = 0usize;
        for (name, err) in &rejected {
            // import/include rejections are not rules; bucket them but do not
            // count them against the rule totals.
            if name.starts_with("import ") {
                let module = name.trim_start_matches("import ").trim();
                *buckets.entry(format!("module: {module}")).or_default() += 1;
                continue;
            }
            if name == "include" {
                *buckets.entry("include".to_string()).or_default() += 1;
                continue;
            }
            // A real rule rejection.
            rule_rejects += 1;
            let bucket = normalize(err.message());
            if bucket == "external variable / unknown identifier" {
                if let Some(id) = extract_ident(err.message()) {
                    *ext_idents.entry(id).or_default() += 1;
                }
            }
            *buckets.entry(bucket).or_default() += 1;
        }
        rejected_rules += rule_rejects;

        // total declared for this file = clean + rejected rules. Prefer the
        // authoritative sum over the regex count (they should agree closely).
        total_rules_declared += clean + rule_rejects;
        let _ = declared;
    }

    // ---- Report ---------------------------------------------------------
    println!("=== YARA coverage over {} ===", dir.display());
    println!("files scanned:        {files_seen}");
    println!("parse-failed files:   {parse_failed_files} ({parse_failed_rules} rules lost)");
    println!("total rules declared: {total_rules_declared}");
    let pct = |n: usize| {
        if total_rules_declared == 0 {
            0.0
        } else {
            100.0 * n as f64 / total_rules_declared as f64
        }
    };
    println!(
        "rules compiled clean: {clean_rules} ({:.1}%)",
        pct(clean_rules)
    );
    println!(
        "rules rejected:       {rejected_rules} ({:.1}%)",
        pct(rejected_rules)
    );
    println!();

    // Ranked rejection table. Note: import/include buckets count occurrences,
    // not rules — but per-module rejection blocks every rule after the import
    // in that file, so it is the effective coverage lever. We report the
    // bucket rule-blocking counts as tallied.
    println!("--- Ranked rejection buckets (rules blocked) ---");
    let mut ranked: Vec<(&String, &usize)> = buckets.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    println!("{:>7}  {:>6}  bucket", "count", "%all");
    for (bucket, count) in &ranked {
        println!("{:>7}  {:>5.1}%  {}", count, pct(**count), bucket);
    }
    println!();

    if !ext_idents.is_empty() {
        println!("--- External-variable / unknown identifiers (rules blocked) ---");
        let mut ids: Vec<(&String, &usize)> = ext_idents.iter().collect();
        ids.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (id, c) in ids {
            println!("{:>5}  {id}", c);
        }
        println!();
    }

    if show_modules {
        println!("--- Imported modules (by #files importing) ---");
        let supported = ["pe", "math", "hash", "string", "time"];
        let mut mods: Vec<(&String, &usize)> = import_counts.iter().collect();
        mods.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (m, c) in mods {
            let mark = if supported.contains(&m.as_str()) {
                "supported"
            } else {
                "UNSUPPORTED"
            };
            println!("{:>5}  {:<8}  {m}", c, mark);
        }
    }
}

/// Recursively collect `.yar`/`.yara` files.
fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext == "yar" || ext == "yara" {
                out.push(path);
            }
        }
    }
}

/// Best-effort count of `rule <name>` declarations in a source string.
/// Ignores occurrences inside strings/comments heuristically by requiring the
/// keyword at a line start (after optional `private`/`global`).
fn count_declared_rules(src: &str) -> usize {
    let mut n = 0;
    for line in src.lines() {
        let t = line.trim_start();
        let t = t
            .strip_prefix("private ")
            .or_else(|| t.strip_prefix("global "))
            .unwrap_or(t);
        let t = t
            .strip_prefix("private ")
            .or_else(|| t.strip_prefix("global "))
            .unwrap_or(t);
        if let Some(rest) = t.strip_prefix("rule ") {
            // next token must look like an identifier
            if rest
                .chars()
                .next()
                .map(|c| c.is_alphabetic() || c == '_')
                .unwrap_or(false)
            {
                n += 1;
            }
        }
    }
    n
}

/// Textual scan for `import "module"` lines.
fn scan_imports(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("import ") {
            let rest = rest.trim();
            let name = rest.trim_matches('"').trim();
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// Collapse a raw compile-error message into a normalized coverage bucket.
fn normalize(msg: &str) -> String {
    // Strip the `.unsupported()` prefix if present.
    let m = msg
        .strip_prefix("unsupported YARA construct: ")
        .unwrap_or(msg);

    if let Some(rest) = m.strip_prefix("module `") {
        let name = rest.split('`').next().unwrap_or(rest);
        return format!("module: {name}");
    }
    if m.starts_with("include") {
        return "include".to_string();
    }
    if m.contains("`wide` modifier on a regexp") {
        return "wide on regexp".to_string();
    }
    if m.contains("bare regular expression in condition") {
        return "bare regex in condition".to_string();
    }
    if let Some(rest) = m.strip_prefix("function call `") {
        let name = rest.trim_end_matches("()`").trim_end_matches('`');
        let name = name.trim_end_matches("()");
        if name.starts_with("float") {
            return "floatN read".to_string();
        }
        return format!("function call: {name}()");
    }
    if let Some(rest) = m.strip_prefix("unsupported pe field: ") {
        let top = top_ident(rest);
        return format!("pe.{top}");
    }
    if let Some(rest) = m.strip_prefix("unsupported pe function: ") {
        let name = rest.trim_end_matches("()");
        let top = top_ident(name);
        return format!("pe.{top}()");
    }
    if let Some(rest) = m.strip_prefix("unknown function ") {
        // form: `pe.foo()` or `math.bar()`
        let head = rest.split("()").next().unwrap_or(rest);
        return format!("unknown function {head}()");
    }
    if m.contains("(module or undefined rule)") {
        // These are almost always YARA *external variables* (filename,
        // filepath, extension, filetype, owner) supplied by the host, which
        // exav does not model. Collapse into one bucket.
        return "external variable / unknown identifier".to_string();
    }
    if m.contains("undefined pattern") {
        return "reference to undefined pattern".to_string();
    }
    if m.starts_with("invalid regexp") {
        return "invalid regexp".to_string();
    }
    if m.contains("not iterable") {
        return "non-iterable expression".to_string();
    }
    if m.contains("module field access") || m.contains("module expression") {
        return "unsupported module field/expr".to_string();
    }
    if m.contains("bare module reference") {
        return "bare module reference".to_string();
    }
    if m.contains("indexing a module") || m.contains("indexing a scalar") {
        return "unsupported indexing".to_string();
    }
    if m.contains("field access on a scalar") {
        return "field access on scalar".to_string();
    }
    if m.starts_with("parse error") {
        return "parse error (rule-local)".to_string();
    }
    // Fall back to a trimmed prefix so novel messages are still visible.
    let short: String = m.chars().take(48).collect();
    format!("other: {short}")
}

/// Pull the backticked identifier out of an `identifier `X` (…)` message.
fn extract_ident(msg: &str) -> Option<String> {
    let start = msg.find('`')? + 1;
    let end = msg[start..].find('`')? + start;
    Some(msg[start..end].to_string())
}

/// Take the leading identifier of a dotted/indexed path (`rich_signature.x` ->
/// `rich_signature`).
fn top_ident(s: &str) -> &str {
    let end = s
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    &s[..end]
}
