//! Signature text nested or chained as long as the file is.
//!
//! A database comes from a feed and is read with the stack of whatever thread
//! loads it. A signature that nests groups or chains operators deeper than the
//! parser expects must be refused or read, not recursed into until the stack
//! ends, which ends the process. Each database kind that has such a syntax is
//! loaded and scanned against here on a small stack with a signature as deep
//! as 200 KB of text makes it.

use exav_core::loader::Builder;
use exav_core::{ScanOptions, analyze};
use std::time::{Duration, Instant};

const STACK: usize = 512 * 1024;
const N: usize = 50_000;

/// Loads `text` as the database `name` and scans a few bytes with it, on a
/// thread with a [`STACK`] stack. What went wrong, if anything.
fn load_small(name: &'static str, text: String) -> Option<String> {
    let started = Instant::now();
    let r = std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            let mut loader = Builder::new();
            loader.add_named_bytes(name, text.as_bytes(), false);
            if let Ok(db) = loader.build() {
                let _ = analyze(
                    &db,
                    b"MZ\x90\x00 a short file with abc and 0123",
                    &ScanOptions::default(),
                );
            }
        })
        .unwrap()
        .join();
    match r {
        Err(_) => Some(format!("{name}: overflowed its stack or panicked")),
        Ok(()) if started.elapsed() > Duration::from_secs(30) => Some(format!(
            "{name}: took {:.1} s",
            started.elapsed().as_secs_f64()
        )),
        Ok(()) => None,
    }
}

fn assert_all(findings: Vec<Option<String>>) {
    let findings: Vec<String> = findings.into_iter().flatten().collect();
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}

/// The harness loads what it is given: a plain signature of each kind found
/// in the bytes it scans, so the cases below are read and not skipped.
#[test]
fn the_databases_here_are_loaded_and_matched() {
    let data = b"MZ\x90\x00 a short file with abc and 0123";
    for (name, text) in [
        ("t.ndb", "Canary.N:0:*:616263"),
        ("t.ldb", "Canary.L;Target:0;0&1;616263;30313233"),
    ] {
        let mut loader = Builder::new();
        loader.add_named_bytes(name, text.as_bytes(), false);
        let db = loader.build().unwrap();
        let report = analyze(&db, data, &ScanOptions::default());
        assert!(
            matches!(report.verdict, exav_core::Verdict::Infected { .. }),
            "{name}: {:?}",
            report.verdict
        );
    }
}

#[test]
fn body_signatures() {
    let a = "aabbcc";
    let cases: Vec<(&str, String)> = vec![
        (
            "parentheses",
            format!("T:0:*:{}{a}{}", "(".repeat(N), ")".repeat(N)),
        ),
        ("alternatives", format!("T:0:*:({})", vec![a; N].join("|"))),
        (
            "nested alternatives",
            format!("T:0:*:{}{a}{}", "(aa|".repeat(N), ")".repeat(N)),
        ),
        ("not", format!("T:0:*:{}({a}|dd)", "!".repeat(N))),
        ("jumps", format!("T:0:*:{}", "aa{1-2}".repeat(N))),
        ("stars", format!("T:0:*:{}", "aa*".repeat(N))),
        ("wildcards", format!("T:0:*:{}", "??".repeat(N))),
        ("nibbles", format!("T:0:*:{}", "a?".repeat(N))),
        ("anchored jumps", format!("T:0:*:{}", "aa[1-2]".repeat(N))),
        ("offsets", format!("T:0:{}EP+0:{a}", "EP+0,".repeat(N))),
        ("sections", format!("T:0:{}SE1:{a}", "SL+0,".repeat(N))),
        ("a long name", format!("{}:0:*:{a}", "T".repeat(N * 4))),
        (
            "many signatures",
            (0..N * 2)
                .map(|i| format!("T{i}:0:*:{a}{i:04x}\n"))
                .collect::<String>(),
        ),
    ];
    assert_all(
        cases
            .into_iter()
            .map(|(n, t)| load_small("t.ndb", t).map(|e| format!("{n}: {e}")))
            .collect(),
    );
}

#[test]
fn logical_signatures() {
    let sub = "6162;6364";
    let flat = |op: &str, n: usize| vec!["0"; n].join(op);
    let cases: Vec<(&str, String)> = vec![
        (
            "parentheses",
            format!(
                "T;Engine:51-255,Target:0;{}0{};{sub}",
                "(".repeat(N),
                ")".repeat(N)
            ),
        ),
        ("and chain", format!("T;Target:0;{};{sub}", flat("&", N))),
        ("or chain", format!("T;Target:0;{};{sub}", flat("|", N))),
        (
            "mixed chain",
            format!("T;Target:0;{};{sub}", vec!["0&1|"; N].concat() + "0"),
        ),
        ("negation", format!("T;Target:0;{}0;{sub}", "!".repeat(N))),
        (
            "counts",
            format!("T;Target:0;{}0>1;{sub}", "(".repeat(N / 100)),
        ),
        (
            "many subsignatures",
            format!("T;Target:0;0;{}", vec!["6162"; N].join(";")),
        ),
        ("a high index", format!("T;Target:0;{};{sub}", N * 1000)),
        (
            "fuzzy-hash chain",
            format!(
                "T;Target:0;0;{}",
                "fuzzy_img#00000000000000000#0;".repeat(N / 100)
            ),
        ),
        (
            "pcre groups",
            format!("T;Target:0;0;0/{}a{}/", "(".repeat(N), ")".repeat(N)),
        ),
        (
            "pcre alternations",
            format!("T;Target:0;0;0/{}/", "a|".repeat(N)),
        ),
        (
            "pcre quantifiers",
            format!("T;Target:0;0;0/{}/", "a*".repeat(N)),
        ),
        (
            "pcre classes",
            format!("T;Target:0;0;0/{}/", "[a-z]".repeat(N)),
        ),
        (
            "pcre lookaheads",
            format!("T;Target:0;0;0/{}a{}/", "(?=".repeat(N), ")".repeat(N)),
        ),
        (
            "pcre backrefs",
            format!("T;Target:0;0;0/(a){}/", "\\1".repeat(N)),
        ),
        ("pcre flags", format!("T;Target:0;0;0/a/{}", "i".repeat(N))),
        (
            "macros",
            format!("T;Target:0;0;6162${{1-2}}{}$", "1$".repeat(N)),
        ),
    ];
    assert_all(
        cases
            .into_iter()
            .map(|(n, t)| load_small("t.ldb", t).map(|e| format!("{n}: {e}")))
            .collect(),
    );
}

#[test]
fn phishing_and_regex_databases() {
    let cases: Vec<(&'static str, &str, String)> = vec![
        (
            "pdb groups",
            "t.pdb",
            format!("R:.+{}a{}:.+", "(".repeat(N), ")".repeat(N)),
        ),
        (
            "pdb alternations",
            "t.pdb",
            format!("R:.+({}):.+", "a|".repeat(N)),
        ),
        (
            "pdb many",
            "t.pdb",
            (0..N).map(|i| format!("R:.+x{i}.com:.+\n")).collect(),
        ),
        (
            "wdb groups",
            "t.wdb",
            format!("X:.+{}a{}:.+", "(".repeat(N), ")".repeat(N)),
        ),
        (
            "wdb mixed",
            "t.wdb",
            format!("M:{}:{}", "(a|".repeat(N), ")".repeat(N)),
        ),
        ("gdb", "t.gdb", format!("H:{}", "a.".repeat(N))),
        ("crb", "t.crb", format!("T;{}", "(".repeat(N))),
        (
            "ftm",
            "t.ftm",
            format!("0:0:{}:Name:CL_TYPE_X:CL_TYPE_ANY", "(".repeat(N)),
        ),
        (
            "cdb",
            "t.cdb",
            format!("N:CL_TYPE_ANY:{}:*:*:*:*:*:*", "9".repeat(N)),
        ),
        (
            "idb",
            "t.idb",
            format!("IconName:GroupName:{}", "0".repeat(N * 4)),
        ),
        ("hdb", "t.hdb", format!("{}:1:N", "a".repeat(N * 4))),
        ("hsb", "t.hsb", format!("{}:1:N:73", "a".repeat(N * 4))),
        ("fp", "t.fp", format!("{}:1:N", "b".repeat(N * 4))),
        ("mdb", "t.mdb", format!("1:{}:N", "c".repeat(N * 4))),
        ("cfg", "t.cfg", "(".repeat(N * 4)),
        ("ign", "t.ign2", "N:".repeat(N)),
        (
            "pwdb",
            "t.pwdb",
            format!("T;Engine:81-255;0;{}", "x".repeat(N * 4)),
        ),
    ];
    assert_all(
        cases
            .into_iter()
            .map(|(n, file, t)| load_small(file, t).map(|e| format!("{n}: {e}")))
            .collect(),
    );
}

#[test]
fn yara_sources() {
    use exav_core::yara::Compiler;
    let rule = |def: &str, cond: &str| {
        format!("import \"pe\"\nrule r {{ strings: $a = \"x\" $b = {def} condition: {cond} }}")
    };
    let sources: Vec<(&str, String)> = vec![
        (
            "regex groups",
            rule(&format!("/{}a{}/", "(".repeat(N), ")".repeat(N)), "$b"),
        ),
        (
            "regex alternations",
            rule(&format!("/{}/", "a|".repeat(N)), "$b"),
        ),
        (
            "regex repeats",
            rule(&format!("/{}/", "a{1,2}".repeat(N)), "$b"),
        ),
        (
            "hex groups",
            rule(
                &format!("{{ {}41{} }}", "( 41 | ".repeat(N), " )".repeat(N)),
                "$b",
            ),
        ),
        (
            "hex jumps",
            rule(&format!("{{ 41 {} 42 }}", "[1-2] 41 ".repeat(N)), "$b"),
        ),
        (
            "hex alternatives",
            rule(&format!("{{ ( {} ) }}", vec!["41"; N].join(" | ")), "$b"),
        ),
        (
            "condition groups",
            rule("\"y\"", &format!("{}true{}", "(".repeat(N), ")".repeat(N))),
        ),
        (
            "for loops",
            rule(
                "\"y\"",
                &format!("{}true", "for any i in (1..2) : ( ".repeat(N)),
            ),
        ),
        (
            "with",
            rule("\"y\"", &format!("{}true", "with a = 1 : ( ".repeat(N))),
        ),
        (
            "of sets",
            rule(
                "\"y\"",
                &format!("any of ({})", vec!["$a"; N * 2].join(",")),
            ),
        ),
        (
            "many rules",
            (0..N)
                .map(|i| format!("rule r{i} {{ condition: true }}\n"))
                .collect(),
        ),
        (
            "rule chain",
            (0..N)
                .map(|i| format!("rule r{i} {{ condition: r{} }}\n", i.saturating_sub(1)))
                .collect::<String>()
                + "rule r0 { condition: true }",
        ),
        ("imports", "import \"pe\"\n".repeat(N)),
        (
            "tags",
            format!("rule r : {} {{ condition: true }}", vec!["t"; N].join(" ")),
        ),
        (
            "meta",
            format!("rule r {{ meta: {} condition: true }}", "a = 1 ".repeat(N)),
        ),
    ];
    let findings: Vec<Option<String>> = sources
        .into_iter()
        .map(|(name, src)| {
            let started = Instant::now();
            let r = std::thread::Builder::new()
                .stack_size(STACK)
                .spawn(move || {
                    let mut c = Compiler::new();
                    let rejected = c.add_source_lenient(&src);
                    if rejected.is_empty() {
                        let rules = c.build();
                        let _ = exav_core::yara::Scanner::new(&rules).scan(b"xxxx");
                    }
                })
                .unwrap()
                .join();
            match r {
                Err(_) => Some(format!("yara {name}: overflowed its stack or panicked")),
                Ok(()) if started.elapsed() > Duration::from_secs(30) => Some(format!(
                    "yara {name}: took {:.1} s",
                    started.elapsed().as_secs_f64()
                )),
                Ok(()) => None,
            }
        })
        .collect();
    assert_all(findings);
}

/// A stored ZIP of one member, `data`.
#[cfg(feature = "all-formats")]
fn stored_zip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let o =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    z.start_file("a.bin", o).unwrap();
    z.write_all(data).unwrap();
    z.finish().unwrap().into_inner()
}

/// The payload, deflated so that the raw scan of the outer layers cannot see
/// it: it is found only by walking every layer.
#[cfg(feature = "all-formats")]
fn deflated_eicar() -> Vec<u8> {
    use std::io::Write;
    let mut data = exav_core::unpack::eicar().to_vec();
    data.extend(std::iter::repeat_n(b'A', 8192));
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&data).unwrap();
    e.finish().unwrap()
}

/// Containers nested to the depth the user allows (`--max-unpack-depth` takes
/// up to 255) are walked to the payload on a 1 MiB stack. At the test profile's
/// opt-level this holds without the frame fixes in the ZIP and XZ walkers; the
/// frames of a release build are what `scripts/stack-frames.py` audits.
#[cfg(feature = "all-formats")]
#[test]
fn zips_in_zips_to_the_allowed_depth_are_walked_on_a_small_stack() {
    let mut layers = deflated_eicar();
    for _ in 0..60 {
        layers = stored_zip(&layers);
    }
    let found = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let db = exav_core::Scanner::builtin();
            let mut opts = ScanOptions::default();
            opts.limits.max_recursion = 255;
            matches!(
                analyze(&db, &layers, &opts).verdict,
                exav_core::Verdict::Infected { .. }
            )
        })
        .unwrap()
        .join()
        .expect("no stack overflow");
    assert!(found, "the payload at the bottom is found");
}

/// Script, markup and text with nesting as deep as 400 KB of it makes it, scanned
/// with every content analysis on, on a small stack: the normalizers, the
/// phishing reader, the structured-data counters.
#[test]
fn script_and_markup_nested_as_deep_as_the_file_is_long() {
    let n = 100_000;
    let rep = |s: &str| s.repeat(n);
    let html = |inner: String| format!("<html><body>{inner}</body></html>");
    let script = |inner: String| format!("<html><script>{inner}</script></html>");
    let cases: Vec<(&str, String)> = vec![
        (
            "js parentheses",
            script(format!("{}1{}", rep("("), rep(")"))),
        ),
        ("js brackets", script(format!("{}1{}", rep("["), rep("]")))),
        ("js braces", script(format!("{}1{}", rep("{"), rep("}")))),
        (
            "js functions",
            script(format!("{}1{}", rep("function f(){"), rep("}"))),
        ),
        ("js ternaries", script(format!("x={}1", rep("a?b:")))),
        ("js signs", script(format!("x={}1", rep("-")))),
        ("js negations", script(format!("x={}1", rep("!")))),
        (
            "js concatenations",
            script(format!("x=\"a\"{}", rep("+\"b\""))),
        ),
        ("js eval", script(format!("{}1{}", rep("eval("), rep(")")))),
        (
            "js unescape",
            script(format!("{}\"%41\"{}", rep("unescape("), rep(")"))),
        ),
        (
            "js atob",
            script(format!("{}\"QQ==\"{}", rep("atob("), rep(")"))),
        ),
        (
            "js from char code",
            script(format!("{}65{}", rep("String.fromCharCode("), rep(")"))),
        ),
        ("js arrays of arrays", script(format!("x={}", rep("[1,")))),
        (
            "js objects",
            script(format!("x={}1{}", rep("{a:"), rep("}"))),
        ),
        ("js ifs", script(format!("{}x=1", rep("if(a)")))),
        ("js comments", script(rep("/*"))),
        ("js template strings", script(format!("x={}", rep("`${")))),
        ("js regexes", script(format!("x={}", rep("/(/")))),
        (
            "js escapes",
            script(format!("x=\"{}\"", rep("\\x41\\u0042"))),
        ),
        ("html divs", html(rep("<div>"))),
        ("html tables", html(rep("<table><tr><td>"))),
        (
            "html anchors",
            html(rep("<a href=\"http://a.example.com\">http://b.example.com")),
        ),
        ("html comments", html(rep("<!--"))),
        ("html entities", html(rep("&amp;lt;"))),
        ("html attributes", html(rep("<a b=\"c\" "))),
        ("html scripts", html(rep("<script>"))),
        ("html iframes", html(rep("<iframe src=\"http://a\">"))),
        ("text digits", rep("4111 1111 1111 1111 ")),
        ("text ssns", rep("123-45-6789 ")),
        ("text base64", rep("QUJDREVGR0hJSktM")),
        ("text parentheses", rep("(")),
        ("text quotes", rep("\"")),
    ];
    let mut findings = vec![];
    for (name, data) in cases {
        let r = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || {
                let mut loader = Builder::new();
                loader.add_named_bytes("t.ndb", b"Canary.N:0:*:6162636465", false);
                loader.add_named_bytes("t.pdb", b"H:example.com", false);
                let db = loader.build().unwrap();
                let mut opts = ScanOptions::default();
                opts.heuristics = true;
                opts.clamav_heuristics = true;
                opts.alert_phishing = true;
                opts.structured_cc_count = Some(1);
                opts.structured_ssn_count = Some(1);
                opts.alert_macros = true;
                let _ = analyze(&db, data.as_bytes(), &opts);
            })
            .unwrap()
            .join();
        if r.is_err() {
            findings.push(Some(format!("{name}: overflowed its stack or panicked")));
        }
    }
    assert_all(findings);
}
