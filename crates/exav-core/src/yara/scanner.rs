//! Scanning: running compiled [`Rules`] over a data buffer.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::yara::atoms::PatternGate;
use crate::yara::compiler::ExternalValue;
use crate::yara::error::{Error, Result};
use crate::yara::ir::{Cond, EvalCtx, Value};
use crate::yara::matcher::{Match, PatternDef, PatternMatcher};
use crate::yara::modules::{ModuleCtx, ModuleKind};

/// A compiled rule (internal representation).
#[derive(Serialize, Deserialize)]
pub(crate) struct CompiledRule {
    pub name: String,
    pub private: bool,
    pub global: bool,
    pub pattern_ids: Vec<usize>,
    pub meta: Vec<(String, String)>,
    pub cond: Cond,
}

/// A compiled set of YARA rules, ready to scan. `'static` — owns everything.
pub struct Rules {
    pub(crate) patterns: Vec<PatternMatcher>,
    /// The serializable definition of each pattern (index == pattern id), kept
    /// in lockstep with `patterns`. Not used at scan time; carried so the rule
    /// set can be re-serialized (the compiled `patterns` are recompiled from
    /// these on load — see [`Rules::serialize`]/[`Rules::deserialize`]).
    pub(crate) defs: Vec<PatternDef>,
    pub(crate) pattern_names: Vec<String>,
    pub(crate) rules: Vec<CompiledRule>,
    /// Modules imported by this rule set (their values are built per scan).
    pub(crate) imported: Vec<ModuleKind>,
    /// Whether any rule uses the `entrypoint` keyword.
    pub(crate) uses_entrypoint: bool,
    /// Required-literal Aho-Corasick prefilter: which patterns even need to be
    /// scanned for a given buffer (see [`crate::yara::atoms`]).
    pub(crate) gate: PatternGate,
}

/// The serialized form of a compiled [`Rules`] set. Everything here is cheap to
/// (de)serialize; the expensive-to-rebuild atom automaton is inside `gate`
/// (serialized as daachorse's own byte form), and the per-pattern regexes are
/// recompiled from `defs` on load. Serialized with borrowed fields, deserialized
/// into the owned twin [`RulesBlobOwned`].
#[derive(Serialize)]
struct RulesBlobRef<'a> {
    defs: &'a [PatternDef],
    pattern_names: &'a [String],
    rules: &'a [CompiledRule],
    imported: &'a [ModuleKind],
    uses_entrypoint: bool,
    gate: &'a PatternGate,
}

#[derive(Deserialize)]
struct RulesBlobOwned {
    defs: Vec<PatternDef>,
    pattern_names: Vec<String>,
    rules: Vec<CompiledRule>,
    imported: Vec<ModuleKind>,
    uses_entrypoint: bool,
    gate: PatternGate,
}

impl Rules {
    /// Serializes the compiled rule set to MessagePack bytes for embedding in the
    /// on-disk database. The atom automaton travels in its compiled (daachorse)
    /// form; only the per-pattern regex SOURCES travel, not the compiled regex
    /// automata. See [`Rules::deserialize`] for the reverse.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let blob = RulesBlobRef {
            defs: &self.defs,
            pattern_names: &self.pattern_names,
            rules: &self.rules,
            imported: &self.imported,
            uses_entrypoint: self.uses_entrypoint,
            gate: &self.gate,
        };
        // Infallible for this data (no maps with non-string keys, no unsupported
        // types); `rmp_serde` only errors on serializer I/O, and Vec never fails.
        rmp_serde::to_vec(&blob).expect("serialize compiled YARA rules")
    }

    /// Reconstructs a compiled rule set from [`Rules::serialize`] bytes. The
    /// daachorse atom automaton is deserialized (NOT rebuilt); the IR and rule
    /// structs are deserialized; and each pattern's `PatternMatcher` is
    /// recompiled from its stored [`PatternDef`]. This skips the aggregate build
    /// cost (source parse, AST->IR lowering, atom extraction, and the daachorse
    /// automaton build), paying only per-pattern regex compilation.
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Rules> {
        let blob: RulesBlobOwned = rmp_serde::from_slice(bytes)
            .map_err(|e| Error::new(format!("invalid serialized YARA rules: {e}")))?;
        let mut patterns = Vec::with_capacity(blob.defs.len());
        for def in &blob.defs {
            patterns.push(def.compile()?);
        }
        Ok(Rules {
            patterns,
            defs: blob.defs,
            pattern_names: blob.pattern_names,
            rules: blob.rules,
            imported: blob.imported,
            uses_entrypoint: blob.uses_entrypoint,
            gate: blob.gate,
        })
    }

    /// Number of rules (including private/global ones).
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Scans `data`, returning the results. Convenience wrapper around
    /// [`Scanner`].
    pub fn scan<'r, 'd>(&'r self, data: &'d [u8]) -> ScanResults<'r, 'd> {
        Scanner::new(self).scan_inner(data)
    }
}

/// Scans data against a set of [`Rules`]. Mirrors yara-x's `Scanner` shape so a
/// differential harness can use either interchangeably.
pub struct Scanner<'r> {
    rules: &'r Rules,
    /// Host-supplied external variable values applied to every scan until
    /// changed (see [`Scanner::set_global`]).
    externals: HashMap<String, Value>,
}

impl<'r> Scanner<'r> {
    pub fn new(rules: &'r Rules) -> Self {
        Self {
            rules,
            externals: HashMap::new(),
        }
    }

    /// Sets the value of an external variable for subsequent scans (mirrors
    /// yara-x's `Scanner::set_global`). The external does not need to have been
    /// declared for this to succeed; an undeclared external simply is never
    /// referenced by any compiled rule. The value is retained across scans until
    /// set again.
    pub fn set_global(&mut self, name: &str, value: impl Into<ExternalValue>) -> &mut Self {
        self.externals
            .insert(name.to_string(), value.into().into_value());
        self
    }

    /// Scans `data`. Never fails in Phase A (kept `Result` for API parity with
    /// yara-x).
    pub fn scan<'d>(&mut self, data: &'d [u8]) -> Result<ScanResults<'r, 'd>> {
        Ok(self.scan_inner(data))
    }

    fn scan_inner<'d>(&self, data: &'d [u8]) -> ScanResults<'r, 'd> {
        let rules = self.rules;

        // 1. Find matches for every pattern. The atom prefilter first tells us
        //    which patterns can possibly match this buffer; the rest are known to
        //    have zero matches (a required literal is absent), so we skip their
        //    O(n) scan and hand them an empty match list — an identical result.
        let run = rules.gate.select(data);
        let matches: Vec<Vec<Match>> = rules
            .patterns
            .iter()
            .enumerate()
            .map(|(i, p)| if run[i] { p.find_all(data) } else { Vec::new() })
            .collect();

        // 2. Build the per-scan module state (parse PE, etc.) once.
        let modules = if rules.imported.is_empty() && !rules.uses_entrypoint {
            ModuleCtx::empty()
        } else {
            ModuleCtx::build(data, &rules.imported, rules.uses_entrypoint)
        };

        // 3. Evaluate rule conditions in order. Rule references only ever point
        //    at earlier rules, so passing the results filled so far is enough.
        //    The step budget is shared by every rule in the scan, so the total
        //    condition work one buffer can cost is bounded no matter how the
        //    ruleset is shaped.
        let steps = std::cell::Cell::new(crate::yara::ir::EVAL_STEP_BUDGET);
        let mut results: Vec<bool> = Vec::with_capacity(rules.rules.len());
        for rule in &rules.rules {
            let ctx = EvalCtx {
                data,
                matches: &matches,
                rule_results: &results,
                modules: &modules,
                externals: &self.externals,
                env: std::cell::RefCell::new(Vec::new()),
                steps: &steps,
            };
            let r = rule.cond.eval_bool(&ctx);
            results.push(r);
        }
        let steps_exhausted = steps.get() == 0;

        // 4. Global rules gate the whole set: if any global rule is false, no
        //    rule matches.
        let global_pass = rules
            .rules
            .iter()
            .zip(&results)
            .filter(|(r, _)| r.global)
            .all(|(_, &res)| res);

        let matching: Vec<usize> = if global_pass {
            rules
                .rules
                .iter()
                .zip(&results)
                .enumerate()
                .filter(|(_, (r, &res))| res && !r.private)
                .map(|(i, _)| i)
                .collect()
        } else {
            Vec::new()
        };

        ScanResults {
            rules,
            data,
            matches,
            matching,
            steps_exhausted,
        }
    }
}

/// The outcome of a scan.
pub struct ScanResults<'r, 'd> {
    rules: &'r Rules,
    data: &'d [u8],
    matches: Vec<Vec<Match>>,
    matching: Vec<usize>,
    steps_exhausted: bool,
}

impl<'r, 'd> ScanResults<'r, 'd> {
    /// Iterator over the rules that matched, in declaration order.
    pub fn matching_rules(&self) -> MatchingRules<'_, 'r, 'd> {
        MatchingRules {
            res: self,
            iter: self.matching.iter(),
        }
    }

    /// Whether the scan spent its whole condition-evaluation budget.
    ///
    /// When this is true the results are a LOWER BOUND: the conditions cut short
    /// evaluated to *undefined* and so did not match, and a rule that would have
    /// matched given unlimited time may be missing. It takes a rule with a range
    /// loop in the hundreds of millions to reach the budget, so this reports a
    /// ruleset that needs fixing rather than a property of the scanned file.
    pub fn budget_exhausted(&self) -> bool {
        self.steps_exhausted
    }
}

/// Iterator over matching rules. Implements [`ExactSizeIterator`] so callers can
/// use `.len()`.
pub struct MatchingRules<'a, 'r, 'd> {
    res: &'a ScanResults<'r, 'd>,
    iter: std::slice::Iter<'a, usize>,
}

impl<'a, 'r, 'd> Iterator for MatchingRules<'a, 'r, 'd> {
    type Item = Rule<'a, 'r, 'd>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|&idx| Rule { res: self.res, idx })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl ExactSizeIterator for MatchingRules<'_, '_, '_> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

/// A handle to a matching rule.
pub struct Rule<'a, 'r, 'd> {
    res: &'a ScanResults<'r, 'd>,
    idx: usize,
}

impl<'a, 'r, 'd> Rule<'a, 'r, 'd> {
    /// The rule's identifier.
    pub fn identifier(&self) -> &'a str {
        &self.res.rules.rules[self.idx].name
    }

    /// The rule's metadata entries as `(identifier, value-as-string)` pairs.
    pub fn metadata(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.res.rules.rules[self.idx]
            .meta
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Iterator over the rule's declared patterns.
    pub fn patterns(&self) -> Patterns<'a, 'r, 'd> {
        Patterns {
            res: self.res,
            iter: self.res.rules.rules[self.idx].pattern_ids.iter(),
        }
    }
}

/// Iterator over a rule's patterns.
pub struct Patterns<'a, 'r, 'd> {
    res: &'a ScanResults<'r, 'd>,
    iter: std::slice::Iter<'a, usize>,
}

impl<'a, 'r, 'd> Iterator for Patterns<'a, 'r, 'd> {
    type Item = Pattern<'a, 'r, 'd>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|&id| Pattern { res: self.res, id })
    }
}

/// A handle to a pattern of a matching rule.
pub struct Pattern<'a, 'r, 'd> {
    res: &'a ScanResults<'r, 'd>,
    id: usize,
}

impl<'a, 'r, 'd> Pattern<'a, 'r, 'd> {
    /// The pattern's identifier (including the `$`).
    pub fn identifier(&self) -> &'a str {
        &self.res.rules.pattern_names[self.id]
    }

    /// Iterator over this pattern's matches within the scanned data.
    pub fn matches(&self) -> Matches<'a, 'd> {
        Matches {
            data: self.res.data,
            iter: self.res.matches[self.id].iter(),
        }
    }
}

/// Iterator over a pattern's matches.
pub struct Matches<'a, 'd> {
    data: &'d [u8],
    iter: std::slice::Iter<'a, Match>,
}

impl<'a, 'd> Iterator for Matches<'a, 'd> {
    type Item = PatternMatch<'d>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|m| PatternMatch {
            data: self.data,
            m: *m,
        })
    }
}

/// A single match.
pub struct PatternMatch<'d> {
    data: &'d [u8],
    m: Match,
}

impl<'d> PatternMatch<'d> {
    /// The matched bytes.
    pub fn data(&self) -> &'d [u8] {
        &self.data[self.m.offset..self.m.offset + self.m.len]
    }

    /// The match's start offset.
    pub fn offset(&self) -> usize {
        self.m.offset
    }

    /// The match's length in bytes.
    pub fn length(&self) -> usize {
        self.m.len
    }
}

#[cfg(test)]
mod budget_tests {
    use crate::yara::compiler::Compiler;
    use crate::yara::scanner::Scanner;

    fn scan(src: &str, data: &[u8]) -> (Vec<String>, bool) {
        let mut c = Compiler::new();
        c.add_source(src).expect("compile");
        let rules = c.build();
        let mut scanner = Scanner::new(&rules);
        let res = scanner.scan(data).expect("scan");
        let ids: Vec<String> = res
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        let exhausted = res.budget_exhausted();
        (ids, exhausted)
    }

    /// A range loop takes its bounds from the rule, not from the file, so its
    /// iteration count is unbounded by anything the scanner can see. Without a
    /// step budget this rule runs two hundred million iterations on every buffer
    /// it is offered and the scan simply stops responding.
    #[test]
    fn a_runaway_range_loop_stops_at_the_budget() {
        let start = std::time::Instant::now();
        let (ids, exhausted) = scan(
            r#"rule runaway { condition: for any i in (0..200000000) : ( i == 199999999 ) }"#,
            b"anything",
        );
        let elapsed = start.elapsed();
        assert!(
            exhausted,
            "the loop asks for 200M iterations against a 20M budget, so the scan \
             must report that it ran out of steps"
        );
        assert!(
            ids.is_empty(),
            "a cut-short condition is undefined, not true"
        );
        assert!(
            elapsed.as_secs() < 10,
            "the budget did not bound the work: the scan took {elapsed:?}"
        );
    }

    /// The counterweight: the budget must be invisible to rules that do a normal
    /// amount of work, including loops sized from the file rather than the rule.
    #[test]
    fn ordinary_rules_never_reach_the_budget() {
        let (ids, exhausted) = scan(
            r#"rule ordinary {
                 strings: $a = "evil"
                 condition: $a and for any i in (0..10) : ( i == 3 )
               }"#,
            b"....evil....",
        );
        assert!(!exhausted, "an ordinary rule must not consume the budget");
        assert_eq!(ids, vec!["ordinary".to_string()]);
    }
}

#[cfg(test)]
mod serialize_tests {
    use crate::yara::compiler::Compiler;
    use crate::yara::scanner::{Rules, Scanner};

    /// Compiles `src` into a rule set.
    fn compile(src: &str) -> Rules {
        let mut c = Compiler::new();
        c.add_source(src).expect("compile");
        c.build()
    }

    /// The sorted identifiers of the rules matching `data` (with `filepath`/
    /// `filename`/`extension` externals set from `path`, mirroring `YaraDb::scan`).
    fn hits(rules: &Rules, data: &[u8], path: Option<&str>) -> Vec<String> {
        let mut scanner = Scanner::new(rules);
        if let Some(p) = path {
            scanner.set_global("filepath", p);
            let base = p.rsplit(['/', '\\']).next().unwrap_or(p);
            scanner.set_global("filename", base);
            if let Some(dot) = base.rfind('.').filter(|&d| d > 0) {
                scanner.set_global("extension", base[dot..].to_ascii_lowercase());
            }
        }
        let res = scanner.scan(data).expect("scan");
        let mut ids: Vec<String> = res
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        ids.sort();
        ids
    }

    /// A serialize -> deserialize round trip must yield IDENTICAL detections to a
    /// directly-compiled rule set, across every pattern kind and condition
    /// feature (literal/nocase/wide/xor/base64/hex/regex/regex-multi, counting,
    /// `of`, anchors, the `matches` operator, and the `pe`/`math` modules).
    #[test]
    fn round_trip_matches_fresh_compile() {
        const SRC: &str = r#"
            import "pe"
            import "math"

            rule literals {
                strings:
                    $a = "malware"
                    $b = "EVIL" nocase
                    $w = "widestr" wide
                condition:
                    $a and $b and $w
            }

            rule xored {
                strings:
                    $k = "secretkey" xor
                condition:
                    $k
            }

            rule b64 {
                strings:
                    $p = "password123" base64
                condition:
                    $p
            }

            rule hexrule {
                strings:
                    $h = { 4D 5A ?? ?? [0-4] 50 45 }
                condition:
                    $h
            }

            rule regexes {
                strings:
                    $r = /https?:\/\/[a-z0-9]+\.(com|net)/
                    $m = /Cafe[0-9]+/ nocase wide ascii
                condition:
                    $r and #m >= 1
            }

            rule counting_and_of {
                strings:
                    $x = "ab"
                    $y = "cd"
                    $z = "ef"
                condition:
                    #x >= 2 and @x[1] == 0 and 2 of ($x, $y, $z)
            }

            rule matches_op {
                condition:
                    filepath matches /\/tmp\/.*\.js$/i
            }

            rule modules {
                strings:
                    $s = "payload"
                condition:
                    $s and (pe.is_pe or filesize > 0) and math.entropy(0, filesize) >= 0.0
            }
        "#;

        let fresh = compile(SRC);
        let bytes = fresh.serialize();
        let loaded = Rules::deserialize(&bytes).expect("deserialize round trip");

        assert_eq!(fresh.len(), loaded.len());

        // A spread of inputs exercising each rule's match / non-match paths.
        let mz =
            b"MZ\x90\x00\x00\x00PE this has malware EVIL and w\x00i\x00d\x00e\x00s\x00t\x00r\x00";
        let inputs: &[(&[u8], Option<&str>)] = &[
            (b"nothing interesting here", None),
            (mz, Some("/tmp/dropper.js")),
            (
                b"visit http://example.com now, Cafe42 Cafe7",
                Some("/home/x/a.txt"),
            ),
            (b"ababab cdcd ef payload", None),
            (b"\x9asecretkey-ish", None),
            (
                b"cGFzc3dvcmQxMjM= is the base64 of password123",
                Some("C:\\Users\\v\\report.JS"),
            ),
            (b"payload with entropy", Some("/tmp/x.js")),
        ];

        for (data, path) in inputs {
            assert_eq!(
                hits(&fresh, data, *path),
                hits(&loaded, data, *path),
                "detections differ for input {data:?} path {path:?}",
            );
        }
    }

    /// A rule set with no patterns / trivial condition must round-trip too.
    #[test]
    fn round_trip_empty_and_constant() {
        let fresh = compile("rule always { condition: true }");
        let loaded = Rules::deserialize(&fresh.serialize()).expect("deserialize");
        assert_eq!(hits(&fresh, b"anything", None), vec!["always".to_string()]);
        assert_eq!(hits(&loaded, b"anything", None), vec!["always".to_string()]);
    }

    /// Load-time measurement (not a correctness gate): compiles a large real
    /// ruleset from source (which includes the expensive daachorse atom-automaton
    /// build) vs. deserializing the serialized compiled form (which skips it), and
    /// prints the timings + blob size. Ignored by default; run with:
    ///
    /// ```text
    /// cargo test -p exav-core --features yara --lib -- --ignored --nocapture load_time
    /// ```
    ///
    /// The source ruleset path can be overridden with `EXAV_YARA_BENCH_RULES`
    /// (e.g. a concatenated signature-base tree); it defaults to the in-repo
    /// `corpus/securiteinfo/securiteinfo.yara`.
    #[test]
    #[ignore = "perf measurement, not a correctness gate"]
    fn load_time_from_source_vs_deserialize() {
        use crate::yara::compiler::Compiler;
        use std::time::Instant;

        let path = std::env::var("EXAV_YARA_BENCH_RULES").unwrap_or_else(|_| {
            format!(
                "{}/../../corpus/securiteinfo/securiteinfo.yara",
                env!("CARGO_MANIFEST_DIR")
            )
        });
        let Ok(src) = std::fs::read_to_string(&path) else {
            eprintln!("skip: ruleset not found at {path}");
            return;
        };

        // Compile from source (lenient, per-rule) — the cost a load must avoid.
        let t0 = Instant::now();
        let mut c = Compiler::new();
        let _rejected = c.add_source_lenient(&src);
        let fresh = c.build();
        let compile_from_source = t0.elapsed();

        let n_rules = fresh.len();
        let n_patterns = fresh.patterns.len();

        // Serialize the compiled form.
        let t1 = Instant::now();
        let bytes = fresh.serialize();
        let serialize = t1.elapsed();

        // Deserialize (the load path): reconstruct the atom automaton + IR, and
        // recompile only the per-pattern regexes — skipping the automaton BUILD.
        let t2 = Instant::now();
        let loaded = Rules::deserialize(&bytes).expect("deserialize");
        let deserialize = t2.elapsed();

        assert_eq!(loaded.len(), n_rules);
        assert_eq!(loaded.patterns.len(), n_patterns);

        eprintln!("---- YARA load-time measurement ({path}) ----");
        eprintln!(
            "rules: {n_rules}, patterns: {n_patterns}, blob: {} bytes",
            bytes.len()
        );
        eprintln!("compile from source (incl. atom-automaton build): {compile_from_source:?}");
        eprintln!("serialize compiled form:                          {serialize:?}");
        eprintln!("deserialize (load, skips automaton build):        {deserialize:?}");
        if deserialize.as_nanos() > 0 {
            eprintln!(
                "speedup (compile / deserialize):                  {:.1}x",
                compile_from_source.as_secs_f64() / deserialize.as_secs_f64()
            );
        }
    }
}
