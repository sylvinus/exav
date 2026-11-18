//! Scanning: running compiled [`Rules`] over a data buffer.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::byte_source::ByteSource;
use crate::engine::WholeLimits;
use crate::yara::atoms::PatternGate;
use crate::yara::compiler::ExternalValue;
use crate::yara::error::{Error, Result};
use crate::yara::feed::{FeedPlan, YaraFeed, YaraPass};
use crate::yara::ir::{Cond, EvalCtx, Value, anchors};
use crate::yara::matcher::{Match, PatternDef, PatternMatcher, StreamRegexes, find_all_windowed};
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

/// A compiled set of YARA rules, ready to scan. `'static`: owns everything.
pub struct Rules {
    pub(crate) patterns: Vec<PatternMatcher>,
    /// Per pattern, its regexes as a search over a source not held in memory
    /// runs them, built from `defs` the first time one is needed.
    pub(crate) stream_regexes: Vec<OnceLock<Option<StreamRegexes>>>,
    /// The serializable definition of each pattern (index == pattern id), kept
    /// in lockstep with `patterns`. Not used at scan time; carried so the rule
    /// set can be re-serialized (the compiled `patterns` are recompiled from
    /// these on load; see [`Rules::serialize`]/[`Rules::deserialize`]).
    pub(crate) defs: Vec<PatternDef>,
    pub(crate) pattern_names: Vec<String>,
    pub(crate) rules: Vec<CompiledRule>,
    /// Modules imported by this rule set (their values are built per scan).
    pub(crate) imported: Vec<ModuleKind>,
    /// Whether any rule uses the `entrypoint` keyword.
    pub(crate) uses_entrypoint: bool,
    /// Required-literal prefilter: which patterns even need to be
    /// scanned for a given buffer (see [`crate::yara::atoms`]).
    pub(crate) gate: PatternGate,
    /// How the patterns are searched as an object is read, worked out on first
    /// use (see [`crate::yara::feed`]).
    pub(crate) feed_plan: OnceLock<FeedPlan>,
    /// Per pattern, the offset it is anchored at, if it is
    /// ([`crate::yara::ir::anchors`]): worked out from `rules`, not stored.
    pub(crate) anchored: Vec<Option<usize>>,
}

/// The serialized form of a compiled [`Rules`] set. Everything here is cheap to
/// (de)serialize; the atom index is inside `gate` (in its own binary form), and
/// the per-pattern regexes are
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
    /// on-disk database. The atom index travels in its built form; only the
    /// per-pattern regex SOURCES travel, not the compiled regex
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
        // Infallible for this data: every length is known and fits, and
        // writing to a Vec never fails.
        crate::database::to_vec_indexed(&blob).expect("serialize compiled YARA rules")
    }

    /// Reconstructs a compiled rule set from [`Rules::serialize`] bytes. The
    /// atom index is read back (NOT rebuilt from the atoms); the IR and rule
    /// structs are deserialized; and each pattern's `PatternMatcher` is
    /// recompiled from its stored [`PatternDef`]. This skips the aggregate build
    /// cost (source parse, AST->IR lowering, atom extraction, and the atom
    /// index build), paying only per-pattern regex compilation.
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Rules> {
        let blob: RulesBlobOwned = rmp_serde::from_slice(bytes)
            .map_err(|e| Error::new(format!("invalid serialized YARA rules: {e}")))?;
        if !blob.gate.fits(blob.defs.len()) {
            return Err(Error::new(
                "invalid serialized YARA rules: the prefilter does not fit the patterns",
            ));
        }
        let mut patterns = Vec::with_capacity(blob.defs.len());
        for def in &blob.defs {
            patterns.push(def.compile()?);
        }
        let anchored = anchors(blob.rules.iter().map(|r| &r.cond), patterns.len());
        Ok(Rules {
            patterns,
            stream_regexes: blob.defs.iter().map(|_| OnceLock::new()).collect(),
            defs: blob.defs,
            pattern_names: blob.pattern_names,
            rules: blob.rules,
            imported: blob.imported,
            uses_entrypoint: blob.uses_entrypoint,
            gate: blob.gate,
            feed_plan: OnceLock::new(),
            anchored,
        })
    }

    /// The search of the patterns in `src`, to be fed it as it is read, and
    /// the answer handed back to [`Scanner::scan_source`]. `None` when there
    /// is no pattern to search for.
    pub(crate) fn feed<'a>(
        &'a self,
        src: &'a dyn ByteSource,
        whole: &WholeLimits,
    ) -> Option<YaraFeed<'a>> {
        YaraFeed::new(self, src, whole)
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
    /// Whether the object scanned was cut out of a host at an offset.
    carved: bool,
}

impl<'r> Scanner<'r> {
    pub fn new(rules: &'r Rules) -> Self {
        Self {
            rules,
            externals: HashMap::new(),
            carved: false,
        }
    }

    /// Says the objects scanned from now on were cut out of a host at an
    /// offset: an import table of a PE that lies past its bytes is then
    /// absent, not unread.
    pub(crate) fn set_carved(&mut self, carved: bool) {
        self.carved = carved;
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
        let e = self.evaluate(&data, &WholeLimits::NONE, None);
        ScanResults {
            rules: self.rules,
            data,
            matches: e.matches,
            matching: e.matching,
            steps_exhausted: e.steps_exhausted,
            complete: e.complete,
        }
    }

    /// Scans an object that need not be held in memory. `whole.materialize`
    /// is the largest such object read whole where a search or a module needs
    /// it so, and `whole.regex_steps` the steps the searches of a regexp
    /// pattern may make. `pass` is what a read of the object has found of the
    /// patterns already (see [`Rules::feed`]).
    pub(crate) fn scan_source(
        &self,
        src: &dyn ByteSource,
        whole: &WholeLimits,
        pass: Option<YaraPass>,
    ) -> SourceResults<'r> {
        let e = self.evaluate(src, whole, pass);
        SourceResults {
            matching: e
                .matching
                .iter()
                .map(|&i| self.rules.rules[i].name.as_str())
                .collect(),
            steps_exhausted: e.steps_exhausted,
            complete: e.complete,
        }
    }

    fn evaluate(
        &self,
        data: &dyn ByteSource,
        whole: &WholeLimits,
        pass: Option<YaraPass>,
    ) -> Evaluated {
        let rules = self.rules;
        let materialize = whole.materialize;

        // 1. Find matches for every pattern. The atom prefilter first tells us
        //    which patterns can possibly match this buffer; the rest are known to
        //    have zero matches (a required literal is absent), so we skip their
        //    O(n) scan and hand them an empty match list, an identical result.
        //    A read of the object may have made the prefilter's search and
        //    found some of the matches already.
        let (run, mut fed) = match pass {
            Some(p) => (p.run, p.found),
            None => (rules.gate.select(data), Vec::new()),
        };
        fed.resize_with(rules.patterns.len(), || None);
        let mut complete = true;
        // Over an object not held in memory, the literal and base64 patterns
        // the read did not search are searched in one read of it together,
        // but for those anchored at an offset, looked for there alone.
        let mut windowed = vec![Vec::new(); rules.patterns.len()];
        let together: Vec<usize> = match data.as_slice() {
            Some(_) => Vec::new(),
            None => (0..rules.patterns.len())
                .filter(|&i| {
                    run[i]
                        && fed[i].is_none()
                        && rules.patterns[i].windowed()
                        && rules.anchored[i].is_none()
                })
                .collect(),
        };
        let pats: Vec<&PatternMatcher> = together.iter().map(|&i| &rules.patterns[i]).collect();
        for (&i, found) in together.iter().zip(find_all_windowed(&pats, data)) {
            complete &= found.complete;
            windowed[i] = found.matches;
        }
        let matches: Vec<Vec<Match>> = rules
            .patterns
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if !run[i] {
                    return Vec::new();
                }
                if let Some(found) = fed[i].take() {
                    complete &= found.complete;
                    return found.matches;
                }
                if together.contains(&i) {
                    return std::mem::take(&mut windowed[i]);
                }
                let stream = || {
                    rules.stream_regexes[i]
                        .get_or_init(|| rules.defs[i].stream_regexes())
                        .as_ref()
                };
                let only = rules.anchored[i];
                let found = p.find_all(data, &stream, materialize, whole.regex_steps, only);
                complete &= found.complete;
                found.matches
            })
            .collect();

        // 2. Build the per-scan module state (parse PE, etc.) once.
        let modules = if rules.imported.is_empty() && !rules.uses_entrypoint {
            ModuleCtx::empty()
        } else {
            let (modules, built) = ModuleCtx::build(
                data,
                &rules.imported,
                rules.uses_entrypoint,
                materialize,
                self.carved,
            );
            complete &= built;
            modules
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
                .filter(|&(_, (r, &res))| res && !r.private)
                .map(|(i, _)| i)
                .collect()
        } else {
            Vec::new()
        };

        Evaluated {
            matches,
            matching,
            steps_exhausted,
            complete,
        }
    }
}

/// What evaluating the rules over one object found.
struct Evaluated {
    matches: Vec<Vec<Match>>,
    matching: Vec<usize>,
    steps_exhausted: bool,
    complete: bool,
}

/// The outcome of [`Scanner::scan_source`].
pub(crate) struct SourceResults<'r> {
    /// The rules that matched, in declaration order.
    pub matching: Vec<&'r str>,
    /// As [`ScanResults::budget_exhausted`].
    pub steps_exhausted: bool,
    /// As [`ScanResults::complete`], and the modules could parse the object.
    pub complete: bool,
}

/// The outcome of a scan.
pub struct ScanResults<'r, 'd> {
    rules: &'r Rules,
    data: &'d [u8],
    matches: Vec<Vec<Match>>,
    matching: Vec<usize>,
    steps_exhausted: bool,
    complete: bool,
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
    /// matched given unlimited time may be missing. A loop with literal bounds
    /// needs hundreds of millions of iterations to reach the budget; one bounded
    /// by the file (`#a`, `filesize`) reaches it with a file of a few million
    /// matches or bytes.
    pub fn budget_exhausted(&self) -> bool {
        self.steps_exhausted
    }

    /// Whether every match of every pattern was recorded (of a pattern that
    /// every use names at one offset, the match there). A pattern keeps at
    /// most a million matches, as yara-x does; past that the conditions see a
    /// partial list and the results are not to be trusted either way.
    pub fn complete(&self) -> bool {
        self.complete
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
    pub fn metadata(&self) -> impl Iterator<Item = (&'a str, &'a str)> + use<'a> {
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

    /// Iterator over this pattern's matches within the scanned data: of a
    /// pattern that every use in the rules names at one offset, the match at
    /// that offset alone, as yara-x reports it.
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

    /// `at`, `in` and a count over a range look for the offsets of a pattern's
    /// matches, which are sorted.
    #[test]
    fn anchors_and_ranges_find_the_matches_that_start_in_them() {
        // `a` starts at 1, 4 and 8.
        let data = b"xaxxaxxxa";
        let holds = |cond: &str| {
            let rule = format!(r#"rule r {{ strings: $a = "a" condition: {cond} }}"#);
            !scan(&rule, data).0.is_empty()
        };
        for (cond, want) in [
            ("$a at 4", true),
            ("$a at 8", true),
            ("$a at 1", true),
            ("$a at 0", false),
            ("$a at 5", false),
            ("$a at 9", false),
            ("$a at -1", false),
            ("$a in (2..4)", true),
            ("$a in (2..3)", false),
            ("$a in (5..7)", false),
            ("$a in (8..100)", true),
            ("$a in (0..1)", true),
            ("$a in (9..20)", false),
            ("$a in (4..4)", true),
            ("$a in (5..4)", false),
            ("#a in (0..8) == 3", true),
            ("#a in (2..8) == 2", true),
            ("#a in (2..7) == 1", true),
            ("#a in (5..7) == 0", true),
            ("#a in (4..4) == 1", true),
            ("#a in (5..4) == 0", true),
            ("#a in (-5..0) == 0", true),
            ("#a in (-5..100) == 3", true),
        ] {
            assert_eq!(holds(cond), want, "{cond}");
        }
    }

    /// A loop over a pattern's matches asks about those of another pattern
    /// once per iteration. A pass over them for each question is quadratic in
    /// their number, and the step budget, which counts a question as one step,
    /// does not stop it. Searched, the work takes milliseconds; passed over,
    /// tens of seconds. The time allowed is far above the first.
    #[test]
    fn a_loop_over_many_matches_does_not_scan_them_per_iteration() {
        let mut data = vec![b'a'; 100_000];
        data.extend(vec![b'b'; 100_000]);
        let start = std::time::Instant::now();
        let (ids, exhausted) = scan(
            r#"rule r {
                 strings: $a = "a" $b = "b"
                 condition: for any i in (1..#a) : (
                     $b at @a[i] or $b in (@a[i]..@a[i]) or #b in (@a[i]..@a[i]) > 0
                 )
               }"#,
            &data,
        );
        assert!(!exhausted);
        assert!(ids.is_empty());
        assert!(start.elapsed().as_secs() < 10, "took {:?}", start.elapsed());
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
mod source_tests {
    use std::io::Cursor;

    use crate::byte_source::{BlockCache, CHUNK};
    use crate::engine::WholeLimits;
    use crate::yara::compiler::Compiler;
    use crate::yara::feed::YaraPass;
    use crate::yara::scanner::{Evaluated, Rules, Scanner};

    const RULES: &str = r#"
        import "math"
        import "hash"

        rule literals {
            strings:
                $a = "needle"
                $b = "NeEdLe" nocase
                $c = "wide" wide ascii
                $d = "word" fullword
                $e = "wword" wide fullword
                $f = "xored" xor(1-3)
                $g = "xorword" xor(1-2) fullword
            condition: any of them
        }
        rule b64 {
            strings:
                $p = "password123" base64
                $q = "secret!" base64wide
            condition: $p or $q
        }
        rule hexes {
            strings:
                $h = { 4D 5A ?? ?? [2-40] 50 45 }
                $j = { 6E 65 ( 65 | 64 ) [-] 6C 65 }
            condition: #h > 0 or #j > 1
        }
        rule regexes {
            strings:
                $r = /ne+dle[0-9]*/
                $s = /h.llo/is
                $t = /c[a-z]+e/ wide ascii
                $u = /word[0-9]?/ fullword
                $v = /x[^x]{1,300}y/s
            condition: any of them
        }
        rule counts {
            strings:
                $a = "needle"
            condition: #a >= 3 and @a[2] > 10 and !a[1] == 6 and $a in (0..filesize)
        }
        rule reads {
            condition:
                uint32(0) != 0 and uint16be(filesize - 2) != 1 and int8(filesize - 1) < 128
                and not defined uint8(filesize)
        }
        rule maths {
            condition:
                math.entropy(0, filesize) > 1.0
                and math.mean(3, filesize) >= 0.0
                and math.deviation(0, filesize, 127.5) >= 0.0
                and math.serial_correlation(1, filesize) != 7.0
                and math.monte_carlo_pi(5, filesize) >= 0.0
                and math.count(0x61, 0, filesize) >= 0
                and math.percentage(0x61) >= 0.0
                and math.mode(0, filesize) >= 0
        }
        rule hashes {
            condition:
                hash.md5(0, filesize) != ""
                and hash.sha1(1, filesize - 1) != ""
                and hash.sha256(0, filesize) != ""
                and hash.crc32(2, filesize - 2) != 0
                and hash.checksum32(0, filesize) != 1
        }
    "#;

    fn rules(src: &str) -> Rules {
        let mut c = Compiler::new();
        c.add_source(src).expect("compile");
        c.build()
    }

    fn evaluate(
        rules: &Rules,
        src: &dyn crate::byte_source::ByteSource,
        materialize: usize,
    ) -> Evaluated {
        let whole = WholeLimits {
            materialize,
            ..WholeLimits::NONE
        };
        Scanner::new(rules).evaluate(src, &whole, None)
    }

    /// Pattern text, one of each kind the rules look for, and near misses
    /// that only the bytes around them rule out.
    fn plants() -> Vec<Vec<u8>> {
        let wide = |s: &[u8]| -> Vec<u8> { s.iter().flat_map(|&b| [b, 0]).collect() };
        let mut plants: Vec<Vec<u8>> = [
            &b"needle"[..],
            b"NEEDLE7",
            b" word ",
            b"xword",
            b"wordx",
            b"cGFzc3dvcmQxMjM=",
            // "Apassword123" and "ABpassword123": decoded from before the match.
            b"QXBhc3N3b3JkMTIz",
            b"QUJwYXNzd29yZDEyMw==",
            // A character past the encoded text that fails the decode.
            b"cGFzc3dvcmQxMjM!",
            b"MZ\x90\x00 some bytes PE",
            b"x long gap y",
            b"hElLo",
            b"neddle",
        ]
        .iter()
        .map(|p| p.to_vec())
        .collect();
        for s in [&b"wide"[..], b"cake", b" wword ", b"awword", b"wwordz"] {
            plants.push(wide(s));
        }
        // "secret!", "Asecret!" and "ABsecret!", base64 then widened.
        for s in [
            &b"c2VjcmV0IQ=="[..],
            b"QXNlY3JldCE=",
            b"QUJzZWNyZXQh",
            b"c2VjcmV0IQ!!",
        ] {
            plants.push(wide(s));
        }
        plants.push(b"xored".iter().map(|b| b ^ 2).collect());
        plants.push(b" xorword ".iter().map(|b| b ^ 1).collect());
        plants.push(b"axorword".iter().map(|b| b ^ 1).collect());
        plants
    }

    /// A haystack of noise with `plants()[kind]` planted at each `(at, kind)`.
    fn haystack(len: usize, spots: &[(usize, usize)], seed: u64) -> Vec<u8> {
        haystack_of(&plants(), len, spots, seed)
    }

    /// [`haystack`] of any `plants`.
    fn haystack_of(plants: &[Vec<u8>], len: usize, spots: &[(usize, usize)], seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        let mut h: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"abcdehlnorwxyz \x00\n.MZPE"[(state % 20) as usize]
            })
            .collect();
        for &(at, kind) in spots {
            let plant = &plants[kind % plants.len()];
            let at = at.min(len.saturating_sub(plant.len()));
            h[at..at + plant.len()].copy_from_slice(plant);
        }
        h
    }

    fn assert_same(rules: &Rules, h: &[u8], block: usize, what: &str) {
        let want = evaluate(rules, &h, usize::MAX);
        let cache = BlockCache::with_sizes(Cursor::new(h.to_vec()), block, 8 * block).unwrap();
        // Nothing may be read whole: every search runs through the cache.
        let got = evaluate(rules, &cache, 0);
        assert!(
            want.complete && got.complete,
            "{what}: a search was cut short"
        );
        for (i, (w, g)) in want.matches.iter().zip(&got.matches).enumerate() {
            assert_eq!(w, g, "{what}: pattern {} ({})", i, rules.pattern_names[i]);
        }
        assert_eq!(want.matching, got.matching, "{what}");
    }

    #[test]
    fn a_streamed_object_matches_as_in_memory() {
        let rules = rules(RULES);
        let kinds = plants().len();
        for seed in 1..6 {
            let spots: Vec<(usize, usize)> =
                (0..kinds).map(|k| (k * 23, k + seed as usize)).collect();
            let h = haystack(kinds * 23 + seed as usize * 7, &spots, seed);
            assert_same(&rules, &h, 7, &format!("small seed {seed}"));
        }
        // Each kind of plant straddling a seam between two search windows, at
        // every split, and a few more plants away from the seams.
        let mut spots = Vec::new();
        for kind in 0..kinds {
            let len = plants()[kind].len();
            for cut in 1..len {
                let seam = (1 + spots.len()) * CHUNK;
                spots.push((seam - cut, kind));
            }
        }
        let seams = spots.len();
        spots.extend((0..kinds).map(|k| (5 + k * 31, k)));
        let h = haystack((seams + 2) * CHUNK, &spots, 99);
        // Blocks that never line up with the windows.
        assert_same(&rules, &h, 509, "seams");
        // Every rule must have had something to find, or the comparison proves
        // little.
        let e = evaluate(&rules, &h, usize::MAX);
        let names: Vec<&str> = e
            .matching
            .iter()
            .map(|&i| rules.rules[i].name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "literals", "b64", "hexes", "regexes", "counts", "reads", "maths", "hashes"
            ]
        );
    }

    /// More patterns than [`RULES`] has: atoms in the middle of long needles,
    /// regexps whose atom is not at their start, bounded and unbounded ones,
    /// anchors, boundaries, and hex patterns with jumps or wildcards first.
    const MORE_RULES: &str = r#"
        rule long_literals {
            strings:
                $a = "the quick brown fox jumps over the lazy dog"
                $b = "THE QUICK BROWN FOX JUMPS" nocase
                $c = "long wide needle text" wide
                $d = "another quite long literal" fullword
            condition: any of them
        }
        rule mid_atom {
            strings:
                $a = "                    \xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x02\x03\x04\x05\x06\x07\x08\x09"
                $b = "                    \xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x02\x03\x04\x05\x06\x07\x08\x0a" nocase
                $c = "                    \xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x02\x03\x04\x05\x06\x07\x08\x0b" wide
            condition: any of them
        }
        rule bounded {
            strings:
                $a = /[a-z]{3}needle[0-9]{2}/
                $b = /ab[0-9]{2,5}cd/
                $c = /\bfoo(bar|baz)\b/
                $d = /^MZ.{0,8}PE/
                $e = /end$/
                $f = /[a-z0-9]{12,}/
                $g = /Z[a-z]{2}Q|[0-9]{3}needle/
            condition: any of them
        }
        rule more_hexes {
            strings:
                $a = { 61 62 63 [2-6] 64 65 66 }
                $b = { ?? ?? 61 62 ( 63 | 64 ) }
                $c = { 61 [-] 7A 7A }
            condition: any of them
        }
    "#;

    /// [`plants`], and one of each of the patterns of [`MORE_RULES`].
    fn fed_plants() -> Vec<Vec<u8>> {
        let mut plants = plants();
        for s in [
            &b"the quick brown fox jumps over the lazy dog"[..],
            b"THE QUICK BROWN FOX JUMPS",
            b" another quite long literal ",
            b"abcneedle42",
            b"ab123cd",
            b" foobar ",
            b"MZ12345678PE",
            b"xxabc12def",
            b"a1b2c3d4e5f6g7h8i9",
            b"Zabc!",
            b"123needle",
            b"a very long gap zz",
        ] {
            plants.push(s.to_vec());
        }
        plants.push(
            b"long wide needle text"
                .iter()
                .flat_map(|&b| [b, 0])
                .collect(),
        );
        // The literals of `mid_atom`: the atom of each is its tail.
        let tail = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x02\x03\x04\x05\x06\x07\x08";
        for last in [0x09, 0x0a, 0x0b] {
            let text: Vec<u8> = [&[b' '; 20][..], tail, &[last]].concat();
            plants.push(match last {
                0x0b => text.iter().flat_map(|&b| [b, 0]).collect(),
                _ => text,
            });
        }
        plants
    }

    /// The object read once: `h`, in pieces of `piece` bytes, and the answer.
    fn fed(
        rules: &Rules,
        cache: &BlockCache<Cursor<Vec<u8>>>,
        h: &[u8],
        piece: usize,
        whole: &WholeLimits,
    ) -> YaraPass {
        let mut feed = rules.feed(cache, whole).expect("patterns");
        for (i, w) in h.chunks(piece).enumerate() {
            feed.feed(i * piece, w);
        }
        feed.finish().expect("all of the object was fed")
    }

    /// What the read found of the patterns, and what is left to search after
    /// it, give the matches of the object held in memory.
    fn assert_same_fed(rules: &Rules, h: &[u8], block: usize, piece: usize, what: &str) {
        let want = evaluate(rules, &h, usize::MAX);
        let cache = BlockCache::with_sizes(Cursor::new(h.to_vec()), block, 8 * block).unwrap();
        // Nothing may be read whole: every search runs through the cache.
        let whole = WholeLimits {
            materialize: 0,
            ..WholeLimits::NONE
        };
        let pass = fed(rules, &cache, h, piece, &whole);
        for (i, (&run, found)) in pass.run.iter().zip(&pass.found).enumerate() {
            let ctx = format!(
                "{what}, piece {piece}: pattern {i} ({})",
                rules.pattern_names[i]
            );
            assert!(run || want.matches[i].is_empty(), "{ctx} was not slated");
            assert!(
                !run || found.is_some(),
                "{ctx} was left to the search after the read"
            );
            if let Some(found) = found {
                assert_eq!(found.matches, want.matches[i], "{ctx}");
                assert!(found.complete, "{ctx}");
            }
        }
        let got = Scanner::new(rules).evaluate(&cache, &whole, Some(pass));
        assert!(
            want.complete && got.complete,
            "{what}: a search was cut short"
        );
        assert_eq!(want.matches, got.matches, "{what}, piece {piece}");
        assert_eq!(want.matching, got.matching, "{what}, piece {piece}");
    }

    /// Every pattern found in a read of the object, handed over in pieces of
    /// any size, equals the object searched whole in memory: with the plants
    /// of each kind straddling the seams between segments, pieces and blocks,
    /// at the start of the object and at its end.
    #[test]
    fn the_matches_found_while_the_object_is_read_are_those_of_a_search_of_it() {
        let rules = rules(&format!("{RULES}{MORE_RULES}"));
        let plants = fed_plants();
        let kinds = plants.len();
        for seed in 1..4u64 {
            let spots: Vec<(usize, usize)> =
                (0..kinds).map(|k| (k * 23, k + seed as usize)).collect();
            let h = haystack_of(&plants, kinds * 23 + seed as usize * 7, &spots, seed);
            for piece in [1, 7, 64, 1000] {
                assert_same_fed(&rules, &h, 7, piece, &format!("small seed {seed}"));
            }
        }
        // Each kind of plant straddling a multiple of 1024 at every split, so
        // that it crosses a segment, and pieces and blocks of other sizes.
        let mut spots = Vec::new();
        for (kind, plant) in plants.iter().enumerate() {
            for cut in 1..plant.len() {
                spots.push(((1 + spots.len()) * 1024 - cut, kind));
            }
        }
        let seams = spots.len();
        // And at the very start and end.
        spots.extend((0..kinds).map(|k| (0, k)));
        spots.extend((0..kinds).map(|k| (usize::MAX, k)));
        let mut h = haystack_of(&plants, (seams + 2) * 1024, &spots, 99);
        h.extend_from_slice(b"end");
        for (block, piece) in [(509, 64), (509, 100), (64, 1024), (4096, 509), (61, 1)] {
            assert_same_fed(&rules, &h, block, piece, "seams");
        }
        // Every kind of rule had something to find, or the comparison proves little.
        let e = evaluate(&rules, &h, usize::MAX);
        let found = e.matches.iter().filter(|m| !m.is_empty()).count();
        assert!(
            found + 4 >= e.matches.len(),
            "{found} of {} patterns matched",
            e.matches.len()
        );
    }

    /// Runs of one byte, long and short, at the ends of the object and in the
    /// middle of it, are searched for the literals made of that byte as the
    /// object goes by, without one entry for each of its segments.
    #[test]
    fn runs_of_one_byte_are_searched_as_the_object_goes_by() {
        let rules = rules(
            r#"rule runs {
                strings:
                    $z = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    $a = "aaaaaaaaaaaa" nocase
                    $w = "\x00\x00\x00\x00\x00\x00\x00\x00" wide
                    $b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                condition: any of them
            }"#,
        );
        let mut state = 17u64;
        let mut noise = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    b"bcdxyz\n"[(state % 7) as usize]
                })
                .collect()
        };
        let mut h = Vec::new();
        // At the start, between noise, mixed in case, and at the end.
        for (byte, len) in [
            (0u8, 9),
            (0, 3000),
            (b'a', 11),
            (b'a', 200),
            (0, 64),
            (0, 10_000),
            (b'A', 130),
            (0, 70),
        ] {
            h.extend(noise(17));
            h.extend(std::iter::repeat_n(byte, len));
            if len == 130 {
                h.extend(b"aAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaA");
            }
        }
        h.extend(std::iter::repeat_n(b'a', 1000));
        h.extend(noise(5));
        h.extend(std::iter::repeat_n(0u8, 5000));
        for (block, piece) in [(61, 1), (509, 7), (64, 100), (4096, 5000), (509, 64)] {
            assert_same_fed(&rules, &h, block, piece, "runs");
        }
        let e = evaluate(&rules, &h, usize::MAX);
        assert!(
            e.matches.iter().all(|m| m.len() > 100),
            "{:?}",
            e.matches.iter().map(Vec::len).collect::<Vec<_>>()
        );
    }

    /// The read hands the bytes in windows that leave gaps, overlap and
    /// repeat, as the sweep that drives it does: what lies in a gap is read
    /// from the object, and the matches after a gap are found.
    #[test]
    fn the_matches_after_a_window_that_skips_ahead_are_found() {
        use crate::pass::{Fed, Tap};
        struct Fead<'a>(crate::yara::YaraFeed<'a>);
        impl Tap for Fead<'_> {
            fn feed(&mut self, at: usize, w: &[u8]) {
                self.0.feed(at, w)
            }
            fn wants_more(&self) -> bool {
                self.0.wants_more()
            }
        }
        let rules = rules(&format!("{RULES}{MORE_RULES}"));
        let plants = fed_plants();
        let spots: Vec<(usize, usize)> = (0..plants.len() * 4).map(|k| (200 + k * 41, k)).collect();
        let h = haystack_of(&plants, 6000, &spots, 5);
        let want = evaluate(&rules, &h, usize::MAX);
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 61, 61 * 8).unwrap();
        let whole = WholeLimits {
            materialize: 0,
            ..WholeLimits::NONE
        };
        let mut tap = Fead(rules.feed(&cache, &whole).expect("patterns"));
        let mut fed = Fed::new(&mut tap, &cache);
        // The first window, one inside it, a repeat, then windows that
        // skip over stretches holding plants, the last cut short of the end.
        for (a, b) in [
            (0, 150),
            (20, 60),
            (0, 150),
            (700, 900),
            (880, 1200),
            (2500, 2600),
            (4000, 5900),
        ] {
            fed.feed(a, &h[a..b]);
        }
        fed.drain();
        let pass = tap.0.finish().expect("all of the object was fed");
        for (i, found) in pass.found.iter().enumerate() {
            assert!(!pass.run[i] || found.is_some(), "pattern {i}");
            if let Some(found) = found {
                assert_eq!(
                    found.matches, want.matches[i],
                    "pattern {i} ({})",
                    rules.pattern_names[i]
                );
            }
        }
        let got = Scanner::new(&rules).evaluate(&cache, &whole, Some(pass));
        assert_eq!(want.matches, got.matches);
    }

    /// The matches of `rules` over `cache`, as the search after a read gives them,
    /// with `steps` for the regexp patterns and the read's answer if there is one.
    fn evaluate_steps(
        rules: &Rules,
        cache: &BlockCache<Cursor<Vec<u8>>>,
        steps: usize,
        pass: Option<YaraPass>,
    ) -> Evaluated {
        let whole = WholeLimits {
            materialize: 0,
            regex_steps: steps,
            ..WholeLimits::NONE
        };
        Scanner::new(rules).evaluate(cache, &whole, pass)
    }

    /// The object read once and handed to the feed, as the pass hands it.
    fn read_once(
        rules: &Rules,
        cache: &dyn crate::byte_source::ByteSource,
        whole: &WholeLimits,
    ) -> Option<YaraPass> {
        use crate::pass::{Fed, Tap};
        struct Fead<'a>(crate::yara::YaraFeed<'a>);
        impl Tap for Fead<'_> {
            fn feed(&mut self, at: usize, w: &[u8]) {
                self.0.feed(at, w)
            }
            fn wants_more(&self) -> bool {
                self.0.wants_more()
            }
        }
        let mut tap = Fead(rules.feed(cache, whole)?);
        Fed::new(&mut tap, cache).drain();
        tap.0.finish()
    }

    /// A pattern whose searches reach their limit is searched again after the
    /// read, so the limit falls where it always fell: at the same number of
    /// steps, with the same matches kept, whether the read found the pattern
    /// or not.
    #[test]
    fn a_regexp_pattern_reaches_its_limit_at_the_same_step_with_or_without_the_read() {
        // A run of capitals, a wide and ascii pattern, one whose atom comes
        // late, and a hex pattern with an open jump.
        let mut h = vec![0u8];
        h.extend(vec![b'A'; 300]);
        h.extend(b"\0\0QAAAA\0");
        h.extend((0..2500u32).map(|i| b"bcdefg"[(i * i % 6) as usize]));
        h.extend(b"abcneedle42 and the rest\0");
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 61, 61 * 8).unwrap();
        let (mut used, mut left_to_search) = (0, 0);
        for pattern in [
            "/[A-Z]{40,}/",
            "/Q[A-Z]{2,}/ wide ascii",
            "/[a-z]{3}needle[0-9]{2}/",
            "{ 41 41 [-] 51 41 }",
        ] {
            let rules = rules(&format!(
                "rule r {{ strings: $a = {pattern} condition: $a }}"
            ));
            let complete = |steps| evaluate_steps(&rules, &cache, steps, None).complete;
            // The fewest steps that finish the search of the pattern.
            let (mut lo, mut hi) = (0, 1_000_000);
            assert!(!complete(lo) && complete(hi), "{pattern}");
            while hi - lo > 1 {
                let mid = (lo + hi) / 2;
                match complete(mid) {
                    true => hi = mid,
                    false => lo = mid,
                }
            }
            for steps in [0, 1, lo / 2, lo - 1, lo, hi, hi + 1, 2 * hi, usize::MAX] {
                let want = evaluate_steps(&rules, &cache, steps, None);
                let whole = WholeLimits {
                    materialize: 0,
                    regex_steps: steps,
                    ..WholeLimits::NONE
                };
                let pass = read_once(&rules, &cache, &whole).expect("the object was read");
                if pass.found.iter().all(Option::is_some) {
                    used += 1;
                } else {
                    left_to_search += 1;
                }
                let got = evaluate_steps(&rules, &cache, steps, Some(pass));
                let ctx = format!("{pattern}, {steps} steps (the limit is at {hi})");
                assert_eq!(want.matches, got.matches, "{ctx}");
                assert_eq!(want.complete, got.complete, "{ctx}");
                assert_eq!(want.matching, got.matching, "{ctx}");
            }
        }
        // Both happened: the read had the result where the limit was not
        // reached, and left the pattern to the search where it was.
        assert!(
            used >= 8 && left_to_search >= 8,
            "{used} and {left_to_search}"
        );
    }

    /// The state tables of the regexp searches that follow the read take no
    /// more memory than they are given: a pattern whose search does not fit
    /// is searched after the read, with the same matches.
    #[test]
    fn regexp_patterns_that_do_not_fit_in_the_memory_given_are_searched_after_the_read() {
        let rules = rules(&format!("{RULES}{MORE_RULES}"));
        let plants = fed_plants();
        let spots: Vec<(usize, usize)> = (0..plants.len() * 3).map(|k| (100 + k * 47, k)).collect();
        let h = haystack_of(&plants, 5000, &spots, 7);
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 61, 61 * 8).unwrap();
        let want = evaluate(&rules, &h, usize::MAX);
        let regex = |i: usize| rules.patterns[i].regex_fullword().is_some();
        let mut seen = [0; 2];
        for search_bytes in [0, 2000, 20_000, usize::MAX] {
            let whole = WholeLimits {
                materialize: 0,
                search_bytes,
                ..WholeLimits::NONE
            };
            let pass = read_once(&rules, &cache, &whole).expect("the object was read");
            let held = |i: usize| pass.found[i].is_some();
            seen[0] += (0..rules.patterns.len())
                .filter(|&i| pass.run[i] && regex(i) && held(i))
                .count();
            seen[1] += (0..rules.patterns.len())
                .filter(|&i| pass.run[i] && regex(i) && !held(i))
                .count();
            if search_bytes == 0 {
                assert!((0..rules.patterns.len()).all(|i| !(regex(i) && held(i))));
            }
            if search_bytes == usize::MAX {
                assert!((0..rules.patterns.len()).all(|i| !pass.run[i] || held(i)));
            }
            let got = evaluate_steps(&rules, &cache, usize::MAX, Some(pass));
            assert_eq!(want.matches, got.matches, "{search_bytes} bytes");
        }
        assert!(seen[0] > 0 && seen[1] > 0, "{seen:?}");
    }

    /// A pattern with more matches than the search keeps is left to the
    /// search after the read, which says it is incomplete.
    #[test]
    fn a_pattern_past_the_match_cap_is_left_to_the_search_after_the_read() {
        let rules = rules(
            r#"rule z { strings: $a = { 00 00 } $b = "\x00\x00\x00" $c = /\x00\x00\x00\x00/
               condition: #a > 5 and #b > 5 and #c > 5 }"#,
        );
        let h = vec![0u8; super::super::matcher::MAX_MATCHES + 10];
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 1 << 16, 1 << 20).unwrap();
        let whole = WholeLimits {
            materialize: 0,
            ..WholeLimits::NONE
        };
        let pass = read_once(&rules, &cache, &whole).expect("the object was read");
        assert!(pass.run.iter().all(|&r| r));
        assert!(
            pass.found.iter().all(Option::is_none),
            "{}",
            pass.found.iter().flatten().count()
        );
        let e = evaluate_steps(&rules, &cache, usize::MAX, Some(pass));
        assert!(!e.complete);
        assert!(
            e.matches
                .iter()
                .all(|m| m.len() == super::super::matcher::MAX_MATCHES)
        );
    }

    /// A regexp the lazy DFAs cannot follow over these bytes is left to the
    /// search after the read, which reads the object whole or reports it.
    #[test]
    fn a_regexp_the_read_cannot_follow_is_left_to_the_search_after_it() {
        let rules =
            rules(r#"rule u { strings: $a = /(?u)\bcaf/ $b = "caf" condition: all of them }"#);
        let h = b"\xe9caf caf".to_vec();
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 3, 12).unwrap();
        let want = evaluate(&rules, &h, usize::MAX);
        for materialize in [usize::MAX, 0] {
            let whole = WholeLimits {
                materialize,
                ..WholeLimits::NONE
            };
            let pass = read_once(&rules, &cache, &whole).expect("the object was read");
            assert!(pass.found[0].is_none() && pass.found[1].is_some());
            let got = Scanner::new(&rules).evaluate(&cache, &whole, Some(pass));
            let without = Scanner::new(&rules).evaluate(&cache, &whole, None);
            assert_eq!(got.matches, without.matches);
            assert_eq!(got.complete, without.complete);
            assert_eq!(got.complete, materialize == usize::MAX);
            if materialize == usize::MAX {
                assert_eq!(got.matches, want.matches);
            }
        }
    }

    #[test]
    fn a_regex_the_stepped_search_cannot_follow_is_read_whole_or_reported() {
        // A Unicode word boundary against non-ASCII bytes stops the lazy DFA.
        let rules = rules(r#"rule u { strings: $a = /(?u)\bcaf/ condition: $a }"#);
        let h = b"\xe9caf caf".to_vec();
        let want = evaluate(&rules, &h, usize::MAX);
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 3, 12).unwrap();
        let whole = evaluate(&rules, &cache, usize::MAX);
        assert!(whole.complete);
        assert_eq!(want.matches, whole.matches);
        let cut = evaluate(&rules, &cache, 0);
        assert!(!cut.complete, "a search that could not run must say so");
    }

    #[test]
    fn modules_read_a_large_object_only_when_it_may_be_of_their_format() {
        let rules = rules(
            r#"import "pe"
               rule p { condition: pe.is_pe and pe.number_of_sections > 0 }
               rule n { condition: not pe.is_pe }"#,
        );
        let pe = include_bytes!("../../tests/testdata/tiny_pe32.exe").to_vec();
        let cache = BlockCache::with_sizes(Cursor::new(pe.clone()), 64, 1024).unwrap();
        let whole = evaluate(&rules, &cache, usize::MAX);
        assert!(whole.complete);
        assert_eq!(whole.matching, evaluate(&rules, &pe, usize::MAX).matching);
        assert_eq!(whole.matching, [0]);
        // Too large to read whole, and it starts as a PE does.
        assert!(!evaluate(&rules, &cache, 0).complete);
        // Not a PE: the parser's answer is known without reading it.
        let other = b"PK\x03\x04 not a PE".to_vec();
        let cache = BlockCache::with_sizes(Cursor::new(other), 4, 16).unwrap();
        let e = evaluate(&rules, &cache, 0);
        assert!(e.complete);
        assert_eq!(e.matching, [1]);
    }

    #[test]
    fn a_pattern_past_the_match_cap_is_incomplete_in_memory_too() {
        let rules = rules(r#"rule z { strings: $a = { 00 00 } condition: #a > 5 }"#);
        let h = vec![0u8; super::super::matcher::MAX_MATCHES + 10];
        let e = evaluate(&rules, &h, usize::MAX);
        assert_eq!(e.matches[0].len(), super::super::matcher::MAX_MATCHES);
        assert!(!e.complete);
    }

    /// A pattern anchored at an offset, every use of it naming that one, is
    /// looked for there alone, as yara-x does: its matches elsewhere, past
    /// the match cap or not, leave the scan complete. Held, streamed, and
    /// through the read.
    #[test]
    fn a_pattern_anchored_at_an_offset_is_looked_for_there_alone() {
        use crate::yara::matcher::{MAX_MATCHES, Match};
        let mut zeros = vec![0u8; MAX_MATCHES + 10];
        zeros.extend_from_slice(b"hello");
        let mut mz = zeros.clone();
        mz[..2].copy_from_slice(b"MZ");
        for v in [r"{ 00 00 }", r#""\x00\x00""#, r"/\x00\x00/"] {
            let src = format!(
                r#"rule r {{ strings: $v = {v} $m = "hello" condition: $m and not $v at 0 }}"#
            );
            let rules = rules(&src);
            assert_eq!(rules.anchored, [Some(0), None], "{src}");
            for (data, matching) in [(&zeros, false), (&mz, true)] {
                let cache =
                    BlockCache::with_sizes(Cursor::new(data.clone()), 1 << 16, 1 << 20).unwrap();
                let whole = WholeLimits {
                    materialize: 0,
                    ..WholeLimits::NONE
                };
                let pass = read_once(&rules, &cache, &whole).expect("the object was read");
                let at_zero = [Match { offset: 0, len: 2 }];
                for e in [
                    evaluate(&rules, data, usize::MAX),
                    evaluate(&rules, &cache, 0),
                    Scanner::new(&rules).evaluate(&cache, &whole, Some(pass)),
                ] {
                    assert!(e.complete, "{src}");
                    assert_eq!(e.matching == [0], matching, "{src}");
                    let want = if matching { &[][..] } else { &at_zero[..] };
                    assert_eq!(e.matches[0], want, "{src}");
                }
            }
            // One search, which no limit on the steps of a search for every
            // match cuts.
            let few = WholeLimits {
                regex_steps: 1000,
                ..WholeLimits::NONE
            };
            let e = Scanner::new(&rules).evaluate(&&zeros[..], &few, None);
            assert!(e.complete && e.matching.is_empty(), "{src}");
        }
        // Streamed, an anchored pattern the read left is looked for in the
        // start alone.
        struct Counted(Cursor<Vec<u8>>, std::rc::Rc<std::cell::Cell<usize>>);
        impl std::io::Read for Counted {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(b)?;
                self.1.set(self.1.get() + n);
                Ok(n)
            }
        }
        impl std::io::Seek for Counted {
            fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0.seek(p)
            }
        }
        for v in [r"{ 00 00 }", r#""\x00\x00""#] {
            let rules = rules(&format!(
                "rule r {{ strings: $v = {v} condition: not $v at 0 }}"
            ));
            let read = std::rc::Rc::new(std::cell::Cell::new(0));
            let src = Counted(Cursor::new(zeros.clone()), read.clone());
            let cache = BlockCache::with_sizes(src, 1 << 12, 1 << 16).unwrap();
            let whole = WholeLimits {
                materialize: 0,
                ..WholeLimits::NONE
            };
            let mut pass = read_once(&rules, &cache, &whole).expect("the object was read");
            pass.found[0] = None;
            read.set(0);
            let e = Scanner::new(&rules).evaluate(&cache, &whole, Some(pass));
            assert!(e.complete && e.matching.is_empty(), "{v}");
            assert!(read.get() <= 1 << 17, "{v}: {} bytes read", read.get());
        }
        // Used otherwise too, or at two offsets, it is searched for whole.
        for cond in ["$v at 0 and #v > 5", "$v at 0 or $v at 2"] {
            let rules = rules(&format!(
                "rule r {{ strings: $v = {{ 00 00 }} condition: {cond} }}"
            ));
            assert_eq!(rules.anchored, [None], "{cond}");
            assert!(!evaluate(&rules, &zeros, usize::MAX).complete, "{cond}");
        }
    }

    /// A pattern of each kind, anchored at an offset, has there the matches
    /// it has there unanchored, and no other: held, streamed, and through the
    /// read.
    #[test]
    fn an_anchored_pattern_matches_there_as_it_does_unanchored() {
        let decls = [
            r#""needle""#,
            r#""NeEdLe" nocase"#,
            r#""wide" wide ascii"#,
            r#""word" fullword"#,
            r#""wword" wide fullword"#,
            r#""xored" xor(1-3)"#,
            r#""xorword" xor(1-2) fullword"#,
            r#""password123" base64"#,
            r#""secret!" base64wide"#,
            r"{ 4D 5A ?? ?? [2-40] 50 45 }",
            r"{ 6E 65 ( 65 | 64 ) [-] 6C 65 }",
            r"/ne+dle[0-9]*/",
            r"/h.llo/is",
            r"/c[a-z]+e/ wide ascii",
            r"/word[0-9]?/ fullword",
            r"/\bword/",
            r"/x[^x]{1,300}y/s",
        ];
        let kinds = plants().len();
        let spots: Vec<(usize, usize)> = (0..kinds).map(|k| (k * 41, k)).collect();
        let h = haystack(kinds * 41 + 7, &spots, 3);
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 7, 56).unwrap();
        let whole = WholeLimits {
            materialize: 0,
            ..WholeLimits::NONE
        };
        let rule = |decl: &str, cond: &str| {
            rules(&format!(
                "rule r {{ strings: $x = {decl} condition: {cond} }}"
            ))
        };
        for decl in decls {
            let all = evaluate(&rule(decl, "$x"), &h, usize::MAX).matches[0].clone();
            assert!(!all.is_empty(), "{decl}");
            let mut offsets: Vec<usize> =
                all.iter().flat_map(|m| [m.offset, m.offset + 1]).collect();
            offsets.extend([0, 1, h.len() - 1, h.len(), h.len() + 5]);
            for at in offsets {
                let rules = rule(decl, &format!("$x at {at}"));
                assert_eq!(rules.anchored, [Some(at)], "{decl} at {at}");
                let want: Vec<_> = all.iter().filter(|m| m.offset == at).cloned().collect();
                let pass = read_once(&rules, &cache, &whole).expect("the object was read");
                for (how, e) in [
                    ("held", evaluate(&rules, &h, usize::MAX)),
                    ("streamed", evaluate(&rules, &cache, 0)),
                    (
                        "read",
                        Scanner::new(&rules).evaluate(&cache, &whole, Some(pass)),
                    ),
                ] {
                    assert!(e.complete, "{decl} at {at}, {how}");
                    assert_eq!(e.matches[0], want, "{decl} at {at}, {how}");
                    assert_eq!(
                        e.matching.is_empty(),
                        want.is_empty(),
                        "{decl} at {at}, {how}"
                    );
                }
            }
        }
    }

    /// Which uses of a pattern anchor it.
    #[test]
    fn a_pattern_is_anchored_when_every_use_names_one_offset() {
        for (cond, want) in [
            ("$a at 0", [Some(0), None]),
            ("$a at 0x10 and not $a at 16", [Some(16), None]),
            ("any of ($a, $b) at 4", [Some(4), Some(4)]),
            ("$a at 0 and $b", [Some(0), None]),
            ("$a at 0 or $a at 1", [None, None]),
            ("$a at 0 and #a > 1", [None, None]),
            ("$a at 0 and @a[1] == 0", [None, None]),
            ("$a at 0 and !a[1] == 2", [None, None]),
            ("$a in (0..10)", [None, None]),
            ("$a at filesize - 2", [None, None]),
            ("$a at -1", [None, None]),
            ("any of them", [None, None]),
            ("for any of ($a) : ($ at 0)", [None, None]),
            ("for any i in (0..1) : ($a at i)", [None, None]),
            ("$a at 0 and any of them", [None, None]),
            ("true", [None, None]),
        ] {
            let src = format!(r#"rule r {{ strings: $a = "AB" $b = "CD" condition: {cond} }}"#);
            assert_eq!(rules(&src).anchored, want, "{cond}");
        }
        // Each rule's patterns are its own.
        let two = rules(
            r#"rule p { strings: $a = "AB" condition: $a at 0 }
               rule q { strings: $a = "AB" condition: $a at 4 }"#,
        );
        assert_eq!(two.anchored, [Some(0), Some(4)]);
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
    /// ruleset from source (which includes the atom index build) vs.
    /// deserializing the serialized compiled form (which skips it), and
    /// prints the timings + blob size. Ignored by default; run with:
    ///
    /// ```text
    /// cargo test -p exav-core --features yara --lib -- --ignored --nocapture load_time
    /// ```
    ///
    /// The source ruleset path can be overridden with `EXAV_DEBUG_YARA_BENCH_RULES`
    /// (e.g. a concatenated signature-base tree); it defaults to the in-repo
    /// `corpus/securiteinfo/securiteinfo.yara`.
    #[test]
    #[ignore = "perf measurement, not a correctness gate"]
    fn load_time_from_source_vs_deserialize() {
        use crate::yara::compiler::Compiler;
        use std::time::Instant;

        let path = std::env::var("EXAV_DEBUG_YARA_BENCH_RULES").unwrap_or_else(|_| {
            format!(
                "{}/../../corpus/securiteinfo/securiteinfo.yara",
                env!("CARGO_MANIFEST_DIR")
            )
        });
        let Ok(src) = std::fs::read_to_string(&path) else {
            eprintln!("skip: ruleset not found at {path}");
            return;
        };

        // Compile from source (lenient, per-rule): the cost a load must avoid.
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

        // Deserialize (the load path): read back the atom index + IR, and
        // recompile only the per-pattern regexes, skipping the index BUILD.
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
        eprintln!("compile from source (incl. atom index build): {compile_from_source:?}");
        eprintln!("serialize compiled form:                      {serialize:?}");
        eprintln!("deserialize (load, skips index build):        {deserialize:?}");
        if deserialize.as_nanos() > 0 {
            eprintln!(
                "speedup (compile / deserialize):                  {:.1}x",
                compile_from_source.as_secs_f64() / deserialize.as_secs_f64()
            );
        }
    }
}
