//! Atom-based Aho-Corasick prefilter for the YARA string matcher.
//!
//! Scanning every compiled pattern over the whole buffer (one `find_all` per
//! pattern) is O(patterns × bytes) and dominates scan time on many-rule sets.
//! This module builds a *required-literal gate*: for each pattern we extract one
//! or more **atoms** — literal byte substrings that MUST appear in EVERY match of
//! the pattern. A single shared Aho-Corasick automaton (daachorse) is run over
//! the buffer ONCE; a pattern's `find_all` is then executed ONLY if one of its
//! atoms was found (or if the pattern is *ungated* — has no provable required
//! literal, e.g. `xor`, `/a+/`, alternations with an atomless branch).
//!
//! ## Why this is false-negative-safe
//!
//! An atom is a literal that is present in *every* buffer the pattern can match.
//! So if none of a pattern's atoms occur in the buffer, the pattern provably has
//! zero matches, and returning an empty match list for it is IDENTICAL to running
//! `find_all`. When we cannot prove such a literal exists, the pattern is left
//! **ungated** and always scanned. We only ever *skip* a pattern whose required
//! literal is provably absent — never a pattern that might match.
//!
//! Required literals for regexp / hex patterns are extracted with
//! `regex_syntax`'s literal `Extractor` (the same analysis the `regex` crate uses
//! for its own prefilters): a finite prefix (or suffix) literal `Seq` with no
//! empty member is a sound set of required literals — every match begins (ends)
//! with one of them. When the extractor gives up it returns an infinite `Seq`,
//! which we treat as "no required literal" → ungated.

use std::collections::HashMap;

use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder};
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use serde::{Deserialize, Serialize};

use crate::yara::matcher::{parse_hir, widen_hir, Base64Sub, Needle};

/// Maximum atom window length taken from a literal / base64 needle. A longer
/// window is a strictly more selective (rarer) gate; the cap bounds the shared
/// automaton's size for pathologically long literals.
const MAX_ATOM: usize = 16;

/// The gate classification of one compiled pattern.
pub(crate) enum Gate {
    /// No provable required literal — the pattern is always scanned.
    Ungated,
    /// The pattern matches only if at least ONE of these atoms is present
    /// (a disjunction). `nocase` means the atoms are ASCII-lowercased and are
    /// searched in the ASCII-lowercased buffer.
    Atoms { atoms: Vec<Vec<u8>>, nocase: bool },
}

// ---------------------------------------------------------------------------
// Per-pattern atom extraction (compile time)
// ---------------------------------------------------------------------------

/// Selectivity score of a candidate atom window, reused verbatim from the
/// AV-engine heuristic (`engine::parse::anchor_score`): a low-entropy run (a
/// constant byte, or a 2-symbol repeat) matches repetitive content millions of
/// times and is a terrible prefilter even when long, so it is down-ranked; a
/// varied run scores its length (longer = rarer = better). Kept byte-identical
/// here because `engine::parse` is a private module unreachable from `yara`.
fn anchor_score(b: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &x in b {
        if !seen[x as usize] {
            seen[x as usize] = true;
            distinct += 1;
        }
    }
    match distinct {
        0 | 1 => 1,
        2 => 3.min(b.len()),
        _ => b.len(),
    }
}

/// Picks the most selective window of length `min(bytes.len(), MAX_ATOM)` from a
/// required literal. Any contiguous substring of a required literal is itself
/// required, so this preserves soundness while choosing a rarer anchor.
fn best_window(bytes: &[u8]) -> &[u8] {
    let len = bytes.len().min(MAX_ATOM);
    if bytes.len() <= MAX_ATOM {
        return bytes;
    }
    let mut best_start = 0;
    let mut best_score = 0;
    for start in 0..=(bytes.len() - len) {
        let score = anchor_score(&bytes[start..start + len]);
        if score > best_score {
            best_score = score;
            best_start = start;
        }
    }
    &bytes[best_start..best_start + len]
}

/// Gate for a `Literal` pattern (plain/`nocase`/`wide`, no `xor`). Each non-empty
/// needle contributes one required-literal window; the pattern matches iff SOME
/// needle matches, so the atom set is the disjunction over needles. An `xor`
/// pattern transforms the bytes and cannot be gated by a plain automaton, so its
/// caller passes `xor_present = true` → ungated.
pub(crate) fn literal_gate(needles: &[Needle], xor_present: bool) -> Gate {
    if xor_present {
        return Gate::Ungated;
    }
    // `compile_text` sets `nocase` uniformly across a pattern's needles.
    let nocase = needles.iter().any(|n| n.nocase);
    let mut atoms = Vec::new();
    for n in needles {
        if n.bytes.is_empty() {
            // An empty needle never matches (see `find_all`), so it imposes no
            // requirement and contributes no atom.
            continue;
        }
        let mut a = best_window(&n.bytes).to_vec();
        if nocase {
            a.make_ascii_lowercase();
        }
        atoms.push(a);
    }
    if atoms.is_empty() {
        Gate::Ungated
    } else {
        Gate::Atoms { atoms, nocase }
    }
}

/// Gate for a `base64`/`base64wide` pattern. Each `Base64Sub::searched` is the
/// literal that `find_all` requires at a candidate position, and the pattern
/// matches iff SOME entry does, so the disjunction of the searched bytes is a
/// sound required-literal set.
pub(crate) fn base64_gate(entries: &[Base64Sub]) -> Gate {
    if entries.is_empty() {
        return Gate::Ungated;
    }
    let mut atoms = Vec::with_capacity(entries.len());
    for e in entries {
        if e.searched.is_empty() {
            return Gate::Ungated;
        }
        atoms.push(best_window(&e.searched).to_vec());
    }
    Gate::Atoms {
        atoms,
        nocase: false,
    }
}

/// Gate for a regexp / hex pattern. Parses `src` (with the SAME syntax config the
/// matcher compiles it under, via [`parse_hir`]) into an HIR and asks
/// `regex_syntax` for the required prefix and suffix literals, keeping the more
/// selective sound set. Returns [`Gate::Ungated`] whenever no such set exists
/// (regex too permissive, a nullable/optional branch, extractor gave up, …).
pub(crate) fn regex_gate(src: &str, case_insensitive: bool, dot_matches_new_line: bool) -> Gate {
    regex_gate_ex(src, case_insensitive, dot_matches_new_line, false)
}

/// Like [`regex_gate`], but for a `wide` regexp (`wide = true`) the HIR is
/// widened (each matched byte followed by `\x00`) *before* literal extraction, so
/// the required literals are the zero-interleaved bytes actually present in the
/// buffer. The widening is [`widen_hir`], identical to what the matcher compiles,
/// so the extracted atoms are a sound required-literal set for the wide form. If
/// widening/extraction yields nothing usable the pattern is left ungated
/// (false-negative-safe).
pub(crate) fn regex_gate_ex(
    src: &str,
    case_insensitive: bool,
    dot_matches_new_line: bool,
    wide: bool,
) -> Gate {
    let hir = match parse_hir(src, case_insensitive, dot_matches_new_line) {
        Ok(h) => h,
        Err(_) => return Gate::Ungated,
    };
    let hir = if wide { widen_hir(hir) } else { hir };

    let prefix = required_literals(&hir, ExtractKind::Prefix);
    let suffix = required_literals(&hir, ExtractKind::Suffix);
    let chosen = pick_more_selective(prefix, suffix);

    match chosen {
        None => Gate::Ungated,
        Some(mut atoms) => {
            if case_insensitive {
                // The HIR encodes case folding as classes; the extractor emits
                // per-case literals. Lowercasing + de-duplicating collapses them
                // and lets one atom gate over the lowercased buffer.
                for a in &mut atoms {
                    a.make_ascii_lowercase();
                }
                atoms.sort_unstable();
                atoms.dedup();
            }
            Gate::Atoms {
                atoms,
                nocase: case_insensitive,
            }
        }
    }
}

/// Combines two gates for a pattern that matches iff EITHER branch matches (used
/// for a `wide ascii` regexp: the plain-form gate OR the wide-form gate). The
/// atom sets are unioned (a required literal of either branch is a candidate);
/// if either branch is ungated, or the two branches disagree on case-folding, the
/// combined gate is [`Gate::Ungated`] — never skip a pattern that might match.
pub(crate) fn combine_gates(a: Gate, b: Gate) -> Gate {
    match (a, b) {
        (Gate::Ungated, _) | (_, Gate::Ungated) => Gate::Ungated,
        (
            Gate::Atoms {
                atoms: mut xa,
                nocase: na,
            },
            Gate::Atoms {
                atoms: xb,
                nocase: nb,
            },
        ) => {
            if na != nb {
                return Gate::Ungated;
            }
            xa.extend(xb);
            Gate::Atoms {
                atoms: xa,
                nocase: na,
            }
        }
    }
}

/// Extracts a sound set of required literals for `kind` (prefix or suffix) from
/// `hir`. Returns `None` (no usable requirement) when the literal sequence is
/// infinite, empty, or contains an empty literal (i.e. some match has no such
/// required literal). A finite, all-non-empty `Seq` is a sound over-approximation
/// the `regex` crate itself relies on: every match begins (ends) with one member.
fn required_literals(hir: &regex_syntax::hir::Hir, kind: ExtractKind) -> Option<Vec<Vec<u8>>> {
    let mut extractor = Extractor::new();
    extractor.kind(kind);
    let seq = extractor.extract(hir);
    let lits = seq.literals()?;
    if lits.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(lits.len());
    for l in lits {
        let b = l.as_bytes();
        if b.is_empty() {
            // A required literal that can be empty gates nothing.
            return None;
        }
        out.push(best_window(b).to_vec());
    }
    Some(out)
}

/// Picks the more selective of two candidate required-literal sets. A set is only
/// as strong as its weakest (lowest-scoring) atom, since ANY atom hit triggers a
/// scan, so we rank by the minimum [`anchor_score`] across the set.
fn pick_more_selective(a: Option<Vec<Vec<u8>>>, b: Option<Vec<Vec<u8>>>) -> Option<Vec<Vec<u8>>> {
    let score = |s: &[Vec<u8>]| s.iter().map(|a| anchor_score(a)).min().unwrap_or(0);
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => {
            if score(&y) > score(&x) {
                Some(y)
            } else {
                Some(x)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The compiled gate (one automaton over all atoms)
// ---------------------------------------------------------------------------

/// De-duplicating pool of atoms feeding one Aho-Corasick automaton. Distinct
/// atoms map to automaton values; each value carries the list of pattern ids that
/// share that atom (`groups`).
#[derive(Default)]
struct Pool {
    index: HashMap<Vec<u8>, usize>,
    atoms: Vec<Vec<u8>>,
    groups: Vec<Vec<usize>>,
}

impl Pool {
    fn add(&mut self, atom: Vec<u8>, pid: usize) {
        let idx = match self.index.get(&atom) {
            Some(&i) => i,
            None => {
                let i = self.atoms.len();
                self.index.insert(atom.clone(), i);
                self.atoms.push(atom);
                self.groups.push(Vec::new());
                i
            }
        };
        if !self.groups[idx].contains(&pid) {
            self.groups[idx].push(pid);
        }
    }

    /// Builds the automaton. On a (very unlikely) build failure the pool's
    /// patterns are force-ungated so they are still scanned — never silently
    /// dropped.
    fn finish(
        self,
        ungated: &mut [bool],
    ) -> (Option<DoubleArrayAhoCorasick<u32>>, Vec<Vec<usize>>) {
        if self.atoms.is_empty() {
            return (None, Vec::new());
        }
        match DoubleArrayAhoCorasickBuilder::new()
            .match_kind(daachorse::MatchKind::Standard)
            .build_with_values(self.atoms.iter().zip(0u32..))
        {
            Ok(ac) => (Some(ac), self.groups),
            Err(_) => {
                for g in &self.groups {
                    for &pid in g {
                        ungated[pid] = true;
                    }
                }
                (None, Vec::new())
            }
        }
    }
}

/// The prefilter gate for a whole compiled rule set. Case-sensitive atoms are
/// searched in the raw buffer; `nocase` atoms in an ASCII-lowercased copy.
pub(crate) struct PatternGate {
    ac_cs: Option<DoubleArrayAhoCorasick<u32>>,
    groups_cs: Vec<Vec<usize>>,
    ac_ci: Option<DoubleArrayAhoCorasick<u32>>,
    groups_ci: Vec<Vec<usize>>,
    /// Per pattern id: `true` = always scan (ungated).
    ungated: Vec<bool>,
    /// Number of patterns with a required-literal gate (diagnostics).
    gated: usize,
    /// Kill switch: when set (via `EXAV_YARA_NO_GATE`), the prefilter is bypassed
    /// and every pattern is scanned. A safety valve — results are identical to a
    /// gated scan by construction, but this lets an operator rule the prefilter
    /// out if a gate bug is ever suspected. Read once at build time (never on the
    /// hot path).
    bypass: bool,
}

impl PatternGate {
    /// Builds the gate from one [`Gate`] per pattern (index == pattern id).
    pub(crate) fn from_gates(gates: &[Gate]) -> PatternGate {
        let n = gates.len();
        let mut ungated = vec![false; n];
        let mut cs = Pool::default();
        let mut ci = Pool::default();
        for (pid, g) in gates.iter().enumerate() {
            match g {
                Gate::Ungated => ungated[pid] = true,
                Gate::Atoms { atoms, nocase } => {
                    let pool = if *nocase { &mut ci } else { &mut cs };
                    for a in atoms {
                        pool.add(a.clone(), pid);
                    }
                }
            }
        }
        let (ac_cs, groups_cs) = cs.finish(&mut ungated);
        let (ac_ci, groups_ci) = ci.finish(&mut ungated);
        // Whatever remains not-ungated after the (possibly failing) builds is
        // in fact gated.
        let gated = ungated.iter().filter(|&&u| !u).count();
        PatternGate {
            ac_cs,
            groups_cs,
            ac_ci,
            groups_ci,
            ungated,
            gated,
            bypass: std::env::var_os("EXAV_YARA_NO_GATE").is_some(),
        }
    }

    /// Number of patterns that carry a required-literal gate.
    #[allow(dead_code)]
    pub(crate) fn gated_count(&self) -> usize {
        self.gated
    }

    /// Returns, per pattern id, whether `find_all` must be run: `true` for every
    /// ungated pattern, plus every gated pattern one of whose atoms occurs in
    /// `data`. A gated pattern whose atoms are all absent provably has no match.
    pub(crate) fn select(&self, data: &[u8]) -> Vec<bool> {
        if self.bypass {
            return vec![true; self.ungated.len()];
        }
        let mut run = self.ungated.clone();
        // Number of gated patterns still to resolve; lets us stop scanning once
        // every pattern is already slated to run (dense buffers).
        let mut pending = run.iter().filter(|&&r| !r).count();

        if pending > 0 {
            if let Some(ac) = &self.ac_cs {
                for m in ac.find_overlapping_iter(data) {
                    for &pid in &self.groups_cs[m.value() as usize] {
                        if !run[pid] {
                            run[pid] = true;
                            pending -= 1;
                        }
                    }
                    if pending == 0 {
                        break;
                    }
                }
            }
        }

        if pending > 0 {
            if let Some(ac) = &self.ac_ci {
                let lower = data.to_ascii_lowercase();
                for m in ac.find_overlapping_iter(&lower) {
                    for &pid in &self.groups_ci[m.value() as usize] {
                        if !run[pid] {
                            run[pid] = true;
                            pending -= 1;
                        }
                    }
                    if pending == 0 {
                        break;
                    }
                }
            }
        }
        run
    }
}

// ---------------------------------------------------------------------------
// Serialization of the compiled gate
// ---------------------------------------------------------------------------
//
// The atom automaton is the expensive artifact this whole module exists to
// avoid rebuilding on load, so the gate is serialized in its COMPILED form: each
// daachorse automaton travels as its own byte serialization (`serialize`), and
// the per-atom pattern-id groups + the ungated bitmap travel as plain data. On
// load the automaton is reconstructed via daachorse's checked `deserialize` (no
// rebuild). `bypass` is NOT serialized — it is an operator kill switch read
// afresh from the environment on load, exactly as at build time.

/// True when the prefilter kill switch is set. Read once (build or load time),
/// never on the hot path.
fn bypass_env() -> bool {
    std::env::var_os("EXAV_YARA_NO_GATE").is_some()
}

impl Serialize for PatternGate {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let ac_cs = self.ac_cs.as_ref().map(|ac| ac.serialize());
        let ac_ci = self.ac_ci.as_ref().map(|ac| ac.serialize());
        (
            ac_cs,
            &self.groups_cs,
            ac_ci,
            &self.groups_ci,
            &self.ungated,
            self.gated,
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for PatternGate {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        type Wire = (
            Option<Vec<u8>>,
            Vec<Vec<usize>>,
            Option<Vec<u8>>,
            Vec<Vec<usize>>,
            Vec<bool>,
            usize,
        );
        let (ac_cs_bytes, groups_cs, ac_ci_bytes, groups_ci, ungated, gated): Wire =
            Deserialize::deserialize(d)?;

        fn rebuild<E: serde::de::Error>(
            bytes: Option<Vec<u8>>,
        ) -> Result<Option<DoubleArrayAhoCorasick<u32>>, E> {
            match bytes {
                None => Ok(None),
                Some(b) => {
                    // Checked deserialize: rejects data that would cause
                    // out-of-bounds access (the database is a trusted artifact,
                    // but a corrupt/mismatched blob must fail loudly, not misread).
                    let (ac, _rest) =
                        DoubleArrayAhoCorasick::<u32>::deserialize(&b).map_err(|e| {
                            serde::de::Error::custom(format!("bad atom automaton: {e}"))
                        })?;
                    Ok(Some(ac))
                }
            }
        }

        Ok(PatternGate {
            ac_cs: rebuild(ac_cs_bytes)?,
            groups_cs,
            ac_ci: rebuild(ac_ci_bytes)?,
            groups_ci,
            ungated,
            gated,
            bypass: bypass_env(),
        })
    }
}
