//! Atom prefilter for the YARA string matcher.
//!
//! Scanning every compiled pattern over the whole buffer (one `find_all` per
//! pattern) is O(patterns × bytes) and dominates scan time on many-rule sets.
//! This module builds a *required-literal gate*: for each pattern we extract one
//! or more **atoms**: literal byte substrings that MUST appear in EVERY match of
//! the pattern. One anchor index over every atom ([`crate::grams`], the one the
//! signature engine uses) is swept over the buffer ONCE; a pattern's `find_all`
//! is then executed ONLY if one of its
//! atoms was found (or if the pattern is *ungated*, i.e. has no provable required
//! literal, e.g. `xor`, `/a+/`, alternations with an atomless branch).
//!
//! ## Why this is false-negative-safe
//!
//! An atom is a literal that is present in *every* buffer the pattern can match.
//! So if none of a pattern's atoms occur in the buffer, the pattern provably has
//! zero matches, and returning an empty match list for it is IDENTICAL to running
//! `find_all`. When we cannot prove such a literal exists, the pattern is left
//! **ungated** and always scanned. We only ever *skip* a pattern whose required
//! literal is provably absent, never a pattern that might match.
//!
//! Required literals for regexp / hex patterns are extracted with
//! `regex_syntax`'s literal `Extractor` (the same analysis the `regex` crate uses
//! for its own prefilters): a finite prefix (or suffix) literal `Seq` with no
//! empty member is a sound set of required literals: every match begins (ends)
//! with one of them. When the extractor gives up it returns an infinite `Seq`,
//! which we treat as "no required literal" → ungated.

use std::collections::HashMap;

use regex_syntax::hir::literal::{ExtractKind, Extractor};
use serde::{Deserialize, Serialize};

use crate::byte_source::ByteSource;
use crate::grams::{structural, sweep, GramStats, Grams, IndexAnchor};
use crate::yara::matcher::{parse_hir, widen_hir, Base64Sub, Needle};

/// Maximum atom window length taken from a literal / base64 needle. A longer
/// window is a strictly more selective (rarer) gate; the cap bounds what the
/// index holds for pathologically long literals.
const MAX_ATOM: usize = 16;

/// The gate classification of one compiled pattern.
pub(crate) enum Gate {
    /// No provable required literal, so the pattern is always scanned.
    Ungated,
    /// The pattern matches only if at least ONE of these atoms is present
    /// (a disjunction). `nocase` means the atoms are ASCII-lowercased and are
    /// searched in the ASCII-lowercased buffer.
    Atoms { atoms: Vec<Vec<u8>>, nocase: bool },
}

// ---------------------------------------------------------------------------
// Per-pattern atom extraction (compile time)
// ---------------------------------------------------------------------------

/// Picks the most selective window of length `min(bytes.len(), MAX_ATOM)` from a
/// required literal, by its bytes alone ([`structural`]). Any contiguous
/// substring of a required literal is itself required, so this preserves
/// soundness while choosing a rarer anchor.
fn best_window(bytes: &[u8]) -> &[u8] {
    let len = bytes.len().min(MAX_ATOM);
    if bytes.len() <= MAX_ATOM {
        return bytes;
    }
    let mut best_start = 0;
    let mut best_score = 0;
    for start in 0..=(bytes.len() - len) {
        let score = structural(&bytes[start..start + len]);
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
/// pattern transforms the bytes and cannot be gated by a plain literal, so its
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
/// combined gate is [`Gate::Ungated`]: never skip a pattern that might match.
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
/// scan, so we rank by the minimum [`structural`] score across the set.
fn pick_more_selective(a: Option<Vec<Vec<u8>>>, b: Option<Vec<Vec<u8>>>) -> Option<Vec<Vec<u8>>> {
    let score = |s: &[Vec<u8>]| s.iter().map(|a| structural(a)).min().unwrap_or(0);
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
// The compiled gate (one index over all atoms)
// ---------------------------------------------------------------------------

/// De-duplicating pool of the atoms of one case. Distinct atoms are values of
/// the index; each value carries the list of pattern ids that share that atom
/// (`groups`).
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
}

/// The prefilter gate for a whole compiled rule set: one index over every
/// atom, the case-sensitive ones in partition 0 and the `nocase` ones,
/// lowercased, in partition 1, found in the one read of the object.
pub(crate) struct PatternGate {
    grams: Grams,
    /// Per partition, per atom, the patterns behind it.
    groups: [Vec<Vec<usize>>; 2],
    /// Per pattern id: `true` = always scan (ungated).
    ungated: Vec<bool>,
}

impl PatternGate {
    /// Builds the gate from one [`Gate`] per pattern (index == pattern id).
    pub(crate) fn from_gates(gates: &[Gate]) -> PatternGate {
        let mut ungated = vec![false; gates.len()];
        let mut pools: [Pool; 2] = Default::default();
        for (pid, g) in gates.iter().enumerate() {
            match g {
                // A pattern with no atom at all would never be slated to run.
                Gate::Atoms { atoms, nocase }
                    if !atoms.is_empty() && atoms.iter().all(|a| !a.is_empty()) =>
                {
                    for a in atoms {
                        pools[*nocase as usize].add(a.clone(), pid);
                    }
                }
                _ => ungated[pid] = true,
            }
        }
        let atoms = || pools.iter().flat_map(|p| &p.atoms);
        let stats = GramStats::build(atoms().count(), |f| atoms().for_each(|a| f(a)));
        let anchors: Vec<IndexAnchor> = pools
            .iter()
            .enumerate()
            .flat_map(|(part, p)| {
                p.atoms
                    .iter()
                    .zip(0u32..)
                    .map(move |(bytes, value)| IndexAnchor {
                        part: part as u32,
                        nocase: part == 1,
                        value,
                        bytes,
                    })
            })
            .collect();
        let grams = Grams::build(&anchors, &stats);
        let [cs, ci] = pools;
        PatternGate {
            grams,
            groups: [cs.groups, ci.groups],
            ungated,
        }
    }

    /// Whether the gate is one for `patterns` patterns: one entry each, and
    /// every gated one behind some atom, so it can be slated to run.
    pub(crate) fn fits(&self, patterns: usize) -> bool {
        let mut reached = self.ungated.clone();
        for &pid in self.groups.iter().flatten().flatten() {
            reached[pid] = true;
        }
        self.ungated.len() == patterns && reached.iter().all(|&r| r)
    }

    /// Number of patterns that carry a required-literal gate.
    #[allow(dead_code)]
    pub(crate) fn gated_count(&self) -> usize {
        self.ungated.iter().filter(|&&u| !u).count()
    }

    /// Returns, per pattern id, whether `find_all` must be run: `true` for every
    /// ungated pattern, plus every gated pattern one of whose atoms occurs in
    /// `data`. A gated pattern whose atoms are all absent provably has no match.
    pub(crate) fn select(&self, src: &dyn ByteSource) -> Vec<bool> {
        let mut run = self.ungated.clone();
        // Number of gated patterns still to resolve; lets us stop scanning once
        // every pattern is already slated to run (dense buffers).
        let mut pending = run.iter().filter(|&&r| !r).count();
        if pending == 0 {
            return run;
        }
        sweep(
            &self.grams,
            &[true, true],
            src,
            &mut |part, value, _, _, _| mark(&self.groups[part], value, &mut run, &mut pending),
        );
        run
    }
}

/// Slates the patterns of atom `value` to run. `false` once none is left.
fn mark(groups: &[Vec<usize>], value: u32, run: &mut [bool], pending: &mut usize) -> bool {
    for &pid in &groups[value as usize] {
        if !run[pid] {
            run[pid] = true;
            *pending -= 1;
        }
    }
    *pending > 0
}

// ---------------------------------------------------------------------------
// Serialization of the compiled gate
// ---------------------------------------------------------------------------
//
// The index travels as its own binary form ([`Grams::write`]), the per-atom
// pattern-id groups and the ungated bitmap as plain data. A load checks every
// id against what it indexes, so a corrupt blob fails loudly, never misreads.

impl Serialize for PatternGate {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use crate::database::Blob;
        let mut index = Vec::new();
        self.grams
            .write(&mut index)
            .map_err(serde::ser::Error::custom)?;
        (Blob(&index), &self.groups, &self.ungated).serialize(s)
    }
}

impl<'de> Deserialize<'de> for PatternGate {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::database::BlobBuf;
        let (index, groups, ungated): (BlobBuf, [Vec<Vec<usize>>; 2], Vec<bool>) =
            Deserialize::deserialize(d)?;
        if groups
            .iter()
            .flatten()
            .flatten()
            .any(|&pid| pid >= ungated.len())
        {
            return Err(serde::de::Error::custom("bad atom pattern id"));
        }
        let mut index = &index.0[..];
        let grams = Grams::read(&mut index, &[groups[0].len(), groups[1].len()])
            .map_err(|e| serde::de::Error::custom(format!("bad atom index: {e}")))?;
        if !index.is_empty() {
            return Err(serde::de::Error::custom("bad atom index: trailing bytes"));
        }
        Ok(PatternGate {
            grams,
            groups,
            ungated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_source::BlockCache;

    /// The gate slates a gated pattern to run exactly when one of its atoms
    /// occurs in the object (lowercased for a `nocase` one), in memory and read
    /// through a cache, runs of one byte included.
    #[test]
    fn the_gate_selects_the_patterns_whose_atoms_occur() {
        let atoms = |a: &[&[u8]], nocase| Gate::Atoms {
            atoms: a.iter().map(|x| x.to_vec()).collect(),
            nocase,
        };
        let gates = vec![
            atoms(&[b"abcd"], false),
            atoms(&[b"xyz", &[0; 12]], false),
            atoms(&[b"hello"], true),
            Gate::Ungated,
            atoms(&[b"zzzz", b"q\0\0\0\0\0\0q"], true),
        ];
        let gate = PatternGate::from_gates(&gates);
        let mut state = 0x5eed_u64;
        let mut next = |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        for _ in 0..300 {
            let mut hay = Vec::new();
            for _ in 0..1 + next(8) {
                match next(4) {
                    0 => hay.extend(std::iter::repeat_n(
                        b"\0zZ"[next(3)],
                        [3, 11, 12, 70, 3000][next(5)],
                    )),
                    1 => hay.extend_from_slice(
                        [&b"abcd"[..], b"HeLLo", b"xyz", b"Q\0\0\0\0\0\0Q"][next(4)],
                    ),
                    _ => hay.extend((0..next(40)).map(|_| b"abcdxyzhelo\0HELOQ"[next(17)])),
                }
            }
            let lower = hay.to_ascii_lowercase();
            let want: Vec<bool> = gates
                .iter()
                .map(|g| match g {
                    Gate::Ungated => true,
                    Gate::Atoms { atoms, nocase } => {
                        let h = if *nocase { &lower } else { &hay };
                        atoms
                            .iter()
                            .any(|a| h.windows(a.len()).any(|w| w == &a[..]))
                    }
                })
                .collect();
            let slice: &[u8] = &hay;
            let cache =
                BlockCache::with_sizes(std::io::Cursor::new(hay.clone()), 64, 1024).unwrap();
            assert_eq!(gate.select(&slice), want, "{hay:?}");
            assert_eq!(gate.select(&cache), want, "{hay:?}");
        }
    }

    /// A pattern with no atom runs always. A gate read back is refused unless
    /// it has an entry per pattern, a way to slate each to run, and nothing
    /// after its index.
    #[test]
    fn a_gate_that_cannot_run_a_pattern_is_refused() {
        let gates = [
            Gate::Atoms {
                atoms: vec![b"abcd".to_vec()],
                nocase: false,
            },
            Gate::Atoms {
                atoms: vec![],
                nocase: false,
            },
        ];
        let gate = PatternGate::from_gates(&gates);
        assert_eq!(gate.select(&&b"nothing"[..]), [false, true]);
        assert!(gate.fits(2) && !gate.fits(3));
        let bytes = rmp_serde::to_vec(&gate).unwrap();
        let mut orphan: PatternGate = rmp_serde::from_slice(&bytes).unwrap();
        orphan.groups[0].clear();
        assert!(!orphan.fits(2), "a gated pattern behind no atom");
        let (index, groups, ungated): (crate::database::BlobBuf, [Vec<Vec<usize>>; 2], Vec<bool>) =
            rmp_serde::from_slice(&bytes).unwrap();
        let mut longer = index.0.clone();
        longer.push(0);
        let tampered =
            rmp_serde::to_vec(&(crate::database::Blob(&longer), groups, ungated)).unwrap();
        assert!(
            rmp_serde::from_slice::<PatternGate>(&tampered).is_err(),
            "trailing bytes"
        );
    }
}
