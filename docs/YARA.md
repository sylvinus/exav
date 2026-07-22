# YARA support — native engine, design, coverage, and reuse

ClamAV loads `.yar`/`.yara` rules by default, so a drop-in must too. exav ships a
**native YARA engine**: it uses the YARA-X parser and compiles rule conditions to
a native tree-walking evaluator. No WASM runtime, no Cranelift, no runtime codegen
at scan time (W^X preserved), and no crypto/JIT crates pulled into the tree.

This document records the design, what is and isn't reused from exav-core, the
supported feature surface, measured real-world coverage, and the roadmap.

## Licensing

yara-x is **BSD-3-Clause** (permissive, MIT-compatible). exav's engine is a
clean-room-*ish* reimplementation that legitimately **reuses and adapts** yara-x
source and test vectors under that license, with attribution: the yara-x
copyright + 3-clause text + disclaimer are retained (`LICENSE-YARA-X`), files
substantially derived from yara-x carry a header note, and the exav project does
**not** use the "YARA-X"/"VirusTotal" names to endorse itself. This is
categorically different from the hard "never derive from ClamAV" rule — that rule
is GPL-specific and does not apply here.

## Where the code lives

YARA support lives **inside `exav-core`**, behind the default-on `yara` feature:

```
crates/exav-core/src/yara/
  mod.rs        public API + `YaraDb` (DB integration, YARA.<id> naming, rejection accounting)
  compiler.rs   yara-x-parser AST → owned IR lowering
  ir.rs         owned condition tree (`Cond`/`Value`) + the native tree-walk evaluator
  matcher.rs    string matching (Literal / Regex / Hex / Base64) → all (offset,length) matches
  scanner.rs    Rules / Scanner / ScanResults, rule references, global/private gating
  base64.rs     base64/base64wide modifier expansion
  error.rs      compile errors
  modules/      math, hash, pe (goblin), string, time
```

The engine is a module of `exav-core`, not a separate crate. It shares
exav-core's `goblin`, hashes and PE parsing rather than carrying its own copies,
and a consumer who wants YARA alone reaches it through `exav_core::yara`.

## Architecture

Pipeline:

```
source → yara-x-parser AST (borrows source) → lower to owned IR
       → Rules → Scanner: match strings over the buffer, then tree-evaluate each rule's condition
```

Because the parser AST is lifetime-bound to the source (`<'src>`), the compiler
**lowers it into an owned IR** so `Rules` is `'static` and cacheable. That
lowering (`compiler.rs`) is the bulk of the work.

- **Front-end — reused:** the `yara-x-parser` crate (tokenizer + AST). It is the
  light half of yara-x (no wasmtime). We do not reimplement the grammar.
- **Strings (`matcher.rs`):** each pattern compiles to a matcher that returns
  **every** `(offset, length)` match — required for `#a` (count), `@a[i]`
  (offset), `!a[i]` (length), `$a at N`, `$a in (a..b)`. Text patterns handle
  `nocase`/`ascii`/`wide`/`fullword`/`xor`/`base64`/`base64wide`; hex patterns are
  lowered to an equivalent byte-regex (`??` → any byte, `[a-b]` jumps → lazy
  `.{a,b}?`) so one regex engine covers hex and regexp alike; regexp patterns run
  anchored at every start offset to match YARA's overlapping-match semantics.
- **Conditions (`ir.rs`):** a native tree-walk over the owned `Cond` tree
  returning `Option<Value>`. Undefined propagation is exact (a missing/OOB value
  is `None`, false in boolean context), matching yara-x. Covers boolean logic,
  `N of`/`any`/`all`/`none`/`P% of`, counts/offsets/lengths/anchors, arithmetic
  and bitwise ops, float, all six comparisons, string operators, `matches /re/`,
  `for … in`/`for … of`/`with` (with a scoped binding environment), `uintN`/`intN`
  reads, `filesize`, `entrypoint`, and module field/function access.
- **Modules (`modules/`):** each imported module parses the scanned bytes once
  per scan into an owned `Value` tree (struct/array/map); conditions resolve field
  access against it. `pe` uses `goblin`; `math`/`hash`/`string`/`time` are native.

## What is reused from exav-core — and what deliberately isn't

Living inside exav-core buys a few **leaf-level** reuses:

- **Dependency dedup:** the `pe` module uses exav-core's `goblin`; the `hash`
  module uses exav-core's `md-5`/`sha1`/`sha2`. There is one copy of each.
- **`math.entropy`** → `exav_core::pe::shannon_entropy`.
- **`entrypoint` / `pe.entry_point`** → `exav_core::pe::layout().entry`.

The three big exav-core subsystems are **intentionally NOT reused** for YARA,
because their semantics are the wrong shape. The reasons are recorded here so
nobody re-attempts it and breaks the diff harness:

- **The AV pattern `engine`** is architected for *"does signature S match, and
  where is its first hit"* over one shared Aho-Corasick automaton. It returns the
  first match only (`verify` → `Option<u64>` start; `match_forward` discards the
  end offset), dedups by signature name, and — critically — is **non-exhaustive by
  design**: the verify-step budget (`SCAN_VERIFY_BUDGET`/`SCAN_TRUNCATED`) makes
  wildcard verification *bail conservatively* under load. That is correct for a
  clean/infected verdict but wrong for YARA, whose match set must be **complete
  and deterministic**. It also has no path for YARA's string modifiers or regexp.
- **`engine/logic.rs`'s `Node`** is a fixed 5-variant boolean/count algebra with
  static thresholds — no `not`/`none of`, no percentage or computed quantifiers,
  no anchors, no `defined`, no undefined propagation.
- **The `.cbc` bytecode VM** is a typed LLVM-bitcode ISA with a ClamAV API and a
  machine-word/pointer value model — **no "undefined", no struct/array/map
  values**. YARA's evaluator is built on `Option<Value>` and dynamic module
  structs; retargeting the VM would need a new codegen backend plus a parallel
  dynamic-value layer, at real risk to the parity baseline.

A **follow-up** is planned to share more by *evolving* `logic.rs` and the bytecode
VM themselves (generalizing `Node` to YARA's quantifiers/anchors; giving the VM an
undefined-aware dynamic value layer), rather than force-fitting YARA onto them
as-is. Until then, the matcher and the `Cond` evaluator stay in `yara/`.

## Dependency footprint

With the `yara` feature on, exav-core's YARA path adds only light, pure-Rust
crates: `yara-x-parser`, `regex-automata`, `base64`, `bstr`, `crc32fast` (and
reuses exav-core's existing `goblin`/hash/`memchr`). There is **no
wasmtime, no Cranelift, no `walrus`, no `rsa`** — the ~200-crate heavy subtree the
old `yara-x` dependency pulled is gone. A non-`yara` build compiles all of this
away.

## Feature coverage

**Supported:** text/hex/regexp strings + all modifiers (`nocase`/`ascii`/`wide`/
`fullword`/`xor`/`base64`/`base64wide`/`private`); full condition logic
(boolean/`of`/counts/offsets/lengths/anchors/arithmetic/bitwise/float/comparisons/
string-ops/`matches`); `for … in`/`for … of`/`with`; integer reads
(`uint/int 8/16/32` + `_be`); `filesize`; `entrypoint`; **external variables**
(`filename`/`filepath`/`extension`/`filetype`/`owner`, host-supplied from the
scan context); rule references; global/private rules; and the `pe`/`math`/`hash`/
`string`/`time` modules.

**External variables** are declared string-typed by default (`Compiler::new`
pre-declares the five standard ones; `Compiler::define_external` adds more) and
set per scan (`Scanner::set_global`; exav-core threads the filename from
`ScanOptions.filename` → `YaraDb::scan`, deriving `filename`/`filepath`/
`extension` — the latter lowercased with leading dot, e.g. `".js"`). An unset
external is *undefined* (false in boolean context), matching YARA semantics.

**Not yet supported — and rejected as explicit COMPILE ERRORS, never silently
mis-evaluated** (per exav's never-silent-incompleteness rule): the
`macho`/`dex`/`cuckoo`/`androguard`/… modules; `include`; `floatN()` reads;
the `wide` modifier on *regexp* patterns; a bare regexp used as a whole condition;
and the unimplemented `pe.` fields (`rich_signature`, `version_info`, resources,
`signatures`, regexp `imports`/`exports` overloads).

## Rule-rejection accounting (never silent)

A real `.yar` feed may contain rules using unsupported constructs. exav compiles
**per rule** (`Compiler::add_source_lenient`), so one unsupported rule can't drop a
whole feed, and every rejection is recorded in `YaraDb.rejected` (name + reason)
and logged (`WARN`) at database-build time — the coverage gap is always visible,
never an invisibly-missing rule.

## Condition step budget

A YARA range loop takes its bounds from the rule, not from the file:
`for any i in (0..200000000) : ( … )` is a well-formed rule that runs two hundred
million iterations against every buffer it is offered. Nothing in the language
caps that.

Each scan therefore gets `EVAL_STEP_BUDGET` (20M) condition-evaluation steps,
shared across all of its rules, charged one per IR node evaluated. A condition
that runs out yields *undefined*, the same value any other unanswerable
sub-expression yields, so it propagates through the operators without a special
case and the rule does not match. `ScanResults::budget_exhausted()` reports that
it happened: the results are then a lower bound, and the ruleset is what needs
fixing. Large community feeds evaluate in the low millions of steps for a whole
scan, so the ceiling costs real rules nothing.

## Measured real-world coverage

Compiled against two public rulesets (harness: `examples/yara_coverage.rs`):

| Ruleset | Rules | Compile clean |
|---|---|---|
| A large THOR-grade community ruleset | 5,904 | **98.3%** |
| An older, broader community ruleset | 12,911 | **99.1%** |
| A commercial vendor ruleset | 173 | **100%**, 0 disagreements vs yara-x |

**Correctness:** ~17,300 rules were cross-checked against the real `yara-x` over
varied inputs — **0 disagreements** on matching-rule sets. The coverage figures
therefore measure correct matching, not lenient parsing.

Top rejection buckets (by rules blocked):

| Gap | community-ruleset cost | Status / effort |
|---|---|---|
| ~~external variables~~ (`filename`/`filepath`/`extension`) | ~~~10%~~ | **DONE** — 88%→98.3% |
| `wide` on regexp | ~1.2% | now the #1 remaining gap; moderate (widen HIR to UTF-16LE) |
| cheap `pe` helpers (`is_dll`/`is_32bit`/`number_of_resources`/`overlay`) | ~0.1% | trivial (derivable from goblin) |
| `pe.signatures`/`version_info` | ~0.3% | moderate (resource + Authenticode parsing) |
| `floatN()` | 0 rules observed | trivial, not worth prioritizing |
| macho/dex/androguard/cuckoo | ~0 in practice | large, low value — **skip** |
| ~~dotnet~~ | — | **implemented**, validated field-by-field against `yr dump --module dotnet` |

With external variables closed, the remaining *relevant* gap in that community
ruleset is small
(`wide`-on-regexp + a few cheap `pe` helpers). Exotic modules are a trap: large
effort, near-zero real-world rules.

## Performance

The string matcher uses a **required-literal atom Aho-Corasick prefilter**
(`yara/atoms.rs`) — the standard YARA scan architecture. Measured: on 173 real
rules (a commercial vendor ruleset) over ~2.3 MB obfuscated JS, **~1.3 s/file → ~30–50 ms/file
(~44×)**, with **byte-identical detections** (the yara-x A/B diff stays at 0
disagreements; a build-time `EXAV_YARA_NO_GATE` kill switch proves gate-on ==
gate-off on the real corpus).

How it works:
- **Atom extraction** (compile time) — each pattern contributes one or more
  *required literal atoms* (substrings that must appear in **every** match),
  chosen by selectivity (`anchor_score`): a long window for plain/`wide`
  literals, the lowercased window for `nocase` (into a separate CI automaton to
  avoid case-variant explosion), the `searched` bytes for `base64`, and — for
  regexp/hex — the required prefix/suffix literal `Seq` from `regex-syntax`'s
  extractor (the same analysis the `regex` crate trusts for its own prefilters).
- **One shared `daachorse` Aho-Corasick** over all atoms (two automata:
  case-sensitive over the buffer, `nocase` over a lowercased copy). Scanned once.
- **The gate is FN-safe:** a pattern is skipped **only** when a literal that must
  appear in every match is provably absent; when no sound required literal exists
  (`xor` — bytes transformed; `/a*/`, optional/alternation branches, `/.abc/`
  with no fixed prefix/suffix) the pattern is **ungated** and always scanned. On
  that vendor ruleset all 1437 patterns gated, 0 ungated — hence the speedup.
- Two independent matcher fixes: `anchored_matches` went **O(n²) → O(matches)**
  (leftmost-first unanchored sweep, same overlapping set), and literals use
  `memchr::memmem` SIMD search (advancing by 1 byte to keep YARA's overlapping
  counts).

Note: YARA the format hands the engine the strings/condition split (the prefilter
affordance) but deliberately leaves the *atom algorithm* to each engine — so this
was the standard engine responsibility yara-x implements and exav initially
skipped, not a format gap.

**Still open (stretch, deferred to keep the diff green):** per-position windowed
verify (verify only in a window around each atom hit, vs. re-scanning the whole
buffer for a gated pattern); **serializing the compiled automaton into `.exavdb`**
(today the yara `Rules` aren't serialized at all — only rule *source* is, and the
automaton rebuilds lazily on first scan, which is already fast); and yara-x-style
`slow_pattern` compile warnings for ungated/atomless rules.

## Testing

- **Conformance** (`tests/yara_conformance.rs`): assertions ported from yara-x's
  own `lib/src/tests/mod.rs` (the gold oracle), reimplemented against exav's
  public API (`condition_true!`/`rule_true!`/`pattern_match!`-style macros).
- **A/B differential** (`tests/yara_difftest.rs`): gives the same rules and the
  same inputs to exav's engine and to yara-x, and asserts the matching-rule sets
  are **equal**. yara-x is invoked as the `yr` *binary*, not linked — nothing
  from it enters the dependency graph. The tests skip when `yr` is absent;
  `cargo install yara-x-cli` provides it, and `EXAV_YR_BIN` overrides the lookup.
- **Corpus coverage** (`examples/yara_coverage.rs`,
  `tests/yara_coverage_difftest.rs`): the coverage and at-scale correctness
  measurement above.

Run: `cargo test -p exav-core --all-features`.

## Using it standalone

```rust
use exav_core::yara::{Compiler, Scanner};
let mut c = Compiler::new();
c.add_source(r#"rule demo { strings: $a = "evil" condition: $a }"#)?;
let rules = c.build();
let hit = Scanner::new(&rules).scan(b"...evil...").matching_rules().next().is_some();
```

## Roadmap

1. **Atom-prefilter performance rewrite** — *in progress*; see the Performance
   section. It brings many-rule scanning from ~seconds to ~milliseconds per file.
2. **Deep sharing follow-up** — evolve `logic.rs` (generalize `Node` to YARA
   quantifiers/anchors) and the bytecode VM (undefined-aware dynamic value layer)
   so YARA and the AV side share them, with the diff harness pinning correctness.
3. **Cheap wins** — `wide` on regexp (now the #1 *coverage* gap); `pe.is_dll`/
   `is_32bit`/`number_of_resources`/`overlay`.
4. **Moderate** — `pe.version_info`/`signatures` (resource + Authenticode
   parsing; exav-core already has an authenticode module to draw specs from);
   regexp `imports`/`exports` overloads.
5. Exotic modules (macho/dex) only if a concrete need appears — the data
   says they're near-absent in real rulesets.
