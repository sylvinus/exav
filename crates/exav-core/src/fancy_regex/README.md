# fancy-regex, vendored

The backtracking engine for the PCRE subsignatures the `regex` crate cannot
run (lookaround, backreferences, atomic groups). It is
[fancy-regex](https://github.com/fancy-regex/fancy-regex) 0.19.2, MIT
(`LICENSE` here), with two pull requests merged upstream after that release
and not yet released:

- [#278](https://github.com/fancy-regex/fancy-regex/pull/278) (merged
  2026-09-20), hex escapes above 0x7F match the raw byte in bytes modes:
  - 092b96787cce0ea66e333ed2ccadc8d4e02d2363 fix: hex escapes above 0x7F match raw byte in bytes modes
  - 5faa1e19d3e826437b25bfc18003380c920a775c refactor: emit Literal for ASCII-range \xHH escapes instead of LiteralBytes
  - 57e37f59d5069137eb039f54cfba8ee43e4ed7cb add tests proving behavior - regex-automata and fancy-regex only support simple case folding
  - 62fda14f6c64498c9cc13cb85076f395db6e0f7b fixes after merging main branch in
  - bde92dd3bd1e27c6e9d1252621b9094cb6578451 additional test cases
  - 231906c659fb870d74c6871aa9cf0d9d65fd0f35 additional test case
  - bf9d8cd4ccc936368fc01a75adc79a4287017387 additional test case
  - b4d4f3da48db03c56e5311729a61ae127b71b1ef additional test case
- [#292](https://github.com/fancy-regex/fancy-regex/pull/292) (merged
  2026-09-24), literal bytes used in Unicode mode by mistake:
  - 54739bd085d637c413c307f966e247ec3ce14aad fix bug with literal bytes being used in unicode mode unexpectedly

They were cherry-picked in that order onto the crates.io release (sha256
`d301f5bf187b3c295fce6468d3875037a0bccc5f6b151c63cac2f85babf21912`), keeping
0.19.2's CHANGELOG.md and, in `seek.rs`'s tests, only the one 231906c6 adds.

Every difference from 0.19.2 is listed below: the two pull requests above,
the fixes ported from 0.20.1 and 0.20.2, the fixes of exav's own, the work
accounting, and what building it as a module takes.

Without them, in `BytesMode::Ascii` 0.19.2 reads `\xB6` as the character
U+00B6 and matches its UTF-8 encoding (C2 B6), not the byte B6, and refuses to
compile a class holding such a byte (`[\x00-\xff]`). exav runs ClamAV's PCRE
signatures in that mode, and its translation writes every byte that way.

It is vendored rather than depended on because a crate published on crates.io
can only depend on crates.io releases: `cargo install exav` would build the
release without the fixes.

## Fixes ported from 0.20.1 and 0.20.2

Patched in by hand, from the upstream commits (fancy-regex is MIT). Each is
pinned by a test in `engine/pcre.rs`, run through the translation exav gives
the engine.

- Ambiguous concat repeats (`optimize.rs`), PR
  [#326](https://github.com/fancy-regex/fancy-regex/pull/326), 0.20.1:
  `a+b?a+` matched `a`, because the pass moved the second repeat into an
  optional tail and lost its minimum.
  - 50fedf7569a0a492dd10c482eb6c21e93ebe619d Fix ambiguous concat repeat optimization dropping required minimum
  - Only the case of both repeats having a minimum of one is taken. 0.20.1
    also rewrites bounded edge repeats (fixed again by PR #333 in 0.20.2);
    this copy has the unbounded form alone.
- A counted loop whose body can match empty (`vm.rs`, `compile.rs`, `mod.rs`),
  PR [#312](https://github.com/fancy-regex/fancy-regex/pull/312), 0.20.1,
  with its follow-up PR #327: the slot that holds where the last iteration
  started was only written from the minimum on, so a second run of the loop at
  the same position could end below its minimum.
  - b46236b5fea9aedd59ab4c3d08fb9688d501e74a Don't end a repetition before its minimum count because of a previous run
  - 5ae1fc76ea9fdcc47bdd348687162ed3e8523093 Run the required iterations of a repetition after an empty iteration
  - `has_descendant_or_self` is added to `Expr` for it.
- Positive lookahead is atomic (`compile.rs`), PR
  [#313](https://github.com/fancy-regex/fancy-regex/pull/313), 0.20.1:
  - d1abb0beea900cdf3720ea9b668e659f22d24b32 Make positive lookaheads atomic
- A failed condition balances the explicit stack (`compile.rs`), PR
  [#316](https://github.com/fancy-regex/fancy-regex/pull/316), 0.20.1: the
  program of a conditional has one more instruction.
  - a62755b99da9135ef7f9f52c35f8d6e66be0f9e6 Balance the explicit stack when a condition fails
- A conditional's true branch that is a group of alternatives (`parse.rs`),
  PR [#315](https://github.com/fancy-regex/fancy-regex/pull/315), 0.20.1:
  - 668901e7eb54dfc6172bdc1095ef3a470be62df0 Do not split a group's alternatives into the branches of a conditional
- A back reference or condition inside its own group (`compile.rs`, `vm.rs`),
  PR [#329](https://github.com/fancy-regex/fancy-regex/pull/329), 0.20.1: the
  group's start moved to the current position while its end was still the
  previous one, and the back reference sliced a start past its end. The group
  now keeps its previous capture in two slots (`SaveCaptureGroupStartKeepPrevious`)
  and is open until it ends; `BackrefExistsCondition` takes a slot.
  - 099cf2621ff2b56502ca5f1b8f6c72852e911739 Let a backref inside its own group read the previous capture
- The reverse DFA of a variable lookbehind gets the Unicode and bytes-mode
  syntax of the pattern (`compile.rs`, `compile_variable_lookbehind`). Without
  it a class over bytes above 0x7F was read as the code points U+0080 to
  U+00FF in UTF-8. Upstream made the change for this function in PR
  [#285](https://github.com/fancy-regex/fancy-regex/pull/285) and for the hard
  variable lookbehind in PR [#310](https://github.com/fancy-regex/fancy-regex/pull/310),
  which 0.19.2 does not have.
  - ea7919b76022c8d82dc3fd419f97038dc221995f Compile variable-length lookbehind alternations as one reverse-DFA delegate
    (only the `.syntax(...)` call, not the alternation delegate)
  - c3a603c33386b762b473ed7e2dda73ee87ff2850 Pass unicode/bytes-mode syntax config to hard variable lookbehind reverse DFA
    (the same change, for code this copy does not have)

Not ported: PR #331 (a variable lookbehind with a leading assertion misses
start positions) and PR #286, the hard variable lookbehind it builds on. A
variable lookbehind with a part that is not of constant size and not easy
(a single byte above 0x7F such as `\xe9`, a back reference or a lookaround)
does not build here; the caller reports the scan as incomplete.

## Fixes of exav's own

0.20.0 (2026-10-24) has the two pull requests above and, on its own, the last
two fixes below (`utf8_empty(false)` is in its `compile.rs`, the ASCII word
boundaries in its `vm.rs`). Run against it, `cargo test -p exav-core pcre`
passes but for the first fix.

`optimize.rs`: `(?:a+b?a*)+` was rewritten to `a+(?:ba*)*`, which lets the
optional part follow itself (`abba` matched where the original cannot). The
rewrite of a repeated `A{L,} (M A{R,})?` now needs L to be 0. Present in 0.20.2
as well, not yet reported upstream. Pinned by
`a_repeated_block_with_a_required_start_does_not_repeat_its_middle` in
`engine/pcre.rs`.

`analyze.rs`, `compile.rs`: the size analysis adds and multiplies with
saturating arithmetic where 0.19.2 and 0.20.0 use `+` and `*` for the minimum
size (`min_size * lo` of a repeat, the sums over a conditional and over the
children of a sequence, `go_back` of a lookbehind). A signature of nested
repeat counts, `((((a{65535}){65535}){65535}){65535}){65535}\1`, overflows
`usize`: a panic where overflow checks are on (this workspace's release
profile has them), a wrong size where they are off. Pinned by
`nested_repeat_counts_do_not_overflow_the_size_analysis` in `engine/pcre.rs`,
which panics inside 0.20.0's `analyze.rs`. Not yet reported upstream.

`compile.rs`: the delegated regex-automata engines are configured with
`utf8_empty(false)` outside `BytesMode::Unicode`. With its default (`true`) an
engine skips an empty match at a position inside what would be a UTF-8
sequence, so a delegated `x*` found no match before a byte over 0x7F, and
`(\bb)x*` did not match `b\x9e`. Pinned by the same test as the next fix.
Fixed in 0.20.0.

`vm.rs`: in `BytesMode::Ascii`, `\b`, `\B` and `\b{start}`/`\b{end}` (and their
half forms) read a word character as an ASCII one, as `\w` does. 0.19.2 asks
regex-automata's Unicode boundary in every mode, which decodes the bytes beside
the position as UTF-8: `\bab` did not match `1\x9aab` (the byte `\x9a` was read
with the `1` before it), where `regex` and PCRE2 find a boundary after `\x9a`,
no word character. Found by `fuzz/fuzz_targets/pcre.rs`, pinned by
`a_word_boundary_beside_a_high_byte_reads_the_same_in_both_engines` in
`engine/pcre.rs`. Fixed in 0.20.0.

## Work accounting

A search is limited by the work it does, not by a count of backtracks, so
that a crafted pattern cannot make a delegated search or a back reference
read an object over and over. exav-core's PCRE path (`count_in` in
`engine/mod.rs`) shares one budget between all the matches of a subsignature.

- `vm.rs`, `STEP_BYTES`: a backtrack costs 32 units, a byte read costs one.
  The backtrack limit of the options is multiplied by it when the input has
  no budget of its own.
- `vm.rs`, `spend`: adds to the work of the run and fails with the
  backtrack-limit error past the limit. A back reference charges the length
  of the text it compares.
- `vm.rs`, `Extent` and `delegate_read`: a delegated search is charged the
  bytes it reads, found by running the same pattern as a lazy DFA, since the
  regex crate does not report it. When that DFA cannot be built, gives up, or
  clears its cache, the charge is all that follows the start of the search.
  `Delegate` carries its `Extent`; `compile.rs`, `extent_of` builds it with
  the same syntax as the delegate. Each such search is charged at least one.
  The reverse search of a variable lookbehind is charged the bytes its DFA
  reads back, and the searches are cut one byte past the room left.
- `input.rs`, `RegexInput::work`: a `Cell` holding the room left. A run draws
  from it and leaves what it did not use, so the searches that share the cell
  share the budget; a run that exhausts it leaves it empty.
- `vm.rs`, `run_with`: sets the limit from the cell, or from the options.
- Tests: `the_bytes_a_delegated_search_reads_are_work` and its neighbours in
  `vm.rs`.

## What differs from upstream's `src/`

Besides the fixes and the work accounting above, only what building it as a
module of exav-core takes:

- `lib.rs` is `mod.rs`, without its crate attributes (the doc includes,
  `deny(missing_docs)`, `deny(missing_debug_implementations)`, `no_std`).
- `crate::` is `crate::fancy_regex::`.
- The features are fixed at upstream's defaults: `feature = "std"` and
  `feature = "variable-lookbehinds"` are `true`, `feature =
  "leftmost_longest"` and `feature = "track_caller"` are `false`.
- The edition is 2024: `ref` and `ref mut` binding modifiers are dropped where
  the edition refuses them, and one macro takes `expr_2021`.

exav-core provides its dependencies (`regex-automata`, `regex-syntax`,
`bit-set`) and, for the unit tests, `matches` and `quickcheck`. The unit tests
are upstream's, plus those of the changes above; a few in `analyze.rs` and
`seek.rs` are the ones PR 278 changes. `lib.rs` declares `extern crate alloc`,
and the module skips rustfmt and the lints. The doc examples are written for
fancy-regex as a crate and do not run here.

## Going back to the crates.io release

Once a release has the size analysis fix above and the work accounting is
carried some other way: `engine/mod.rs` uses `STEP_BYTES` and
`RegexInput::work`, which no release has. 0.20.2 has the ports above and
everything else (with `variable-lookbehinds` in its features, which `exav-core`
needs), and fails `nested_repeat_counts_do_not_overflow_the_size_analysis`. It
also still has the `(?:a+b?a*)+` rewrite, and depends on `bit-set` 0.8, so the
direct `bit-set` 0.11 goes with the copy.

1. Delete this directory, and in `lib.rs` the `mod fancy_regex` declaration and
   `extern crate alloc`.
2. In `Cargo.toml`, add `fancy-regex` with `default-features = false` and the
   features `std`, `unicode`, `perf` and `variable-lookbehinds`, and remove `bit-set`, the
   `matches` and `quickcheck` dev-dependencies, and `[lib] doctest = false`.
3. `crate::fancy_regex::` becomes `fancy_regex::` in `engine/mod.rs` and
   `engine/pcre.rs`.
4. `cargo test -p exav-core pcre`, then the `pcre` fuzz target for a few
   minutes: the cases with a byte above 0x7F in a lookaround or back reference,
   and the word boundary ones, are what the fixes above are pinned by.
