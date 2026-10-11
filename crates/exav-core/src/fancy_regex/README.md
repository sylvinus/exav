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

Without them, in `BytesMode::Ascii` 0.19.2 reads `\xB6` as the character
U+00B6 and matches its UTF-8 encoding (C2 B6), not the byte B6, and refuses to
compile a class holding such a byte (`[\x00-\xff]`). exav runs ClamAV's PCRE
signatures in that mode, and its translation writes every byte that way.

It is vendored rather than depended on because a crate published on crates.io
can only depend on crates.io releases: `cargo install exav` would build the
release without the fixes.

## Two fixes of exav's own

`compile.rs`: the delegated regex-automata engines are configured with
`utf8_empty(false)` outside `BytesMode::Unicode`. With its default (`true`) an
engine skips an empty match at a position inside what would be a UTF-8
sequence, so a delegated `x*` found no match before a byte over 0x7F, and
`(\bb)x*` did not match `b\x9e`. Pinned by the same test as the next fix.

`vm.rs`: in `BytesMode::Ascii`, `\b`, `\B` and `\b{start}`/`\b{end}` (and their
half forms) read a word character as an ASCII one, as `\w` does. 0.19.2 asks
regex-automata's Unicode boundary in every mode, which decodes the bytes beside
the position as UTF-8: `\bab` did not match `1\x9aab` (the byte `\x9a` was read
with the `1` before it), where `regex` and PCRE2 find a boundary after `\x9a`,
no word character. Found by `fuzz/fuzz_targets/pcre.rs`, pinned by
`a_word_boundary_beside_a_high_byte_reads_the_same_in_both_engines` in
`engine/pcre.rs`. Not yet reported upstream: when it is, say so here, and drop
the change once a release carries the fix.

## What differs from upstream's `src/`

Only what building it as a module of exav-core takes:

- `lib.rs` is `mod.rs`, without its crate attributes (the doc includes,
  `deny(missing_docs)`, `deny(missing_debug_implementations)`, `no_std`).
- `crate::` is `crate::fancy_regex::`.
- The features are fixed at upstream's defaults: `feature = "std"` and
  `feature = "variable-lookbehinds"` are `true`, `feature =
  "leftmost_longest"` and `feature = "track_caller"` are `false`.

exav-core provides its dependencies (`regex-automata`, `regex-syntax`,
`bit-set`) and, for the unit tests, which are unchanged, `matches` and
`quickcheck`. `lib.rs` declares `extern crate alloc`, and the module skips
rustfmt and the lints. The doc examples are written for fancy-regex as a crate
and do not run here.

## Going back to the crates.io release

Once a release has both fixes (0.19.3 or later):

1. Delete this directory, and in `lib.rs` the `mod fancy_regex` declaration and
   `extern crate alloc`.
2. In `Cargo.toml`, add `fancy-regex = "0.19.3"`, and remove `bit-set`, the
   `matches` and `quickcheck` dev-dependencies, and `[lib] doctest = false`.
3. `crate::fancy_regex::` becomes `fancy_regex::` in `engine/mod.rs` and
   `engine/pcre.rs`.
4. `cargo test -p exav-core pcre`: the cases there with a byte above 0x7F in a
   lookaround or back reference fail without the fixes, and
   `a_word_boundary_beside_a_high_byte_reads_the_same_in_both_engines` fails
   unless the release also has the ASCII word boundary fix above.
