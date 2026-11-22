# YARA support: native engine, design, coverage, and reuse

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
categorically different from the hard "never derive from ClamAV" rule: that rule
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
  atoms.rs      required-literal atom prefilter
  modules/      math, hash, pe (goblin), string, time, elf (elf crate), dotnet
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

- **Front-end (reused):** the `yara-x-parser` crate (tokenizer + AST). It is the
  light half of yara-x (no wasmtime). We do not reimplement the grammar.
- **Strings (`matcher.rs`):** each pattern compiles to a matcher that returns
  **every** `(offset, length)` match, as required for `#a` (count), `@a[i]`
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
  access against it. `pe` and `dotnet` use `goblin`, `elf` the `elf` crate
  (records only: exav's code locates the tables); `math`/`hash`/`string`/`time`
  are native.

## What is reused from exav-core, and what deliberately isn't

Living inside exav-core buys a few **leaf-level** reuses:

- **Dependency dedup:** the `pe` module uses exav-core's `goblin`; the `hash`
  module uses exav-core's `md-5`/`sha1`/`sha2`. There is one copy of each.
- **`math.entropy`** → `exav_core::pe::shannon_entropy`.
- **`entrypoint` / `pe.entry_point`** → `exav_core::pe::layout().entry`.

The three big exav-core subsystems are **intentionally NOT reused** for YARA,
because their semantics are the wrong shape. The reasons are recorded here so
nobody re-attempts it and breaks the diff harness:

- **The AV pattern `engine`** is architected for *"does signature S match, and
  where is its first hit"* over one index of literal anchors. It returns the
  first match only (`verify` → `Option<u64>` start; the simulator reports no end
  offset) and dedups by signature name. That is correct for a clean/infected
  verdict but wrong for YARA, whose match set must be **complete and
  deterministic**. It also has no path for YARA's string modifiers or regexp.
- **`engine/logic.rs`'s `Node`** is a fixed 5-variant boolean/count algebra with
  static thresholds: no `not`/`none of`, no percentage or computed quantifiers,
  no anchors, no `defined`, no undefined propagation.
- **The `.cbc` bytecode VM** is a typed LLVM-bitcode ISA with a ClamAV API and a
  machine-word/pointer value model: **no "undefined", no struct/array/map
  values**. YARA's evaluator is built on `Option<Value>` and dynamic module
  structs; retargeting the VM would need a new codegen backend plus a parallel
  dynamic-value layer, at real risk to the parity baseline.

A **follow-up** is planned to share more by *evolving* `logic.rs` and the bytecode
VM themselves (generalizing `Node` to YARA's quantifiers/anchors; giving the VM an
undefined-aware dynamic value layer), rather than force-fitting YARA onto them
as-is. Until then, the matcher and the `Cond` evaluator stay in `yara/`.

## Dependency footprint

With the `yara` feature on, exav-core's YARA path adds only light, pure-Rust
crates: `yara-x-parser` (which brings `bstr`), `regex-automata`, `base64` and
`elf` (and reuses exav-core's existing `goblin`/hash/`crc32fast`/`memchr`). There is **no
wasmtime, no Cranelift, no `walrus`, no `rsa`**; the ~200-crate heavy subtree the
old `yara-x` dependency pulled is gone. A non-`yara` build compiles all of this
away.

## Feature coverage

**Supported:** text/hex/regexp strings + all modifiers (`nocase`/`ascii`/`wide`/
`fullword`/`xor`/`base64`/`base64wide`/`private`); full condition logic
(boolean/`of`/counts/offsets/lengths/anchors/arithmetic/bitwise/float/comparisons/
string-ops/`matches`); `for … in`/`for … of`/`with`; integer reads
(`uint/int 8/16/32` + `_be`); `filesize`; `entrypoint`; **external variables**
(`filename`/`filepath`/`extension`); rule references; global/private rules; and
the `pe`/`math`/`hash`/`string`/`time`/`elf`/`dotnet` modules.

**External variables** are declared string-typed by default (`Compiler::new`
pre-declares the five standard ones; `Compiler::define_external` adds more) and
set per scan (`Scanner::set_global`; exav-core threads the filename from
`ScanOptions.filename` → `YaraDb::scan`, deriving `filename`/`filepath`/
`extension`, the latter lowercased with leading dot, e.g. `".js"`). `filetype`
and `owner` are declared but never set. An unset external is *undefined* (false
in boolean context), matching YARA semantics.

**Not yet supported, and rejected as explicit COMPILE ERRORS, never silently
mis-evaluated** (per exav's never-silent-incompleteness rule): the
`macho`/`dex`/`cuckoo`/`androguard`/… modules; `include`; `floatN()` reads;
a bare regexp used as a whole condition; `xor`/`base64` on a regexp pattern;
the unimplemented `pe.` fields (`rich_signature`, `version_info`, resources,
`signatures`, regexp `imports`/`exports` overloads); `dotnet.classes`; and
`.len()` on a string (`pe.sections[0].name.len()`).

`.len()` on an array or a map of a module (`pe.sections.len()`,
`elf.dynsym.len()`, `dotnet.streams.len()`, also on an array bound by `for` or
`with`) is a function of the engine, not of a module: it is the number of
elements, 0 for an array the file does not have, and it takes no argument.

## The `elf` module

The module has the fields of yara-x's: `type`, `machine`, `osabi`,
`entry_point`, `sh_offset`, `sh_entry_size`, `ph_offset`, `ph_entry_size`,
`number_of_sections`, `number_of_segments`, `symtab_entries`, `dynsym_entries`,
`dynamic_section_entries`, and the arrays `sections` (`name`, `type`, `flags`,
`address`, `size`, `offset`), `segments` (`type`, `flags`, `offset`,
`virtual_address`, `physical_address`, `file_size`, `memory_size`,
`alignment`), `symtab` and `dynsym` (`name`, `value`, `size`, `type`, `bind`,
`shndx`, `visibility`) and `dynamic` (`type`, `val`), with its constants (and
no `SHF_*`, which it has not). Where yara-x and the ELF specification disagree,
exav gives what yara-x gives:

- The program headers are `e_phnum` records at `e_phoff` and the section
  headers `e_shnum` records at `e_shoff`, whatever `e_phentsize` and
  `e_shentsize` say. An offset of 0 is an offset like another, and `e_shnum` 0
  is no section (there is no extended section numbering, and `e_shstrndx` is
  an index like another). A table that is not all in the file is undefined,
  and the rest of the module is not.
- `symtab` and `dynsym` are the first `SHT_SYMTAB` and the first `SHT_DYNSYM`
  section, with `sh_size` divided by the size of a symbol (not `sh_entsize`)
  symbols and the names from the section `sh_link` names. A file with no section
  headers has no symbols: the dynamic section, its hash tables and its
  relocations are not read for them. The counts are 0 for a file that has
  none, and undefined when the section headers are not in the file.
- `dynamic` has the entries of every `PT_DYNAMIC` segment, each up to its first
  `DT_NULL`, which is not listed.
- A name is read from the file at the offset of the string section, up to the
  next NUL, whatever the size of that section; it is undefined when there is no
  such section or the name starts past the end of the file.
- `entry_point` is undefined for an `e_entry` of 0. It is the file offset given
  by the first segment that holds the address in an executable or a shared
  object (of any type), and by the first section that does (not `SHT_NOBITS`)
  in any other file.
- The types of sections and segments and the tags of `dynamic` are signed
  32-bit numbers.

`tests/yara_difftest.rs` checks each of these against `yr` on ELF images written
by the test (`differential_elf_module_on_written_images`), and
`tests/yara_elf_module.rs` states the same values without it.

### `import_md5()` and `telfhash()`

Both read the symbols of `dynsym` when the file has any (the null symbol
counts) and else those of `symtab`, with names as the module gives them, a byte
that is not UTF-8 replaced, then lowercased as text and sorted.

- `import_md5()` is the MD5 of the names of the undefined symbols
  (`shndx` 0, any type and binding, no empty name) joined with commas, in lower
  case hex. It is the MD5 of nothing for a file with no such symbol and for a
  file that is not an ELF.
- `telfhash()` is [telfhash](https://github.com/trendmicro/telfhash) of Trend
  Micro (Apache-2.0): the names of the global functions of default visibility,
  except `main`, `__libc_start_main`, `abort`, `cachectl`, `cacheflush`, `puts`,
  `atol`, `malloc_trim` and the names that start with `_`, `.`, `str` or `mem`
  or end with `64`, joined with commas and hashed with TLSH, in upper case with
  the `T1` prefix. The call destinations telfhash uses for a file without
  symbols are not in yara-x and not here. It is undefined for a file that is
  not an ELF, for under 50 bytes of names, and when yara-x's TLSH gives nothing
  (see below).
- The TLSH is `modules/tlsh.rs`, not the crate of `fuzzy`: yara-x 1.23 gives a
  digest for a sparse input (the reference wants more than half of its buckets
  used), and its search for the first and third quartile leaves them 0 for
  about one input in twenty. A first quartile of 0 shows as a 0 in the digest
  where the reference has a ratio, and a third quartile of 0 gives no digest.
  The Pearson table and the table of lengths are TLSH's (Trend Micro,
  BSD-3-Clause or Apache-2.0).

`tests/yara_difftest.rs` compares both functions with `yr` on 400 written
files (`differential_elf_import_md5_and_telfhash`), and the unit tests of
`modules/tlsh.rs` hold digests of `yr` for the quartile cases.

## The `dotnet` offsets

`dotnet.field_offsets` and `dotnet.resources[].offset` are file offsets, as in
yara-x 1.23, not the numbers of the tables:

- `field_offsets` are the RVAs of the FieldRVA table converted as the `pe` module
  converts an RVA; a row whose RVA is in no section has no entry, and the count
  is that of the entries.
- `resources[].offset` is the file offset of the resources directory of the CLI
  header plus the offset of the ManifestResource row plus 4, the length that
  starts the resource. It is undefined for a resource of another file
  (`Implementation` not 0), for one that starts past the end of the directory,
  and when the directory is in no section; such a resource still counts in
  `number_of_resources`. yara-x also gives `resources[].length`, which exav does
  not.

## The `dotnet` module on damaged assemblies

exav reads an assembly that is not well formed as yara-x 1.23 does. Each of
these was found by comparing `yr dump --module dotnet` with exav on damaged
copies of assemblies; `tests/dotnet_damaged/mod.rs` holds a case for each, and
`differential_dotnet_damaged` checks them against `yr`.

- PE headers: the optional header is PE32+ only for the magic `0x20B`, and any
  other magic is read as PE32; the number of data directories is not read; the
  CLI header must start with its size, `0x48`. At most 96 section headers are
  read, and those that are whole in the file, however many the header counts.
- Metadata root: the streams start right after the version length the root
  states (not rounded up to 4 bytes); a version of more than 255 bytes or that
  is not UTF-8 is not an assembly; the root and the list of streams are read
  only inside the size the CLI header gives the metadata; the number of streams
  is not capped; with two streams of one name the last is read. A stream name
  that is not UTF-8 is undefined, the stream still counts.
- Without a table stream, or one that does not hold its tables, the file is an
  assembly with no tables: `number_of_classes` and the others read 0 and the
  names are undefined.
- Tables are read in order, at most 15,000 rows of each, and the tables and the
  indexes are laid out for no more rows than that. A coded index is 4 bytes
  once a table it names has more than `2^(16 - tag bits)` rows (one more than
  ECMA-335 says). The first table that does not parse ends the read: what comes
  from it and from the tables after it (`classes`, `constants`, `modulerefs`,
  `field_offsets`, `assembly`, `assembly_refs`, `resources`) reads as if the
  file had none. A table does not parse when its rows are not all in the table
  stream, when a coded index in a TypeDef, InterfaceImpl, MemberRef, Constant,
  CustomAttribute, DeclSecurity, Event, ExportedType or ManifestResource row
  has a tag that names no table, or when the type byte of a Constant row is not
  an `ELEMENT_TYPE_*` value.
- A string that is not in the heap, that no NUL ends before the heap does, or
  that is not UTF-8 is undefined (a module, assembly or resource name); so is a
  blob that is not in the heap, and an empty public key. A row of the Constant
  or ModuleRef table with such a value has no entry. `number_of_classes` counts
  the TypeDef rows whose name can be read and is neither empty nor `<Module>`.
- User strings are read from the first byte of the stream; an entry that does
  not fit in the stream voids all of them, a length that is not valid (a first
  byte of `0xE0` or more) ends the list, and an entry with less than two bytes
  of characters is skipped.
- The sizes of the rarely written tables are those of the format: ENCLog 8,
  ENCMap 4, AssemblyProcessor 4, AssemblyOS 12.

Not implemented, and compile errors in a rule: `dotnet.classes`,
`dotnet.typelib`, `dotnet.assembly.culture` and `dotnet.resources[].length`.

## Rule-rejection accounting (never silent)

A real `.yar` feed may contain rules using unsupported constructs. exav compiles
**per rule** (`Compiler::add_source_lenient`), so one unsupported rule can't drop a
whole feed, and every rejection is recorded in `YaraDb.rejected` (name + reason)
and logged (`WARN`) at database-build time. The coverage gap is always visible,
never an invisibly-missing rule.

## Condition step budget

A YARA range loop takes its bounds from the rule, not from the file:
`for any i in (0..200000000) : ( … )` is a well-formed rule that runs two hundred
million iterations against every buffer it is offered. Nothing in the language
caps that.

Each scan therefore gets `--max-yara-steps` (20M by default, `off` for none)
condition-evaluation steps, shared across all of its rules, charged one per IR node evaluated. A condition
that runs out yields *undefined*, the same value any other unanswerable
sub-expression yields, so it propagates through the operators without a special
case and the rule does not match. `ScanResults::budget_exhausted()` reports that
it happened: the results are then a lower bound, and exav-core reports the scan
`LimitsExceeded` unless something matched. A pattern that reaches
`MAX_MATCHES` (1M, as in yara-x) is treated the same way. A pattern every use
of which names one offset (`$a at 0`, `any of ($a, $b) at 0`) is looked for
there alone, as yara-x anchors it, so its matches elsewhere never count.
Large community feeds evaluate in the low millions of steps for a whole
scan, so the ceiling costs real rules nothing.

## Measured real-world coverage

Compiled against two public rulesets (harness: `examples/yara_coverage.rs`):

| Ruleset | Rules | Compile clean |
|---|---|---|
| A large THOR-grade community ruleset | 5,904 | **98.3%** |
| An older, broader community ruleset | 12,911 | **99.1%** |
| A commercial vendor ruleset | 173 | **100%**, 0 disagreements vs yara-x |

**Correctness:** ~17,300 rules were cross-checked against the real `yara-x` over
varied inputs, with **0 disagreements** on matching-rule sets. The coverage figures
therefore measure correct matching, not lenient parsing.

Top rejection buckets (by rules blocked):

| Gap | community-ruleset cost | Status / effort |
|---|---|---|
| ~~external variables~~ (`filename`/`filepath`/`extension`) | ~~~10%~~ | **DONE**: 88%→98.3% |
| ~~`wide` on regexp~~ | ~~~1.2%~~ | **DONE** (widened HIR, UTF-16LE) |
| cheap `pe` helpers (`is_dll`/`is_32bit`/`number_of_resources`/`overlay`) | ~0.1% | trivial (derivable from goblin) |
| `pe.signatures`/`version_info` | ~0.3% | moderate (resource + Authenticode parsing) |
| `floatN()` | 0 rules observed | trivial, not worth prioritizing |
| macho/dex/androguard/cuckoo | ~0 in practice | large, low value: **skip** |
| ~~dotnet~~ | n/a | **implemented**, validated field-by-field against `yr dump --module dotnet` |

The remaining *relevant* gap in that community ruleset is a few cheap `pe`
helpers. Exotic modules are a trap: large effort, near-zero real-world rules.

## Performance

The string matcher uses a **required-literal atom prefilter**
(`yara/atoms.rs`), the standard YARA scan architecture. Measured: on 173 real
rules (a commercial vendor ruleset) over ~2.3 MB obfuscated JS, **~1.3 s/file → ~30–50 ms/file
(~44×)**, with **byte-identical detections** (the yara-x A/B diff stays at 0
disagreements).

How it works:
- **Atom extraction** (compile time): each pattern contributes one or more
  *required literal atoms* (substrings that must appear in **every** match),
  chosen by selectivity (`anchor_score`): a long window for plain/`wide`
  literals, the lowercased window for `nocase` (looked up on the bytes
  lowercased, so case variants are never enumerated), the `searched` bytes for
  `base64`, and, for
  regexp/hex, the required prefix/suffix literal `Seq` from `regex-syntax`'s
  extractor (the same analysis the `regex` crate trusts for its own prefilters).
- **One shared index of all atoms**, the one the signature engine finds its
  anchors with (`grams/`), case-sensitive and `nocase` atoms in two partitions.
  The object is read once, with no lowercased copy.
- **The gate is FN-safe:** a pattern is skipped **only** when a literal that must
  appear in every match is provably absent; when no sound required literal exists
  (`xor`, whose bytes are transformed; `/a*/`, optional/alternation branches, `/.abc/`
  with no fixed prefix/suffix) the pattern is **ungated** and always scanned. On
  that vendor ruleset all 1437 patterns gated, 0 ungated, hence the speedup.
- Two independent matcher fixes: `anchored_matches` went **O(n²) → O(matches)**
  (leftmost-first unanchored sweep, same overlapping set), and literals use
  `memchr::memmem` SIMD search (advancing by 1 byte to keep YARA's overlapping
  counts).

Note: YARA the format hands the engine the strings/condition split (the prefilter
affordance) but deliberately leaves the *atom algorithm* to each engine, so this
was the standard engine responsibility yara-x implements and exav initially
skipped, not a format gap.

**Still open (stretch, deferred to keep the diff green):** per-position windowed
verify (verify only in a window around each atom hit, vs. re-scanning the whole
buffer for a gated pattern); and yara-x-style `slow_pattern` compile warnings
for ungated/atomless rules. (The compiled rule set, atom index included, is
serialized into `.exavdb` as `YaraDb::compiled_blob`, so a prebuilt database
does not recompile.)

## Testing

- **Conformance** (`tests/yara_conformance.rs`): assertions ported from yara-x's
  own `lib/src/tests/mod.rs` (the gold oracle), reimplemented against exav's
  public API (`condition_true!`/`rule_true!`/`pattern_match!`-style macros).
- **A/B differential** (`tests/yara_difftest.rs`): gives the same rules and the
  same inputs to exav's engine and to yara-x, and asserts the matching-rule sets
  are **equal**. yara-x is invoked as the `yr` *binary*, not linked, so nothing
  from it enters the dependency graph. The tests skip when `yr` is absent, so
  that a plain `cargo test` passes without it; `cargo install yara-x-cli`
  provides it, and `EXAV_DEBUG_YR_BIN` overrides the lookup. `make
  test-yara-diff` fails instead when `yr` is not found or when
  `EXAV_DEBUG_YARA_CORPUS` (a directory of rule files, for the corpus suite
  below) is not set. CI, which has no corpus, runs `make test-yara-diff-rules`
  with the `yr` release of the version of `yara-x-parser`.
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
let mut scanner = Scanner::new(&rules);
let hit = scanner.scan(b"...evil...")?.matching_rules().next().is_some();
```

## Roadmap

1. **Atom-prefilter performance rewrite**: *in progress*; see the Performance
   section. It brings many-rule scanning from ~seconds to ~milliseconds per file.
2. **Deep sharing follow-up**: evolve `logic.rs` (generalize `Node` to YARA
   quantifiers/anchors) and the bytecode VM (undefined-aware dynamic value layer)
   so YARA and the AV side share them, with the diff harness pinning correctness.
3. **Cheap wins**: `pe.is_dll`/`is_32bit`/`number_of_resources`/`overlay`.
4. **Moderate**: `pe.version_info`/`signatures` (resource + Authenticode
   parsing; exav-core already has an authenticode module to draw specs from);
   regexp `imports`/`exports` overloads.
5. Exotic modules (macho/dex) only if a concrete need appears; the data
   says they're near-absent in real rulesets.
