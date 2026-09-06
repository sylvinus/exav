# Dependency policy

exav aims to stay in control of its own codebase. Dependencies are where that
control is easiest to lose — to code we don't read, `unsafe` we don't audit,
supply-chain risk we don't track, and compile time / binary size we don't want.
So we are deliberate about what we pull in.

## Principles

1. **Favour leaf dependencies.** Prefer crates that are small and have few (ideally
   zero) transitive dependencies. A focused crate that does one thing over a
   bounded byte arena is worth more to us than a "batteries-included" crate that
   drags in a large tree. When two crates solve the same problem, the one with
   the smaller/shallower dependency graph wins, all else equal.

2. **Avoid pulling huge trees.** A dependency that expands into dozens or hundreds
   of transitive crates is a red flag: it inflates the `unsafe` surface we're
   trying to drive down (see [the `unsafe` posture in the README](../README.md)),
   the audit burden, the attack surface, cold compile time, and the binary/WASM
   size. We say no to such a dependency unless it earns its place and we've looked
   at what it actually pulls in (`cargo tree -e no-dev`).

3. **Gate optional capability behind features.** Anything not everyone needs is a
   Cargo feature, so a build only compiles the code and dependencies it uses:
   - **Archive/container formats** are per-format features on `exav-unpack`,
     forwarded through `exav-core`, `exav`, and the WASM crates. A ZIP-only
     build is `--no-default-features --features zip`; it drops every non-ZIP
     extractor and its deps. (A recognised-but-not-compiled format is reported
     `UNSCANNABLE`, never silently clean.)
   - **YARA** (`yara`, on by default) — see the outlier note below.
   - **HTTP(S) range scanning** (`http`, off by default) — the only feature that
     links a TLS stack (`ureq → rustls → ring`).

4. **Prefer pure-Rust, and keep the tree pruned.** The default build links no C
   and no native JIT. Concretely:
   - The daemon's stream-spill temp file is in-tree (`exav/src/tmpfile.rs`,
     a page of `std::fs`) and `tar` is built without `xattr`. Together those keep
     the `rustix`/`linux-raw-sys` syscall crates out — 8,624 `unsafe`
     occurrences, which would outweigh the rest of the tree twice over, for code
     that never touches a scanned byte.
   - Decryption cipher/KDF crates are in, but no RNG path is ever enabled, so
     the default tree is `getrandom`-free.
   - YARA is an in-tree native engine rather than the `yara-x` runtime (see
     below), which keeps out an entire WASM-runtime + JIT subtree and the `rsa`
     crate (RUSTSEC-2023-0071).

## YARA: a native, in-tree engine

A YARA engine can be a dependency outlier: running compiled rule conditions on a
WASM runtime **with Cranelift** pulls a ~200-crate subtree (a WASM runtime plus a
codegen backend) — squarely at odds with principle 2.

exav avoids that. It has its **own native, in-tree YARA engine**: it uses the
YARA-X parser and compiles rule conditions to a native tree-walking evaluator. As
a result:

- There is **no `wasmtime` and no Cranelift** anywhere in the build, and no
  runtime JIT / W^X page at scan time.
- The `rsa` crate (and other crypto-module dependencies a WASM-backed engine
  would pull) are absent.
- What remains for YARA is a small pure-Rust subtree (the `yara-x` parser plus a
  handful of leaf crates such as `regex-automata`, `base64`, `bstr`,
  `crc32fast`).
- It stays **behind the `yara` feature (on by default)**; `--no-default-features`
  compiles the YARA parser/evaluator away entirely for an even smaller,
  still-useful compatible scanner.

See [YARA.md](YARA.md) for the engine's design and coverage. The `yara-x` parser
is BSD-3-Clause (permissive, MIT-compatible), reused with attribution — the
clean-room "never derive from GPL" rule is GPL-specific and does not apply to it.

## Filesystem readers: a costed decision

Reconstructing a disk image gives a pile of sectors. Reading the *filesystem* on
it is what turns those into files with names, and what reassembles a
**fragmented** file — which a raw carve can only see as disconnected pieces.

`fatfs` was taken (feature `fat`). It fits the principles above almost exactly:
MIT, no `unsafe`, and `bitflags` + `log` are its only dependencies.

**NTFS was measured, and the measurement changed the answer.** The numbers are
kept here because they are the whole argument:

| | |
|---|---|
| crate | `ntfs` 0.4 (Colin Finck), MIT OR Apache-2.0, read-only, `no_std` |
| `unsafe` | 2 occurrences |
| new crates in the lock file | **14** (402 → 416) |
| what they are | `arrayvec`, `derive_more`, `enumn`, `memoffset`, `nt-string`, and via them `binrw` + `binrw_derive`, `array-init`, `convert_case`, `heck`, `widestring`, a second `syn` |

Fourteen crates is well short of the "dozens or hundreds" red flag, and the
capability is real: VHD and VHDX are Windows-native, so a disk image aimed at a
Windows victim holds NTFS rather than FAT. Against that, several of the new
crates are proc-macro/codegen (`binrw_derive`, `derive_more`, `enumn`), which is
the kind of expansion this project has spent effort removing.

Four alternatives were measured the same way. `ntfs-reader` is +13 but pulls the
**`windows`** bindings, which is a non-starter for a cross-platform scanner.
`mft` is the most downloaded at 748k and the heaviest at **+54**, because it is a
forensics *tool* crate — `csv`, `dialoguer`, `rkyv`, `sonic-rs`, `simplelog`.
`ntfs-core` is the cheapest at **+6** and the only one that handles compression,
but the crate and its whole dependency chain were published within the preceding
two months by a single author, with sixteen releases in seven weeks; accepting it
after rejecting `newtua-mscompress` and `xpress-huffman` on exactly that ground
would be incoherent.

**What was taken instead: an in-tree MFT walk plus `lznt1` — one crate.** A
scanner does not need a filesystem driver. Walking the MFT record by record
gets every file's bytes without index B-trees, `$Upcase` or case-insensitive
lookup, and it picks up deleted-but-resident records, which no directory walk
does. `lznt1` is MIT, single-purpose, dependency-free and unchanged since
December 2025, and it closes the compression gap that `ntfs` 0.4 does not even
claim to.

The deciding factor was that it is **validatable**: `mkntfs` and `ntfscp` build
fixtures, `ntfsls` and `ntfscat` are an independent oracle, all without root.

### ext2/3/4: `ext4-view` was taken

`ext4-view` sat where `ntfs` did, and the same questions were asked of it. It
answered them better:

- **Tree**: zero dependencies. `cargo tree -i ext4-view` adds one node.
- **`unsafe`**: none, and no write path at all — the crate cannot corrupt an
  image because it has no code that could.
- **Validatable**: `mke2fs` builds fixtures, `debugfs` populates and deletes
  inside them, and `filefrag`/`debugfs stat` are an independent oracle — all
  without root, exactly like the NTFS case. The regression fixture's payload
  really does span two non-adjacent extents, and `debugfs` says so.
- **Scope**: read-only access to files by path is precisely what a scanner
  needs, with none of the mount/journal-replay surface a driver carries.

The one real cost is recorded in `formats/ext.rs`: `Ext4::load` takes an owned
`Box<dyn Ext4Read>`, so the image is copied once rather than borrowed. That is a
forced-materialization site, charged against `max_buffer_bytes` like the
others, and an image past the budget is reported rather than skipped.

### ZOO: vendored, after linking it broke something else

`unarc-rs` has a working ZOO reader and was tried as a dependency first. It
brought in a second `zip` with **default features**, and Cargo's feature
unification then enabled the `zip` crate's own LZMA/bzip2/deflate64 decoders
inside exav — which bypass exav's per-member budget, and which exav deliberately
turns off (`default-features = false`) so its own budgeted decoders handle those
methods. The ZIP-codec suite went red immediately.

The fix was to vendor the ~200 lines of ZOO structures instead, as the ARJ
reader already was, leaving two leaf crates: `salzweg` (LZW, dependency-free)
and `delharc`, which exav already had for LHA. **Feature unification is a real
cost of a dependency and it does not show up in `cargo tree`** — this is the
case to remember when weighing one.

## x86 decoding: `iced-x86` costed

`iced-x86` was the largest single `unsafe` surface exav linked. **No shipped
binary links it now.** Both x86 call sites run on `exav-x86`:

- `crates/exav-pe-emu/src/cpu.rs` — the packer emulator's fetch step.
- `crates/exav-core/src/bytecode/disasm.rs` — the bytecode `disasm_x86` API,
  translating one instruction into the 64-byte `DISASM_RESULT` ABI.

`iced-x86` remains in the workspace in exactly one role, as a **test oracle**:
`exav-x86`'s differential suite, its table generator, and the `x86_decode` fuzz
target. It is a dev-dependency of one crate and reaches no shipped artifact —
`cargo tree -e no-dev -p exav` does not list it.

The emulator move was gated on output, not on the tests passing:
`crates/exav-pe-emu/examples/corpus-outcomes.rs` records the outcome, entry
point, tick count and image digest of all 276 packed samples, and the two
decoders produce **byte-identical results on every one**.

### What it costs

| | |
|---|---|
| crate | `iced-x86` 1.21, MIT, features `std, decoder, instr_info` |
| dependencies it adds | 1 (`lazy_static`) |
| `unsafe` in `src/` | 640 total; **481 compiled** under those features (`formatter/` 119 and `encoder/` 40 are not built) |
| where | `decoder/handlers/legacy.rs` 162, `vex.rs` 56, `evex.rs` 46, `decoder.rs` 28, `handlers.rs` 27, `info/` 43, `enums.rs` 34, `code.rs` 24 |
| what kind | 307 × `&*(self_ptr as *const Self)` (the handler-table dispatch) and ~250 × `mem::transmute(int → enum)` (table index → `Code`/`Register`/`OpKind`). No FFI, no SIMD intrinsics, no aliasing tricks. |
| build cost | a release rebuild of `iced-x86` + `exav-pe-emu` is **3 s** on the 2-core box; the release rlib is 11.7 MB, nearly all decode tables, of which the linker keeps only what is reached |

The build cost is the point that changes the argument: `iced-x86` is expensive in
`unsafe` and cheap in everything else. Both `unsafe` categories have safe
equivalents upstream (a `match`, a `TryFrom`, an index into a slice) at some
decode-speed cost — this is a performance posture, not a necessity.

### What we actually use

The *interface* is twenty `Instruction` accessors (`op_kind`, `op_register`,
`immediate`, `memory_base`/`index`/`scale`/`displacement32`, `near_branch32`,
`mnemonic`, `code`, `len`, `ip`, the prefix predicates) over five enums. That is
the shallow answer, and it understates the work: what iced actually performs is
prefix handling, ModRM/SIB decoding, the mode-dependent `C4`/`C5`/`62`
disambiguation, instruction length, normalisation of every encoding of an
operation into one `Code`, and the valid/invalid decision.

The *demand* on that machinery was measured by instrumenting the decode point in
`cpu.rs` and running the emulator over all 276 packed corpus samples —
**1,916,485,956 instructions decoded**:

| | |
|---|---|
| distinct encodings (`Code`) reached | **253** of iced's 4,936 — **5.1%** |
| distinct mnemonics | 114 |
| encodings covering 50% of decodes | 8 |
| …90% / 99% / 99.9% | 42 / 87 / 111 |

The shape is unremarkable and that is the finding: `Pop_r32`, `Mov_r32_rm32`,
`Inc_r32`, `Push_r32`, `Retnd` and three more are half of two billion decodes.
The tail is 16-bit operand-size forms (`Add_AX_imm16`, `And_rm16_imm16`),
`moffs` forms, and `cmovcc` — mundane, not exotic.

**No SSE or MMX encoding appears anywhere in the corpus**, and x87 shows up only
as `Fninit`, `Fnop`, `Ftst`, `Fxam` and `Wait`. `cpu.rs` implements a full
`simd()` path; no corpus sample exercises it, so its only coverage is unit tests.
Check that before relying on it.

`instr_info` is pulled in for exactly seven `Register` predicates — `is_gpr8`,
`is_gpr16`, `is_gpr32`, `is_xmm`, `is_mm`, `is_segment_register`, `number()` —
plus `size()`, across 42 call sites. All are pure classification over a finite
enum, so an in-tree table replaces them and the feature (43 occurrences) with it.

### Alternatives, measured

**`yaxpeax-x86` 2.2.0** (0BSD): 104 `unsafe` across all three modes plus the
formatters. With `default-features = false` (no `fmt`, `colors`, `use-serde`) and
only `protected_mode` reachable, that falls to roughly 20–35 — mostly
`unreachable_unchecked()`, which is the sharpest kind on hostile input but the
easiest to replace. It adds `yaxpeax-arch`, `num-traits` and `cfg-if`. The port
is concentrated rather than diffuse: the operand-access helpers in `cpu.rs`, the
131-arm mnemonic match, and the `real_op` mapping in `disasm.rs`.

**An in-tree decoder — written, and measured rather than estimated.** A
prototype covering the emulator's demand is **732 lines** of dependency-free,
`#![forbid(unsafe_code)]` Rust (912 with comments and blanks):

| region | code |
|---|---|
| `decode()` — prefixes, dispatch, x87 escapes | 178 |
| operand-form decode | 114 |
| group / condition-code / arithmetic tables | 104 |
| one-byte opcode map | 103 |
| ModRM + SIB + 16-bit addressing | 79 |
| `lock` validity + condition-code naming | 56 |
| types (`Size`, `Op`, `Insn`) | 35 |
| `0F` opcode map | 32 |
| operand-form enum (26 variants) | 30 |

It decodes **all 253 encodings the corpus executes**, and against `iced-x86` over
every byte offset of all 276 samples — **94,245,255 sites where iced decoded
something** — it produces **zero disagreements** in length, mnemonic, memory
operand or register operand, and **declines nothing**. The sweep asserts both,
so either is a test failure rather than a number in a report.

The line count is the cheap part of the answer. The expensive part is that a
decoder is only as good as what it is checked against, and the rules that decide
correctness are not visible in the tables — they are prefix interactions:

- `/6` in the shift group is `sal`, not a second `shl`
- `lock` is only legal on a read-modify-write to memory, for a fixed set of ops
- `8D` with `mod=3` is not an instruction — `lea` needs an address
- a `66` prefix renames `pushad`/`popad`/`pushfd`/`popfd`/`cdq`/`cwde`
- **`66 E9` takes an `imm16`, not an `imm32`** — a length error, the class that
  desynchronises every instruction after it
- `F2` and `F3` are one prefix class: the last one wins, so `F3 F2 90` is `nop`
- `F3 0F BC`/`BD` are `tzcnt`/`lzcnt`, not `rep bsf`/`bsr`
- `67 E3` branches on CX, so it is `jcxz`, not `jecxz`

Every one of those is a silent wrong answer, not a crash, and none is visible by
inspection — which is why `exav-x86` keeps `iced-x86` as a dev-dependency oracle
and sweeps the opcode maps under every prefix combination on each test run.

The harder cost was never the 253 encodings; it is **correctly saying no to
everything else**, which is the part a decoder gets wrong quietly. The emulator
has the right shape for it either way: `Stop::Unsupported` is not delivered to
the stub's SEH handler, so an encoding the in-tree decoder does not claim is an
honest `UNSCANNABLE`, not a fabricated fault. The 253 is a floor, not a ceiling —
it is what *these* 276 samples execute, and every packer added extends it, which
is why the decoder covers the whole of 32-bit mode rather than that measured
subset.

The `disasm_x86` side could never have been bounded by measurement. It decodes
arbitrary file bytes at a bytecode program's cursor, so its demand is "whatever a
`.cbc` points at". Its 287-entry ABI table already existed
(`bytecode/disasm.rs` is 478 lines of code, 289 of them that table), so the
decoder swap there was re-pointing the translation at a new instruction type
rather than rebuilding the table.

The reason the swap-or-rewrite question is answerable at all is that it is
**differential-testable**: keep `iced-x86` as a dev-dependency, decode the same
bytes both ways and compare length, mnemonic and operands over random bytes, the
`fuzz/fuzz_targets/pe_emulator.rs` corpus, and the 276 packed samples the
emulator already runs. A decoder disagreement is a test failure, not a field
report.

### Where this stands

The decoder is `crates/exav-x86` — 32-bit, decode-only, dependency-free,
`#![forbid(unsafe_code)]`. It covers 32-bit protected mode in full: the integer
and control-flow set, port I/O, far transfers, segment-register loads, both
address sizes, the whole x87 escape map, the system-instruction space, SSE/MMX
with the `0F 38` and `0F 3A` escapes, 3DNow!, VEX, EVEX and AMD's XOP.

Against `iced-x86` over every byte offset of the 276 packed samples (94,245,255
decode sites) it agrees on **every one**: no disagreements and nothing declined.

The SIMD and system regions are not hand-written. `scripts/gen-x86-tables.sh`
runs `crates/exav-x86/tools/gen-tables`, which probes `iced-x86` for every
(prefix, opcode, `/digit`, `mod`) combination and records what came back —
hand-transcribing an opcode table is how a decoder acquires quiet errors, and
the differential tests that catch them are cheaper to run than to write. The
attribution is in `NOTICE`; the generator is its own workspace so it stays
runnable while a table-layout change has the crate not compiling.

The tables record only what a decoder cannot infer from the bytes: which
instruction an encoding names, how many immediate bytes follow, which register
file each operand belongs to, how wide a memory operand is, and — for EVEX — the
factor its compressed `disp8` is scaled by. Never a displacement, so a change to
the addressing rules cannot be contradicted by a stale table.

Both `exav-core` and `exav-pe-emu` use it, and **neither depends on `iced-x86`**,
so the 481 compiled `unsafe` occurrences that decoder contributed are gone from
every shipped binary.

Operands carry their register file (`Op::Xmm`, `Op::Mmx`, general-purpose
registers at their real width) and memory operands their true access width, all
generated from the oracle and all compared against it. Moving the emulator
across surfaced three defects that only an output diff could have found: `crc32`
had no `reg` operand because operand shapes covered the `0F` map but not the
`0F 38` escape; a wide memory operand was clamped to four bytes, so SSE block
moves copied four instead of sixteen; and `GetProcAddress` resolved an export by
iterating a hash map, which made the *unpacked image itself* differ between runs
(see [`QUIRKS.md`](QUIRKS.md)).

The one behavioural rule that swap depends on: a declined decode marks the
bytecode run **unsupported**, so `run_program` discards its result. Returning the
ABI's `-1` instead would let a program take a branch it would not have taken with
a full decoder and report a verdict built on it — a false negative with nothing
to show for it.

`iced-x86` stays in the workspace as `exav-x86`'s **dev-dependency oracle**. It
reaches no shipped binary, and every encoding the decoder claims is checked
against it on each test run.

## Adding or bumping a dependency — checklist

- Is there a smaller/leaf alternative, or can we do it in-crate over our bounded
  byte arena? (Several parsers are vendored for exactly this reason — see
  `NOTICE`.)
- Run `cargo tree -e no-dev -i <crate>` and look at what it pulls in. Huge tree →
  justify or decline.
- Does it pull `getrandom`, a C/asm build, or a JIT? If so, it needs a strong
  reason and probably a feature gate.
- Gate it behind a feature if it's format- or capability-specific.
- CI must stay green: `cargo deny check` (advisories/bans/sources/licenses) and
  the license allowlist in `deny.toml`.

## Measuring WASM size fairly

A plain `cargo build --release` `.wasm` is **not** the shipped size — it still
carries the `__wasm_bindgen_unstable` metadata section and the `name` section,
which `wasm-bindgen`/`wasm-pack` and `wasm-opt` strip. Measure the real artifact:

```sh
wasm-pack build --release crates/exav-unpack-wasm -- --no-default-features --features zip
wasm-opt -Oz --all-features pkg/exav_unpack_wasm_bg.wasm -o out.wasm   # final size
```

For reference (release profile `opt-level="z"` + LTO, then `wasm-opt -Oz`): the
ZIP-only extractor is ~**323 KiB** vs ~**1.21 MiB** for the full all-formats
build — the per-format features earn their keep. Roughly a third of an
unoptimised `cargo build` `.wasm` is transient tooling data, so always strip +
`wasm-opt` before quoting a number.
