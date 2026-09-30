# Bytecode signatures (`.cbc`) — design, scope, and security

ClamAV's most expressive signature type is **bytecode**: a small program (written
in C, compiled to a custom VM bytecode, shipped as a `.cbc` file in
`bytecode.cvd`) that runs against a candidate file and decides whether it's
malicious. It expresses detection logic that pattern/logical signatures can't.

exav implements a reader and a **memory-safe, sandboxed interpreter** for this
format. This document records what the format is, what's actually in the live
database, the scope we target, and — the main point — **why exav's approach is
structurally safer than ClamAV's**, which has a documented history of remote
code execution in exactly this subsystem.

> ClamAV is GPL; exav is MIT. The `.cbc` format is treated here purely as an
> interoperability format (the same way exav reads `.cvd`/`.ndb`). The
> implementation is exav's own.

## 1. The format, in brief

A `.cbc` file is line-oriented:

- **`ClamBC` header line** — format level, timestamp, compiler, type/function
  counts, functionality-level range, and a validation magic
  (`0x53e5493e9f3d1c30`). Integers use a nibble encoding: a byte `0x6N` carries
  nibble `N` (so `` ` ``=0 … `o`=15); a number is a count byte followed by that
  many little-endian nibbles.
- **Trigger line** — a logical signature in `.ldb` form
  (`Name;TDB;expr;subsigs…`). The program runs **only** when this signature
  matches a file. exav already has a full `.ldb` engine, so the trigger side is
  free.
- **Records** — `T` types, `E` API declarations, `G` globals, `A` function
  headers, `B` basic-block instruction streams, `S` strings.

The instruction set is an LLVM-IR-like SSA form: arithmetic, bitwise, casts,
integer comparisons, branches, calls, `GEP` pointer math, `load`/`store`,
`memcpy`/`memset`/`memcmp`, and intrinsics (`bswap`, …). Programs cannot make
syscalls; they reach the outside world only through a fixed **API** (107
functions in ClamAV's table): `read`/`seek`/`file_find` to inspect the file, PE/PDF/JSON
accessors, hashing, `disasm_x86`, and `setvirusname` to report a hit.

## 2. What's actually in the live database

Analysis of `bytecode.cvd` (v339, Sep 2025) — all **85** programs:

| Property | Finding |
|---|---|
| Total programs | **85** (none in `daily.cvd`/`main.cvd`) |
| Kind | 74 logical-triggered (256), 11 PE/PDF/other hooks |
| **Functions per program** | **71 of 85 have a single function**; only 4 are large |
| Trigger | a logical signature (line 2); 42 use a bare subsig, the rest small boolean exprs |

API usage frequency (how many of the 85 call each):

```
setvirusname 79 · seek 60 · read 55 · file_find 32 · file_find_limit 26
engine_functionality_level 24 · bytecode_rt_error 19 · debug_* ~36 · malloc 10
read_number 7 · write 6 · get_pe_section 6 · pe_rawaddr 5 · memstr 4
disasm_x86 4 · extract_new 3 · pdf_* / json_* / matchicon  (few)
```

**Takeaway:** the overwhelming pattern is a *single-function verification
routine* that reads bytes (`read`/`seek`/`file_find`), maybe checks PE section
info, and calls `setvirusname`. The exotic, heavy APIs (`disasm_x86`, PDF/JSON,
the compression codecs) appear in only a handful of programs.

## 3. Scope

- **Implemented:** the file-access, detection and PE APIs (`setvirusname`,
  `read`, `seek`, `file_byteat`, `file_find`/`file_find_limit`, `read_number`,
  `memstr`, `get_pe_section`, `pe_rawaddr`, `malloc`, `write`, `extract_new`),
  `disasm_x86` (over `exav-x86`), the PDF object accessors, `matchicon`,
  `engine_functionality_level`, and the math/util helpers. The `debug_*` family
  and `bytecode_rt_error` are accepted and do nothing.
- **Stubbed:** every other API in ClamAV's table (buffer pipes, maps,
  hashsets, the inflate/bzip2/LZMA and `jsnorm` contexts, JSON accessors, trace
  and environment calls) returns a fail-safe value (0, -1 or a null pointer),
  so a program that calls one still runs and takes its failure path. See
  [Host APIs](#host-apis-34-of-107).
- A program whose body does not decode, or that names an API outside ClamAV's
  table, is loaded but never run. All 85 programs in the live database run to
  completion.

## 4. Why exav's interpreter is safer than ClamAV's

This is the part that matters. ClamAV's bytecode subsystem has a **documented
RCE history**, because it executes DB-supplied programs in memory-unsafe C and
historically via an LLVM JIT:

- **CVE-2020-37167**: weak validation of bytecode function names in ClamBC
  before 0.103.0, a code-injection flaw (CWE-94), **CVSS 3.1 8.4**, local
  vector.
- **ClamAV < 0.102 `bytecode_vm` code execution** (exploit-db 47687) — the
  bytecode VM/JIT path.
- The optional **LLVM JIT** generated and ran native code from bytecode: a large
  attack surface (and dependency) that Cisco has been moving away from.

exav's design removes these failure modes by construction:

| Risk in ClamAV's C VM | exav |
|---|---|
| Memory corruption or code injection in the VM (the class of the two above) | **Pure safe Rust, no `unsafe`** — every memory access is a bounds-checked slice; an out-of-range index panics into isolation, it cannot corrupt memory |
| Native code generation from bytecode (JIT spray, W^X issues) | **No JIT, ever** — interpret only |
| Untrusted program escaping the sandbox (syscalls, host memory) | Program sees only bounded `Vec`s and a fixed read-only file API; no syscalls, no host pointers |
| Runaway program (CPU/memory exhaustion) | **Instruction budget**, scratch-memory cap, and call-depth limit |
| A parser/VM bug taking down the scan | **`catch_unwind` per program** (and per file) — one bad program is skipped, the scan continues |
| Malformed/hostile `.cbc` | Fallible parser (no panics); 100% of the live DB parses cleanly; a program that isn't fully understood is **never executed** |

The net: the worst a hostile or buggy `.cbc` can do to exav is *be skipped or
time out*. In ClamAV the worst case has been *remote code execution*. For anyone
who disables ClamAV bytecode for safety, exav offers the capability **without
that trade-off** — a real reason to switch.

## 5. Dangers identified (and how they're handled)

- **Decompression/alloc bombs via `malloc`/codecs** → scratch-memory cap; the
  codec APIs are stubs; allocation bounded.
- **Infinite loops** → instruction budget (programs are not guaranteed to halt).
- **Pointer math (`GEP`) out of bounds** → modeled as `(region, offset)` with
  checked access; never a raw pointer.
- **Reading beyond the file** → the file is a read-only slice; all API reads are
  clamped.
- **Trigger-only false positives** → a program is the *confirmation* step; if it
  can't run, exav reports nothing (never fires on the trigger alone).
- **`deserialize_unchecked`-style trust** → N/A *for the bytecode subsystem*:
  no `.cbc` content is loaded unchecked, and the DB itself is signature-verified
  by `freshclam`/`cvdupdate`. (The one `deserialize_unchecked` in the project is
  the prebuilt-database loader in `engine.rs`, which is a SHA-256-verified trusted
  artifact — a separate trust model, see SECURITY.md.)

## 6. Status

**Done and verified against the real corpus:**
- Exact nibble number/data/**operand** decoder (`bytecode::decode`) — fuzzed.
- Header + trigger + API declarations (`bytecode::parse`) — **parses 100% of the
  85 programs**.
- **Function headers** (`A` records: args, return type, locals+flags, inst/block
  counts) — **all 134 headers across the 85 files decode cleanly** (27,290
  instructions framed).
- Bounded, memory-safe interpreter (`bytecode::exec`, public surface in
  `bytecode::runtime`) with the core opcode set, checked memory,
  instruction/memory/depth budgets, host API surface — proven end-to-end on
  constructed programs.
- Loader integration ("Bytecode programs loaded: N"); fuzz target. Execution is
  **live in the normal scan path**, trigger-gated per program (`lib.rs` calls
  `db.bytecode.scan(...)`), producing real `Method::Bytecode` detections. The
  gating is per-program (a program runs only when its trigger lsig matches and
  every API it names is in ClamAV's table), not a global off switch.
- Confirmed: opcode enum + `operand_counts` table; CALL/GEPN read their arg
  count inline; inline-constant operands marked by a `0x4N`/`0x50` lead byte.

**Static decode — done (Phases A + B).**
- **A — instructions** (`bytecode::instr`): the exact per-instruction framing
  (terminator marker, `'E'` end-of-function marker, per-opcode operand shapes
  incl. `CALL`/`GEP`/`BRANCH`/`RET`/`ICMP`, `0x4N`/`0x50` inline constants).
  **Decodes every instruction of all 85 programs** — 134 functions, 27,290
  instructions; each block consumes exactly to its terminator.
- **B — types + globals** (`bytecode::types`): the `T` type table and `G`
  constant globals (with component counting). **Decodes all 85** (1,257
  globals) with no errors.

**Execution: live.** `bytecode::exec` is a bounded interpreter over the decoded
IR: value array, integer arithmetic/bitwise/compare/cast/select,
`branch`/`jmp`/`ret`, host-API dispatch, and the `(region, offset)` pointer
addressing model. It runs in the live scan path (`Scanner::bytecode.scan`),
trigger-gated per program, emitting `Method::Bytecode` detections. A program
that calls a stubbed API runs and gets the stub's fail-safe value; a program
that runs out of its instruction budget makes the scan `LIMITS-EXCEEDED` unless
something else is found. Detections that depend on `disasm_x86` or a stub are
not yet validated against `clamscan` (see `BYTECODE_VALIDATION.md`).

Known limitation: functionality-level handling is unenforced for
bytecode. Programs observe `FLEVEL=167` via `engine_functionality_level`
(`bytecode/runtime.rs`), while signature loading gates on `EXAV_FLEVEL=213`
(`engine/parse.rs`); per-program `min/max_flevel` and `format_level` are parsed
but not enforced. A program requiring a newer engine may run when it should be
skipped, or vice versa. This does not affect signature loading, only the value
reported inside bytecode execution.

## Real-world importance of the 85 programs

Numerically tiny — 85 of ~3.7M signatures (0.002%) — but uneven in value:

- **Unpackers (~6, `BC.Win.Packer`/`Packed`) matter most.** Some
  of ClamAV's unpacking is *implemented as bytecode*; an unpacker deobfuscates a
  packed PE so the other ~3.7M signatures can match the payload. Missing one
  silently weakens detection across *many* packed samples — far beyond one sig.
- **Polymorphic / entry-point-obfuscated families** (`BC.Win.Virus` Xpaj,
  `Ransom`) — per-sample algorithmic checks static sigs can't express; each
  catches a whole family.
- **The long tail is legacy.** 36/85 are literally `BC.Legacy.Exploit` for
  2010–2012 CVEs (one notable still-in-the-wild exception: CVE-2012-0158, the
  Office/RTF workhorse); 11 `BC.Img.Exploit`, plus a few PDF/JS/Flash. Mostly
  dated, often also covered by static sigs or long patched.

Implication for the roadmap: prioritize the **unpacker and polymorphic-family**
bytecodes (broad, current impact); the 36 single-CVE legacy checks are low
priority. And note the bigger picture — the **detection delta** from 85 mostly-
legacy programs is modest, so exav's headline win here is the **memory-safe,
non-JIT sandbox** (removing the RCE class), more than the raw extra coverage.

## 7. How decoding was validated

The decisive tool was a **self-validating oracle**: decoding is correct iff
every `B` record consumes exactly to its end *and* the per-function instruction
total equals the header's `numInsts`, across all 85 files. That holds for the
whole live database, and the decoder and VM are fuzzed.

## Host APIs: 34 of 107

ClamAV's host-API table has 107 entries, byte-identical in 1.4.3 and 1.5.3. exav
implements 34.

The `maxapi 89` in debug output is not the table size: it is a per-program
declaration in each `.cbc` header, and 89 is the highest value any shipped
program declares. So indices 0–89 are the reachable surface: exav implements 34
of those 90, and 56 are unimplemented. Indices 90–106 (JSON accessors, LZMA and
bzip2 stream contexts, `get_file_reliability`, `engine_scan_options_ex`) exist in
ClamAV, but no program in the shipped database references any of them.

| Group | Missing | APIs |
|---|---|---|
| Buffer pipes | 9 | `buffer_pipe_new`, `_new_fromfile`, `_read_avail`, `_read_get`, `_read_stopped`, `_write_avail`, `_write_get`, `_write_stopped`, `_done` |
| Debug / trace | 10 | `debug_print_str`, `debug_print_uint`, `debug_print_str_start`, `debug_print_str_nonl`, `trace_directory`, `trace_scope`, `trace_source`, `trace_op`, `trace_value`, `trace_ptr` |
| Engine / environment | 9 | `bytecode_rt_error`, `engine_scan_options`, `engine_db_options`, `extract_set_container`, `input_switch`, `disable_bytecode_if`, `disable_jit_if`, `check_platform`, `running_on_jit` |
| Maps | 8 | `map_new`, `map_addkey`, `map_setvalue`, `map_remove`, `map_find`, `map_getvaluesize`, `map_getvalue`, `map_done` |
| Hashsets | 6 | `hashset_new`, `_add`, `_remove`, `_contains`, `_done`, `_empty` |
| PDF extras | 6 | `pdf_get_obj_num`, `pdf_set_flags`, `pdf_getobj`, `pdf_getobjflags`, `pdf_setobjflags`, `pdf_get_dumpedobjid` |
| Decompression | 3 | `inflate_init`, `inflate_process`, `inflate_done` |
| JS normalisation | 3 | `jsnorm_init`, `jsnorm_process`, `jsnorm_done` |
| Self-test | 2 | `test1`, `test2` |
| **Total** | **56** | of the 90 reachable indices |

At the time of writing all 85 bytecode programs in the official database run to
completion, and across 400 real malware samples one stub was reached
(`get_environment`). A program declares a `maxapi` ceiling; it does not call
every API below it. Some of the 56 are unlikely to matter (the debug and trace
groups are compile-time instrumentation; `running_on_jit` and `disable_jit_if`
have an obvious answer on an engine with no JIT). The pipes, maps and `inflate`
groups would be real work if a future program used them.
