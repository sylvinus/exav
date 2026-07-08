# Bytecode signatures (`.cbc`) — design, scope, and security

ClamAV's most powerful signature type is **bytecode**: a small program (written
in C, compiled to a custom VM bytecode, shipped as a `.cbc` file in
`bytecode.cvd`) that runs against a candidate file and decides whether it's
malicious. It expresses detection logic that pattern/logical signatures can't.

exav implements a reader and a **memory-safe, sandboxed interpreter** for this
format. This document records what the format is, what's actually in the live
database, the scope we target, and — the main point — **why exav's approach is
fundamentally safer than ClamAV's**, which has a documented history of remote
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
syscalls; they reach the outside world only through a fixed **API** (~96
functions): `read`/`seek`/`file_find` to inspect the file, PE/PDF/JSON
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

## 3. Minimal scope

Targeting the file-access + detection + info/debug APIs covers the bulk:

- **In scope (implemented host API surface):** `setvirusname`, `read`, `seek`,
  `file_byteat`, `file_find`/`file_find_limit`, `engine_functionality_level`,
  `bytecode_rt_error`, the `debug_*` family, `read_number`, `memstr`.
- With exav's current parser, **66 of 85 (78%)** of the live programs use *only*
  APIs in this set — i.e. they're within reach of the minimal interpreter once
  instruction lowering is complete.
- **Out of scope for now (safe stubs / not executed):** `disasm_x86` (an x86
  decoder), the PDF/JSON object APIs, `inflate`/`lzma`/`bzip2`,
  `jsnorm`, `matchicon`. A program needing these is loaded but not run — it can
  never false-positive or crash.

## 4. Why exav's interpreter is safer than ClamAV's

This is the part that matters. ClamAV's bytecode subsystem has a **documented
RCE history**, because it executes DB-supplied programs in memory-unsafe C and
historically via an LLVM JIT:

- **CVE-2020-37167** — heap issue in the bytecode interpreter's function-name
  handling, **CVSS 9.8 (RCE)**.
- **ClamAV < 0.102 `bytecode_vm` code execution** (exploit-db 47687) — the
  bytecode VM/JIT path.
- The optional **LLVM JIT** generated and ran native code from bytecode: a large
  attack surface (and dependency) that Cisco has been moving away from.

exav's design removes these failure modes by construction:

| Risk in ClamAV's C VM | exav |
|---|---|
| Buffer overflow / UAF in the VM (the CVE-2020-37167 class) | **Pure safe Rust, no `unsafe`** — every memory access is a bounds-checked slice; an out-of-range index panics into isolation, it cannot corrupt memory |
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

- **Decompression/alloc bombs via `malloc`/codecs** → scratch-memory cap; codecs
  out of scope; allocation bounded.
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
  the prebuilt-cache loader in `engine.rs`, which is a SHA-256-verified trusted
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
  its host APIs are implemented), not a global off switch.
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

**Execution — live, with partial coverage.** `bytecode::exec` is a bounded
interpreter over the decoded IR: value array, integer
arithmetic/bitwise/compare/cast/select, `branch`/`jmp`/`ret`, host-API dispatch,
and the `(region, offset)` pointer addressing model — and it runs in the live
scan path (`Database::bytecode.scan`), trigger-gated per program, emitting
`Method::Bytecode` detections. The remaining work is **coverage, not gating**:
programs needing not-yet-implemented host APIs (`disasm_x86`, the PDF/JSON
object APIs, the inflate/lzma/bzip2 codecs) are skipped rather than executed, and
the disasm/codec-dependent detections that do run are not yet
detection-validated against `clamscan` (see `BYTECODE_VALIDATION.md`).

## Real-world importance of the 85 programs

Numerically tiny — 85 of ~3.7M signatures (0.002%) — but uneven in value:

- **Unpackers (~6, `BC.Win.Packer`/`Packed`) are the high-leverage set.** Some
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

## 7. Roadmap to 100% of the 85 programs

The decisive tool throughout is a **self-validating oracle**: decoding is correct
iff every `B` record consumes exactly to its end *and* the per-function
instruction total equals the header's `numInsts`, across all 85 files. Each
phase is "done" only when that holds.

- **Phase A — instruction decode (done).** Pin the exact `B`-record framing:
  the `T` terminator layout, the trailing marker (the observed `@d E` tail), the
  `GEP1`/`GEPZ` operand reads, and confirm the opcode field encoding. *Gate:
  100% of B records consume exactly; Σinsts == numInsts for all 85.* (~1–2 wk)
- **Phase B — types + SSA value model.** Decode the `T` type table
  (struct/array/pointer/function) and the value-numbering so register sizes,
  constants, and pointer types are correct. (~1–2 wk)
- **Phase C — lower to executable IR.** Map all ~50 opcodes to the VM IR with a
  bounds-checked `(region, offset)` pointer model (covers `load`/`store`/`GEP`/
  `memcpy`/`select`/casts/branches/calls). (~2–3 wk)
- **Phase D — host APIs (→78%).** Implement the API ladder over the existing
  file buffer + `pe.rs`: `read`/`seek`/`file_byteat`/`file_find(_limit)`,
  `setvirusname`, `engine_functionality_level`, `debug_*`, `read_number`,
  `memstr`, bounded `malloc`, `get_pe_section`/`pe_rawaddr`. This set already
  covers **66/85 (78%)** of the live programs. (~1–2 wk)
- **Phase E — gated execution + differential testing.** Trigger lsig match → run
  under budget + `catch_unwind` → `setvirusname` → detection; run only when a
  program fully lowers and all its APIs are implemented (else safe no-op).
  Differential-test verdicts against `clamscan` on the same inputs. (~1 wk)
- **Phase F — long tail (→100%).** The remaining ~19 need `disasm_x86` (an x86
  decoder — the single biggest API, ~4 programs), the PDF/JSON object APIs, the
  `inflate`/`lzma`/`bzip2` codecs (reuse exav's unpack decoders), `jsnorm`,
  `matchicon`, `extract_new`. Each is an isolated, on-demand addition. (~3–6 wk)

**Cross-cutting:** fuzz the decoder/VM every phase; keep execution gated so
partial support can never false-positive or crash; the memory-safe, non-JIT,
strictly-bounded sandbox is invariant throughout.

Phases A–E (~6–8 weeks) reach ~78% coverage with real, safe detections; the
`disasm_x86` long tail (Phase F) is the bulk of the remainder.
