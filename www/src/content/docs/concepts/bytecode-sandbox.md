---
title: Bytecode sandbox
description: What ClamAV .cbc bytecode signatures are, and why exav's memory-safe interpreter with no JIT removes the code-execution class that has affected ClamAV.
---

ClamAV's most expressive signature type is bytecode: a small program (written in
C, compiled to a custom VM bytecode, shipped as a `.cbc` file in `bytecode.cvd`)
that runs against a candidate file and decides whether it is malicious. It
expresses logic that pattern and logical signatures cannot, most usefully a
handful of unpackers that deobfuscate packed PEs so the other signatures can
match the payload. What an unpacker produces is scanned like an archive member:
through the whole pipeline, under the same depth and scan budgets.

exav implements a reader and a memory-safe, sandboxed interpreter for this
format. The live database holds few programs, so the point is less extra
coverage than running them without the code-execution class that has affected
ClamAV's bytecode subsystem.

## The format, in brief

A `.cbc` file is line-oriented: a `ClamBC` header, a trigger line (a `.ldb`
logical signature; the program runs only when it matches, or on every file of
one type for a program that hooks it instead), and records for types,
API declarations, globals, function headers, basic-block instruction streams
and strings. The instruction set is an SSA form close to LLVM IR. Programs cannot
make syscalls; they reach the outside world only through a fixed host API of 107
functions (the same in ClamAV 1.4.3 and 1.5.3): `read`/`seek`/`file_find` to
inspect the file, PE/PDF/JSON accessors, hashing, and `setvirusname` to report a
hit. The trigger side comes for free with exav's `.ldb` engine.

## Why the attack surface is smaller

ClamAV's bytecode subsystem has a documented code-execution history, because it
runs database-supplied programs in memory-unsafe C and, historically, through an
LLVM JIT. An attacker needs to get a `.cbc` file loaded, from a third-party feed
for instance:

- **[CVE-2020-37167](https://www.cve.org/CVERecord?id=CVE-2020-37167):** weak
  validation in the interpreter's function-name processing (CWE-94) lets a
  crafted `.cbc` corrupt the VM's memory and chain to arbitrary code execution
  in the scanner process, with a
  [public ROP exploit](https://www.exploit-db.com/exploits/47687) (exploit-db
  47687, the `bytecode_vm` sandbox escape). CVSS 8.4; ClamAV before 0.103.0.
  Also tracked by [Ubuntu](https://ubuntu.com/security/CVE-2020-37167).
- The optional LLVM JIT generated and ran native code from bytecode, a large
  attack surface Cisco has been moving away from.

exav removes these failure modes by construction:

| Risk in ClamAV's C VM | exav |
|---|---|
| Memory corruption in the VM (the CVE-2020-37167 class) | Safe Rust with no `unsafe`: every access is a bounds-checked slice, and an out-of-range index panics into isolation instead of corrupting memory |
| Native code generation from bytecode | No JIT: interpretation only |
| A program escaping the sandbox (syscalls, host memory) | The program sees only bounded buffers and a fixed read-only file API: no syscalls, no host pointers |
| A runaway program | An instruction budget, a scratch-memory cap and a call-depth limit |
| A VM bug taking down the scan | `catch_unwind` per program: a bad program is stopped and the scan continues |
| A malformed or hostile `.cbc` | A fallible parser with no panics; a program not fully understood is never executed |

The worst a hostile or buggy `.cbc` can do to exav is be skipped or be stopped.
A program stopped before it finished (out of instructions, or a VM panic) makes
the scan `LIMITS-EXCEEDED` unless something is found, since what it would have
found is unknown. exav can run these programs with the code-execution risk
removed, for anyone who disables ClamAV bytecode for safety.

## Trigger-gated execution, and the API subset

Execution is live in the normal scan path and gated per program: a program runs
only when its logical-signature trigger matches. The few programs with no
trigger (two PDF hooks in the current `bytecode.cvd`) run on every file of the
type they hook.

exav implements about 40 of the 107 host API functions. The rest are fail-safe
stubs rather than a reason to skip a program: a call returns a conservative value
and is recorded, so the program still runs to the end. A stub that fabricates a
result is recorded in the run's outcome and, with the `EXAV_BC_WARN`
environment variable set, printed to stderr. On a live
`bytecode.cvd`, every program parses and runs to completion with no unsupported
opcode, and in practice programs rarely reach a stub: a `.cbc` header declares a
`maxapi` ceiling, not a call list. The per-API breakdown is in the repository's
[`docs/BYTECODE.md`](https://github.com/sylvinus/exav/blob/main/docs/BYTECODE.md).

## Real-world weight

Bytecode programs are a tiny fraction of the signatures, and uneven in value: the
few unpackers matter most (missing one weakens detection across many packed
samples), the polymorphic-family checks each cover a whole family, and a long
tail are legacy single-CVE checks. The detection difference is modest, which is
why the memory-safe sandbox is the main gain.
