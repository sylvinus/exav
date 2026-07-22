---
title: Bytecode sandbox
description: What ClamAV .cbc bytecode signatures are, and why exav's memory-safe, non-JIT interpreter removes the code-execution class that has affected ClamAV.
---

ClamAV's most expressive signature type is **bytecode**: a small program (written
in C, compiled to a custom VM bytecode, shipped as a `.cbc` file in
`bytecode.cvd`) that runs against a candidate file and decides whether it's
malicious. It expresses detection logic that pattern and logical signatures
can't — most valuably, a handful of **unpackers** that deobfuscate packed PEs so
the other millions of signatures can match the payload.

exav implements a reader and a **memory-safe, sandboxed interpreter** for this
format. The headline is not extra coverage (the live DB is only 85 programs) —
it's that exav runs them **without the code-execution class** that has
affected ClamAV's bytecode subsystem.

## The format, in brief

A `.cbc` file is line-oriented: a `ClamBC` header, a **trigger line** (a `.ldb`
logical signature — the program runs *only* when this matches a file), and
records for types, API declarations, globals, function headers, basic-block
instruction streams, and strings. The instruction set is an LLVM-IR-like SSA
form. Programs cannot make syscalls; they reach the outside world only through a
fixed **host API** — a table of **107 functions**, identical in ClamAV 1.4.3 and
1.5.3: `read`/`seek`/`file_find` to inspect the file, PE/PDF/JSON accessors,
hashing, and `setvirusname` to report a hit.

The trigger side is free for exav because it already has a full `.ldb` engine.

## Why exav's interpreter has a smaller attack surface

ClamAV's bytecode subsystem has a **documented code-execution history**, because
it executes DB-supplied programs in memory-unsafe C and historically via an LLVM
JIT:

- **[CVE-2020-37167](https://www.cve.org/CVERecord?id=CVE-2020-37167)** — weak
  validation in the bytecode interpreter's function-name processing (CWE-94 code
  injection) lets a crafted `.cbc` corrupt the VM's memory and chain to
  arbitrary code execution in the scanner process, with a
  [public ROP exploit](https://www.exploit-db.com/exploits/47687) (exploit-db
  47687, the `bytecode_vm` sandbox escape). **CVSS 8.4**; ClamAV before
  0.103.0. Also tracked by
  [Ubuntu](https://ubuntu.com/security/CVE-2020-37167).
- The optional **LLVM JIT** generated and ran native code from bytecode — a large
  attack surface Cisco has been moving away from.

exav removes these failure modes by construction:

| Risk in ClamAV's C VM | exav |
|---|---|
| Memory corruption in the VM (the CVE-2020-37167 class) | **Pure safe Rust, no `unsafe`** — every memory access is a bounds-checked slice; an out-of-range index panics into isolation, it cannot corrupt memory |
| Native code generation from bytecode (JIT spray, W^X issues) | **No JIT, ever** — interpret only |
| A program escaping the sandbox (syscalls, host memory) | The program sees only bounded `Vec`s and a fixed read-only file API — no syscalls, no host pointers |
| Runaway program (CPU/memory exhaustion) | **Instruction budget**, scratch-memory cap, and call-depth limit |
| A parser/VM bug taking down the scan | **`catch_unwind` per program** (and per file) — one bad program is skipped, the scan continues |
| Malformed/hostile `.cbc` | Fallible parser (no panics); 100% of the live DB parses cleanly; a program not fully understood is **never executed** |

The net: the worst a hostile or buggy `.cbc` can do to exav is *be skipped or
time out*. In ClamAV the worst case has been *arbitrary code execution*. For anyone
who disables ClamAV bytecode for safety, exav offers the capability **without
that trade-off**.

## Trigger-gated execution, and the API subset

Execution is **live in the normal scan path**, trigger-gated per program: a
program runs only when its logical-signature trigger matches. The gating is
per-program, not a global off switch.

exav implements **34 of the 107 host APIs**. The other 73 are present as
**fail-safe stubs** rather than as a reason to skip the program: a call to one
returns a conservative value and is recorded, so the program still runs to the
end. Every stub that actually fabricates a result is surfaced in the run's
outcome (and warned under `EXAV_BC_WARN`), because a verdict that rests partly
on fiction must never look like one that does not.

What that buys, measured on a live `bytecode.cvd`: exav parses **100% of the 85
programs** and **all 85 execute to completion** with no unsupported opcode.
Across 400 real malware samples, exactly **one** stub was ever reached
(`get_environment`). A `.cbc` header declares a `maxapi` *ceiling*, not a call
list — which is why a third of the table has been enough for all of the shipped
programs so far. The
[full per-group breakdown of the 56 unimplemented reachable APIs](/project/comparison-with-clamav/#bytecode-host-apis--34-of-107)
is in the ClamAV gap list.

## Real-world weight

Numerically the 85 programs are 0.002% of ~3.7M signatures, but uneven in value:
the ~6 **unpackers** matter most (missing one silently weakens detection
across many packed samples), the polymorphic-family checks each catch a whole
family, and a long tail of ~36 are legacy single-CVE checks. The detection delta
is modest — which is why exav's win here is the memory-safe, non-JIT sandbox,
more than the raw extra coverage.
