---
title: Design principles
description: The principles exav is built around — never a silent clean, memory safety, no runtime codegen, constant-memory streaming, minimal dependencies, drop-in compatibility, bounded work, and clean-room licensing.
---

exav is built around a handful of principles. They reinforce each other: several
are about *safety* (of the host, and of the verdict), several are about *fit*
(dropping into an existing setup and staying lean), and one ties the rest
together — every bound the engine hits is surfaced, never hidden.

## Never a silent clean

This is the invariant the whole verdict model is built around:

> **Never report a file clean unless it was actually, *fully* scanned.**

A scanner's clean verdict is a safety claim. If exav did not finish looking,
claiming `OK` is a lie an adversary will engineer. Anything that makes the
scanner *stop looking early* — for **any** reason, no exceptions — must surface,
never be swallowed into `OK`.

### Why this is a security property, not a nicety

ClamAV has a long-standing large-file limitation: files over ~2 GB are read but
scanned as **zero bytes** and still reported **`OK` / clean**. That's a silent
clean verdict on data that was never inspected — exactly the kind of gap an
attacker pads a payload to exploit. exav closes it, and generalizes the fix to
*every* reason a scan might stop early.

The invariant holds in every mode, including `--clamav-compat`. Compat changes
the *names* exav reports and the rough scope of what it opens so a differential
run compares like with like — it does not switch unpackers off. A miss is a miss
whichever mode produced it.

Three rules follow:

1. **A detection always beats a limit.** A signature match is reported `FOUND`,
   never downgraded because some *other* part of the input tripped a budget.
2. **Never refuse by size without scanning.** A file over `--max-extracted-bytes`
   isn't skipped wholesale — the flat pattern/hash core still runs over the
   in-budget bytes, so a payload in the scanned prefix is still caught. Otherwise
   `cat malware huge.pad > evil` would be a one-line bypass.
3. **Not-fully-scanned is never clean — whatever the cause.** This is exhaustive:
   it covers external resource limits **and exav's own internal work bounds**. If
   the engine caps its own effort (a per-buffer verification-step budget that
   bounds pathological wildcard backtracking, a matcher time/step budget), hitting
   that cap without finishing surfaces as a non-clean verdict.

Anything not fully scanned resolves to `LIMITS-EXCEEDED`, `UNSCANNABLE`, or
`PASSWORD-PROTECTED` — distinct, non-clean, and reported rather than hidden. See
[Verdicts & exit codes](/reference/verdicts/) for what each one means and how it
maps to a status tag and process exit code.

### Stricter than ClamAV, on purpose

This invariant holds even where it makes exav stricter than ClamAV. `clamscan`
silently returns `OK` after bounding its own work (its `alert-exceeds-max` /
`alert-encrypted` heuristics are off by default); exav does not. That is the one
deliberate behavioral difference a migrating user should know — see
[Migrating from ClamAV](/guides/migrating-from-clamav/). `--clamav-compat`
matches ClamAV's *limit values* for differential testing, but exav still surfaces
the outcome rather than hiding it.

### The invariant is about the verdict, not about the policy

Surfacing a bound and *acting* on it are different jobs. The engine always
reports `LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED` rather than
`OK`; what a deployment does with that verdict is the deployment's call, and some
of them will reasonably choose to deliver the object anyway rather than reject a
user's upload.

Where a deployment makes that choice — [`--not-scanned pass`](/guides/icap/)
is the one that does — it is opt-in, named per verdict, announced at startup,
logged per object, and still reported in the response. What the invariant rules
out is not an operator accepting a risk; it is a scanner *hiding* one. A pass
nobody configured, or one nobody can see in a log, is the failure this principle
exists to prevent.

### The daemon refuses empty coverage too

The same principle extends to configuration. With **no real signature database**
loaded (absent, empty, or a signature-less DB), exav **refuses to run** rather
than answer scans against near-zero coverage — a reachable scanner that silently
passes real malware as clean is the exact bypass exav exists to prevent. The tiny
built-in EICAR-only baseline is opt-in via `EXAV_ALLOW_NO_DB` (testing/CI only).

## Memory safety

exav is written in Rust with minimal `unsafe`. The scanner parses hostile input
by design, so the core scanning and extraction crates are
`#![forbid(unsafe_code)]`; the residual `unsafe` lives only in audited,
widely-used dependency primitives (compression/crypto SIMD, OS syscalls), not in
attacker-driven parsing logic — and driving that surface down is an explicit,
ongoing goal.

## No runtime codegen (W^X / no JIT)

Nothing is compiled to native code at scan time. The bytecode programs and YARA
rules run on interpreters/evaluators, so there is no writable-executable memory
while scanning — closing an entire class of exploitation primitive.

## Clean-room & permissive licensing

exav is MIT-licensed and derives nothing from GPL sources. Every part is
implemented from public specifications and permissively-licensed
(MIT/BSD/Apache/public-domain) code with attribution. See
[Contributing](/project/contributing/) and [License](/project/license/).

## Constant-memory streaming

The per-scan working set stays flat regardless of file size. A multi-gigabyte
file and a one-kilobyte file use the same forward-pass machinery and the same
tiny (~2 MiB) working set — so exav scans inputs larger than RAM. See
[Streaming & memory](/concepts/streaming-memory/).

## Minimal dependencies

exav favors small leaf crates and a lean, pure-Rust dependency tree — for
control, auditability, `unsafe` surface, and binary/WASM size. The native
[YARA engine](/guides/yara/), for instance, is a compact tree-walking evaluator
that needs no WASM runtime and no JIT/codegen backend. Every crate in the
default build is listed on the [Dependencies](/reference/dependencies/) page.

## Drop-in compatibility

exav loads the signature databases you already have, speaks the `clamd` wire
protocol, and matches an established scanner's CLI flags, output, and exit
codes — so it fits into an existing deployment without rewriting tooling. See
[Comparison with ClamAV](/project/comparison-with-clamav/) and
[Migrating from ClamAV](/guides/migrating-from-clamav/).

## Bounded work

Every decode and match is size-, time-, and step-bounded, so hostile input can't
turn a scan into an unbounded computation or allocation. Hitting a bound is never
swallowed: it surfaces as a non-clean verdict, never a silent truncation.

## How they fit together

*Memory safety* and *no runtime codegen* protect the **host** running exav.
*Never a silent clean* and *bounded work* protect the **verdict** — a bound is
always visible. *Constant-memory streaming*, *minimal dependencies* and *drop-in
compatibility* make exav practical to run at scale and to adopt in place. And
*clean-room licensing* keeps the whole thing permissively licensed and
independently built.
