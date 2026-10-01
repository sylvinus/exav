---
title: Design principles
description: The principles exav is built around, from never a silent clean and memory safety to no runtime code generation, bounded work, work done at database build time, drop-in compatibility and clean-room licensing.
---

exav is built around a handful of principles. Some protect the host, some protect
the verdict, and some make exav practical to adopt. One ties them together: a
scan that stopped short is reported as such.

## Never a silent clean

> Never report a file clean unless it was fully scanned.

A clean verdict is a safety claim. If exav did not finish looking, `OK` would be
a false claim that an attacker can arrange on purpose, by padding a payload past
a size limit or wrapping it in something the scanner gives up on. So anything
that makes the scanner stop early, for any reason, is reported instead of being
folded into `OK`.

ClamAV, for example, reads a file over about 2 GB, scans none of it, and reports
`OK`. exav closes that gap and every other way a scan can stop early.

Three rules follow:

1. **A detection beats a limit.** A signature match is reported `FOUND`, even if
   another part of the input hit a budget.
2. **Refusing by size still scans.** An input over `--max-input-bytes` is not
   skipped: its first `--max-input-bytes` bytes get the same scan as a smaller
   input, so a payload there is still caught, and the input is reported
   `LIMITS-EXCEEDED`. Otherwise `cat malware huge.pad > evil` would be a bypass.
   A file, stdin and every daemon verb go through that one scan.
3. **Not fully scanned is never clean, whatever the cause.** That covers external
   limits and exav's own work bounds: the budget that stops a pathological
   wildcard search, a PE emulation that runs out of instructions
   (`--max-pe-emulation-steps`), a bytecode program that runs out of steps or
   reaches an opcode or API exav does not model. A bytecode program that fails
   on its own (an out-of-bounds access) is discarded, as ClamAV discards it.

A scan that did not complete resolves to `LIMITS-EXCEEDED`, `UNSCANNABLE` or
`PASSWORD-PROTECTED`. See [Verdicts & exit codes](/reference/verdicts/) for what
each means and how it is reported.

### Stricter than ClamAV

`clamscan` returns `OK` after bounding its own work (its `alert-exceeds-max` and
`alert-encrypted` heuristics are off by default); exav does not. It is the main
behavioral difference a migrating user has to plan for, along with the flags
(see [Migrating from ClamAV](/guides/migrating-from-clamav/)). The one exception
is asked for by name:
[`--clamav-compat`](/reference/cli/#clamav-compatibility), a preset for
differential testing, answers an incomplete scan `OK` as ClamAV does and logs
each such object on stderr.

### The verdict is not the policy

Reporting a bound and acting on it are different jobs. The engine always reports
`LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`; what a deployment does
with that is its own decision, and some will reasonably deliver the object anyway
rather than reject an upload.

Where a deployment chooses that, with
[`--partial-as ok`](/reference/cli/#what-an-unscannable-object-becomes), the
choice is named per verdict and logged per object on stderr; the ICAP service
also announces it at startup and keeps `X-Exav-Status: PARTIAL` in its response.
The rule does not forbid accepting a risk; it forbids hiding one.

### Refusing empty coverage

With no real signature database loaded (absent, empty, or with no signatures),
exav refuses to run rather than answer scans against near-zero coverage. The
built-in EICAR-only baseline is opt-in with `--allow-no-db`, for testing.

## Memory safety

exav is written in Rust. The scanning and extraction crates are
`#![forbid(unsafe_code)]`; the remaining `unsafe` lives in widely used
dependency primitives (compression and crypto SIMD, OS syscalls) and in the
daemon's calls into libc, not in the code that parses hostile input. Reducing it
further is an ongoing goal (see the [roadmap](/project/roadmap/)).

## No runtime code generation

Nothing is compiled to native code at scan time. Bytecode programs and YARA rules
run on interpreters, so there is no writable and executable memory while
scanning, which rules out a whole class of exploitation primitive.

## Clean-room, permissive licensing

exav is MIT-licensed and derives nothing from GPL sources. Everything is
implemented from public specifications and permissively licensed
(MIT/BSD/Apache/public-domain) code, with attribution. See
[Contributing](/project/contributing/) and [License](/project/license/).

## Bounded work and memory

Every decode and match is bounded by size or by a step count, so hostile input
cannot turn a scan into an unbounded computation or allocation; the prefork
daemon adds a per-job wall-clock and CPU limit on top. Most archives are walked
member by member, and the main bounds are flags. Reaching a bound on the scan is
reported, never a silent truncation. See
[Streaming & memory](/concepts/streaming-memory/) and [Limits](/reference/limits/).

## Work at build time

> Whatever can be computed once from the signatures is computed when the
> database is built, not when it is loaded or when a file is scanned.

A [prebuilt `.exavdb`](/guides/prebuilt-database/) is built once and loaded by
every CLI run, daemon start and reload, then shared by every worker. So the
build does the expensive
work (the anchor index, tables derived from the signatures) and stores the
result in a form that loads with little more than a copy. Load time and scan
speed come first; a larger file is an acceptable price.

## Minimal dependencies

exav prefers small crates and a pure-Rust dependency tree, for auditability,
`unsafe` surface, and binary and WASM size. The native
[YARA engine](/guides/yara/), for instance, is a compact tree-walking evaluator
with no WASM runtime and no code generation. Every crate in the default build is
listed on the [Dependencies](/reference/dependencies/) page.

## Drop-in compatibility

exav loads the signature databases you already have, speaks the `clamd` wire
protocol, and prints `clamscan`'s output format and exit codes (plus exit code 3
for `PARTIAL`), so it fits into
an existing deployment without rewriting tooling. Its flags are its own. See
[Comparison with ClamAV](/project/comparison-with-clamav/) and
[Migrating from ClamAV](/guides/migrating-from-clamav/).
