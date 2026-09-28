---
title: Roadmap
description: What's next for exav, from signature-matching performance and a streaming full engine to broader bytecode coverage, PE protectors, decryption, and less dependency unsafe.
---

exav is beta. The current focus is the known gaps below, none of which lets an
incomplete scan pass as clean.

An input for which exav reports `OK` while ClamAV detects malware is
[a bug](/project/security/), not a roadmap item. See
[silent false negatives](/project/comparison-with-clamav/#silent-false-negatives)
for how they are looked for.

## Now → next

- **Signature-matching performance** on large inputs against the full database.
  Wildcard verification is already non-backtracking (see
  [Performance](/project/comparison-with-clamav/#performance)), so what remains
  is raw automaton throughput.
- **Broader bytecode coverage.** Trigger-gated execution is
  [live](/concepts/bytecode-sandbox/) and every program in a live `bytecode.cvd`
  runs to completion, but many of ClamAV's host APIs are still stubs returning
  fail-safe values. The groups a real program could need (buffer pipes, maps,
  `inflate`) come first, with differential validation against `clamscan`.
- **Extended and continuous fuzzing**, and a large no-silent-skip CI suite.

## A streaming full engine

The full signature engine (wildcard, anchored and file-type `.ndb` signatures,
`.ldb` logical signatures, YARA, bytecode, the normalised text views) scans a
file held in memory, up to `--max-object-bytes` (256 MiB by default). A larger
file only gets the streaming matcher, which covers literal signatures and
whole-file hashes, and is reported `LIMITS-EXCEEDED` unless one of those
matches.

The goal is a full engine that reads a file as a stream: partial matches carried
across chunk boundaries, per-signature state kept for logical signatures, and
end-of-file and file-size conditions resolved once the stream ends. A file of any
size would then be checked against every signature in bounded memory.

## Streaming the last three container formats

Most containers are walked member by member off the source, so peak memory is
one member rather than the whole decoded object (see
[archive extraction](/concepts/archive-extraction/)). DMG and RAR are still
decoded whole, so a large disk image or RAR archive is refused as
`LIMITS-EXCEEDED` past `--max-object-bytes` rather than scanned. DMG is the next
to stream; RAR needs its decoders rewritten and will take longer. PDF is
buffered too, but already holds only the file plus one bounded object, so there
is nothing to gain.

## v2

- A trained static-ML model (the current ML scorer is a transparent heuristic
  baseline, not a trained classifier).
- Broader fuzzy/similarity matching.
- Widening what the PE stub emulator can follow. The
  [x86 interpreter](/concepts/pe-emulation/) already runs the packers that need
  emulation (ASPack, MEW, Upack, wwpack32, PESpin, yC), but a stub can still
  outrun it: an instruction outside the implemented set, a Windows export with no
  implementation, an anti-emulation trick. Each is reported and counted, so the
  list of what to add is measured.
- The Authenticode signature-verification engine.
- RAR AES decryption, and joining RAR volume sets. ClamAV does not join them
  either; exav reports the split member and scans the part in the volume it was
  given.
- The unimplemented `Target:` values (graphics, internal, other, and ClamAV's
  reserved slot 8) and the unloaded database extensions (`.cat`, `.ioc`, and the
  legacy `.sdb`/`.zmd`/`.rmd`). None appears in a stock official database; all
  matter for third-party feeds. See
  [Targets](/project/comparison-with-clamav/#targets).

## v3 (optional)

- QEMU/KVM dynamic detonation: a separate, heavyweight feature, only if there is
  demand.

## Hardening: less dependency `unsafe`

exav's own scanning and extraction code is safe Rust (`exav-core` and
`exav-unpack` are `#![forbid(unsafe_code)]`), and it runs no C, no UnRAR and no
native JIT. The remaining `unsafe` lives in widely used dependency primitives
(compression and crypto SIMD, OS syscalls), not in the code that parses hostile
input. Reducing it is an ongoing goal:

- **Audit** every production dependency's `unsafe` (e.g. with `cargo geiger`), by
  kind and by reachability from a hostile-input scan path.
- **Drop** dependencies exav does not need (done for `tar`'s `xattr`, which was
  the largest source of syscall `unsafe`).
- **Make safe** what can be: portable builds without SIMD where the speed cost is
  acceptable, and vendoring then removing `unsafe` (the RAR PPMd decoder has
  none).
- **Reuse exav's own safe code** where it duplicates an `unsafe` dependency.
- **Verify** the rest with `cargo-fuzz` and Miri (`make miri`), and document the
  containment (panic isolation, the prefork process boundary, the WASM build).

