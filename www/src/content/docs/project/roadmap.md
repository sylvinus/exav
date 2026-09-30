---
title: Roadmap
description: What's next for exav, from signature-matching performance and one read pass for large files to broader bytecode coverage, streaming RAR, multi-volume archives and less dependency unsafe.
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

## Large files: fewer passes, PE structure

A file larger than `--max-object-bytes` gets the full engine, read through a
block cache (see [Streaming & memory](/concepts/streaming-memory/)). Two things
remain:

- **One forward pass.** Each part of the scan (the signature automata, YARA's
  patterns, hashes, normalised views, carving) reads the file on its own, so a
  large file is read many times. Feeding them from one pass would make a
  multi-gigabyte scan several times faster, and cheaper over HTTP.
- **PE structure past the limit.** A PE's layout, imports, icons and
  Authenticode signature are parsed from the whole file, so a PE over the limit
  is `LIMITS-EXCEEDED` unless something is found. Reading only the headers and
  sections would cover the common case of a small executable with a large
  overlay.

## Streaming RAR, 7z and OLE

Most containers, DMG disk images included, are walked member by member off the
source, so peak memory is one member rather than the whole decoded object (see
[archive extraction](/concepts/archive-extraction/)). RAR, 7z and OLE containers,
and the virtual disks, are still read whole: past `--max-object-bytes` their own
bytes get the full scan but their members are not extracted, and the file is
`LIMITS-EXCEEDED` unless something is found. Streaming them needs their readers
rewritten. PDF is buffered too, but already holds only the file plus one bounded
object, so there is nothing to gain.

## v2

- A trained static-ML model (the current ML scorer is a transparent heuristic
  baseline, not a trained classifier).
- Broader fuzzy/similarity matching.
- Widening what the PE stub emulator can follow. The
  [x86 interpreter](/concepts/pe-emulation/) already unpacks 15 of the 23
  packers in the measured corpus on every sample and 4 more on most, but a stub
  can still outrun it: an instruction outside the implemented set, a Windows
  export with no implementation, an anti-emulation trick. Each is reported and
  counted, so the list of what to add is measured.
- Verifying Authenticode signatures cryptographically. Parsing, digest checks
  and `.crb` matching exist today.
- RAR AES decryption.
- **Joining format-aware volume sets**: RAR `.partN`/`.rNN`, ZIP `.zNN`, and
  multi-cabinet CAB. Byte-split sets (`x.7z.001`, `x.7z.002`, ...) are already
  joined when their parts arrive together (see
  [split archives](/guides/daemon/#split-archives)). A format-aware volume
  carries its own headers and a member's data resumes past the next volume's
  header, so the join belongs in the format's decoder. ClamAV does not join
  them either; exav reports the split member and scans the part in the volume
  it was given. Sibling volumes will only be looked for next to the scanned
  file, under names generated from its own, as regular files (no symlinks). A
  cabinet names its successor inside the file, so that name will be matched
  against the directory listing and never opened as a path.
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
`exav-unpack` are `#![forbid(unsafe_code)]`), and the default build runs no C,
no UnRAR and no native JIT. The remaining `unsafe` lives in widely used dependency primitives
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

