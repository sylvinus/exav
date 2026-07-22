---
title: Roadmap
description: What's next for exav — signature-matching performance, broader bytecode coverage, PE protectors, decryption, and driving down dependency unsafe.
---

exav is **beta**. The current focus is closing the known gaps below — none of
which silently affect a verdict.

There is no known input for which exav reports a clean `OK` while ClamAV detects
malware. If you find one, [that is a bug](/project/security/), not a roadmap
item — see [zero known silent false
negatives](/project/comparison-with-clamav/#zero-known-silent-false-negatives)
for what that claim does and does not cover.

## Now → next

- **Signature-matching performance** on large inputs against the full DB.
  (Wildcard verification is already non-backtracking — see
  [Performance](/project/comparison-with-clamav/#performance) — so what remains
  is raw automaton throughput, not pathological blow-up.)
- **Broader bytecode coverage** — trigger-gated execution is
  [live](/concepts/bytecode-sandbox/) and all 85 programs in a live
  `bytecode.cvd` run to completion. 34 of ClamAV's 107 host APIs are
  implemented; 56 of the 90 indices any shipped program can reach are stubbed
  and return fail-safe values (only `get_environment` was reached across 400
  real samples). The work worth doing first is the groups a real program could
  plausibly need — buffer pipes, maps, `inflate` — rather than the debug/trace
  instrumentation, plus differential validation vs `clamscan`. Breakdown in
  [the gap list](/project/comparison-with-clamav/#bytecode-host-apis--34-of-107).
- **Extended/continuous fuzzing** and a >10 GB no-silent-skip CI suite.

## Streaming the last three container formats

exav optimises for **memory**, not bandwidth. A streamable format is walked
member-by-member straight off the seekable source, so peak memory is one
member's window rather than the whole decoded object. Most containers already
work that way — see [`is_streamable`][streamable] — including tar, zip, 7z and
cab. Three do not, for different reasons, and only two of them are worth
changing.

**DMG — the tractable one, and the next concrete step.** `decompress_udif`
materialises the entire virtual disk into one `Vec` because the HFS+/APFS
readers need random access over it, so a 4 GB image costs 4 GB of resident
memory (bounded by the peak-buffer limit, which means large images are refused
rather than scanned). The reader is already the right shape: `DmgReader` is
position-based, mapping an offset to a BLKX run and decompressing that run. Two
pieces are missing. First a decompressed-run cache: `read` currently
re-decompresses the containing run on every call, which is fine for a linear
pass and unusable under the seek storms a filesystem crate generates. Then
`impl Seek`, after which the reader can be handed to the filesystem crates
directly instead of a materialised image. Roughly 150 lines, and it converts a
whole-image allocation into one cached run.

**RAR — real work, deliberately not rushed.** `rar3_unpack.rs` (1,851 lines) and
`rar5_unpack.rs` (955) are vendored decoders that build the complete output
`Vec`. Streaming them means turning both into resumable `Read` state machines
that retain only the already-capped LZ window — major surgery on fuzzed,
differential-tested code, where a subtle break costs correctness on a format
attackers actively use. It is a focused effort of its own, not a change to slip
in alongside others.

**PDF — measured, and not worth doing.** `extract_pdf` already decompresses
stream objects one at a time into a budget-bounded buffer, and the file itself
has to be buffered regardless because the xref table lives at the end and the
recovery path scans the whole file. Peak is therefore already input plus one
bounded object; streaming would save a single bounded body. The memory problem
the other two solve does not exist here.

[streamable]: /concepts/archive-extraction/

## v2

- A trained static-ML model (the current ML scorer is a transparent heuristic
  baseline, not a trained classifier).
- Broader fuzzy/similarity matching.
- Widening what the PE stub emulator can follow. The
  [x86 interpreter](/concepts/pe-emulation/) already runs the emulation-required
  packers (ASPack / MEW / Upack / wwpack32 / PESpin / yC) rather than merely
  detecting them, but a stub can still outrun it — an instruction outside the
  implemented set, a Windows export with no implementation, an anti-emulation
  trick. Each of those is reported and counted rather than guessed at, which is
  what makes the list of things to add a measurement instead of a guess.
- The Authenticode signature-verification engine.
- RAR AES decryption. Joining RAR volume sets is listed here as *reach*, not
  parity: ClamAV does not join them either (verified — a set whose payload lives
  only in the last volume returns `OK` there). exav reports the split member and
  scans the part present in the volume it was given.
- The 4 unimplemented `Target:` values (graphics, internal, other, and ClamAV's
  reserved slot 8) and the unloaded database extensions (`.cat`, `.ioc`, and the
  legacy `.sdb`/`.zmd`/`.rmd`). None appears in a stock official database; all
  matter for third-party feeds. See
  [Targets](/project/comparison-with-clamav/#targets--11-of-15).

## v3 (optional)

- QEMU/KVM dynamic detonation — a separate, heavyweight feature, only if demand
  warrants.

## Hardening: drive down dependency `unsafe`

exav's own scanning and extraction code is safe Rust (`exav-core` and
`exav-unpack` are `#![forbid(unsafe_code)]`), and it runs no C, no UnRAR, and no
native JIT. It is **not** zero-`unsafe`, though — the residual lives in audited,
widely-used dependency primitives (compression/crypto SIMD, OS syscalls), not in
attacker-driven parsing logic. Reviewing and shrinking that surface is an explicit
ongoing goal:

- **Audit** every production dependency's `unsafe` (e.g. `cargo geiger`),
  categorized by kind and by reachability from a hostile-input scan path.
- **Drop** deps we don't need (already done: `tar`'s `xattr`, which removed the
  largest syscall-`unsafe` source).
- **Make safe** what we can: prefer portable/no-SIMD builds where the speed cost
  is acceptable, and vendor-then-make-safe (the RAR PPMd decoder is already
  zero-`unsafe`).
- **Reuse our own safe code** instead of an `unsafe` dependency where an
  equivalent already exists.
- **Verify** the residual with `cargo-fuzz` + Miri, and document containment
  (panic isolation, the prefork process boundary, the WASM-sandboxed extractor).

