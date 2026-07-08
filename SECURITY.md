# Security

exav parses untrusted, attacker-controlled files. The parsing/scanning engine
is written in safe Rust, which removes the memory-corruption bug class that
dominates C scanners' CVE history. The `unsafe` surface in exav's own code is
minimal, audited, and confined to two spots, each independently justified:

- **`crates/exav-cli/src/daemon.rs`** — SCM_RIGHTS file-descriptor passing over
  the local clamd-compatible socket (`recvmsg`/`sendmsg` and `File::from_raw_fd`).
  Required for `clamdscan --fdpass` interop; the peer is a local-socket client,
  and every block carries a `SAFETY` comment.
- **`crates/exav-core/src/engine.rs`** — one `DoubleArrayAhoCorasick::deserialize_unchecked`
  when loading a prebuilt cache. The cache is a **trusted artifact** whose
  integrity is verified by a SHA-256 + version header *before* this call (see the
  Prebuilt cache section of the README); it is not meant for untrusted input.

No `unsafe` exists in the parsers that touch hostile file content (file typing,
signature/CVD parsing, archive extraction, PE, the bytecode interpreter). The
residual risks for a memory-safe scanner are denial of service (panics,
unbounded memory, infinite loops) and detection evasion — those are where the
hardening below focuses.

## Threat model

A scanned file (and a signature database loaded with `-d`) is fully hostile and
may be malformed or crafted. exav must:

- never crash the process on any input (panics are isolated per-file);
- never exhaust memory or hang, regardless of input;
- never report a file as clean (`OK`) unless it was actually fully scanned —
  anything that prevents a full scan is reported `LIMITS-EXCEEDED`.

## Defenses

- **Bounded extraction.** Recursive unpacking is governed by a budget:
  total decompressed bytes, per-member size, compression ratio, file count,
  and recursion depth. The budget is reserved *before* each member is read, so
  peak memory across an archive (and nested archives) cannot exceed the total
  cap. Hitting any bound yields `LIMITS-EXCEEDED`, never a clean result.
- **In-memory extraction only.** Archive contents are never written to disk,
  which removes the zip-slip / path-traversal / symlink class entirely.
- **No silent skips.** Files too large for structural analysis are still
  pattern+hash scanned; if such a file is an archive or executable, it is
  reported `LIMITS-EXCEEDED` rather than cleared.
- **64-bit sizes/offsets** throughout; release builds enable `overflow-checks`
  so a wrapping size calculation panics (and is then contained) rather than
  silently bypassing a limit.
- **Panic isolation.** Each file is scanned under `catch_unwind`; a parser
  panic on one file is reported as an error and does not abort a batch.
- **Continuous fuzzing.** Every parser (file typing, signature text, CVD
  container, archive extraction, PE) and the full pipeline has a `cargo-fuzz`
  target under `fuzz/`. CI runs a smoke pass; extended/continuous fuzzing is
  recommended before production use.
- **Dependency auditing.** CI runs `cargo audit` and `cargo deny` against the
  RustSec advisory database.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than a
public issue. We aim to acknowledge within a few days.
