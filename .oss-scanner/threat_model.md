# Threat model

exav is a set of memory-safe tools for files the user did not write: a malware
scanner (`exav`, with a clamd-compatible daemon and an ICAP server), a bounded
extractor (`exav-unpack`), a signature-aware grep (`exav-grep`), an image
hasher (`exav-imagehash`), the renderers behind a browser viewer
(`exav-render`, `exav-viewer`) and WebAssembly bindings (`exav-unpack-wasm`).
`SECURITY.md` at the root is the maintainers' own statement of the same model.

## What this project does and where untrusted input enters

- **A scanned file is fully hostile.** Every byte of it, at any depth of
  nesting: `crates/exav-core` (file typing, PE/ELF/Mach-O parsing, the
  bytecode interpreter, the YARA engine, `.ndb`/`.ldb` matching),
  `crates/exav-unpack` (about 80 archive, disk image, filesystem, document and
  packer decoders), `crates/exav-x86` and `crates/exav-pe-emu` (an x86
  emulator that runs packer stubs), and `crates/exav-render` (PDF, image, DWG,
  DXF, IFC, STL decoding for the viewer).
- **Network input**: the daemon's clamd protocol (`crates/exav/src/daemon.rs`),
  the ICAP listener (`crates/exav/src/icap/`, which parses straight off the
  socket), and with `--features http` the `SCANURL` command and the signature
  updater (`crates/exav-update`).
- **Command-line and daemon arguments** reach `exav-imagehash`, `exav-grep`
  and the `exav` options; they come from the operator, not from a file.
- **The 32-bit WebAssembly build** (`crates/exav-unpack-wasm`,
  `crates/exav-viewer`) has a 32-bit `usize`, no overflow checks and
  `panic=abort`. A sum of two header numbers that cannot wrap on a 64-bit host
  can wrap there and defeat a bounds check.

## Components that matter most / least

Most: the decoders in `crates/exav-unpack/src/formats/`, the PE emulator
(`crates/exav-pe-emu`, `crates/exav-x86`), the bytecode interpreter
(`crates/exav-core/src/bytecode/`), the signature matching engine
(`crates/exav-core/src/engine/`), the daemon and ICAP code, and the code that
decides a result is `OK` rather than `PARTIAL`.

Least: `www/` (the documentation site), `scripts/`, `packaging/`, `corpus/`,
`tmp/`, the test suites and fixtures, and `crates/exav-viewer`'s JavaScript
beyond the places it hands bytes to the Rust or wasm decoders.

## How to exercise it

- Everything is built in `/src/target/debug` and on `PATH`: `exav`,
  `exav-unpack`, `exav-grep`, `exav-imagehash`.
- `exav-unpack FILE` extracts any supported container in memory with the
  default budgets; this is the shortest path to a decoder. `exav-unpack -l`
  lists. It never writes to a path named by the archive.
- `exav` refuses to scan with no signature database. A minimal one for a
  test is a `.ndb` file in a directory: `echo 'Test.Sig:0:*:4558415600' >
  /tmp/db/t.ndb`, then `exav -d /tmp/db FILE`. A `.cbc` bytecode program or
  a YARA rule file in the same directory exercises those engines.
- A decoder panic shows as `decoder panicked` in the output; this is how the
  tests recognise one.
- `fuzz/fuzz_targets/` has a `cargo-fuzz` target for each parser and for the
  whole pipeline (`full_pipeline`, `unpack`). The image has no nightly
  toolchain, so write a proof of concept as an input file for the CLI, or as a
  unit test in the crate, rather than as a fuzz target.
- For the 32-bit class, `crates/exav-unpack/tests/suites/extreme.rs` sets
  header fields to extreme values; `scripts/test-wasm.sh` runs the unit tests
  on `wasm32-wasip1` (it needs `wasmtime`, which the image does not have), so
  reason about 32-bit wraps from the code.

## How you rate severity

- **Critical**: code execution or memory corruption in the exav process from
  scanned bytes (this needs `unsafe`, which is confined to
  `crates/exav/src/daemon.rs`, `crates/exav/src/main.rs` and third-party
  crates); a file-system write outside what the operator configured (the
  extractor decodes in memory and spills only to unnamed temp files, so a
  write to a path taken from an archive is a finding); a remote client of the
  daemon or ICAP port running code or reading files it should not.
- **High**: a file reported `OK` (clean) that was not fully scanned, or whose
  malicious content a signature should have seen: a member skipped, a decoder
  that returns a prefix and no error, a limit that is hit and not reported. This
  is the worst outcome for a scanner and ranks above a crash. Also a
  stack overflow, an allocation that aborts the process, or a loop that does
  not end within the configured limits, from one small file in the one-shot
  CLI; in the prefork daemon these cost one worker, so rate them medium.
- **Medium**: memory or CPU far beyond the documented budgets (decompressed
  bytes, per-member size, compression ratio, file count, recursion depth,
  emulation steps) from a file much smaller than the work it causes
  (amplification); an integer wrap on the 32-bit wasm build that defeats a
  bounds check; a panic that the container boundary does not contain.
- **Low**: a panic that `catch_unwind` contains and reports for that one
  container (`decoder panicked`), with no wrong verdict; a wrong or missing
  name or size in a listing.

## Anything to leave alone

- **A signature database is a trusted input.** A `.cbc`/`.ldb` author running
  a long bytecode loop, or a YARA rule that matches slowly, is not a finding;
  the instruction cap is a failsafe against exav's own bugs. A parser bug
  reachable with a crafted database (a panic or abort on load) is in scope
  at low severity only.
- The `testing-faults` feature lets a scanned file ask a decoder to panic or
  abort so tests can check the reporting; it is never enabled in a shipped
  build.
- A panic that the walk reports as `decoder panicked` with the container then
  marked `PARTIAL` is the designed behaviour, not a bug.
- Findings in third-party crates (hayro, zune, image, ruzstd, xz4rust and the
  like) are welcome only when exav's use of them is what makes them reachable
  or unbounded; report the dependency's own bugs upstream.
- Detection quality (a malware family not detected, a false positive) is not a
  security finding.
- `exav-viewer` rendering differences from the original application are not
  findings; script execution in the sandboxed frames is, but only when it
  crosses the frame boundary.
- Prefer a minimal fix with a test that fails without it: every fixed finding
  in this project has one (see `docs/FUZZING.md`). Deduplicate by root cause
  in one function, not by file format.
