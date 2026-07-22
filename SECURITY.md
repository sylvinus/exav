# Security

exav parses untrusted, attacker-controlled files. The parsing/scanning engine
is written in safe Rust, which removes the memory-corruption bug class that
dominates C scanners' CVE history.

**No `unsafe` exists anywhere near hostile file content.** `exav-core` (file
typing, signature/CVD parsing, PE parsing, the bytecode interpreter, the YARA
engine), `exav-unpack` (every archive/document decoder), `exav-x86` (the
instruction decoder), `exav-pe-emu` (the packer emulator) and `exav-update` all
carry `#![forbid(unsafe_code)]` — the compiler enforces it.

One crate does not: `crates/exav-unpack-wasm`, the WebAssembly bindings
published to npm. `#[wasm_bindgen]` expands to `unsafe`, and `forbid` cannot be
overridden from inside, so the attribute has to be absent for the crate to
build at all. The decoders it exposes are the same `forbid`-carrying
`exav-unpack` code; the exception covers the generated binding layer.

All of exav's own `unsafe` lives in one file, **`crates/exav-cli/src/daemon.rs`**,
and none of it touches scanned bytes:

- **Process control for the prefork worker pool** — `fork`, `waitpid`, `kill`,
  `_exit`, `getpid`/`getppid`.
- **Signal and resource-limit setup** — `sigaction`/`signal`/`sigemptyset`,
  `setitimer` (the per-job watchdog), `setrlimit` (the kernel-enforced per-worker
  caps).
- **SCM_RIGHTS file-descriptor passing** over the local clamd-compatible socket
  (`recvmsg`/`sendmsg` + `File::from_raw_fd`): the daemon's `FILDES` command and
  the client's `--send-as fd`, required for `clamdscan --fdpass` interop. The
  peer is a local-socket client.
- **Socket creation mode** — `umask` around the daemon's `bind`, so the Unix
  socket is created with no permissions and carries the mode its address asked
  for before any client can reach it, whatever mask the daemon inherited.

Everything else is safe Rust; the residual `unsafe` in third-party dependencies
(compression/crypto SIMD, syscall shims) is inventoried at
<https://exav.org/reference/dependencies/>.

The residual risks for a memory-safe scanner are denial of service (panics,
unbounded memory, infinite loops) and detection evasion — those are where the
hardening below focuses.

## Threat model

**A scanned file is fully hostile** and may be malformed or crafted. Against
one, exav must:

- never crash the process (panics are isolated per-file);
- never report a file as clean (`OK`) unless it was actually fully scanned —
  anything that prevents a full scan is reported `LIMITS-EXCEEDED`,
  `UNSCANNABLE` or `PASSWORD-PROTECTED` (exit code 2);
- stay within its budgets, which bound decompressed bytes, per-member size,
  compression ratio, file count and recursion depth.

**A signature database is a trusted input.** Load only databases you trust.
Detection content is code — `.cbc` bytecode programs run on an interpreter, and
YARA rules compile to automata — so the budgets that apply to it are failsafes
against exav's own bugs, not defences against a hostile author. The instruction
cap on a bytecode program bounds a runaway loop; it is not sized to make a
malicious program safe, and nothing checks that a database's rules are
well-intentioned. A database fetched over the network is trusted to the same
degree as the mirror it came from.

To scan with a database you do not trust, run exav under a sandbox that bounds
it from outside — the WebAssembly build, or the prefork daemon, whose workers
carry kernel-enforced address-space and CPU limits and are replaced when killed.

**Bounds are not absolute.** Two failure modes are outside what in-process
budgets can reach, in any deployment: an allocation large enough to abort the
process (Rust aborts rather than unwinding, so the per-file panic boundary does
not catch it), and unbounded recursion inside a single file's parser, which the
container-nesting limit does not govern. The daemon contains both with
`RLIMIT_AS` and worker replacement: one hostile file costs one job. A one-shot
run applies the same rlimits when `--max-process-bytes` / `--max-scan-secs` are
given, but with no second process behind it the run ends rather than continuing.
A library embedding has neither unless the host process sets the rlimits itself,
and should not be treated as though it did.

Counting allocations in-process would not change this. A refusal only becomes a
recoverable error where the allocating code asked fallibly (`try_reserve`), which
across exav's decoder dependencies is a handful of files out of hundreds;
everywhere else Rust routes allocation failure to an abort, so a ceiling would
abort on allocations the machine could have served. Address space is the layer
that can refuse safely, which is why the bound lives there.

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
  reported `LIMITS-EXCEEDED` rather than cleared. An unsupported codec is
  `UNSCANNABLE` and an encrypted member `PASSWORD-PROTECTED` — never `OK`.
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
