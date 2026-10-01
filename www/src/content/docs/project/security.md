---
title: Security
description: exav's threat model and hardening, from memory safety, bounded extraction and panic isolation to the position on residual unsafe and database trust.
---

A scanner reads files an attacker chose, and the engine is built to contain
them. The repository's
[`SECURITY.md`](https://github.com/sylvinus/exav/blob/main/SECURITY.md) has the
full threat model.

## Reporting a vulnerability

Report security issues privately through
[GitHub Security Advisories](https://github.com/sylvinus/exav/security/advisories/new),
not in a public issue. We aim to acknowledge within a few days. This covers any
way crafted input can make exav crash, hang, or skip content without saying so
(detection evasion).

:::note[Status: beta]
exav is young, and a scanner earns trust from use. A miss (ClamAV detects a file
exav reports `OK`) or a false positive is a bug rather than a vulnerability:
please [open an issue](https://github.com/sylvinus/exav/issues).
:::

## Hardening

- **Never a silent clean:** a file is reported clean only if it was fully
  scanned (see [design principles](/concepts/design-principles/#never-a-silent-clean)).
- **Bounded extraction:** every materialization is reserved against a budget
  before it is allocated (output bytes, ratio, file count, recursion depth,
  matcher bytes, emulation steps). A decompression bomb is `LIMITS-EXCEEDED`.
- **In-memory unpacking:** members are decoded in memory. Only an object too
  large to hold is written to a temporary file under `--spill-dir` (`off` to
  never write one).
- **Panic isolation:** a parser panic is caught (`catch_unwind`) and reported for
  that container, never as a clean result. An allocation too large to serve and
  stack exhaustion still end the process; the prefork daemon contains them in one
  worker.
- **`overflow-checks` in release:** arithmetic overflow traps rather than wraps.
- **Fuzzing:** `cargo-fuzz` targets for the parsers and the emulator, with a
  short smoke run of every target in CI; `cargo audit` / `cargo deny` in CI.
  Continuous fuzzing is on the [roadmap](/project/roadmap/).
- **Prefork worker pool:** the daemon runs each job in a worker under
  kernel-enforced limits and replaces a worker that exceeds them (see the
  [daemon guide](/guides/daemon/)).

## On `unsafe`

exav's own scanning, extraction and emulation code is safe Rust: `exav-core`,
`exav-unpack`, `exav-x86`, `exav-pe-emu`, `exav-update`, `exav-grep` and the
ICAP listener are `#![forbid(unsafe_code)]`. The default build runs no C, no
UnRAR and no native JIT, so the memory-corruption bugs behind most scanner CVEs
cannot occur in exav's own code. The
[bytecode interpreter](/concepts/bytecode-sandbox/), for one, has no counterpart
to the bugs that have repeatedly affected ClamAV's C/JIT bytecode VM.

The remaining `unsafe` is the daemon's libc calls and code inside dependencies:
SIMD, syscalls, and buffer handling in some decoders that read scanned bytes
(see [Dependencies](/reference/dependencies/) for counts per crate). The
approach is to minimise it (drop dependencies exav does not need), contain it
(panic isolation, the prefork process boundary, the WASM build), and look for
bugs in it (fuzzing, and Miri through `make miri`). Reducing it further is on the
[roadmap](/project/roadmap/).

## Untrusted signatures

The native engine treats signatures as trusted input. To load signatures you do
not fully trust (third-party `.ndb` sets, community YARA rules), use the
[WASM sandbox](/guides/wasm-sandbox/), which bounds memory, has no ambient
system access, and turns a parser panic into a contained trap.

## Database authenticity is not verified

exav does not verify the authenticity of a signature database; securing that
supply chain is up to the deployment.

A `.cvd` carries an MD5 digest and an RSA signature (`dsig`) in its header. exav
parses both fields and checks neither: a `.cvd` whose digest is zeroed, payload
untouched, loads and matches normally, where ClamAV refuses it with "Can't verify
database integrity". ClamAV also checks a signed `.info` member inside
`.cvd` and `.cld` containers, and signed `.cdiff` patches; exav checks none of
these. A prebuilt `.exavdb` carries only a CRC-32 against a torn or damaged file,
no signature.

The risk that matters is not injected detections, which are noisy, but the
reverse: a forged database can carry `.fp`/`.sfp` allowlists and `.ign`/`.ign2`
ignore lists that suppress detection. Treat the database directory as a trusted
asset:

- fetch over TLS from a source you trust, and keep the directory writable only by
  the account that updates it;
- verify a container yourself if you distribute one: `sigtool --info` checks a
  `.cvd`'s digest and signature and `sigtool --verify-cdiff` checks a patch, and
  either makes a fine gate in a build pipeline;
- note that ClamAV does not verify content fetched through `DatabaseCustomURL`
  either, so a custom feed is unverified on both engines;
- prefer shipping a prebuilt `.exavdb` built from a database you verified, so
  verification happens once, where you control it.

## Daemon exposure

- exav refuses the clamd `SHUTDOWN` command by default, so a client that can
  reach the socket or port cannot stop the daemon (`--allow-shutdown` allows
  it).
- A client that can reach the daemon or the [ICAP listener](/guides/icap/) can
  request scans, so restrict access regardless: bind to localhost, a private
  network, or a Unix socket.
- `--allow-http-scan` (in an `http-scan` build) lets any such client make the
  daemon fetch a URL with `SCANURL`. Leave it off unless every client is
  trusted.
- The daemon refuses to serve with no real signature database (unless
  `--allow-no-db` is set, for testing), so a misconfiguration cannot answer scans
  against near-zero coverage.
