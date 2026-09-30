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
not in a public issue. A crash on a crafted file counts: it may be a denial of
service.

:::note[Status: beta]
exav is young, and a scanner earns trust from use. For something wrong that is
not a security issue (a miss, a false positive), please
[open an issue](https://github.com/sylvinus/exav/issues).
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
- **Fuzzing:** `cargo-fuzz` targets for the parsers, with a short smoke run per
  target in CI; `cargo audit` / `cargo deny` in CI. Continuous fuzzing (OSS-Fuzz)
  is on the roadmap.
- **Prefork worker pool:** the daemon runs each job in a worker under
  kernel-enforced limits and replaces a worker that exceeds them (see the
  [daemon guide](/guides/daemon/)).

## On `unsafe`

exav's own scanning and extraction code is safe Rust (`exav-core` and
`exav-unpack` are `#![forbid(unsafe_code)]`), and the default build runs no C,
no UnRAR and no native JIT, so the memory-corruption bugs behind most scanner
CVEs cannot occur in it. The [bytecode interpreter](/concepts/bytecode-sandbox/), for one,
has no counterpart to the bugs that have repeatedly affected ClamAV's C/JIT
bytecode VM.

The remaining `unsafe` lives in widely used dependency primitives (compression
and crypto SIMD, OS syscalls) and the daemon's libc calls, not in the code that
parses hostile input. The approach is to minimise it (drop dependencies exav
does not need), contain it (panic isolation, the prefork process boundary, the
WASM build), and look for bugs in it (fuzzing, and Miri through `make miri`).
Reducing it further is on the [roadmap](/project/roadmap/).

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
database integrity".

ClamAV's own verification has two independent layers and three compiled-in keys:

1. **Outer** (`.cvd` only): the MD5 of the body from offset 512 to the end must
   match the header, and that digest is checked by RSA-1024 against a key built
   into the binary. The signature is a big integer in a custom base64-like
   alphabet, not PKCS#1.
2. **Inner** (every container except `.cud`): a `.info` member in the tar lists
   `name:size:sha256` for each database file and ends with a `DSIG:` line,
   verified by RSA-2048/PSS over SHA-256 against a different key. Each member's
   size and SHA-256 are enforced at load, and a member missing from `.info` is
   fatal.
3. **`.cdiff`** patches carry a footer signed with a third key, verified before
   any patch command is parsed.

So a `.cld`, which freshclam builds locally after applying patches, is not
covered by the outer signature and relies on the inner layer alone, and a `.cud`
is the explicitly unsigned container.

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

Incremental `.cdiff` updates are not applied; exav expects whole containers.

## Daemon exposure

- exav refuses the clamd `SHUTDOWN` command by default, so a client that can
  reach the socket or port cannot stop the daemon (`--allow-shutdown` allows
  it).
- A client that can reach the daemon can request scans, so restrict access
  regardless: bind to localhost, a private network, or a Unix socket.
- The daemon refuses to serve with no real signature database, so a
  misconfiguration cannot answer scans against near-zero coverage.
