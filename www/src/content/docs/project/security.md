---
title: Security
description: exav's threat model and hardening — memory safety, bounded extraction, panic isolation, and the posture on residual unsafe.
---

exav parses hostile input for a living. The engine is built to contain it. See
the repository's `SECURITY.md` for the full threat model and how to report
vulnerabilities.

:::note[Status: beta]
exav is young, and a scanner earns trust from use. If you find something wrong —
a miss, a false positive, a crash — please [report
it](https://github.com/sylvinus/exav/issues); fixes ship quickly.
:::

## Hardening

- **The never-report-clean-unless-scanned invariant** — the security property
  (see [Never silently clean](/concepts/design-principles/#never-a-silent-clean)).
- **Bounded extraction** — every materialization is budget-before-allocation:
  output-byte, ratio, file-count, recursion-depth, and cumulative scan-byte caps.
  A decompression bomb is `LIMITS-EXCEEDED`, never `OK`.
- **In-memory-only unpacking** — the extractor never writes to disk.
- **Per-file panic isolation** — a parser panic on a crafted input is caught
  (`catch_unwind`) and counts as an error, never a clean result, and never aborts
  the run.
- **`overflow-checks` in release** — arithmetic overflow traps rather than wraps.
- **Fuzzing** — a `cargo-fuzz` target for every parser; `cargo audit` /
  `cargo deny` in CI. Continuous fuzzing (OSS-Fuzz) is on the roadmap.
- **Prefork worker pool** — the daemon `SIGKILL`s a corrupted or runaway worker
  under kernel-enforced per-job limits (see the [daemon guide](/guides/daemon/)).

## On `unsafe`

exav's own scanning and extraction code is safe Rust — both `exav-core` and
`exav-unpack` are `#![forbid(unsafe_code)]` — and it runs **no C, no UnRAR, and
no native JIT**, which rules out whole classes of remote-code-execution CVE by
construction rather than patching them one at a time. In particular,
the [bytecode interpreter](/concepts/bytecode-sandbox/) removes the RCE class that
has repeatedly affected ClamAV's C/JIT bytecode VM.

It is **not** zero-`unsafe`: the residual lives in audited, widely-used dependency
*primitives* (compression/crypto SIMD, OS syscalls), not in attacker-driven
parsing logic. The posture is **minimize** it (drop deps we don't need),
**contain** it (per-file panic isolation, the prefork process boundary, the
WASM-sandboxed extractor), and **detect** bugs in it (fuzzing + Miri). Driving it
down further is an explicit [roadmap](/project/roadmap/) goal.

## Untrusted signatures

The native engine treats signatures as **trusted** input. If you load signatures
you don't fully trust — third-party `.ndb` sets, community YARA rules — run under
the [WASM sandbox](/guides/wasm-sandbox/), which bounds memory, blocks syscalls,
and turns any parser panic into a contained trap.

## Database authenticity is not verified

**exav does not verify the authenticity of a signature database, and you must
secure that supply chain yourself.**

A `.cvd` carries an MD5 digest and an RSA signature (`dsig`) in its header. exav
parses both fields and checks neither. Demonstrated rather than assumed: a `.cvd`
whose digest field is replaced with `00000000000000000000000000000000`, payload
untouched, loads without complaint and its signatures match normally. ClamAV
refuses the same file with *"Can't verify database integrity"*.

For scale, what ClamAV actually does is **two independent layers with three
compiled-in keys** — so this is not a one-line fix:

1. **Outer** (`.cvd` only): MD5 of the body from offset 512 to EOF must match the
   header field, and that digest is then checked by RSA-1024 against a key
   compiled into the binary. The signature is carried as a big integer in a
   custom base64-like alphabet, not PKCS#1.
2. **Inner** (every container except `.cud`): a `.info` member inside the tar
   lists `name:size:sha256` for each database file and ends with a `DSIG:` line,
   verified by RSA-2048/PSS over SHA-256 against a *different* key. Each member's
   size and SHA-256 are then enforced at load; a member missing from `.info` is
   fatal.
3. **Cdiff** patches carry a footer signed with a *third* key, verified before any
   patch command is parsed.

Two consequences follow: a `.cld` — which freshclam builds locally after
applying patches — is **not** covered by the outer signature at all, so its trust
rests entirely on the inner layer; and a `.cud` is the explicitly unsigned
container type, with both layers suppressed by design.

The risk that matters is not injected detections, which are noisy and obvious. It
is the reverse: a forged database can carry `.fp`/`.sfp` hash allowlists and
`.ign`/`.ign2` name-ignore entries that **silently suppress** detection. A scanner
that reports `OK` because someone edited its database is the exact failure this
project otherwise refuses to allow.

Until this is implemented, treat the database directory as a trusted asset:

- fetch over TLS from a source you trust, and keep the directory writable only by
  the account that updates it;
- verify the container yourself if you distribute one — `sigtool --info` checks a
  `.cvd`'s digest and signature, and `sigtool --verify-cdiff` checks a patch;
  either is a fine gate in a build pipeline;
- note that ClamAV itself does **not** verify content fetched via
  `DatabaseCustomURL`, so a custom feed is unverified on both engines;
- prefer shipping a prebuilt `.exavdb` you built from a database you verified, so
  the verification happens once, where you control it.

Incremental `.cdiff` updates are not applied either; exav skips them and expects
whole containers.

## Daemon exposure

- exav **refuses the clamd `SHUTDOWN` command by default** — a client that can
  reach the socket/port can't stop the daemon (`EXAV_ALLOW_SHUTDOWN=1` to allow).
- A client that can reach the daemon can already request scans, so restrict the
  port regardless: bind to localhost, a private network, or a Unix socket.
- The daemon **refuses to serve with no real signature database**, so a
  misconfiguration can't silently answer scans against near-zero coverage.
