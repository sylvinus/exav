---
title: Limits and tuning
description: Every bound exav applies to a scan, from the in-core budgets to the kernel backstops, and which one to change when a scan reports LIMITS-EXCEEDED.
---

A scanner is handed files chosen by an attacker, so every stage is bounded. The
bounds measure different things, and reaching any of them produces
`LIMITS-EXCEEDED` rather than a clean result.

## The in-core budgets

These act first, and they are the ones that produce a verdict. The engine fields
are `Limits` in `crates/exav-unpack/src/lib.rs` and `ScanOptions` in
`crates/exav-core/src/lib.rs`.

| CLI flag | Engine field | Default | What it stops |
|---|---|---|---|
| `--max-input-bytes` | `ScanOptions::max_scan_size` | no limit | A top-level input too big to take whole (its first bytes still get the whole scan) |
| `--max-object-bytes` | `Limits::max_buffer_bytes` and `ScanOptions::deep_analysis_max` | 256 MiB | The largest single object held in memory; a larger file or member is read through a block cache or a temporary file |
| `--max-matcher-bytes` | `Limits::max_scanned_bytes` | 10 GiB | Cumulative bytes fed to the matcher |
| `--max-pe-emulation-steps` | `Limits::max_pe_emulation_steps` | 1,000,000,000 | Emulator instructions across all packed executables in one file |
| `--max-unpack-depth` | `Limits::max_recursion` | 16 | Nesting depth, containers inside containers |
| `--max-members` | `Limits::max_members` | 100000 | Member-count blowup |
| `--max-process-bytes` (half of it) | `Limits::max_extracted_bytes` | 1 GiB | What extractors hold at once across the whole recursion |
| none | `Limits::max_compression_ratio` | 1000 | One stream that expands past the ratio |

Each bound has one spelling; `clamscan`'s names (`--max-filesize`,
`--max-scansize`, `--max-files`) are refused with an error naming the exav flag.
See [the flag matrix](/reference/clamav-flag-matrix/).

The total a scan may hold has no flag of its own. It is 1 GiB, and
`--max-process-bytes` lowers it, together with `--max-object-bytes`, to half the
memory a scan gets (see [the kernel backstops](#the-kernel-backstops)). One
number to set, the memory, rather than two to keep consistent with it.

`--clamav-compat` moves four of them: `--max-input-bytes` to 100M,
`--max-unpack-depth` to 17, `--max-members` to 10000, and both the total held
per file and the largest top-level file held whole to 400M, ClamAV's scan size.

### `0` and `off`

- On a limit (every `--max-` flag above except `--max-unpack-depth`,
  `--max-scan-secs`, `--max-process-bytes`, `--max-spill-bytes`,
  `--max-total-spill-bytes`, `--max-jobs-per-worker`, `--icap-max-requests`,
  `--build-shard-bytes`), `0` and `off` both mean no limit. An explicit `0` wins
  over the `--clamav-compat` default.
- Where no limit would be unsafe, there is no `off`: `--max-unpack-depth` (each
  level costs stack), `--icap-idle-secs` and `--icap-max-header-bytes` (a client
  could hold a connection forever). `0` is refused too.
- On a period (`--update-interval-secs`, `--metrics-secs`, `--slow-scan-secs`),
  `off` turns it off and `0` is refused, because a zero-second period reads as
  "always".
- Where `0` is a value in its own right, `off` says something else:
  `--spill-threshold-bytes 0` spills every stream at once and has no `off`
  (`--spill-dir off` keeps streams in RAM); `--icap-preview-bytes 0` previews
  headers only and `off` leaves the header out; `--icap-options-ttl-secs 0`
  expires at once and `off` never does.
- A threshold of findings (`--dlp-credit-cards`, `--dlp-ssns`) refuses `0`,
  which would alert on every file; leave the flag out instead.

Notes:

- **`max_buffer_bytes` bounds one buffer, not their sum.** A container, its
  member and that member's member can each be mid-scan at once. The bound on
  total live memory is `max_extracted_bytes`.
- **`max_scanned_bytes` is a CPU bound.** It counts bytes fed to the matcher,
  not bytes held in memory. Raising it costs only scan time.
- **`max_compression_ratio` is the weak one.** The input size it divides by is a
  header field the attacker wrote, so it is a cheap early filter; the byte
  budgets are what hold.

One more bound is charged against the rules rather than the file: each buffer
gets 20 million YARA condition-evaluation steps, shared by every rule in the set.
A YARA range loop takes its size from the rule text, so
`for any i in (0..200000000)` would otherwise stall every scan. A YARA string also
keeps at most one million matches per buffer. A scan whose rules run out of steps,
or whose strings reach that count, is reported `LIMITS-EXCEEDED` unless a rule
matched; real feeds use a few million steps for a whole scan.

## Streams: the spill budgets

A stream (`INSTREAM`, stdin, an ICAP body), and a member that decodes past
`--max-object-bytes`, is held in RAM up to a threshold and then in a temporary
file. Reaching one of these has what was held scanned, and is `LIMITS-EXCEEDED`
unless that finds something.

| Flag | Default | Bounds |
|---|---|---|
| `--spill-threshold-bytes` | 16 MiB | RAM held per object before it spills; with `--spill-dir off`, the most held at all |
| `--max-spill-bytes` | 2 GiB | Temporary-file space for one object |
| `--max-total-spill-bytes` | 8 GiB | Temporary-file space for every in-flight object in one process |

See [Buffering a stream](/reference/cli/#buffering-a-stream-spill) for how they
nest and what `--spill-dir off` changes.

## The kernel backstops

Available on Unix, in the daemon and in a one-shot run. They catch what the
in-core budgets cannot see: an allocation inside a third-party decoder, or a loop
that produces no output.

| Flag | Bounds | Where it applies |
|---|---|---|
| `--max-scan-secs SECS` | Wall clock, and CPU time in the pool | Per job in the daemon; the whole run otherwise |
| `--max-process-bytes SIZE` | Address space (`RLIMIT_AS`) | Per worker in the daemon; the process otherwise |

Setting `--max-process-bytes` also keeps what a scan holds to half of it: the
1 GiB extraction total and `--max-object-bytes` are lowered when they are larger.
The other half is the matcher's working set, chiefly the lowercase copy it makes
of each buffer it scans. The in-core cap then fires first and reports a limit
instead of the kernel killing the scan. In the pool, the per-worker figure is
also lowered to what the host can back: RAM, less a third for the rest of the
system, less the shared database, divided by `--workers`. A daemon job stopped
by `--max-scan-secs` is answered `LIMITS-EXCEEDED` before its worker exits.

For a worked example on one machine, see [sizing a server](/guides/sizing/).

## What the layers cannot reach

Two failure modes escape every in-process bound:

- **An allocation large enough to abort.** Rust aborts rather than unwinding, so
  the per-file panic boundary cannot catch it.
- **Stack exhaustion** inside a single parser. `max_recursion` counts containers,
  not recursive descent within one file's grammar.

Only the kernel layer reaches these: on by default in the worker pool, opt-in
elsewhere.

The daemon contains both: `RLIMIT_AS` bounds each worker, and a worker that dies
is replaced, so one hostile file costs one job. A one-shot run applies the same
rlimits when `--max-process-bytes` / `--max-scan-secs` are set, but there is no
second process to fall back on, so the run ends. A
[library embedding](/guides/library-usage/) gets neither unless the host process
sets the rlimits itself.

An in-process allocation counter would not help: refusing an allocation is only
an error the caller can handle where the code asked fallibly (`try_reserve`), and
almost none of exav's decoder dependencies do; elsewhere a refusal aborts just as
exhaustion would. Address space is the layer that can say no.

## Which one do I change?

The verdict reason names the budget that stopped the scan. Read it first: the
flags bound different quantities, and raising the wrong one changes nothing.

- A large archive of ordinary files: `--max-members`, or `--max-process-bytes`
  if the total held is what stopped it.
- One large file, or one large member of an archive: `--max-object-bytes` (and
  `--max-input-bytes` if you set one).
- A member streamed past the matcher budget: `--max-matcher-bytes`.
- Deeply nested archives: `--max-unpack-depth`.
- Many packed executables in one file: `--max-pe-emulation-steps`.
- A stream past a spill budget: `--max-spill-bytes`, `--max-total-spill-bytes`,
  or `--spill-threshold-bytes` under `--spill-dir off`.
- A scan that never returns: `--max-scan-secs`, and consider whether you want the
  file scanned at all.

Raising a limit trades resources for reach. The defaults keep a scan of hostile
input bounded on a modest host; a build server scanning its own artifacts can
afford to be more generous than a mail gateway.
