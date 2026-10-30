---
title: Limits and tuning
description: Every bound exav applies to a scan, from the in-core budgets to the kernel backstops, and which one to change when a scan reports LIMITS-EXCEEDED.
---

A scanner is handed files chosen by an attacker, so every stage is bounded. The
bounds measure different things, and reaching any of them produces
`LIMITS-EXCEEDED` rather than a clean result, unless
[`--partial-as`](/scanner/reference/cli/#what-an-unscannable-object-becomes) says
otherwise.

## The in-core budgets

These act first, and they are the ones that produce a verdict. The engine field
column is for [library users](/subprojects/exav-core/) (`Limits` in exav-unpack,
`ScanOptions` in exav-core).

| CLI flag | Engine field | Default | What it stops |
|---|---|---|---|
| `--max-input-bytes` | `ScanOptions::max_scan_size` | no limit | A top-level input too big to take whole (its first bytes still get the whole scan) |
| `--max-object-bytes` | `Limits::max_buffer_bytes` and `ScanOptions::deep_analysis_max` | 256 MiB | The largest single object held in memory; a larger file or member is read through a block cache or a temporary file |
| `--max-matcher-bytes` | `Limits::max_scanned_bytes` | 10 GiB | Cumulative bytes fed to the matcher |
| `--max-pcre-bytes` | `ScanOptions::max_pcre_bytes` | no limit (100 MiB under `--clamav-compat`) | PCRE subsignatures on an object larger than this, which then do not match |
| `--min-scan-bytes` | `ScanOptions::min_scan_bytes` | 6 bytes | Every check on an object smaller than this, which then counts as clean; `0` scans every object |
| `--max-pe-emulation-steps` | `Limits::max_pe_emulation_steps` | 1,000,000,000 | Emulator instructions across all packed executables in one file |
| `--max-unpack-depth` | `Limits::max_recursion` | 16 | Nesting depth, containers inside containers |
| `--max-members` | `Limits::max_members` | 100000 | Member-count blowup |
| `--max-extracted-bytes` (lowered by `--max-process-bytes`) | `Limits::max_extracted_bytes` | 1 GiB (400M under `--clamav-compat`) | What formats that decode a member whole have produced so far in one scan; never released. Members streamed to the matcher are not counted (ZIP, 7z, TAR, CAB and the stream codecs scan past it, bounded by `--max-matcher-bytes`) |
| `--max-bytecode-memory-bytes` (lowered by `--max-process-bytes`) | `Limits::max_bytecode_memory_bytes` | 256 MiB | What one run of a bytecode signature holds: its `malloc`s, its call frames and the globals it reads; past it the run stops as incomplete |
| `--object-cache-bytes` (lowered by `--max-process-bytes`) | `ScanOptions::object_cache_bytes` | 8 MiB | Memory held by the block cache of each object read in place; not a limit on what is scanned, only on how often the source is read again |
| `--object-cache-block-bytes` | `ScanOptions::object_cache_block_bytes` | 1 MiB | The unit of that cache, and of a request that does not continue the previous one over HTTP |
| `--http-request-bytes` (lowered by `--max-process-bytes`) | `ScanOptions::http_request_bytes` | 8 MiB | The most one HTTP range request fetches, and holds while it is read |
| none | `Limits::max_compression_ratio` | 1000 | One stream that expands past the ratio |
| none | none (fixed) | 16 of each kind | PE, ELF or Mach-O images [carved](/scanner/reference/formats/#found-inside-other-files) from one object |
| none | none (fixed) | 32 | Archives carved from one object |

Each bound has one spelling; `clamscan`'s names (`--max-filesize`,
`--max-scansize`, `--max-files`) are refused with an error naming the exav flag.
See [the flag matrix](/scanner/reference/clamav-flag-matrix/).

`--max-extracted-bytes` is the total a scan may decode whole. It counts the
members that a format decodes into memory (RAR, OLE streams, PDF streams, RTF
objects, installers and the like), added up over the scan; a member streamed to
the matcher is not in it, so a ZIP, 7z, TAR or CAB that unpacks to several
gigabytes is scanned, within `--max-matcher-bytes`. It is 1 GiB (400M under
`--clamav-compat`), `off` or `0` removes it, and `--max-process-bytes` lowers
it, together with `--max-object-bytes` and `--max-bytecode-memory-bytes`, to what fits
the memory a scan gets (see
[the kernel backstops](#the-kernel-backstops)): beside an object held whole, an
image decoded from it and its grey copy can take as much again twice, so one
object is kept to a quarter of that memory, and the total to what leaves room
for those plus a tenth. Matching makes no other copy of an object but a
lowercase one of at most 16 MiB. The
default 2 G changes neither the default limits nor `--clamav-compat`'s.

`--clamav-compat` sets `--max-input-bytes` to 100M, `--max-unpack-depth` to 17
and `--max-members` to 10000, and holds 400M per file, both in total and as the
largest top-level file held whole: ClamAV's scan size.

### `0` and `off`

- On a limit (every `--max-` flag except `--max-unpack-depth`, which includes
  `--max-jobs-per-worker`, plus `--icap-max-requests`), `0` and `off` both mean
  no limit. An explicit `0` wins over the `--clamav-compat` default.
  `--startup-wait-secs 0` and `off` both mean no wait.
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
  expires at once and `off` never does. `--min-scan-bytes 0` scans every
  object and has no `off`.
- A threshold of findings (`--dlp-credit-cards`, `--dlp-ssns`) refuses `0`,
  which would alert on every file; leave the flag out instead.
- `--workers` refuses `0`; the in-process model is `--workers threads`.

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

See [Buffering a stream](/scanner/reference/cli/#buffering-a-stream-spill) for how they
nest and what `--spill-dir off` changes.

## The kernel backstops

Unix only. They catch what the in-core budgets cannot see: an allocation inside
a third-party decoder, or a loop that produces no output.

| Flag | Bounds | Default | Where it applies |
|---|---|---|---|
| `--max-scan-secs SECS` | Wall clock, and CPU time in the pool | 120 in the pool, unset otherwise | Per job in the clamd worker pool; the whole run in a one-shot scan, which the limit ends where it is, the files after it unscanned, with the exit status of what was found by then (`1` for a detection, `2` for an error) and otherwise the one `--partial-as` gives a `LIMITS-EXCEEDED` (`3`). Refused on any other listener (`--workers threads`, ICAP alone). |
| `--max-process-bytes SIZE` | Address space (`RLIMIT_AS`) | 2G in the pool, unset otherwise | Per clamd worker in the pool; the whole process in a one-shot scan or any other listener. |

ICAP scans get no `--max-scan-secs` in any mode. Under the pool the ICAP
listener runs in a child of its own with no `RLIMIT_AS` either; the in-core
budgets, fitted to `--max-process-bytes`, are what bound its scans.

Setting `--max-process-bytes` also keeps what a scan holds inside it:
`--max-object-bytes` is lowered to a quarter of it, and the 1 GiB extraction
total to what leaves room for an image decoded from the largest object and its
grey copy (twice its size) plus a tenth. `--object-cache-bytes` and
`--http-request-bytes` are each lowered to an eighth of it. The in-core cap
then fires first and reports a limit instead of the kernel killing the scan. In the pool, the per-worker figure is
also lowered to what the host can back: RAM, less a third for the rest of the
system, less the shared database, divided by `--workers`. A daemon job stopped
by `--max-scan-secs` is answered `LIMITS-EXCEEDED` before its worker exits.

For a worked example on one machine, see [sizing a server](/scanner/guides/sizing/).

## What the layers cannot reach

Two failure modes escape every in-process bound:

- **An allocation large enough to abort.** Rust aborts rather than unwinding, so
  the per-file panic boundary cannot catch it.
- **Stack exhaustion** inside a single parser. `max_recursion` counts containers,
  not recursive descent within one file's grammar.

Only the kernel layer reaches these: on by default in the worker pool, opt-in
elsewhere.

The clamd worker pool contains both: `RLIMIT_AS` bounds each worker, and a
worker that dies is replaced, so one hostile file costs one job. The pool's ICAP
child has no such cap: if it dies it is replaced too, but every ICAP connection
it held goes with it. A one-shot run applies the same rlimits when
`--max-process-bytes` / `--max-scan-secs` are set, but there is no second
process to fall back on, so the run ends. A
[library embedding](/subprojects/exav-core/#read-this-first-you-supply-the-bounds) gets neither unless the host process
sets the rlimits itself.

An in-process allocation counter would not help: refusing an allocation is only
an error the caller can handle where the code asked fallibly (`try_reserve`), and
almost none of exav's decoder dependencies do; elsewhere a refusal aborts just as
exhaustion would. Address space is the layer that can say no.

## Which one do I change?

The verdict reason names the budget that stopped the scan. Read it first: the
flags bound different quantities, and raising the wrong one changes nothing.

- A large archive of ordinary files: `--max-members`.
- The total a scan decodes whole: `--max-extracted-bytes`. If
  `--max-process-bytes` lowered it (exav says so at startup, with the figures),
  raise that first (in the pool, only as far as the host's RAM allows); past
  that point raising this one changes nothing.
- A bytecode signature that stops as incomplete: `--max-bytecode-memory-bytes`.
- One large file, or one large member of an archive: `--max-object-bytes` (and
  `--max-input-bytes` if you set one). Under `--max-process-bytes` it is also
  capped at a quarter of that.
- A member streamed past the matcher budget: `--max-matcher-bytes`.
- A scan of a large file or an `http(s)://` object that works but is slow: not a
  limit, so no verdict names it. The object is read from its source several times
  over, and a request or read per block; see `--object-cache-block-bytes`,
  `--object-cache-bytes` and `--http-request-bytes`, and the
  [block cache](/scanner/concepts/streaming-memory/#the-block-cache) for the
  figures.
- Deeply nested archives: `--max-unpack-depth`.
- Many packed executables in one file: `--max-pe-emulation-steps`.
- A stream past a spill budget: `--max-spill-bytes`, `--max-total-spill-bytes`,
  or `--spill-threshold-bytes` under `--spill-dir off`.
- A scan that never returns: `--max-scan-secs` in the clamd pool or a one-shot
  run, and consider whether you want the file scanned at all. An ICAP scan has
  no time bound; it is bounded by work (`--max-matcher-bytes`,
  `--max-pe-emulation-steps`, `--max-unpack-depth`, `--max-members`).

Raising a limit trades resources for reach. The defaults keep a scan of hostile
input bounded on a modest host; a build server scanning its own artifacts can
afford to be more generous than a mail gateway.
