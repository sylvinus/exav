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
| `--max-extracted-bytes` | `deep_analysis_max` **and** `Limits::max_extracted_bytes` | 256 MiB / 1 GiB | Cumulative decompressed bytes across the whole recursion |
| `--max-object-bytes` | `Limits::max_buffer_bytes` (and `deep_analysis_max`) | 256 MiB | The largest single buffered object, and the largest file or member the full engine scans |
| `--max-matcher-bytes` | `Limits::max_scanned_bytes` | 10 GiB | Cumulative bytes fed to the matcher |
| `--max-pe-emulation-steps` | `Limits::max_pe_emulation_steps` | 1,000,000,000 | Emulator instructions across all packed executables in one file |
| `--max-unpack-depth` | `Limits::max_recursion` | 16 | Nesting depth, containers inside containers |
| `--max-members` | `Limits::max_members` | 100000 | Member-count blowup |
| none | `Limits::max_compression_ratio` | 1000 | One stream that expands absurdly |

Each bound has one spelling; `clamscan`'s names (`--max-filesize`,
`--max-scansize`, `--max-files`) are refused. See
[the flag matrix](/reference/clamav-flag-matrix/).

Two flags move more than one field. `--max-extracted-bytes` sets the
deep-analysis size and the summed extracted bytes to one value; left unset they
keep their defaults, 256 MiB and 1 GiB. `--max-object-bytes` sets the per-object
cap and the deep-analysis size together, and wins over `--max-extracted-bytes`
for the deep-analysis size when both are given.

`--clamav-compat` moves four of them: `--max-input-bytes` to 100M,
`--max-extracted-bytes` to 400M (both fields), `--max-unpack-depth` to 17 and
`--max-members` to 10000.

`0` or `off` means no limit on every size flag here and on
`--max-pe-emulation-steps`, as a zero does in ClamAV and for `--max-scan-secs` /
`--max-process-bytes`. An explicit `0` wins over the `--clamav-compat` default.

Things about this table that are easy to get wrong:

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
`for any i in (0..200000000)` would otherwise stall every scan. A scan whose rules
run out of steps is reported `LIMITS-EXCEEDED`; real feeds use a few million
steps for a whole scan.

## The kernel backstops

Available on Unix, in the daemon and in a one-shot run. They catch what the
in-core budgets cannot see: an allocation inside a third-party decoder, or a loop
that produces no output.

| Flag | Bounds | Where it applies |
|---|---|---|
| `--max-scan-secs SECS` | Wall clock, and CPU time in the pool | Per job in the daemon; the whole run otherwise |
| `--max-process-bytes SIZE` | Address space (`RLIMIT_AS`) | Per worker in the daemon; the process otherwise |

Setting `--max-process-bytes` also lowers the in-core extraction budget to fit
inside it, so the in-core cap fires first and reports a limit instead of the
kernel killing the scan. A daemon job stopped by `--max-scan-secs` is answered
`LIMITS-EXCEEDED` before its worker exits.

## What the layers cannot reach

Two failure modes escape every in-process bound:

- **An allocation large enough to abort.** Rust aborts rather than unwinding, so
  the per-file panic boundary cannot catch it.
- **Stack exhaustion** inside a single parser. `max_recursion` counts containers,
  not recursive descent within one file's grammar.

Only the kernel layer reaches these, and only if you ask for it.

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

- A large archive of ordinary files: `--max-members` or `--max-extracted-bytes`.
- One large file, or one large member of an archive: `--max-object-bytes` (and
  `--max-input-bytes` if you set one).
- A member streamed past the matcher budget: `--max-matcher-bytes`.
- Deeply nested archives: `--max-unpack-depth`.
- Many packed executables in one file: `--max-pe-emulation-steps`.
- A scan that never returns: `--max-scan-secs`, and consider whether you want the
  file scanned at all.

Raising a limit trades resources for reach. The defaults keep a scan of hostile
input bounded on a modest host; a build server scanning its own artifacts can
afford to be more generous than a mail gateway.
