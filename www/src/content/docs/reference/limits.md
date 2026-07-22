---
title: Limits and tuning
description: Every bound exav applies to a scan — the in-core budgets, the kernel backstops, and which one to change when a scan reports LIMITS-EXCEEDED.
---

A scanner is handed files chosen by an attacker, so every stage is bounded. The
bounds measure different things, and hitting any one of them produces
`LIMITS-EXCEEDED` rather than a clean result.

## The in-core budgets

These decide first, and they are the ones that produce a verdict. Each flag is
spelled like the engine field it feeds — `Limits` in
`crates/exav-unpack/src/lib.rs`, `ScanOptions` in `crates/exav-core/src/lib.rs`.

| CLI flag | Engine field | Default | What it stops |
|---|---|---|---|
| `--max-input-bytes` | `ScanOptions::max_scan_size` | no limit | One top-level file too big to take at all |
| `--max-extracted-bytes` | `deep_analysis_max` **and** `Limits::max_extracted_bytes` | 256 MiB / 1 GiB | Cumulative decompressed bytes across the whole recursion |
| `--max-object-bytes` | `Limits::max_buffer_bytes` (and `deep_analysis_max`) | 256 MiB | The largest **single** buffered object |
| `--max-matcher-bytes` | `Limits::max_scanned_bytes` | 10 GiB | Cumulative bytes fed to the matcher |
| `--max-depth` | `Limits::max_recursion` | 16 | Nesting depth, containers inside containers |
| `--max-members` | `Limits::max_members` | 100000 | Member-count blowup |
| — | `Limits::max_compression_ratio` | 1000 | One stream that expands absurdly |

Each bound has exactly one spelling. `clamscan`'s names — `--max-filesize`,
`--max-scansize`, `--max-files` — are not accepted as aliases; a clamscan flag
exav does not have stops the run rather than being swallowed. See
[the flag matrix](/reference/clamav-flag-matrix/).

Two flags move more than one field. `--max-extracted-bytes` sets the
deep-analysis size and the summed extracted bytes to one value; left unset the
two keep their own defaults, 256 MiB and 1 GiB. `--max-object-bytes` sets the
per-object cap and the deep-analysis size together, so one knob governs the
largest single allocation on every materialization path.

`--clamav-compat` moves four of them: `--max-input-bytes` to 100M,
`--max-extracted-bytes` to 400M (both fields), `--max-depth` to 17 and
`--max-members` to 10000.

`0` means **no limit** on every size flag here — the reading ClamAV gives a zero,
and the same one `--max-scan-secs 0` / `--max-process-bytes 0` take. An explicit
`0` wins over the `--clamav-compat` default, because the flag was given.

Three things about this table are easy to get wrong.

**`max_buffer_bytes` bounds one buffer, not the sum of them.** Several are live
at once, because a container, its member, and that member's own member can each
be mid-scan. The bound on total live memory is `max_extracted_bytes`.

**`max_scanned_bytes` is a CPU bound, not a memory one.** A streamed member is
fed to the matcher without being held in RAM, so this counts scan *reach* rather
than resident bytes. Raising it lets a multi-gigabyte member be scanned in full
and costs only scan time; what bounds the memory is `max_buffer_bytes`.

**`max_compression_ratio` is the weak one.** The input size it divides by is a header field
the attacker wrote, so it is a cheap early filter rather than a defence. The
byte budgets are what actually hold.

One more bound sits outside that table because it is charged against the
*rules*, not the file: each scan gets 20 million YARA condition-evaluation
steps, shared across every rule in the set. A YARA range loop sizes itself from
the rule text, so `for any i in (0..200000000)` would otherwise stall every scan
that ruleset touches. A condition that runs out of steps evaluates to undefined
and does not match; real feeds use a few million steps for a whole scan.

## The kernel backstops

Available on Unix, in the daemon and in a one-shot run. These catch what the
in-core budgets cannot see — an allocation inside a third-party decoder, or a
loop that produces no output.

| Flag | Bounds | Where it applies |
|---|---|---|
| `--max-scan-secs SECS` | Wall clock, and CPU time in the pool | Per job in the daemon; the whole run otherwise |
| `--max-process-bytes SIZE` | Address space (`RLIMIT_AS`) | Per worker in the daemon; the process otherwise |

Setting `--max-process-bytes` also lowers the in-core extraction budget to fit
inside it. That ordering is deliberate: the in-core cap should fire first and
report a limit, leaving the kernel as the backstop it was meant to be. Without
the clamp the kernel wins, and a scan that should have said "I hit a limit" gets
killed for hitting one.

## What the layers cannot reach

Two failure modes escape every in-process bound:

- **An allocation large enough to abort.** Rust aborts rather than unwinding, so
  the per-file panic boundary cannot catch it.
- **Stack exhaustion** inside a single parser. `max_recursion` counts containers,
  not recursive descent within one file's grammar.

Only the kernel layer reaches these, and only if you ask for it.

The daemon contains both: `RLIMIT_AS` bounds each worker, and a worker that dies
is replaced, so one hostile file costs one job. A one-shot run applies the same
rlimits when `--max-process-bytes` / `--max-scan-secs` are set — but there is no
second process to fall back on, so the run ends. A
[library embedding](/guides/library-usage/) gets neither unless the host process
sets the rlimits itself.

An in-process allocation counter would not close this. Refusing an allocation
only becomes an error the caller can handle where the allocating code asked
fallibly (`try_reserve`); across exav's decoder dependencies almost none do, and
for the rest a refusal aborts exactly as exhaustion would — including for
allocations the machine could have served. Address space is the layer that can
say no, so that is where the bound lives.

## Which one do I change?

The verdict reason names the budget that stopped the scan. Read it before
raising anything — the flags bound different quantities, and raising the wrong
one changes nothing.

- A large archive of ordinary files → `--max-members`, or `--max-extracted-bytes`.
- One very large top-level file → `--max-input-bytes`.
- One very large member inside a container → `--max-object-bytes` (buffered
  formats) or `--max-matcher-bytes` (streamed ones).
- Deeply nested archives → `--max-depth`.
- A scan that never returns → `--max-scan-secs`, and consider whether you want
  the file scanned at all.

Raising a limit trades resources for reach. The defaults are set where a scan of
hostile input stays bounded on a modest host; a build server scanning its own
artifacts can afford to be far more generous than a mail gateway.
