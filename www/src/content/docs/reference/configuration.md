---
title: Configuration
description: exav's EXAV_* environment variables, the flag each one falls back from, and the ScanOptions-level limit knobs behind the limit flags.
---

exav is configured three ways: **CLI flags** (see the [CLI reference](/reference/cli/)),
**`EXAV_*` environment variables**, and the underlying **`ScanOptions`** limit
knobs each limit flag maps to.

## Precedence

**An explicit flag wins, then the environment variable, then the default.** The
rule is the same for every setting: no flag is refused because a variable is set,
and no variable overrides a flag. A container image can therefore carry its whole
configuration in the environment while any single value stays overridable on the
command line — `docker run … exav --auto-update --workers 2` overrides
`EXAV_WORKERS` and nothing else.

Booleans accept `1`/`yes`/`on`/`true` (and `y`/`t`) for on, `0`/`no`/`off`/`false`
(and `n`/`f`) for off. Anything else stops the run rather than being guessed at:
`EXAV_AUTO_UPDATE=ture` read as false would fetch nothing and say nothing about
why.

## Every flag has a variable, spelled the same way

There is no table of exceptions to learn, and no variable without a flag. A
flag's variable is its own name: uppercase, dashes to underscores, `EXAV_` in
front.

| Flag | Variable |
|---|---|
| `--listen` | `EXAV_LISTEN` |
| `--max-input-bytes` | `EXAV_MAX_INPUT_BYTES` |
| `--partial-as` | `EXAV_PARTIAL_AS` |
| `--icap-max-requests` | `EXAV_ICAP_MAX_REQUESTS` |

That holds for all 59 of them, and `exav --help` prints the `[env: …]` line under
each. The [CLI reference](/reference/cli/) documents what each one does; this page
covers what does *not* live in a flag, and the engine budgets behind the limits.

## What lives in the address, not in a flag

Some settings belong to *one listener* rather than to the run, so they ride on
its `--listen` address. An ICAP service is the URL path; the rest are a
`?key=value` tail:

| On the address | Default | Meaning |
|---|---|---|
| `/avscan` *(the path)* | `avscan`, `srv_clamav`, `virus_scan` | The ICAP service to answer on — the path of the URL a proxy is already configured with. Naming one replaces the default set. |
| `?service=a&service=b` | — | Several ICAP services. Repeat the key: a comma separates *addresses*, not names, which is why the key is singular. |
| `?mode=660` | `0600` | Permission bits for a Unix socket. Owner-only unless widened, because every user the mode admits can submit scans and read the verdicts. |
| `?max-connections=200` | `128` clamd, `100` ICAP | Concurrent connections this listener accepts. ICAP also advertises it as `Max-Connections`. Bounds the clamd listener only under `--workers threads`; the prefork pool bounds concurrency by its worker count. |

```sh
exav --listen 'clamd:///run/exav.sock?mode=660' \
     --listen 'icap://0.0.0.0:1344/avscan?max-connections=200'
```

A flag for any of these would have to say *which* listener it meant — a socket
mode applied to a `host:port` means nothing, a connection cap has to pick a
protocol, and a service name exists for only one of the two. On the address there
is exactly one thing each can attach to, so there is nothing to cross-check and
nothing to get wrong.

An unknown option is an error rather than an ignored word: a setting that parses
and does nothing is one an operator believes is in force.

### Engine diagnostics are not on this page

`exav-core` reads a few more variables that are **library diagnostics, not
deployment settings**: switches that bypass the YARA prefilter, select the legacy
matcher path, warn on a stubbed bytecode API, or cap a verification budget. They
exist so two code paths can be run over the same input and compared, which is how
the engine is tested — not so a scan can be tuned.

They are documented next to the mechanism each one toggles, in
[Bytecode sandbox](/concepts/bytecode-sandbox/), [Interesting
quirks](/concepts/quirks/) and the YARA design notes, because a switch of that
kind is only meaningful alongside the thing it turns off. Setting one in a
deployment changes which code path answers, so treat anything not listed above as
belonging to the test bench.

### Migrating a ClamAV container

Translate its settings: `CLAMAV_NO_CLAMD` becomes `--auto-update` with no
`--listen`, `CLAMD_STARTUP_TIMEOUT` becomes `EXAV_STARTUP_WAIT_SECS`, and
`FRESHCLAM_CHECKS` becomes `EXAV_UPDATE_INTERVAL_SECS` (seconds between checks,
not checks per day). See the [Docker guide](/guides/docker/).

## Limit knobs (ScanOptions)

Each CLI limit flag sets an engine-level budget. The two are deliberately split
into a **memory** axis and a **CPU/time** axis:

| CLI flag | Engine field | Axis | Default |
|---|---|---|---|
| `--max-input-bytes` | `max_scan_size` | largest top-level input scanned | unlimited |
| `--max-extracted-bytes` | `deep_analysis_max` + `max_extracted_bytes` | data-scanned budget | 256M / 1G (the flag sets both to one value) |
| `--max-object-bytes` | `max_buffer_bytes` (+ `deep_analysis_max`) | largest **single** materialized object — one buffer, of the several live at once | 256M |
| `--max-matcher-bytes` | `max_scanned_bytes` | **CPU/time** — cumulative bytes fed to the matcher | 10G |
| `--max-unpack-depth` | `max_recursion` | nesting depth | 16 |
| `--max-members` | `max_members` | members across the whole recursive walk | 100000 |

Key distinction: raising `--max-matcher-bytes` lets exav fully scan multi-gigabyte
members (paying only in scan time), because streamed members are bounded by *this*
and are not held in RAM.

Peak memory is not a single knob. `--max-object-bytes` bounds the largest
individual buffer; `--max-extracted-bytes` bounds how much extracted data can
be resident at once, since extraction is charged cumulatively and never
released. Under the daemon the latter is clamped to fit the per-job address
space, so a scan that runs out reports `LIMITS-EXCEEDED` instead of the worker
being killed. See [Streaming & memory](/concepts/streaming-memory/).

### Buffering a stream (spill)

Separate from the scan budgets above, and not engine fields: these decide where a
streamed object waits while it is scanned. They apply to every surface —
`INSTREAM`, stdin, ICAP — because all three have to materialise a stream before a
container-aware scan can seek in it. See
[the CLI reference](/reference/cli/#buffering-a-stream-spill) for the full
rationale.

| Flag | Default | Meaning |
|---|---|---|
| `--spill-dir <DIR\|off>` | `$TMPDIR` | Where spilled objects are written, or `off` to never write one. |
| `--spill-threshold-bytes` | `16M` | RAM per in-flight object before it spills — the bound on a listener's memory. |
| `--max-spill-bytes` | `2G` | Temp space one object may occupy (clamd `StreamMaxLength`). |
| `--max-total-spill-bytes` | `8G` | Temp space all in-flight objects may occupy together. |

The sizes have to nest — RAM inside one object inside the process — and exav
refuses to start otherwise. An object a budget refuses is `UNSCANNABLE`, never
clean and never a dropped connection. `--spill-dir off` turns disk buffering off
entirely; `0` on the two `--max-` flags means "no ceiling", not "none allowed".

## Capability toggles

| CLI flag | ScanOptions field | Default |
|---|---|---|
| `--base64 off` | `decode_base64` | on |
| `--detect heuristics` | `heuristics` | off |
| `--detect macros` / `phishing` / `broken` / `broken-media` / `packed` / `partition-intersection` | matching `alert_*` fields | off |
| `--detect pua` | PUA databases loaded, `PUA.*` kept | off |
| `--partial-as …=found` | `alert_encrypted` / `alert_exceeds_max` | partial |
| `--clamav-compat` | `restrict_extractors` + `unofficial_suffix` + `clamav_compat` | off (full reach) |
| — (always on, FP-safe) | `clamav_heuristics` (imphash + PDF obfuscation) | on |

The ClamAV-parity heuristic subset (`clamav_heuristics`) is on by default and can
only be turned off through the library, not the CLI — so an out-of-the-box scan
already matches ClamAV's default detection surface.

Two of the engine's `alert_*` fields are reached through `--partial-as`
rather than `--detect`, because they answer a verdict question rather than a
detection one: `alert` turns "could not fully examine this" into a detection
under ClamAV's own `Heuristics.Encrypted.*` / `Heuristics.Limits.*` names.
