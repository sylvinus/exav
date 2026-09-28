---
title: Configuration
description: exav's EXAV_* environment variables, the flag each one falls back from, and the ScanOptions-level limit knobs behind the limit flags.
---

exav is configured three ways: **CLI flags** (see the [CLI reference](/reference/cli/)),
**`EXAV_*` environment variables**, and the underlying **`ScanOptions`** limit
knobs each limit flag maps to.

## Precedence

An explicit flag wins, then the environment variable, then the default, for
every setting. A container image can carry its whole configuration in the
environment while any value stays overridable on the command line:
`docker run … exav --auto-update --workers 2` overrides `EXAV_WORKERS` and nothing
else.

Booleans accept `1`/`yes`/`on`/`true` (and `y`/`t`) for on, `0`/`no`/`off`/`false`
(and `n`/`f`) for off. Anything else stops the run: `EXAV_AUTO_UPDATE=ture` read
as false would fetch nothing and say nothing.

## Every flag has a variable, spelled the same way

A flag's variable is its own name, uppercased, with dashes turned to underscores
and `EXAV_` in front. There are no exceptions and no variable without a flag.

| Flag | Variable |
|---|---|
| `--listen` | `EXAV_LISTEN` |
| `--max-input-bytes` | `EXAV_MAX_INPUT_BYTES` |
| `--partial-as` | `EXAV_PARTIAL_AS` |
| `--icap-max-requests` | `EXAV_ICAP_MAX_REQUESTS` |

`exav --help` prints the `[env: …]` line under each flag. The
[CLI reference](/reference/cli/) documents what each one does; this page covers
what does not live in a flag, and the engine budgets behind the limits.

## What lives in the address, not in a flag

Settings that belong to one listener go on its `--listen` address: an ICAP
service is the URL path, the rest a `?key=value` tail.

| On the address | Default | Meaning |
|---|---|---|
| `/avscan` *(the path)* | `avscan`, `srv_clamav`, `virus_scan` | The ICAP service to answer on, the path of the URL a proxy is configured with. Naming one replaces the default set. |
| `?service=a&service=b` | none | Several ICAP services. Repeat the key: a comma separates addresses, not names. |
| `?mode=660` | `0600` | Permission bits for a Unix socket. Owner-only unless widened, because every user the mode admits can submit scans and read the verdicts. |
| `?max-connections=200` | `128` clamd, `100` ICAP | Concurrent connections this listener accepts. ICAP also advertises it as `Max-Connections`. Bounds the clamd listener only under `--workers threads`; the prefork pool bounds concurrency by its worker count. |

```sh
exav --listen 'clamd:///run/exav.sock?mode=660' \
     --listen 'icap://0.0.0.0:1344/avscan?max-connections=200'
```

A flag for any of these would have to say which listener it meant; on the
address each has exactly one thing to attach to. An unknown option is an error,
not an ignored word.

### Engine diagnostics are not on this page

`exav-core` reads a few more variables that are library diagnostics, not
deployment settings: switches that bypass the YARA prefilter, select the legacy
matcher path, warn on a stubbed bytecode API, or cap a verification budget. They
let two code paths be compared on the same input, which is how the engine is
tested. They are documented next to what they toggle, in
[Bytecode sandbox](/concepts/bytecode-sandbox/) and the YARA design notes; treat
anything not listed here as belonging to the test bench.

### Migrating a ClamAV container

Translate its settings: `CLAMAV_NO_CLAMD` becomes `--auto-update` with no
`--listen`, `CLAMD_STARTUP_TIMEOUT` becomes `EXAV_STARTUP_WAIT_SECS`, and
`FRESHCLAM_CHECKS` becomes `EXAV_UPDATE_INTERVAL_SECS` (seconds between checks,
not checks per day). See the [Docker guide](/guides/docker/).

## Limit knobs (ScanOptions)

Each CLI limit flag sets an engine-level budget, on a memory axis or a CPU axis:

| CLI flag | Engine field | Bounds | Default |
|---|---|---|---|
| `--max-input-bytes` | `max_scan_size` | the largest top-level input taken | unlimited |
| `--max-extracted-bytes` | `deep_analysis_max` + `max_extracted_bytes` | what decompression may produce | 256M / 1G (the flag sets both to one value) |
| `--max-object-bytes` | `max_buffer_bytes` (+ `deep_analysis_max`) | memory: the largest single object, and the largest file the full engine scans | 256M |
| `--max-matcher-bytes` | `max_scanned_bytes` | CPU: bytes fed to the matcher | 10G |
| `--max-pe-emulation-steps` | `max_pe_emulation_steps` | CPU: emulator instructions across all packed executables in one file | 1000000000 |
| `--max-unpack-depth` | `max_recursion` | nesting depth | 16 |
| `--max-members` | `max_members` | members across the whole recursive walk | 100000 |

See [Limits](/reference/limits/) for which one to raise.

Peak memory is not a single knob. `--max-object-bytes` bounds the largest
individual buffer; `--max-extracted-bytes` bounds how much extracted data can
be resident at once, since extraction is charged cumulatively and never
released. Under the daemon the latter is clamped to fit the per-job address
space, so a scan that runs out reports `LIMITS-EXCEEDED` instead of the worker
being killed. See [Streaming & memory](/concepts/streaming-memory/).

### Buffering a stream (spill)

These are not engine fields: they decide where a streamed object waits while it
is scanned, on every surface (`INSTREAM`, stdin, ICAP), since a stream has to be
held before a container-aware scan can seek in it. See
[the CLI reference](/reference/cli/#buffering-a-stream-spill).

| Flag | Default | Meaning |
|---|---|---|
| `--spill-dir <DIR\|off>` | `$TMPDIR` | Where spilled objects are written, or `off` to never write one. |
| `--spill-threshold-bytes` | `16M` | RAM per in-flight object before it spills: the bound on a listener's memory. |
| `--max-spill-bytes` | `2G` | Temp space one object may occupy (clamd `StreamMaxLength`). |
| `--max-total-spill-bytes` | `8G` | Temp space all in-flight objects in one process may occupy together (per worker and per ICAP child under the pool). |

The sizes have to nest (RAM inside one object inside the process), and exav
refuses to start otherwise. An object past a budget has what was held scanned,
and is `LIMITS-EXCEEDED` unless that finds something. `--spill-dir off` turns disk buffering off
entirely; `0` on the two `--max-` flags means "no ceiling", not "none allowed".

## Capability toggles

| CLI flag | ScanOptions field | Default |
|---|---|---|
| `--decode base64` / `--no-decode base64` | `decode_base64` | on |
| `--detect exav-heuristics` | `heuristics` | off |
| `--detect macros` / `phishing` / `broken` / `broken-media` / `packed` / `partition-intersection` | matching `alert_*` fields | off |
| `--detect pua` | PUA databases loaded, `PUA.*` kept | off |
| `--partial-as …=found` | `alert_encrypted` / `alert_exceeds_max` | partial |
| `--clamav-compat` | `restrict_extractors` + `unofficial_suffix` + `clamav_compat` | off (full reach) |
| none (always on) | `clamav_heuristics` (imphash + PDF obfuscation) | on |

The ClamAV-parity heuristics (`clamav_heuristics`) can only be turned off through
the library, so an out-of-the-box scan matches ClamAV's default detection surface.

Two `alert_*` fields are set by `--partial-as` rather than `--detect`, because
they answer a verdict question: `found` turns "could not fully examine this" into
a detection under ClamAV's own `Heuristics.Encrypted.*` / `Heuristics.Limits.*`
names.
