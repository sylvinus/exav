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
`docker run … exav --auto-update --workers 2` overrides `EXAV_AUTO_UPDATE` and
`EXAV_WORKERS` and nothing else.

Booleans accept `1`/`yes`/`on`/`true` (and `y`/`t`) for on, `0`/`no`/`off`/`false`
(and `n`/`f`) for off. Anything else stops the run: `EXAV_AUTO_UPDATE=ture` read
as false would fetch nothing and say nothing.

## Every flag has a variable, spelled the same way

A flag's variable is its own name, uppercased, with dashes turned to underscores
and `EXAV_` in front, with no exceptions. The only variables without a flag are
the [engine diagnostics](#engine-diagnostics) below.

| Flag | Variable |
|---|---|
| `--listen` | `EXAV_LISTEN` |
| `--max-input-bytes` | `EXAV_MAX_INPUT_BYTES` |
| `--partial-as` | `EXAV_PARTIAL_AS` |
| `--icap-max-requests` | `EXAV_ICAP_MAX_REQUESTS` |

`exav --help` prints the `[env: …]` line under each flag. The
[CLI reference](/reference/cli/) documents what each one does; this page covers
what does not live in a flag, and the engine budgets behind the limits.

A repeatable flag named on the command line replaces its variable rather than
merging with it. `EXAV_LISTEN`, `EXAV_SIG_SOURCES` and `EXAV_PASSWORDS` split on
commas, as the flags do on the command line (a password containing a comma goes
in `--passwords-from`). `EXAV_EXCLUDE`, `EXAV_EXCLUDE_DIR` and `EXAV_INCLUDE`
hold one pattern each, since a comma is legal inside a regex; repeat the flag for
more.

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

### Engine diagnostics

`exav-core` reads a few more variables. They are diagnostics, not settings: they
let two code paths be compared on the same input, or trace one. Leave them unset
in production.

| Variable | Effect |
|---|---|
| `EXAV_YARA_NO_GATE` | Set: skip the YARA atom prefilter and evaluate every rule. |
| `EXAV_SPLIT_MATCH=0` | Use the backtracking signature verifier instead of the default non-backtracking one. |
| `EXAV_VERIFY_BUDGET` | Step budget for that backtracking verifier. |
| `EXAV_SIM_BUDGET` | Step budget for the default verifier. |
| `EXAV_MAX_GROUP_STEPS` | Steps one anchor group may draw per scan. |
| `EXAV_MAX_BUFFERED_HITS` | Anchor hits buffered before the matcher falls back to its direct path. |
| `EXAV_ANCHOR_STATS=0` | Skip the build-time anchor re-pick (speed only; matching is the same). |
| `EXAV_BC_WARN` | Set: warn once per stubbed bytecode API a signature calls. See [Bytecode sandbox](/concepts/bytecode-sandbox/). |
| `EXAV_BC_TRACE`, `EXAV_BC_FN=<n>` | Trace bytecode execution, optionally for one function. |

### Migrating a ClamAV container

Translate its settings: `CLAMAV_NO_CLAMD` becomes `--auto-update` with no
`--listen`, `CLAMD_STARTUP_TIMEOUT` becomes `EXAV_STARTUP_WAIT_SECS`, and
`FRESHCLAM_CHECKS` becomes `EXAV_UPDATE_INTERVAL_SECS` (seconds between checks,
not checks per day). See the [Docker guide](/guides/docker/).

## Limit knobs (ScanOptions)

Each CLI limit flag sets an engine-level budget, on a memory axis or a CPU axis:

The engine fields behind each limit flag, with defaults and which one to raise,
are in [Limits](/reference/limits/#the-in-core-budgets). The spill flags are not
engine fields; see [Buffering a stream](/reference/cli/#buffering-a-stream-spill).
For peak memory, see [Streaming & memory](/concepts/streaming-memory/) and
[sizing a server](/guides/sizing/).

## Capability toggles

| CLI flag | ScanOptions field | Default |
|---|---|---|
| `--decode base64` / `--no-decode base64` | `decode_base64` | on |
| `--detect exav-heuristics` | `heuristics` | off |
| `--detect macros` / `phishing` / `broken` / `broken-media` / `packed` / `partition-intersection` | matching `alert_*` fields | off |
| `--detect pua` | PUA databases loaded, `PUA.*` kept | off |
| `--dlp-credit-cards` / `--dlp-ssns` | `structured_cc_count` / `structured_ssn_count` | off |
| `--passwords` / `--passwords-from` | `passwords` | none |
| `--partial-as …=found` | `alert_encrypted` / `alert_exceeds_max` | partial |
| `--clamav-compat` | `restrict_extractors` + `unofficial_suffix` + `clamav_compat` | off (full reach) |
| none (always on) | `clamav_heuristics` (imphash + PDF obfuscation) | on |

The ClamAV-parity heuristics (`clamav_heuristics`) can only be turned off through
the library, so an out-of-the-box scan matches ClamAV's default detection surface.

Two `alert_*` fields are set by `--partial-as` rather than `--detect`, because
they answer a verdict question: `found` turns "could not fully examine this" into
a detection under ClamAV's own `Heuristics.Encrypted.*` / `Heuristics.Limits.*`
names.
