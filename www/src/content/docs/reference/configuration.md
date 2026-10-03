---
title: Configuration
description: exav's EXAV_* environment variables, how they combine with flags, the diagnostic variables, and the library options behind the flags.
---

exav is configured with **CLI flags** (see the [CLI reference](/reference/cli/))
and their **`EXAV_*` environment variables**. It reads no configuration file.

## Precedence

An explicit flag wins, then the environment variable, then the default. A
container image can carry its whole configuration in the environment:
`docker run … exav --auto-update --workers 2` overrides `EXAV_AUTO_UPDATE` and
`EXAV_WORKERS` and nothing else. Two exceptions:

- A switch set in the environment cannot be turned off on the command line:
  switches take no value there (`--quiet=no` is refused). Set the variable to
  `0` instead.
- A listener set in `EXAV_LISTEN` yields when the command line asks for
  something else: paths, `--connect`, `--build-db` or `--files-from`. An empty
  `EXAV_LISTEN=` serves nothing, which is how a container switches off its
  image's listener.

In a variable, booleans accept `1`/`yes`/`on`/`true` (and `y`/`t`) for on,
`0`/`no`/`off`/`false` (and `n`/`f`) for off. Anything else stops the run:
`EXAV_AUTO_UPDATE=ture` read as false would fetch nothing and say nothing.

## Every flag has a variable, spelled the same way

A flag's variable is its own name, uppercased, with dashes turned to underscores
and `EXAV_` in front, with no exceptions. The only variables without a flag are
`EXAV_DEBUG_*`, the [diagnostics](#diagnostics) below, and two
[removed ones](#removed-variables) that stop the run.

| Flag | Variable |
|---|---|
| `--listen` | `EXAV_LISTEN` |
| `--max-input-bytes` | `EXAV_MAX_INPUT_BYTES` |
| `--partial-as` | `EXAV_PARTIAL_AS` |
| `--icap-max-requests` | `EXAV_ICAP_MAX_REQUESTS` |

`exav --help` prints the `[env: …]` line under each flag, and the
[CLI reference](/reference/cli/) documents what each one does.

A repeatable flag named on the command line replaces its variable rather than
merging with it. `EXAV_LISTEN`, `EXAV_SIG_SOURCES` and `EXAV_PASSWORDS` split on
commas, as the flags do on the command line (a password containing a comma goes
in `--passwords-from`). `EXAV_EXCLUDE`, `EXAV_EXCLUDE_DIR` and `EXAV_INCLUDE`
hold one pattern each, since a comma is legal inside a regex; repeat the flag for
more.

Settings of one listener (ICAP service names, socket mode, connection limit)
have no flag or variable: they go on the `--listen` address. See
[What belongs to one listener](/reference/cli/#what-belongs-to-one-listener).

### Removed variables

The variables of two removed flags are still read, only to stop the run with a
message naming what replaced them: `EXAV_MAX_EXTRACTED_BYTES` (see
[Limits](/reference/limits/)) and `EXAV_BUILD_SHARD_BYTES`. Delete them from an
image or unit file when upgrading to 0.0.2.

### Diagnostics

`EXAV_DEBUG_*` variables are diagnostics, not settings: leave them unset in
production.

| Variable | Effect |
|---|---|
| `EXAV_DEBUG_BC_WARN` | Set: warn once per stubbed bytecode API a signature calls. See [Bytecode sandbox](/concepts/bytecode-sandbox/). |
| `EXAV_DEBUG_BC_TRACE`, `EXAV_DEBUG_BC_FN=<n>` | Trace bytecode execution, optionally for one function. |

The test suites and examples read a few more, each described where it is
used: `EXAV_DEBUG_YR_BIN` (the `yr` binary the YARA differential tests run),
`EXAV_DEBUG_YARA_CORPUS`, `EXAV_DEBUG_YARA_BENCH_RULES`,
`EXAV_DEBUG_PARITY_DB`, `EXAV_DEBUG_PARITY_CORPUS`, `EXAV_DEBUG_PARITY_LIMIT`
and `EXAV_DEBUG_BC_FORCED`.

## Migrating a ClamAV container

Translate its settings: `CLAMAV_NO_CLAMD` becomes `--auto-update` with no
`--listen`, `CLAMD_STARTUP_TIMEOUT` becomes `EXAV_STARTUP_WAIT_SECS` (which only
applies with `--auto-update` and no `EXAV_SIG_SOURCES`, when a sidecar fills the
directory), and `FRESHCLAM_CHECKS` becomes `EXAV_UPDATE_INTERVAL_SECS` (seconds
between checks, not checks per day). See the [Docker guide](/guides/docker/).

## Library options behind the flags

For [library users](/guides/library-usage/): the `ScanOptions` fields each flag
sets. The limit fields, with defaults, are in
[Limits](/reference/limits/#the-in-core-budgets); the spill flags are not engine
fields (see [Buffering a stream](/reference/cli/#buffering-a-stream-spill)).

| CLI flag | ScanOptions field | Default |
|---|---|---|
| `--decode base64` / `--no-decode base64` | `decode_base64` | on |
| `--detect exav-heuristics` | `heuristics` | off |
| `--detect macros` / `phishing` / `broken` / `broken-media` / `packed` / `partition-intersection` | matching `alert_*` fields | off |
| `--detect pua` | PUA databases loaded, `PUA.*` kept | off |
| `--dlp-credit-cards` / `--dlp-ssns` | `structured_cc_count` / `structured_ssn_count` | off |
| `--passwords` / `--passwords-from` | `passwords` | none |
| `--partial-as …=found` | `alert_encrypted` / `alert_exceeds_max` | partial |
| `--clamav-compat` | `restrict_extractors` + `unofficial_suffix` + `clamav_compat`, plus the limits and decoders listed under [ClamAV compatibility](/reference/cli/#clamav-compatibility) | off (full reach) |
| none (always on) | `clamav_heuristics` (imphash + PDF obfuscation) | on |

The ClamAV-parity heuristics (`clamav_heuristics`) can only be turned off through
the library, so an out-of-the-box scan matches ClamAV's default detection surface.

Two `alert_*` fields are set by `--partial-as` rather than `--detect`, because
they answer a verdict question: `found` turns "could not fully examine this" into
a detection under ClamAV's own `Heuristics.Encrypted.*` / `Heuristics.Limits.*`
names.
