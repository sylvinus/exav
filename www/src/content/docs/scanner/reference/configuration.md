---
title: Configuration
description: exav's EXAV_* environment variables, how they combine with flags, the diagnostic variables, and translating a ClamAV container's settings.
---

exav is configured with **CLI flags** (see the [CLI reference](/scanner/reference/cli/))
and their **`EXAV_*` environment variables**. It reads no configuration file.

## Precedence

An explicit flag wins, then the environment variable, then the default. A
container image can carry its whole configuration in the environment:
`docker run … exav --auto-update --workers 2` overrides `EXAV_AUTO_UPDATE` and
`EXAV_WORKERS` and nothing else. Three exceptions:

- A switch set in the environment cannot be turned off on the command line:
  switches take no value there (`--quiet=no` is refused). Set the variable to
  `0` instead.
- A listener set in `EXAV_LISTEN` yields when the command line asks for
  something else: paths, `--connect`, `--build-db` or `--files-from`. An empty
  `EXAV_LISTEN=` serves nothing, which is how a container switches off its
  image's listener.
- A setting for a listener the run does not have (`--workers`,
  `--allow-shutdown`, `--listen-health`, `--max-jobs-per-worker`, the `--icap-*`
  flags) that only its variable sets is ignored, with a warning on stderr: the
  variable that serves a daemon in an image must not stop a one-shot scan in
  it. On the command line it is refused.

In a variable, booleans accept `1`/`yes`/`on`/`true` (and `y`/`t`) for on,
`0`/`no`/`off`/`false` (and `n`/`f`) for off. Anything else stops the run:
`EXAV_AUTO_UPDATE=ture` read as false would fetch nothing and say nothing.

## Every flag has a variable, spelled the same way

A flag's variable is its own name, uppercased, with dashes turned to underscores
and `EXAV_` in front, with no exceptions. The only variables without a flag are
`EXAV_DEBUG_*`, the [diagnostics](#diagnostics) below, and the variable of a
[removed flag](#removed-variables), which stops the run.

| Flag | Variable |
|---|---|
| `--listen` | `EXAV_LISTEN` |
| `--max-input-bytes` | `EXAV_MAX_INPUT_BYTES` |
| `--partial-as` | `EXAV_PARTIAL_AS` |
| `--spill-threshold-bytes` | `EXAV_SPILL_THRESHOLD_BYTES` |

`exav --help` prints the `[env: …]` line under each flag, and the
[CLI reference](/scanner/reference/cli/) documents what each one does.

A repeatable flag named on the command line replaces its variable rather than
merging with it. `EXAV_LISTEN`, `EXAV_SIG_SOURCES` and `EXAV_PASSWORDS` split on
commas, as the flags do on the command line (a password containing a comma goes
in `--passwords-from`). `EXAV_EXCLUDE`, `EXAV_EXCLUDE_DIR` and `EXAV_INCLUDE`
hold one pattern each, since a comma is legal inside a regex; repeat the flag for
more.

Settings of one listener (ICAP service names and preview, socket mode,
connection limit, timeouts) have no flag or variable: they go on the `--listen`
address. See
[What belongs to one listener](/scanner/reference/cli/#what-belongs-to-one-listener).

### Removed variables

The variable of a removed flag is still read, only to stop the run with a
message naming what replaced it: `EXAV_BUILD_SHARD_BYTES`, and since 0.0.3
the seven `EXAV_ICAP_*` variables (`EXAV_ICAP_IDLE_SECS`,
`EXAV_ICAP_MAX_REQUESTS`, `EXAV_ICAP_MAX_HEADER_BYTES`,
`EXAV_ICAP_PREVIEW_BYTES`, `EXAV_ICAP_TRANSFER_PREVIEW`,
`EXAV_ICAP_OPTIONS_TTL_SECS`, `EXAV_ICAP_INFECTION_HEADER`), now keys of the
ICAP address of the same name without the `icap-` (`?idle-secs=`,
`?preview-bytes=`, and so on). Delete it from an image or unit file when upgrading. (`EXAV_MAX_EXTRACTED_BYTES` was removed in
0.0.2 and is the variable of `--max-extracted-bytes` again; see
[Limits](/scanner/reference/limits/).)

### Diagnostics

`EXAV_DEBUG_*` variables are diagnostics, not settings: leave them unset in
production.

| Variable | Effect |
|---|---|
| `EXAV_DEBUG_BC_WARN` | Set: warn once per stubbed bytecode API a signature calls. See [Bytecode sandbox](/scanner/concepts/bytecode-sandbox/). |
| `EXAV_DEBUG_BC_TRACE`, `EXAV_DEBUG_BC_FN=<n>` | Trace bytecode execution, optionally for one function. |

The test suites and examples read a few more `EXAV_DEBUG_*` variables, described
where they are used.

## Migrating a ClamAV container

Translate its settings: `CLAMAV_NO_CLAMD` becomes `--auto-update` with no
`--listen`, `CLAMD_STARTUP_TIMEOUT` becomes `EXAV_STARTUP_WAIT_SECS` (which only
applies with `--auto-update` and no `EXAV_SIG_SOURCES`, when a sidecar fills the
directory), and `FRESHCLAM_CHECKS` becomes `EXAV_UPDATE_INTERVAL_SECS` (seconds
between checks, not checks per day). See the [Docker guide](/scanner/guides/docker/).

## In the library

Embedding the engine, the flags become `ScanOptions` fields: the table is under
[exav-core](/subprojects/exav-core/#options-behind-the-cli-flags), and the limit
fields under [Limits](/scanner/reference/limits/#the-in-core-budgets).
