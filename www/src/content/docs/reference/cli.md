---
title: CLI reference
description: Every exav command-line flag, from targets and scanning limits to output, listeners, and the ClamAV-compatibility preset.
---

`exav [OPTIONS] [PATH]...`

Scan `PATH`(s), files or directories, for malware. `-` reads stdin. An
`http(s)://` target is scanned over range requests (needs an `http-scan` build).
With no real signatures loaded, exav refuses to run unless `--allow-no-db`.

`exav --help` is the authoritative list; this page mirrors it.

## How a setting is decided

An explicit flag wins, then the environment variable, then the default, for every
setting. A container image can carry its configuration in the environment while
any value stays overridable on the command line.

Every flag has an `EXAV_*` variable: the flag uppercased, dashes to underscores,
`EXAV_` in front (`--max-input-bytes` reads `EXAV_MAX_INPUT_BYTES`). `exav --help`
prints the `[env: …]` line under each. [Configuration](/reference/configuration/)
covers the rest.

A boolean variable takes `1`/`yes`/`on`/`true` or `0`/`no`/`off`/`false`; anything
else stops the run.

Repeatable flags (`--exclude`, `--exclude-dir`, `--include`, `--passwords`) follow
the same rule without merging: naming the flag on the command line replaces the
environment value. Repeat the flag for two patterns. (The environment holds one
pattern, since a comma is legal inside a regex.)

## Targets, filters and logging

| Flag | Description |
|---|---|
| `PATH...` | Files or directories to scan. `-` reads stdin. A named directory is scanned recursively. |
| `--no-recursive` | Scan only the files directly inside a named directory. |
| `--files-from <FILE>` | Read paths to scan from `FILE`, one per line (`-` reads the list from stdin). Blank lines and `#` comments are skipped; the paths merge with any on the command line. |
| `--exclude <REGEX>` | Skip files whose path matches (repeatable). |
| `--exclude-dir <REGEX>` | Skip directories whose path matches (repeatable). |
| `--include <REGEX>` | Only scan files whose path matches (repeatable). |
| `--bell` | Sound a bell on detection. |
| `--log <FILE>` | Append every result line to `FILE` as well as stdout. Opened before scanning starts, so a bad path fails immediately. |

`--log` adds to stdout rather than replacing it, so pipes keep working. On a
listener it records what the daemon answered, one line per scan command, under
the daemon's view of the target (`stream:` for a streamed scan, `fd:` for a
passed descriptor). `PING`, `VERSION` and `STATS` are not logged.

### `--files-from` and the daemon

The list is expanded before the mode is chosen, so it works the same for a local
scan and for a `--connect` client. Paths are sent to the daemon as paths, so the
daemon must be able to see them; otherwise send the contents (see
[`--send-as`](#sending-a-file-the-daemon-cannot-open)).

## Signature sources

| Flag | Default | Description |
|---|---|---|
| `-d`, `--database <PATH>` | none | Load signatures from a file or directory (`.ndb`/`.hdb`/`.cvd`/… or a prebuilt `.exavdb`). A directory is loaded recursively. |
| `--sig-dir <DIR>` | `/var/lib/exav` | The directory signatures live in: the one `--auto-update` writes into and a sidecar populates. |
| `--sig-sources <FILE>` | none | File of signature source URLs (also reads `freshclam.conf` source directives). |
| `--allow-no-db` | off | Testing only. Run against the built-in EICAR-only baseline when no real database is present, instead of refusing. |
| `--build-db <FILE>` | none | Compile the loaded signatures into a prebuilt `.exavdb` and exit. |
| `--build-shard-bytes <SIZE>` | none | Cap the per-shard automaton-build transient (`--build-db` only). |

`-d` and `--sig-dir` are different things: `--sig-dir` names a directory that is
written to, so a deployment can serve a prebuilt `.exavdb` from one path with
`-d` while an updater keeps a signature directory current at another.

## Signature lifecycle

`--auto-update` keeps the signature source current while the process runs. Add it
to a listener, or to a one-shot scan that should fetch first. It:

1. creates the signature directory and fetches every configured source before the
   first load;
2. where a sidecar owns the directory, waits `--startup-wait-secs` for it to be
   filled;
3. re-checks the sources every `--update-interval-secs` (at least 60 seconds) and
   hot-reloads on every change;
4. can pull a prebuilt `.exavdb` from `--db-url` instead of signature files, with
   the same change detection and reload.

Serving with no real signatures is refused in every case, including on a reload:
an emptied volume keeps the database already loaded.

| Flag | Default | Description |
|---|---|---|
| `--auto-update` | off | Bootstrap, refresh and hot-reload the signature source. Fetching needs an `http-update` build; Unix only. |
| `--sig-sources <URL\|FILE>` | none | Where to fetch from. Repeatable; the sources merge. |
| `--db-url <URL>` | none | A prebuilt `.exavdb` to pull and serve instead of signature files. |
| `--startup-wait-secs <SECS>` | `1800` with `--auto-update`, `0` otherwise | How long to wait for a sidecar to populate an empty signature directory. `0` does not wait. |
| `--update-interval-secs <SECS>` | `86400`, or `300` with `--db-url` | Seconds between source re-checks. |

`--auto-update` with no `--listen` and no paths is the updater half of a
two-container deployment: it keeps the signature volume current and loads no
database of its own.

### `--sig-sources` reads three shapes from one value

| Value | Read as |
|---|---|
| `https://host/main.cvd` | an exact source, fetched as given |
| `https://host/db/` | a mirror base (the trailing slash makes it one), expanded to `<base>/{main,daily,bytecode}.cvd` |
| `/etc/exav/sources` | a file of the above, one per line (`#` comments allowed), or a `freshclam.conf` |

Anything that is not an `http(s)` URL is a path. From a `freshclam.conf`, exav
reads the source directives (`DatabaseMirror`/`PrivateMirror`,
`DatabaseCustomURL`) and warns about every line it ignores, including
`DatabaseDirectory`, which is `--sig-dir`.

Every source is fetched the same way, over plain HTTPS with no signature
verification: point it at a mirror you trust, or use `freshclam` / `cvd` and let
exav hot-reload the directory. A source named without `--auto-update` is
reported.

The `--db-url` re-check defaults to 300 seconds because it is a conditional
`HEAD` that transfers nothing when the database has not changed.

## Scan limits

Sizes accept `K`/`M`/`G`/`T` suffixes (binary: `45M` is 45 MiB). `0` or `off`
means no limit on every size limit and on `--max-pe-emulation-steps`. A period
(how often something happens, such as `--update-interval-secs`) refuses `0`,
which would read as "always"; only `off` disables it. `--workers` takes a count
or `threads`, and refuses `0`. See [Limits](/reference/limits/) for which one to
change.

| Flag | exav default | `--clamav-compat` | Description |
|---|---|---|---|
| `--max-input-bytes <SIZE>` | unlimited | `100M` | Largest top-level input taken. Past it the first bytes get the whole scan, and without a detection there the input is `LIMITS-EXCEEDED`. The same for a file, stdin and every daemon verb. |
| `--max-extracted-bytes <SIZE>` | `256M` / `1G` | `400M` | What decompression may produce across one top-level file: sets the deep-analysis size and the summed extracted bytes to one value; unset, they keep their own defaults. |
| `--max-object-bytes <SIZE>` | `256M` | none | The most memory one materialized object may use; several are live at once across nesting levels, and `--max-extracted-bytes` bounds their sum. Also the largest file the full signature engine scans: a larger one is matched against literal signatures and whole-file hashes only, and is `LIMITS-EXCEEDED` unless one of those matches. |
| `--max-matcher-bytes <SIZE>` | `10G` | none | Bytes fed to the matcher across one top-level file: a CPU bound, not a memory one. |
| `--max-pe-emulation-steps <N>` | `1000000000` | none | Instructions the PE unpacking emulator may run across one top-level file, summed over every packed executable in it. Reaching it is `LIMITS-EXCEEDED`. |
| `--max-unpack-depth <N>` | `16` | `17` | Maximum nesting depth for recursive unpacking. |
| `--max-members <N>` | `100000` | `10000` | Maximum members visited across the whole recursive walk. Higher than ClamAV's because exav descends into nested archives ClamAV does not, so it counts more objects for the same file. |

Each bound has one spelling. `clamscan`'s names (`--max-filesize`,
`--max-scansize`, `--max-files`) are refused, with an error naming the exav flag.
The mapping is in the [ClamAV flag matrix](/reference/clamav-flag-matrix/).

### Buffering a stream (spill)

Container-aware scanning needs to seek (a ZIP's directory is at its end), so
every stream (`INSTREAM`/`EXINSTREAM`, stdin, an ICAP body) is held before it is
scanned: small ones in RAM, larger ones in a temp file. These bound that, on
every surface.

| Flag | Default | Description |
|---|---|---|
| `--spill-dir <DIR\|off>` | platform temp dir (`$TMPDIR`) | Where the temp files go, or `off` to never write one. Use a filesystem with room, and one you are willing to see fill up. |
| `--spill-threshold-bytes <SIZE>` | `16M` | Bytes held in RAM before an object spills. This bounds a listener's memory: a connection costs this much whatever the object weighs. |
| `--max-spill-bytes <SIZE>` | `2G` | The most temp space one object may occupy (clamd's `StreamMaxLength`). |
| `--max-total-spill-bytes <SIZE>` | `8G` | The most temp space every in-flight object may occupy together within one process. Under the worker pool each worker and the ICAP child counts separately. |

A per-object cap does not bound the total: a hundred connections at `2G` each is
200 GB, and filling the temp filesystem takes down everything else on it. Size
`--max-total-spill-bytes` against the free space on `--spill-dir`.

The sizes must nest (RAM inside one object inside the process), and exav refuses
to start otherwise. An object a budget refuses is `UNSCANNABLE`, answered rather
than dropped.

#### Turning it off

```sh
exav --listen icap://0.0.0.0:1344 --spill-dir off --spill-threshold-bytes 64M
```

Nothing is written to disk: `--spill-threshold-bytes` becomes the largest object
exav takes, and anything larger is `UNSCANNABLE`. Use it for a read-only root
filesystem or a container with no writable temp directory, and budget memory as
threshold times concurrent scans. It is spelled `--spill-dir off` rather than a
`0`, because `0` on the `--max-` flags means "no ceiling"; combining
`--spill-dir off` with `--max-spill-bytes` is refused.

## Detection

| Flag | Default | Description |
|---|---|---|
| `--detect <LIST>` | `none` | Heuristic detectors to switch on, on top of the signature database: `none`, `all`, or a comma-separated list of `exav-heuristics`, `macros`, `broken`, `broken-media`, `partition-intersection`, `phishing`, `packed`, `pua`. |
| `--no-detect <LIST>` | none | Detectors to leave off, subtracted from `--detect` (for `--detect all` minus a noisy one). |
| `--decode <LIST>` | `all` | Encodings to recover a payload from before scanning: `all`, `none`, or a list; today the list is `base64`. On by default, unlike `--detect`, because a carrier hiding its payload is the ordinary case. `--clamav-compat` sets `none`. |
| `--no-decode <LIST>` | none | Encodings to leave alone, subtracted from `--decode`. |
| `--passwords <PW>` | none | Password to try on encrypted archive members. Repeatable (comma-separated in the environment), tried in order, together with any `.pwdb` databases. A password containing a comma goes in `--passwords-from`. |
| `--passwords-from <FILE>` | none | Read passwords from a file, one per line, after `--passwords`. Lines are kept verbatim apart from the line ending. The contents stay out of process listings, though the path does not; `chmod 0600` it. |
| `--dlp-credit-cards <N>` | off | Alert `Heuristics.Structured.CreditCardNumber` on a textual file holding N or more valid credit-card numbers. Needs the `dlp` feature. |
| `--dlp-ssns <N>` | off | Alert `Heuristics.Structured.SSN` on N or more valid US Social Security numbers. Needs the `dlp` feature. |

A decoder is not an unpacker: an unpacker opens a container the file declares
itself to be; a decoder finds a payload the carrier does not announce, such as a
PE base64'd into a PowerShell one-liner. `--decode` and `--no-decode` compose by
subtraction. The `--dlp-` flags detect data leaks rather than malware, which is
why they are not `--detect` values.

### What an unscannable object becomes

`--detect` says what to look for; `--partial-as` says what happens to an object
exav could not fully examine. The value is the status it reports as, and each
status has one exit code:

| Value | Status | Exit | Effect |
|---|---|---|---|
| `partial` *(default)* | `PARTIAL` | 3 | The verdict stands, under its category. A clamd `ERROR` reply, an ICAP block. |
| `ok` | `OK` | 0 | Deliver it as clean. An ICAP `204`. |
| `found` | `FOUND` | 1 | Report it as a detection named `Heuristics.*`, what ClamAV's `--alert-exceeds-max` / `--alert-encrypted` produce. |
| `error` | `ERROR` | 2 | Report it as an operational failure, for a caller that does not want a fourth exit code. |

It also takes a per-category list, such as
`--partial-as password-protected=ok,limits-exceeded=found`, over
`limits-exceeded`, `unscannable` and `password-protected`.

`ok` is what ClamAV does for an encrypted archive and what `c-icap` does past
`MaxObjectSize`. exav does it only when asked: every such object is logged, and
the listener announces the policy at startup. `--clamav-compat` implies
`--partial-as ok`; an explicit value still wins. Without the preset:

```sh
exav --partial-as ok /data
```

It is refused with `--connect`: the policy belongs to whatever scans, and a client
only sees the reply the daemon decided. On the clamd wire `partial` and `error`
are both an `ERROR` reply, since a `clamdscan` reads any other word as `OK`; they
differ only in the exit code of an exav client.

## Output

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Print informational findings (type, entropy, imphash, ML score). A daemon reply carries only a verdict, so in client mode it names the daemon that answered and the command sent per target instead. |
| `--quiet` | Print only errors and detections: no per-file `OK` lines, no summary. |
| `--json` | Newline-delimited JSON, one object per input, then a summary object. |
| `--all-matches` | Report every matching signature, not just the first. |

## Finding where the CPU went

A listener serves objects nobody kept, so it counts for itself:

| Flag | Default | Description |
|---|---|---|
| `--profile` | off | Measure where scan time goes, per matcher. Scanning files, it replaces the output with a CSV row per file; on a listener the numbers accumulate and come back as `MATCHERSTATS`. Off by default because it times every matcher call. |
| `--slow-scan-secs <SECS\|off>` | `10` | Log any scan taking longer, naming the object and (with `--profile`) where the time went. |
| `--metrics-secs <SECS\|off>` | `300` | Seconds between the scan-totals lines a listener writes to its log. Silent while nothing is scanned. |

Scan counts, bytes and wall time are always collected (one clock read per scan);
only the per-matcher breakdown is opt-in. Three ways to read them:

**On demand**, over the clamd protocol (what `clamdtop` polls):

```console
$ printf 'zSTATS\0' | nc 127.0.0.1 3310
…
SCANSTATS: scans 3 bytes 20135159 scan-seconds 5.435 mean-ms 1811.617
  slowest-ms 5382.013 throughput-MBps 3.7 in-flight 0 slow 0 infected 1 partial 0
MATCHERSTATS: engine=2278.692ms/7calls/60405341b normalize=566.013ms/4calls/40270182b
END
```

**In the log**, every `--metrics-secs`. An ICAP-only deployment has no clamd port
to ask `STATS` on, so for a container `docker logs` is the answer.

**Per slow object:**

```
exav: slow scan: 5.295s for 20000000 bytes of http://host/_matrix/media/v3/upload/big.bin
  [engine 2253.1ms, normalize 596.4ms, bytecode 0.0ms]
```

Under the worker pool the counters are per process, so a `STATS` reply describes
the worker that answered it; the log lines cover every process. For one set of
totals across both listeners, run `--workers threads`.

`--max-scan-secs` is refused under `--workers threads`, since only the pool can
stop one job. There a scan is bounded by work: `--max-matcher-bytes`,
`--max-pe-emulation-steps`, `--max-unpack-depth` and `--max-members`.

## Serving and connecting

`--listen` accepts connections and `--connect` makes one; paths with neither scan
locally. See the [daemon guide](/guides/daemon/) and
[One binary, three roles](/guides/migrating-from-clamav/#one-binary-three-roles).

Both take the same address grammar, with the protocol in the value:

```
clamd://0.0.0.0:3310         the clamd protocol over TCP
clamd:///var/run/exav.sock   the clamd protocol over a Unix socket
icap://0.0.0.0:1344          ICAP (RFC 3507), for a proxy's adaptation hook
icap://0.0.0.0:1344/avscan   ICAP answering on that service only
0.0.0.0:3310                 no scheme: clamd
/var/run/exav.sock           no scheme, a path: clamd over a Unix socket
```

A leading `/` is a socket path; anything else is `host:port`, optionally followed
by `/<service>` for ICAP. A TCP address without a port is refused. Nothing
listens without `--listen`.

### What belongs to one listener

Settings of one listener go on its address: an ICAP service is the URL path, the
rest a `?key=value` tail.

| On the address | Default | Meaning |
|---|---|---|
| `/avscan` *(the path)* | `avscan`, `srv_clamav`, `virus_scan` | The ICAP service to answer on. Naming one replaces the default set. |
| `?service=a&service=b` | none | Several ICAP services. Repeat the key; a comma separates addresses, not names. |
| `?mode=660` | `0600` | Permission bits for a Unix socket. |
| `?max-connections=200` | `128` clamd, `100` ICAP | Concurrent connections this listener accepts. |

```sh
exav --listen 'clamd:///run/exav.sock?mode=660' \
     --listen 'icap://0.0.0.0:1344/avscan?max-connections=200'
```

Each option is refused where it cannot apply (a path on a `clamd://` address, a
mode on a `host:port`), and an unknown option is an error. `max-connections`
bounds the clamd listener only under `--workers threads`; the pool bounds
concurrency by its worker count. ICAP always reads it and advertises it as
`Max-Connections`.

| Flag | Default | Description |
|---|---|---|
| `--listen <ADDR>` | none | Serve on this address. Repeatable (comma-separated in the environment). |
| `--connect <ADDR>` | none | Scan by handing each file to a daemon already running there, instead of loading a database. Listener options (`?mode=`, `?max-connections=`, `?service=`) are refused here. |
| `--send-as <WHAT>` | `path` | What a `--connect` client hands the daemon: `path`, `contents` or `fd`. |
| `--ping` | off | Ask a daemon whether it is answering, and exit `0` or `2`. Probes `--connect` when given, otherwise the listener this configuration would serve (so a container health check needs no address of its own), with `PING` on clamd and `OPTIONS` on ICAP. One probe; retrying is up to the caller. |
| `--workers <N\|threads>` | CPU cores | Daemon worker model (Unix): a count runs a prefork pool, `threads` runs the listeners in one process. |
| `--max-scan-secs <SECS>` | `120` in the pool, unset otherwise | Unix. Per job in the pool (wall clock, plus CPU time via `RLIMIT_CPU`): a job past it is answered `LIMITS-EXCEEDED` and its worker replaced. In a one-shot run it bounds the whole run, which exits 3. Refused for a listener under `--workers threads`. |
| `--max-process-bytes <SIZE>` | `2G` in the pool, unset otherwise | Unix. Address space (`RLIMIT_AS`): per worker in the pool, the whole process in a one-shot run or the thread model. Also lowers the in-core extraction budget to fit inside it. |
| `--max-jobs-per-worker <N>` | `1000` | Prefork only: recycle a worker after this many jobs. |
| `--allow-shutdown` | off | Honour the clamd `SHUTDOWN` command, letting any client that can reach the daemon stop it. |
| `--allow-http-scan` | off | Fetch `http(s)://` scan targets (`exav URL` one-shot, the daemon's `SCANURL`). Needs an `http-scan` build. |

`SHUTDOWN` is off by default because a scanner that is not running reports
nothing, and a pipeline that reads no answer as "fine" passes everything.

Naming both protocols serves both from one process over one loaded database,
replacing a `c-icap` + `clamav` container pair:

```sh
exav --listen clamd://0.0.0.0:3310 --listen icap://0.0.0.0:1344
```

Under the worker pool the ICAP listener runs in its own child of the supervisor,
sharing the loaded database copy-on-write and replaced along with the workers on
a reload, since ICAP connections are keep-alive and would otherwise occupy every
worker. Two `--listen` addresses on the same protocol are refused.

### Socket permissions

The Unix socket is created `0600` (owner only); `?mode=` widens it, as
`LocalSocketMode` does in `clamd.conf`:

```sh
exav --listen 'clamd:///run/exav.sock?mode=660'
```

A milter, MTA or web server under another UID needs it; prefer a shared group
(`660`) to `666`. The mode is octal, a value that is not a workable mode is
refused, and the socket is created with no permissions and given its mode
immediately, whatever the umask.

### Sending a file the daemon cannot open

`--connect` with paths makes exav a `clamdscan`-style client. By default it sends
paths, which the daemon opens itself; `--send-as` sends the file instead:

| Command | What goes over the socket |
|---|---|
| `exav --connect /run/exav.sock /data` | `SCAN <path>`: the daemon opens the file |
| `exav --connect /run/exav.sock --send-as fd /data` | `FILDES`: an open descriptor, over `SCM_RIGHTS` |
| `exav --connect /run/exav.sock --send-as contents /data` | `INSTREAM`: the bytes |
| `exav --connect scanner:3310 --send-as contents /data` | `INSTREAM`, the only one that crosses hosts |
| `cat file \| exav --connect /run/exav.sock -` | `INSTREAM`, reported as `stdin` |

`fd` is the cheapest (no copy) and needs a Unix socket; asking for it over TCP is
refused rather than falling back to the path. `contents` works anywhere. Both
send the parts of a byte-split archive together (`EXINSTREAM MULTI`) so the
archive is scanned whole; by path, the same job is a `CONTSCAN` of the directory.

A client walks a directory itself in every mode and sends one request per file,
so `--exclude`, `--exclude-dir`, `--include`, `--files-from` and `--no-recursive`
apply, and every request has one reply.

The daemon scans under the configuration it was started with, so a limit, a
`--detect` list or a `--passwords` pool given with `--connect` is refused rather
than silently dropped:

```sh
exav --connect /run/exav.sock --max-input-bytes 1M /data
# exav: --connect hands each file to the daemon, which scans it under the
#       configuration it was started with, so a client cannot apply
#       --max-input-bytes
```

A client keeps what it does itself: which paths, what is printed and where
(`--quiet`, `--verbose`, `--json`, `--log`, `--bell`, `--all-matches`,
`--send-as`). Variables are exempt: `EXAV_MAX_INPUT_BYTES` in an image that also
runs clients is a default for its daemon.

### ICAP server

An `icap://` address serves [RFC 3507](/guides/icap/) in place of a `c-icap`
container. These tune it; none of them binds anything.

| Flag | Default | Description |
|---|---|---|
| the path of the `--listen` address | `avscan`, `srv_clamav`, `virus_scan` | Service name to answer on (`icap://host:1344/avscan`). Naming one replaces the defaults; `?service=a&service=b` names several. See [address options](#what-belongs-to-one-listener). |
| `--icap-preview-bytes <N>` | `4096` | Bytes advertised in the `Preview` header. |
| `--icap-transfer-preview <PATTERN\|off>` | `*` | `Transfer-Preview` value; `off` omits the header. |
| `?max-connections=` on the address | `100` | Concurrent connections, also advertised as `Max-Connections`. |
| `--icap-options-ttl-secs <SECS>` | `3600` | How long a client may cache the `OPTIONS` answer. |
| `--icap-max-requests <N>` | `100` | Requests served on one connection before it is closed. |
| `--icap-idle-secs <SECS>` | `600` | How long an idle connection is held open. |
| `--icap-max-header-bytes <N>` | `65536` | Largest ICAP head plus encapsulated HTTP headers. |
| `--icap-infection-header <WHEN>` | `blocks` | Which blocks carry `X-Infection-Found`: `blocks` (every one; a `PARTIAL` verdict under `Heuristics.Exav.*`) or `detections` (a signature match only). |

There is no ICAP-specific size ceiling: the same `--max-input-bytes` and spill
budgets apply as for a clamd client, so a file gets the same verdict on either
port.

## ClamAV compatibility

| Flag | Description |
|---|---|
| `--clamav-compat` | Preset: `--max-input-bytes 100M --max-extracted-bytes 400M --max-unpack-depth 17 --max-members 10000 --decode none --partial-as ok`, plus the extractor set of stock ClamAV and ClamAV's naming where the two engines name the same fact differently. For differential testing only: it reduces detection on purpose. |

Each preset value can be set on its own, and an explicit flag wins over the
preset. The preset leaves `--max-object-bytes`, `--max-matcher-bytes`,
`--max-pe-emulation-steps`, the spill settings, `--detect`/`--no-detect`,
passwords and update, network and worker settings on exav's defaults. The
narrower extractor set and the `.UNOFFICIAL` naming have no flags of their own.

For the complete `clamscan` / `clamd` / `clamdscan` surface against exav's, see
the [ClamAV flag matrix](/reference/clamav-flag-matrix/).

## Exit codes

`0` `OK`, clean; `1` `FOUND`, a detection; `2` `ERROR`, exav could not do its job;
`3` `PARTIAL`, something could not be fully examined (`LIMITS-EXCEEDED`,
`UNSCANNABLE` or `PASSWORD-PROTECTED`), unless `--partial-as` says otherwise. See
[Verdicts & exit codes](/reference/verdicts/).
