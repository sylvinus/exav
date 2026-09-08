---
title: CLI reference
description: Every exav command-line flag — targets, scanning limits, output, listeners, and the ClamAV-compatibility preset.
---

`exav [OPTIONS] [PATH]...`

Scan `PATH`(s) — files or directories — for malware. Use `-` for stdin. An
`http(s)://` target is scanned over range requests (needs a `http-scan` build).
With no `-d`/`--sigs-dir` and no real signatures loaded, exav refuses to run
unless `--allow-no-db`.

Run `exav --help` for the authoritative list; this page mirrors the clap
definitions.

## How a setting is decided

**An explicit flag wins, then the environment variable, then the default.** One
rule, every setting, no exceptions: a flag is never refused because a variable is
set, and a variable never overrides a flag. That is what lets a container image
carry its configuration in the environment while any single value stays
overridable on the command line.

Every flag on this page has an `EXAV_*` variable, spelled from the flag: uppercase,
dashes to underscores, `EXAV_` in front. `--max-input-bytes` reads
`EXAV_MAX_INPUT_BYTES`, `--send-as` reads `EXAV_SEND_AS`. `exav --help` prints the
`[env: …]` line under each one. [Configuration](/reference/configuration/) has the
table the other way round, plus the variables with no flag.

A boolean variable takes `1`/`yes`/`on`/`true` or `0`/`no`/`off`/`false`.
Anything else stops the run rather than being read as "off" — a typo that silently
disables a setting is one an operator has no way to see.

## Targets, filters and logging

| Flag | Description |
|---|---|
| `PATH...` | Files or directories to scan. `-` reads stdin. A named directory is scanned **recursively**. |
| `--no-recursive` | Scan only the files directly inside a named directory, not its subdirectories. |
| `--files-from <FILE>` | Read paths to scan from `FILE`, one per line. `-` reads the list from stdin. Blank lines and `#` comments are skipped, and the paths merge with any given on the command line. |
| `--exclude <REGEX>` | Skip files whose path matches (repeatable). |
| `--exclude-dir <REGEX>` | Skip directories whose path matches (repeatable). |
| `--include <REGEX>` | Only scan files whose path matches (repeatable). |
| `--bell` | Sound a bell on detection. |
| `--log <FILE>` | Append every result line to `FILE` as well as stdout. Opened before scanning starts, so a bad path fails immediately rather than after a long scan. |

Recursion is the default because naming a directory and getting some of it is
the kind of surprise that reads as a clean result: the files that were never
opened are indistinguishable, in the output, from files that were and were fine.

`--log` is an *addition*, never a redirection: stdout still gets every line, so
pipes keep working and a log that cannot be written can never swallow a
detection.

On a listener the same flag records what the daemon answered — one line per scan
verb (`SCAN`, `CONTSCAN`, `INSTREAM`, `FILDES`, …), the daemon's own view of the
target, so a streamed scan is logged as `stream:` and a passed descriptor as
`fd:`. The daemon's results otherwise go to the client and nowhere else, which
makes this the operator's only record of them. `PING`, `VERSION` and `STATS` are
answers about the daemon rather than about a file and are not logged.

### `--files-from` and the daemon

The list is expanded before the scan mode is chosen, so it behaves the same for a
local scan and for a `--connect` client scan. One protocol detail: paths are sent
to the daemon **as paths**, so the daemon's filesystem has to be able to see them
(`SCAN` semantics, same as `clamdscan`). If the daemon is remote or in a container
that does not mount your files, send the *contents* instead — see
[`--send-as`](#sending-a-file-the-daemon-cannot-open).

## Signature sources

| Flag | Default | Description |
|---|---|---|
| `-d`, `--database <PATH>` | — | Load signatures from a FILE or DIR (`.ndb`/`.hdb`/`.cvd`/… or a prebuilt `.exavdb`). A DIR is scanned recursively. |
| `--sigs-dir <DIR>` | `/var/lib/exav` | The directory signatures **live in** — the one `--auto-update` writes into and a sidecar populates. |
| `--sig-sources <FILE>` | — | File of signature source URLs (also reads `freshclam.conf` source directives). |
| `--allow-no-db` | off | **Testing only.** Run against the built-in EICAR-only baseline when no real database is present, instead of refusing. |
| `--build-db <FILE>` | — | Compile loaded signatures into a prebuilt `.exavdb` and exit. |
| `--build-shard-bytes <SIZE>` | — | Cap the per-shard automaton-build transient (`--build-db` only). |

`-d` and `--sigs-dir` are not two spellings of one thing. `--sigs-dir` names a
*directory that is written to*, so it stays a directory even when `-d` points the
load somewhere else — which is how a deployment serves a prebuilt `.exavdb` from
one path while an updater keeps a signature directory current at another.

## Signature lifecycle

`--auto-update` is what keeps the signature source current for as long as the
process runs. It is a capability, not a mode: add it to a listener or to a
one-shot scan that should fetch before it scans.

It does four things, each of which is a way a deployment otherwise ends up
serving nothing:

1. creates the signature directory and **fetches every configured source before
   the first load**, so the first request is answered from real signatures;
2. where a sidecar owns the directory instead, **waits `--startup-wait-secs`**
   for it to appear rather than coming up blind;
3. **re-checks the sources every `--update-interval-secs`** — floored at 60
   seconds, however low the number — and hot-reloads on every change;
4. pulls a prebuilt `.exavdb` from `--db-url` as an alternative to fetching
   signature files, with the same change detection and reload.

Serving with no real signatures is refused in every case (see `--allow-no-db`),
including on a reload: an emptied volume keeps the database already loaded rather
than downgrading a running scanner to near-zero coverage.

| Flag | Default | Description |
|---|---|---|
| `--auto-update` | off | Bootstrap, refresh and hot-reload the signature source. Fetching needs a `http-update` build; Unix only. |
| `--sig-sources <URL\|FILE>` | — | Where to fetch from. Repeatable; the sources merge. |
| `--db-url <URL>` | — | A prebuilt `.exavdb` to pull and serve *instead of* signature files. |
| `--startup-wait-secs <SECS>` | `1800` with `--auto-update`, `0` otherwise | How long to wait for a sidecar to populate an empty signature directory. `0` does not wait. |
| `--update-interval-secs <SECS>` | `86400`, or `300` with `--db-url` | Seconds between source re-checks. |

`--auto-update` with **no `--listen` and no paths** is the updater half of a
two-container deployment: it keeps the signature volume current for whoever
serves it and loads no database of its own. That is inferred rather than declared,
so a command line cannot ask to update and to serve and mean neither.

### `--sig-sources` reads three shapes from one value

Which of them a value is, is legible from the value — so there is one flag rather
than one per shape, and no way to classify a URL wrongly and get a silently inert
setting:

| Value | Read as |
|---|---|
| `https://host/main.cvd` | an exact source, fetched verbatim |
| `https://host/db/` | a **mirror base** — the trailing slash makes it one — expanding to `<base>/{main,daily,bytecode}.cvd` |
| `/etc/exav/sources` | a file of the above, one per line (`#` comments OK), **or a `freshclam.conf`** |

Anything that is not an `http(s)` URL is a path; that is the same rule `--listen`
uses to tell a socket path from a `host:port`. Pointed at a real `freshclam.conf`,
exav reads its *source* directives (`DatabaseMirror`/`PrivateMirror`,
`DatabaseCustomURL`) and warns about every line it ignores — including
`DatabaseDirectory`, which is `--sigs-dir` and not a source.

No source is privileged: every URL is fetched the same way, over plain HTTPS with
**no signature verification**. Point it at a mirror you trust, or use
`freshclam` / `cvd` and let exav hot-reload the directory. Naming a source
without `--auto-update` is reported rather than silently ignored.

The re-check cadence for `--db-url` defaults to 300 seconds rather than a day
because that check is a conditional `HEAD` which transfers nothing when the
database has not moved. It is the same `--update-interval-secs` either way: how
often exav re-checks is one question, and the default follows from how expensive
the check is.

## Scan limits

All sizes accept `K`/`M`/`G`/`T` suffixes, and `0` means **no limit** on every one
of them. See [Configuration](/reference/configuration/) for how each maps to an
engine budget.

| Flag | exav default | `--clamav-compat` | Description |
|---|---|---|---|
| `--max-input-bytes <SIZE>` | unlimited | `100M` | Largest top-level input scanned. Over it → `LIMITS-EXCEEDED`. |
| `--max-extracted-bytes <SIZE>` | `256M` / `1G` | `400M` | What decompression may *produce* across one top-level file: the flag sets deep-analysis size and summed extracted bytes to one value; unset they keep their own defaults. |
| `--max-object-bytes <SIZE>` | `256M` | — | The most memory a **single** materialized object may use. It bounds one buffer: several are live at once across nesting levels, and `--max-extracted-bytes` bounds their sum. |
| `--max-matcher-bytes <SIZE>` | `10G` | — | Cumulative scan-reach (CPU/time) bound, decoupled from memory. Raising it scans larger members in full, paying only in time. |
| `--max-unpack-depth <N>` | `16` | `17` | Max nesting depth for recursive unpacking. |
| `--max-members <N>` | `100000` | `10000` | Max members visited across the whole recursive walk. Higher than ClamAV's default on purpose: exav descends into nested archives ClamAV does not, so it counts strictly more objects for the same file. |

Each bound has exactly one spelling. `clamscan`'s names (`--max-filesize`,
`--max-scansize`, `--max-files`) are **not** hidden aliases for them: a clamscan
flag exav does not have stops the run rather than being swallowed, so a migrated
command line never scans under settings nobody asked for. The mapping is in the
[ClamAV flag matrix](/reference/clamav-flag-matrix/).

### Buffering a stream (spill)

Container-aware scanning needs to **seek** — a ZIP's directory is at its end — so
every streaming surface (`INSTREAM`/`EXINSTREAM`, stdin, an ICAP body)
materialises what it receives before scanning it. Small objects stay in RAM;
larger ones go to a temp file. These bound that, and apply to every surface
alike.

| Flag | Default | Description |
|---|---|---|
| `--spill-dir <DIR\|off>` | platform temp dir (`$TMPDIR`) | Where the temp files go, or `off` to never write one at all. Point it at a filesystem with room, and one you are willing to see fill up. |
| `--spill-threshold-bytes <SIZE>` | `16M` | Bytes held in RAM before an object spills. **This is what bounds a listener's memory**: a connection costs this much whatever the object on it weighs. |
| `--max-spill-bytes <SIZE>` | `2G` | The most temp space **one** object may occupy. clamd's `StreamMaxLength`. |
| `--max-total-spill-bytes <SIZE>` | `8G` | The most temp space every in-flight object may occupy **together**, across the process. |

The last one is the one a per-object cap cannot stand in for: a hundred
connections at `2G` each is a 200 GB worst case, and filling the temp filesystem
is a denial of service against the *host* — one that outlives the connection
causing it and takes down everything else sharing that filesystem. Size it
against the free space on `--spill-dir`, not against the object size you expect.

The sizes nest — RAM inside one object inside the process — and exav refuses to
start if they don't, rather than letting the contradiction surface as a verdict
in production.

An object a budget refuses is `UNSCANNABLE`: never clean, and never a dropped
connection. Running out of room must not cost a client its answer, because a
client with no answer decides for itself.

#### Turning it off

```sh
exav --listen icap://0.0.0.0:1344 --spill-dir off --spill-threshold-bytes 64M
```

Nothing is written to disk, ever: `--spill-threshold-bytes` is then simply the
largest object exav will take, and anything above it is `UNSCANNABLE`. Use it for
a read-only root filesystem, a container with no writable temp directory, or a
deployment that would rather refuse a large object than let a scanned payload
touch a disk at all. Budget the memory as threshold × concurrent scans.

Turning it off is `--spill-dir off` and not a `0`, deliberately. `0` on the two
`--max-` flags reads as "no ceiling", the way it does on `--max-input-bytes` and
every other size flag here — a number that meant "none allowed" on one flag and
"unlimited" on its neighbours is how an operator ends up with the exact opposite
of what they configured. Since `--spill-dir off` describes a disk nothing will be
written to, passing it together with `--max-spill-bytes` is refused rather than
silently resolved.

## Detection

| Flag | Default | Description |
|---|---|---|
| `--detect <LIST>` | `none` | Heuristic detectors to switch on, over and above the signature database: `none`, `all`, or a comma-separated list of `heuristics`, `macros`, `broken`, `broken-media`, `partition-intersection`, `phishing`, `packed`, `pua`. |
| `--base64 [<on\|off>]` | on | Decode base64-encoded executables embedded in text/script files. Off under `--clamav-compat`, which has no such reach; an explicit value wins over the preset. |
| `--passwords <PW>` | — | Password to try when decrypting encrypted archive members. Repeatable (comma-separated in the environment) to build a pool, tried in order, unioned with any `.pwdb` databases. |
| `--alert-credit-cards <N>` | off | Alert `Heuristics.Structured.CreditCardNumber` on a textual file holding N or more valid credit-card numbers. Needs the `dlp` feature. |
| `--alert-ssns <N>` | off | Alert `Heuristics.Structured.SSN` on N or more valid US Social Security numbers. Needs the `dlp` feature. |

The two `--alert-` flags are leak detectors rather than malware ones — what they
find is the organisation's own data on its way somewhere — which is why they are
not values of `--detect`.

One detector list rather than a switch per detector: a boolean each cannot say
"all of them" without the reader already knowing the whole set.

### What an unscannable object becomes

`--detect` says what to *look for*. What happens to an object exav could not
fully examine is a different question, and `--partial-as` is the only flag
that answers it.

The value **is** the status it reports as, and each status is one exit code — so
the value names the code you get, with nothing to look up:

| Value | Status | Exit | Effect |
|---|---|---|---|
| `partial` *(default)* | `PARTIAL` | 3 | The verdict stands, under its category. A clamd `ERROR` reply, an ICAP block. |
| `ok` | `OK` | 0 | Deliver it as clean. An ICAP `204`. |
| `found` | `FOUND` | 1 | Report it as a detection named `Heuristics.*` — an ordinary hit to any client, and what ClamAV's `--alert-exceeds-max` / `--alert-encrypted` produce. |
| `error` | `ERROR` | 2 | Report it as an operational failure, for a caller that would rather not learn a fourth exit code. |

It also takes a per-category list — `--partial-as
password-protected=ok,limits-exceeded=found` — over the three categories
`limits-exceeded`, `unscannable` and `password-protected`.

`ok` is what ClamAV does for an encrypted archive and what `c-icap` does past
`MaxObjectSize`. It is a real trade rather than a mistake, and exav will not make
it quietly: **every such object is logged**, and the listener says so at startup.

`--clamav-compat` implies `--partial-as ok`, because that is what a stock ClamAV
build answers for this whole class. An explicit value still wins over the preset.

Refused together with `--connect`: the policy belongs to whatever does the
scanning, and a client only ever sees the reply the daemon already decided.

On the clamd wire, `partial` and `error` are both an `ERROR` reply. That
protocol's vocabulary is `OK`/`FOUND`/`ERROR`, and a real `clamdscan` reads a
word outside it as `OK` — a fail-open exav will not risk. They differ only where
there is an exit code to differ in.

## Output

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Print informational findings (type, entropy, imphash, ML score). In client mode those come from the local scanner and a daemon reply carries only a verdict, so it names the daemon that answered and the command sent per target instead. |
| `--quiet` | Print only errors and detections: no per-file `OK` lines, no summary. The single output dial, with `-v` at the other end. |
| `--json` | Newline-delimited JSON, one object per input, plus a final summary object. |
| `--all-matches` | Report every matching signature, not just the first. |

## Finding where the CPU went

A one-shot scan can be timed from outside. A listener cannot: it is a long-lived
process serving objects nobody kept, so "the box is at 100% CPU" is all you get
unless the process counts for itself. These are how it does.

| Flag | Default | Description |
|---|---|---|
| `--profile` | off | Measure where scan time goes, per matcher. Scanning files it replaces the output with a CSV row per file; on a listener the same numbers accumulate and come back as `MATCHERSTATS`. Off by default: it times every matcher invocation, and there are many per scan. |
| `--slow-scan-secs <SECS\|off>` | `10` | Log any scan taking longer, naming the object and (with `--profile`) where its time went. |
| `--metrics-secs <SECS\|off>` | `300` | Seconds between the scan-totals lines a listener writes to its log. Silent while nothing is being scanned. |

Scan counts, bytes and wall time are **always** collected — one clock read per
scan — so a listener can always say how busy it is. Only the per-matcher
breakdown is opt-in.

Three ways to read them:

**On demand**, over the clamd protocol, which is also what `clamdtop` polls:

```console
$ printf 'zSTATS\0' | nc 127.0.0.1 3310
…
SCANSTATS: scans 3 bytes 20135159 scan-seconds 5.435 mean-ms 1811.617
  slowest-ms 5382.013 throughput-MBps 3.7 in-flight 0 slow 0 infected 1 partial 0
MATCHERSTATS: engine=2278.692ms/7calls/60405341b normalize=566.013ms/4calls/40270182b
END
```

**In the log**, every `--metrics-secs`. This is the channel every arrangement
has: an ICAP-only deployment binds no clamd port to ask `STATS` on, so for a
container `docker logs` is the answer.

**Per slow object**, which is the one that names names:

```
exav: slow scan: 5.295s for 20000000 bytes of http://host/_matrix/media/v3/upload/big.bin
  [engine 2253.1ms, normalize 596.4ms, bytecode 0.0ms]
```

**Under the worker pool the numbers are per process.** A clamd listener with
`--workers N` forks a scan pool, and ICAP gets a child of its own. Counters are
per process, so a `STATS` reply describes the worker that answered it — not the
pool. The log lines cover every process. For one set of totals across both
listeners, run the thread model (`--workers threads`).

`--max-scan-secs` is a different thing and is **refused** under `--workers
threads`: it means "kill the job", and only the prefork pool can do that. There a
scan is bounded by work rather than time — `--max-matcher-bytes` is the
per-object CPU bound, with `--max-unpack-depth` and `--max-members`.

## Serving and connecting

Two flags decide what the binary does, and the **direction is the flag**:
`--listen` accepts connections, `--connect` makes one. Paths with neither scan
locally. See the [daemon guide](/guides/daemon/) for the full model, and
[One binary, three roles](/guides/migrating-from-clamav/#one-binary-three-roles)
for the `clamd` / `clamdscan` mapping.

Both take the same address grammar, with the protocol in the value:

```
clamd://0.0.0.0:3310         the clamd protocol over TCP
clamd:///var/run/exav.sock   the clamd protocol over a Unix socket
icap://0.0.0.0:1344          ICAP (RFC 3507), for a proxy's adaptation hook
icap://0.0.0.0:1344/avscan   ICAP answering on that service only
0.0.0.0:3310                 no scheme — clamd
/var/run/exav.sock           no scheme, a path — clamd over a Unix socket
```

A leading `/` is a socket path; anything else is `host:port`, optionally
followed by `/<service>` for ICAP. A TCP address without a port is refused rather
than carried to a bind that fails obscurely. Nothing listens without `--listen`,
and there is no default address.

### What belongs to one listener

Some settings belong to *one listener* rather than to the run, so they ride on
its address instead of on a flag. An ICAP service is the URL path; the rest are a
`?key=value` tail:

| On the address | Default | Meaning |
|---|---|---|
| `/avscan` *(the path)* | `avscan`, `srv_clamav`, `virus_scan` | The ICAP service to answer on. Naming one replaces the default set. |
| `?service=a&service=b` | — | Several ICAP services. Repeat the key; a comma separates *addresses*, not names. |
| `?mode=660` | `0600` | Permission bits for a Unix socket. |
| `?max-connections=200` | `128` clamd, `100` ICAP | Concurrent connections this listener accepts. |

```sh
exav --listen 'clamd:///run/exav.sock?mode=660' \
     --listen 'icap://0.0.0.0:1344/avscan?max-connections=200'
```

A flag for any of these would have to say *which* listener it meant: a socket
mode applied to a `host:port` means nothing, a connection cap has to pick a
protocol, and a service name only exists for one of the two. Two listeners would
need two flags, and the one without a flag would be stuck on a constant. On the
address there is exactly one thing each can attach to, so there is nothing to
cross-check and nothing to get wrong. Each is refused where it cannot apply — a
path on a `clamd://` address, a mode on a `host:port` — and an unknown option is
an error rather than an ignored word.

`max-connections` bounds the **clamd** listener only under `--workers threads`;
the prefork pool bounds concurrency by its worker count instead, so a second cap
there would be a setting with nothing to do. ICAP always reads it, and advertises
it to clients as `Max-Connections`.

| Flag | Default | Description |
|---|---|---|
| `--listen <ADDR>` | — | Serve on this address. Repeatable (comma-separated in the environment). |
| `--connect <ADDR>` | — | Scan by handing each file to a daemon already running here, instead of loading a database. |
| `--send-as <WHAT>` | `path` | What a `--connect` client hands the daemon: `path`, `contents` or `fd`. |
| `--ping` | off | Ask a daemon whether it is answering, and exit `0` or `2`. Scans nothing. Probes `--connect` when given, otherwise the listener this same configuration would serve — so a container health check needs no address of its own — and speaks the protocol it finds there: `PING` on clamd, `OPTIONS` on ICAP. One probe; clamdscan's `attempts[:interval]` argument is refused, because retrying belongs to whatever is asking. |
| `--workers <N\|threads>` | CPU cores | Daemon worker model (Unix): a count runs a prefork pool, `threads` runs the listeners in one process. |
| `--max-scan-secs <SECS>` | `120` in the pool, unset otherwise | Unix. Per job in the pool (wall clock, plus CPU time via `RLIMIT_CPU`); the worker is killed on expiry. In a one-shot run it bounds the whole run, which exits 3 saying so — running out of time is a scan that stopped short, not a scanner that failed. Refused for a listener under `--workers threads`. |
| `--max-process-bytes <SIZE>` | `2G` in the pool, unset otherwise | Unix. Address space (`RLIMIT_AS`): per worker in the pool, whole-process in a one-shot run or the thread model. Also lowers the in-core extraction budget to fit inside it. |
| `--max-jobs-per-worker <N>` | `1000` | Prefork only: recycle a worker after this many jobs. |
| `--allow-shutdown` | off | Honour the clamd `SHUTDOWN` command, letting any client that can reach the daemon stop it. |

`SHUTDOWN` is off by default because a scanner that is not running does not
report infected — it reports nothing, and a pipeline that reads "no answer" as
"fine" passes everything.

Naming both protocols serves both **from one process over one loaded database**,
which is what replaces a `c-icap` + `clamav` container pair:

```sh
exav --listen clamd://0.0.0.0:3310 --listen icap://0.0.0.0:1344
```

A full signature set costs seconds and gigabytes to load, and a second container
exists mainly to avoid paying that twice. Under the worker pool the ICAP listener
runs in a dedicated child process of the same supervisor — it shares the warmed
database copy-on-write, and a signature reload re-forks it along with the scan
workers. It gets its own process rather than a pool slot because ICAP connections
are keep-alive and long-lived, and a handful of idle proxy connections would
otherwise occupy every worker.

Two `--listen` addresses on the same protocol are refused: whichever the code
picked first would serve, and the other would appear on the command line while
never being bound.

### Socket permissions

The daemon's Unix socket is its front door: every user the mode admits can submit
scan jobs and read the verdicts. It is created **0600** — owner only — and
`?mode=` on the address is what widens it, the way `LocalSocketMode` does in a
`clamd.conf`:

```sh
exav --listen 'clamd:///run/exav.sock?mode=660'
```

A milter, MTA or web server under another UID needs it; give that set the
narrowest mode it can work with (a shared group, `660`) rather than `666`.

The mode travels with the address rather than living in a flag of its own,
because it is a property of *that socket*: there is nothing else it could be
attached to, so there is nothing to cross-check. It is octal, and a value that is
not a workable mode is refused rather than applied — read as decimal, `666` would
be 0o1232, and a mode granting write to nobody is an outage with a listening
socket in front of it. The socket is created with no permissions and given its
mode immediately after, so it never exists more widely open than asked for,
whatever the process umask.

### Sending a file the daemon cannot open

`--connect` with paths makes exav a `clamdscan`-style client. By default it sends
**paths**, which the daemon opens itself. `--send-as` sends the file instead:

| Command | What goes over the socket |
|---|---|
| `exav --connect /run/exav.sock /data` | `SCAN <path>` — the daemon opens the file |
| `exav --connect /run/exav.sock --send-as fd /data` | `FILDES` — an open descriptor, over `SCM_RIGHTS` |
| `exav --connect /run/exav.sock --send-as contents /data` | `INSTREAM` — the bytes |
| `exav --connect scanner:3310 --send-as contents /data` | `INSTREAM`, the only one that crosses a host |
| `cat file \| exav --connect /run/exav.sock -` | `INSTREAM`, reported as `stdin` |

`fd` is the cheapest of the three (no copy) and needs a Unix socket, since a
descriptor cannot cross a TCP connection — asking for it over TCP is refused
rather than degraded to sending the path, which would scan whatever that path
holds on the daemon's host. `contents` works anywhere. Both send the parts of a
byte-split archive together (`EXINSTREAM MULTI`) so the archive they form is
scanned rather than each fragment alone; by path the same job is a `CONTSCAN` over
the directory, which makes the daemon rejoin them.

A client walks a directory itself in every mode and sends one request per file, so
the filter flags apply to the tree and every request has one reply.

### ICAP server

An `icap://` address serves [RFC 3507](/guides/icap/) as a drop-in for a `c-icap`
container. These tune it; none of them binds anything on its own.

| Flag | Default | Description |
|---|---|---|
| the path of the `--listen` address | `avscan`, `srv_clamav`, `virus_scan` | Service name to answer on — `icap://host:1344/avscan`. Not a flag: it is the path of the URL a proxy is already configured with. Naming one replaces the defaults; `?service=a&service=b` names several. See [address options](#what-belongs-to-one-listener). |
| `--icap-preview-bytes <N>` | `4096` | Bytes advertised in the `Preview` header. |
| `--icap-transfer-preview <PATTERN\|off>` | `*` | `Transfer-Preview` value; `off` omits the header. |
| `?max-connections=` on the address | `100` | Concurrent connections, also advertised as `Max-Connections`. Not a flag — see [address options](#what-belongs-to-one-listener). |
| `--icap-options-ttl-secs <SECS>` | `3600` | How long a client may cache the `OPTIONS` answer. |
| `--icap-max-requests <N>` | `100` | Requests served on one connection before it is closed. |
| `--icap-idle-secs <SECS>` | `600` | How long an idle connection is held open. |
| `--icap-max-header-bytes <N>` | `65536` | Largest ICAP head plus encapsulated HTTP headers. |
| `--icap-infection-header <WHEN>` | `blocks` | Which blocks carry `X-Infection-Found`: `blocks` (every one; a `PARTIAL` verdict under `Heuristics.Exav.*`) or `detections` (a signature match only). |

There is no ICAP-specific size ceiling. An object's fate is decided by the same
`--max-input-bytes` and spill budgets a clamd client's is, so the same file gets
the same verdict on either port.

## ClamAV compatibility

| Flag | Description |
|---|---|
| `--clamav-compat` | Preset: `--max-input-bytes 100M --max-extracted-bytes 400M --max-unpack-depth 17 --max-members 10000 --base64 off`, plus narrowing unpacking to the formats stock ClamAV handles and reporting under ClamAV's vocabulary where the two engines name the same fact differently. **Diff-testing only** — it deliberately reduces detection. |

Each preset value can still be set on its own, and an explicit flag wins over the
preset. Narrowing the format set and appending `.UNOFFICIAL` to unofficial-database
signature names have no flags of their own: both are only ever wanted for a
differential run, so the preset is the whole interface.

For the complete `clamscan` / `clamd` / `clamdscan` surface against exav's, see
the [ClamAV flag matrix](/reference/clamav-flag-matrix/).

## Exit codes

`0` `OK` clean · `1` `FOUND` a detection · `2` `ERROR` exav could not do its job
· `3` `PARTIAL` something could not be fully examined (`LIMITS-EXCEEDED` /
`UNSCANNABLE` / `PASSWORD-PROTECTED`), unless `--partial-as` says otherwise. See
[Verdicts & exit codes](/reference/verdicts/).
