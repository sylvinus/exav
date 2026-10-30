---
title: Sizing a server
description: What to set on a 4 GiB machine running exav as a clamd or ICAP server, and how each flag divides the memory.
---

A worked example: one machine with 4 GiB of RAM and 40 GB of free disk for
temp files, serving the clamd protocol (and optionally ICAP) with the full
official database. The database figures were measured with the official
`main`, `daily` and `bytecode` databases of September 2026 (3.6 million
signatures); a later database is somewhat larger. The limits that follow from
them are worked out by exav at every start and printed in its log.

## The short answer

```sh
exav --listen /run/clamav/clamd.ctl \
     -d /var/lib/exav/official.exavdb \
     --workers 2 \
     --max-process-bytes 818M \
     --max-object-bytes 204M \
     --max-extracted-bytes 311M \
     --max-bytecode-memory-bytes 204M \
     --object-cache-bytes 8M \
     --spill-threshold-bytes 16M \
     --spill-dir /var/cache/exav \
     --max-spill-bytes 4G --max-total-spill-bytes 12G
```

Each memory setting says how much one thing may hold, and the numbers add up
to the machine ([where they come from](#where-the-4-gib-goes)):

| Flag | Value | What it bounds | Where the value comes from |
|---|---|---|---|
| `--workers` | 2 | Scans at once | The memory left after the database, shared between them |
| `--max-process-bytes` | 818M | Everything one scan holds, as address space | (4096 MiB − a third kept for the system − the 1094 MiB database) / 2 workers |
| `--max-object-bytes` | 204M | The largest object held whole; a larger one is read through a block cache or a spill file | A quarter of the scan's memory: matching may also need an image decoded from the object and its grey copy, each as large again |
| `--max-extracted-bytes` | 311M | What formats that decode a member whole have produced, added up over the scan | What is left after those two copies, a 16 MiB lowercase copy and a tenth to spare: 818 − 2 × 204 − 16 − 82 |
| `--max-bytecode-memory-bytes` | 204M | What one run of a bytecode signature holds | A quarter of the scan's memory |
| `--object-cache-bytes` | 8M | The block cache of each object read in place | The default; an eighth of the scan's memory at most. More fetches an object less often |
| `--spill-threshold-bytes` | 16M | What a stream holds in RAM before it goes to disk | The default; each connection holds this much |

exav checks each of them against the machine at startup and only ever lowers
one that does not fit, never raises one.

The disk settings come from the 40 GB. The spill directory must exist (exav
refuses to start otherwise) and be writable by the daemon. The packaged unit
makes the filesystem read-only, so add `CacheDirectory=exav` with
`systemctl edit exav`, which creates `/var/cache/exav` for the unit's user.

- `--max-total-spill-bytes 12G` is per process, and three processes spill here:
  the two workers, and the ICAP child once [ICAP is added](#adding-icap).
  Keeping 4 GB spare, 36 GB over three is 12 GB each. The default, 8 GB per
  process, would let the three use 24 GB.
- `--max-spill-bytes 4G` is the most one stream or one member may take. A text
  member also needs its normalised views beside it, which came to more than the
  member again in the [measurements below](#archives-past-the-spill-ceiling), so
  4G keeps a member and its views inside 12G. exav refuses to start with a total
  below `--max-spill-bytes`.

Leave the memory flags out and exav works out the same values on this machine
and prints them at startup, which is how the figures above were found:

```text
exav: per-job memory 2048 MiB x 2 workers exceeds what this host can back; using 818 MiB per job (two thirds of RAM, less the 1094 MiB shared database, over the workers). ...
exav: of the 818 MiB of memory a scan gets, it may hold 311 MiB at once and 204 MiB in one object, so a size limit is reported rather than the scan being killed for hitting one
exav: prefork daemon: 2 workers; per-job limits: wall 120s, mem 818 MiB, cpu 120s; recycle every 1000 jobs
```

In a container, the RAM exav divides is the container's memory limit, not the
host's.

## Where the 4 GiB goes

exav divides the RAM it sees (4096 MiB here) once the database is loaded:

| Part | Size here | Set by |
|---|---|---|
| Kept for the kernel, page cache and everything else | a third of RAM: 1365 MiB | fixed |
| The signature database, loaded once and shared by every worker | 1094 MiB: the process's address space once the database is loaded, about 800 MiB of it resident | the database |
| One scan per worker | the rest over `--workers`: (4096 − 1365 − 1094) / 2 = 818 MiB each | `--workers`, `--max-process-bytes` |
| Streams waiting to be scanned | 16 MiB each in RAM, then on disk | `--spill-threshold-bytes`, `--spill-dir` |

The RAM is the total the machine (or the container's limit) has, read once at
startup, not what is free at that moment: `MemAvailable`, the page cache and
pages still being written after a database download play no part, so starting
right after a fetch changes nothing, and neither does a restart. Adding RAM
raises the figures at the next start. On a host of 8 GiB (7940 MiB) with a
2123 MiB database and two workers, each gets (7940 − 2647 − 2123) / 2 = 1585
MiB, and one scan may hold at most about 619 MiB of extracted data, 396 MiB
in one object (worked out below). If
that is too little for the largest files you scan, give the host more RAM or
run one worker: the figures are the scan's, not a guess about what is free.

The database is counted at its address space rather than what is resident,
because the address space is what each worker's kernel limit (`RLIMIT_AS`)
counts. Workers are forked after it loads and share it copy-on-write, so two
workers do not cost two databases. A prefork pool of N workers shows N+1
processes of about 0.8 GB resident each in `top`; the real total is one
database plus what the scans use (the `Pss` line of `/proc/<pid>/smaps_rollup`
shows each process's share).

Within one scan's 818 MiB, the second line of the log divides again. One
object may take a quarter, 204 MiB, because matching it may also need an image
decoded from it and that image's grey copy, each as large again. What the scan
holds in all is what is left after those two copies, a 16 MiB lowercase copy
used for case-insensitive matching, and a tenth to spare:
818 − 2 × 204 − 16 − 82 = 311 MiB.

## What this host scans, and what to change to scan more

With the command above (2 workers, 818 MiB a scan, 4 GiB for one stream or member and 12 GiB of spill per process),
by kind of input:

| Input | Scanned in full | Past that | To go further |
|---|---|---|---|
| A file on disk, an `http(s)://` object | Any size. Up to 204 MiB it is held whole; larger, it is read through an 8 MiB block cache | A PE, ELF or .NET file is not parsed, so the signatures and rules on its structure are not evaluated, and RAR, OLE, PDF and the other [formats read whole](/scanner/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole) are not opened. Either is `LIMITS-EXCEEDED` if nothing is found | `--workers 1` gives a scan 1637 MiB, and one object 409 MiB. Beyond that, more RAM |
| Members of ZIP, tar, 7z, CAB, ISO, the compressors and the other formats decoded as read | Each member up to 4 GiB: held up to 204 MiB, and past that written to disk. All of them together up to 10 GiB fed to the matcher | A member over 4 GiB is not scanned. An archive past 10 GiB is scanned as far as that | `--max-spill-bytes` (disk for one member), `--max-total-spill-bytes` (disk for all of a process's), `--max-matcher-bytes` (the 10 GiB, a time bound) |
| Members that have to be decoded whole: encrypted ZIP members, RAR, OLE and PDF streams, installers, files a filesystem stores compressed | 311 MiB added up over one scan, 204 MiB in one object | `LIMITS-EXCEEDED`, naming the limit | `--workers 1` raises them to 640 MiB and 409 MiB; `--max-process-bytes` sets the memory a scan gets. `--max-extracted-bytes` and `--max-object-bytes` only lower what that memory allows |
| A stream: `INSTREAM`, an ICAP body, stdin | The first 4 GiB, 16 MiB of it in RAM and the rest on disk | The first 4 GiB is scanned and the stream is `LIMITS-EXCEEDED` | `--max-spill-bytes`, `--max-total-spill-bytes` and the disk under `--spill-dir` |
| A bytecode signature | 204 MiB held by one run | The run stops, the scan says so | `--max-bytecode-memory-bytes`, itself capped at a quarter of a scan's memory |

Scanning a file or object past 204 MiB is slow rather than limited: it is read
from its source several times over. Over a network each read is a request, and
`--object-cache-block-bytes`, `--object-cache-bytes` and `--http-request-bytes`
set how many. The [block cache](/scanner/concepts/streaming-memory/#the-block-cache)
page explains the model and shows what each setting did against a slow server.

Measured on this configuration over HTTP, against a local server that makes up
each object from its offset, so there was nothing to download and no disk to
fill: a 20 GB object of text, RAR, OLE or PDF magic, held between 50 and 61 MB at
its peak, and took from 2 to 21 minutes (the server answers at several GB/s, so
this is the scan's own time). Archives holding one 20 GB member (ZIP, tar, gzip)
peaked near 260 MB and, with the default 2 GiB spill ceiling, were reported
`LIMITS-EXCEEDED` for the member, as was a small PE followed by 20 GB (19
minutes, 258 MB). Raising the limits scans a member that size,
as [the next measurements](#archives-past-the-spill-ceiling) show.

### Archives past the spill ceiling

A ZIP, a tar and a gzip, each holding one 5 GB text member (same server, same
818 MiB scan), with `--max-matcher-bytes 30G` and `--max-spill-bytes` raised so
that the member fits:

| `--max-total-spill-bytes` | Result | Time | Peak memory |
|---|---|---|---|
| 6G | The member was scanned, but not its normalised text views: `LIMITS-EXCEEDED PARTIAL`, `no room in the 6 GiB process-wide spill budget` (all three formats) | 189 to 257 s | 261 to 269 MB |
| 12G | tar: `OK` | 226 s | 272 MB |

A text member is written to disk once as it is decoded, and its normalised
views, which are as large as it is, are written beside it. Give the spill
directory the member's size several times over, and set both
`--max-spill-bytes` and `--max-total-spill-bytes` to it. Memory does not grow
with the member: 270 MB is one 204 MiB object and the block caches.

## The flags, in the order to decide them

1. **The database.** Load a prebuilt `.exavdb` (`-d file.exavdb`), not the raw
   `.cvd` files: from raw files exav builds the signature index at every start
   and reload, which takes longer and more memory than loading a prebuilt one
   (see [what it costs](/scanner/guides/prebuilt-database/#what-it-costs)). Build the
   `.exavdb` on another machine, or on this one while nothing is served. A
   reload loads the new database next to the old one, and the old workers keep
   theirs until they finish their jobs (up to `--max-scan-secs` plus 5 seconds),
   so leave room for a second copy for that long, or schedule reloads for quiet
   hours.

2. **`--workers`**, how many scans run at once. Each takes a share of what is
   left after the database: 1637 MiB here, so 2 workers get 818 MiB each and
   4 workers 409 MiB. Fewer workers means larger files are held whole and more
   scans wait; more workers means more concurrency and smaller files held. On
   this machine, 2 is the balance for mail or upload scanning. The default is one
   per CPU core.

3. **`--max-process-bytes`**, the memory one scan may use. Left unset, it is 2 GB
   lowered to the share above, which is the right value. Set it lower to leave
   room for another service on the same machine. One object is kept to a
   quarter of it and what a scan holds in all to a little over a third (204 and
   311 MiB here, [worked out above](#where-the-4-gib-goes)). A larger object is
   scanned through a block cache or a spill file instead of being loaded, or
   reported `LIMITS-EXCEEDED`.

4. **`--max-object-bytes`**, the largest object held whole (default 256 MiB).
   exav lowers it to that quarter when it is larger, so there is nothing to set.
   Raise `--max-process-bytes` rather than this one when a large container is
   reported `LIMITS-EXCEEDED` and the machine has room.

5. **Spill**, for streams (`INSTREAM`, ICAP bodies). Each connection holds up to
   `--spill-threshold-bytes` (16 MiB) in RAM, and the rest on disk. Point
   `--spill-dir` at a filesystem with room. `--max-total-spill-bytes` is per
   process, and every worker and the ICAP child counts separately, so set it to
   what the disk can spare divided by the number of processes, and no lower
   than `--max-spill-bytes`: 12G each above lets the 2 workers and the ICAP
   child use 36G together. Do not leave it on a small `/tmp` held in RAM (`tmpfs`),
   which is memory again.

6. **`--max-input-bytes`**, if the clients should not send anything larger. The
   default is no limit: a large file is scanned through a block cache and costs
   time rather than memory. A mail gateway can set its own attachment limit
   here.

## Adding ICAP

An `icap://` listener next to the clamd one runs in one more child process,
sharing the same database. It scans in threads, one per connection (up to 100 by
default), with no `--max-scan-secs` and no `RLIMIT_AS` (see
[Limits](/scanner/reference/limits/)). Each scan may hold what a worker's scan may (311
MiB here), plus up to `--spill-threshold-bytes` of buffered body. Most scans hold
far less, but the worst case is that times the number of connections, so on a
4 GiB machine bound them with `?max-connections=` on the address:

```sh
exav --listen /run/clamav/clamd.ctl \
     --listen 'icap://0.0.0.0:1344?max-connections=4' \
     -d /var/lib/exav/official.exavdb \
     --workers 2 \
     --max-process-bytes 818M \
     --max-object-bytes 204M \
     --max-extracted-bytes 311M \
     --max-bytecode-memory-bytes 204M \
     --object-cache-bytes 8M \
     --spill-threshold-bytes 16M \
     --spill-dir /var/cache/exav \
     --max-spill-bytes 4G --max-total-spill-bytes 12G
```

The only way to lower what one scan holds is a smaller `--max-process-bytes`,
which applies to the workers too.

## If it is still too much

- **`--workers 1`**: one scan at a time, with the most memory each.
- **`--workers threads`** runs every scan in one process, with no way to stop
  one runaway scan without stopping all of them; `--max-process-bytes` then
  caps the whole process, database included.
- **A smaller database.** Most of the memory is `main` and `daily`; dropping the
  `bytecode` database saves little. Third-party feeds add to it.

See [Limits and tuning](/scanner/reference/limits/) for every bound, and
[Daemon mode](/scanner/guides/daemon/#worker-pool-and-per-job-limits) for the pool.
