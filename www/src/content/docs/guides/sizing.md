---
title: Sizing a server
description: What to set on a 4 GB machine running exav as a clamd or ICAP server, and how each flag divides the memory.
---

A worked example: one machine with 4 GB of RAM, serving the clamd protocol (and
optionally ICAP) with the full official database. The figures were measured with
exav 0.0.2 and the official `main`, `daily` and `bytecode` databases of June 2026
(3.6 million signatures); a later database is somewhat larger.

## The short answer

```sh
exav --listen /run/clamav/clamd.ctl \
     -d /var/lib/exav/official.exavdb \
     --workers 2 \
     --spill-dir /var/tmp/exav --max-total-spill-bytes 4G
```

Everything else stays at its default, and exav fits the rest to the machine at
startup:

```text
exav: per-job memory 2048 MiB x 2 workers exceeds what this host can back; using 692 MiB per job (two thirds of RAM, less the 1346 MiB shared database, over the workers). ...
exav: a scan may hold at most 346 MiB (half the 692 MiB of memory it gets), so a size limit is reported rather than the scan being killed for hitting one
exav: prefork daemon: 2 workers; per-job limits: wall 120s, mem 692 MiB, cpu 120s; recycle every 1000 jobs
```

In a container, the RAM exav divides is the container's memory limit, not the
host's.

## Where the 4 GB goes

| Part | Size | Set by |
|---|---|---|
| Kept for the kernel, page cache and everything else | a third of RAM: 1.3 GB | fixed |
| The signature database, loaded once and shared by every worker | 1.2 GB resident, 1.3 GB of address space | the database |
| One scan per worker | the rest, divided by `--workers`: 690 MB each at 2 workers | `--workers`, `--max-process-bytes` |
| Streams waiting to be scanned | 16 MB each in RAM, then on disk | `--spill-threshold-bytes`, `--spill-dir` |

The database is the fixed cost. Workers are forked after it loads and share it
copy-on-write, so two workers do not cost two databases. A prefork pool of N
workers shows N+1 processes of about 1.2 GB resident each in `top`; the real
total is one database plus what the scans use (the `Pss` line of
`/proc/<pid>/smaps_rollup` shows each process's share).

## The flags, in the order to decide them

1. **The database.** Load a prebuilt `.exavdb` (`-d file.exavdb`), not the raw
   `.cvd` files: loading the raw files builds the matcher at startup, which takes
   minutes and peaks at 2.4 GB even with `--build-shard-bytes 256M`. Build the
   `.exavdb` on another machine, or on this one while nothing is served, and see
   [Prebuilt database](/guides/prebuilt-database/). A reload loads the new
   database next to the old one before the old one goes, so leave room for a
   second copy for a few seconds, or schedule reloads for quiet hours.

2. **`--workers`**, how many scans run at once. Each takes a share of what is
   left after the database: about 1.4 GB here, so 2 workers get 690 MB each and
   4 workers 345 MB. Fewer workers means larger files are held whole and more
   scans wait; more workers means more concurrency and smaller files held. On
   this machine, 2 is the balance for mail or upload scanning. The default is one
   per CPU core.

3. **`--max-process-bytes`**, the memory one scan may use. Left unset, it is 2 GB
   lowered to the share above, which is the right value. Set it lower to leave
   room for another service on the same machine. A scan is kept to half of it
   (the other half is the matcher's working set), so what it holds is at most
   346 MB here, and an object past that is scanned through a block cache or a
   spill file instead of being loaded, or reported `LIMITS-EXCEEDED`.

4. **`--max-object-bytes`**, the largest object held whole (default 256 MB).
   exav lowers it to that half when it is larger, so there is nothing to set.
   Raise `--max-process-bytes` rather than this one when a large container is
   reported `LIMITS-EXCEEDED` and the machine has room.

5. **Spill**, for streams (`INSTREAM`, ICAP bodies). Each connection holds up to
   `--spill-threshold-bytes` (16 MB) in RAM, and the rest on disk. Point
   `--spill-dir` at a filesystem with room, and set `--max-total-spill-bytes` to
   what it can spare: every worker and the ICAP child counts separately. Do not
   leave it on a small `/tmp` held in RAM (`tmpfs`), which is memory again.

6. **`--max-input-bytes`**, if the clients should not send anything larger. The
   default is no limit: a large file is scanned through a block cache and costs
   time rather than memory. A mail gateway can set its own attachment limit
   here.

## Adding ICAP

An `icap://` listener next to the clamd one runs in one more child process,
sharing the same database. It scans in threads, one per connection (up to 100 by
default), and each scan holds up to `--max-object-bytes`. On a 4 GB machine,
bound it with `?max-connections=` on its address, and keep `--max-object-bytes`
small enough that the connections it allows can each hold that much:

```sh
exav --listen /run/clamav/clamd.ctl \
     --listen 'icap://0.0.0.0:1344?max-connections=8' \
     -d /var/lib/exav/official.exavdb --workers 2 --max-object-bytes 64M
```

## If it is still too much

- **`--workers 1`**: one scan at a time, with the most memory each.
- **`--workers threads`** runs every scan in one process: no copy of the
  database per worker to account for, but no way to stop one runaway scan
  without stopping all of them, and `--max-process-bytes` then caps the whole
  process.
- **A smaller database.** Most of the memory is `main` and `daily`; dropping the
  `bytecode` database saves little. Third-party feeds add to it.

See [Limits and tuning](/reference/limits/) for every bound, and
[Daemon mode](/guides/daemon/#worker-pool-and-per-job-limits) for the pool.
