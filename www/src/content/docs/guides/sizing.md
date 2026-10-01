---
title: Sizing a server
description: What to set on a 4 GB machine running exav as a clamd or ICAP server, and how each flag divides the memory.
---

A worked example: one machine with 4 GB of RAM, serving the clamd protocol (and
optionally ICAP) with the full official database. The figures were measured with
exav 0.0.2 and the official `main`, `daily` and `bytecode` databases of
September 2026 (3.6 million signatures); a later database is somewhat larger.

## The short answer

```sh
exav --listen /run/clamav/clamd.ctl \
     -d /var/lib/exav/official.exavdb \
     --workers 2 \
     --spill-dir /var/cache/exav --max-total-spill-bytes 2G
```

The spill directory must exist (exav refuses to start otherwise) and be writable
by the daemon. The packaged unit makes the filesystem read-only, so add
`CacheDirectory=exav` with `systemctl edit exav`, which creates
`/var/cache/exav` for the unit's user.

Everything else stays at its default, and exav fits the rest to the machine at
startup:

```text
exav: per-job memory 2048 MiB x 2 workers exceeds what this host can back; using 818 MiB per job (two thirds of RAM, less the 1094 MiB shared database, over the workers). ...
exav: a scan may hold at most 409 MiB (half the 818 MiB of memory it gets), so a size limit is reported rather than the scan being killed for hitting one
exav: prefork daemon: 2 workers; per-job limits: wall 120s, mem 818 MiB, cpu 120s; recycle every 1000 jobs
```

In a container, the RAM exav divides is the container's memory limit, not the
host's.

## Where the 4 GB goes

| Part | Size | Set by |
|---|---|---|
| Kept for the kernel, page cache and everything else | a third of RAM: 1.3 GB | fixed |
| The signature database, loaded once and shared by every worker | 0.8 GB resident, 1.1 GB of address space | the database |
| One scan per worker | the rest, divided by `--workers`: 818 MB each at 2 workers | `--workers`, `--max-process-bytes` |
| Streams waiting to be scanned | 16 MB each in RAM, then on disk | `--spill-threshold-bytes`, `--spill-dir` |

The database is the fixed cost. Workers are forked after it loads and share it
copy-on-write, so two workers do not cost two databases. A prefork pool of N
workers shows N+1 processes of about 0.8 GB resident each in `top`; the real
total is one database plus what the scans use (the `Pss` line of
`/proc/<pid>/smaps_rollup` shows each process's share).

## The flags, in the order to decide them

1. **The database.** Load a prebuilt `.exavdb` (`-d file.exavdb`), not the raw
   `.cvd` files: from raw files exav builds the signature index at every start
   and reload, which takes longer and more memory than loading a prebuilt one
   (see [what it costs](/guides/prebuilt-database/#what-it-costs)). Build the
   `.exavdb` on another machine, or on this one while nothing is served. A
   reload loads the new database next to the old one, and the old workers keep
   theirs until they finish their jobs (up to `--max-scan-secs` plus 5 seconds),
   so leave room for a second copy for that long, or schedule reloads for quiet
   hours.

2. **`--workers`**, how many scans run at once. Each takes a share of what is
   left after the database: about 1.6 GB here, so 2 workers get 818 MB each and
   4 workers 409 MB. Fewer workers means larger files are held whole and more
   scans wait; more workers means more concurrency and smaller files held. On
   this machine, 2 is the balance for mail or upload scanning. The default is one
   per CPU core.

3. **`--max-process-bytes`**, the memory one scan may use. Left unset, it is 2 GB
   lowered to the share above, which is the right value. Set it lower to leave
   room for another service on the same machine. A scan is kept to half of it
   (the other half is the matcher's working set), so what it holds is at most
   409 MB here, and an object past that is scanned through a block cache or a
   spill file instead of being loaded, or reported `LIMITS-EXCEEDED`.

4. **`--max-object-bytes`**, the largest object held whole (default 256 MB).
   exav lowers it to that half when it is larger, so there is nothing to set.
   Raise `--max-process-bytes` rather than this one when a large container is
   reported `LIMITS-EXCEEDED` and the machine has room.

5. **Spill**, for streams (`INSTREAM`, ICAP bodies). Each connection holds up to
   `--spill-threshold-bytes` (16 MB) in RAM, and the rest on disk. Point
   `--spill-dir` at a filesystem with room. `--max-total-spill-bytes` is per
   process, and every worker and the ICAP child counts separately, so set it to
   what the disk can spare divided by the number of processes: 2G each above
   lets 2 workers use 4G together. Do not leave it on a small `/tmp` held in RAM
   (`tmpfs`), which is memory again.

6. **`--max-input-bytes`**, if the clients should not send anything larger. The
   default is no limit: a large file is scanned through a block cache and costs
   time rather than memory. A mail gateway can set its own attachment limit
   here.

## Adding ICAP

An `icap://` listener next to the clamd one runs in one more child process,
sharing the same database. It scans in threads, one per connection (up to 100 by
default), with no `--max-scan-secs` and no `RLIMIT_AS` (see
[Limits](/reference/limits/)). Each scan may hold what a worker's scan may (409
MB here), plus up to `--spill-threshold-bytes` of buffered body. Most scans hold
far less, but the worst case is that times the number of connections, so on a
4 GB machine bound them with `?max-connections=` on the address:

```sh
exav --listen /run/clamav/clamd.ctl \
     --listen 'icap://0.0.0.0:1344?max-connections=4' \
     -d /var/lib/exav/official.exavdb --workers 2
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

See [Limits and tuning](/reference/limits/) for every bound, and
[Daemon mode](/guides/daemon/#worker-pool-and-per-job-limits) for the pool.
