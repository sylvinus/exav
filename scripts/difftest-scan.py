#!/usr/bin/env python3
"""Scan a manifest of files through ONE engine and record its verdicts.

Both clamd and the exav daemon speak the same wire protocol, so one scanner
serves both. That is the point: a difference in the results cannot come from a
difference in how they were driven.

ALL-MATCH ONLY
    Every scan is `ALLMATCHSCAN`, so a file's verdict is the SET of signatures
    that matched rather than whichever one the engine happened to reach first.
    First-match comparison is the largest source of *fake* disagreement between
    two engines — both find the malware, each names a different signature, and
    the diff reports it as a conflict.

    This forces one connection per file. clamd 1.5.3 refuses every multi-reply
    command inside `IDSESSION` — `ALLMATCHSCAN`, `CONTSCAN` and `MULTISCAN` all
    answer "Command invalid inside IDSESSION. ERROR" and hang up, because the
    session protocol tags one reply per command id and these emit an unbounded
    number. Outside a session the daemon closes after a single command, and that
    close is the terminator.

    Getting this wrong is quiet, not loud: the refusal arrives as an ordinary
    reply and the hang-up looks like a finished scan, so every file lands in the
    table as ERROR with nothing saying why.

COMPLIANCE, NOT BENCHMARKING
    This harness answers "do the two engines agree", and is tuned for throughput
    so that question can be asked often.

    Timings are recorded anyway — total wall-clock per run, and per-file `ms` —
    but ONLY as a debugging aid: they are what tells you a file wedged a worker
    or that one engine is dramatically slower over the same corpus. **They are
    not a performance benchmark and must not be quoted as one.** Under
    `--jobs > 1` a file's elapsed time is mostly contention with the other jobs,
    and the first read of a sample is dominated by disk (~4 s cold vs ~18 ms
    warm), so the same file times differently depending on what ran before it.
    Real performance work belongs in a dedicated benchmark: one job, warm cache,
    repeated runs.

CONCURRENCY
    Scanning is dominated by reading the sample off disk, not by the engine, so
    `--jobs` keeps several scans in flight to overlap that I/O. Both daemons are
    threaded and each job owns its own connection.

    Measured here, on disjoint COLD file sets (a warm page cache is worth ~10x
    on its own and swamps everything else, so sets must not be reused):

        jobs=1   0.4 files/s   1 timeout
        jobs=4   0.6 files/s   2 timeouts
        jobs=8   0.7 files/s   3 timeouts

    Concurrency is worth about 1.75x, not the 8x the job count suggests — the
    disk is the wall — and over-subscribing steadily converts throughput into
    timeouts. Hence the default below: a small multiple of the CPU count,
    capped. More is not better.

CACHING
    The output TSV is the cache. A path already in it, with the same size, is
    skipped. ClamAV's verdicts do not change between runs of the same database,
    so its side is written once and reused; exav's is re-run whenever the binary
    changes. Delete the file to force a fresh run.
"""

import argparse
import os
import queue
import socket
import sys
import threading
import time

# Replies are NUL-terminated ("z" command framing).
TERM = b"\0"


def default_jobs():
    """Concurrency to use when the caller does not say.

    Twice the CPU count, since the work is I/O-bound and a scan spends most of
    its time waiting on the disk rather than on a core. Capped at 8 because the
    measurement above shows throughput flattening while timeouts keep climbing,
    and floored at 2 so a single-core host still overlaps something.
    """
    return min(8, max(2, (os.cpu_count() or 1) * 2))


def scan_one(sock_path, path, timeout):
    """`(replies, milliseconds)` for one file, over its own connection."""
    t0 = time.monotonic()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall(f"zALLMATCHSCAN {path}\0".encode())
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        try:
            s.close()
        except OSError:
            pass
    replies = []
    for raw in buf.split(TERM):
        if not raw:
            continue
        text = raw.decode("utf-8", "replace")
        # A session tag would be `<n>: `; harmless to strip if it ever appears.
        head, sep, rest = text.partition(": ")
        replies.append(rest if sep and head.isdigit() else text)
    return replies, int((time.monotonic() - t0) * 1000)


def verdict_of(replies):
    """Collapse a file's replies into one comparable value.

    * `-`            nothing found
    * `sig[,sig...]` the SET of signatures, deduped and sorted, so two engines
                     that found the same things in a different order compare
                     equal instead of reading as a disagreement
    * `!TAG`         a not-scanned outcome (exav reports these; clamd has no
                     equivalent and simply says OK). The `!` cannot collide with
                     a signature name, which is what lets the comparison tell
                     "flagged as unreadable" apart from "found malware".
    * `ERROR`        the scan itself failed
    """
    # NO replies at all is not "clean" — it is a scan that did not answer. The
    # daemon closes the connection without a word when its worker dies mid-scan
    # (an allocation failure or the OOM killer under the per-job RLIMIT_AS), and
    # reading that as `-` turns a crash into a clean verdict, then into a false
    # negative in the comparison.
    #
    # Measured: 55 worker deaths in one 8,978-file run, every one recorded as
    # clean. The daemon logs them and the harness prints a NOTE, but a count in a
    # log does not stop the TABLE from being wrong — the row itself has to say
    # the scan failed, which also keeps it out of the cache so the next pass
    # retries it.
    if not replies:
        return "ERROR"
    sigs = set()
    marker = None
    for r in replies:
        line = r.strip()
        if line.endswith(" FOUND"):
            body = line[: -len(" FOUND")]
            sigs.add(body.split(": ")[-1])
        elif line.endswith("ERROR"):
            for tag in ("LIMITS-EXCEEDED", "UNSCANNABLE", "PASSWORD-PROTECTED"):
                if tag in line:
                    marker = marker or "!" + tag
                    break
            else:
                marker = marker or "ERROR"
    # A detection outranks a not-scanned marker: a file that both matched a
    # signature and hit a limit is a detection, and reporting the limit instead
    # would hide it.
    if sigs:
        return ",".join(sorted(sigs))
    return marker or "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--manifest", required=True, help="file listing paths, one per line")
    ap.add_argument("--out", required=True, help="TSV results; doubles as the cache")
    ap.add_argument("--meta", help="where to write the run totals (default: <out>.meta)")
    ap.add_argument("--timeout", type=float, default=60.0, help="per-file seconds")
    ap.add_argument(
        "--jobs",
        type=int,
        default=0,
        help="concurrent scans; 0 (default) picks 2x CPUs, capped at 8",
    )
    ap.add_argument("--label", default="engine")
    args = ap.parse_args()
    if args.jobs <= 0:
        args.jobs = default_jobs()

    with open(args.manifest) as f:
        paths = [ln.rstrip("\n") for ln in f if ln.strip()]

    # The cache. Keyed on path + size so a corpus file that changed is re-scanned
    # rather than silently answered from a stale row.
    #
    # An ERROR row is NOT a result and is deliberately not cached. It records
    # that the scan did not happen — a timeout, a refused connection, a daemon
    # that died mid-run — and every one of those is transient. Caching them makes
    # a one-off outage permanent: the affected files are skipped by every later
    # run, so the damage silently shrinks the comparable set forever instead of
    # being repaired by the next pass. (Observed: a clamd container that died
    # part-way through a run left 2,525 of 8,978 files as ERROR.)
    done = {}
    if os.path.exists(args.out):
        with open(args.out) as f:
            next(f, None)
            for ln in f:
                p = ln.rstrip("\n").split("\t")
                if len(p) >= 4 and p[2] != "ERROR":
                    done[p[0]] = p[1]
    else:
        with open(args.out, "w") as f:
            f.write("path\tsize\tverdict\tms\n")

    todo = []
    skipped = 0
    for p in paths:
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        if done.get(p) == str(size):
            skipped += 1
            continue
        todo.append((p, size))

    work = queue.Queue()
    for item in todo:
        work.put(item)
    results = queue.Queue()
    counters = {"failed": 0}
    lock = threading.Lock()

    def worker():
        while True:
            try:
                p, size = work.get_nowait()
            except queue.Empty:
                return
            t0 = time.monotonic()
            try:
                replies, ms = scan_one(args.socket, p, args.timeout)
                v = verdict_of(replies)
            # Deliberately every exception, not just the socket ones. A thread
            # that dies without posting a result leaves the collector below
            # blocked on `results.get()` for a row that can never arrive — the
            # run hangs with no error, which over a corpus this size means an
            # overnight pass silently producing nothing. Recording the file as
            # ERROR costs one row and keeps the run finite.
            except BaseException as e:  # noqa: BLE001
                # The time actually spent, not the timeout constant: a protocol
                # refusal fails in milliseconds and a real timeout takes the whole
                # budget, and recording both as the timeout hides which happened.
                ms = int((time.monotonic() - t0) * 1000)
                v = "ERROR"
                with lock:
                    counters["failed"] += 1
                    if counters["failed"] <= 5:
                        print(
                            f"{args.label}: {type(e).__name__}: {e}  ({p})",
                            file=sys.stderr,
                            flush=True,
                        )
            results.put((p, size, v, ms))

    print(
        f"{args.label}: {len(todo)} to scan, {skipped} from cache, jobs={args.jobs}",
        file=sys.stderr,
        flush=True,
    )
    t_start = time.monotonic()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, args.jobs))]
    for t in threads:
        t.start()

    n = 0
    total = len(todo)
    with open(args.out, "a", buffering=1) as out:
        while n < total:
            p, size, v, ms = results.get()
            out.write(f"{p}\t{size}\t{v}\t{ms}\n")
            n += 1
            if n % 100 == 0 or n == total:
                el = max(time.monotonic() - t_start, 1e-9)
                eta = (total - n) / (n / el)
                print(
                    f"{args.label}: {n}/{total}  {counters['failed']} failed  "
                    f"{n / el:.1f}/s  eta {eta / 60:.0f}m",
                    file=sys.stderr,
                    flush=True,
                )
    for t in threads:
        t.join(timeout=1)

    el = time.monotonic() - t_start
    scanned_bytes = sum(sz for _, sz in todo)
    # Aggregate only. Enough to see one engine take twice as long over the same
    # corpus; not enough to pass for a benchmark, which is the point.
    meta = args.meta or args.out + ".meta"
    with open(meta, "w") as f:
        f.write(f"label\t{args.label}\n")
        f.write(f"scanned\t{n}\n")
        f.write(f"from_cache\t{skipped}\n")
        f.write(f"failed\t{counters['failed']}\n")
        f.write(f"jobs\t{args.jobs}\n")
        f.write(f"elapsed_s\t{el:.1f}\n")
        f.write(f"bytes\t{scanned_bytes}\n")
    print(
        f"{args.label}: done — {n} scanned, {skipped} from cache, "
        f"{counters['failed']} failed, {el:.0f}s ({n / max(el, 1e-9):.1f}/s, "
        f"{scanned_bytes / max(el, 1e-9) / 1e6:.0f} MB/s)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
