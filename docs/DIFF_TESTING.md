# Differential testing: exav vs clamscan

How we validate exav's correctness as a drop-in: scan the **same files** with the
**same signature database** using both engines and compare verdicts (and speed).
Disagreements are exav bugs — a false negative (clamscan detects, exav misses) or
a false positive (exav detects, clamscan clean).

The corpus is live MalwareBazaar malware under `corpus/` (gitignored,
static-scan only, never executed).

## Protocol

0. **Free memory.** The signature automaton is memory-heavy to *build* (see
   [DATABASE.md](DATABASE.md)), and this is easy to get wrong:
   - `/tmp` is often **tmpfs (RAM-backed)** — anything there counts against RAM.
   - A resident `clamd` from a previous run can hold ~1 GB.
   - Check with `free -h`, `df -h /tmp`, `ps aux --sort=-%mem | head`.

1. **Pick the DB scope.** `daily.cvd` only (fits in RAM here) or full
   `main+daily` (needs a capable build host). Both engines must use the *same*
   set or the comparison is meaningless.

2. **Build the exav cache once** so the daemon starts fast and avoids the
   build-time peak on every run:
   ```sh
   exav -d /tmp/difdb_daily --build-cache /tmp/daily.cache
   ```

3. **Start both engines as resident daemons** (loaded once — no per-file reload,
   so timing is honest and runs are fast):
   ```sh
   # exav daemon
   exav --daemon -d /tmp/daily.cache --socket /tmp/exav.sock &

   # clamd on the same DB (clamscan itself is one-shot; its daemon is clamd,
   # its client is clamdscan)
   cat > /tmp/clamd_daily.conf <<CONF
   DatabaseDirectory /tmp/difdb_daily
   LocalSocket /tmp/clamd.sock
   Foreground yes
   MaxThreads 4
   MaxScanSize 2000M
   MaxFileSize 2000M
   CONF
   clamd --config-file=/tmp/clamd_daily.conf &
   ```

4. **Iterate, timed and logged.** Run `corpus/difftest.sh` for a bounded time;
   it scans files in random (`shuf`) order through both daemons, appends one row
   per file to `/tmp/difftest/results.tsv`
   (`path  clam  exav  verdict  clam_ms  exav_ms`), and is **resumable** — a
   re-run skips already-logged files, so repeated short runs accumulate coverage.
   ```sh
   DUR=300 corpus/difftest.sh        # 5 minutes; Ctrl-C-safe, just re-run to continue
   ```
   The script prints a summary (AGREE / clean / FN / FP counts, average per-file
   ms for each engine) and lists the FN/FP cases to investigate.

Key choices, and why:
- **Daemons, not one-shot.** exav reloads a ~1 GB cache per invocation; clamscan
  reloads its DB per invocation. Running both as daemons removes that and makes
  per-file timing the real steady-state cost.
- **Never in parallel.** The two engines run sequentially per file so neither
  starves the other for CPU/RAM and the timings are comparable.
- **`shuf`, not a frozen list.** Random order means even an interrupted run is a
  representative sample; the log makes it cumulative. Don't use `head` on the
  corpus — `find` returns the curated family folders first, which biases the
  sample toward easily-detected families (e.g. Locky).
- **Size cap (`MAXSZ`, 20 MB default).** exav currently buffers whole members
  (see the streaming item in the roadmap), so very large samples can OOM a
  RAM-constrained host and abort the run. Capped for now.

## Interpreting results

- **AGREE / clean**: exav matches clamscan. This is the headline metric.
- **FN** (clamscan found, exav missed): a real gap — investigate the signature
  type (`clamscan --debug` on the file shows what it matched). Known causes
  found this way: imphash ordinal encoding, section-hash on truncated PEs, and
  **embedded-PE scanning** (a PE appended inside another file) — all since fixed.
- **FP** (exav found, clamscan clean): rarer; usually an over-broad match.
- **Absolute hit rate is DB-bound, not a corpus problem.** With `daily` only (no
  `main.cvd`, which holds most coverage) both engines detect a small fraction —
  e.g. clamscan with full `main+daily` flags ~13% of a random MalwareBazaar
  sample, and far less with `daily` alone. The *agreement* is what matters.
