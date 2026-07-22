# Differential testing: exav vs ClamAV

How we validate exav's correctness as a drop-in: scan the **same files** with the
**same signature database** using both engines and compare verdicts.
Disagreements are exav bugs — a false negative (clam detects, exav misses) or
a false positive (exav detects, clam clean).

**This is a compliance harness, not a benchmark.** It records timings, and they
are useful for spotting a wedged file or an engine that is dramatically slower,
but they are measured under concurrency against a cold page cache and must never
be quoted as performance numbers. Performance work belongs in a dedicated
single-job benchmark.

The corpus is live MalwareBazaar malware under `corpus/` (gitignored,
static-scan only, never executed).

The harness lives in `scripts/` (tracked, reproducible, no secrets):

| Script | Role |
|---|---|
| `scripts/difftest.sh` | the runner — three phases, one engine resident at a time |
| `scripts/difftest-scan.py` | drives ONE engine over a manifest; used for both |
| `scripts/difftest-compare.py` | joins the two result tables and buckets the differences |
| `scripts/clamd-docker.sh` | standalone start/stop/status for the Dockerised clamd |
| `scripts/bc-difftest.sh` | narrower bytecode-engine differential harness |
| `scripts/fetch-corpus*.py`, `scripts/query-clamav-hits.py` | build the (gitignored) corpus from MalwareBazaar |

## How the runner is shaped, and why

```
  1. clamd over the corpus  ->  results-clam.tsv   (CACHED)
  2. exav  over the corpus  ->  results-exav.tsv
  3. compare the two tables
```

* **ClamAV does not change.** Its verdicts are a function of the pinned
  signature database, so phase 1 is paid once and cached. Iterating on exav
  re-pays only phase 2.
* **One engine is resident at a time.** Running both together on a small host
  meant ~2 GB of clamd plus ~1 GB of exav competing for RAM and disk: workers
  died to OOM, a stuck job head-of-line blocked the pool, and ~3 slow files
  turned into ~36 rows recorded as errors — differences that were artefacts of
  the harness, not of the engines.
* **Both engines are driven by the same client**, so a difference in results
  cannot come from a difference in how they were asked.
* **Every scan is all-match.** A verdict is the *set* of signatures that
  matched, not whichever one an engine reached first. Comparing first-matches is
  the largest source of fake disagreement.

### Two protocol facts worth knowing

* **clamd refuses every multi-reply command inside `IDSESSION`** —
  `ALLMATCHSCAN`, `CONTSCAN` and `MULTISCAN` all answer `Command invalid inside
  IDSESSION. ERROR` and hang up. Only single-reply commands (`SCAN`, `PING`,
  `VERSION`, `STATS`) are allowed, because the session tags one reply per
  command id. So all-match means one connection per file. (exav's daemon is more
  permissive here and does allow it in a session — a divergence, not a bug, but
  a clamd-compatible client cannot rely on it.)
* **exav preforks one worker per core.** Driving more concurrent scans than
  there are workers puts the excess in the accept queue behind long jobs, where
  they time out having never been looked at — recorded as `ERROR`, which reads
  as a compliance difference and is not one. The runner therefore passes
  `--workers $JOBS` and matches `--max-scan-secs` to the client timeout.

### Usage

```sh
scripts/difftest.sh                  # whole corpus
LIMIT=500 scripts/difftest.sh        # deterministic 500-file sample
JOBS=8 scripts/difftest.sh           # more concurrency
PHASE=exav scripts/difftest.sh       # re-run exav only, reuse the clam cache
PHASE=compare scripts/difftest.sh    # re-compare what is already there
FRESH_CLAM=1 scripts/difftest.sh     # rebuild the clam cache
```

`LIMIT` samples deterministically (fixed `SEED`) and **both engines scan exactly
that list** — the manifest is generated once and shared. Giving each engine its
own random subset would compare different files and call the result a
difference.

### What makes a cached result reusable

A results table is stamped with the profile it was produced under — the flags
(`COMPAT`, `HEURISTICS`, `JOBS`) **and a checksum of the manifest itself**. A run
whose stamp differs discards the table rather than joining against it.

The manifest checksum is the part that is easy to get wrong. Phase 1 skips the
clam scan on *row count*, so a cache holding the right number of rows for the
wrong files would otherwise be reused — and since the compare joins by path, the
overlap would be empty and the run would confidently report on nothing. Changing
`SEED` at a fixed `LIMIT`, or adding samples to the corpus, both produce exactly
that shape. Neither `LIMIT` nor `SEED` alone is sufficient to detect it, which is
why the manifest is fingerprinted instead.

### Scale, measured on the dev host (Aug 2026)

| | |
|---|---|
| corpus on disk | 18,596 files, 34 GB |
| what the manifest takes (≤ `MAXSZ`, 20 MB) | 8,978 files, 20.8 GB, mean 2.3 MB |
| cold disk read | ~8.6 MB/s — **the wall** |
| clamd, all-match | ~0.2–0.7 files/s depending on concurrency |
| concurrency gain | ~1.75× from 1→8 jobs, not 8× |

Re-measure rather than trust the table — the corpus grows. The two rows are
different populations and it matters which one an estimate uses: **less than
half** the files on disk are inside the size cap.

A full pass is many hours *per engine* and is bounded by storage rather than by
either scanner. Use `LIMIT` while iterating.

## Prerequisites (one-time setup)

Everything below is reproducible from a clean checkout; nothing secret is
committed (the corpus and the API key are both gitignored).

1. **Build the binary under test** — `cargo build --release -p exav-cli`.
2. **Tools:** Docker (runs the reference `clamd`), `clamdscan` on the host
   (Debian/Ubuntu: `apt-get install clamdscan`), and `python3` with `pyzipper`
   (`pip install pyzipper`) only if you fetch the corpus.
3. **Signatures** into the clamd DB dir the runner expects — both engines must
   load the *same* set. The runner fetches these itself on first run, so this
   step is only for supplying your own.

   `DBDIR` defaults to **`$TMPROOT/difdb_daily`**, and `TMPROOT` is resolved at
   runtime: `/var/tmp` when `/tmp` is tmpfs (the common case), else `/tmp`. So
   on a typical host the database lives at `/var/tmp/difdb_daily`, **not**
   `/tmp/difdb_daily` — check before concluding it is missing:
   ```sh
   scripts/difftest.sh --help 2>/dev/null; # or just:
   ls "$( [ "$(stat -f -c %T /tmp)" = tmpfs ] && echo /var/tmp || echo /tmp )/difdb_daily"
   # to supply your own instead of letting the runner fetch:
   cvd config set --dbdir /var/tmp/difdb_daily && cvd update   # Cisco's cvdupdate
   # (or copy an existing daily.cvd there; `main.cvd` too for full coverage)
   ```
4. **Corpus** under `corpus/samples/` (gitignored). Put your own samples there,
   or fetch from MalwareBazaar — needs a free Auth-Key, read from
   `MALWAREBAZAAR_API_KEY` in a gitignored `.env.local` at the repo root (never
   committed; get a key at <https://bazaar.abuse.ch/account/>):
   ```sh
   echo 'MALWAREBAZAAR_API_KEY=<your-key>' >> .env.local
   pip install pyzipper
   python3 scripts/fetch-corpus-bulk.py       # writes corpus/samples/_bulk/…
   ```

## Protocol

0. **Memory & temp layout on a small host.** The signature automaton is
   memory-heavy to *build* (see [DATABASE.md](DATABASE.md)), and RAM is the usual
   failure:
   - `/tmp` is often **tmpfs (RAM-backed)** — anything there counts against RAM.
   - A resident `clamd` from a previous run can hold ~1 GB.
   - clamd extracts **every scanned file's members into temp**; over a run that
     can reach gigabytes. The harness bind-mounts `$SOCK_DIR` as clamd's `/tmp`,
     so `$SOCK_DIR` **must be on real disk, not tmpfs**, or a big scan (or a
     container killed mid-scan, which leaks its temp) will exhaust RAM and wedge
     the box. The script now auto-picks a disk-backed `TMPROOT` (falls off `/tmp`
     to `/var/tmp` when `/tmp` is tmpfs); override with `TMPROOT=` / `SOCK_DIR=`.
   - Check with `free -h`, `df -h /tmp`, `ps aux --sort=-%mem | head`.

1. **Pick the DB scope.** `daily.cvd` only (fits in RAM here) or full
   `main+daily` (needs a capable build host). Both engines must use the *same*
   set or the comparison is meaningless.

2. **Build the database once (from the binary under test).** The prebuilt
   database avoids the build-time memory peak on every later daemon start. The
   database format is **versioned**: any change that alters how signatures are
   parsed or compiled bumps the version, which makes an old database fail to load.
   Build it once when RAM is free. Paths below assume the usual
   `TMPROOT=/var/tmp` (see step 3 of the prerequisites):
   ```sh
   cargo build --release -p exav-cli      # build the binary under test FIRST
   exav -d /var/tmp/difdb_daily --build-db /var/tmp/daily.exavdb
   ```
   The harness does this itself when needed, so run it by hand only to control
   *when* the memory peak happens. It **reuses a database that still loads** with
   the current binary and only rebuilds when it is missing or fails to load (a
   format bump) — so a format-compatible binary change does **not** pay the
   RAM-heavy rebuild. To force a clean rebuild, `rm -f $DB` first. (On a host too
   small to build the database at all, build it elsewhere and copy it in, or point
   `DB=` / `TMPROOT=` at disk — the script prints this hint if a build OOMs.)

3. **Run `scripts/difftest.sh`.** It manages everything — resolves a disk-backed
   temp dir, reuses-or-builds the database, runs each phase with only that
   engine resident, and tears down on exit. On a host where `/tmp` is tmpfs and
   `/var/tmp` is disk (the common case) a bare invocation "just works".
   ```sh
   LIMIT=500 scripts/difftest.sh      # a deterministic 500-file sample
   ```
   Phase 3 prints the bucket counts, the aggregate wall-clock per engine, and
   examples from each disagreement bucket. Both phases are resumable: results
   are keyed on path + size, so re-running continues rather than restarting.

4. **Tear down (if needed).** The runner's EXIT trap stops the daemon, saves the
   clamd container log to `$TMPROOT/difftest-clamd.log` and removes the
   container. After an abnormal exit:
   ```sh
   docker rm -f clamd-difftest; pkill -x exav
   ```

Key choices, and why:
- **Daemons, not one-shot.** exav reloads a ~1 GB database per invocation, and
  clamd reloads its own; running each as a daemon removes that from the loop.
- **Sequential phases, not interleaved.** Two resident engines on a small host
  compete for RAM and disk, and the resulting OOMs and queue timeouts are
  recorded as engine disagreements. One at a time, they are not.
- **`shuf` with a fixed seed.** Random order means even a partial run is a
  representative sample, and the fixed seed means the same `LIMIT` selects the
  same files, so two runs are comparable. Don't use `head` on the corpus —
  `find` returns the curated family folders first, which biases the sample
  toward easily-detected families (e.g. Locky).
- **Size cap (`MAXSZ`, 20 MB default).** exav currently buffers whole members
  (see the streaming item in the roadmap), so very large samples can OOM a
  RAM-constrained host and abort the run. Capped for now.

## Interpreting results

- **AGREE / clean**: exav matches clamscan. This is the headline metric.
- **FN** (clamscan found, exav missed): a real gap — investigate the signature
  type (`clamscan --debug` on the file shows what it matched). Known causes
  found this way: imphash ordinal encoding, section-hash on truncated PEs, and
  **embedded-PE scanning** (a PE appended inside another file) — all since fixed.
- **EXAV_ONLY** (exav found, clamscan clean): *do not assume this is a false
  positive.* On the 8,978-file run of 2026-07-28, all 32 were checked and none
  was an exav error — see below.
- **Absolute hit rate is DB-bound, not a corpus problem.** With `daily` only (no
  `main.cvd`, which holds most coverage) both engines detect a small fraction —
  e.g. clamscan with full `main+daily` flags ~13% of a random MalwareBazaar
  sample, and far less with `daily` alone. The *agreement* is what matters.


## The 2026-07-28 campaign (8,978 files, daily-only DB)

| verdict | compat (as run) | full capability (re-scan) |
|---|---|---|
| clean (both OK) | 4,137 | — |
| ERROR | 3,542 | 29 (exav side) |
| AGREE | 766 | 769 |
| CAREFUL | 471 | 458 |
| EXAV_ONLY | 32 | **104** |
| NAMEDIFF | 25 | 24 |
| **FN** | 3 | **0** |
| CAREFUL_FN | 2 | **0** |

The full-capability column is a re-scan of the 5,436 comparable files after the
fixes below.

The two rows at the bottom are both "clamd named the malware and exav did not",
and the difference between them decides how serious each is:

* **`FN`** — exav returned a clean `OK`. A user acting on that verdict runs the
  file. This is the failure the engine exists to prevent, and it is the number
  that had to reach zero.
* **`CAREFUL_FN`** — exav returned `UNSCANNABLE` / `PASSWORD-PROTECTED` /
  `LIMITS-EXCEEDED`. It could not name the malware, but it did not claim the
  file was safe, so the file is still quarantinable and the gap is visible.

Both counts are now zero. The two samples that sat in `CAREFUL_FN` — an
MPRESS-packed dropper and a UPX image with a bare `PackHeader` — are unpacked
and detected under clamd's own signature names. Neither needed a new decoder
written from scratch.

Read the ERROR row first: most of it is `clam=ERROR`, a 2 GB-capped clamd
container on a 5.9 GB host, not an exav signal. Roughly 40% of that run measured
the harness rather than the engine, and the comparison is only sound across the
~5,400 rows where both engines actually answered. The run also ended by
OOM-killing the exav daemon.

### The five FNs — three fixed, two are packer support

Each was a distinct cause, which is the argument for triaging every one rather
than the biggest bucket:

* two APKs where a packer set the "encrypted" flag on every member;
* one JAR hiding classes behind trailing-slash names, which *also* needed
  `Target:12` re-enabled before the payload matched;
* two packed PEs — one MPRESS, one UPX. Both are now unpacked and detected.
  Neither needed a decoder written from scratch, which is the interesting part:
  ClamAV unpacks MPRESS with a **bytecode program shipped in the signature DB**,
  which exav already loaded and could already run; and the UPX sample only
  needed the bare-`PackHeader` layout routed plus ClamAV's rebuilt-PE layout
  reproduced.


### Measure added coverage at COMPAT=0, never at the default

The harness runs `--clamav-compat` by default, which is right for checking
*agreement* — it holds limits and format reach fixed so a disagreement means a
real engine difference. It is the wrong mode for measuring what exav adds,
because compat is defined as switching that reach off.

The same corpus gives:

| | compat (default) | full capability (`COMPAT=0`) |
|---|---|---|
| exav detections | 823 | 897 |
| exav-only | 32 (3.9%) | **104 (11.6%)** |

A 3× understatement. Any claim of the form "exav detects things ClamAV misses"
has to come from a `COMPAT=0` pass; anything else is measuring exav with its own
extractors deliberately disabled.

### The EXAV_ONLY hits — zero false positives

Every one was checked, and the method matters because the naive reading is
wrong. Handing clamd **exav's own extracted members** (see
`exav-unpack/examples/dump_members.rs`) makes clamd flag them under the *same
signature name* while still calling the container clean. That is the oracle
settling it: exav was not matching wrongly, it was reaching content clamd never
unpacked — `word/*.rtf` inside a docx, `/cab1.cab/MainExecutable` inside an MSI,
`x.exe` inside a gzipped `.bat`.

* **101 of 104** were hits nested inside extracted members.
* **2 of 104** were `Target:0` RTF-exploit signatures matching RTF files at top
  level, which is what `Target:0` means.
* **1 of 104** was `Win.Trojan.Mimikatz` inside a PE base64-encoded within an
  RTF: none of the signature's seven subsignatures occurs in the raw file and
  all seven occur in the decoded image.

Four of them looked like a target-gating bug at first — `Target:1` (PE-only)
signatures apparently firing on RTF files. They were not: the signature's bytes
do not occur anywhere in the raw RTF, only inside a hex-encoded embedded PE. The
detections were right and the *reporting* was wrong; 13 of the 17 sites that
return a detection were not recording the match location, so nested hits looked
like container-level ones. Fixed, with `exav-core/tests/match_location.rs`
guarding it. Without match locations this triage is guesswork, which is why that
bug is worth more than its cosmetic appearance suggests.

### NAMEDIFF — benign

Both engines detect; they disagree only on which signature won a first-match
race. The dominant case (16 of 25) is clamd's `Win.Ransomware.Wanna` versus
exav's `Win.Exploit.Doublepulsar` on the same samples — and WannaCry bundles
DoublePulsar. Verified by hand: both of exav's required subsignatures are
really present (offsets 249260 and 249335). No action.
