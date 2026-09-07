#!/usr/bin/env bash
# exav vs ClamAV differential testing, in three separable phases.
#
#   1. clamd over the corpus  -> results-clam.tsv   (CACHED — see below)
#   2. exav  over the corpus  -> results-exav.tsv
#   3. compare the two tables
#
# WHY PHASES INSTEAD OF ONE INTERLEAVED LOOP
#
#   * **ClamAV does not change.** Its verdicts are a function of the signature
#     database, which is pinned here. Re-scanning 18k files through it on every
#     exav change is pure waste — so phase 1 writes a cache and later runs skip
#     straight to phase 2. Phase 1 is the slow one; you pay it once.
#   * **Only one engine is resident at a time.** The old harness ran both
#     daemons together. On a small host that is ~2 GB of clamd plus ~1 GB of
#     exav plus the corpus page cache, and it showed: workers died to OOM, a
#     stuck job head-of-line blocked the two-worker pool, and ~3 slow files
#     turned into ~36 files recorded as errors. Running them separately removes
#     the interference AND the misattribution.
#   * The two phases become independently re-runnable and independently
#     debuggable, which the interleaved loop never was.
#
# Both engines are driven by the SAME client (scripts/difftest-scan.py), so a
# difference in results cannot come from a difference in how they were asked.
# Every scan is ALL-MATCH: a verdict is the SET of signatures that matched, not
# whichever one an engine reached first. Comparing first-matches is the single
# largest source of fake disagreement — both engines find the malware, each
# names a different signature, and the diff calls it a conflict.
#
# USAGE
#   scripts/difftest.sh                  # whole corpus
#   LIMIT=500 scripts/difftest.sh        # a 500-file sample (deterministic)
#   JOBS=8 scripts/difftest.sh           # more concurrency (scanning is I/O-bound)
#   PHASE=exav scripts/difftest.sh       # re-run exav only, reuse the clam cache
#   PHASE=compare scripts/difftest.sh    # just re-compare what is already there
#   FRESH_CLAM=1 scripts/difftest.sh     # discard the clam cache and rebuild it
#
# SCALE, measured on this host (Aug 2026; re-measure rather than trust these)
#   corpus on disk:         18,596 files, 34 GB
#   what the manifest takes (<= MAXSZ): 8,978 files, 20.8 GB, mean 2.3 MB
#   cold disk read:         ~8.6 MB/s   <- the wall
#   clamd, all-match:       ~0.2-0.7 files/s depending on concurrency
#
# So a full pass is many hours PER ENGINE, and it is bounded by storage, not by
# either scanner. Use LIMIT while iterating. The clam side is cached, so once
# phase 1 has run for a given manifest only exav is re-paid.
#
# LIMIT picks a deterministic sample (fixed seed), and BOTH engines scan exactly
# that list — the manifest is generated once and shared. A sampled run that gave
# each engine its own random subset would compare different files and call the
# result a difference.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

# ── Tunables ─────────────────────────────────────────────────────────────────
CORPUS="${CORPUS:-$ROOT/corpus/samples}"
LIMIT="${LIMIT:-0}"                   # 0 = every file
SEED="${SEED:-42}"                    # deterministic sampling
MAXSZ="${MAXSZ:-20971520}"            # skip files > 20 MB
# Per-file cap. Generous on purpose: under all-match neither engine may stop at
# the first hit, so a single xlsx or 7z is a full walk of every member, and the
# disk here reads cold data at ~8.6 MB/s. A tight cap does not make the run
# faster — it converts slow files into ERROR rows, which is worse than waiting
# because they then look like a compliance difference.
TMO="${TMO:-120}"
CLAMD_START_TMO="${CLAMD_START_TMO:-900}"  # clamd DB load can take minutes
PHASE="${PHASE:-all}"                 # all | clam | exav | compare
FRESH_CLAM="${FRESH_CLAM:-0}"
COMPAT="${COMPAT:-1}"                 # exav at --clamav-compat (apples-to-apples)
HEURISTICS="${HEURISTICS:-1}"         # opt-in alert classes, BOTH engines
SHOW="${SHOW:-15}"                    # examples per bucket in the report
# Concurrent scans. Both engines run at the SAME value — that is what keeps the
# two runs comparable at all — and clamd's own thread pool is sized to match.
#
# Default: 2x CPUs, capped at 8. Measured on cold data (see difftest-scan.py),
# concurrency is worth ~1.75x rather than the job count, because the disk is the
# wall; past that it converts throughput into timeouts. Raising this on a host
# with fast storage is reasonable, but measure rather than assume.
if [ -z "${JOBS:-}" ]; then
  _cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
  JOBS=$(( _cpus * 2 )); [ "$JOBS" -gt 8 ] && JOBS=8; [ "$JOBS" -lt 2 ] && JOBS=2
fi

# `/tmp` is RAM on this host; a clamd extraction temp can run to gigabytes, and
# a container killed mid-scan leaks it there. Default off tmpfs.
is_tmpfs() { [ "$(stat -f -c %T "$1" 2>/dev/null)" = tmpfs ]; }
if [ -z "${TMPROOT:-}" ]; then
  if is_tmpfs /tmp && [ -d /var/tmp ] && ! is_tmpfs /var/tmp; then TMPROOT=/var/tmp; else TMPROOT=/tmp; fi
fi
OUT="${OUT:-$TMPROOT/difftest}"; mkdir -p "$OUT"
MANIFEST="$OUT/manifest.txt"
CLAM_TSV="$OUT/results-clam.tsv"
EXAV_TSV="$OUT/results-exav.tsv"
JOINED="$OUT/results-joined.tsv"

EXAV="${EXAV:-$ROOT/target/release/exav}"
ESOCK="${ESOCK:-$TMPROOT/difftest-exav.sock}"
IMAGE="${IMAGE:-clamav/clamav-debian:latest}"
CONTAINER="${CONTAINER:-clamd-difftest}"
# clamd's cgroup cap. Only one engine is resident per phase, so this can be
# generous. At 2500m clamd was SIGKILLed part-way through a full all-match run
# (its log ends mid-line on a normal detection, with no shutdown message) and
# the stale socket then failed 2,525 of 8,978 files in minutes.
MEMORY="${MEMORY:-3500m}"
DBDIR="${DBDIR:-$TMPROOT/difdb_daily}"
SOCK_DIR="${SOCK_DIR:-$TMPROOT/clamd_difftest_sock}"
CSOCK="$SOCK_DIR/clamd.sock"
DB="${DB:-$TMPROOT/daily.exavdb}"

# The profile every result row was produced under. Mixing rows from different
# profiles yields a plausible-looking table of nothing, so it is recorded and
# checked rather than assumed.
PROFILE="COMPAT=$COMPAT HEURISTICS=$HEURISTICS JOBS=$JOBS"

# The FILE LIST is part of that identity, not just the flags. The cached clam
# table is skipped on row count alone, so a cache holding the right NUMBER of
# rows for the wrong files would be reused and then joined against exav's — and
# the join is by path, so the overlap is empty and the run reports on nothing.
# LIMIT/SEED are not enough on their own either: the corpus itself changes as
# samples are added. Fingerprint the manifest that was actually scanned.
manifest_fp() {
  if [ -f "$MANIFEST" ]; then cksum < "$MANIFEST" | awk '{print $1 "-" $2}'; else echo none; fi
}
current_profile() { printf '%s manifest=%s' "$PROFILE" "$(manifest_fp)"; }

say() { echo "[$(date '+%H:%M:%S')] $*"; }

cleanup() {
  # Save the container's log BEFORE removing it. Removing first is what turned
  # a startup failure into "FATAL: clamd socket never appeared" with no way to
  # find out why — the evidence was deleted by the handler reporting the error.
  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    docker logs "$CONTAINER" >"$TMPROOT/difftest-clamd.log" 2>&1 || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  [ -n "${EXAV_PID:-}" ] && kill "$EXAV_PID" 2>/dev/null
  rm -f "$ESOCK" 2>/dev/null || true
}
trap cleanup EXIT

# ── Signatures ───────────────────────────────────────────────────────────────
# daily.cvd ONLY, deliberately: both engines must load exactly the same set or
# the comparison is meaningless. `freshclam` also fetches main.cvd, so it is
# removed again — which also keeps the exav database build to ~340k signatures
# instead of 3.6M, the difference between building and being OOM-killed here.
#
# Called by the phases that need it rather than run up front. Two of them do:
# clamd loads this directory, and building the exav database reads it. Neither
# applies to `PHASE=exav` against an already-built `$DB` — the documented way to
# iterate on exav — and fetching there would make the fast path depend on docker
# and a network it has no use for.
need_signatures() {
  [ -f "$DBDIR/daily.cvd" ] && return 0
  say "fetching signatures (daily only) into $DBDIR"
  mkdir -p "$DBDIR"
  docker run --rm -v "$DBDIR":/var/lib/clamav --entrypoint freshclam "$IMAGE" --stdout \
    >/dev/null 2>&1 || { echo "FATAL: freshclam bootstrap failed"; exit 1; }
  rm -f "$DBDIR"/main.cvd "$DBDIR"/main-*.cvd.sign
  [ -f "$DBDIR/daily.cvd" ] || { echo "FATAL: no daily.cvd after freshclam"; exit 1; }
}

# ── Manifest: the exact file list BOTH engines will scan ─────────────────────
build_manifest() {
  say "building manifest from $CORPUS (limit=${LIMIT:-all}, seed=$SEED)"
  # `shuf` with a fixed random source so a sampled run is reproducible: the same
  # LIMIT and SEED select the same files, which is what makes two runs
  # comparable at all.
  # `find -printf` gives size and path in ONE pass. The obvious version — pipe
  # paths into a shell loop and `stat` each — spawns a process per file and took
  # 3m47s over 18.5k files, which is longer than scanning a good few of them.
  find "$CORPUS" -type f \
    ! -name '*.py' ! -name '*.sh' ! -name '*.json' ! -name '*.md' \
    -printf '%s\t%p\n' 2>/dev/null \
    | awk -F'\t' -v max="$MAXSZ" '$1 > 0 && $1 <= max { sub(/^[^\t]*\t/, ""); print }' \
    | grep -v '/\.venv/' \
    | shuf --random-source=<(yes "$SEED") \
    > "$MANIFEST.tmp"
  if [ "$LIMIT" -gt 0 ]; then
    head -n "$LIMIT" "$MANIFEST.tmp" > "$MANIFEST"
  else
    mv "$MANIFEST.tmp" "$MANIFEST"
  fi
  rm -f "$MANIFEST.tmp"
  local n
  n=$(wc -l < "$MANIFEST")
  # An empty manifest is not an empty run: every later phase "succeeds" over
  # nothing and the report reads as a clean sweep. Fail where the cause is
  # visible (wrong CORPUS, everything over MAXSZ, a find that matched nothing).
  [ "$n" -gt 0 ] || { echo "FATAL: manifest is empty — is CORPUS=$CORPUS right, and MAXSZ=$MAXSZ not excluding everything?"; exit 1; }
  say "manifest: $n files"
}

# A cache built from a different manifest or profile cannot be reused: it would
# answer for files this run never selected, or under flags it never used.
check_cache() {
  local tsv=$1 stamp="$1.profile" now
  now="$(current_profile)"
  if [ -f "$tsv" ] && [ -s "$stamp" ] && [ "$(cat "$stamp")" != "$now" ]; then
    say "WARNING: $tsv was built under [$(cat "$stamp")], now [$now] — discarding"
    rm -f "$tsv"
  fi
  printf '%s' "$now" > "$stamp"
}

# ── Phase 1: clamd ───────────────────────────────────────────────────────────
phase_clam() {
  need_signatures
  [ "$FRESH_CLAM" = 1 ] && rm -f "$CLAM_TSV"
  check_cache "$CLAM_TSV"
  local todo have
  todo=$(wc -l < "$MANIFEST")
  # Count ANSWERED rows, not all rows. An ERROR row records that the scan did
  # not happen (timeout, refused connection, a daemon that died mid-run), and
  # `difftest-scan.py` deliberately does not cache those so the next pass retries
  # them. Counting them here would defeat that: the phase would skip on a table
  # that is nominally complete and actually full of holes. Measured: a clamd
  # container OOM-killed part-way through left 2,525 of 8,978 rows as ERROR,
  # which under a raw row count would have been skipped forever.
  if [ -f "$CLAM_TSV" ]; then
    have=$(awk -F'\t' 'NR>1 && $3!="ERROR"' "$CLAM_TSV" | wc -l)
    if [ "$have" -ge "$todo" ]; then
      say "phase 1: clam results already cached ($have answered rows) — skipping"
      return 0
    fi
    say "phase 1: cache has $have answered of $todo — rescanning the rest"
  fi

  say "phase 1: starting clamd"
  mkdir -p "$SOCK_DIR"
  rm -f "$CSOCK"
  local conf="$TMPROOT/clamd-difftest.conf"
  cat > "$conf" <<CONF
DatabaseDirectory /var/lib/clamav
LocalSocket /tmp/clamd.sock
LocalSocketMode 666
Foreground yes
MaxThreads $JOBS
MaxScanSize 2000M
MaxFileSize 2000M
CONF
  # Without this clamd REFUSES ALLMATCHSCAN, and the refusal looks like a clean
  # file — every reply would read OK and the whole run would be silently void.
  echo "AllowAllMatchScan yes" >> "$conf"
  if [ "$HEURISTICS" = 1 ]; then
    cat >> "$conf" <<'HEUR'
AlertEncryptedArchive yes
AlertEncryptedDoc yes
AlertOLE2Macros yes
AlertBrokenExecutables yes
AlertBrokenMedia yes
AlertExceedsMax yes
AlertPhishingSSLMismatch yes
AlertPhishingCloak yes
AlertPartitionIntersection yes
HEUR
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  # The corpus is bind-mounted at the SAME absolute path inside the container,
  # so a plain `SCAN <path>` works and no file descriptor has to be passed. That
  # is both simpler and faster than `--fdpass`.
  docker run -d --name "$CONTAINER" --entrypoint clamd \
    -v "$DBDIR":/var/lib/clamav:ro \
    -v "$SOCK_DIR":/tmp \
    -v "$CORPUS":"$CORPUS":ro \
    -v "$conf":/etc/clamav/clamd.conf:ro \
    --memory="$MEMORY" \
    "$IMAGE" --foreground --config-file=/etc/clamav/clamd.conf >/dev/null || {
      echo "FATAL: could not start the clamd container"; exit 1; }
  # clamd loads ~340k signatures before it binds the socket, and with the alert
  # classes on it took 7 MINUTES here — a 3-minute wait failed the run for no
  # reason. Wait generously: the cost of waiting is nothing next to the cost of
  # a wasted phase.
  local waited=0
  while [ "$waited" -lt "$CLAMD_START_TMO" ]; do
    [ -S "$CSOCK" ] && break
    docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true || {
      echo "FATAL: clamd container exited after ${waited}s"
      docker logs "$CONTAINER" 2>&1 | tail -20; exit 1; }
    sleep 5; waited=$((waited + 5))
    [ $((waited % 60)) -eq 0 ] && say "  still waiting for clamd (${waited}s)…"
  done
  [ -S "$CSOCK" ] || {
    echo "FATAL: clamd socket never appeared after ${CLAMD_START_TMO}s"
    docker logs "$CONTAINER" 2>&1 | tail -20; exit 1; }
  say "phase 1: clamd ready after ${waited}s — scanning"

  python3 scripts/difftest-scan.py --socket "$CSOCK" --manifest "$MANIFEST" \
    --out "$CLAM_TSV" --timeout "$TMO" --jobs "$JOBS" --label clam

  # Save the log BEFORE removing the container — `cleanup()` also does this, but
  # only on script EXIT, by which time this `rm` has already destroyed the
  # evidence. The log is the sole record of clamd's own bail-outs (a single run
  # showed 119 bytecode-interpreter timeouts on one program, plus hundreds of
  # JPEG parser warnings), and those explain whole classes of EXAV_ONLY / FN rows
  # that are otherwise unattributable.
  docker logs "$CONTAINER" >"$TMPROOT/difftest-clamd.log" 2>&1 || true
  # A daemon that died mid-run turns every remaining file into an ERROR row, and
  # a stale socket makes those fail instantly — so the run *finishes*, fast, with
  # a table full of holes. Say so plainly; the row count alone looks like success.
  if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    say "WARNING: clamd was NOT running at the end of the phase — it died mid-run."
    say "         Re-run PHASE=clam to retry the ERROR rows; see $TMPROOT/difftest-clamd.log"
    say "         If it was OOM-killed (log ends mid-line, no shutdown message), raise MEMORY=$MEMORY."
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  say "phase 1: done, clamd stopped"
}

# ── Phase 2: exav ────────────────────────────────────────────────────────────
phase_exav() {
  [ -x "$EXAV" ] || { echo "FATAL: $EXAV not built (cargo build --release -p exav)"; exit 1; }
  # A rebuilt exav can bump the database format, making a stale database
  # unloadable — but `--build-db` needs several GB of RAM, so do NOT rebuild
  # merely because the binary is newer. Rebuild when it is missing or fails to
  # LOAD, which is the failure that actually matters.
  local need=0
  if [ ! -f "$DB" ]; then need=1
  elif [ "$EXAV" -nt "$DB" ]; then
    mkdir -p "$SOCK_DIR"; : > "$SOCK_DIR/.probe"
    "$EXAV" -d "$DB" "$SOCK_DIR/.probe" >/dev/null 2>&1 \
      && { say "phase 2: database older than the binary but loads — reusing"; touch "$DB"; } \
      || need=1
  fi
  if [ "$need" = 1 ]; then
    need_signatures
    say "phase 2: building the exav database from $DBDIR"
    local avail shard=""
    avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    [ "$avail" -gt 0 ] && [ "$avail" -lt 8000000 ] && shard="--build-shard-bytes ${BUILD_SHARD_BYTES:-1G}"
    # shellcheck disable=SC2086
    "$EXAV" -d "$DBDIR" --build-db "$DB" $shard || {
      echo "FATAL: exav database build failed (it needs several GB of FREE RAM)"; exit 1; }
  fi

  # exav's results are NOT cached across binaries — that is the entire reason for
  # re-running it — so the table is rebuilt unless the caller kept it on purpose.
  [ "${KEEP_EXAV:-0}" = 1 ] || rm -f "$EXAV_TSV"
  check_cache "$EXAV_TSV"

  # Size the daemon to the concurrency this run actually drives, and give a job
  # the same budget the client waits. Both matter, and getting either wrong is
  # invisible in the results:
  #
  #   * exav preforks one worker PER CORE by default — 2 here. Sending 4
  #     concurrent scans meant half of them sat in the accept queue behind a
  #     long job and timed out having never been looked at. That records as
  #     ERROR, which reads as a compliance difference and is not one. Measured:
  #     27 of 40 files "failed" this way, with 13 worker deaths.
  #   * `--max-scan-time` defaults to 120s. If the client's own timeout is
  #     longer, a killed worker looks like a slow file; if shorter, the client
  #     gives up on work the daemon then completes for nobody. Keep them equal.
  local flags="--workers $JOBS --max-scan-secs ${TMO%.*}"
  [ "$COMPAT" = 1 ] && flags="$flags --clamav-compat"
  # Cover every alert class clamd was configured with. Anything clamd is asked
  # to alert on and exav is not becomes a fake FN — the file is bucketed as
  # "clam detected, exav did not" when exav was never asked to look. Measured
  # before these were added: 150 of 258 FNs, dominated by 119
  # Heuristics.Broken.Executable and 33 Heuristics.Limits.Exceeded.*.
  #
  # Two flags, because the AlertX directives are two different questions.
  # `--detect` is "also look for this", and covers AlertOLE2Macros,
  # AlertBrokenExecutables, AlertBrokenMedia, AlertPhishing* and
  # AlertPartitionIntersection. `--partial-as` is "what becomes of an object
  # exav could not fully examine", and that is what AlertEncryptedArchive /
  # AlertEncryptedDoc and AlertExceedsMax actually are: ClamAV reports both as
  # `Heuristics.* FOUND`, so exav has to as well or the same file is a PARTIAL
  # here and a detection there. `unscannable` is deliberately left at the
  # default — ClamAV has no flag for it, so making it a detection would invent a
  # disagreement rather than remove one.
  #
  # Keep both in step with the AlertX lines in the clamd conf above; they are
  # two halves of one setting.
  if [ "$HEURISTICS" = 1 ]; then
    flags="$flags --detect macros,broken,broken-media,phishing,partition-intersection"
    flags="$flags --partial-as password-protected=found,limits-exceeded=found"
  fi
  say "phase 2: starting the exav daemon ($flags)"
  pkill -x exav 2>/dev/null; sleep 0.5; rm -f "$ESOCK"
  # shellcheck disable=SC2086
  "$EXAV" $flags --listen "$ESOCK" -d "$DB" >"$TMPROOT/difftest-exav-daemon.log" 2>&1 &
  EXAV_PID=$!
  for _ in $(seq 1 60); do [ -S "$ESOCK" ] && break; sleep 2; done
  [ -S "$ESOCK" ] || {
    echo "FATAL: exav socket never appeared:"; tail -5 "$TMPROOT/difftest-exav-daemon.log"; exit 1; }
  say "phase 2: exav ready — scanning"

  python3 scripts/difftest-scan.py --socket "$ESOCK" --manifest "$MANIFEST" \
    --out "$EXAV_TSV" --timeout "$TMO" --jobs "$JOBS" --label exav
  kill "$EXAV_PID" 2>/dev/null; EXAV_PID=""
  say "phase 2: done, exav stopped"
  # Worker deaths are the difference between "exav disagreed" and "exav never
  # got to answer", and they are only visible here.
  # `grep -c` prints 0 AND exits 1 when nothing matches, so `|| echo 0` would
  # make this "0\n0" and the numeric test below an error. Assign on failure.
  local dead
  dead=$(grep -c "worker .* exited" "$TMPROOT/difftest-exav-daemon.log" 2>/dev/null) || dead=0
  [ "$dead" -gt 0 ] && say "NOTE: $dead worker exits (timeout/OOM) — see $TMPROOT/difftest-exav-daemon.log"
}

# ── Phase 3: compare ─────────────────────────────────────────────────────────
phase_compare() {
  [ -f "$CLAM_TSV" ] && [ -f "$EXAV_TSV" ] || {
    echo "FATAL: need both $CLAM_TSV and $EXAV_TSV"; exit 1; }
  echo
  echo "=============== $PROFILE ==============="
  python3 scripts/difftest-compare.py --clam "$CLAM_TSV" --exav "$EXAV_TSV" \
    --show "$SHOW" --out "$JOINED"
}

case "$PHASE" in
  all)     build_manifest; phase_clam; phase_exav; phase_compare ;;
  clam)    build_manifest; phase_clam ;;
  exav)    [ -f "$MANIFEST" ] || build_manifest; phase_exav ;;
  compare) phase_compare ;;
  *) echo "PHASE must be one of: all clam exav compare"; exit 2 ;;
esac
