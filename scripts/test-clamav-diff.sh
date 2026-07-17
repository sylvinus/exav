#!/usr/bin/env bash
# Daemon-based differential test: exav vs clamscan on the SAME signature DB.
#
# Both engines run as resident daemons (loaded once), so per-file timing is the
# real steady-state scan cost with no DB-reload. Files are taken in random
# (`shuf`) order and the run is RESUMABLE — already-scanned paths are skipped, so
# repeated short runs accumulate coverage. Stops after $DUR seconds or when
# killed; partial results are always in the log.
#
#   DUR=300 scripts/test-clamav-diff.sh           # 5 min, --clamav-compat (default)
#   COMPAT=0 DUR=300 scripts/test-clamav-diff.sh  # full exav capability
#
# By default exav runs at `--clamav-compat` (clam limits/formats) for an
# apples-to-apples comparison. Set COMPAT=0 to scan at full exav capability.
#
# The script manages the full daemon lifecycle: it starts clamd (in Docker) and
# the exav daemon, runs the comparison, and tears everything down on exit.
# No prereq steps — just run this.
set -u

# ── Tunables ─────────────────────────────────────────────────────────────────
DUR="${DUR:-300}"
TMO="${TMO:-10}"                      # per-file per-engine wall-clock cap (seconds)
MAXSZ="${MAXSZ:-20971520}"            # skip files > 20 MB (buffer-everything OOM guard)
# COMPAT=1 (default): run exav at `--clamav-compat` — clam's documented limits,
# clam-only formats, unofficial-name suffixing — for an apples-to-apples diff.
# COMPAT=0: run exav at FULL capability (its own extractors + limits), which
# surfaces detections/handling clamd lacks (expect more exav-only hits).
COMPAT="${COMPAT:-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXAV="${EXAV:-$ROOT/target/release/exav}"
ESOCK="${ESOCK:-/tmp/exav.sock}"
CORPUS="${CORPUS:-$ROOT/corpus/samples}"
LOGDIR="${LOGDIR:-/tmp/difftest}"; mkdir -p "$LOGDIR"; LOG="$LOGDIR/results.tsv"
[ -f "$LOG" ] || printf 'path\tclam\texav\tverdict\tclam_ms\texav_ms\n' > "$LOG"

# clamd Docker settings
IMAGE="clamav/clamav-debian:latest"
CONTAINER="clamd-diff"
DBDIR="${DBDIR:-/tmp/difdb_daily}"
# clamd extracts EVERY scanned file's members into its container `/tmp`, which we
# bind-mount from $SOCK_DIR (see the `docker run -v "$SOCK_DIR":/tmp` below). That
# dir MUST live on real disk, NOT a RAM-backed tmpfs: a big archive scan can pile
# up gigabytes of extraction temp, and if the container is killed mid-scan the
# temp leaks there — on tmpfs that silently exhausts RAM and wedges the whole box.
# So default it off `/tmp` whenever `/tmp` is tmpfs. Override with TMPROOT/SOCK_DIR.
is_tmpfs() { [ "$(stat -f -c %T "$1" 2>/dev/null)" = tmpfs ]; }
if [ -z "${TMPROOT:-}" ]; then
  if is_tmpfs /tmp && [ -d /var/tmp ] && ! is_tmpfs /var/tmp; then TMPROOT=/var/tmp; else TMPROOT=/tmp; fi
fi
SOCK_DIR="${SOCK_DIR:-$TMPROOT/clamd_diff_sock}"
CCONF="${SOCK_DIR}/clamd.sock"
CLAMD_CLIENT_CONF="/tmp/clamd_daily.conf"
MEMORY="${MEMORY:-3g}"

# ── Cleanup on exit ──────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "--- tearing down ---"
  pkill -x exav 2>/dev/null || true
  sleep 0.5
  pkill -9 -x exav 2>/dev/null || true
  docker rm -f "$CONTAINER" 2>/dev/null || true
  rm -f "$ESOCK" "$CCONF" 2>/dev/null || true
  echo "engines stopped."
}
trap cleanup EXIT

# ── Build/refresh the exav prebuilt cache ────────────────────────────────────
# A rebuilt exav CAN bump the cache format, making a stale cache unloadable (the
# daemon then exits and the socket never appears). But `--build-cache` needs
# several GB RAM and OOM-dies on a small host — so we do NOT blindly rebuild just
# because the binary is newer. Instead: rebuild only if the cache is missing or
# fails to LOAD with this binary (the real failure we care about); if it still
# loads, reuse it (a format-compatible binary change needs no rebuild).
CACHE="${CACHE:-/tmp/daily.cache}"
cache_loads() { printf '' >"$SOCK_DIR/.probe" 2>/dev/null || return 1; "$EXAV" -d "$CACHE" "$SOCK_DIR/.probe" >/dev/null 2>&1; }
need_build=0
if [ ! -f "$CACHE" ]; then
  need_build=1
elif [ "$EXAV" -nt "$CACHE" ]; then
  mkdir -p "$SOCK_DIR"
  if cache_loads; then
    echo "cache is older than the binary but loads fine — reusing (skipping the RAM-heavy rebuild)."
    touch "$CACHE"
  else
    need_build=1
  fi
fi
if [ "$need_build" = 1 ]; then
  echo "building exav cache from $DBDIR ..."
  "$EXAV" -d "$DBDIR" --build-cache "$CACHE" || {
    echo "FATAL: exav cache build failed — it needs several GB of FREE RAM."
    echo "  Note /tmp here is tmpfs (RAM), so cache/temp there compete with the build."
    echo "  Fix: free RAM (stop other engines) and retry, or put CACHE + TMPROOT on disk,"
    echo "       e.g.  CACHE=/var/tmp/daily.cache TMPROOT=/var/tmp $0"
    exit 1
  }
fi

# ── Start exav daemon ───────────────────────────────────────────────────────
COMPAT_FLAG=""
[ "$COMPAT" = 1 ] && COMPAT_FLAG="--clamav-compat"
echo "starting exav daemon (${COMPAT:+COMPAT=$COMPAT }${COMPAT_FLAG:-full-capability})..."
pkill -x exav 2>/dev/null || true; sleep 0.5; rm -f "$ESOCK"
# shellcheck disable=SC2086
nohup "$EXAV" $COMPAT_FLAG --daemon -d "$CACHE" --socket "$ESOCK" >/tmp/exav-daemon.log 2>&1 &
for i in $(seq 1 60); do
  [ -S "$ESOCK" ] && break
  sleep 2
done
[ -S "$ESOCK" ] || {
  echo "FATAL: exav socket never appeared; daemon log:"; tail -5 /tmp/exav-daemon.log
  exit 1
}
echo "exav daemon ready."

# ── Start clamd in Docker ───────────────────────────────────────────────────
echo "starting clamd in Docker..."
docker rm -f "$CONTAINER" 2>/dev/null || true
mkdir -p "$SOCK_DIR"
CLAMD_CONF="/tmp/clamd_docker.conf"
cat > "$CLAMD_CONF" <<CONF
DatabaseDirectory /var/lib/clamav
LocalSocket /tmp/clamd.sock
LocalSocketMode 666
Foreground yes
MaxThreads 4
MaxScanSize 2000M
MaxFileSize 2000M
CONF
# Override the image entrypoint to run clamd directly: the default entrypoint
# runs freshclam first, which would DOWNLOAD main.cvd into the DB dir and make
# clamd scan with main+daily while exav uses only what we mounted — an invalid
# comparison (every main.cvd-only hit would look like an exav false-negative).
# Running clamd directly loads ONLY the mounted DB, exactly matching exav.
docker run -d \
  --name "$CONTAINER" \
  --network=host \
  --entrypoint clamd \
  -v "$DBDIR":/var/lib/clamav \
  -v "$SOCK_DIR":/tmp \
  -v "$CLAMD_CONF":/etc/clamav/clamd.conf:ro \
  --memory="$MEMORY" \
  "$IMAGE" --foreground --config-file=/etc/clamav/clamd.conf >/dev/null
for i in $(seq 1 60); do
  [ -S "$CCONF" ] && break
  docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true || {
    echo "FATAL: clamd container exited"
    docker logs "$CONTAINER" 2>&1 | tail -20
    exit 1
  }
  sleep 2
done
  [ -S "$CCONF" ] || { echo "FATAL: clamd socket never appeared"; exit 1; }
  echo "clamd ready."

# ── Write clamdscan client config ────────────────────────────────────────────
cat > "$CLAMD_CLIENT_CONF" <<CLIENTCONF
LocalSocket $CCONF
CLIENTCONF

# ── Preflight: both engines must detect a known sample before we start ───────
# Use EICAR, not a corpus sample: it's carried by daily.cvd's Eicar-Test-Signature
# (and exav's baseline), so the check is valid for ANY DB scope. A corpus sample
# only works if the mounted DB happens to cover it — e.g. most Locky detections
# live in main.cvd, so with a daily-only DB both engines correctly return OK and
# a corpus-based preflight would false-fail.
echo "preflight check..."
PF="$(mktemp /tmp/exav_eicar.XXXXXX)"
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$PF"
e_out=$("$EXAV" --socket "$ESOCK" "$PF" 2>&1); e_rc=$?
c_out=$(clamdscan --config-file="$CLAMD_CLIENT_CONF" --no-summary --fdpass "$PF" 2>&1); c_rc=$?
rm -f "$PF"
if ! echo "$e_out" | grep -q FOUND; then
  echo "FATAL: exav preflight failed (rc=$e_rc): $e_out"
  exit 1
fi
if ! echo "$c_out" | grep -q FOUND; then
  echo "FATAL: clamd preflight failed (rc=$c_rc): $c_out"
  exit 1
fi
echo "preflight OK — both engines detect EICAR."

# ── Resume: remember everything already scanned ──────────────────────────────
declare -A DONE
while IFS= read -r p; do DONE["$p"]=1; done < <(tail -n +2 "$LOG" | cut -f1)

sig() { sed -n 's/.*: \(.*\) FOUND$/\1/p' | head -1; }
# exav verdict: the matched signature, or a `!`-prefixed marker for the
# non-clean verdicts clam doesn't have (exav flags content it couldn't fully
# scan instead of silently returning OK). The `!` prefix can't collide with a
# signature name, so the bucketing tells these apart from real detections.
everdict() {
  awk '
    /: .* FOUND$/        { s=$0; sub(/.*: /,"",s); sub(/ FOUND$/,"",s); print s; exit }
    /UNSCANNABLE/        { print "!UNSCANNABLE"; exit }
    /PASSWORD-PROTECTED/ { print "!PASSWORD-PROTECTED"; exit }
    /LIMITS-EXCEEDED/    { print "!LIMITS-EXCEEDED"; exit }
  '
}

deadline=$((SECONDS + DUR)); n=0
while IFS= read -r f; do
  [ $SECONDS -ge $deadline ] && break
  [ -n "${DONE[$f]:-}" ] && continue
  sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
  { [ "$sz" -le 0 ] || [ "$sz" -gt "$MAXSZ" ]; } && continue

  # --- exav scan ---
  t0=$(date +%s%3N)
  e_raw=$(timeout "$TMO" "$EXAV" --socket "$ESOCK" "$f" 2>&1)
  e_rc=$?
  t1=$(date +%s%3N)
  ems=$((t1-t0))
  e=$(echo "$e_raw" | everdict)
  if [ -z "$e" ]; then
    if [ $e_rc -eq 124 ]; then
      e="ERROR"  # timeout
    elif [ $e_rc -ge 2 ] && ! echo "$e_raw" | grep -q FOUND; then
      e="ERROR"  # connection refused, crash, etc. (but not if FIND was reported)
    else
      e="-"
    fi
  fi

  # --- clamdscan scan ---
  t0=$(date +%s%3N)
  c_raw=$(timeout "$TMO" clamdscan --config-file="$CLAMD_CLIENT_CONF" --no-summary --fdpass "$f" 2>&1)
  c_rc=$?
  t1=$(date +%s%3N)
  cms=$((t1-t0))
  c=$(echo "$c_raw" | sig)
  if [ -z "$c" ]; then
    if [ $c_rc -eq 124 ]; then
      c="ERROR"  # timeout
    elif [ $c_rc -ge 2 ] && ! echo "$c_raw" | grep -qiE 'FOUND|OK'; then
      c="ERROR"  # connection refused, crash, etc.
    else
      c="-"
    fi
  fi

  # Buckets. A `!`-prefixed exav verdict means it flagged the file as not fully
  # scanned (UNSCANNABLE/PASSWORD-PROTECTED/LIMITS-EXCEEDED) — never a silent
  # miss. That's an *expected capability difference* vs clam (which returns OK),
  # not an FP; and if clam DID detect, it's CAREFUL_FN (exav refused to call it
  # clean) rather than a plain FN.
  case "$e" in
    ERROR)  v=ERROR ;;
    '!'*) [ "$c" = - ] && v=CAREFUL || v=CAREFUL_FN ;;
    -)    [ "$c" = - ] && v=clean   || v=FN ;;
    *)    if   [ "$c" = - ];      then v=FP
          elif [ "$c" = "$e" ];   then v=AGREE
          else                         v=NAMEDIFF; fi ;;
  esac
  # If clamd also errored, the comparison is invalid — mark as ERROR too.
  [ "$c" = "ERROR" ] && [ "$v" != "ERROR" ] && v=ERROR

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$c" "$e" "$v" "$cms" "$ems" >> "$LOG"
  DONE["$f"]=1; n=$((n+1))
done < <(find "$CORPUS" -type f ! -name '*.py' ! -name '*.sh' ! -name '*.json' ! -name '*.md' 2>/dev/null | grep -v '/.venv/' | shuf)

echo "scanned this run: $n   total logged: $(($(wc -l < "$LOG") - 1))"
awk -F'\t' 'NR>1{t[$4]++; if($5+0>0)cm+=$5; if($6+0>0)em+=$6; k++}
  END{for(x in t)printf "  %-7s %d\n",x,t[x]; if(k)printf "avg ms: clam=%.0f exav=%.0f (n=%d)\n",cm/k,em/k,k}' "$LOG"
echo "=== errors (scan failed — daemon down or file unreadable) ==="
awk -F'\t' '$4=="ERROR"{print "  clam="$2" exav="$3"  "$1}' "$LOG" | head -20
echo "=== false negatives (clam found, exav silently missed) ==="
awk -F'\t' '$4=="FN"{print "  "$2"  "$1}' "$LOG" | head -20
echo "=== false positives (exav found, clam clean) ==="
awk -F'\t' '$4=="FP"{print "  "$3"  "$1}' "$LOG" | head -20
echo "=== exav more-careful (exav flagged not-fully-scanned, clam said OK — expected capability diff, NOT an FP) ==="
awk -F'\t' '$4=="CAREFUL"{print "  "$3"  "$1}' "$LOG" | head -20
echo "=== careful-FN (clam found; exav flagged not-fully-scanned rather than silently clean) ==="
awk -F'\t' '$4=="CAREFUL_FN"{print "  clam="$2" exav="$3"  "$1}' "$LOG" | head -20
