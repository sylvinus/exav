#!/usr/bin/env bash
# Scan speed of exav and clamscan over the same files, one process each.
#
#   scripts/bench-speed.sh                       # the *.bin up to 1 MiB of corpus/samples
#   MAXSZ=4194304 RUNS=5 scripts/bench-speed.sh
#   CPU=1 scripts/bench-speed.sh                 # pin each run to core 1
#
# WHAT IT MEASURES
#
#   The wall time of `clamscan -f LIST` and `exav --files-from LIST` over the
#   same files and the same signatures (the directory freshclam keeps), with
#   the page cache warm, and each engine on its own. The time to load the
#   signatures is measured separately, on one tiny file, and taken off, so the
#   figure is the time to scan, not to start.
#
#   The default set is every file of the corpus up to MAXSZ bytes, because the
#   whole set has to stay in the page cache: a bigger one makes the first
#   engine pay for the disk and the second read it warm, which is how an
#   earlier comparison of these two ended up unusable (see
#   docs/COMPARISON_NOTES.md).
#
#   Three rows: ClamAV, exav as shipped, and exav under --clamav-compat (the
#   limits and the extractors of a stock ClamAV, so the work per file is the
#   nearest the two come to equal).
#
# WHAT IT DOES NOT
#
#   It is one machine, one corpus and one signature set. It is no claim about
#   other hardware, other files, or the daemons (clamd against `exav --listen`),
#   which pay the load once and scan in parallel.
#
# REQUIREMENTS: a release build of exav (`cargo build --release -p exav`),
# clamscan, /usr/bin/time, and a corpus directory. corpus/ is gitignored.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${CORPUS:-$ROOT/corpus/samples}"
MAXSZ="${MAXSZ:-1048576}"
# The corpus keeps a .json of metadata beside each sample; only the samples count.
NAME="${NAME:-*.bin}"
RUNS="${RUNS:-3}"
DB="${DB:-/var/lib/clamav}"
EXAV="${EXAV:-$ROOT/target/release/exav}"
CLAMSCAN="${CLAMSCAN:-clamscan}"
CPU="${CPU:-}"
OUT="${OUT:-$ROOT/target/bench}"

for need in "$EXAV" "$CLAMSCAN"; do
  command -v "$need" >/dev/null 2>&1 || { echo "error: $need not found" >&2; exit 1; }
done
[ -d "$CORPUS" ] || { echo "error: no corpus at $CORPUS" >&2; exit 1; }
mkdir -p "$OUT"

pin=()
[ -n "$CPU" ] && pin=(taskset -c "$CPU")

LIST="$OUT/files.txt"
find "$CORPUS" -type f -name "$NAME" -size -$((MAXSZ + 1))c | LC_ALL=C sort > "$LIST"
FILES=$(wc -l < "$LIST")
BYTES=$(xargs -d '\n' stat -c %s < "$LIST" | awk '{s += $1} END {print s}')
echo "files: $FILES, bytes: $BYTES (up to $MAXSZ each)"
echo "engines: $("$CLAMSCAN" --version | head -1); $("$EXAV" --version)"

# Warm the page cache, twice, so the first timed run reads no disk.
xargs -d '\n' cat < "$LIST" > /dev/null
xargs -d '\n' cat < "$LIST" > /dev/null

# A file every engine knows, to time the start alone.
EICAR="$OUT/eicar.com"
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-' 'TEST-FILE!$H+H*' > "$EICAR"
printf '%s\n' "$EICAR" > "$OUT/one.txt"

# run NAME CMD...: wall user sys peak-KiB into $OUT/NAME.time, output into NAME.out
run() {
  local name="$1"
  shift
  /usr/bin/time -f '%e %U %S %M' -o "$OUT/$name.time" "${pin[@]}" "$@" > "$OUT/$name.out" 2>/dev/null || true
  # A non-zero exit (a detection) makes time(1) add a line before its own.
  tail -n 1 "$OUT/$name.time" > "$OUT/$name.time.tmp"
  mv "$OUT/$name.time.tmp" "$OUT/$name.time"
}

engine_cmd() {
  local engine="$1" list="$2"
  case "$engine" in
    clamscan) echo "$CLAMSCAN -d $DB --no-summary -f $list" ;;
    exav) echo "$EXAV -d $DB --files-from $list" ;;
    exav-compat) echo "$EXAV -d $DB --clamav-compat --files-from $list" ;;
  esac
}

median() { sort -n | awk '{a[NR] = $1} END {print a[int((NR + 1) / 2)]}'; }

declare -A LOAD
for engine in clamscan exav exav-compat; do
  : > "$OUT/$engine.load"
  for i in 1 2 3; do
    run "$engine.load" $(engine_cmd "$engine" "$OUT/one.txt")
    cut -d' ' -f1 "$OUT/$engine.load.time" >> "$OUT/$engine.load"
  done
  LOAD[$engine]=$(median < "$OUT/$engine.load")
  echo "$engine start (signatures loaded, one file): ${LOAD[$engine]} s"
done

# Interleave the engines, so a drift in the machine hits each of them.
for r in $(seq 1 "$RUNS"); do
  for engine in clamscan exav exav-compat; do
    run "$engine.$r" $(engine_cmd "$engine" "$LIST")
    echo "$engine run $r: $(cat "$OUT/$engine.$r.time")"
  done
done

echo
echo "| Engine | Start | Scan (median of $RUNS) | Files/s | MB/s | CPU user | Peak memory | Infected |"
echo "|---|---|---|---|---|---|---|---|"
for engine in clamscan exav exav-compat; do
  wall=$(for r in $(seq 1 "$RUNS"); do cut -d' ' -f1 "$OUT/$engine.$r.time"; done | median)
  user=$(for r in $(seq 1 "$RUNS"); do cut -d' ' -f2 "$OUT/$engine.$r.time"; done | median)
  rss=$(for r in $(seq 1 "$RUNS"); do cut -d' ' -f4 "$OUT/$engine.$r.time"; done | median)
  inf=$(grep -c ' FOUND$' "$OUT/$engine.1.out" || true)
  awk -v e="$engine" -v w="$wall" -v l="${LOAD[$engine]}" -v u="$user" -v m="$rss" -v n="$FILES" -v b="$BYTES" -v i="$inf" 'BEGIN {
    s = w - l
    printf "| %s | %.1f s | %.1f s | %.0f | %.1f | %.1f s | %.0f MB | %d |\n", e, l, s, n / s, b / s / 1e6, u, m / 1024, i
  }'
done
