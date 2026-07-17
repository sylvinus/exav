#!/usr/bin/env bash
# General bytecode differential + perf harness: clamscan's bytecode engine
# (reference) vs exav's bytecode runtime (under test), over any corpus.
#
#   scripts/bc-difftest.sh [CORPUS_DIR]
#
# Env: BCDB=<bytecode.cvd>  CBC_DIR=<dir of extracted .cbc>
# Reports per-file agreement (AGREE-hit / agree-clean / false-neg / false-pos)
# and the wall-clock of each engine over the corpus.
set -u
BCDB="${BCDB:-/tmp/clamdb/bytecode.cvd}"
CBC_DIR="${CBC_DIR:-/tmp/bc}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${1:-$ROOT/corpus/samples}"

mapfile -t files < <(find "$CORPUS" -type f \
  ! -path '*/.venv/*' ! -path '*/.git/*' \
  ! -name '*.md' ! -name '*.py' ! -name '*.sh' ! -name '*.json' | sort)
echo "corpus: $CORPUS  files: ${#files[@]}"
[ "${#files[@]}" -eq 0 ] && { echo "no files"; exit 1; }

# --- exav side: one process over all files, gated scan, timed ---
exav_bin=$(cd "$ROOT" && cargo build -q -p exav-core --example bc_scan 2>/dev/null; echo "$ROOT/target/debug/examples/bc_scan")
t0=$(date +%s%3N)
"$exav_bin" "$CBC_DIR" "${files[@]}" 2>/dev/null > /tmp/exav_diff.txt
t1=$(date +%s%3N); exav_ms=$((t1-t0))

# --- clamscan side: per file (batching makes its bytecode engine miss later
# detections), bytecode-only, timed ---
t0=$(date +%s%3N)
declare -A clam
for f in "${files[@]}"; do
  sig=$(clamscan --no-summary --bytecode=yes --database="$BCDB" "$f" 2>/dev/null \
        | sed -n 's|.*: \(.*\) FOUND|\1|p' | head -1)
  [ -n "$sig" ] && clam["$f"]="$sig"
done
t1=$(date +%s%3N); cs_ms=$((t1-t0))

# --- compare ---
ah=0; ac=0; fn=0; fp=0
printf '%-40s %-26s %-26s %s\n' "FILE" "CLAMSCAN" "EXAV" "VERDICT"
for f in "${files[@]}"; do
  cs="${clam[$f]:--}"
  e=$(grep -F "$f	" /tmp/exav_diff.txt | sed -n 's/.*gated=\([^	]*\).*/\1/p'); [ -z "$e" ] && e="-"
  if   [ "$cs" != "-" ] && [ "$e" != "-" ]; then v="AGREE-hit"; ah=$((ah+1))
  elif [ "$cs" = "-" ]  && [ "$e" = "-" ];  then v="agree-clean"; ac=$((ac+1))
  elif [ "$cs" != "-" ] && [ "$e" = "-" ];  then v="FALSE-NEG"; fn=$((fn+1))
  else v="FALSE-POS"; fp=$((fp+1)); fi
  # only print non-clean rows to keep it readable
  [ "$v" != "agree-clean" ] && printf '%-40s %-26s %-26s %s\n' "$(basename "$f"|cut -c1-40)" "$(echo $cs|cut -c1-26)" "$(echo $e|cut -c1-26)" "$v"
done
echo
echo "AGREE-hit=$ah  agree-clean=$ac  FALSE-NEG=$fn  FALSE-POS=$fp   (of ${#files[@]})"
printf 'wall-clock over %d files:  exav=%d ms   clamscan=%d ms\n' "${#files[@]}" "$exav_ms" "$cs_ms"
