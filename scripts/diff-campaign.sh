#!/usr/bin/env bash
# 4-hour exav-vs-clamscan differential campaign.
#
#   1. Grow the corpus from MalwareBazaar (up to ~40 min), so the run has enough
#      distinct samples to fill the budget.
#   2. Run the daemon-based differential test (scripts/test-clamav-diff.sh) on the
#      enlarged corpus for the remaining budget, with the freshly-built binary.
#
# Total wall-clock budget: BUDGET seconds (default 14400 = 4h). Live malware —
# static scan only; corpus/ is gitignored.
set -u
cd "$(dirname "$0")/.." || exit 1

BUDGET="${BUDGET:-14400}"
FETCH_CAP="${FETCH_CAP:-2400}"          # max seconds spent growing the corpus
LOGDIR=/tmp/difftest
mkdir -p "$LOGDIR"
CLOG="$LOGDIR/campaign.log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$CLOG"; }

# Fresh comparison: archive any prior (older-binary) results so every file is
# re-scanned with the current binary. The run itself stays resumable within this
# campaign (crash-safe).
if [ -f "$LOGDIR/results.tsv" ]; then
  mv "$LOGDIR/results.tsv" "$LOGDIR/results-prev-$(date +%s).tsv"
fi

START=$SECONDS
log "campaign start (budget ${BUDGET}s); corpus has $(find corpus/samples -type f 2>/dev/null | wc -l) files"

# ── Phase 1: grow the corpus ────────────────────────────────────────────────
log "phase 1: fetching more samples (cap ${FETCH_CAP}s)…"
timeout "$FETCH_CAP" python3 scripts/fetch-corpus-bulk.py 500 30000 >>"$CLOG" 2>&1
log "phase 1 done; corpus now has $(find corpus/samples -type f 2>/dev/null | wc -l) files"

# ── Phase 2: differential test for the remaining budget ─────────────────────
ELAPSED=$((SECONDS - START))
REMAIN=$((BUDGET - ELAPSED))
[ "$REMAIN" -lt 600 ] && REMAIN=600
log "phase 2: differential test for ${REMAIN}s"
DUR="$REMAIN" scripts/test-clamav-diff.sh >>"$CLOG" 2>&1

log "campaign complete. results: $LOGDIR/results.tsv"
