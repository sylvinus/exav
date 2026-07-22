#!/usr/bin/env bash
# Fetch the free unofficial ClamAV signature feeds that add the most coverage for
# our differential corpus's misses — TwinWave (EvilDoc, malicious Office docs) and
# Sanesecurity (BadMacro / Shelter / Foxhole / Porcupine) — over plain HTTPS (no
# rsync needed). exav loads these standard `.ndb`/`.ldb`/`.hdb`/`.hsb`/`.cdb`
# databases the same as `daily.cvd`.
#
#   scripts/fetch-unofficial-sigs.sh [DEST]        # DEST default: corpus/unofficial
#
# Analysis behind the choice (see scripts/clamav-sources.py): ~85% of both-clean
# MalwareBazaar misses are caught by *some* ClamAV feed; TwinWave + Sanesecurity
# alone cover ~36% of ours, at zero cost. These feeds are heavily Office-macro
# focused, which is exactly our largest miss class.
#
# LICENSES / TERMS (not redistributed here — fetched at runtime, DEST is gitignored):
#   * TwinWave twinclams — BSD-2-Clause (github.com/twinwave-security/twinclams).
#   * Sanesecurity — free for use under Sanesecurity's terms; see sanesecurity.org.
#     For production/mirrored use prefer rsync + the official clamav-unofficial-sigs
#     tool (github.com/extremeshok/clamav-unofficial-sigs) to respect mirror load.
set -euo pipefail

DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/corpus/unofficial}"
TW_BASE="${TW_BASE:-https://raw.githubusercontent.com/twinwave-security/twinclams/master}"
SS_MIRROR="${SS_MIRROR:-https://mirror.rollernet.us/sanesecurity}"

# TwinWave: logical sigs + hashes + ignore list.
TW_FILES=(twinclams.ldb twinclams.hdb twinwave.ign2)
# Sanesecurity: the macro/malware DBs that hit our misses (not the spam/phish set).
SS_FILES=(
  badmacro.ndb shelter.ldb
  foxhole_filename.cdb foxhole_generic.cdb foxhole_js.cdb foxhole_js.ndb
  porcupine.ndb porcupine.hsb
)

mkdir -p "$DEST"
fetch() { # url dest
  local code
  code=$(curl -fsSL -w '%{http_code}' -o "$2.tmp" "$1" 2>/dev/null) || { rm -f "$2.tmp"; echo "  MISS $(basename "$2")"; return 0; }
  if [ "$code" = 200 ] && [ -s "$2.tmp" ]; then
    mv "$2.tmp" "$2"; echo "  ok   $(basename "$2")  ($(wc -c <"$2") bytes)"
  else
    rm -f "$2.tmp"; echo "  MISS $(basename "$2") ($code)"
  fi
}

echo "TwinWave  -> $DEST"
for f in "${TW_FILES[@]}"; do fetch "$TW_BASE/$f" "$DEST/$f"; done
echo "Sanesecurity ($SS_MIRROR) -> $DEST"
for f in "${SS_FILES[@]}"; do fetch "$SS_MIRROR/$f" "$DEST/$f"; done

echo
echo "done. Load into exav alongside the official DB, e.g.:"
echo "  exav -d $DEST --build-db /tmp/unofficial.exavdb"
echo "  exav -d /tmp/unofficial.exavdb <target>        # or point -d at a dir holding both sets"
