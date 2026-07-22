#!/usr/bin/env bash
# Measure which container members ClamAV actually REACHES, not which formats it
# claims to support.
#
# WHY: comparing feature lists answers the wrong question. ClamAV's EGG submodule
# is on by default and it still returns `OK` on an EGG whose members are LZMA or
# solid — format-level support is not member-level reach. And a signature-database
# comparison cannot separate "did not detect" from "never looked".
#
# METHOD: extract each container's members with exav, hash every member into an
# `.hdb`, then scan the UNTOUCHED container with clamscan and every alert flag it
# has. A member whose hash does not come back FOUND was never reached. Nothing
# here depends on either engine's signature set.
#
# The alert flags matter: this is ClamAV at its most talkative, so an `OK` is not
# a disabled heuristic, it is an absence of any name for the condition.
#
# USAGE:
#   scripts/clamav-reach.sh crates/exav-unpack/tests/fixtures/{lzw,wim,egg}/*
#
# GOTCHA: gunzip `.gz`-wrapped fixtures first. Otherwise this measures gzip
# rather than the inner format and reports "reached all" for images ClamAV never
# opens — a mistake made and caught while producing docs/VERDICT_PROTOCOL_PLAN.md.
#
# REQUIREMENTS: clamscan on PATH; `cargo build --release -p exav-cli` and
# `cargo build -p exav-unpack`.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNPACK="${UNPACK:-$REPO/target/debug/exav-unpack}"

if ! command -v clamscan >/dev/null 2>&1; then
  echo "error: clamscan not found; this script measures ClamAV." >&2
  exit 1
fi
if [ ! -x "$UNPACK" ]; then
  echo "error: $UNPACK missing. Run: cargo build -p exav-unpack" >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ALERTS="--allmatch --heuristic-alerts=yes --alert-broken=yes --alert-broken-media=yes
        --alert-encrypted=yes --alert-encrypted-archive=yes --alert-encrypted-doc=yes
        --alert-macros=yes --alert-exceeds-max=yes --alert-phishing-ssl=yes
        --alert-phishing-cloak=yes --alert-partition-intersection=yes"

printf '%-34s %-9s %-9s %s\n' "container" "members" "clamav" "verdict"
printf '%s\n' "----------------------------------------------------------------------"

misses=0
for f in "$@"; do
  [ -f "$f" ] || continue
  base=$(basename "$f")

  out="$WORK/$base.d"; mkdir -p "$out"
  "$UNPACK" extract "$f" "$out" >/dev/null 2>&1
  if [ "$(find "$out" -type f 2>/dev/null | wc -l | tr -d ' ')" -eq 0 ]; then
    printf '%-34s %-9s %-9s %s\n' "$base" "0" "-" "exav extracted nothing"
    continue
  fi

  db="$WORK/$base.db"; mkdir -p "$db"; : > "$db/m.hdb"
  i=0
  while IFS= read -r m; do
    sz=$(stat -c %s "$m" 2>/dev/null || echo 0)
    [ "$sz" -gt 0 ] || continue
    echo "$(md5sum "$m" | cut -d' ' -f1):$sz:member$i" >> "$db/m.hdb"
    i=$((i+1))
  done < <(find "$out" -type f)

  # An archive exav reports rather than decodes has no member bytes to hash;
  # that is a correct exav result, not a comparable data point.
  if [ ! -s "$db/m.hdb" ]; then
    printf '%-34s %-9s %-9s %s\n' "$base" "0" "-" "reported, not decoded (no comparison)"
    continue
  fi

  found=$(clamscan -d "$db" $ALERTS "$f" 2>&1 | grep -cE "FOUND")
  total=$(wc -l < "$db/m.hdb" | tr -d ' ')
  if [ "$found" -eq 0 ]; then
    verdict="SILENT MISS — clamav reached none"
    misses=$((misses+1))
  elif [ "$found" -lt "$total" ]; then
    verdict="partial"
  else
    verdict="reached all"
  fi
  printf '%-34s %-9s %-9s %s\n' "$base" "$total" "$found" "$verdict"
done

echo
echo "containers ClamAV reached nothing in: $misses"
