#!/usr/bin/env bash
# A timeboxed fuzzing campaign across every target.
#
# WHY A DRIVER AND NOT ONE `cargo fuzz run`: libFuzzer runs one target per
# process, so a campaign that only ever runs the broadest target never touches
# the narrow ones — and the narrow targets are where a decoder or a signature
# compiler gets hostile input directly rather than through a format wrapper.
# This splits a wall-clock budget across all of them and reports what each one
# found, so "we fuzzed for an hour" is attributable rather than a slogan.
#
# Fork mode throughout: the parent keeps going after a child crashes, so one
# pass yields a batch of distinct artifacts to triage instead of stopping at
# the first. Each target's corpus persists in a gitignored work dir, so
# coverage accumulates across campaigns.
#
#   scripts/fuzz-campaign.sh              # one hour, split evenly
#   TOTAL=1800 scripts/fuzz-campaign.sh   # half an hour
#   TARGETS="analyze x86_decode" scripts/fuzz-campaign.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

TOTAL="${TOTAL:-3600}"
WORK="${WORK:-$ROOT/tmp/data}"
# Building `exav-core` under AddressSanitizer is the memory peak of the whole
# repository — one rustc process, one codegen unit, full instrumentation. On a
# small host it is what the OOM killer reaches for, and a killed build is
# indistinguishable in the log from a target that ran and found nothing. One
# job at a time keeps the peak to a single rustc, and splitting the crate into
# several codegen units keeps that rustc inside a few gigabytes.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CODEGEN_UNITS="${CODEGEN_UNITS:-16}"
# Order matters when a campaign is cut short: the broadest targets run first.
TARGETS="${TARGETS:-analyze full_pipeline unpack x86_decode pe_emulator bytecode sigs ndb_compile cvd pe filetype rar3_ppmd parser_recursion}"

n=$(printf '%s\n' $TARGETS | wc -l)
slice=$((TOTAL / n))
[ "$slice" -lt 30 ] && slice=30

echo "campaign: $n targets x ${slice}s"
mkdir -p "$WORK"

# Build every target up front, and refuse to start if any fails. A campaign
# that runs `cargo fuzz run` per target and pipes the output away turns a
# compile error into a target that "ran" and found nothing — the same shape as
# a clean run, which is the worst possible way to be wrong about test coverage.
for t in $TARGETS; do
  printf 'building %s ... ' "$t"
  if ! cargo +nightly fuzz build --codegen-units "$CODEGEN_UNITS" "$t" \
    >/dev/null 2>"$WORK/fuzzbuild_$t.err"; then
    echo "FAILED"
    tail -30 "$WORK/fuzzbuild_$t.err"
    exit 1
  fi
  echo ok
done

# Artifacts from earlier campaigns would be reported as this run's findings.
before="$(find fuzz/artifacts -type f 2>/dev/null | sort)"

fail=0
for t in $TARGETS; do
  corpus="$WORK/fuzzwork_$t"
  mkdir -p "$corpus"
  echo "=== $t (${slice}s, corpus $(find "$corpus" -type f | wc -l) inputs) ==="
  # -timeout is the DoS threshold; -rss_limit_mb catches runaway allocation.
  # The ignore_* flags are what make this a batch run rather than a bisect.
  if ! cargo +nightly fuzz run --codegen-units "$CODEGEN_UNITS" "$t" "$corpus" -- \
    -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
    -timeout=60 -rss_limit_mb=4096 -max_total_time="$slice" 2>&1 |
    tail -20; then
    echo "!! $t exited non-zero"
    fail=1
  fi
done

echo
echo "=== artifacts found by THIS campaign ==="
comm -13 <(printf '%s\n' "$before") <(find fuzz/artifacts -type f 2>/dev/null | sort) || true
echo "(pre-existing artifacts are excluded; see fuzz/artifacts for all)"
exit "$fail"
