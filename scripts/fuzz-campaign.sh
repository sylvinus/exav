#!/usr/bin/env bash
# A timeboxed fuzzing campaign across every target.
#
# WHY A DRIVER AND NOT ONE `cargo fuzz run`: libFuzzer runs one target per
# process, so a campaign that only ever runs the broadest target never touches
# the narrow ones, and the narrow targets are where a decoder or a signature
# compiler gets hostile input directly rather than through a format wrapper.
# This splits a wall-clock budget across all of them and reports what each one
# found, so "we fuzzed for an hour" is attributable rather than a slogan.
#
# Every `fuzz/fuzz_targets/*.rs` is run unless TARGETS names some. WORKERS
# targets are fuzzed at a time (one per core); the builds queue behind cargo's
# lock. A target's slice is what is left of TOTAL, shared among the targets not
# started yet, so a slow build shortens the slices and never the campaign.
#
# Fork mode throughout: the parent keeps going after a child crashes, so one
# pass yields a batch of distinct artifacts to triage instead of stopping at
# the first. The timeout and memory limit are CI's (the smoke run), so a
# finding here is one CI would have made. A unit that takes over SLOW seconds
# is saved too (`slow-unit-*`): those are the ones that time out on a slower
# machine. Each target's corpus persists in a gitignored work dir, so coverage
# accumulates across campaigns. A target's binary is deleted once it has run:
# each is hundreds of megabytes.
#
#   scripts/fuzz-campaign.sh                       # one hour, one worker
#   TOTAL=25200 WORKERS=3 scripts/fuzz-campaign.sh # seven hours, three at a time
#   TARGETS="analyze x86_decode" scripts/fuzz-campaign.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

TOTAL="${TOTAL:-3600}"
WORKERS="${WORKERS:-1}"
WORK="${WORK:-$ROOT/tmp/data}"
SLOW="${SLOW:-6}"
KEEP_BINARIES="${KEEP_BINARIES:-0}"
# Building `exav-core` under AddressSanitizer is the memory peak of the whole
# repository: one rustc process, full instrumentation. On a small host it is
# what the OOM killer reaches for, and a killed build is indistinguishable in
# the log from a target that ran and found nothing, so a failed build is
# reported as such, with its log. Several codegen units keep that rustc inside
# a few gigabytes.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
CODEGEN_UNITS="${CODEGEN_UNITS:-16}"
# On aarch64 a fuzz binary has more code than a direct branch reaches (128 MB),
# and GNU ld stops with "relocation truncated to fit: R_AARCH64_CALL26". LLD adds
# the branch thunks. cargo-fuzz adds its flags to RUSTFLAGS; the lld setup in
# .cargo/config.toml does not apply once RUSTFLAGS is set.
if command -v ld.lld >/dev/null 2>&1; then
  export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-fuse-ld=lld"
fi
# Order matters when a campaign is cut short: the broadest targets run first.
FIRST="analyze full_pipeline unpack seekable volumes fsimage vdisk imagehash parser_recursion filetype yara pcre clamd icap"
if [ -z "${TARGETS:-}" ]; then
  # The `[[bin]]`s: some files of fuzz_targets/ are modules the targets include.
  all="$(sed -n 's/^name = "\(.*\)"$/\1/p' fuzz/Cargo.toml | sed 1d)"
  TARGETS="$FIRST $(printf '%s\n' $all | grep -vxF "$(printf '%s\n' $FIRST)" | tr '\n' ' ')"
fi
# Strings the mutator splices in, for the targets whose input is text or a
# protocol (fuzz/dicts/).
dict_for() {
  case "$1" in
    yara) echo yara ;;
    pcre) echo pcre ;;
    icap) echo icap ;;
    clamd) echo clamd ;;
    markdown) echo markdown ;;
    full_pipeline | ndb_compile | sigs | cvd) echo signatures ;;
  esac
}
# Seeds from the test fixtures (scripts/fuzz-seeds.sh), unmasked, so outside
# the repository.
SEEDS="${SEEDS:-${XDG_CACHE_HOME:-$HOME/.cache}/exav-fuzz-seeds}"
HOST="$(rustc +nightly -vV | sed -n 's/^host: //p')"
BIN="$ROOT/fuzz/target/$HOST/release"

n=$(printf '%s\n' $TARGETS | wc -l)
START=$(date +%s)
DEADLINE=$((START + TOTAL))
LOGS="$WORK/fuzzlogs"
mkdir -p "$WORK" "$LOGS"
QUEUE="$WORK/fuzzqueue"
rm -rf "$QUEUE"
mkdir -p "$QUEUE"

echo "campaign: $n targets, $WORKERS at a time, ${TOTAL}s"
scripts/fuzz-seeds.sh "$SEEDS" || exit 1

# Artifacts from earlier campaigns would be reported as this run's findings.
before="$(find fuzz/artifacts -type f 2>/dev/null | sort)"

worker() {
  local w="$1" t left remaining slice corpus seeds dict d asan code
  for t in $TARGETS; do
    # Claim a target: the first worker to make its directory runs it.
    mkdir "$QUEUE/$t" 2>/dev/null || continue
    left=$(printf '%s\n' $TARGETS | while read -r x; do [ -d "$QUEUE/$x" ] || echo "$x"; done | wc -l)
    remaining=$((DEADLINE - $(date +%s)))
    # What is left, shared among this target and those not started, less the
    # build; across WORKERS at a time.
    slice=$(((remaining * WORKERS) / (left + 1) - 180))
    [ "$slice" -lt 30 ] && slice=30
    if [ "$remaining" -lt 120 ]; then
      echo "[$w] $t skipped: out of time"
      continue
    fi
    printf '[%s] building %s ... ' "$w" "$t"
    if ! cargo +nightly fuzz build --codegen-units "$CODEGEN_UNITS" "$t" \
      >"$LOGS/build_$t.log" 2>&1; then
      echo "FAILED (see $LOGS/build_$t.log)"
      tail -5 "$LOGS/build_$t.log"
      echo "build failed" >"$QUEUE/$t/result"
      continue
    fi
    echo ok
    remaining=$((DEADLINE - $(date +%s)))
    [ "$slice" -gt "$remaining" ] && slice=$remaining
    corpus="$WORK/fuzzwork_$t"
    mkdir -p "$corpus"
    # Read-only seed dirs: the CI's corpus of the target, and the fixtures.
    seeds=""
    [ -d "$ROOT/fuzz/corpus/$t" ] && seeds="$ROOT/fuzz/corpus/$t"
    [ -d "$SEEDS/$t" ] && seeds="$seeds $SEEDS/$t"
    dict=""
    d="$(dict_for "$t")"
    [ -n "$d" ] && dict="-dict=$ROOT/fuzz/dicts/$d.dict"
    # iced-x86, the oracle `x86_decode` compares against, never frees its decoder
    # tables, which LeakSanitizer reports at exit (docs/FUZZING.md).
    asan=""
    [ "$t" = x86_decode ] && asan="detect_leaks=0"
    mkdir -p "$ROOT/fuzz/artifacts/$t" "$LOGS/cwd_$t"
    echo "[$w] === $t (${slice}s, corpus $(find "$corpus" -type f | wc -l) inputs) ==="
    # In a directory of its own: fork mode writes `fuzz-N.log` files to the
    # working directory.
    # shellcheck disable=SC2086
    (cd "$LOGS/cwd_$t" && ASAN_OPTIONS="$asan" "$BIN/$t" "$corpus" $seeds \
      -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 $dict \
      -artifact_prefix="$ROOT/fuzz/artifacts/$t/" -max_len=65536 \
      -timeout=10 -rss_limit_mb=2048 -report_slow_units="$SLOW" \
      -max_total_time="$slice") >"$LOGS/run_$t.log" 2>&1
    code=$?
    echo "exit $code" >"$QUEUE/$t/result"
    echo "[$w] $t done (exit $code): $(grep -c 'artifact_prefix' "$LOGS/run_$t.log") artifacts reported, $(tail -1 "$LOGS/run_$t.log" | cut -c1-120)"
    [ "$KEEP_BINARIES" = 1 ] || rm -f "$BIN/$t" "$BIN"/deps/"$t"-* 2>/dev/null
  done
}

for w in $(seq 1 "$WORKERS"); do
  worker "$w" &
done
wait

echo
echo "=== artifacts found by THIS campaign ==="
comm -13 <(printf '%s\n' "$before") <(find fuzz/artifacts -type f 2>/dev/null | sort) || true
echo "(pre-existing artifacts are excluded; see fuzz/artifacts for all)"
echo "=== targets that did not build ==="
failed="$(grep -l "build failed" "$QUEUE"/*/result 2>/dev/null | sed 's|.*/fuzzqueue/||; s|/result||')"
printf '%s\n' "$failed"
echo "logs: $LOGS"
# A target that did not build was not fuzzed: that is a failed campaign.
[ -z "$failed" ]
