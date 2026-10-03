#!/usr/bin/env bash
# Builds exav-unpack with each format feature on its own.
#
# The test passes build feature sets whole (default, all-formats, none), and a
# whole set unifies dependencies and modules across formats: a format that only
# compiles because another one pulled in its dependency, or a `cfg` naming the
# wrong feature, goes unseen until someone enables that format alone. `ole`
# was such a feature.
#
#   scripts/check-features.sh            # every format in all-formats
#   FEATURES="ole zip" scripts/check-features.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

if [ -z "${FEATURES:-}" ]; then
  # The members of `all-formats-no-emu`, plus `pe-emu`.
  FEATURES="$(
    sed -n '/^all-formats-no-emu = \[/,/^\]/p' crates/exav-unpack/Cargo.toml |
      grep -o '"[a-z0-9-]*"' | tr -d '"'
  ) pe-emu"
fi

failed=""
for f in $FEATURES; do
  printf '%s ... ' "$f"
  if cargo check -q -p exav-unpack --no-default-features --features "$f" 2>"${TMPDIR:-/tmp}/check-feature-$f.err"; then
    echo ok
  else
    echo FAILED
    tail -20 "${TMPDIR:-/tmp}/check-feature-$f.err"
    failed="$failed $f"
  fi
done

if [ -n "$failed" ]; then
  echo "features that do not build alone:$failed"
  exit 1
fi
