#!/usr/bin/env bash
# Run the extractor unit tests on the 32-bit wasm32-wasip1 target under wasmtime.
#
# WHY: `usize` is 32-bit on wasm32 (and exav ships a WASM build — the extractor
# runs sandboxed under wasmtime in production). Integer-overflow and
# capacity-overflow bugs on parsed offsets/lengths are invisible on a 64-bit host
# but abort the process on wasm32. This target runs the same unit tests — which
# include the `u32::MAX`/`u64::MAX` hostile-input regressions — with a 32-bit
# `usize`, so that class fails the build instead of the fuzzer/prod.
#
# USAGE:
#   scripts/test-wasm.sh                 # run the wasm32 extractor unit tests
#   scripts/test-wasm.sh formats::sevenz # pass extra `cargo test` args/filters
#
# REQUIREMENTS:
#   - rustup target: `rustup target add wasm32-wasip1` (auto-added below).
#   - wasmtime on PATH, or point $WASMTIME at a binary. Install: https://wasmtime.dev
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASMTIME="${WASMTIME:-wasmtime}"

if ! command -v "$WASMTIME" >/dev/null 2>&1; then
  echo "error: '$WASMTIME' not found. Install wasmtime (https://wasmtime.dev) or set \$WASMTIME." >&2
  exit 1
fi

rustup target add wasm32-wasip1 >/dev/null 2>&1 || true

# The wasi sandbox denies filesystem access by default; a few tests read fixture
# files via their absolute build-time path, so pre-open the repo dir (mapped to
# the same guest path) for the test runner.
export CARGO_TARGET_WASM32_WASIP1_RUNNER="$WASMTIME run --dir $REPO::$REPO"

# `--lib` only: unit tests (incl. the hostile-input regressions) build their
# inputs in-code and are the 32-bit-sensitive surface. Integration tests under
# tests/ are the same code paths and run natively via `make test`.

# 1) The extractor (pure Rust, the main parsing attack surface).
cargo test --lib -p exav-unpack --target wasm32-wasip1 "$@"

# 2) The scanning core, minus `yara` (yara-x pulls wasmtime/cranelift, which
#    can't target wasm) — so the engine/pe/patterns/phishing/dlp byte-processing
#    logic is checked on a 32-bit `usize` too. Host-filesystem tests (DB/cache
#    loaders) are `#[cfg_attr(target_family = "wasm", ignore)]` and run natively.
cargo test --lib -p exav-core \
  --no-default-features --features "all-formats,decrypt,dlp,phishing" \
  --target wasm32-wasip1 "$@"
