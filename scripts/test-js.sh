#!/usr/bin/env bash
# Run the JavaScript test suites of `crates/exav-unpack-wasm` — the WASM bindings
# that ship to npm and run in a browser.
#
# WHY: the Rust side is covered by `cargo test`, but the bindings layer is not
# Rust. Everything between `wasm-bindgen` and the caller — the `Archive` class,
# the streaming `ReadableStream` extraction, the custom-reader protocol, the
# `File`/drag-and-drop paths, and every error case — only executes in a JS
# engine. `cargo test` covers the Rust side and cannot reach any of it, so
# without this script the published package's public API goes unverified.
#
# Two passes:
#   1. vitest    — pure-JS helper units, no browser, no wasm. Fast.
#   2. playwright — the real `pkg/` wasm loaded in headless Chromium, which is
#                   the environment the package actually ships into.
#
# The e2e pass rebuilds `pkg/` from the current Rust source first: testing a
# stale artifact would pass while the code it claims to cover is broken.
#
# USAGE:
#   scripts/test-js.sh            # both passes
#   scripts/test-js.sh --unit     # vitest only (no wasm-pack/browser needed)
#
# REQUIREMENTS:
#   - node + npm
#   - e2e only: `wasm-pack` (auto-installed via cargo if absent), a chromium
#     download (~110 MB, cached), and python3 for the static file server.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO/crates/exav-unpack-wasm"

if ! command -v node >/dev/null 2>&1; then
  echo "error: node not found. Install Node.js to run the WASM binding tests." >&2
  exit 1
fi

# `npm ci` is reproducible but demands a lockfile in sync with package.json;
# fall back rather than fail a test run over a dependency bump.
if [ ! -d node_modules ]; then
  npm ci || npm install
fi

echo "== vitest (pure-JS helpers) =="
npx vitest run

if [ "${1:-}" = "--unit" ]; then
  exit 0
fi

echo "== building pkg/ from the current Rust source =="
if ! command -v wasm-pack >/dev/null 2>&1; then
  cargo install wasm-pack --locked
fi
# `--features testing-faults` is what `npm run build:e2e` passes, and the e2e
# suite needs it: several cases assert that a decoder panic or a budget
# exhaustion takes down the archive rather than the page, and the only way to
# provoke either on demand is the fault-injection feature. Built without it
# those tests do not skip — they fail, on a build that is working correctly.
wasm-pack build --release --target web -- --features testing-faults

echo "== playwright (headless chromium, real wasm) =="
# `--with-deps` needs root and is only wanted on a fresh CI image; locally the
# plain download is enough and the shared libraries are already present.
if [ -n "${CI:-}" ]; then
  npx playwright install --with-deps chromium
else
  npx playwright install chromium
fi
npx playwright test
