#!/usr/bin/env bash
# Run the test suites of `crates/exav-viewer`, the @exav/viewer npm package.
#
# Four passes:
#   1. vitest: the core (detection, sources, sessions), the copy step, the
#      CAD renderer's pure parts, the CSV reader, the decoders given to
#      pdf.js against pdf.js's own, the sandboxed frame's protocol and host
#      side, and the gates below. No browser. It needs the wasm modules, so
#      they are rebuilt from the current Rust source first (and their imports
#      and memory caps checked).
#   2. the package: dist/ rebuilt with its frame app, and `check-package.mjs`
#      on what `npm publish` would upload.
#   3. the gates: no sink in the package's own code (check-sinks.mjs); in
#      the built frame and demo, no sink but the reviewed ones
#      (check-bundle-sinks.mjs) and no wasm import off its module's list
#      (check-wasm-imports.mjs).
#   4. playwright: the demo built for production, as a host's bundler builds
#      the package, driven in headless Chromium under the demo's
#      Content-Security-Policy, each file in the sandboxed frame and again in
#      the page, against samples whose content is known; and the frame's
#      guarantees (e2e/frame.spec.ts) and text selection and copy in PDF,
#      Word, PowerPoint and Excel files (e2e/selection.spec.ts) in
#      Chromium, Firefox and WebKit.
#
# USAGE:
#   scripts/test-viewer.sh            # all three
#   scripts/test-viewer.sh --unit     # vitest only, on the wasm/ built last
#
# REQUIREMENTS:
#   - node + npm
#   - the wasm32-unknown-unknown target, wasm-bindgen-cli at the version
#     crates/exav-viewer/Cargo.toml pins, and wasm-opt if available (for
#     --unit, only to have built wasm/ once)
#   - beyond --unit: wasm-pack (installed if absent), which builds
#     crates/exav-unpack-wasm/pkg/, the archive plugin's peer; and git and
#     network access to clone github.com/sylvinus/exav-samples, unless
#     EXAV_SAMPLES names a local checkout.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO/crates/exav-viewer"

if [ ! -d node_modules ]; then
  npm ci || npm install
fi

if [ "${1:-}" = "--unit" ]; then
  if [ ! -f wasm/pdf_decoders.js ]; then
    echo "error: wasm/ is missing: run npm run build:wasm first" >&2
    exit 1
  fi
  npx vitest run
  exit 0
fi

echo "== the wasm modules, from the current source =="
npm run build:wasm

echo "== the package's own code: no sink =="
node scripts/check-sinks.mjs

echo "== vitest =="
npx vitest run

echo "== @exav/unpack-wasm, from the current source =="
# The archive plugin's peer, installed from ../exav-unpack-wasm: built here as
# it ships (scripts/test-js.sh builds it with test-only features).
if ! command -v wasm-pack >/dev/null 2>&1; then
  cargo install wasm-pack --locked
fi
(cd ../exav-unpack-wasm && wasm-pack build --release --target web)

echo "== the package, from the current source =="
npm run build
# After the builds: the sources import the wasm glue, and the demo the built
# Vite plugin, neither of which is checked in.
npm run typecheck
node scripts/check-package.mjs

echo "== the demo, and what it ships =="
# Its sidebar's files, from github.com/sylvinus/exav-samples (HEAD), or from
# the checkout EXAV_SAMPLES names.
npm run demo:showcase
rm -rf demo/dist
npm run demo:build
node scripts/check-bundle-sinks.mjs dist/frame/app demo/dist
node scripts/check-wasm-imports.mjs --all dist/frame/app demo/dist

echo "== playwright (the demo in chromium; the frame and text selection in chromium, firefox and webkit) =="
if [ -n "${CI:-}" ]; then
  npx playwright install --with-deps chromium firefox webkit
else
  npx playwright install chromium firefox webkit
fi
npx playwright test
