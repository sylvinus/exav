#!/usr/bin/env bash
# Type-check and build the exav.org docs site (www/, Astro + Starlight).
#
# WHY: the docs are the project's single authoritative answer on format coverage,
# CLI flags and ClamAV parity, and they are edited in the same commits as the
# code they describe. A build failure — a broken internal link, a malformed
# frontmatter block, a sidebar entry pointing at a page that no longer exists —
# is a documentation bug that reaches readers, and nothing else in CI catches it.
#
# `astro check` is the type/diagnostic pass; `astro build` is the one that
# resolves every internal link and renders every page.
#
# USAGE: scripts/test-www.sh
# REQUIREMENTS: node + npm.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO/www"

if ! command -v node >/dev/null 2>&1; then
  echo "error: node not found. Install Node.js to build the docs site." >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  npm ci || npm install
fi

npx astro check
npm run build
