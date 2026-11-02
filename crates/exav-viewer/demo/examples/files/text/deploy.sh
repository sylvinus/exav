#!/usr/bin/env bash
# Build, check and copy a static site. CC0-1.0, exav project.
set -euo pipefail

SITE_DIR="${SITE_DIR:-./public}"
REMOTE="${REMOTE:-deploy@example.invalid:/var/www/site}"
LOG="$(mktemp)"

cleanup() {
  local status=$?
  rm -f "$LOG"
  if [ "$status" -ne 0 ]; then
    echo "deploy failed with status $status" >&2
  fi
}
trap cleanup EXIT

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

build() {
  log "building"
  npm ci --silent >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
  npm run build --silent
}

check() {
  local broken=0
  while IFS= read -r -d '' file; do
    if ! grep -q '</html>' "$file"; then
      log "incomplete page: $file"
      broken=$((broken + 1))
    fi
  done < <(find "$SITE_DIR" -name '*.html' -print0)
  return "$broken"
}

case "${1:-all}" in
  build) build ;;
  check) check ;;
  all)   build && check && rsync -az --delete "$SITE_DIR/" "$REMOTE" && log "done" ;;
  *)     echo "usage: $0 [build|check|all]" >&2; exit 2 ;;
esac
