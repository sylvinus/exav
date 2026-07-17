#!/usr/bin/env bash
# Teardown for a differential-test run: stop both engines and remove all scratch
# so nothing is left holding RAM, a socket, or hundreds of MB of disk.
#
# Run this when you're done diffing, or just let test-clamav-diff.sh handle it (it has
# an EXIT trap). This script is idempotent and safe to run anytime.
#
#   scripts/test-clamav-diff-teardown.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 1. Stop the engines.
pkill -x exav 2>/dev/null || true
sleep 0.5
pkill -9 -x exav 2>/dev/null || true

# 2. Stop clamd Docker container (if any).
docker rm -f clamd-diff 2>/dev/null || true
# Also kill any native clamd (leftover from old runs).
pkill -x clamd 2>/dev/null || true
sleep 0.5
pkill -9 -x clamd 2>/dev/null || true

# 3. Remove sockets, configs, logs, and the resumable results log.
rm -f /tmp/exav.sock /tmp/clamd_sock/clamd.sock 2>/dev/null || true
rm -f /tmp/clamd_*.conf /tmp/clamd_docker.conf /tmp/clamd_*.log /tmp/clamd_daily.conf 2>/dev/null || true
rm -rf /tmp/difftest 2>/dev/null || true

# 4. Remove the diff scratch on disk (matched DBs + prebuilt caches are
#    rebuildable; the rar/unrar tooling under tmp/data/rarbin is kept).
rm -rf "$ROOT"/tmp/data/diff \
       "$ROOT"/tmp/data/clamdb_* \
       "$ROOT"/tmp/data/clamd_*.conf "$ROOT"/tmp/data/clamd_*.log 2>/dev/null || true

echo "teardown done — engines:"
[ -n "$(docker ps -q --filter name=clamd-diff 2>/dev/null)" ] && echo "  WARNING: clamd container still exists" || echo "  clamd: none"
pgrep -x exav >/dev/null && echo "  WARNING: an exav daemon is still running" || echo "  exav:  none"
command -v free >/dev/null && free -h | awk '/Mem:/{print "  mem available: "$7}'
