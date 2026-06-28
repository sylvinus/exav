#!/usr/bin/env bash
# Generate XZ test fixtures for exav-unpack.
# Run: cd tests/fixtures/xz && bash fixture_gen.sh
set -euo pipefail
cd "$(dirname "$0")"

# Simple payload (same as the old inline XzWriter tests)
echo -n "hello exav inside xz" | xz -c > simple.xz

# Bomb: 4096 zero bytes, highly compressible — trips the budget cap
dd if=/dev/zero bs=1024 count=4 2>/dev/null | xz -c > bomb.xz

# Concatenated multi-member stream (simulates pixz/parallel-xz output)
echo -n "first-xz " | xz -c > a.xz
echo -n "second-X5O!" | xz -c > b.xz
cat a.xz b.xz > multi.xz
rm -f a.xz b.xz

echo "Generated: simple.xz bomb.xz multi.xz"
ls -la *.xz
