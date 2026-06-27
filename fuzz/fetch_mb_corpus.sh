#!/usr/bin/env bash
# Coverage-guided corpus growth from MalwareBazaar.
#
# Fetches recent samples from MalwareBazaar and folds them into a fuzz target's
# corpus with libFuzzer's `-merge=1`, which KEEPS ONLY inputs that add new edge
# coverage and discards the rest. So the corpus grows in information, not just in
# size, and a later `cargo fuzz run` starts from a richer seed set.
#
# Safety: the samples are live malware. They are only ever read as bytes by the
# fuzz target (static parsing — NEVER executed), are stored solely in the
# gitignored work dir, and the downloaded archives are deleted after extraction.
#
# Requires the MalwareBazaar Auth-Key in the environment (do NOT hard-code or
# commit it):
#   MALWAREBAZAAR_API_KEY=<key> fuzz/fetch_mb_corpus.sh
#   MALWAREBAZAAR_API_KEY=<key> TARGET=analyze LIMIT=200 MAXSZ=262144 fuzz/fetch_mb_corpus.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Load secrets from a gitignored env file if present, so the Auth-Key never has
# to be typed on the command line or committed.
ENVFILE="${ENVFILE:-$ROOT/.env.local}"
[ -f "$ENVFILE" ] && { set -a; . "$ENVFILE"; set +a; }

: "${MALWAREBAZAAR_API_KEY:?set MALWAREBAZAAR_API_KEY (in $ROOT/.env.local or the environment)}"
TARGET="${TARGET:-analyze}"          # which fuzz target's corpus to grow
LIMIT="${LIMIT:-100}"                # how many recent samples to consider
MAXSZ="${MAXSZ:-1048576}"            # skip samples larger than this (the -merge does the real selection)
WORK="${WORK:-$ROOT/tmp/data/fuzzwork_${TARGET}}"   # the live, gitignored corpus
API="https://mb-api.abuse.ch/api/v1/"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/mbstage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$WORK" "$STAGE/ex" "$STAGE/cand"

echo "==> Fetching recent MalwareBazaar hashes (auth-key from env)…"
# `get_recent&selector=100` returns the latest 100 additions as JSON; pull the
# sha256 hashes without depending on jq.
curl -sS -X POST "$API" -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
     -d 'query=get_recent&selector=100' \
  | grep -oE '"sha256_hash":[[:space:]]*"[0-9a-f]{64}"' \
  | grep -oE '[0-9a-f]{64}' | head -n "$LIMIT" > "$STAGE/hashes.txt"
echo "    got $(wc -l < "$STAGE/hashes.txt") hashes"

echo "==> Downloading + extracting (password-protected zips, pw 'infected')…"
got=0
while read -r h; do
  z="$STAGE/$h.zip"
  curl -sS -X POST "$API" -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
       -d "query=get_file&sha256_hash=$h" -o "$z" || continue
  # MalwareBazaar returns a zip on success and JSON on error; skip non-zips.
  [ "$(head -c2 "$z" 2>/dev/null)" = "PK" ] || { rm -f "$z"; continue; }
  # The sample zips are WinZip-AES encrypted (password 'infected'); Info-ZIP
  # `unzip` can't do AES, so use 7z. The sample is only ever read as bytes by the
  # fuzz target — never executed.
  7z x -pinfected -y -o"$STAGE/ex" "$z" >/dev/null 2>&1 && got=$((got+1)) || true
  rm -f "$z"
done < "$STAGE/hashes.txt"

# Stage only reasonably small samples (hash-named to dedupe).
find "$STAGE/ex" -type f -size -"${MAXSZ}"c -print0 2>/dev/null \
  | while IFS= read -r -d '' f; do
      cp "$f" "$STAGE/cand/$(sha1sum "$f" | cut -c1-16)" 2>/dev/null || true
    done
echo "    downloaded $got samples; $(ls "$STAGE/cand" | wc -l) within ${MAXSZ}-byte cap"

before=$(find "$WORK" -type f | wc -l)
echo "==> Merging into corpus (libFuzzer -merge: keep only coverage-increasing)…"
# `-merge=1 DEST SRC`: fold SRC into DEST, copying over only units that add new
# coverage. Requires the fuzz target to be built (cargo fuzz builds on demand).
CARGO_INCREMENTAL=0 cargo +nightly fuzz run "$TARGET" "$WORK" "$STAGE/cand" -- \
    -merge=1 -rss_limit_mb=4096 -timeout=60 > "$STAGE/merge.log" 2>&1 || {
  echo "merge failed; tail of log:"; tail -20 "$STAGE/merge.log"; exit 1; }
after=$(find "$WORK" -type f | wc -l)
echo "==> Corpus: $before -> $after  (+$((after-before)) coverage-increasing samples kept)"
