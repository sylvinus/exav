#!/usr/bin/env bash
# Build exav-unpack to WebAssembly with EACH format feature in isolation and
# report the resulting `.wasm` size — i.e. "how big is a minimal <fmt> extractor".
#
# It compiles a tiny generated `wasm32-wasip1` binary that only calls
# `exav_unpack::detect` + `extract` (so the whole extractor for the enabled
# format is linked in, nothing else), then shrinks it with `wasm-opt -Oz`. This
# is a PURE-cargo measurement: no wasm-bindgen / wasm-pack / JS glue, so the
# numbers are the extractor's own code size, not browser-binding overhead.
#
#   scripts/wasm-format-sizes.sh              # all formats, sorted by size
#   FMTS="zip gzip tar" scripts/wasm-format-sizes.sh   # a subset
#
# Requires: rustup target wasm32-wasip1, and `wasm-opt` (binaryen) on PATH.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/var/tmp/exav-wasm-size}"          # on disk, not tmpfs
export CARGO_TARGET_DIR="$WORK/target"
# Measure the browser target (`wasm32-unknown-unknown`), which is what
# exav-unpack-wasm actually ships and is ~13 KB lighter at the floor than WASI
# (`wasm32-wasip1` drags in the whole WASI std). Override with TARGET=.
TARGET="${TARGET:-wasm32-unknown-unknown}"
# BUILDSTD=1 rebuilds std with `panic=immediate-abort` on nightly (drops std's
# panic-formatting machinery). Cuts the floor from ~13 KB to ~2 KB, ~40% off the
# full dispatch build. Needs the `nightly` toolchain + its `rust-src` component.
BUILDSTD="${BUILDSTD:-0}"
mkdir -p "$WORK/src"

# Format list: exav-unpack's `all-formats` array (kept in sync automatically).
if [ -z "${FMTS:-}" ]; then
  FMTS=$(awk '/^all-formats = \[/{f=1} f{print} f&&/\]/{exit}' \
    "$ROOT/crates/exav-unpack/Cargo.toml" | grep -oE '"[a-z0-9]+"' | tr -d '"' \
    | grep -v '^all-formats$' | tr '\n' ' ')
fi

# Generate the minimal wrapper crate (all format features forwarded).
{
  cat <<EOF
[package]
name = "uwsz"
version = "0.0.0"
edition = "2021"
[[bin]]
name = "uwsz"
path = "src/main.rs"
[dependencies]
exav-unpack = { path = "$ROOT/crates/exav-unpack", default-features = false }
[features]
EOF
  for f in $FMTS decrypt all-formats; do echo "$f = [\"exav-unpack/$f\"]"; done
  cat <<'EOF'
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
EOF
} > "$WORK/Cargo.toml"

cat > "$WORK/src/main.rs" <<'EOF'
// Force the extractor for whatever formats are compiled to be linked: detect the
// type at runtime and extract, so dead-code elimination can't drop any of them.
use std::io::Read;
fn main() {
    let mut data = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut data);
    let mut b = exav_unpack::Budget::new(exav_unpack::Limits::default());
    let n = match exav_unpack::detect(&data) {
        Some(f) => exav_unpack::extract(f, &data, &mut b).map(|e| e.len()).unwrap_or(0),
        None => 0,
    };
    std::process::exit((n & 0x7f) as i32);
}
EOF

sz() { stat -c %s "$1" 2>/dev/null || echo 0; }
build() { # $1 = comma feature list ("" = none). echoes wasm path on success.
  local feats="$1" ok
  if [ "$BUILDSTD" = 1 ]; then
    RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" \
      cargo +nightly build --release --manifest-path "$WORK/Cargo.toml" --target "$TARGET" \
      -Z build-std=std,panic_abort --no-default-features ${feats:+--features "$feats"} -j 2 \
      >/dev/null 2>"$WORK/err.log" && ok=1
  else
    cargo build --release --manifest-path "$WORK/Cargo.toml" --target "$TARGET" \
      --no-default-features ${feats:+--features "$feats"} -j 2 \
      >/dev/null 2>"$WORK/err.log" && ok=1
  fi
  [ -n "${ok:-}" ] && echo "$CARGO_TARGET_DIR/$TARGET/release/uwsz.wasm"
}
measure() { # $1 = raw wasm path -> echoes "raw opt"
  local raw opt; raw=$(sz "$1")
  wasm-opt -Oz -all "$1" -o "$WORK/o.wasm" 2>/dev/null && opt=$(sz "$WORK/o.wasm") || opt=0
  echo "$raw $opt"
}

echo "Building baseline (no formats) ..."
base_opt=0
if w=$(build ""); then read -r braw bopt < <(measure "$w"); base_opt=$bopt
  printf 'baseline (dispatch only): raw=%d opt=%d\n\n' "$braw" "$bopt"
else echo "baseline build failed (empty feature set)"; echo; fi

rows="$WORK/rows.txt"; : > "$rows"
for f in $FMTS; do
  echo "  building $f ..." >&2
  if w=$(build "$f"); then
    read -r raw opt < <(measure "$w")
    printf '%s\t%d\t%d\t%d\n' "$f" "$raw" "$opt" "$((opt-base_opt))" >> "$rows"
  else
    printf '%s\tBUILD-FAIL\t\t%s\n' "$f" "$(head -1 "$WORK/err.log" | cut -c1-60)" >> "$rows"
  fi
done

# Combined builds for context.
for combo in "zip,decrypt" "all-formats" "all-formats,decrypt"; do
  echo "  building $combo ..." >&2
  if w=$(build "$combo"); then read -r raw opt < <(measure "$w")
    printf '%s\t%d\t%d\t%d\n' "$combo" "$raw" "$opt" "$((opt-base_opt))" >> "$rows"
  else printf '%s\tBUILD-FAIL\n' "$combo" >> "$rows"; fi
done

echo
printf '%-22s %12s %12s %12s\n' FORMAT RAW 'OPT(-Oz)' 'Δ vs base'
printf '%-22s %12s %12s %12s\n' '----------------------' '----------' '----------' '----------'
# per-format rows sorted by optimized size; combos appended verbatim.
grep -vE 'all-formats|zip,decrypt' "$rows" | sort -t$'\t' -k3 -n | \
  awk -F'\t' '{if($2=="BUILD-FAIL")printf "%-22s %12s   %s\n",$1,$2,$4; else printf "%-22s %12d %12d %12d\n",$1,$2,$3,$4}'
echo
grep -E 'all-formats|zip,decrypt' "$rows" | \
  awk -F'\t' '{if($2=="BUILD-FAIL")printf "%-22s %12s\n",$1,$2; else printf "%-22s %12d %12d %12d\n",$1,$2,$3,$4}'
echo
echo "(sizes in bytes; OPT = wasm-opt -Oz -all; Δ = OPT minus baseline dispatch-only build of $base_opt B)"

# In CI, also render a Markdown table into the job summary.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### exav-unpack WASM size per format"
    echo
    echo "Minimal \`wasm32-wasip1\` extractor per format (\`wasm-opt -Oz\`). Baseline"
    echo "(dispatch only, zero formats): **$base_opt B**."
    echo
    echo "| Format | OPT (B) | Δ vs base (B) |"
    echo "|---|--:|--:|"
    sort -t$'\t' -k3 -n "$rows" | awk -F'\t' '{
      if ($2=="BUILD-FAIL") printf "| %s | BUILD-FAIL | %s |\n", $1, $4;
      else printf "| %s | %d | %d |\n", $1, $3, $4 }'
  } >> "$GITHUB_STEP_SUMMARY"
fi
