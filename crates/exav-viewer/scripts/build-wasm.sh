#!/usr/bin/env bash
# Build the WebAssembly modules into wasm/: exav_viewer_image (raster
# decoders), exav_viewer_dwg (DWG and DXF) and exav_viewer_model (IFC and
# STL), and the two decoders pdf.js
# loads in place of its C and C++ ones, each embedded in its fallback module
# (openjpeg_nowasm_fallback.js, jbig2_nowasm_fallback.js; see
# build-pdf-decoders.mjs). Needs the wasm32-unknown-unknown target and
# wasm-bindgen-cli at the version Cargo.toml pins; wasm-opt is used when
# present.
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET=wasm32-unknown-unknown
OUT=wasm
PDF=target/pdf-decoders
want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"/\1/p' Cargo.toml)
have=$(wasm-bindgen --version | cut -d' ' -f2)
if [ "$want" != "$have" ]; then
  echo "wasm-bindgen-cli $have, but Cargo.toml pins $want" >&2
  exit 1
fi

optimise() {
  if command -v wasm-opt >/dev/null 2>&1; then
    wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
      --enable-mutable-globals --enable-reference-types --enable-multivalue "$1" -o "$1"
  fi
}

# Most linear memory each module may grow to: past it an allocation fails,
# the module traps, and its worker reports the file unreadable, instead of a
# decoder taking the tab's memory. Pages of 64 KiB, set at link time
# (`--max-memory`). Kept in step with MEMORY_CAPS in check-wasm-imports.mjs.
# - image: 1 GiB. The default decode limit is 256 MiB of RGBA; the file's
#   bytes, the decoded pixels and their RGBA copy are held at once.
# - dwg: 2 GiB. The largest real drawing measured (14 MB, 75 layouts) peaks
#   at 1.2 GiB.
# - model: 3 GiB. The file, its index, and the meshes twice (the scene and
#   the buffers handed over) for the default 6 million triangles fit in 1.5.
# - pdf-jpx, pdf-jbig2: 1 GiB for one image of a PDF.
cap() {
  case "$1" in
    image) echo $((1024 * 1024 * 1024)) ;;
    dwg) echo $((2048 * 1024 * 1024)) ;;
    model) echo $((3072 * 1024 * 1024)) ;;
    pdf-jpx | pdf-jbig2) echo $((1024 * 1024 * 1024)) ;;
  esac
}

mkdir -p "$OUT" "$PDF"
for feature in image dwg model pdf-jpx pdf-jbig2; do
  # The cdylib's file has no hash in its name, so every feature writes the
  # same one, and a feature cargo finds up to date would leave the module
  # another feature built last: it is removed, so that it is linked again.
  rm -f "target/$TARGET/release/exav_viewer.wasm" "target/$TARGET/release/deps/exav_viewer.wasm"
  # `cargo rustc`: the cap is for this crate's link only, so the dependencies
  # built for the other features are not rebuilt.
  cargo rustc --release --target "$TARGET" --no-default-features --features "$feature" --crate-type cdylib \
    -- -C "link-arg=--max-memory=$(cap "$feature")"
  name="exav_viewer_${feature//-/_}"
  case "$feature" in
    pdf-*)
      # A classic script's glue: build-pdf-decoders.mjs wraps it in a function.
      wasm-bindgen "target/$TARGET/release/exav_viewer.wasm" \
        --out-dir "$PDF" --out-name "$name" --target no-modules --no-typescript
      optimise "$PDF/${name}_bg.wasm"
      ;;
    *)
      wasm-bindgen "target/$TARGET/release/exav_viewer.wasm" \
        --out-dir "$OUT" --out-name "$name" --target web
      optimise "$OUT/${name}_bg.wasm"
      ;;
  esac
done
node scripts/build-pdf-decoders.mjs "$PDF" "$OUT"
node scripts/check-wasm-imports.mjs "$OUT"
ls -la "$OUT"
