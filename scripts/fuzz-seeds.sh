#!/usr/bin/env bash
# Seed corpora for the fuzz targets, from the repository's test fixtures.
#
#   scripts/fuzz-seeds.sh OUT     # writes OUT/<target>/ for each seeded target
#
# A cold fuzzer spends its run rediscovering magic numbers; a fixture starts
# it inside the parser. Pass OUT/<target> to `cargo fuzz run` after the
# target's own corpus directory: libFuzzer reads the extra directories and
# never writes to them.
#
# `.xor` fixtures are unmasked (XOR 0x5A, crates/exav-unpack/tests/fixtures/
# README.md), so OUT holds files other scanners detect: keep it outside the
# repository.
#
# Left out:
#   - files over MAX_BYTES (default 64 KiB): every execution reads the whole
#     input, and libFuzzer sizes its inputs after the largest seed;
#   - SKIP, inputs slow by design, which libFuzzer would report as a timeout
#     on its first pass (docs/FUZZING.md, "Seeding strategy").
#
# Targets without fixtures of their input format get no directory:
# x86_decode, rar3_ppmd and parser_recursion take framed input, and no
# signature, CVD or bytecode file is committed for sigs, ndb_compile, cvd and
# bytecode.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: scripts/fuzz-seeds.sh OUT}"
MAX_BYTES="${MAX_BYTES:-65536}"
SKIP="crates/exav-unpack/tests/fixtures/rar/ppmd_lzss_conversion.rar"

cd "$ROOT"
rm -rf "$OUT"
mkdir -p "$OUT"/{containers,pe,drawing,imagehash,cad_dxf,cad_dwg,ifc}

# Tracked files, and new ones not yet committed (but not ignored ones).
files() { git ls-files -co --exclude-standard -- "$@"; }

# Copies $1 into directory $2 under a name unique to its path, unmasked.
add() {
  local src="$1" dir="$2" name
  case " $SKIP " in *" $src "*) return ;; esac
  [ "$(wc -c <"$src")" -le "$MAX_BYTES" ] || return 0
  name="$(printf '%s' "${src%.xor}" | tr '/' '_')"
  if [[ "$src" == *.xor ]]; then
    python3 -c 'import sys; sys.stdout.buffer.write(bytes(b ^ 0x5A for b in open(sys.argv[1], "rb").read()))' "$src" >"$dir/$name"
  else
    cp "$src" "$dir/$name"
  fi
}

# Every fixture, for the targets that take any file: analyze, full_pipeline,
# unpack, filetype.
while IFS= read -r f; do
  case "$f" in *.md | *.py | *.sh) continue ;; esac
  add "$f" "$OUT/containers"
done < <(files 'crates/*/tests/fixtures/**')

# pe and pe_emulator: the fixtures that are PE files.
for f in "$OUT"/containers/*; do
  if cmp -s -n 2 "$f" <(printf MZ); then cp "$f" "$OUT/pe/"; fi
done

while IFS= read -r f; do add "$f" "$OUT/drawing"; done < <(
  files 'crates/exav-render/tests/fixtures/fuzz/**' 'crates/exav-viewer/e2e/fixtures/*.dwg' 'crates/exav-viewer/e2e/fixtures/*.dxf'
)
# drawing also runs exav-render's end-to-end drawings (ezdxf's, and the ODA
# File Converter's DWG of them) and its proxy graphics drawings, stored
# gzipped; the DXF ones go to cad_dxf.
while IFS= read -r f; do
  name="$(printf '%s' "${f%.gz}" | tr '/' '_')"
  gzip -dc "$f" >"$OUT/drawing/$name"
  case "$name" in *.dxf) cp "$OUT/drawing/$name" "$OUT/cad_dxf/$name" ;; esac
done < <(files 'crates/exav-render/tests/fixtures/dwg/*.gz' 'crates/exav-render/tests/fixtures/cad/proxy/**.gz')

# cad_dxf: the drawing model's DXF fixtures, stored gzipped, as the files
# themselves; containers gets them too, for DXF as a format.
while IFS= read -r f; do
  name="$(printf '%s' "${f%.gz}" | tr '/' '_')"
  gzip -dc "$f" >"$OUT/cad_dxf/$name"
  if [ "$(wc -c <"$OUT/cad_dxf/$name")" -gt "$MAX_BYTES" ]; then
    rm "$OUT/cad_dxf/$name"
  else
    cp "$OUT/cad_dxf/$name" "$OUT/containers/$name"
  fi
done < <(files 'crates/exav-render/tests/fixtures/cad/**.dxf.gz' 'crates/exav-unpack/tests/fixtures/dxf/*.gz')
while IFS= read -r f; do add "$f" "$OUT/cad_dxf"; done < <(
  files 'crates/exav-viewer/e2e/fixtures/*.dxf'
)

# cad_dwg: the drawing model's R13 to R2018 DWG fixtures (the ODA File
# Converter's DWG of the DXF ones) and exav-unpack's, stored gzipped;
# containers gets them too, for DWG as a format. The R2000 ones exceed the
# size cap; R2004 on compress theirs.
while IFS= read -r f; do
  name="$(printf '%s' "${f%.gz}" | tr '/' '_')"
  gzip -dc "$f" >"$OUT/cad_dwg/$name"
  if [ "$(wc -c <"$OUT/cad_dwg/$name")" -gt "$MAX_BYTES" ]; then
    rm "$OUT/cad_dwg/$name"
  else
    cp "$OUT/cad_dwg/$name" "$OUT/containers/$name"
  fi
done < <(files 'crates/exav-render/tests/fixtures/cad/dwg/**.dwg.gz' 'crates/exav-render/tests/fixtures/cad/proxy/dwg/**.dwg.gz' 'crates/exav-unpack/tests/fixtures/dwg/*.gz')

# imagehash also runs exav-render's JPEG 2000 and JBIG2 files, and the
# viewer's JPXDecode, JBIG2Decode and CCITTFaxDecode streams.
while IFS= read -r f; do
  case "$f" in *.py | *.json | *.pdf) continue ;; esac
  add "$f" "$OUT/imagehash"
done < <(
  files 'crates/exav-imagehash/tests/fixtures/img/**' 'fuzz/seeds/imagehash/**' \
    'crates/exav-render/tests/fixtures/images/**' 'crates/exav-viewer/e2e/fixtures/pdf-images/**'
)

# ifc: exav-render's IFC and STL fixtures (STEP text and STL written by
# their make.py), the viewer tests' house in both.
while IFS= read -r f; do add "$f" "$OUT/ifc"; done < <(
  files 'crates/exav-render/tests/fixtures/ifc/*.ifc' 'crates/exav-render/tests/fixtures/stl/*.stl' \
    'crates/exav-render/tests/fixtures/viewer/*'
)

for t in analyze full_pipeline unpack filetype; do ln -sfn containers "$OUT/$t"; done
ln -sfn pe "$OUT/pe_emulator"

for d in containers pe drawing imagehash cad_dxf cad_dwg ifc; do
  echo "$d: $(find "$OUT/$d" -type f | wc -l) seeds"
done
