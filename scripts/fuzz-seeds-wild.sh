#!/usr/bin/env bash
# Seeds from files found in the wild, for the targets whose input is a whole
# file of a format.
#
#   scripts/fuzz-seeds-wild.sh OUT [DIR]    # adds OUT/<target>/wild_* from DIR
#
# DIR is a tree of sample files (default: tmp/samples-issues, which is not in
# the repository). The test fixtures give a target one file of a format; a
# directory of what other programs write gives it the variants that parsers
# are written against, and the fuzzer starts from the structure instead of
# finding it. Run by scripts/fuzz-seeds.sh; nothing is copied into the
# repository, and a missing DIR is not an error.
#
# Files over MAX_BYTES (default 64 KiB) are left out, as in the other seeds,
# and at most PER_TARGET (default 300) of a target's, the smallest first.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: scripts/fuzz-seeds-wild.sh OUT [DIR]}"
DIR="${2:-$ROOT/tmp/samples-issues}"
MAX_BYTES="${MAX_BYTES:-65536}"
PER_TARGET="${PER_TARGET:-300}"

[ -d "$DIR" ] || exit 0

# wild TARGET EXT...: the files of DIR with one of the extensions.
wild() {
  local target="$1" ext expr=() n=0 f name
  shift
  for ext in "$@"; do expr+=(-o -iname "*.$ext"); done
  mkdir -p "$OUT/$target"
  while IFS= read -r f; do
    name="wild_$(printf '%s' "$f" | cksum | cut -d' ' -f1)_$(basename "$f")"
    cp "$f" "$OUT/$target/$name"
    n=$((n + 1))
  done < <(
    find "$DIR" -type f -size "-$((MAX_BYTES / 1024 + 1))k" \( "${expr[@]:1}" \) -printf '%s %p\n' 2>/dev/null |
      sort -n | head -n "$PER_TARGET" | cut -d' ' -f2-
  )
  echo "wild $target: $n"
}

wild docs_doc doc dot
wild docs_odt odt ott fodt
wild docs_rtf rtf
wild docs_wml xml
wild docs_html html htm
wild docs_pages pages
wild sheets_xls xls xlt
wild sheets_ods ods ots fods
wild sheets_numbers numbers
wild sheets_text slk
wild slides_ppt ppt pps pot
wild slides_odp odp otp fodp
wild slides_odg odg otg fodg
wild slides_vsdx vsdx vsdm vstx
wild slides_keynote key
wild imagehash j2k jp2 jpx jb2 jbig2 png gif jpg jpeg bmp tif tiff webp ico cur dds hdr qoi pnm ppm pgm pbm
wild raw_preview dng cr2 nef arw orf rw2 raf pef srw
wild cad_dxf dxf
wild cad_dwg dwg
wild drawing dxf dwg
wild ifc ifc stl
wild mesh obj ply gltf glb
wild markdown md markdown
wild containers zip rar 7z tar gz bz2 xz cab arj lha lzh iso cpio ar deb rpm pdf eml msg
