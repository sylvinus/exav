#!/usr/bin/env bash
# Builds the differential oracles the ignored tests of formats/lzfse.rs and
# formats/dcl_explode.rs compare the in-tree decoders against, from the
# reference sources, which are fetched and not kept in this repository:
#
#   tests/oracle/build.sh DIR     # DIR is created; prints the variables to set
#
# Then:
#   EXAV_LZFSE_ORACLE=DIR/lzfse_oracle EXAV_DCL_ORACLE=DIR/dcl_oracle \
#     cargo test -p exav-unpack --lib -- --ignored oracle
#
# The oracles are built with AddressSanitizer and UndefinedBehaviorSanitizer,
# so a damaged stream the reference itself mishandles is reported by the run.
#
# References: Apple's lzfse (BSD-3-Clause) and zlib's contrib/blast (zlib
# licence). They are only compiled here, never copied into the tree.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?usage: build.sh DIR}"
LZFSE_REV="${LZFSE_REV:-e634ca58b4821d9f3d560cdc6df5dec02ffc93fd}"
ZLIB_TAG="${ZLIB_TAG:-v1.3.1}"

mkdir -p "$OUT"
cd "$OUT"

if [ ! -d lzfse-src ]; then
  git init -q lzfse-src
  git -C lzfse-src fetch -q --depth 1 https://github.com/lzfse/lzfse "$LZFSE_REV"
  git -C lzfse-src checkout -q FETCH_HEAD
fi
for f in blast.c blast.h; do
  [ -f "$f" ] || curl -fsSL "https://raw.githubusercontent.com/madler/zlib/$ZLIB_TAG/contrib/blast/$f" -o "$f"
done

CC="${CC:-cc}"
# The reference loads unaligned words on purpose, adds to a header's bit count
# where only the range check after it matters, and blast.c forms a pointer
# before its window (`to - dist`) that it moves back inside before the read,
# which the object-size check reports although AddressSanitizer sees every
# access in bounds.
SAN="-fsanitize=address,undefined -fno-sanitize=alignment,signed-integer-overflow,object-size -fwrapv -fno-sanitize-recover=undefined -g -O1"
S=lzfse-src/src
# shellcheck disable=SC2086
$CC $SAN -I"$S" "$HERE/lzfse_oracle.c" \
  "$S/lzfse_decode.c" "$S/lzfse_decode_base.c" "$S/lzfse_fse.c" "$S/lzvn_decode_base.c" \
  -o lzfse_oracle
# shellcheck disable=SC2086
$CC $SAN -I. "$HERE/dcl_oracle.c" blast.c -o dcl_oracle

echo "EXAV_LZFSE_ORACLE=$PWD/lzfse_oracle"
echo "EXAV_DCL_ORACLE=$PWD/dcl_oracle"
