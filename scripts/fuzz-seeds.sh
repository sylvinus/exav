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
# Targets whose input is framed (full_pipeline, seekable, volumes, yara, pcre)
# get the fixtures behind the frame's header, or seeds written for them
# (fuzz/seeds/); cvd and database get a container and a database made from
# fuzz/db/. x86_decode, rar3_ppmd, parser_recursion, clamd and icap take framed
# or structured input no file is committed in: sigs, ndb_compile and bytecode
# start from nothing, and the structured two decode any bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: scripts/fuzz-seeds.sh OUT}"
MAX_BYTES="${MAX_BYTES:-65536}"
SKIP="crates/exav-unpack/tests/fixtures/rar/ppmd_lzss_conversion.rar"

cd "$ROOT"
rm -rf "$OUT"
mkdir -p "$OUT"/{containers,pe,drawing,imagehash,cad_dxf,cad_dwg,ifc,full_pipeline,seekable,volumes,yara,pcre,cvd,database,authenticode}

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

# full_pipeline: a zero header (no option bits, no database files: the
# signatures are fuzz/db/'s) in front of each fixture. seekable: no option
# bits, reads of 297 bytes, no failure.
for f in "$OUT"/containers/*; do
  name="$(basename "$f")"
  { printf '\000\000\000'; cat "$f"; } >"$OUT/full_pipeline/$name"
  { printf '\000\000\010\000'; cat "$f"; } >"$OUT/seekable/$name"
done

# full_pipeline also gets the files of fuzz/db/ in the header, one a seed and
# eight of them in one, over a text that several of their signatures match
# (the kind byte indexes `KINDS` in fuzz/db.rs, bit 7 is "official").
python3 - "$OUT/full_pipeline" <<'PY'
import os, struct, sys
kinds = ["ndb","ldb","hdb","hsb","mdb","msb","cdb","ftm","yar","pdb","gdb","wdb","fdb","imp","crb","db","fp","sfp","ign","ign2","pwdb","cbc","idb"]
scan = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"
        b"hello world MARKER secret ab cd ab payload macro work doc ABCD\n")
def frame(files):
    out = struct.pack("<HB", 0, len(files))
    for k, b in files:
        out += bytes([k]) + struct.pack("<H", len(b)) + b
    return out + scan
allfiles = []
for name in sorted(os.listdir("fuzz/db")):
    ext = name.rsplit(".", 1)[-1]
    if not name.startswith("fuzz.") or ext not in kinds:
        continue
    b = open("fuzz/db/" + name, "rb").read()[:65535]
    allfiles.append((kinds.index(ext), b))
    open(f"{sys.argv[1]}/db_{ext}", "wb").write(frame([allfiles[-1]]))
for i in range(0, len(allfiles), 8):
    open(f"{sys.argv[1]}/db_set{i // 8}", "wb").write(frame(allfiles[i:i + 8]))
PY

# authenticode: the signed PEs, and the PEs among the fixtures.
cp crates/exav-core/tests/fixtures/authenticode/*.exe "$OUT/authenticode/"
cp "$OUT"/pe/* "$OUT/authenticode/" 2>/dev/null || true

# cvd: fuzz/db/ as a signature container; database: the same, built by exav
# into a prebuilt database (needs a build of the `exav` binary: $EXAV, or
# cargo builds one).
python3 - "$OUT/cvd/fuzz.cvd" <<'PY'
import gzip, io, os, sys, tarfile
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tar:
    for name in sorted(os.listdir("fuzz/db")):
        if name.startswith("fuzz."):
            tar.add(os.path.join("fuzz/db", name), arcname=name)
head = b"ClamAV-VDB:01 Jan 2026 00-00 +0000:1:1:90:" + b"0" * 32 + b":dsig:exav-fuzz:1700000000"
with open(sys.argv[1], "wb") as out:
    out.write(head.ljust(512, b" "))
    out.write(gzip.compress(buf.getvalue()))
PY
printf 'MZ\220\000 sample\n' >"$OUT/database/sample.bin"
exav="${EXAV:-}"
if [ -z "$exav" ] && cargo build -q -p exav; then
  exav="${CARGO_TARGET_DIR:-target}/debug/exav"
fi
if [ -x "$exav" ]; then
  "$exav" -d fuzz/db --build-db "$OUT/database/fuzz.exavdb" "$OUT/database/sample.bin" >/dev/null 2>&1
else
  echo "warning: no exav binary, so no seed for the database target" >&2
fi
rm -f "$OUT/database/sample.bin"

# yara: [rule length: u16 LE] [rules] [data]. The rules of fuzz/db/ and
# fuzz/seeds/yara/, each over a PE, an ELF and some text.
python3 - "$OUT/yara" <<'PY'
import glob, os, struct, sys
out = sys.argv[1]
data = [
    open("crates/exav-core/tests/testdata/tiny_pe32.exe", "rb").read(),
    open("crates/exav-core/tests/testdata/tiny_elf64", "rb").read(),
    b"hello world MARKER secret ab cd ab payload\n",
]
rules = ["fuzz/db/fuzz.yar"] + sorted(glob.glob("fuzz/seeds/yara/*.yar"))
for r in rules:
    text = open(r, "rb").read()[:4096]
    for i, d in enumerate(data):
        name = os.path.basename(r).replace(".", "_") + f"_{i}"
        with open(os.path.join(out, name), "wb") as f:
            f.write(struct.pack("<H", len(text)) + text + d)
PY

# pcre: [flags: u8, bits for i s m x E U] [pattern length: u16 LE] [pattern]
# [haystack], from fuzz/seeds/pcre/patterns.txt.
python3 - "$OUT/pcre" <<'PY'
import struct, sys
out = sys.argv[1]
n = 0
for line in open("fuzz/seeds/pcre/patterns.txt", encoding="utf-8"):
    line = line.rstrip("\n")
    if line.startswith("#"):
        continue
    flags, pattern, hay = line.split("\t")
    bits = sum(1 << i for i, l in enumerate("ismxEU") if l in flags)
    p = pattern.encode()
    h = hay.encode().decode("unicode_escape").encode("latin-1", "replace")
    with open(f"{out}/p{n:03}", "wb") as f:
        f.write(bytes([bits]) + struct.pack("<H", len(p)) + p + h)
    n += 1
PY

# volumes: the RAR sets of exav-unpack's fixtures, in the order and under the
# kinds `NAMES` in fuzz_targets/volumes.rs gives their names.
python3 - "$OUT/volumes" <<'PY'
import struct, sys
fx = "crates/exav-unpack/tests/fixtures/rar_volumes/"
sets = {
    "set5": [(5, "set5.part1.rar"), (6, "set5.part2.rar"), (7, "set5.part3.rar")],
    "set4": [(9, "set4.r00"), (10, "set4.r01"), (8, "set4.rar")],
    "set4_inorder": [(8, "set4.rar"), (9, "set4.r00"), (10, "set4.r01")],
    "set5_gap": [(5, "set5.part1.rar"), (7, "set5.part3.rar")],
}
for name, parts in sets.items():
    body = bytearray(struct.pack("<HB", 0, len(parts)))
    for kind, f in parts:
        d = open(fx + f, "rb").read()[:65535]
        body += bytes([kind]) + struct.pack("<H", len(d)) + d
    open(f"{sys.argv[1]}/{name}", "wb").write(bytes(body))
PY

for t in analyze unpack filetype; do ln -sfn containers "$OUT/$t"; done
ln -sfn pe "$OUT/pe_emulator"

for d in containers pe drawing imagehash cad_dxf cad_dwg ifc full_pipeline seekable volumes yara pcre cvd database authenticode; do
  echo "$d: $(find "$OUT/$d" -type f | wc -l) seeds"
done
