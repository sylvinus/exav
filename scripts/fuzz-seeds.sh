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
mkdir -p "$OUT"/{containers,pe,drawing,imagehash,raw_preview,cad_dxf,cad_dwg,ifc,mesh,markdown,visible_text,full_pipeline,seekable,volumes,vdisk,fsimage,lzo,yara,pcre,cvd,database,authenticode,sheets_xls,sheets_ods,sheets_numbers,sheets_text,slides_ppt,slides_odp,slides_odg,slides_vsdx,slides_keynote,docs_doc,docs_odt,docs_rtf,docs_wml,docs_html,docs_pages}

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

# imagehash also runs exav-render's JPEG 2000, JBIG2 and JPEG XL files, and the
# viewer's JPXDecode, JBIG2Decode and CCITTFaxDecode streams.
while IFS= read -r f; do
  case "$f" in *.py | *.json | *.pdf) continue ;; esac
  add "$f" "$OUT/imagehash"
done < <(
  files 'crates/exav-imagehash/tests/fixtures/img/**' 'fuzz/seeds/imagehash/**' \
    'crates/exav-render/tests/fixtures/images/**' 'crates/exav-viewer/e2e/fixtures/pdf-images/**'
)

# raw_preview: exav-render's synthetic camera RAW files (written by their
# make.py), and the TIFFs and JPEG that `decode_any` falls back to.
while IFS= read -r f; do
  case "$f" in *.py) continue ;; esac
  add "$f" "$OUT/raw_preview"
done < <(files 'crates/exav-render/tests/fixtures/raw/*' 'crates/exav-imagehash/tests/fixtures/img/*')

# ifc: exav-render's IFC and STL fixtures (STEP text and STL written by
# their make.py), the viewer tests' house in both.
while IFS= read -r f; do add "$f" "$OUT/ifc"; done < <(
  files 'crates/exav-render/tests/fixtures/ifc/*.ifc' 'crates/exav-render/tests/fixtures/stl/*.stl' \
    'crates/exav-render/tests/fixtures/viewer/*'
)

# vdisk: the disk images written for it (fuzz/seeds/vdisk, each behind the byte
# that picks its format), and the disk image fixtures behind 0x08, which tries
# every format.
cp fuzz/seeds/vdisk/* "$OUT/vdisk/"
for f in "$OUT"/containers/*; do
  if [ -n "$(head -c 4 "$f" | grep -a -e 'QFI' -e 'KDMV' -e 'vhdx' -e 'cone')" ]; then
    { printf '\010'; cat "$f"; } >"$OUT/vdisk/fixture_$(basename "$f")"
  fi
done
# The small DMG fixtures (HFS+ in a zlib run and in LZFSE runs), behind 0x07: a
# koly trailer, no magic first. The APFS ones are too big for a seed.
for f in crates/exav-unpack/tests/fixtures/dmg/hfs_plus_udzo.dmg crates/exav-unpack/tests/fixtures/dmg/udif_lzfse.dmg; do
  { printf '\007'; cat "$f"; } >"$OUT/vdisk/fixture_$(basename "$f")"
done

# fsimage and lzo: the small images and blocks written for them
# (fuzz/seeds/fsimage and fuzz/seeds/lzo, each behind the byte or the two bytes
# their target reads first).
cp fuzz/seeds/fsimage/*.bin "$OUT/fsimage/"
cp fuzz/seeds/lzo/*.bin "$OUT/lzo/"

# full_pipeline: a zero header (no option bits, no database files: the
# signatures are fuzz/db/'s) in front of each fixture. seekable: no option
# bits, reads of 297 bytes, no failure.
for f in "$OUT"/containers/*; do
  name="$(basename "$f")"
  { printf '\000\000\000'; cat "$f"; } >"$OUT/full_pipeline/$name"
  { printf '\000\000\010\000'; cat "$f"; } >"$OUT/seekable/$name"
  # The same behind a reader that fails: at once, and a quarter of the way in.
  { printf '\000\000\010\001'; cat "$f"; } >"$OUT/seekable/fail_first_$name"
  { printf '\000\000\010\100'; cat "$f"; } >"$OUT/seekable/fail_quarter_$name"
done

# full_pipeline also gets the files of fuzz/db/ in the header, one a seed and
# eight of them in one, over a text that several of their signatures match
# (the kind byte indexes `KINDS` in fuzz/db.rs, bit 7 is "official").
python3 - "$OUT/full_pipeline" <<'PY'
import os, struct, sys
kinds = ["ndb","ldb","hdb","hsb","mdb","msb","cdb","ftm","yar","pdb","gdb","wdb","fdb","imp","crb","db","fp","sfp","ign","ign2","pwdb","cbc","idb"]
# The antivirus test string, backwards: this tree may not carry it whole.
scan = ("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X"[::-1].encode() + b"\n"
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
  # And one database per file, so each kind's stored form is a seed of its own.
  for f in fuzz/db/fuzz.*; do
    one="$(mktemp -d)"
    cp "$f" "$one/"
    "$exav" -d "$one" --build-db "$OUT/database/only_${f##*.}.exavdb" "$OUT/database/sample.bin" >/dev/null 2>&1 || true
    rm -rf "$one"
  done
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

# mesh: a triangle and a quad as OBJ, PLY (ASCII and binary) and glTF (a
# document with its buffer embedded, and a GLB), written here.
python3 - "$OUT/mesh" <<'PY'
import base64, json, struct, sys
out = sys.argv[1]
def put(name, data):
    open(f"{out}/{name}", "wb").write(data if isinstance(data, bytes) else data.encode())
put("quad.obj", "# a quad and a triangle\no seed\nv 0 0 0\nv 1 0 0 1 0 0\nv 1 1 0\nv 0 1 0\nvn 0 0 1\nvt 0 0\ng quad\nf 1/1/1 2/1/1 3/1/1 4/1/1\ng tri\nf -4 -3 -2\n")
put("quad.ply", "ply\nformat ascii 1.0\ncomment seed\nelement vertex 4\nproperty float x\nproperty float y\nproperty float z\nproperty uchar red\nproperty uchar green\nproperty uchar blue\nelement face 2\nproperty list uchar int vertex_indices\nend_header\n0 0 0 255 0 0\n1 0 0 0 255 0\n1 1 0 0 0 255\n0 1 0 9 9 9\n4 0 1 2 3\n3 0 1 2\n")
verts = [(0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1)]
faces = [(0, 2, 1), (0, 1, 3), (0, 3, 2), (1, 2, 3)]
for order, tag in (("<", "binary_little_endian"), (">", "binary_big_endian")):
    head = f"ply\nformat {tag} 1.0\nelement vertex 4\nproperty float x\nproperty float y\nproperty float z\nelement face 4\nproperty list uchar uint vertex_indices\nend_header\n"
    body = b"".join(struct.pack(order + "fff", *v) for v in verts) + b"".join(struct.pack(order + "BIII", 3, *f) for f in faces)
    put(f"tetra_{tag}.ply", head.encode() + body)
buf = b"".join(struct.pack("<fff", *v) for v in verts) + b"".join(struct.pack("<HHH", *f) for f in faces)
buf += b"\0" * (-len(buf) % 4)
doc = {
    "asset": {"version": "2.0"},
    "scene": 0, "scenes": [{"nodes": [0]}],
    "nodes": [{"mesh": 0, "translation": [1, 2, 3], "children": [1]}, {"scale": [2, 2, 2], "mesh": 0}],
    "meshes": [{"primitives": [{"attributes": {"POSITION": 0}, "indices": 1, "material": 0}]}],
    "materials": [{"pbrMetallicRoughness": {"baseColorFactor": [0.8, 0.4, 0.1, 1]}}],
    "accessors": [
        {"bufferView": 0, "componentType": 5126, "count": 4, "type": "VEC3"},
        {"bufferView": 1, "componentType": 5123, "count": 12, "type": "SCALAR"},
    ],
    "bufferViews": [{"buffer": 0, "byteLength": 48}, {"buffer": 0, "byteOffset": 48, "byteLength": 24}],
    "buffers": [{"byteLength": len(buf)}],
}
doc["buffers"][0]["uri"] = "data:application/octet-stream;base64," + base64.b64encode(buf).decode()
put("tetra.gltf", json.dumps(doc))
del doc["buffers"][0]["uri"]
j = json.dumps(doc).encode()
j += b" " * (-len(j) % 4)
glb = struct.pack("<4sII", b"glTF", 2, 12 + 8 + len(j) + 8 + len(buf))
glb += struct.pack("<II", len(j), 0x4E4F534A) + j + struct.pack("<II", len(buf), 0x004E4942) + buf
put("tetra.glb", glb)
PY

# markdown: one document with every construct the reader folds, and the
# links it must refuse.
python3 - "$OUT/markdown" <<'PY'
import sys
out = sys.argv[1]
def put(name, data):
    open(f"{out}/{name}", "wb").write(data.encode())
put("all.md", "# Title #\n\nSetext\n=====\n\nSome *em*, **strong**, ~~gone~~, `code` and a hard  \nbreak, &amp; &hearts; &#x41;.\n\n> quote\ncontinued\n>> nested\n\n- one\n- two\n  - sub\n\n3. three\n4. four\n\n- loose\n\n- items\n\n```rust\nfn main() {}\n```\n\n    indented\n\n---\n\n| A | B |\n|:--|--:|\n| 1 | 2 |\n| 3 |\n\n[docs](https://example.com/a \"title\") <https://example.com/x> <me@example.com>\n[ref][1] ![alt *x*](https://example.com/i.png)\n\n[1]: https://example.com/ref\n\n<div onclick=alert(1)>raw</div>\n\ntext <b>inline</b> html\n")
put("links.md", "[a](javascript:alert(1)) [b](https://user:pass@example.com/) [c](https://a@b/) [d](data:text/html,x) [e](//host/x) [f](mailto:me@example.com) [g](<https://example.com/a b>)\n")
put("deep.md", "> " * 30 + "x\n" + "".join("  " * i + "- l%d\n" % i for i in range(30)))
PY

# visible_text: the first byte picks the reader (the target's NAMES: Markdown,
# HTML, the Word, sheet, shared strings, slide and OpenDocument parts, PDF, DXF,
# DWG), the rest is a document of that kind. Drawings are the cad seeds.
python3 - "$OUT" <<'PY'
import glob, os, sys, zlib
out = sys.argv[1]
dst = f"{out}/visible_text"
def put(name, pick, data):
    open(f"{dst}/{name}", "wb").write(bytes([pick]) + (data if isinstance(data, bytes) else data.encode()))
put("all.md", 0, open(f"{out}/markdown/all.md", "rb").read())
put("page.html", 1, "<!doctype html><html><head><title>T &amp; U</title><style>p{}</style><script>var x='<b>';</script></head><body><p>Click <b>here</b> to <a href=\"https&#58;//evil.example/x?a=1&amp;b=2\">https://www.paypal.com/login</a></p><img alt=\"a diagram\" src=x><table><tr><td>a<td>b</table><!-- hid --></body></html>")
put("fragment.html", 1, "Hi <a href='javascript:alert(1)'>run</a> <br> &hearts;&notit;&#x41;&zzz;")
put("document.xml", 2, '<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:instrText>HYPERLINK "http://x"</w:instrText></w:r><w:r><w:delText>gone</w:delText></w:r><w:r><w:t xml:space="preserve"> world &amp; &#65;</w:t></w:r></w:p></w:body></w:document>')
put("sheet.xml", 3, '<worksheet><sheetData><row><c t="s"><v>0</v></c><c><f>HYPERLINK("http://x","y")</f></c></row><row><c t="inlineStr"><is><t>z</t></is></c></row></sheetData></worksheet>')
put("shared.xml", 4, "<sst><si><t>one</t></si><si><r><t>tw</t></r><r><t>o</t></r></si></sst>")
put("slide.xml", 5, "<p:sld><a:p><a:r><a:t>Title</a:t></a:r></a:p><a:p><a:r><a:t>Body</a:t></a:r><a:br/></a:p></p:sld>")
put("content.xml", 6, "<office:text><text:h>Head</text:h><text:p>a <text:span>b</text:span><text:s/>c<text:line-break/>d</text:p><table:table-row><table:table-cell><text:p>x</text:p></table:table-cell></table:table-row></office:text>")
content = "BT /F1 12 Tf 72 700 Td [(Pay to ev) 10 (il.exa) 5 (mple)] TJ 0 -20 Td (Second line) Tj ET"
pdf = (f"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
       f"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj\n"
       f"4 0 obj<</Length {len(content)}>>\nstream\n{content}\nendstream\nendobj\n"
       f"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
put("page.pdf", 7, pdf)
z = zlib.compress(content.encode())
put("flate.pdf", 7, (f"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
       f"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 9 9]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj\n"
       f"4 0 obj<</Length {len(z)}/Filter/FlateDecode>>\nstream\n").encode() + z +
       b"\nendstream\nendobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
put("mtext.dxf", 8, "  0\nSECTION\n  2\nENTITIES\n  0\nMTEXT\n  8\n0\n 10\n0.0\n 20\n0.0\n 30\n0.0\n 40\n2.5\n  1\nPay\\Pnow\n  0\nENDSEC\n  0\nEOF\n")
for pick, seeds in ((8, "cad_dxf"), (9, "cad_dwg")):
    for path in sorted(glob.glob(f"{out}/{seeds}/*"))[:6]:
        put("cad-" + os.path.basename(path), pick, open(path, "rb").read())
PY

# The sheets targets: the `sheets` fixtures, and for sheets_numbers the
# fixture's IWA streams joined, which the target stores in a ZIP itself (a
# joined stream is one stream to the reader), and a Numbers '09 index.xml,
# plain and gzipped, which it stores the same way.
SHEETS=crates/exav-render/tests/fixtures/office/sheets
for f in "$SHEETS/sample.xls"; do add "$f" "$OUT/sheets_xls"; done
for f in "$SHEETS/sample.ods" "$SHEETS/sample.fods"; do add "$f" "$OUT/sheets_ods"; done
for f in "$SHEETS/sample.numbers" fuzz/seeds/sheets_numbers/*; do add "$f" "$OUT/sheets_numbers"; done
python3 - "$SHEETS/sample.numbers" "$OUT/sheets_numbers/sample.iwa" fuzz/seeds/sheets_numbers/index09.xml "$OUT/sheets_numbers/index09.xml.gz" <<'PY'
import gzip, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
open(sys.argv[2], "wb").write(b"".join(z.read(n) for n in z.namelist() if n.endswith(".iwa")))
open(sys.argv[4], "wb").write(gzip.compress(open(sys.argv[3], "rb").read(), mtime=0))
PY
# sheets_text: the text fixtures behind the byte that picks their reader.
python3 - "$OUT/sheets_text" <<'PY'
import sys
d = "crates/exav-render/tests/fixtures/office/sheets/"
for pick, name in ((0, "sample-2003.xml"), (1, "sample.html"), (2, "sample.slk")):
    open(f"{sys.argv[1]}/{name}", "wb").write(bytes([pick]) + open(d + name, "rb").read())
PY

# The slides targets: the `slides` fixtures. slides_ppt gets the PPT's
# `PowerPoint Document` stream, which the target stores in a compound file
# itself (the fixture is over MAX_BYTES with its thumbnail); slides_keynote the
# Keynote document's IWA streams joined, but its package metadata.
SLIDES=crates/exav-render/tests/fixtures/office/slides
for f in "$SLIDES/sample.odp" "$SLIDES/sample.fodp" "$SLIDES/chart.fodp"; do add "$f" "$OUT/slides_odp"; done
DRAW=crates/exav-render/tests/fixtures/office/draw
for f in "$DRAW/sample.odg" "$DRAW/sample.fodg"; do add "$f" "$OUT/slides_odg"; done
for f in "$DRAW/sample.vsdx" "$DRAW/themed.vsdx"; do add "$f" "$OUT/slides_vsdx"; done
# Keynote 1 to 5's XML and a PowerPoint 95 stream, written by hand.
for f in fuzz/seeds/slides_keynote/*; do add "$f" "$OUT/slides_keynote"; done
add fuzz/seeds/slides_ppt/powerpoint95.bin "$OUT/slides_ppt"
python3 - "$SLIDES" "$OUT" <<'PY'
import struct, sys, zipfile
d, out = sys.argv[1], sys.argv[2]
z = zipfile.ZipFile(f"{d}/sample.key")
iwa = [n for n in z.namelist() if n.endswith(".iwa") and not n.endswith("/Metadata.iwa")]
open(f"{out}/slides_keynote/sample.iwa", "wb").write(b"".join(z.read(n) for n in iwa))
# The one stream, from the FAT: version 3, its first 109 FAT sectors.
b = open(f"{d}/sample.ppt", "rb").read()
ss = 1 << struct.unpack_from("<H", b, 30)[0]
sec = lambda i: b[(i + 1) * ss:(i + 2) * ss]
fat = b"".join(sec(i) for i in struct.unpack_from("<109I", b, 76) if i < 0xFFFFFFFA)
nxt = lambda i: struct.unpack_from("<I", fat, i * 4)[0]
def chain(i):
    while i < 0xFFFFFFFA:
        yield sec(i)
        i = nxt(i)
dirs = b"".join(chain(struct.unpack_from("<I", b, 48)[0]))
for o in range(0, len(dirs), 128):
    e = dirs[o:o + 128]
    name = e[:struct.unpack_from("<H", e, 64)[0]].decode("utf-16-le").rstrip("\0")
    if name == "PowerPoint Document":
        start, size = struct.unpack_from("<IQ", e, 116)
        open(f"{out}/slides_ppt/document.bin", "wb").write(b"".join(chain(start))[:size])
PY

# The docs targets: the `docs` fixtures. docs_pages has none of its own
# yet: the Keynote document's IWA streams are the nearest thing (same archive
# layer).
D=crates/exav-render/tests/fixtures/office/docs
add "$D/sample.doc" "$OUT/docs_doc"
# A Word 6 document, written by the reader's tests (tests/office_common).
for f in fuzz/seeds/docs_doc/*; do add "$f" "$OUT/docs_doc"; done
for f in "$D/sample.odt" "$D/sample.fodt"; do add "$f" "$OUT/docs_odt"; done
add "$D/sample.rtf" "$OUT/docs_rtf"
add "$D/sample-2003.xml" "$OUT/docs_wml"
add "$D/sample.html" "$OUT/docs_html"
cp "$OUT/slides_keynote/sample.iwa" "$OUT/docs_pages/sample.iwa"

# visible_text, the office formats: each fixture behind the byte that picks its
# name in the target's NAMES (11 a.doc, 12 a.xls, 13 a.ppt, 14 a.rtf, 15 a.xml,
# 16 a.slk, 17 a.fodt, 18 a.fods, 19 a.fodp, 20 a.fodg, 21 a.numbers,
# 22 a.pages, 23 a.key), within MAX_BYTES.
python3 - "$OUT/visible_text" "$MAX_BYTES" crates/exav-render/tests/fixtures/office <<'PY'
import os, sys
dst, limit, root = sys.argv[1], int(sys.argv[2]), sys.argv[3]
for pick, path in (
    (11, "docs/sample.doc"), (14, "docs/sample.rtf"), (15, "docs/sample-2003.xml"), (17, "docs/sample.fodt"),
    (12, "sheets/sample.xls"), (15, "sheets/sample-2003.xml"), (16, "sheets/sample.slk"), (18, "sheets/sample.fods"), (21, "sheets/sample.numbers"),
    (13, "slides/sample.ppt"), (19, "slides/sample.fodp"), (23, "slides/sample.key"), (20, "draw/sample.fodg"),
):
    data = open(f"{root}/{path}", "rb").read()
    if len(data) < limit:
        open(f"{dst}/office-{path.replace('/', '-')}", "wb").write(bytes([pick]) + data)
PY

# Small seeds written from what each target's source reads (see the script).
python3 scripts/fuzz-seeds-synth.py "$OUT"

for t in analyze unpack filetype; do ln -sfn containers "$OUT/$t"; done
ln -sfn pe "$OUT/pe_emulator"

for d in containers pe drawing imagehash raw_preview cad_dxf cad_dwg ifc mesh markdown visible_text full_pipeline seekable volumes yara pcre cvd database authenticode sheets_xls sheets_ods sheets_numbers sheets_text slides_ppt slides_odp slides_odg slides_vsdx slides_keynote docs_doc docs_odt docs_rtf docs_wml docs_html docs_pages; do
  echo "$d: $(find "$OUT/$d" -type f | wc -l) seeds"
done
