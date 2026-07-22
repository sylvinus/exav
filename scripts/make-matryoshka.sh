#!/bin/sh
# Rebuild crates/exav-core/tests/fixtures/matryoshka.uu: one EICAR test file
# wrapped through twenty-six container formats in a row.
#
# The point of the fixture is the *seams*. Every format has its own test proving
# it decodes; this one proves each layer hands its member to the next format's
# detector in a shape that detector accepts. A break anywhere looks exactly like
# a clean file, which is why the test also pins the behaviour one level short of
# the payload: that must read as LIMITS-EXCEEDED, never as clean.
#
# The first run of this fixture found a real bug — a compressed QCOW2 cluster at
# an odd host offset was being silently zero-filled.
#
# Every layer is produced by that format's own reference tool. Nothing here is
# written by exav, so the fixture cannot agree with exav on a misreading of a
# format. Install the tools with:
#
#   apt-get install zip gzip bzip2 xz-utils zstd lz4 ncompress lzip tar arj \
#                   cpio binutils xar libgsf-bin gcab genisoimage qemu-utils \
#                   wimtools sharutils util-linux python3
#
# plus 7-Zip (`7zz`, https://7-zip.org) and official RAR (`rar`,
# https://rarlab.com) — neither is packaged in Debian main.
#
# Layer order is deliberate: the bulky disk images sit in the middle, so the
# QCOW2 layer above them compresses their megabytes of zeroes back down and the
# finished fixture is ~13 KB.
#
# Usage: scripts/make-matryoshka.sh [output-path]
set -eu

OUT="${1:-crates/exav-core/tests/fixtures/matryoshka.uu}"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

for t in zip lzip gzip bzip2 xz zstd lz4 compress tar 7zz arj rar gcab cpio ar \
         xar gsf wimcapture genisoimage qemu-img fdisk uuencode python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 1; }
done

n=0
step() { n=$((n + 1)); printf '%2d %-10s %10s bytes\n' "$n" "$1" "$(wc -c < "$2")"; }

# Pad a file up to a 512-byte sector so it can be handed to qemu-img as a raw
# disk whose first bytes are the artefact itself — the reconstructed disk then
# types by magic at offset 0 rather than relying on carving.
pad() { python3 -c "
import sys
d = open(sys.argv[1], 'rb').read()
open(sys.argv[2], 'wb').write(d + b'\0' * (-len(d) % 512))" "$1" "$2"; }

# The payload. Not malware: the EICAR industry test string, which every scanner
# is expected to detect and nothing else.
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com

zip -q -9 a01.zip eicar.com                              ; step ZIP      a01.zip
lzip -9 -c a01.zip                > a02.lz               ; step lzip     a02.lz
gzip -9 -c a02.lz                 > a03.gz               ; step gzip     a03.gz
bzip2 -9 -c a03.gz                > a04.bz2              ; step bzip2    a04.bz2
xz -9 -c a04.bz2                  > a05.xz               ; step xz       a05.xz
zstd -19 -q -o a06.zst a05.xz                            ; step zstd     a06.zst
lz4 -9 -q -c a06.zst              > a07.lz4              ; step LZ4      a07.lz4
compress -c a07.lz4               > a08.Z                ; step compress a08.Z
tar cf a09.tar a08.Z                                     ; step tar      a09.tar
7zz a -t7z -mx=9 -bso0 -bsp0 a10.7z a09.tar > /dev/null  ; step 7z       a10.7z
arj a -m1 -i a11.arj a10.7z       > /dev/null 2>&1       ; step ARJ      a11.arj
rar a -m5 -ep -inul a12.rar a11.arj                      ; step RAR5     a12.rar
gcab -c a13.cab a12.rar                                  ; step CAB      a13.cab
echo a13.cab | cpio -o --quiet    > a14.cpio             ; step cpio     a14.cpio
ar rc a15.a a14.cpio 2>/dev/null                         ; step ar       a15.a
xar -cf a16.xar a15.a                                    ; step XAR      a16.xar
cp a16.xar payload.bin
gsf createole a17.ole payload.bin > /dev/null            ; step OLE2     a17.ole

# WIM and ISO take a directory rather than a file.
mkdir wd && cp a17.ole wd/
wimcapture wd a18.wim --compress=LZX > /dev/null 2>&1    ; step WIM      a18.wim

python3 - <<'PY'
from email.message import EmailMessage
m = EmailMessage()
m['Subject'] = 'nested'
m['From'] = 'a@example.invalid'
m['To'] = 'b@example.invalid'
m.set_content('see attachment')
m.add_attachment(open('a18.wim', 'rb').read(), maintype='application',
                 subtype='octet-stream', filename='nested.wim')
open('a19.eml', 'wb').write(m.as_bytes())
PY
step email a19.eml

mkdir id && cp a19.eml id/
genisoimage -quiet -o a20.iso -V NEST id                 ; step ISO      a20.iso

pad a20.iso r21.raw
qemu-img convert -f raw -O vhdx -o block_size=1M r21.raw a21.vhdx
step VHDX a21.vhdx
pad a21.vhdx r22.raw
qemu-img convert -f raw -O vpc r22.raw a22.vhd           ; step VHD      a22.vhd
pad a22.vhd r23.raw
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized r23.raw a23.vmdk
step VMDK a23.vmdk

# An MBR partition table whose first partition holds the previous artefact.
python3 -c "
d = open('a23.vmdk', 'rb').read()
open('a24.img', 'wb').write(b'\0' * (2048 * 512) + d + b'\0' * (-len(d) % 512))"
printf 'o\nn\np\n1\n2048\n\nw\n' | fdisk a24.img > /dev/null 2>&1
step MBR a24.img

pad a24.img r25.raw
qemu-img convert -f raw -O qcow2 -c -o cluster_size=512 r25.raw a25.qcow2
step QCOW2 a25.qcow2
uuencode a25.qcow2 nested.qcow2  > matryoshka.uu         ; step uuencode matryoshka.uu

cp matryoshka.uu "$OUT"
echo "wrote $OUT"
