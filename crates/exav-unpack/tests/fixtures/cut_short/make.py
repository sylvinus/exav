#!/usr/bin/env python3
"""Containers whose one member is text with the EICAR test file in it, each
written by a tool exav does not share code with, for the tests that cut a
member short or damage it part way (exav-core tests/suites/cut_short_members.rs).

    python3 make.py

Writes, each gzipped then XORed with 0x5A as `<name>.gz.xor` (../README.md):

  7z_lzma.7z, 7z_lzma2.7z, 7z_deflate.7z   7-Zip 25.01, `7z a -m0=<codec> -mhc=off`
  7z_bcj2.7z                                7-Zip 25.01, `7z a -mf=BCJ2 -mhc=off`
  swf_cws.swf, swf_zws.swf                  Python's zlib / liblzma (FORMAT_ALONE)
  nsis_solid_lzma.exe, nsis_zlib.exe        makensis 3.11 (`/SOLID lzma`, `zlib`)
  upx_lzma.elf                              gcc + upx 4.2.4 `--lzma` (aarch64 ELF)
  disk.qcow2                                qemu-img 10, `convert -c -o cluster_size=4096`
  disk.vmdk                                 qemu-img 10, `convert -o subformat=streamOptimized`

The content is base64-alphabet noise (seeded), so compressed offsets track
plain ones, with EICAR at a known offset; `make.py` prints where.
"""

import gzip
import lzma
import os
import random
import shutil
import struct
import subprocess
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
# In two pieces, so that no scanner flags this file.
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-" + rb"STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
ALPHA = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
rng = random.Random(7)


def noise(n):
    out = bytearray()
    while len(out) < n:
        out += bytes(rng.choice(ALPHA) for _ in range(76)) + b"\n"
    return bytes(out[:n])


def text(before, after):
    return noise(before) + EICAR + b"\n" + noise(after)


def save(name, data):
    masked = bytes(b ^ 0x5A for b in gzip.compress(data, mtime=0))
    open(os.path.join(HERE, name + ".gz.xor"), "wb").write(masked)
    print(name, len(data))


def run(*cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, stdout=subprocess.DEVNULL)


tmp = tempfile.mkdtemp()
try:
    # 7z: EICAR in the middle.
    open(os.path.join(tmp, "payload.txt"), "wb").write(text(20000, 20000))
    for codec in ("LZMA", "LZMA2", "Deflate", "BCJ2"):
        out = f"{codec}.7z"
        method = "-mf=BCJ2" if codec == "BCJ2" else f"-m0={codec}"
        run("7z", "a", "-t7z", method, "-mhc=off", out, "payload.txt", cwd=tmp)
        save(f"7z_{codec.lower()}.7z", open(os.path.join(tmp, out), "rb").read())

    # SWF: EICAR 85% in.
    body = text(34000, 6000)
    flen = struct.pack("<I", 8 + len(body))
    save("swf_cws.swf", b"CWS\x0a" + flen + zlib.compress(body, 9))
    alone = lzma.compress(body, format=lzma.FORMAT_ALONE)
    stream = alone[13:]
    save("swf_zws.swf", b"ZWS\x0d" + flen + struct.pack("<I", len(stream)) + alone[:5] + stream)

    # NSIS: EICAR 80% into the installed file.
    open(os.path.join(tmp, "payload3.txt"), "wb").write(text(12000, 3000))
    for name, comp in (("solid_lzma", "/SOLID lzma"), ("zlib", "zlib")):
        script = (
            f'Unicode false\nOutFile "{name}.exe"\nSetCompressor {comp}\n'
            "RequestExecutionLevel user\nSection\nSetOutPath $TEMP\n"
            'File "payload3.txt"\nSectionEnd\n'
        )
        open(os.path.join(tmp, f"{name}.nsi"), "w").write(script)
        run("makensis", "-V1", f"{name}.nsi", cwd=tmp)
        save(f"nsis_{name}.exe", open(os.path.join(tmp, f"{name}.exe"), "rb").read())

    # UPX: the text as a const array of an ELF, EICAR in the middle.
    blob = text(30000, 30000)
    src = "const unsigned char blob[] = {" + ",".join(map(str, blob)) + "};\n"
    src += "int main(int c, char **v) { return blob[c * 1000] + (int)sizeof blob; }\n"
    open(os.path.join(tmp, "p.c"), "w").write(src)
    run("gcc", "-O1", "-o", "p", "p.c", cwd=tmp)
    run("upx", "-q", "--lzma", "p", cwd=tmp)
    save("upx_lzma.elf", open(os.path.join(tmp, "p"), "rb").read())

    # Disk images: a 64 KiB disk, the text at its start.
    disk = text(20000, 20000)
    open(os.path.join(tmp, "disk.raw"), "wb").write(disk + bytes(65536 - len(disk)))
    run("qemu-img", "convert", "-c", "-f", "raw", "-O", "qcow2", "-o", "cluster_size=4096",
        "disk.raw", "disk.qcow2", cwd=tmp)
    run("qemu-img", "convert", "-f", "raw", "-O", "vmdk", "-o", "subformat=streamOptimized",
        "disk.raw", "disk.vmdk", cwd=tmp)
    for name in ("disk.qcow2", "disk.vmdk"):
        save(name, open(os.path.join(tmp, name), "rb").read())
finally:
    shutil.rmtree(tmp)
