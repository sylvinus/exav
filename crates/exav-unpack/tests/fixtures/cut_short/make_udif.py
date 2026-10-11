#!/usr/bin/env python3
"""UDIF disk images (DMG) of one HFS+ volume, its whole disk in one compressed
run, for the tests that damage a run part way (exav-core
tests/suites/cut_short_members.rs).

    python3 make_udif.py

The disk is ../dmg/hfs_plus_udrw.dmg (a raw HFS+ disk written by hdiutil)
with its one file, test.txt, grown to one allocation block of text with the
EICAR test file in it, and the volume's free blocks around it filled with
words, so the run does not compress to almost nothing (bzip2's blocks then
end around the file). The run is written by Python's zlib,
bz2 (level 1: 100 kB blocks) and lzma (.xz): udif_<codec>.dmg, gzipped then
XORed with 0x5A as `<name>.gz.xor` (../README.md). The data fork is 512
unused bytes then the run, so the run is file[512..XMLOffset].

udif_bzip2_first.dmg and udif_xz_first.dmg have no unused bytes: the file
opens with a bzip2 or xz run (the disk up to test.txt), and a zlib run holds
the rest of the disk, for the test that such an image is walked as a DMG.

For each, prints what the codec's own Python decoder, fed 16 bytes at a
time, recovers from copies with 256 bytes of 0xFF 30% and 90% into the run.
"""

import base64
import bz2
import gzip
import lzma
import os
import random
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
# In two pieces, so that no scanner flags this file.
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-" + rb"STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
ALPHA = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
rng = random.Random(11)


WORDS = [bytes(rng.choice(ALPHA) for _ in range(rng.randint(3, 8))) for _ in range(256)]


def noise(n):
    """Words drawn from a fixed list: compresses about 3:1, with no runs
    bzip2's first stage would collapse."""
    out = bytearray()
    while len(out) < n:
        out += rng.choice(WORDS) + b" "
    return bytes(out[:n])


disk = bytearray(open(os.path.join(HERE, "../dmg/hfs_plus_udrw.dmg"), "rb").read())
part = 0x5000  # the HFS+ volume; its header is 1024 bytes in
vh = part + 1024
assert disk[vh : vh + 2] == b"H+"
block = struct.unpack(">I", disk[vh + 40 : vh + 44])[0]
blocks = struct.unpack(">I", disk[vh + 44 : vh + 48])[0]
bitmap_at = part + block * struct.unpack(">I", disk[vh + 128 : vh + 132])[0]

# test.txt's catalog record, found by its BSD info as tests/suites/dmg.rs does;
# its data fork: logical size 88 bytes into the record, first extent at 104.
bsd = bytes([0, 0, 1, 0xF5, 0, 0, 0, 0x14, 0, 0, 0x81, 0xA4])
rec = disk.find(bsd) - 32
file_block = struct.unpack(">I", disk[rec + 104 : rec + 108])[0]
content = noise(1500) + EICAR + b"\n" + noise(block - 1500 - len(EICAR) - 1)
disk[rec + 88 : rec + 96] = struct.pack(">Q", len(content))
at = part + file_block * block
disk[at : at + block] = content
eicar_at = at + 1500

# Free blocks from 25 before the file's to the end of the volume.
for b in range(file_block - 25, blocks):
    if not disk[bitmap_at + b // 8] & (0x80 >> (b % 8)):
        disk[part + b * block : part + (b + 1) * block] = noise(block)

SECTORS = len(disk) // 512
PAD = 512
CODECS = {
    "zlib": (0x80000005, lambda d: zlib.compress(d, 9), zlib.decompressobj),
    "bzip2": (0x80000006, lambda d: bz2.compress(d, 1), bz2.BZ2Decompressor),
    "xz": (0x80000008, lambda d: lzma.compress(d, lzma.FORMAT_XZ), lzma.LZMADecompressor),
}


def udif(kind, run, more=(), pad=PAD):
    """The data fork (`pad` unused bytes, then the run, then the `more` runs
    as `(kind, sectors, data)`), the plist, then the koly trailer. The unused
    bytes keep the file from opening with the run's own magic, which exav
    once took for a bare bzip2 or xz stream."""
    first = SECTORS - sum(n for _, n, _ in more)
    runs = [(kind, first, run), *more]
    fork = bytes(pad) + b"".join(data for _, _, data in runs)
    mish = b"mish" + struct.pack(">IQQQII", 1, 0, SECTORS, 0, 0, 2)
    mish += bytes(200 - len(mish)) + struct.pack(">I", len(runs) + 1)
    sector, offset = 0, pad
    for k, n, data in runs:
        mish += struct.pack(">IIQQQQ", k, 0, sector, n, offset, len(data))
        sector, offset = sector + n, offset + len(data)
    mish += struct.pack(">IIQQQQ", 0xFFFFFFFF, 0, SECTORS, 0, len(fork), 0)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
        "<key>resource-fork</key><dict><key>blkx</key><array><dict>"
        "<key>Name</key><string>disk image</string>"
        f"<key>Data</key><data>{base64.b64encode(mish).decode()}</data>"
        "</dict></array></dict></dict></plist>\n"
    ).encode()
    koly = bytearray(512)
    koly[0:16] = b"koly" + struct.pack(">III", 4, 512, 1)
    koly[24:40] = struct.pack(">QQ", 0, len(fork))
    koly[216:232] = struct.pack(">QQ", len(fork), len(xml))
    koly[488:500] = struct.pack(">IQ", 1, SECTORS)
    return fork + xml + bytes(koly)


def oracle(new, data):
    dec, out = new(), b""
    try:
        for i in range(0, len(data), 16):
            out += dec.decompress(data[i : i + 16])
    except Exception as e:  # noqa: BLE001 (each codec has its own error type)
        return out, type(e).__name__
    return out, "ok"


print(f"EICAR at {eicar_at}, disk {len(disk)}")
for name, (kind, compress, new) in CODECS.items():
    run = compress(bytes(disk))
    image = udif(kind, run)
    masked = bytes(b ^ 0x5A for b in gzip.compress(image, mtime=0))
    open(os.path.join(HERE, f"udif_{name}.dmg.gz.xor"), "wb").write(masked)
    for pct in (30, 90):
        d = bytearray(run)
        p = len(run) * pct // 100
        d[p : p + 256] = b"\xff" * 256
        out, how = oracle(new, bytes(d))
        found = out[eicar_at : eicar_at + len(EICAR)] == EICAR
        print(f"{name} run {len(run)}, 0xFF at {pct}%: {how}, {len(out)} bytes, EICAR {found}")

# The data fork opening with its first run, as hdiutil writes UDBZ and ULMO
# images, so the file starts with that run's bzip2 or xz magic. The disk up
# to test.txt's block is that run and the rest, EICAR in it, one zlib run:
# read as a bare bzip2 or xz stream, the file never reaches EICAR.
split = at // 512
zlib_kind, zlib_compress, _ = CODECS["zlib"]
rest = (zlib_kind, SECTORS - split, zlib_compress(bytes(disk[split * 512 :])))
for name in ("bzip2", "xz"):
    kind, compress, _ = CODECS[name]
    image = udif(kind, compress(bytes(disk[: split * 512])), [rest], pad=0)
    masked = bytes(b ^ 0x5A for b in gzip.compress(image, mtime=0))
    open(os.path.join(HERE, f"udif_{name}_first.dmg.gz.xor"), "wb").write(masked)
    print(f"udif_{name}_first: {name} run of sectors 0..{split}, zlib run after")
