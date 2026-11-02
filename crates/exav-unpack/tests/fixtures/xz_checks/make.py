#!/usr/bin/env python3
"""Builds the xz fixtures with a check type the decoder does not read.

    python3 make.py        # needs the xz command

plain.bin           the data every stream below decodes to (random bytes, so that
                    LZMA2 stores chunks, then text)
crc32.xz            xz --check=crc32, three blocks (a check the decoder reads)
sha256.xz           xz --check=sha256, three blocks
reserved_*.xz       the same streams with a reserved check type (2, 9, 12, 15),
                    rebuilt from a CRC32 stream: the check bytes are filled
                    with 0xA5 and the index and the stream flags are rewritten
                    (liblzma decodes these without verifying them)
"""
import random
import struct
import subprocess
import zlib

rng = random.Random(7)
plain = bytes(rng.randrange(256) for _ in range(6000)) + b"the quick brown fox jumps over the lazy dog\n" * 140
open("plain.bin", "wb").write(plain)


def xz(check):
    return subprocess.run(
        ["xz", "-c", "-T1", f"--check={check}", "--block-size=4000", "-1"],
        input=plain,
        capture_output=True,
        check=True,
    ).stdout


def vli(n):
    out = b""
    while n >= 0x80:
        out += bytes([n & 0x7F | 0x80])
        n >>= 7
    return out + bytes([n])


def read_vli(b, at):
    v, shift = 0, 0
    while True:
        byte = b[at]
        at += 1
        v |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return v, at


def reserved(check_id):
    """The CRC32 stream with check type `check_id` instead."""
    old = 4  # CRC32
    new = 4 << ((check_id - 1) // 3)
    d = xz("crc32")
    backward = struct.unpack("<I", d[-8:-4])[0]
    index_size = (backward + 1) * 4
    index_at = len(d) - 12 - index_size
    index = d[index_at : len(d) - 12]
    count, at = read_vli(index, 1)
    records = []
    for _ in range(count):
        unpadded, at = read_vli(index, at)
        uncompressed, at = read_vli(index, at)
        records.append((unpadded, uncompressed))
    out = d[:6] + bytes([0, check_id]) + struct.pack("<I", zlib.crc32(bytes([0, check_id])))
    pos = 12
    for unpadded, _ in records:
        block = unpadded - old
        out += d[pos : pos + block]
        out += bytes(-block % 4)
        out += bytes([0xA5]) * new
        pos += (block + 3) // 4 * 4 + old
    body = b"\0" + vli(count)
    for unpadded, uncompressed in records:
        body += vli(unpadded - old + new) + vli(uncompressed)
    body += bytes(-len(body) % 4)
    body += struct.pack("<I", zlib.crc32(body))
    tail = struct.pack("<I", len(body) // 4 - 1) + bytes([0, check_id])
    return out + body + struct.pack("<I", zlib.crc32(tail)) + tail + b"YZ"


open("crc32.xz", "wb").write(xz("crc32"))
open("sha256.xz", "wb").write(xz("sha256"))
for i in (2, 9, 12, 15):
    open(f"reserved_{i}.xz", "wb").write(reserved(i))
