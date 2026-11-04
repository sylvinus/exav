#!/usr/bin/env python3
"""Write the files a compressing filesystem has something to do on.

    zextras.py DIR [--zeros-only]

Data that compresses well and data that does not, in one file and apart: long
extents, extents stored as they are, and the zeros of a long run. The same
bytes are made by `z_extras` in `tests/suites/erofs.rs`, which is what the
walk of an image is compared with. --zeros-only writes the one file of zeros,
64 MiB, that the memory tests read.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tree import pat  # noqa: E402


def noise(seed, n):
    """Bytes a compressor cannot shrink."""
    return bytes(
        ((((i * 2654435761) + seed * 40503) & 0xFFFFFFFF) >> 13) & 0xFF
        for i in range(n)
    )


def rep(seed, n):
    """n bytes of a block of 4099, repeated: long matches, far apart."""
    block = pat(seed, 4099)
    return (block * (n // len(block) + 1))[:n]


def mixed(n):
    """Pieces of 20000 bytes that alternate between noise and repeats."""
    out = bytearray()
    k = 0
    while len(out) < n:
        out += noise(60 + k, 20000) if k % 2 == 0 else rep(70 + k, 20000)
        k += 1
    return bytes(out[:n])


def write(root, path, data):
    p = os.path.join(root, path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)


def main():
    root = sys.argv[1]
    if "--zeros-only" in sys.argv:
        write(root, "zeros.bin", bytes(64 << 20))
        return
    write(root, "z/rep.bin", rep(7, 1500000))
    write(root, "z/zeros.bin", bytes(3000000))
    write(root, "z/noise.bin", noise(5, 20000))
    write(root, "z/mixed.bin", mixed(120000))


if __name__ == "__main__":
    main()
