#!/usr/bin/env python3
"""Write the seeds of the `lzo` fuzz target into this directory.

    python3 make.py

Each seed is the most the decoder may write (two bytes, little-endian) and the
LZO1X stream of the first block of a file compressed by `lzop`, at levels 1 and
9, of text and of bytes that are runs and noise.
"""
import os
import random
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def first_block(lzo):
    """The compressed first block of an lzop file, and its uncompressed size."""
    p = 9 + 2 + 2 + 2 + 1 + 1
    (flags,) = struct.unpack_from(">I", lzo, p)
    p += 4
    if flags & 0x800:
        p += 4
    p += 4 + 4 + 4
    p += 1 + lzo[p] + 4
    usize, csize = struct.unpack_from(">II", lzo, p)
    p += 8
    # The checksums of the uncompressed data, and of the compressed if it is.
    p += 4 * ((flags & 1) + ((flags >> 8) & 1))
    if csize < usize:
        p += 4 * (((flags >> 1) & 1) + ((flags >> 9) & 1))
    return lzo[p : p + csize], usize


def main():
    rnd = random.Random(7)
    text = (b"the quick brown fox jumps over the lazy dog. " * 40 + bytes(range(256)) * 3) * 4
    mixed = b"".join(
        bytes([rnd.randrange(256)]) * rnd.randrange(1, 40) if i % 3 else rnd.randbytes(rnd.randrange(1, 30))
        for i in range(600)
    )
    with tempfile.TemporaryDirectory() as w:
        for name, data in (("text", text), ("mixed", mixed)):
            src = os.path.join(w, name)
            open(src, "wb").write(data)
            for level in ("-1", "-9"):
                out = subprocess.run(
                    ["lzop", level, "-c", src], check=True, capture_output=True
                ).stdout
                block, usize = first_block(out)
                open(os.path.join(HERE, f"{name}{level}.bin"), "wb").write(
                    struct.pack("<H", min(usize, 0xFFFF)) + block
                )


if __name__ == "__main__":
    sys.exit(main())
