#!/usr/bin/env python3
"""Write, in the current directory, what only a mounted filesystem makes.

    extras.py [--trunc-only]

Preallocated space that was written in part, a hole punched in a written file,
a file written across the holes of deleted ones, a file longer than what was
written to it, and a directory that lost a third of its entries. The matching
list is `extras` in `tests/suites/fs_tree.rs`.
"""
import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tree import pat  # noqa: E402

KEEP_SIZE, PUNCH_HOLE = 1, 2


def main():
    os.mkdir("k")
    # Blocks that hold something when they are preallocated, to be read as zeros.
    with open("k/stale", "wb") as f:
        f.write(b"stale" * (1 << 18))
        f.flush()
        os.fsync(f.fileno())
    os.unlink("k/stale")
    os.sync()
    # A file longer than what was written to it. Only this, for a filesystem
    # that keeps the length written apart (exFAT) and has no holes or
    # preallocation to speak of.
    with open("k/trunc.bin", "wb") as f:
        f.write(b"abc")
        f.truncate(100000)
    if "--trunc-only" in sys.argv:
        return
    fd = os.open("k/prealloc.bin", os.O_CREAT | os.O_WRONLY)
    os.posix_fallocate(fd, 0, 1 << 20)
    os.pwrite(fd, pat(3000, 5000), 300000)
    os.close(fd)

    with open("k/holey.bin", "wb") as f:
        f.write(pat(3001, 1 << 20))
    fd = os.open("k/holey.bin", os.O_WRONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fallocate(fd, PUNCH_HOLE | KEEP_SIZE, ctypes.c_long(100000), ctypes.c_long(300000))
    os.close(fd)

    os.mkdir("k/d")
    for i in range(300):
        with open("k/d/f%d" % i, "wb") as f:
            f.write(b"x" * i)
    for i in range(0, 300, 3):
        os.unlink("k/d/f%d" % i)


if __name__ == "__main__":
    main()
