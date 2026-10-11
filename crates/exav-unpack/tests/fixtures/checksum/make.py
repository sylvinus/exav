#!/usr/bin/env python3
"""Archives for the checksum-mismatch tests (exav-core
tests/suites/checksum_mismatch.rs), each written by the format's own tool:

    python3 make.py

* bzip2 1.0.8 (`bzip2 -1`, 100 kB blocks): two_blocks.bz2 (EICAR in the
  second block) and clean.bz2 (two blocks, no EICAR);
* lzip 1.25: two_members.lz (two `lzip` outputs concatenated, EICAR in the
  second) and clean.lz;
* wimlib 1.14.4 (`wimcapture --compress=LZX`): eicar.wim and clean.wim, one
  file each;
* arc 5.21q (`arc a`, which picks the method, here crunched): eicar.arc and
  clean.arc.

The files holding EICAR are XORed with 0x5A as `<name>.xor` (../README.md).
The tests patch the recorded checksums at run time; nothing here is damaged.
In every file EICAR is compressed: its bytes do not appear in the clear.
"""

import os
import random
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
# In two pieces, so that no scanner flags this file.
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-" + rb"STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
ALPHA = b"abcdefghijklmnopqrstuvwxyz"
rng = random.Random(7)
WORDS = [bytes(rng.choice(ALPHA) for _ in range(rng.randint(2, 9))) for _ in range(400)]


def text(n):
    """Words from a fixed list: compresses, with no long runs."""
    out = bytearray()
    while len(out) < n:
        out += rng.choice(WORDS) + b" "
    return bytes(out[:n])


def lines(n):
    """Numbered lines: repetitive enough that arc crunches them (LZW)
    rather than squeezing them (Huffman, which exav does not decode)."""
    return b"".join(
        b"line %d: the quick brown fox jumps over the lazy dog %d\n" % (i, rng.randrange(100))
        for i in range(n)
    )


def run(*cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def put(name, data):
    """Write `name`, masked unless it is a clean one."""
    assert EICAR not in data, name
    masked = not name.startswith("clean")
    path = os.path.join(HERE, name + (".xor" if masked else ""))
    if masked:
        data = bytes(b ^ 0x5A for b in data)
    with open(path + ".tmp", "wb") as f:
        f.write(data)
    os.replace(path + ".tmp", path)


def tool(cmd, files, out, tmp):
    """Run `cmd` in a fresh directory holding `files`, return `out`'s bytes."""
    d = tempfile.mkdtemp(dir=tmp)
    for name, data in files.items():
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
    run(*cmd, cwd=d)
    with open(os.path.join(d, out), "rb") as f:
        return f.read()


def main():
    tmp = tempfile.mkdtemp()
    try:
        # bzip2 -1 cuts blocks at about 100 kB of input: EICAR at 120 kB is in
        # the second.
        big = text(120_000) + EICAR + text(40_000)
        put("two_blocks.bz2", tool(["bzip2", "-1", "-k", "in"], {"in": big}, "in.bz2", tmp))
        put("clean.bz2", tool(["bzip2", "-1", "-k", "in"], {"in": text(160_000)}, "in.bz2", tmp))

        first = tool(["lzip", "-k", "in"], {"in": text(20_000)}, "in.lz", tmp)
        second = tool(["lzip", "-k", "in"], {"in": text(10_000) + EICAR + text(10_000)}, "in.lz", tmp)
        put("two_members.lz", first + second)
        put("clean.lz", tool(["lzip", "-k", "in"], {"in": text(20_000)}, "in.lz", tmp))

        for name, body in [("eicar", lines(60) + EICAR + lines(60)), ("clean", lines(120))]:
            d = tempfile.mkdtemp(dir=tmp)
            os.mkdir(os.path.join(d, "src"))
            with open(os.path.join(d, "src", f"{name}.txt"), "wb") as f:
                f.write(body)
            run("wimcapture", "src", "out.wim", "--compress=LZX", cwd=d)
            with open(os.path.join(d, "out.wim"), "rb") as f:
                put(f"{name}.wim", f.read())
            put(f"{name}.arc", tool(["arc", "a", "out.arc", f"{name}.txt"],
                                    {f"{name}.txt": body}, "out.arc", tmp))
    finally:
        shutil.rmtree(tmp)


main()
