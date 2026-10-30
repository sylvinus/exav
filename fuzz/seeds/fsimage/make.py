#!/usr/bin/env python3
"""Write the seeds of the `fsimage` fuzz target into this directory.

    python3 make.py

Each seed is the byte that picks the format (the index in FORMATS of
fuzz_targets/fsimage.rs) and a small image of a tree of three files and a
folder. The images are made by e2fsprogs, squashfs-tools, mkcramfs
(github.com/npitre/cramfs-tools), genromfs, erofs-utils and 7-Zip; the exFAT,
xar and WIM ones are written here (the exFAT tool makes it too big, and the WIM
has chunks stored as they are, so that it needs no codec). The last six are the same
volumes behind a partition table that says each is 128 KiB, over the target's
buffer limit, so that they are walked where they lie (and the images cut short
at their end, as a seed is).
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXT, EXFAT, SQUASHFS, CRAMFS, ROMFS, EROFS, PARTITION, SEVENZ, WIM, XAR = range(10)


def run(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def trimmed(path):
    d = open(path, "rb").read().rstrip(b"\0")
    return d + b"\0" * (-len(d) % 512)


def exfat():
    """A volume of 512-byte clusters: the root in cluster 2, `a.txt` in 3,
    `sub` in 4 holding `b.bin` in 5 to 10."""
    img = bytearray(8 * 512 + 100 * 512)
    img[0] = 0xEB
    img[3:11] = b"EXFAT   "
    struct.pack_into("<QIIIII", img, 72, 108, 1, 4, 8, 100, 2)
    struct.pack_into("<H", img, 104, 0x0100)
    img[108], img[109], img[110] = 9, 0, 1
    img[510:512] = b"\x55\xaa"

    def link(c, nxt):
        struct.pack_into("<I", img, 512 + c * 4, nxt)

    def entry_set(name, attr, first, size, in_a_row):
        units = name.encode("utf-16-le")
        names = [units[i : i + 30] for i in range(0, len(units), 30)]
        file = bytearray(32)
        file[0], file[1] = 0x85, 1 + len(names)
        struct.pack_into("<H", file, 4, attr)
        stream = bytearray(32)
        stream[0], stream[1], stream[3] = 0xC0, 1 | (2 if in_a_row else 0), len(units) // 2
        struct.pack_into("<Q", stream, 8, size)
        struct.pack_into("<I", stream, 20, first)
        struct.pack_into("<Q", stream, 24, size)
        out = [bytes(file), bytes(stream)]
        for n in names:
            out.append(bytes([0xC1, 0]) + n.ljust(30, b"\0"))
        return b"".join(out)

    def put(c, data):
        at = 8 * 512 + (c - 2) * 512
        img[at : at + len(data)] = data

    link(2, 0xFFFFFFFF)
    put(2, entry_set("a.txt", 0x20, 3, 6, True) + entry_set("sub", 0x10, 4, 512, True))
    put(3, b"hello\n")
    link(4, 0xFFFFFFFF)
    put(4, entry_set("b.bin", 0x20, 5, 3000, True))
    put(5, bytes((i * 7) % 251 for i in range(3000)))
    return bytes(img)


def xar():
    """An archive with one member stored zlib-compressed and one as it is."""
    import zlib

    big = bytes((i * 31) % 251 for i in range(3000))
    heap = b""
    files = ""
    for name, data, deflate in (("a.bin", big, True), ("b.txt", b"hello\n", False)):
        stored = zlib.compress(data) if deflate else data
        style = "application/x-gzip" if deflate else "application/octet-stream"
        files += (
            f"<file><name>{name}</name><data><offset>{len(heap)}</offset>"
            f"<length>{len(stored)}</length><size>{len(data)}</size>"
            f'<encoding style="{style}"/></data></file>'
        )
        heap += stored
    toc = f"<xar><toc>{files}</toc></xar>".encode()
    packed = zlib.compress(toc)
    head = b"xar!" + struct.pack(">HHQQI", 28, 1, len(packed), len(toc), 1)
    return head + packed + heap


def wim():
    """An image of one resource of three chunks, stored as they are (so that
    no codec is needed), and one that is not compressed."""
    chunk = 1024
    data = bytes((i * 13) % 241 for i in range(3000))
    table = struct.pack("<II", chunk, 2 * chunk)
    first = table + data
    second = bytes((i * 7) % 251 for i in range(100))

    def resource(size, flags, offset, original):
        return size.to_bytes(7, "little") + bytes([flags]) + struct.pack("<QQ", offset, original)

    at_first, at_second = 208, 208 + len(first)
    at_table = at_second + len(second)
    entries = b"".join(
        resource(*r) + struct.pack("<HI", 1, 1) + bytes(20)
        for r in (
            (len(first), 0x04, at_first, len(data)),
            (len(second), 0x00, at_second, len(second)),
        )
    )
    head = bytearray(208)
    head[0:8] = b"MSWIM\0\0\0"
    struct.pack_into("<III", head, 8, 208, 0x10D00, 0x2 | 0x20000)
    struct.pack_into("<I", head, 20, chunk)
    head[48:72] = resource(len(entries), 0x00, at_table, len(entries))
    return bytes(head) + first + second + entries


def mbr(volume):
    """A disk with an MBR listing one partition of 128 KiB at 4 KiB: not at 512
    bytes, where a cramfs with room for boot code has its superblock."""
    table = bytearray(4096)
    table[0x1BE + 4] = 0x83
    struct.pack_into("<II", table, 0x1BE + 8, 8, 256)
    table[510:512] = b"\x55\xaa"
    return bytes(table) + volume


def main():
    with tempfile.TemporaryDirectory() as w:
        tree = os.path.join(w, "tree")
        os.makedirs(os.path.join(tree, "sub"))
        open(os.path.join(tree, "a.txt"), "w").write("hello\n")
        open(os.path.join(tree, "empty"), "w").close()
        open(os.path.join(tree, "sub", "b.bin"), "wb").write(bytes((i * 7) % 251 for i in range(3000)))

        def path(n):
            return os.path.join(w, n)

        images = {}
        run("truncate", "-s", "128K", path("ext2"))
        run("mke2fs", "-q", "-F", "-t", "ext2", "-b", "1024", "-N", "16", "-O", "^resize_inode", "-d", tree, path("ext2"))
        images["ext2"] = (EXT, trimmed(path("ext2")))
        run("truncate", "-s", "256K", path("ext4"))
        run("mke2fs", "-q", "-F", "-t", "ext4", "-b", "1024", "-N", "16", "-O", "^has_journal,^resize_inode,inline_data", "-d", tree, path("ext4"))
        images["ext4_inline"] = (EXT, trimmed(path("ext4")))
        for c in ("gzip", "lzo", "xz", "zstd", "lz4", "lzma"):
            run("mksquashfs", tree, path(c), "-comp", c, "-noappend", "-quiet")
            images["squashfs_" + c] = (SQUASHFS, open(path(c), "rb").read())
        run(os.environ.get("MKCRAMFS", "mkcramfs"), tree, path("cram"))
        images["cramfs"] = (CRAMFS, open(path("cram"), "rb").read())
        run("genromfs", "-f", path("rom"), "-d", tree)
        images["romfs"] = (ROMFS, open(path("rom"), "rb").read())
        run("mkfs.erofs", path("ero"), tree)
        images["erofs"] = (EROFS, trimmed(path("ero")))
        images["exfat"] = (EXFAT, exfat())
        run("7z", "a", "-t7z", "-ms=on", "-mx=1", path("seven.7z"), tree + "/*")
        images["sevenz"] = (SEVENZ, open(path("seven.7z"), "rb").read())
        images["xar"] = (XAR, xar())
        images["wim"] = (WIM, wim())

    for name, (kind, image) in images.items():
        open(os.path.join(HERE, name + ".bin"), "wb").write(bytes([kind]) + image)
    # The same volumes behind a partition table.
    for name in ("ext2", "squashfs_xz", "cramfs", "romfs", "erofs", "exfat"):
        open(os.path.join(HERE, "partition_" + name + ".bin"), "wb").write(
            bytes([PARTITION]) + mbr(images[name][1])
        )


if __name__ == "__main__":
    sys.exit(main())
