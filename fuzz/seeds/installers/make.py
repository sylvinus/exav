#!/usr/bin/env python3
"""Write the seeds of the `installers` fuzz target into this directory.

    python3 -I make.py

Each seed is the byte that picks the format (the index in FORMATS of
fuzz_targets/installers.rs) and a small file written here: AppleSingle and
AppleDouble files, InstallShield cabinets holding their header in the
layouts of versions 5, 6 and 20 (names in UTF-16), each with a stored file, a
deflated one and an obfuscated deflated one, and an Inno Setup 6.4 installer
with LZMA2 chunks and a stored one. They are laid out as the tests of
crates/exav-unpack/src/formats/ishield_cab.rs and inno.rs build them.
"""
import lzma
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
APPLESINGLE, ISHIELDCAB, INNO = range(3)


def applefile(double, entries):
    out = struct.pack(">I", 0x00051607 if double else 0x00051600)
    out += struct.pack(">I", 0x00020000) + bytes(16) + struct.pack(">H", len(entries))
    at = 26 + 12 * len(entries)
    for eid, data in entries:
        out += struct.pack(">III", eid, at, len(data))
        at += len(data)
    for _, data in entries:
        out += data
    return out


def deflate_chunks(data, size=600):
    out = b""
    for i in range(0, len(data), size):
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        z = c.compress(data[i : i + size]) + c.flush()
        out += struct.pack("<H", len(z)) + z
    return out


def obfuscate(data):
    out = bytearray()
    for i, b in enumerate(data):
        b = (b + i % 0x47) & 0xFF
        b = ((b << 2) | (b >> 6)) & 0xFF
        out.append(b ^ 0xD5)
    return bytes(out)


def cabinet(major, files):
    """`files`: (directory, name, data, compressed, obfuscated)."""
    if major == 5:
        version = 0x01005000
    elif major < 16:
        version = 0x01000000 | (major << 12)
    else:
        version = 0x04000000 | (major * 100)
    d, t = 0x200, 0x400
    dirs = []
    for f in files:
        if f[0] not in dirs:
            dirs.append(f[0])
    n = len(files)
    hdr = bytearray(t + 4 * (len(dirs) + (n if major <= 5 else 0)))

    def string(s):
        off = len(hdr) - t
        hdr.extend(s.encode("utf-16-le") + b"\0\0" if major >= 17 else s.encode() + b"\0")
        return off

    for i, name in enumerate(dirs):
        struct.pack_into("<I", hdr, t + 4 * i, string(name))
    names = [string(f[1]) for f in files]
    records = len(hdr) - t
    rec_len = 0x3A if major <= 5 else 0x57
    rec_start = len(hdr)
    hdr.extend(bytes(n * rec_len))
    header_end = len(hdr)
    data, placed = b"", []
    for _, _, content, compressed, obfuscated in files:
        stored = deflate_chunks(content) if compressed else content
        if obfuscated:
            stored = obfuscate(stored)
        placed.append((header_end + len(data), len(stored)))
        data += stored
    for i, (dname, _, content, compressed, obfuscated) in enumerate(files):
        at = rec_start + i * rec_len
        flags = (4 if compressed else 0) | (2 if obfuscated else 0)
        off, stored = placed[i]
        di = dirs.index(dname)
        if major <= 5:
            struct.pack_into("<IHxxHII", hdr, at, names[i], di, flags, len(content), stored)
            struct.pack_into("<I", hdr, at + 38, off)
            struct.pack_into("<I", hdr, t + 4 * (len(dirs) + i), at - t)
        else:
            struct.pack_into("<HQQQ", hdr, at, flags, len(content), stored, off)
            struct.pack_into("<IH", hdr, at + 58, names[i], di)
            struct.pack_into("<H", hdr, at + 85, 1)
    struct.pack_into("<4sIIII", hdr, 0, b"ISc(", version, 0, d, header_end - d)
    struct.pack_into("<IIII", hdr, 20, header_end, 0, 0, n - 1)
    struct.pack_into("<I", hdr, d + 0x0C, t - d)
    struct.pack_into("<I", hdr, d + 0x1C, len(dirs))
    struct.pack_into("<I", hdr, d + 0x28, n)
    struct.pack_into("<I", hdr, d + 0x2C, records)
    return bytes(hdr) + data


def lzma1(data):
    raw = lzma.compress(
        data,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}],
    )
    return bytes([(2 * 5 + 0) * 9 + 3]) + struct.pack("<I", 1 << 16) + raw


def lzma2(data):
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
    # Dictionary property 16: 2 << 19 bytes.
    return bytes([16]) + raw


def inno_block(data, compressed):
    raw = b"".join(bytes(4) + data[i : i + 4096] for i in range(0, len(data), 4096))
    return bytes(4) + struct.pack("<IB", len(raw), 1 if compressed else 0) + raw


LOADER_AT = 0x270


def pe_stub():
    """The setup stub: a PE file of one section, `.rsrc`, whose resource
    RCDATA 11111 is the loader table (44 bytes at LOADER_AT, to fill)."""
    s = bytearray(0x400)

    def put(at, fmt, *v):
        struct.pack_into(fmt, s, at, *v)

    s[0:2] = b"MZ"
    put(0x3C, "<I", 0x40)
    s[0x40:0x44] = b"PE\0\0"
    put(0x46, "<H", 1)  # one section
    put(0x54, "<H", 0xE0)  # optional header size
    put(0x58, "<H", 0x10B)  # PE32
    put(0x58 + 92, "<I", 16)  # data directories
    put(0xB8 + 16, "<II", 0x1000, 0x200)  # the third: resources
    s[0x138:0x140] = b".rsrc\0\0\0"
    put(0x138 + 8, "<IIII", 0x200, 0x1000, 0x200, 0x200)
    sub = 0x80000000
    # Type, name and language directories of one entry each, then the data.
    for at, ident, target in ((0x200, 10, sub | 0x18), (0x218, 11111, sub | 0x30), (0x230, 0x409, 0x50)):
        put(at + 14, "<H", 1)
        put(at + 16, "<II", ident, target)
    put(0x250, "<II", 0x1000 + LOADER_AT - 0x200, 44)
    return s


def inno_header(entries, method):
    """The start of the setup header of a 6.4.0 installer (data version
    6.4.0.1) up to its compression method byte, and a tail of the rest."""
    h = bytearray()
    # Strings: names, addresses and the like, and the texts of the wizard.
    for n in [5, 0, 3, 7, 9, 2, 4, 1, 8, 0, 6, 0, 12, 3, 4, 5, 0, 0, 0, 0, 2, 0, 1, 3, 6, 2, 7, 3, 0, 2, 4, 5, 5000, 1, 0, 60]:
        h += struct.pack("<I", n) + b"x" * n
    # Languages, messages, permissions, types, components, tasks,
    # directories, files, data entries, and seven more kinds.
    h += struct.pack("<16I", 1, 2, 3, 4, 5, 6, 7, 8, entries, 9, 10, 11, 12, 13, 14, 15)
    h += bytes(20)  # the Windows versions
    h += bytes(9 + 1)  # the wizard's style, size and alpha format
    h += bytes(4 + 44)  # password hash and salt
    h += bytes(12 + 3 + 1 + 2)  # disk space, slices, modes, privileges, language
    return bytes(h) + bytes([method]) + bytes(5000)


def inno(files, method, comp):
    """An Inno Setup 6.4.0 installer (data version 6.4.0.1: SHA-256 checksums
    and a signing byte) with each file of `files` in a chunk of its own,
    compressed with `comp` (the function for the header's `method`: 1 zlib,
    3 LZMA1, 4 LZMA2) unless it is None, and stored."""
    entry_size = 36 + 32 + 16 + 2 + 1
    exe = pe_stub()
    setup1 = len(exe)
    table = b""
    for data, packed in files:
        z = comp(data) if packed else data
        off = len(exe) - setup1
        exe += b"zlb\x1a" + z
        e = bytearray(entry_size)
        struct.pack_into("<IIIQQQ", e, 0, 0, 0, off, 0, len(data), len(z))
        struct.pack_into("<H", e, 84, 0x80 if packed else 0)
        table += bytes(e)
    setup0 = len(exe)
    exe += b"Inno Setup Setup Data (6.4.0.1)".ljust(64, b"\0")
    exe += inno_block(lzma1(inno_header(len(files), method)), True)
    exe += inno_block(lzma1(table), True)
    exe[LOADER_AT : LOADER_AT + 44] = b"rDlPtS\xcd\xe6\xd7{\x0b*" + struct.pack("<8I", 1, 0, 0, 0, 0, setup0, setup1, 0)
    return bytes(exe)


def write(name, pick, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(bytes([pick]) + data)


def main():
    write(
        "applesingle.bin",
        APPLESINGLE,
        applefile(False, [(3, b"Read Me"), (9, bytes(32)), (1, b"data fork\n" * 4), (2, b"resource fork")]),
    )
    write("appledouble.bin", APPLESINGLE, applefile(True, [(9, bytes(32)), (2, b"resource fork")]))
    text = b"".join(b"line %d of a file in a cabinet\n" % i for i in range(80))
    files = [
        ("", "setup.ini", b"[Startup]\nAppName=Example\n", False, False),
        ("Program Files\\App", "readme.txt", text, True, False),
        ("Program Files\\App", "data.bin", text[:1500], True, True),
    ]
    for major in (5, 6, 20):
        write("ishield_v%d.bin" % major, ISHIELDCAB, cabinet(major, files))
    write(
        "inno_6.4.0.bin",
        INNO,
        inno([(text, True), (text[:900], True), (b"stored file", False), (text, True)], 4, lzma2),
    )


if __name__ == "__main__":
    main()
