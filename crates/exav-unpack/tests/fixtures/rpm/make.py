#!/usr/bin/env python3
"""Builds the RPM fixtures (rpmbuild is not needed): python3 make.py

hello.rpm: a package with install scripts and a gzip cpio payload.
eicar.rpm: the EICAR test string in the payload, which the compression hides
(mask it with XOR 0x5A as the README of this directory's parent says, and
copy it to crates/exav-core/tests/fixtures/eicar.rpm.xor).
"""
import gzip
import struct
import sys

STRING, BIN, STRING_ARRAY = 6, 7, 8
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-" + b"STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"


def header(entries):
    """entries: (tag, type, count, bytes). The index and data of a header structure."""
    data = b""
    index = b""
    for tag, kind, count, blob in sorted(entries):
        index += struct.pack(">IIII", tag, kind, len(data), count)
        data += blob
    return b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", len(entries), len(data)) + index + data


def cpio(files):
    out = b""
    for ino, (name, content) in enumerate(files, 1):
        name = name.encode() + b"\0"
        out += b"070701" + b"".join(
            b"%08X" % v for v in (ino, 0o100644, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(name), 0)
        )
        out += name + bytes(-(110 + len(name)) % 4) + content + bytes(-len(content) % 4)
    trailer = b"TRAILER!!!\0"
    out += b"070701" + b"".join(b"%08X" % v for v in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer), 0))
    return out + trailer + bytes(-(110 + len(trailer)) % 4)


def rpm(files, scripts):
    payload = gzip.compress(cpio(files), mtime=0)
    main = [
        (1000, STRING, 1, b"hello\0"),
        (1124, STRING, 1, b"cpio\0"),
        (1125, STRING, 1, b"gzip\0"),
    ] + scripts
    sig = header([(1000, BIN, 4, bytes(4))])
    sig += bytes(-len(sig) % 8)
    lead = b"\xed\xab\xee\xdb" + bytes([3, 0]) + struct.pack(">HH", 0, 1) + b"hello".ljust(66, b"\0")
    lead += struct.pack(">HH", 1, 5) + bytes(16)
    assert len(lead) == 96
    return lead + sig + header(main) + payload


hello = rpm(
    [("./usr/share/hello/hello.txt", b"hello from an rpm\n")],
    [
        (1023, STRING, 1, b"echo prein\0"),
        (1024, STRING, 1, b"#!/bin/sh\necho postin\n\0"),
        (1065, STRING_ARRAY, 2, b"echo first trigger\0echo second trigger\0"),
    ],
)
open("hello.rpm", "wb").write(hello)
open("eicar.rpm", "wb").write(rpm([("./usr/share/hello/eicar.com", EICAR)], []))
print(len(hello), file=sys.stderr)
