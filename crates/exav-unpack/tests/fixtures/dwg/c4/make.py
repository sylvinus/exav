#!/usr/bin/env python3
"""DWG drawings for the C4 scanner-member tests: an OLE2FRAME holding an
Office document with a macro (a compound file with a `Macros/VBA` storage
whose module stream carries EICAR, compressed in an MS-OVBA container so no
version shows it in the clear), and an OLE2FRAME Packager wrapping a file
that is EICAR (an `\\x01Ole10Native` stream). Each drawing also has an xref
block, for the `dwg-metadata` member.

    ODAFC=/path/to/odafc.sh python3 make.py [--only=ACAD2007,...]

ezdxf writes an R2018 DXF with the OLE2FRAME and the xref (using
exav-render's tests/fixtures/cad/make.py helpers); the ODA File Converter
writes it as DWG of R13, R14, 2000, 2004, 2007, 2010, 2013 and 2018
(--only: those versions). Each DWG is
committed gzipped then XORed with 0x5A, as `<CASE>/<VERSION>.dwg.gz.xor`
(../../README.md). The OLE2FRAME's handle is printed.

Needs ezdxf (tested with 1.4.1).
"""

import base64
import gzip
import io
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../../../../../exav-render/tests/fixtures/cad"))

import ezdxf  # noqa: E402
from make import ole2frame  # noqa: E402

VERSIONS = [
    "ACAD13", "ACAD14", "ACAD2000", "ACAD2004", "ACAD2007", "ACAD2010", "ACAD2013", "ACAD2018",
]
ONLY = [a[len("--only="):].split(",") for a in sys.argv if a.startswith("--only=")]
if ONLY:
    VERSIONS = [v for v in VERSIONS if v in ONLY[0]]
# The EICAR test string, base64 so this script is not itself a sample.
EICAR = base64.b64decode(
    "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
)

END, FREE, FATSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD


def _copy_token_bits(diff):
    """[MS-OVBA] 2.4.1.3.19.1: the offset's bit width for a copy token at
    `diff` bytes into the chunk."""
    bits = 4
    while (1 << bits) < diff:
        bits += 1
    return max(4, min(12, bits))


def compress_chunk(data):
    """Compress one chunk (up to 4096 bytes) with [MS-OVBA] 2.4.1.3.7's
    LZ scheme, greedily, so the bytes are not literal in the file. Returns
    the token stream (without the chunk header)."""
    out = bytearray()
    i = 0
    while i < len(data):
        flags_at = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if i >= len(data):
                break
            bits = _copy_token_bits(i)
            max_len = (0xFFFF >> bits) + 3
            max_off = (0xFFFF >> (16 - bits)) + 1 if False else (1 << bits)
            best_len, best_off = 0, 0
            start = max(0, i - max_off)
            for j in range(start, i):
                length = 0
                while length < max_len and i + length < len(data) and data[j + length] == data[i + length]:
                    length += 1
                if length >= 3 and length > best_len:
                    best_len, best_off = length, i - j
            if best_len >= 3:
                token = ((best_off - 1) << (16 - bits)) | (best_len - 3)
                out += struct.pack("<H", token)
                flags |= 1 << bit
                i += best_len
            else:
                out.append(data[i])
                i += 1
        out[flags_at] = flags
    return bytes(out)


def ovba_container(payload):
    """An MS-OVBA CompressedContainer ([MS-OVBA] 2.4.1): 0x01, then one
    compressed chunk (header bit 15 set, the 0b011 signature, the
    compressed size - 1), then the tokens. Compressed so the payload is
    never literal in the drawing's bytes."""
    assert 1 <= len(payload) <= 4096
    body = compress_chunk(payload)
    header = 0x8000 | (0b011 << 12) | (len(body) - 1)
    return b"\x01" + struct.pack("<H", header) + body


def ole10native(payload):
    """The payload of an `\\x01Ole10Native` stream (how a Packager object
    stores an embedded file): a u32 total size, flags 0x0002, the label,
    the source path and a temp path (NUL-terminated), a u32 data size, then
    the data."""
    label = b"eicar.zip\0"
    path = b"C:\\eicar.zip\0"
    body = struct.pack("<H", 2) + label + path + struct.pack("<II", 0, 0)
    body += struct.pack("<I", len(path)) + path + struct.pack("<I", len(payload)) + payload
    return struct.pack("<I", len(body) + 4) + body


def cfb(entries):
    """A compound file (MS-CFB v3) from a list of entries describing a
    storage tree. Each entry is (name, kind, child, left, right, data):
    kind 5 root, 1 storage, 2 stream; child/left/right are entry indices or
    -1. Every stream is small and lives in the mini stream. The directory
    tree need not be a valid red-black tree: exav reads it leniently. One
    FAT sector (128 sectors) is enough for these fixtures."""
    # Pack every stream into the mini stream, 64-byte mini sectors.
    minis = []  # (first mini sector, size) per entry
    mini_stream = bytearray()
    for _, kind, _, _, _, data in entries:
        if kind == 2 and data:
            minis.append((len(mini_stream) // 64, len(data)))
            mini_stream += data
            if len(mini_stream) % 64:
                mini_stream += b"\0" * (64 - len(mini_stream) % 64)
        else:
            minis.append((END, 0))
    mini_sectors = len(mini_stream) // 64

    # The directory: 128 bytes an entry, padded to whole sectors.
    dir_bytes = bytearray()
    for i, (name, kind, child, left, right, _) in enumerate(entries):
        e = bytearray(128)
        n = (name + "\0").encode("utf-16-le")
        e[0 : len(n)] = n
        struct.pack_into("<HBB", e, 64, len(n), kind, 1)
        struct.pack_into("<III", e, 68, left & 0xFFFFFFFF, right & 0xFFFFFFFF, child & 0xFFFFFFFF)
        if kind == 2:
            start, size = minis[i]
            struct.pack_into("<IQ", e, 116, start if size else END, size)
        dir_bytes += e
    while len(dir_bytes) % 512:
        dir_bytes += bytes(128)
    dir_sectors = len(dir_bytes) // 512

    # The mini FAT: a chain per stream.
    minifat = [FREE] * max(mini_sectors, 1)
    for i, (_, kind, _, _, _, data) in enumerate(entries):
        if kind == 2 and data:
            start, _ = minis[i]
            count = (len(data) + 63) // 64
            for k in range(count):
                minifat[start + k] = (start + k + 1) if k + 1 < count else END
    minifat += [FREE] * ((128 - len(minifat) % 128) % 128)
    minifat_sectors = len(minifat) // 128

    # The root entry carries the mini stream, in the sectors after the mini FAT.
    root_start = 1 + dir_sectors + minifat_sectors
    mini_stream_sectors = (len(mini_stream) + 511) // 512
    struct.pack_into("<IQ", dir_bytes, 116, root_start if mini_stream else END, len(mini_stream))

    # The FAT: sector 0 the FAT itself, then the directory, mini FAT, mini stream.
    fat = [FREE] * 128
    fat[0] = FATSECT

    def chain(first, count):
        for k in range(count):
            fat[first + k] = (first + k + 1) if k + 1 < count else END

    chain(1, dir_sectors)
    chain(1 + dir_sectors, minifat_sectors)
    chain(root_start, mini_stream_sectors)

    header = bytearray(512)
    header[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    # First directory sector, mini cutoff, first mini FAT sector and count,
    # no DIFAT sectors, one FAT sector.
    struct.pack_into("<IIIIIIII", header, 44, 1, 1, 0, 4096, 1 + dir_sectors, minifat_sectors, END, 0)
    struct.pack_into("<I", header, 76, 0)  # DIFAT[0] = FAT sector 0
    for i in range(1, 109):
        struct.pack_into("<I", header, 76 + 4 * i, FREE)

    out = bytearray(header)
    out += struct.pack("<128I", *fat)
    out += dir_bytes
    out += struct.pack("<%dI" % len(minifat), *minifat)
    out += mini_stream + b"\0" * (mini_stream_sectors * 512 - len(mini_stream))
    return bytes(out)


def macros_cfb():
    """A compound file with Root -> Macros -> VBA -> {dir, Module1}, the
    module stream an OVBA container of EICAR as its source."""
    # No performance cache: the module source (an OVBA container) is at
    # offset 0. A fragment of EICAR appears earlier so the OVBA compressor
    # emits a copy token inside the real EICAR string, breaking its literal
    # run: the full 68-byte signature is never contiguous in the drawing's
    # bytes (OVBA keeps literals raw, so a lone copy would not hide it), yet
    # the module decompresses to the whole string.
    source = b"Attribute VB_Name=\"Module1\"\r\n' " + EICAR[5:40] + b"\r\n' " + EICAR + b"\r\n"
    module = ovba_container(source)

    # dir stream: records PROJECTNAME, MODULENAME, MODULESTREAMNAME,
    # MODULEOFFSET 0, terminator; compressed as one OVBA container.
    def record(rid, body):
        return struct.pack("<H", rid) + struct.pack("<I", len(body)) + body

    dir_plain = record(0x0004, b"VBAProject")
    dir_plain += record(0x0019, b"Module1")
    # MODULESTREAMNAME (0x001A): MBCS name, reserved u16, UTF-16 copy.
    name = b"Module1"
    dir_plain += struct.pack("<H", 0x001A) + struct.pack("<I", len(name)) + name
    utf16 = "Module1".encode("utf-16-le")
    dir_plain += struct.pack("<H", 0x0032) + struct.pack("<I", len(utf16)) + utf16
    dir_plain += record(0x0031, struct.pack("<I", 0))  # MODULEOFFSET 0
    dir_plain += record(0x002B, b"")  # terminator
    dir_stream = ovba_container(dir_plain)
    # Root(0) child Macros(1); Macros child VBA(2); VBA child dir(3), sibling Module1(4).
    entries = [
        ("Root Entry", 5, 1, -1, -1, b""),
        ("Macros", 1, 2, -1, -1, b""),
        ("VBA", 1, 3, -1, -1, b""),
        ("dir", 2, -1, -1, 4, dir_stream),
        ("Module1", 2, -1, -1, -1, module),
    ]
    return cfb(entries)


def packager_cfb():
    """A compound file whose one stream is `\\x01Ole10Native` wrapping a
    file: an OLE Package object. The wrapped file is a ZIP of eicar.com
    (deflated), so the signature is not literal in the drawing's bytes (a
    Packager stores its file uncompressed), yet exav carves the Ole10Native
    payload and recurses into the ZIP to it."""
    import zipfile

    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            zipfile.ZipInfo("eicar.com", date_time=(2020, 1, 1, 0, 0, 0)),
            EICAR,
            compress_type=zipfile.ZIP_DEFLATED,
        )
    entries = [
        ("Root Entry", 5, 1, -1, -1, b""),
        ("\x01Ole10Native", 2, -1, -1, -1, ole10native(zipped.getvalue())),
    ]
    return cfb(entries)


def build(case, payload):
    ezdxf.options.write_fixed_meta_data_for_testing = True
    doc = ezdxf.new("R2018")
    doc.add_xref_def("secret-site.dwg", "XREF_C4")
    doc.modelspace().add_blockref("XREF_C4", (0, 0))
    frame = ole2frame(doc.modelspace(), (0, 10), (10, 0), payload)
    out_dir = os.path.join(HERE, case)
    os.makedirs(out_dir, exist_ok=True)
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
        doc.saveas(os.path.join(src, "c4.dxf"))
        for version in VERSIONS:
            subprocess.run([ODAFC, src, out, version, "DWG", "c4.dxf"], check=True)
            with open(os.path.join(out, "c4.dwg"), "rb") as f:
                data = f.read()
            if EICAR in data:
                sys.exit(f"{case} {version}: the string is in the DWG's own bytes")
            packed = io.BytesIO()
            with gzip.GzipFile(filename="", mode="wb", fileobj=packed, mtime=0) as g:
                g.write(data)
            name = version.replace("ACAD", "R") + ".dwg.gz.xor"
            with open(os.path.join(out_dir, name), "wb") as f:
                f.write(bytes(b ^ 0x5A for b in packed.getvalue()))
    print(case, "OLE2FRAME", frame.dxf.handle)


if __name__ == "__main__":
    ODAFC = os.environ.get("ODAFC")
    if not ODAFC:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    build("macros", macros_cfb())
    build("packager", packager_cfb())
