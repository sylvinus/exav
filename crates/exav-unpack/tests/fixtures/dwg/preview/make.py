#!/usr/bin/env python3
"""DWG drawings whose preview is a bitmap this script wrote, for the
scanner's `thumbnail.bmp` member.

    ODAFC=/path/to/odafc.sh python3 make.py [--only=ACAD2007,...]

ezdxf writes an R2018 DXF of one LINE; this script adds a THUMBNAILIMAGE
section holding a 4x2 24-bit device-independent bitmap (DIB.hex beside it
is that bitmap). The ODA File Converter (a black box) writes the drawing as
DWG of R13, R14, 2000, 2004, 2007, 2010, 2013 and 2018 (--only: those
versions), the bitmap as the DWG's preview image. Each is committed
gzipped, as `<VERSION>.dwg.gz`.

Needs ezdxf (tested with 1.4.1).
"""

import gzip
import io
import os
import struct
import subprocess
import sys
import tempfile

import ezdxf

HERE = os.path.dirname(os.path.abspath(__file__))
VERSIONS = [
    "ACAD13", "ACAD14", "ACAD2000", "ACAD2004", "ACAD2007", "ACAD2010", "ACAD2013", "ACAD2018",
]
ONLY = [a[len("--only="):].split(",") for a in sys.argv if a.startswith("--only=")]
if ONLY:
    VERSIONS = [v for v in VERSIONS if v in ONLY[0]]


def dib():
    """BITMAPINFOHEADER (40 bytes: 4x2, one plane, 24 bits, no compression),
    then two rows of four pixels (12 bytes each, a multiple of 4)."""
    w, h = 4, 2
    out = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, 0, 0, 0, 0, 0)
    for y in range(h):
        for x in range(w):
            out += bytes([0x10 * x, 0x40 * y, 0xE0])
    return out


def main():
    odafc = os.environ.get("ODAFC")
    if not odafc:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    ezdxf.options.write_fixed_meta_data_for_testing = True
    doc = ezdxf.new("R2018")
    doc.modelspace().add_line((0, 0), (10, 10))
    text = io.StringIO()
    doc.write(text)
    text = text.getvalue()
    bitmap = dib()
    hexed = bitmap.hex().upper()
    # DXF reference, THUMBNAILIMAGE section: 90 the byte count, 310 the
    # bytes in hexadecimal; the section comes last.
    section = "  0\nSECTION\n  2\nTHUMBNAILIMAGE\n 90\n%d\n" % len(bitmap)
    for i in range(0, len(hexed), 254):
        section += "310\n%s\n" % hexed[i:i + 254]
    section += "  0\nENDSEC\n"
    end = "  0\nEOF\n"
    if not text.endswith(end):
        sys.exit("ezdxf's DXF does not end with EOF")
    text = text[: -len(end)] + section + end
    with open(os.path.join(HERE, "DIB.hex"), "w") as f:
        f.write(hexed + "\n")
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
        with open(os.path.join(src, "preview.dxf"), "w") as f:
            f.write(text)
        for version in VERSIONS:
            subprocess.run([odafc, src, out, version, "DWG", "preview.dxf"], check=True)
            with open(os.path.join(out, "preview.dwg"), "rb") as f:
                data = f.read()
            name = version.replace("ACAD", "R") + ".dwg.gz"
            with open(os.path.join(HERE, name), "wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as g:
                    g.write(data)


if __name__ == "__main__":
    main()
