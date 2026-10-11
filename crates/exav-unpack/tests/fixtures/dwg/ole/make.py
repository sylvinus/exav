#!/usr/bin/env python3
"""DWG drawings whose OLE2FRAME embeds a compound file whose one stream is a
ZIP of the EICAR test file (deflated: an R13 to R2000 object is bit-packed
and an R2004 one's section LZ77-compressed, so a stored string could appear
in the file's own bytes, as it did in the 2013 file), for the scanner's
OLE2FRAME members.

    ODAFC=/path/to/odafc.sh python3 make.py [--only=ACAD2007,...]

ezdxf writes the drawing (an R2018 DXF with the OLE2FRAME, built by
exav-render's tests/fixtures/cad/make.py helpers); the ODA File Converter (a
black box) writes it as DWG of R13, R14, 2000, 2004, 2007, 2010, 2013 and
2018 (--only: those versions).
Each is committed gzipped, then XORed with 0x5A, as `<VERSION>.dwg.gz.xor`
(../../README.md). The OLE2FRAME's handle is 2F.

Needs ezdxf (tested with 1.4.1).
"""

import base64
import gzip
import io
import os
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../../../../../exav-render/tests/fixtures/cad"))

import ezdxf  # noqa: E402
from make import compound_file, ole2frame  # noqa: E402

VERSIONS = [
    "ACAD13", "ACAD14", "ACAD2000", "ACAD2004", "ACAD2007", "ACAD2010", "ACAD2013", "ACAD2018",
]
ONLY = [a[len("--only="):].split(",") for a in sys.argv if a.startswith("--only=")]
if ONLY:
    VERSIONS = [v for v in VERSIONS if v in ONLY[0]]
# The EICAR test string, base64 so that this script is not itself a sample.
EICAR = base64.b64decode(
    "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
)


def main():
    odafc = os.environ.get("ODAFC")
    if not odafc:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    ezdxf.options.write_fixed_meta_data_for_testing = True
    doc = ezdxf.new("R2018")
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("eicar.com", date_time=(2020, 1, 1, 0, 0, 0)), EICAR,
                   compress_type=zipfile.ZIP_DEFLATED)
    payload = compound_file("CONTENTS", zipped.getvalue())
    frame = ole2frame(doc.modelspace(), (0, 10), (10, 0), payload)
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
        doc.saveas(os.path.join(src, "ole.dxf"))
        for version in VERSIONS:
            subprocess.run([odafc, src, out, version, "DWG", "ole.dxf"], check=True)
            with open(os.path.join(out, "ole.dwg"), "rb") as f:
                data = f.read()
            if EICAR in data:
                sys.exit(f"{version}: the string is in the DWG's own bytes")
            # Gzipped (mtime 0, no name), then masked.
            packed = io.BytesIO()
            with gzip.GzipFile(filename="", mode="wb", fileobj=packed, mtime=0) as g:
                g.write(data)
            name = version.replace("ACAD", "R") + ".dwg.gz.xor"
            with open(os.path.join(HERE, name), "wb") as f:
                f.write(bytes(b ^ 0x5A for b in packed.getvalue()))
    print("OLE2FRAME", frame.dxf.handle)


if __name__ == "__main__":
    main()
