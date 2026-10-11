#!/usr/bin/env python3
"""A DWG of a release before R13, which exav does not read: the scanner and
the viewer must say so rather than call it clean or not a drawing.

    ODAFC=/path/to/odafc.sh python3 make.py

ezdxf writes an R12 DXF of a LINE, a CIRCLE and a TEXT; the ODA File
Converter (a black box) saves it as an R12 DWG (version ID AC1009),
committed gzipped as `R12.dwg.gz`. The converter's ACAD9 and ACAD10 outputs
never finish, so older releases are tested from hand-built headers.

Needs ezdxf (tested with 1.4.1).
"""

import gzip
import os
import subprocess
import sys
import tempfile

import ezdxf

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    odafc = os.environ.get("ODAFC")
    if not odafc:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    ezdxf.options.write_fixed_meta_data_for_testing = True
    doc = ezdxf.new("R12")
    msp = doc.modelspace()
    msp.add_line((0, 0), (10, 5))
    msp.add_circle((3, 3), 2)
    msp.add_text("PRE R13", dxfattribs={"height": 1}).set_placement((1, 8))
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
        doc.saveas(os.path.join(src, "r12.dxf"))
        subprocess.run([odafc, src, out, "ACAD12", "DWG", "r12.dxf"], check=True)
        with open(os.path.join(out, "r12.dwg"), "rb") as f:
            data = f.read()
    if not data.startswith(b"AC1009"):
        sys.exit("the converter did not write an AC1009 file")
    with open(os.path.join(HERE, "R12.dwg.gz"), "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as g:
            g.write(data)


if __name__ == "__main__":
    main()
