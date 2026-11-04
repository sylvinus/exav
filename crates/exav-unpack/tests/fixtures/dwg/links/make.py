#!/usr/bin/env python3
"""DWG drawings with hyperlinks, for the tests of `Dwg::hyperlinks` and of
the text a drawing gives a scanner.

    ODAFC=/path/to/odafc.sh python3 make.py [--only=ACAD2007,...]

ezdxf writes an R2018 DXF whose entities carry the extended data AutoCAD's
HYPERLINK command stores under the application `PE_URL`; the ODA File
Converter (a black box) writes it as DWG of R13, R14, 2000, 2004, 2007, 2010,
2013 and 2018 (--only: those versions). Each is committed gzipped, then XORed
with 0x5A, as `<VERSION>.dwg.gz.xor` (../../README.md).

The links, as AutoCAD lists them (a target, braces holding the description
and for a view its name, braces holding a flag):

  LINE    https://evil.example/steal, described as https://www.paypal.com/login
  POINT   the same link again
  TEXT    a link to the view "Detail 1": no target, described "Detail text display"
  CIRCLE  https://example.org/docs/a%20b, described "Docs"
  ARC     https://example.org/café, described "Café" (outside ASCII)
  POINT   https://example.org/same, described by itself
  POINT   extended data of another application (OTHER_APP) holding a
          string that looks like a link: not a hyperlink

Needs ezdxf (tested with 1.4.1).
"""

import gzip
import io
import os
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


def link(target, description, location=None):
    tags = [(1000, target), (1002, "{"), (1000, description)]
    if location is not None:
        tags.append((1000, location))
    tags += [(1002, "{"), (1071, 0 if location is None else 1), (1002, "}"), (1002, "}")]
    return tags


def main():
    odafc = os.environ.get("ODAFC")
    if not odafc:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    ezdxf.options.write_fixed_meta_data_for_testing = True
    doc = ezdxf.new("R2018")
    doc.appids.add("PE_URL")
    doc.appids.add("OTHER_APP")
    msp = doc.modelspace()
    spoof = link("https://evil.example/steal", "https://www.paypal.com/login")
    msp.add_line((0, 0), (10, 10)).set_xdata("PE_URL", spoof)
    msp.add_point((1, 1)).set_xdata("PE_URL", spoof)
    msp.add_text("hello").set_xdata("PE_URL", link("", "Detail text display", "Detail 1"))
    msp.add_circle((5, 5), 2).set_xdata("PE_URL", link("https://example.org/docs/a%20b", "Docs"))
    msp.add_arc((5, 5), 3, 0, 90).set_xdata("PE_URL", link("https://example.org/café", "Café"))
    msp.add_point((3, 3)).set_xdata(
        "PE_URL", link("https://example.org/same", "https://example.org/same")
    )
    msp.add_point((2, 2)).set_xdata("OTHER_APP", [(1000, "https://other.example/not-a-link")])
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
        doc.saveas(os.path.join(src, "links.dxf"))
        for version in VERSIONS:
            subprocess.run([odafc, src, out, version, "DWG", "links.dxf"], check=True)
            with open(os.path.join(out, "links.dwg"), "rb") as f:
                data = f.read()
            packed = io.BytesIO()
            with gzip.GzipFile(filename="", mode="wb", fileobj=packed, mtime=0) as g:
                g.write(data)
            name = version.replace("ACAD", "R") + ".dwg.gz.xor"
            with open(os.path.join(HERE, name), "wb") as f:
                f.write(bytes(b ^ 0x5A for b in packed.getvalue()))


if __name__ == "__main__":
    main()
