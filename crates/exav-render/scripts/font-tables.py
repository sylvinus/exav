#!/usr/bin/env python3
"""Generate the advance-width tables the tessellator lays text out with.

The viewer ships its own faces, so their advances are fixed numbers rather than
something to measure on the machine that happens to be rendering. Baking them in
means MTEXT wraps at the same place everywhere, and that nothing has to cross
the worker boundary before the tessellator can start.

Reads the WOFF2 files in crates/exav-viewer/assets/fonts and writes
crates/exav-render/src/formats/dwg/metrics.rs.

    crates/exav-render/scripts/font-tables.py

Needs fonttools and brotli:

    python3 -m venv .venv && .venv/bin/pip install fonttools brotli
    .venv/bin/python scripts/font-tables.py
"""
import sys
from pathlib import Path

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent.parent.parent.parent
FONTS = ROOT / "crates" / "exav-viewer" / "assets" / "fonts"
OUT = ROOT / "crates" / "exav-render" / "src" / "formats" / "dwg" / "metrics.rs"

# Dense range: ASCII, Latin-1 Supplement and Latin Extended-A. That is every
# European language written in Latin script, which is what the dense table is
# for; anything rarer goes in the sparse tail.
FIRST, LAST = 0x20, 0x24F

# Characters past the dense range that technical drawings genuinely use. Kept
# sorted, because the lookup binary-searches it.
SPARSE = sorted(
    {
        0x2018, 0x2019, 0x201C, 0x201D,  # curly quotes
        0x2013, 0x2014,                  # en and em dash
        0x2026,                          # ellipsis
        0x20AC,                          # euro
        0x2190, 0x2191, 0x2192, 0x2193,  # arrows, used on north points
        0x2205,                          # empty set, a diameter stand-in
        0x2206, 0x2300,                  # increment, diameter
        0x2264, 0x2265, 0x2260,          # <=, >=, !=
        0x00B0, 0x00B1, 0x00B2, 0x00B3,  # already dense, listed to assert
        0x03A9, 0x03BC,                  # ohm, micro
    }
)

# Fixed-point divisor for a stored advance, in em units. An advance is under
# 2 em, so 1/4096 keeps it inside a u16 with three decimal digits to spare.
SCALE = 4096

# (rust name, file, weight for a variable font)
FACES = [
    ("SANS", "Arimo-wght.woff2", 400),
    ("SANS_BOLD", "Arimo-wght.woff2", 700),
    ("SANS_ITALIC", "Arimo-Italic-wght.woff2", 400),
    ("SANS_BOLD_ITALIC", "Arimo-Italic-wght.woff2", 700),
    ("SERIF", "Tinos-Regular.woff2", None),
    ("SERIF_BOLD", "Tinos-Bold.woff2", None),
    ("SERIF_ITALIC", "Tinos-Italic.woff2", None),
    ("SERIF_BOLD_ITALIC", "Tinos-BoldItalic.woff2", None),
    ("MONO", "Cousine-Regular.woff2", None),
    ("MONO_BOLD", "Cousine-Bold.woff2", None),
    ("MONO_ITALIC", "Cousine-Italic.woff2", None),
    ("MONO_BOLD_ITALIC", "Cousine-BoldItalic.woff2", None),
]


def load(path, weight):
    font = TTFont(path)
    if weight is not None and "fvar" in font:
        font = instantiateVariableFont(font, {"wght": weight}, inplace=False)
    return font


def measure(font):
    """Advance per codepoint in em units, plus the cap height as a fraction."""
    upem = font["head"].unitsPerEm
    cmap = font.getBestCmap()
    hmtx = font["hmtx"]
    order = font.getGlyphOrder()

    def advance(cp):
        name = cmap.get(cp)
        if name is None or name not in order:
            return None
        return hmtx[name][0] / upem

    # OS/2 version 2 and later carry a measured cap height; otherwise take the
    # top of "H", which is what cap height means.
    os2 = font["OS/2"]
    cap = getattr(os2, "sCapHeight", None)
    if not cap:
        glyf = font["glyf"]
        cap = glyf["H"].yMax
    return advance, cap / upem


def main():
    if not FONTS.is_dir():
        sys.exit(f"no {FONTS}")

    tables = {}
    caps = {}
    sparse = {}
    missing = []
    for name, filename, weight in FACES:
        path = FONTS / filename
        if not path.exists():
            sys.exit(f"missing {path}")
        advance, cap = measure(load(path, weight))
        caps[name] = cap

        # A face missing a character in the dense range stores zero, and the
        # reader falls back rather than laying out with a bogus width.
        row = []
        for cp in range(FIRST, LAST + 1):
            a = advance(cp)
            row.append(0 if a is None else min(round(a * SCALE), 0xFFFF))
        tables[name] = row

        tail = []
        for cp in SPARSE:
            a = advance(cp)
            if a is None:
                missing.append((name, cp))
                continue
            tail.append((cp, min(round(a * SCALE), 0xFFFF)))
        sparse[name] = tail

    # Faces whose rows are identical share one table, which is most of the
    # monospaced ones.
    canonical = {}
    alias = {}
    for name, _, _ in FACES:
        key = (tuple(tables[name]), tuple(sparse[name]))
        if key in canonical:
            alias[name] = canonical[key]
        else:
            canonical[key] = name

    lines = [
        "//! Advance widths of the bundled faces. Generated; do not edit.",
        "//!",
        "//! Written by `crates/exav-render/scripts/font-tables.py` from the WOFF2",
        "//! files in `crates/exav-viewer/assets/fonts`. The viewer ships those faces, so their advances are",
        "//! constants: baking them in makes MTEXT wrap identically on every",
        "//! machine, and means nothing has to reach the tessellator from the host",
        "//! before it can lay text out.",
        "",
        "/// First codepoint a dense table covers.",
        f"pub const FIRST: u32 = {FIRST:#06x};",
        "/// Last codepoint a dense table covers, inclusive.",
        f"pub const LAST: u32 = {LAST:#06x};",
        "/// Fixed-point divisor for a stored advance, in em units.",
        f"pub const SCALE: f32 = {SCALE}.0;",
        "",
    ]

    for name, _, _ in FACES:
        if name in alias:
            continue
        row = tables[name]
        lines.append(f"pub static {name}: [u16; {len(row)}] = [")
        for i in range(0, len(row), 16):
            lines.append("    " + " ".join(f"{v}," for v in row[i : i + 16]))
        lines.append("];")
        tail = sparse[name]
        lines.append(f"pub static {name}_SPARSE: [(u32, u16); {len(tail)}] = [")
        for cp, v in tail:
            lines.append(f"    ({cp:#06x}, {v}),")
        lines.append("];")
        lines.append("")

    for name, target in alias.items():
        lines.append(f"/// Identical to `{target}`.")
        lines.append(f"pub use self::{{{target} as {name}, {target}_SPARSE as {name}_SPARSE}};")
    if alias:
        lines.append("")

    lines.append("/// Cap height as a fraction of em, per face.")
    for name, _, _ in FACES:
        lines.append(f"pub const {name}_CAP: f32 = {caps[name]:.6};")
    lines.append("")

    OUT.write_text("\n".join(lines))

    shared = len(alias)
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"  {len(FACES)} faces, {len(FACES) - shared} distinct tables, {shared} shared")
    print(f"  dense {FIRST:#x}..{LAST:#x} ({LAST - FIRST + 1} entries), {len(SPARSE)} sparse")
    for name, cp in missing:
        print(f"  note: {name} has no U+{cp:04X}")


if __name__ == "__main__":
    main()
