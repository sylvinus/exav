"""python3 -I run_poppler.py CORPUS OUT MAXPAGES: pdftoppm (poppler) on every PDF, 72 dpi, white page.

Writes OUT/poppler.jsonl and OUT/png-poppler/<stem>-<page>.png; one line per page, and per PDF a line with
the wall time of the process (page -1).
"""
import glob, json, os, subprocess, sys, time
from PIL import Image

Image.MAX_IMAGE_PIXELS = None
corpus, out, maxpages = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out + "/png-poppler", exist_ok=True)
lines = []
files = sorted(f for f in os.listdir(corpus) if f.endswith(".pdf"))
for n, name in enumerate(files):
    stem = os.path.splitext(name)[0]
    prefix = f"{out}/png-poppler/{stem}"
    t = time.time()
    try:
        p = subprocess.run(["pdftoppm", "-r", "72", "-f", "1", "-l", maxpages, "-png", f"{corpus}/{name}", prefix],
                           capture_output=True, text=True, timeout=60)
        wall = time.time() - t
        pngs = sorted(glob.glob(prefix + "-*.png"))
        for f in pngs:
            page = int(f.rsplit("-", 1)[1].split(".")[0])
            # pdftoppm pads the page number to the width of the page count.
            os.replace(f, f"{prefix}-{page}.png") if f != f"{prefix}-{page}.png" else None
            with Image.open(f"{prefix}-{page}.png") as im:
                w, h = im.size
            lines.append({"pdf": stem, "page": page, "w": w, "h": h, "ms": round(1000 * wall / max(1, len(pngs)), 1), "status": "ok"})
        if not pngs:
            lines.append({"pdf": stem, "page": 0, "status": f"fail({p.returncode}): " + (p.stderr.strip().splitlines() or [""])[0][:120]})
        lines.append({"pdf": stem, "page": -1, "status": "proc", "wall_s": round(wall, 2)})
    except subprocess.TimeoutExpired:
        lines.append({"pdf": stem, "page": 0, "status": "timeout"})
    if n % 50 == 49:
        open(out + "/poppler.jsonl", "w").write("\n".join(json.dumps(l) for l in lines) + "\n")
open(out + "/poppler.jsonl", "w").write("\n".join(json.dumps(l) for l in lines) + "\n")
print("done", len(files))
