"""python3 -I compare3.py OUT: hayro, pdf.js and poppler on the same pages (first three of each PDF, 72 dpi).

Poppler is the reference: a page's distance to it is the mean absolute luminance difference after a 3x3 box
blur (0 to 255) and the share of pixels differing by more than 64 ("bad"). Pages over 25 million pixels are
left out of the pixel comparison. Prints the figures the report quotes and writes OUT/compare3.json.
"""
import collections, json, os, re, sys
import numpy as np
from PIL import Image

Image.MAX_IMAGE_PIXELS = None
out = sys.argv[1]
names = ["hayro", "pdfjs", "poppler"]

def read(n):
    rows = {}
    for l in open(f"{out}/{n}.jsonl"):
        l = l.strip()
        if l.startswith("{"):
            try:
                r = json.loads(l)
            except Exception:
                continue
            rows.setdefault(r["pdf"], []).append(r)
    return rows

logs = {n: read(n) for n in names}
pdfs = sorted(set().union(*[set(v) for v in logs.values()]))

def doc_state(n, pdf):
    rs = logs[n].get(pdf, [])
    if any(r["page"] >= 1 and r["status"] == "ok" for r in rs):
        return "ok"
    for r in rs:
        if r["page"] == 0:
            return r["status"].split(":")[0].split("(")[0]
    return "none"

print(f"PDFs: {len(pdfs)}")
for n in names:
    c = collections.Counter(doc_state(n, p) for p in pdfs)
    print(f"  {n}: " + ", ".join(f"{k} {v}" for k, v in c.most_common()))
both_ok_ref = [p for p in pdfs if doc_state("poppler", p) == "ok"]
print(f"  where poppler renders ({len(both_ok_ref)}): hayro fails {sum(1 for p in both_ok_ref if doc_state('hayro', p) != 'ok')}, pdf.js fails {sum(1 for p in both_ok_ref if doc_state('pdfjs', p) != 'ok')}")
print(f"  where poppler fails ({len(pdfs) - len(both_ok_ref)}): hayro renders {sum(1 for p in pdfs if doc_state('poppler', p) != 'ok' and doc_state('hayro', p) == 'ok')}, pdf.js renders {sum(1 for p in pdfs if doc_state('poppler', p) != 'ok' and doc_state('pdfjs', p) == 'ok')}")

pages = collections.defaultdict(dict)
for n in names:
    for pdf, rs in logs[n].items():
        for r in rs:
            if r["page"] >= 1 and r["status"] == "ok":
                pages[(pdf, r["page"])][n] = r

def lum(n, pdf, page):
    return np.asarray(Image.open(f"{out}/png-{n}/{pdf}-{page}.png").convert("L"), dtype=np.float32)

def blur(x):
    p = np.pad(x, 1, mode="edge")
    return sum(p[i:i + x.shape[0], j:j + x.shape[1]] for i in range(3) for j in range(3)) / 9.0

res = {n: [] for n in ("hayro", "pdfjs")}
size = {n: collections.Counter() for n in ("hayro", "pdfjs")}
for key, r in sorted(pages.items()):
    if "poppler" not in r:
        continue
    pw, ph = r["poppler"]["w"], r["poppler"]["h"]
    for n in ("hayro", "pdfjs"):
        if n not in r:
            continue
        w, h = r[n]["w"], r[n]["h"]
        if (w, h) == (pw, ph):
            size[n]["same"] += 1
        elif (w, h) == (ph, pw):
            size[n]["rotated"] += 1
        elif abs(w - pw) <= 1 and abs(h - ph) <= 1:
            size[n]["off by one"] += 1
        else:
            size[n]["different"] += 1
for n in size:
    print(f"  page size vs poppler, {n}: " + ", ".join(f"{k} {v}" for k, v in size[n].items()))

per = {}
for key, r in sorted(pages.items()):
    if not all(n in r for n in names):
        continue
    sizes = {(r[n]["w"], r[n]["h"]) for n in names}
    if len(sizes) != 1:
        continue
    w, h = next(iter(sizes))
    if w * h > 25_000_000:
        continue
    ref = blur(lum("poppler", *key))
    for n in ("hayro", "pdfjs"):
        d = np.abs(blur(lum(n, *key)) - ref)
        res[n].append((key, float(d.mean()), float((d > 64).mean())))
    per[key] = {n: res[n][-1][1:] for n in res}

k = len(res["hayro"])
print(f"  pages with the same size in all three: {k}")
for n in res:
    mad = np.array([x[1] for x in res[n]]); bad = np.array([x[2] for x in res[n]])
    print(f"  {n} vs poppler: MAD median {np.median(mad):.2f}, p90 {np.percentile(mad, 90):.2f}; pages <0.5% pixels far {int((bad < .005).sum())} ({100 * (bad < .005).mean():.1f}%), 0.5-5% {int(((bad >= .005) & (bad < .05)).sum())}, over 5% {int((bad >= .05).sum())} ({100 * (bad >= .05).mean():.1f}%)")
hb = np.array([x[2] for x in res["hayro"]]); pb = np.array([x[2] for x in res["pdfjs"]])
print(f"  closer to poppler by 'bad' (more than 1 point apart): hayro {int((hb + .01 < pb).sum())}, pdf.js {int((pb + .01 < hb).sum())}, level {int((abs(hb - pb) <= .01).sum())}")

# By what the file name says it tests.
cats = {"shading": "shad", "tiling/pattern": "patt|tiling", "jpx": "jpx|jpeg2000|jp2", "jbig2": "jbig2", "ccitt": "ccitt|fax", "mask/blend/transparency": "mask|blend|transp|smask|alpha", "font": "font|glyph|type1|type3|cff|truetype|cid|cmap", "annotation/form": "annot|form|widget|acro"}
print("  by name (pages <0.5% far from poppler / pages):")
for c, rx in cats.items():
    sel = [i for i, x in enumerate(res["hayro"]) if re.search(rx, x[0][0].lower())]
    if sel:
        print(f"    {c}: hayro {sum(1 for i in sel if res['hayro'][i][2] < .005)}/{len(sel)}, pdf.js {sum(1 for i in sel if res['pdfjs'][i][2] < .005)}/{len(sel)}")

# Time.
for n in ("hayro", "pdfjs", "poppler"):
    ms = np.array([r[n]["ms"] for r in pages.values() if n in r])
    print(f"  render ms per page, {n}: median {np.median(ms):.0f}, p90 {np.percentile(ms, 90):.0f}, p99 {np.percentile(ms, 99):.0f}, max {ms.max():.0f}, total {ms.sum() / 1000:.0f} s over {len(ms)} pages")
rss = [r["rss_kb"] for rs in logs["hayro"].values() for r in rs if r["page"] == -1 and r.get("rss_kb")]
print(f"  hayro process peak RSS: median {np.median(rss) / 1024:.0f} MB, p99 {np.percentile(rss, 99) / 1024:.0f} MB, max {max(rss) / 1024:.0f} MB")
worst = sorted(per.items(), key=lambda kv: -kv[1]["hayro"][1])[:8]
print("  hayro's worst against poppler (hayro bad / pdf.js bad):")
for (pdf, page), v in worst:
    print(f"    {pdf} p{page}: {v['hayro'][1] * 100:.1f}% / {v['pdfjs'][1] * 100:.1f}%")
worst = sorted(per.items(), key=lambda kv: -kv[1]["pdfjs"][1])[:8]
print("  pdf.js's worst against poppler (pdf.js bad / hayro bad):")
for (pdf, page), v in worst:
    print(f"    {pdf} p{page}: {v['pdfjs'][1] * 100:.1f}% / {v['hayro'][1] * 100:.1f}%")
json.dump({f"{k[0]}:{k[1]}": v for k, v in per.items()}, open(f"{out}/compare3.json", "w"))
