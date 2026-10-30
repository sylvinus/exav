"""python3 -I run_hayro.py CORPUS OUT MAXPAGES: hayro-eval on every PDF of CORPUS, 60 s and one process each.

Writes OUT/hayro.jsonl (the file is rewritten whole every 25 PDFs): a line per page, and per PDF a line with
the peak RSS and the wall time of the process, or "timeout" / "crash".
"""
import json, os, subprocess, sys, time

corpus, out, maxpages = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out + "/png-hayro", exist_ok=True)
exe = os.environ.get("HAYRO_EVAL") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "hayro-eval/target/release/hayro-eval")
files = sorted(f for f in os.listdir(corpus) if f.endswith(".pdf"))
lines = []

def flush():
    tmp = out + "/hayro.jsonl.tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(json.dumps(l) for l in lines) + "\n")
    os.replace(tmp, out + "/hayro.jsonl")

for n, name in enumerate(files):
    stem = os.path.splitext(name)[0]
    t = time.time()
    try:
        p = subprocess.run(["/usr/bin/time", "-f", "RSS %M", exe, f"{corpus}/{name}", out + "/png-hayro", maxpages],
                           capture_output=True, text=True, timeout=60)
        wall = time.time() - t
        rss = 0
        for l in p.stderr.splitlines():
            if l.startswith("RSS "):
                rss = int(l.split()[1])
        got = 0
        for l in p.stdout.splitlines():
            if l.startswith("{"):
                try:
                    lines.append(json.loads(l)); got += 1
                except Exception:
                    pass
        if p.returncode != 0 or got == 0:
            tail = p.stderr.strip().splitlines()[-2:] if p.stderr else []
            lines.append({"pdf": stem, "page": 0, "status": f"crash({p.returncode}): " + " | ".join(tail)[:160]})
        lines.append({"pdf": stem, "page": -1, "status": "proc", "rss_kb": rss, "wall_s": round(wall, 2)})
    except subprocess.TimeoutExpired:
        lines.append({"pdf": stem, "page": 0, "status": "timeout"})
        lines.append({"pdf": stem, "page": -1, "status": "proc", "rss_kb": 0, "wall_s": 60})
    if n % 25 == 24:
        flush()
flush()
print("done", len(files))
