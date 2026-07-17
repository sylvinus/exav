import os, io, sys, json, urllib.request, pyzipper
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mb_common import mb_key, corpus_dir
API="https://mb-api.abuse.ch/api/v1/"; KEY=mb_key(); PW=b"infected"
OUT=corpus_dir("positive"); os.makedirs(OUT, exist_ok=True)
def post(fields, raw=False):
    data="&".join(f"{k}={v}" for k,v in fields.items()).encode()
    req=urllib.request.Request(API,data=data,headers={"Auth-Key":KEY})
    r=urllib.request.urlopen(req,timeout=60).read()
    return r if raw else json.loads(r)
# candidate ClamAV names: trigger name + each alt-name inside .{...}
names=set()
for f in os.listdir("/tmp/bc"):
    if not f.endswith(".cbc"): continue
    n=open(f"/tmp/bc/{f}").read().split("\n")[1].split(";")[0]
    i=n.find(".{")
    if i>=0:
        base=n[:i]; alts=n[i+2:].rstrip("}").split(",")
        names.add(base)
        for a in alts:
            if a.strip(): names.add(a.strip())
    else:
        names.add(n)
def download(sha):
    blob=post({"query":"get_file","sha256_hash":sha}, raw=True)
    if blob[:2]!=b"PK": return None
    with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
        z.pwd=PW; return z.read(z.namelist()[0])
total=0; per={}
for n in sorted(names):
    j=post({"query":"get_clamavinfo","clamav":n,"limit":"2"})
    if j.get("query_status")!="ok": continue
    data=j.get("data") or []
    if not data: continue
    d=os.path.join(OUT, n.replace("/","_")); os.makedirs(d, exist_ok=True)
    got=0
    for s in data[:2]:
        sha=s["sha256_hash"]; dest=os.path.join(d, sha+".bin")
        if os.path.exists(dest): got+=1; continue
        try:
            p=download(sha)
            if p: open(dest,"wb").write(p); got+=1; total+=1
        except Exception as e: print("  !",sha[:12],e)
    if got: per[n]=got; print(f"{n}: {got}")
print(f"\n{len(per)} detection names with samples; {total} new files")
