import os, sys, json, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mb_common import mb_key, corpus_dir
API="https://mb-api.abuse.ch/api/v1/"; KEY=mb_key()
def post(fields):
    data="&".join(f"{k}={v}" for k,v in fields.items()).encode()
    req=urllib.request.Request(API,data=data,headers={"Auth-Key":KEY})
    try: return json.loads(urllib.request.urlopen(req,timeout=40).read())
    except Exception as e: return {"query_status":f"err:{e}"}
# unique detection names (strip the .{...} alt-name suffix)
names=set()
for f in os.listdir("/tmp/bc"):
    if not f.endswith(".cbc"): continue
    line=open(f"/tmp/bc/{f}").read().split("\n")[1]
    n=line.split(";")[0]
    i=n.find(".{")
    if i>=0: n=n[:i]
    names.add(n)
hits={}
for n in sorted(names):
    j=post({"query":"get_clamavinfo","clamav":n,"limit":"5"})
    st=j.get("query_status")
    if st=="ok":
        data=j.get("data") or []
        if data:
            hits[n]=[d["sha256_hash"] for d in data]
            print(f"HIT {n}: {len(data)} sample(s)")
    elif st not in ("no_results","http_post_expected"):
        # show unexpected statuses once
        pass
print(f"\n{len(hits)} of {len(names)} detection names have samples on MalwareBazaar")
json.dump(hits, open(corpus_dir("clamav_hits.json"),"w"))
