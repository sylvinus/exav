#!/usr/bin/env python3
"""Fetch a small targeted malware corpus from MalwareBazaar for differential
validation of exav's bytecode interpreter. Samples are extracted (password
"infected") into corpus/samples/<family>/. LIVE MALWARE — static scan only.
"""
import io
import os
import sys
import json
import urllib.request

import pyzipper

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mb_common import mb_key, corpus_dir

API = "https://mb-api.abuse.ch/api/v1/"
KEY = mb_key()
ZIP_PW = b"infected"
OUT = corpus_dir("samples")

# Families our bytecode programs target (PE detections + packers).
FAMILIES = sys.argv[1].split(",") if len(sys.argv) > 1 else [
    "Locky", "GandCrab", "Virut", "Xpaj", "ConfuserEx", "MPRESS",
]
PER_FAMILY = int(sys.argv[2]) if len(sys.argv) > 2 else 4


def post(fields):
    data = "&".join(f"{k}={v}" for k, v in fields.items()).encode()
    req = urllib.request.Request(API, data=data, headers={"Auth-Key": KEY})
    return urllib.request.urlopen(req, timeout=60)


def list_family(fam):
    r = post({"query": "get_taginfo", "tag": fam, "limit": str(PER_FAMILY)})
    j = json.loads(r.read())
    if j.get("query_status") != "ok":
        return []
    return [(d["sha256_hash"], d.get("file_name", d["sha256_hash"]),
             d.get("signature")) for d in j["data"]]


def download(sha256):
    r = post({"query": "get_file", "sha256_hash": sha256})
    blob = r.read()
    if blob[:2] != b"PK":  # JSON error, not a zip
        return None
    with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
        z.pwd = ZIP_PW
        name = z.namelist()[0]
        return z.read(name)


def main():
    os.makedirs(OUT, exist_ok=True)
    total = 0
    for fam in FAMILIES:
        famdir = os.path.join(OUT, fam)
        os.makedirs(famdir, exist_ok=True)
        items = list_family(fam)
        got = 0
        for sha, _name, sig in items:
            dest = os.path.join(famdir, sha + ".bin")
            if os.path.exists(dest):
                got += 1
                continue
            try:
                payload = download(sha)
            except Exception as e:
                print(f"  ! {sha[:12]} {e}")
                continue
            if payload is None:
                continue
            with open(dest, "wb") as f:
                f.write(payload)
            got += 1
            total += 1
        print(f"{fam:14} sig={items[0][2] if items else '-':12} got {got}")
    print(f"\nTotal new samples: {total} in {OUT}")


if __name__ == "__main__":
    main()
