#!/usr/bin/env python3
"""Bulk-fetch a large, diverse malware corpus from MalwareBazaar for the full
exav-vs-clamscan differential test. Pulls recent samples across many file types
(to exercise every parser/unpacker), dedupes by sha256, extracts (pw "infected")
into corpus/samples/_bulk/<type>/<sha>.bin.

  MALWAREBAZAAR_API_KEY=... python3 scripts/fetch-corpus-bulk.py [PER_TYPE] [TOTAL_CAP]

LIVE MALWARE — static scan only, never execute. corpus/ is gitignored.
"""
import io
import os
import sys
import json
import shutil

import pyzipper

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mb_common import mb_key, mb_post, save_info, corpus_dir

API = "https://mb-api.abuse.ch/api/v1/"
KEY = mb_key()
ZIP_PW = b"infected"
OUT = corpus_dir("samples", "_bulk")
# free-space checks target the (same) filesystem the corpus lives on
HERE = corpus_dir()

# Diverse file types: executables, archives, documents, scripts — each exercises
# different exav code paths (PE/ELF parsing, unpacking, normalization, hashing).
FILE_TYPES = [
    "exe", "dll", "elf", "apk", "msi",
    "pdf", "doc", "docx", "xls", "xlsx", "rtf", "ppt",
    "zip", "rar", "7z", "gz", "iso", "cab", "jar",
    "js", "vbs", "ps1", "bat", "lnk", "hta", "html",
]

PER_TYPE = int(sys.argv[1]) if len(sys.argv) > 1 else 120
TOTAL_CAP = int(sys.argv[2]) if len(sys.argv) > 2 else 2500
MIN_FREE_GB = 4.0  # stop before filling the disk


def post(fields, retries=3):
    return mb_post(fields, KEY, retries=retries)


def list_type(ft):
    raw = post({"query": "get_file_type", "file_type": ft, "limit": str(PER_TYPE)})
    j = json.loads(raw)
    if j.get("query_status") != "ok":
        return []
    return [d["sha256_hash"] for d in j.get("data", [])]


def download(sha256):
    blob = post({"query": "get_file", "sha256_hash": sha256})
    if blob[:2] != b"PK":  # JSON error, not a zip
        return None
    with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
        z.pwd = ZIP_PW
        return z.read(z.namelist()[0])


def free_gb(path):
    return shutil.disk_usage(path).free / (1 << 30)


def existing_shas():
    seen = set()
    base = corpus_dir("samples")
    for root, _d, files in os.walk(base):
        for fn in files:
            if fn.endswith(".bin"):
                seen.add(os.path.splitext(fn)[0])
    return seen


def main():
    os.makedirs(OUT, exist_ok=True)
    seen = existing_shas()
    print(f"already have {len(seen)} samples; per_type={PER_TYPE} cap={TOTAL_CAP}")
    total = 0
    for ft in FILE_TYPES:
        if total >= TOTAL_CAP:
            break
        if free_gb(HERE) < MIN_FREE_GB:
            print(f"!! stopping: free disk < {MIN_FREE_GB} GB")
            break
        try:
            shas = list_type(ft)
        except Exception as e:  # noqa: BLE001
            print(f"{ft:6} list error: {e}")
            continue
        d = os.path.join(OUT, ft)
        os.makedirs(d, exist_ok=True)
        got = 0
        for sha in shas:
            if total >= TOTAL_CAP or free_gb(HERE) < MIN_FREE_GB:
                break
            if sha in seen:
                continue
            try:
                payload = download(sha)
            except Exception as e:  # noqa: BLE001
                print(f"  ! {sha[:12]} {e}")
                continue
            if not payload:
                continue
            sample_path = os.path.join(d, sha + ".bin")
            with open(sample_path, "wb") as f:
                f.write(payload)
            # Save the full MalwareBazaar metadata (family/tags/clamav/yara/…)
            # as a sibling <sha>.json so the corpus is self-describing.
            try:
                save_info(sample_path, KEY)
            except Exception as e:  # noqa: BLE001
                print(f"  ! meta {sha[:12]} {e}")
            seen.add(sha)
            got += 1
            total += 1
        print(f"{ft:6} +{got:4}  (total {total}, free {free_gb(HERE):.1f} GB)")
    print(f"\nfetched {total} new samples into {OUT}")


if __name__ == "__main__":
    main()
