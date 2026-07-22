#!/usr/bin/env python3
"""Fetch a bounded sample of *benign* packed PE files for unpacker validation.

The malware corpus is a poor test set for a packer unpacker: current malware
uses UPX, MPRESS and the virtualizing protectors, so the older compressors an
unpacker also has to handle (ASPack, FSG, MEW, NsPack, PECompact, PEtite,
RLPack, TELock, WinUpack, Yoda) simply are not in it. This pulls a few samples
per packer from the packing-box dataset — ordinary Windows utilities, packed —
which gives the emulator ground truth it can be checked against: the same
programs are available unpacked in the dataset's `not-packed` folder.

Not malware, and kept out of `corpus/samples/` so the differential harness
(which scans that directory) is unaffected.

    scripts/fetch-packed-pe.py [PER_PACKER] [PACKER,...]
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mb_common import corpus_dir

REPO = "packing-box/dataset-packed-pe"
API = f"https://api.github.com/repos/{REPO}/contents"
RAW = f"https://raw.githubusercontent.com/{REPO}/main"
OUT = corpus_dir("packers")

# Packers worth emulating. The virtualizers (Themida, Enigma Virtual Box) are
# deliberately absent: they are never emulated — there is no original code in
# memory to recover — and samples for the *reporting* path come from
# MalwareBazaar, where they are plentiful.
DEFAULT_PACKERS = [
    "ASPack", "FSG", "MEW", "MPRESS", "NSPack", "PECompact", "PEtite", "RLPack",
    "TELock", "UPX", "WinUpack", "Yoda-Crypter", "Yoda-Protector", "Exe32pack",
    "JDPack", "Packman", "Neolite", "EXpressor", "BeRoEXEPacker", "Alienyze",
    "Amber", "Eronana Packer", "Molebox",
]
# Skip the big ones: coverage comes from the variety of packers, not from
# emulating one large program many times.
MAX_BYTES = 4 << 20


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "exav-fetch"})
    return urllib.request.urlopen(req, timeout=60).read()


def main():
    per = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    packers = sys.argv[2].split(",") if len(sys.argv) > 2 else DEFAULT_PACKERS
    total = 0
    for packer in packers:
        try:
            listing = json.loads(get(f"{API}/packed/{urllib.parse.quote(packer)}"))
        except Exception as e:  # noqa: BLE001 - a missing packer is not fatal
            print(f"{packer:16s} listing failed: {e}")
            continue
        picks = [e for e in listing if e["type"] == "file" and e["size"] <= MAX_BYTES]
        picks.sort(key=lambda e: e["name"])
        picks = picks[:per]
        outdir = os.path.join(OUT, packer.replace(" ", "-"))
        os.makedirs(outdir, exist_ok=True)
        got = 0
        for e in picks:
            dest = os.path.join(outdir, e["name"])
            if os.path.exists(dest):
                got += 1
                continue
            try:
                data = get(e["download_url"])
            except Exception as err:  # noqa: BLE001
                print(f"  {e['name']}: {err}")
                continue
            with open(dest, "wb") as fh:
                fh.write(data)
            got += 1
        total += got
        print(f"{packer:16s} {got} samples in {outdir}")
    print(f"{total} files under {OUT}")


if __name__ == "__main__":
    import urllib.parse

    main()
