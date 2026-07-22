#!/usr/bin/env python3
"""Rank the ClamAV signature FEEDS that would add the most coverage, from the
MalwareBazaar metadata (`<sha>.json`, written by fetch-corpus-meta.py /
fetch-corpus-bulk.py) saved next to each sample.

For each sample's `intelligence.clamav` names, classify which feed the name comes
from — the paid SecuriteInfo feed, the free Sanesecurity / TwinWave / Porcupine /
MiscreantPunch feeds, or official ClamAV main/daily — so you can see which feeds
to subscribe to. Optionally cross-reference a list of samples a scan MISSED (e.g.
the both-clean files from a differential run) to rank feeds by how many of *our*
misses each would have caught.

  python3 scripts/clamav-sources.py [--missed FILE] [ROOT]

ROOT defaults to corpus/samples. --missed FILE is a newline-separated list of
sha256 hashes (or paths whose basename is `<sha>.bin`); with it, only those
samples are counted and the table reads "misses this feed would catch". Without
it, every sample with metadata is counted.
"""
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mb_common import corpus_dir

# Standard ClamAV name prefixes → official main/daily (not an add-on feed). An
# `.UNOFFICIAL` suffix always means an add-on feed regardless of prefix.
OFFICIAL_PREFIXES = {
    "Win", "Unix", "Osx", "Andr", "Doc", "Xls", "Ppt", "Js", "Html", "Vbs",
    "Ps1", "Rtf", "Pdf", "Email", "Legacy", "Multios", "Archive", "Img", "Test",
    "Clamav", "Pua", "PUA", "Heuristics", "Coff", "Elf", "Macho", "Ole2",
}

# Leading token (lowercased) → friendly feed name, for the well-known add-on feeds.
KNOWN_FEEDS = {
    "securiteinfo": "SecuriteInfo (paid)",
    "sanesecurity": "Sanesecurity (free)",
    "porcupine": "Porcupine / Sanesecurity (free)",
    "miscreantpunch": "MiscreantPunch (free)",
    "twinwave": "TwinWave EvilDoc (free)",
    "urlhaus": "URLhaus / abuse.ch (free)",
    "phishtank": "PhishTank (free)",
    "winnow": "Winnow / bit.nl (free)",
    "malwarepatrol": "MalwarePatrol",
    "interserver": "InterServer (free)",
    "foxhole": "Foxhole / Sanesecurity (free)",
    "yara": "YARA feed",
}


def source_of(name):
    """(feed_label, is_unofficial) for a ClamAV signature name."""
    unofficial = name.endswith(".UNOFFICIAL")
    head = name.split(".", 1)[0]
    if not unofficial and head in OFFICIAL_PREFIXES:
        return ("ClamAV official (main/daily)", False)
    return (KNOWN_FEEDS.get(head.lower(), head), True)


def load_missed(path):
    """Return a set of sha256 from a file of hashes or `<sha>.bin` paths."""
    out = set()
    for line in open(path):
        tok = line.strip()
        if not tok:
            continue
        base = os.path.basename(tok)
        out.add(base[:-4] if base.endswith(".bin") else base)
    return out


def main():
    argv = sys.argv[1:]
    missed = None
    if "--missed" in argv:
        i = argv.index("--missed")
        missed = load_missed(argv[i + 1])
        del argv[i : i + 2]
    root = argv[0] if argv else corpus_dir("samples")

    per_feed = defaultdict(set)  # feed -> set(sha) it detects (within scope)
    n_meta = n_scope = 0
    detectable = set()

    for dp, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            sha = fn[:-5]
            try:
                d = json.load(open(os.path.join(dp, fn)))
            except Exception:
                continue
            if not d:
                continue
            n_meta += 1
            if missed is not None and sha not in missed:
                continue
            n_scope += 1
            for nm in ((d.get("intelligence") or {}).get("clamav")) or []:
                # MB sometimes stores a scanner error string here, not a sig name.
                if " " in nm or "." not in nm:
                    continue
                feed, _ = source_of(nm)
                per_feed[feed].add(sha)
                detectable.add(sha)

    scope = "missed samples" if missed is not None else "samples"
    print(f"metadata records: {n_meta}")
    print(f"{scope} in scope: {n_scope}")
    if n_scope:
        print(f"{scope} a ClamAV name exists for (any feed): "
              f"{len(detectable)} ({100 * len(detectable) // n_scope}%)")
    print()
    verb = "misses it would catch" if missed is not None else "samples it detects"
    print(f"{'FEED / SOURCE':<34}{verb:>24}")
    print("-" * 58)
    for feed, shas in sorted(per_feed.items(), key=lambda kv: -len(kv[1])):
        print(f"{feed:<34}{len(shas):>24}")


if __name__ == "__main__":
    main()
