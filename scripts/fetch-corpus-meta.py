#!/usr/bin/env python3
"""Backfill MalwareBazaar metadata for samples already on disk.

Walks corpus/samples/ for `<sha>.bin` files that lack a sibling `<sha>.json` and
fetches the full `get_info` record (family `signature`, tags,
`intelligence.clamav`, `yara_rules`, vendor verdicts, …) for each, writing it
next to the sample. Resumable: an existing `<sha>.json` is skipped, so re-running
only fills gaps. Newly-downloaded samples already get their metadata from
fetch-corpus-bulk.py; this is the one-time backfill for the historical corpus.

  MALWAREBAZAAR_API_KEY=... python3 scripts/fetch-corpus-meta.py [--force] [ROOT]

`ROOT` defaults to corpus/samples. A sha MalwareBazaar no longer knows about
gets an empty `<sha>.json` marker `{}` so it is not retried every run.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mb_common import mb_key, get_info, corpus_dir, meta_path_for

DELAY = 0.2  # polite pause between API calls


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    force = "--force" in sys.argv
    root = args[0] if args else corpus_dir("samples")
    key = mb_key()

    todo = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".bin"):
                continue
            sample = os.path.join(dirpath, fn)
            if force or not os.path.exists(meta_path_for(sample)):
                todo.append(sample)

    print(f"{len(todo)} samples need metadata under {root}")
    ok = miss = err = 0
    for i, sample in enumerate(todo):
        sha = os.path.splitext(os.path.basename(sample))[0]
        try:
            info = get_info(sha, key)
        except Exception as e:  # noqa: BLE001
            err += 1
            print(f"  ! {sha[:12]} {e}")
            time.sleep(2)
            continue
        # Write the record, or an empty marker when MB has no info (so we don't
        # re-query it forever).
        with open(meta_path_for(sample), "w") as f:
            json.dump(info or {}, f, indent=2, sort_keys=True)
        if info:
            ok += 1
        else:
            miss += 1
        if (i + 1) % 100 == 0 or i + 1 == len(todo):
            print(f"  {i + 1}/{len(todo)}  ok={ok} unknown={miss} err={err}")
        time.sleep(DELAY)
    print(f"done: {ok} with metadata, {miss} unknown to MB, {err} errors")


if __name__ == "__main__":
    main()
