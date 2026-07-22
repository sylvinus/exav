#!/usr/bin/env python3
"""Compare two engines' result tables and bucket the differences.

The buckets exist because "they disagreed" is almost never the useful answer.
Most differences are one of a few known shapes, and the ones worth a human's
attention are a small minority that the rest would otherwise bury.

Timings are reported as a DEBUGGING AID ONLY — see the note in
`difftest-scan.py`. They are measured under concurrency and against a cold page
cache, so they are useful for spotting a wedged file or an engine that is
dramatically slower, and useless as a benchmark. Do not quote them as one.
"""

import argparse
import sys
from collections import Counter, defaultdict


def load(path):
    rows = {}
    with open(path) as f:
        next(f, None)
        for ln in f:
            p = ln.rstrip("\n").split("\t")
            if len(p) >= 4:
                rows[p[0]] = (p[2], int(p[3]) if p[3].isdigit() else 0)
    return rows


def load_meta(path):
    """The run totals sidecar. Aggregate only — see difftest-scan.py."""
    meta = {}
    try:
        with open(path + ".meta") as f:
            for ln in f:
                k, _, v = ln.rstrip("\n").partition("\t")
                meta[k] = v
    except OSError:
        pass
    return meta


def sigset(v):
    return set() if v in ("-", "ERROR") or v.startswith("!") else set(v.split(","))


def gave_up(v):
    """Whether a verdict is an engine reporting that IT stopped, not a detection.

    `Heuristics.Limits.Exceeded.*` is clamd saying it hit its own scan-time or
    scan-size ceiling. That is a statement about the scanner, not about the file.
    """
    return all(s.startswith("Heuristics.Limits.Exceeded") for s in sigset(v)) and sigset(v)


def classify(c, e):
    """`(bucket, why)` for one file's pair of verdicts."""
    if c == "ERROR" or e == "ERROR":
        return "ERROR", "a scan failed, so there is nothing to compare"
    cs, es = sigset(c), sigset(e)
    # clam ran out of budget and said so; exav finished the same file. Counting
    # that as a missed detection is a bucketing artifact — there is no malware
    # here that exav failed to find, only a scan clam declined to complete. It
    # was 43 of 97 "false negatives", i.e. the largest FN class was exav winning.
    if gave_up(c) and not es:
        return "CLAM_GAVE_UP", "clam hit its own scan limit; exav completed the scan"
    if e.startswith("!"):
        # exav flagged content it could not fully scan. Against a clam `OK` this
        # is a deliberate capability difference, not a false positive: clam
        # returns OK for content it never opened, and exav refuses to.
        return ("CAREFUL", "exav flagged not-fully-scanned; clam said OK") if not cs \
            else ("CAREFUL_FN", "clam detected; exav flagged not-fully-scanned")
    if not cs and not es:
        return "clean", "both clean"
    if cs and not es:
        return "FN", "clam detected, exav did not"
    if es and not cs:
        # NOT "false positive". On an 8,978-file run every one of these was
        # checked and none was an exav error: nearly all were hits inside
        # members clamd never unpacked (confirmed by re-scanning exav's own
        # extracted members WITH clamd, which then flags them under the same
        # name). Naming this bucket FP invites fixing detections that are right.
        return "EXAV_ONLY", "exav detected, clam clean — verify before assuming an FP"
    if cs == es:
        return "AGREE", "identical signature sets"
    if cs & es:
        return "PARTIAL", "sets overlap — same malware, one engine also named more"
    return "NAMEDIFF", "sets are disjoint — a real disagreement about what this is"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clam", required=True)
    ap.add_argument("--exav", required=True)
    ap.add_argument("--show", type=int, default=15, help="examples per bucket")
    ap.add_argument("--out", help="write the joined table here")
    args = ap.parse_args()

    clam, exav = load(args.clam), load(args.exav)
    both = sorted(set(clam) & set(exav))
    if not both:
        print("no files scanned by both engines", file=sys.stderr)
        return 1

    buckets = Counter()
    examples = defaultdict(list)
    slowest = []
    for p in both:
        cv, ct = clam[p]
        ev, et = exav[p]
        b, _ = classify(cv, ev)
        buckets[b] += 1
        if len(examples[b]) < args.show:
            examples[b].append((p, cv, ev))
        slowest.append((et, ct, p))

    n = len(both)
    print(f"files compared: {n}")
    print(f"  only in clam results: {len(set(clam) - set(exav))}")
    print(f"  only in exav results: {len(set(exav) - set(clam))}")
    print()
    print("buckets:")
    for b, k in buckets.most_common():
        print(f"  {b:<11} {k:>6}  {100.0 * k / n:5.1f}%")
    print()

    # Aggregate wall-clock over the same corpus. Both engines ran at the same
    # concurrency, so the ratio is meaningful; neither number is a benchmark.
    cm, em = load_meta(args.clam), load_meta(args.exav)
    if cm.get("elapsed_s") and em.get("elapsed_s"):
        ct, et = float(cm["elapsed_s"]), float(em["elapsed_s"])
        print(
            f"total wall-clock (jobs={cm.get('jobs', '?')}): "
            f"clam={ct:.0f}s  exav={et:.0f}s  "
            f"ratio={et / ct:.2f}x"
            + ("  [partly from cache]" if cm.get("from_cache", "0") != "0" else "")
        )
        for label, m in (("clam", cm), ("exav", em)):
            b = int(m.get("bytes", 0))
            e = float(m.get("elapsed_s", 0)) or 1e-9
            print(
                f"  {label}: {m.get('scanned', '?')} files, {b / 1e9:.1f} GB, "
                f"{int(m.get('scanned', 0) or 0) / e:.1f} files/s, {b / e / 1e6:.0f} MB/s"
            )
        print("  (debugging aid, NOT a benchmark — measured under concurrency)")
        print()

    # Which files cost exav the most. Useful for finding one that wedged a
    # worker; not a ranking of anything, for the same reason.
    slowest.sort(reverse=True)
    if slowest and slowest[0][0] > 0:
        print("slowest for exav (wall-clock under load, for debugging only):")
        for et, ct, p in slowest[:10]:
            print(f"  exav={et:>7} ms  clam={ct:>7} ms  {p}")
        print()

    order = ["FN", "CAREFUL_FN", "NAMEDIFF", "PARTIAL", "EXAV_ONLY", "CAREFUL",
             "CLAM_GAVE_UP", "ERROR"]
    for b in order:
        if not examples[b]:
            continue
        _, why = classify(*(examples[b][0][1:]))
        print(f"=== {b} ({buckets[b]}) — {why}")
        for p, cv, ev in examples[b]:
            print(f"    clam: {cv}")
            print(f"    exav: {ev}")
            print(f"          {p}")
        print()

    if args.out:
        with open(args.out, "w") as f:
            f.write("path\tclam\texav\tbucket\tclam_ms\texav_ms\n")
            for p in both:
                cv, ct = clam[p]
                ev, et = exav[p]
                f.write(f"{p}\t{cv}\t{ev}\t{classify(cv, ev)[0]}\t{ct}\t{et}\n")
        print(f"joined table: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
