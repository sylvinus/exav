---
title: Differential testing
description: How exav validates its drop-in correctness — scanning the same files with the same database as clamscan, and comparing verdicts.
---

exav's correctness as a drop-in is validated by **differential testing**: scan
the **same files** with the **same signature database** using both engines and
compare verdicts. Disagreements are exav bugs — either a false negative (clamscan
detects, exav misses) or a genuine false positive.

It is a **compliance** harness, not a benchmark. It records timings, which are
useful for spotting a wedged file or an engine that is dramatically slower, but
they are measured under concurrency against a cold page cache and are not
performance numbers.

The harness lives in the repository's `scripts/` (tracked and reproducible); this
page is the concept, not the operator's runbook.

## The setup

- **Corpus:** a live-malware corpus, static-scan only, never executed
  (gitignored).
- **Both engines, same DB:** both must load the *same* signature set (`daily.cvd`
  only, or the full `main+daily`) or the comparison is meaningless.
- **Both driven by the same client:** one scanner program speaks to both daemons,
  so a difference in results cannot come from a difference in how they were asked.
- **Every scan is all-match.** A verdict is the *set* of signatures that matched,
  not whichever one an engine reached first. Comparing first-matches is the
  single largest source of fake disagreement: both engines find the malware, each
  names a different signature, and the diff calls it a conflict.
- **One engine resident at a time, whole corpus per phase.** ClamAV's verdicts are
  a function of the pinned database, so its pass is run once and cached; iterating
  on exav re-pays only its own pass. Running both daemons together on a small host
  meant they competed for RAM, workers died, and a stuck job turned into rows
  recorded as errors — differences that were artefacts of the harness rather than
  of the engines.

## Interpreting results

"They disagreed" is almost never the useful answer, so results are bucketed:

| Bucket | Meaning |
|---|---|
| `AGREE` / `clean` | identical signature sets, or both clean — the headline metric |
| `PARTIAL` | sets overlap: same malware, one engine also named more |
| `NAMEDIFF` | sets are disjoint — a real disagreement about what this is |
| `FN` | clamscan detected, exav did not — **a real gap** |
| `EXAV_ONLY` | exav detected, clamscan clean — verify before assuming an FP |
| `CAREFUL` | exav flagged not-fully-scanned; clamscan said OK |
| `CAREFUL_FN` | clamscan detected; exav flagged not-fully-scanned |
| `ERROR` | a scan failed, so there is nothing to compare |

**`EXAV_ONLY` is deliberately not called "FP".** On an 8,978-file run every one
was checked and none was an exav error: nearly all were hits inside members
clamd never unpacked, confirmed by re-scanning exav's own extracted members
*with clamd*, which then flags them under the same name. Naming the bucket "false
positive" invites fixing detections that are right.

`CAREFUL` is likewise a capability difference rather than a fault — clamscan
returns OK for content it never opened, and exav refuses to (see below).

**FN** is the bucket that means a bug. Real gaps it has surfaced: imphash
ordinal encoding, section-hash on truncated PEs, and embedded-PE scanning (a PE
appended inside another file).

Absolute hit rate is DB-bound, not a corpus property: with `daily` alone (most
coverage lives in `main.cvd`) both engines detect only a small fraction of a
random sample. The **agreement** is what matters.

## `--clamav-compat`: matching boundaries, not quirks

By default exav runs at **full capability**. For an apples-to-apples differential
run, `--clamav-compat` dials exav back to a stock ClamAV build's documented
defaults — the limit values (`--max-input-bytes 100M`, `--max-extracted-bytes 400M`,
`--max-depth 17`, `--max-members 10000`, `--base64 off`), the extractor set, and
cosmetic naming (the `.UNOFFICIAL` suffix on unofficial-database signatures). Each
limit is also an individual flag, and an explicit flag always wins over the
preset; the extractor set and the naming have no flags of their own, being wanted
only for a differential run.

It deliberately stops there. It matches ClamAV's *documented, well-defined
boundaries* — **not** its implementation quirks. It does not reproduce ClamAV's
internal parser caps and bail-outs (e.g. an RTF parser that aborts on oversized
control words and so never reaches an embedded payload). Matching ClamAV *there*
would mean re-implementing each format parser's weaknesses one by one —
deliberately degrading exav to mirror a limitation malware actively exploits.
Those residual divergences are exav being **more thorough**, not bugs, and they
stay even under `--clamav-compat`. In a differential run they're explained by
"ClamAV's parser bailed," not a missing knob.

:::caution
`--clamav-compat` is a diff-testing tool, not a production mode. It *reduces*
exav's detection capability so results reproduce clamscan's — it can miss malware
exav would otherwise catch (e.g. a UPX-packed Mirai ELF whose config exav
decompresses). Run exav at full capability in production.
:::

## What never gets reproduced

The [never-silent-clean invariant](/concepts/design-principles/#never-a-silent-clean) is *not* undone by
`--clamav-compat`. Where stock ClamAV returns clean after bounding its own work,
exav still reports `LIMITS-EXCEEDED` / `UNSCANNABLE` / `PASSWORD-PROTECTED` and
exits 2. A differential harness buckets these as an expected, explained
divergence — exav surfacing an outcome ClamAV hides.
