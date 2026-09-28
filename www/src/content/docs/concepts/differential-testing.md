---
title: Differential testing
description: How exav validates its compatibility by scanning the same files with the same database as clamscan and comparing verdicts.
---

exav's compatibility is validated by differential testing: scan the same files
with the same signature database using both engines and compare verdicts. A
disagreement is either an exav bug (clamscan detects, exav misses) or something
to explain.

It is a compliance harness, not a benchmark. It records timings, which help spot
a wedged file or a much slower engine, but they are taken under concurrency
against a cold page cache and are not performance numbers.

The harness lives in the repository's `scripts/`; this page is the concept, not
the runbook.

## The setup

- **Corpus:** live malware, scanned statically and never executed (not in the
  repository).
- **Same database:** both engines load the same signature set (`daily.cvd` only,
  or the full `main` + `daily`), or the comparison means nothing.
- **Same client:** one program drives both daemons, so a difference cannot come
  from how they were asked.
- **All-match scans:** a verdict is the set of signatures that matched, not
  whichever one an engine reached first. Comparing first matches is the largest
  source of false disagreement: both engines find the malware and name different
  signatures.
- **One engine at a time, whole corpus per phase:** ClamAV's verdicts depend only
  on the pinned database, so its pass is run once and cached. Running both daemons
  together on a small host made them compete for RAM and produced errors that
  came from the harness, not the engines.

## Interpreting results

Results are bucketed, because "they disagreed" is rarely useful on its own:

| Bucket | Meaning |
|---|---|
| `AGREE` / `clean` | identical signature sets, or both clean: the headline metric |
| `PARTIAL` | the sets overlap: same malware, one engine also named more |
| `NAMEDIFF` | the sets are disjoint: a real disagreement about what this is |
| `FN` | clamscan detected, exav did not: a real gap |
| `EXAV_ONLY` | exav detected, clamscan said clean: verify before assuming a false positive |
| `CAREFUL` | exav reported not fully scanned; clamscan said OK |
| `CAREFUL_FN` | clamscan detected; exav reported not fully scanned |
| `ERROR` | a scan failed, so there is nothing to compare |

`EXAV_ONLY` is not called "false positive" because it has mostly been hits inside
members clamd never unpacked, confirmed by feeding exav's extracted members back
to clamd, which then flags them under the same name. `CAREFUL` is likewise a
capability difference: clamscan returns `OK` for content it never opened. `FN` is
the bucket that means a bug.

The absolute hit rate depends on the database, not the corpus: with `daily` alone
(most coverage is in `main.cvd`) both engines detect a small fraction of a random
sample. Agreement is what matters.

## `--clamav-compat`: matching boundaries, not quirks

By default exav runs at full capability. For a like-for-like run,
`--clamav-compat` sets a stock ClamAV build's documented defaults: the limit
values (`--max-input-bytes 100M`, `--max-extracted-bytes 400M`,
`--max-unpack-depth 17`, `--max-members 10000`, `--decode none`), the extractor
set, `.UNOFFICIAL` naming for unofficial-database signatures, and
`--partial-as ok`, so a file ClamAV would call clean is answered `OK` here too.
Each limit is also its own flag, and an explicit flag wins over the preset.

It matches ClamAV's documented boundaries, not its implementation quirks: it does
not reproduce each parser's internal caps and bail-outs (an RTF parser that stops
on an oversized control word and so never reaches an embedded payload, for
example). Reproducing those would mean copying weaknesses malware relies on, so
those divergences remain, and they are exav being more thorough.

A file exav could not fully examine is still logged under `--partial-as ok`, so
the harness can bucket it as `CAREFUL` rather than as agreement.

:::caution
`--clamav-compat` is for differential testing, not production. It reduces
detection so results reproduce clamscan's, and can miss malware exav would
otherwise catch (a UPX-packed Mirai ELF whose configuration exav decompresses,
for one). Run exav at full capability in production.
:::
