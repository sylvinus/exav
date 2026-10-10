# Comparison with ClamAV: measurements and corrections

Moved out of the website's comparison page, which describes behaviour. This file
keeps the dated measurements and the record of claims that were corrected.

## Measured against clamd: the 2026-07-28 run

8,978 live-malware samples, both engines loading the same daily-only signature
set (339,917 signatures). Only the 5,436 files where both engines returned an
answer are counted; the rest hit a resource ceiling in the memory-capped clamd
container and measure the harness, not the engines.

exav ran at full capability (its own extractors and limits). The harness defaults
to `--clamav-compat`, which trades reach for reproducibility; measuring exav's
added coverage in that mode understates it by roughly 3x, so these figures come
from a `COMPAT=0` pass over the same files.

| | exav | clamd |
|---|---|---|
| detections | 897 | 796 |
| detected by this engine alone | **104** | 0 |

104 exav-only detections: 11.6% of exav's detections, 1.91% of files scanned. (In
`--clamav-compat` the same corpus yields 32, or 3.9%; the difference is the
extraction reach compat switches off.) Both engines move, so re-measure before
quoting.

Every one was verified. 101 of the 104 report a nested match location: the hit is
inside a member clamd did not unpack, and re-scanning exav's own extracted
members with clamd (see `exav-unpack/examples/dump_members.rs`) makes clamd flag
them under the same signature name while still calling the container clean. Of
the other three, two are `Target:0` RTF-exploit signatures legitimately matching
RTF files, and one is `Win.Trojan.Mimikatz` inside a PE that was base64-encoded
inside an RTF: none of the signature's seven subsignatures occurs in the raw
file, and all seven occur in the decoded image. None was a false positive.

Across all 5,436 comparable files, the `FN` count (clamd detected, exav returned
`OK`) was zero, and the `CAREFUL_FN` count (clamd names the malware, exav
declines to call the file clean but cannot name it) was also zero once the two
samples that sat there (an MPRESS-packed dropper and a UPX image carrying a bare
`PackHeader`) were unpacked.

A later code review found silent-miss paths the corpus had not exercised
(container hashes and raw signatures over `INSTREAM`/stdin/ICAP, an ignored
signature masking a later member, ZIP members hidden from the central directory,
files over the deep-analysis limit reported clean). They were fixed with tests;
this run predates those fixes.

### Why the run makes no speed claim

The differential harness is a compliance harness: it answers "do the two engines
agree", and is tuned for throughput so the question can be asked often. Its
timings exist to spot a wedged file or a much slower engine, and they are
confounded in at least four ways:

- **Scan ordering.** The engines run in separate phases over the same corpus,
  clamd first. Whatever runs second reads a partly warmed page cache, and a warm
  read is worth roughly 10x a cold one. That favours exav.
- **Concurrency contention.** Under more than one job, a file's elapsed time is
  mostly time spent competing with other jobs.
- **Unequal environments.** clamd ran memory-capped inside Docker; exav ran
  natively on the host.
- **Different work per file.** The compat and full-capability passes do not
  extract the same amount.

An earlier revision of the website quoted a mean/median table from such a run
and concluded a 1.27x speed ratio. That was not supportable from the data it
cited, so it was withdrawn. A speed claim needs a dedicated benchmark (one job,
warm cache, repeated runs, equal environments).

## Corrections

### RAR multi-volume is not a gap

An earlier revision of the comparison page listed RAR volume joining as a
capability gap. One verification pass had tested it on a host whose ClamAV build
ships no unrar library at all, so every RAR returned `OK`, which says nothing
about volume joining. A second pass on 1.5.3 reported the opposite.

Settled with a control: a single-volume RAR containing EICAR is detected by
ClamAV 1.5.3 (so RAR support is live), while a three-volume set whose payload
lives only in the last volume returns `OK` when volume 1 is scanned with all
siblings present. ClamAV does not join RAR volumes.

exav reports the split member and hands over the part that is in the scanned
volume while saying the rest is missing. Before that fix a stored split member
was emitted with no reason attached, so its prefix read as a complete member and
a multi-volume archive scanned clean. That was a silent truncation, closed for
both RAR3 and RAR5.

### Signature-format coverage

The count of signature lines exav could not load was 20 at one point during the
first release cycle, and reached zero. An earlier version of that list led with
"byte-compare subsignatures", which was wrong: the classifier guessed the cause
from punctuation and filed every alternation as a byte-compare, because both
contain a parenthesis. Byte-compare causes zero skips. A second entry,
"malformed database line", was wrong the same way: the line loads in clamscan,
and the real cause was the `:`-suffix on a subsignature reference.

### Things once listed as gaps

Each of these was listed as a shortfall at some point and turned out to be a
format ClamAV does not handle either: ACE, StuffIt, Inno Setup, WIM, ZIP method
10 (DCL Implode), the PDF image filters, KWAJ, NTFS, FAT, VHD, VHDX, QCOW2, VMDK,
UDF, and YARA modules. The website's comparison page keeps the current table.
