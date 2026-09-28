---
title: Troubleshooting & FAQ
description: Common exav questions and problems, from the no-database refusal and exit code 3 to large files, memory at load, encrypted members, false positives, and real-time scanning.
---

See also [Verdicts & exit codes](/reference/verdicts/) and
[Configuration](/reference/configuration/).

## "No signature database loaded — refusing to run"

exav refuses to scan without a real signature database rather than answer every
file `OK` against near-zero coverage. Point `-d`/`--sig-dir` at a directory (or a
prebuilt `.exavdb`) containing real signatures; see
[Signatures](/guides/signatures/). The built-in EICAR-only baseline is available
for testing with `--allow-no-db` (`EXAV_ALLOW_NO_DB=1`).

## exav exits `3` on files ClamAV called clean

Exit `3` is status `PARTIAL`: at least one file could not be fully examined
(`LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`). exav does not report
an incompletely scanned file as clean (see
[Never a silent clean](/concepts/design-principles/#never-a-silent-clean)).

In CI, treat `3` as "not a pass". A scanner failure is still `2`, as in ClamAV.
`--partial-as ok|found|error` maps `3` to another status if your pipeline wants
three codes rather than four.

For a differential run against `clamscan`, `--clamav-compat` matches its limits
and its answer here: it implies `--partial-as ok`, so the two agree file for
file. An explicit `--partial-as` after it wins.

## A large file comes back `LIMITS-EXCEEDED`

A file over `--max-object-bytes` (256 MiB by default) is only checked against
literal signatures and whole-file hashes, so unless one of those matches it is
reported `LIMITS-EXCEEDED`. Raise `--max-object-bytes` to give it the full
engine, at the cost of memory. See [Streaming & memory](/concepts/streaming-memory/).

## A file came back `PASSWORD-PROTECTED` or `UNSCANNABLE`

- **`PASSWORD-PROTECTED`**: an encrypted member. Supply passwords with
  `--passwords` (repeatable) or a `.pwdb` database in the signature directory,
  then scan again. See
  [Migrating from ClamAV](/guides/migrating-from-clamav/#4-encrypted-archives--passwords).
- **`UNSCANNABLE`**: the container was recognised but could not be decoded (an
  unsupported codec, a RAR member split across volumes, a read error). Inspect it
  manually.

## exav uses a lot of memory when loading signatures

Building the in-memory automaton from a large raw signature set takes several GB
for a short time. Do it once: build a [prebuilt `.exavdb`](/guides/prebuilt-database/)
on a capable host and load that everywhere, with a fraction of the RAM and a fast
start. Memory during a scan is a separate matter, bounded by `--max-object-bytes`
and `--max-extracted-bytes`.

## Handling false positives

If a signature matches a file you trust, suppress that match rather than
disabling detection. exav loads ClamAV's formats for this from the signature
directory:

- `.fp` / `.sfp`: an allowlist by file hash (this file is trusted).
- `.ign` / `.ign2`: an ignore list by signature name (this signature is off).

Report a suspected false positive to the author of the signature (the feed it
came from); exav runs signatures, it does not write them.

## Does exav do real-time / on-access scanning?

No. exav has no on-access scanner (no equivalent of ClamAV's `clamonacc` and its
fanotify hooks). It is an on-demand scanner: a CLI for one-shot and scheduled
scans, and a resident [daemon](/guides/daemon/) other tools call over the `clamd`
protocol. To scan on events, drive the daemon from your own trigger (a file
watcher, an upload handler, a mail or proxy hook). For kernel-level blocking,
ClamAV's `clamonacc` remains the tool.

## Can I write my own signatures for exav?

exav loads the standard formats but ships no authoring tools. Write signatures
with the usual ecosystem tools and put the files in your signature directory (see
[Signatures](/guides/signatures/) and
[Comparison with ClamAV](/project/comparison-with-clamav/#signature--format-support-whats-missing-whats-added)).
YARA `.yar`/`.yara` files are often the easiest route for custom rules (see
[YARA rules](/guides/yara/)).

## The daemon won't stop from a client

exav refuses the clamd `SHUTDOWN` command by default, so a client that can reach
the socket cannot stop the daemon. Stop it from the host (a signal, the service
manager), or set `EXAV_ALLOW_SHUTDOWN=1` to honour the command. See
[Security](/project/security/#daemon-exposure).
