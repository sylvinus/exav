---
title: Troubleshooting & FAQ
description: Common exav questions and problems, from the no-database refusal and exit code 3 to large files, memory at load, encrypted members, false positives, and real-time scanning.
---

See also [Verdicts & exit codes](/reference/verdicts/) and
[Configuration](/reference/configuration/).

## "No signature database loaded, refusing to run"

exav refuses to scan without a real signature database rather than answer every
file `OK` against near-zero coverage. Point `-d`/`--database` at a directory of
signatures or at a prebuilt `.exavdb` file, or put signatures in `--sig-dir`
(default `/var/lib/exav`); see [Signatures](/guides/signatures/). The built-in
EICAR-only baseline is available for testing with `--allow-no-db`
(`EXAV_ALLOW_NO_DB=1`).

## "unsupported database version N (this build expects M)"

A prebuilt `.exavdb` is tied to the exav version that built it. After upgrading,
rebuild it with `--build-db` from the raw signatures.

## exav exits `3` on files ClamAV called clean

Exit `3` is status `PARTIAL`: at least one file could not be fully examined
(`LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`). exav does not report
an incompletely scanned file as clean (see
[Never a silent clean](/concepts/design-principles/#never-a-silent-clean)).

In CI, treat `3` as "not a pass". A scanner failure is still `2`, as in ClamAV.
`--partial-as ok|found|error` maps `3` to another status if your pipeline wants
three codes rather than four.

For a differential run against `clamscan`, `--clamav-compat` matches its limits
and its answer here: it implies `--partial-as ok`. An explicit `--partial-as`
wins.

## A file comes back `LIMITS-EXCEEDED`

The reason names the limit that stopped the scan; raise that one. The flags bound
different things, and raising the wrong one changes nothing (see
[which one do I change](/reference/limits/#which-one-do-i-change)).

The common case is a large file. One over `--max-object-bytes` (256 MiB by
default) gets the full engine, but the checks that parse a file whole (a PE's
structure, YARA's `pe` module, a RAR, 7z or OLE container) do not run on it.
With `--spill-dir off` leaving nowhere to write them, neither do the text views
of a large text file (the HTML and script forms signatures are written against),
and an archive member that decodes past the limit is not scanned. Raise
`--max-object-bytes` to have those checks run, at the cost of memory. See
[Streaming & memory](/concepts/streaming-memory/).

## A file came back `PASSWORD-PROTECTED` or `UNSCANNABLE`

- **`PASSWORD-PROTECTED`**: an encrypted member. Supply passwords with
  `--passwords` (repeatable), `--passwords-from FILE` or a `.pwdb` database in
  the signature directory, then scan again. See
  [Migrating from ClamAV](/guides/migrating-from-clamav/#4-encrypted-archives--passwords).
- **`UNSCANNABLE`**: the container was recognised but could not be decoded (an
  unsupported codec, a RAR member split across volumes, a compressed stream
  damaged part way). Inspect it manually.

## exav uses a lot of memory when loading signatures

Building the in-memory automaton from a large raw signature set takes several GB
for a short time. Do it once: build a [prebuilt `.exavdb`](/guides/prebuilt-database/)
on a capable host and load that everywhere, with a fraction of the RAM and a fast
start. Memory during a scan is a separate matter, bounded by `--max-object-bytes`
and `--max-process-bytes` (see [sizing a server](/guides/sizing/)).

## Handling false positives

If a signature matches a file you trust, suppress that match rather than
disabling detection. exav loads ClamAV's formats for this from the signature
directory:

- `.fp` / `.sfp`: an allowlist by file hash (this file is trusted).
- `.ign` / `.ign2`: an ignore list by signature name (this signature is off).

For example, to trust one file:

```sh
f=trusted.bin
echo "$(md5sum "$f" | cut -d' ' -f1):$(stat -c%s "$f"):trusted-bin" >> /var/lib/exav/local.fp
```

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
manager), or pass `--allow-shutdown` (`EXAV_ALLOW_SHUTDOWN=1`) to honour the
command. See
[Security](/project/security/#daemon-exposure).
