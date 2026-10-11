---
title: Troubleshooting & FAQ
description: Common exav questions and problems, from the no-database refusal and exit code 3 to large files, memory at load, encrypted members, false positives, and real-time scanning.
---

See also [Verdicts & exit codes](/scanner/reference/verdicts/) and
[Configuration](/scanner/reference/configuration/).

## "No signature database loaded, refusing to run"

exav refuses to scan without a real signature database rather than answer every
file `OK` against near-zero coverage. Point `-d`/`--database` at a directory of
signatures or at a prebuilt `.exavdb` file, or put signatures in `--sig-dir`
(default `/var/lib/exav`); see [Signatures](/scanner/guides/signatures/). The built-in
EICAR-only baseline is available for testing with `--allow-no-db`
(`EXAV_ALLOW_NO_DB=1`).

## "unsupported database version N (this build expects M)"

A prebuilt `.exavdb` carries a format version, and this exav reads another one.
Rebuild it with `--build-db` from the raw signatures (see
[Prebuilt database](/scanner/guides/prebuilt-database/#rebuild-after-an-exav-upgrade)).

## "a prebuilt database loads by its own path, not from the directory holding it"

A directory given to `-d` or `--sig-dir` held only a `.exavdb`. Load the file
itself: `-d /path/to/file.exavdb`.

## "signature source URLs are set but this build has no updater"

`--auto-update` fetches only in a build with HTTP support; the release binaries
and a plain `cargo install exav` have none. Build with `--features http` (see
[Installation](/scanner/getting-started/installation/)), use the container image, or fill
the signature directory with `cvd` or `freshclam`.

## exav exits `3` on files ClamAV called clean

Exit `3` is status `PARTIAL`: at least one file could not be fully examined
(`LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`). exav does not report
an incompletely scanned file as clean (see
[Never a silent clean](/scanner/concepts/design-principles/#never-a-silent-clean)).

In CI, treat `3` as "not a pass". A scanner failure is still `2`, as in ClamAV.
`--partial-as ok|found|error` maps `3` to another status if your pipeline wants
three codes rather than four. See
[Verdicts & exit codes](/scanner/reference/verdicts/#process-exit-code).

## `clamdscan` or a milter says `ERROR` for an encrypted or oversized file

The clamd protocol has no `PARTIAL`, so over it a file exav could not fully
examine is answered `<CATEGORY> ERROR` (see
[on the clamd wire](/scanner/reference/verdicts/#on-the-clamd-wire)). Clients act on it
as on any scanner error. Supply passwords or raise the limit, or choose the
answer with `--partial-as` on the daemon.

## A client gets "permission denied" on the daemon's socket

exav creates a Unix socket with mode `0600`, so only its own user can connect.
Widen it on the address, for example
`--listen 'clamd:///run/clamav/clamd.ctl?mode=660'`, with the client's user in
the daemon's group (see [Socket permissions](/scanner/reference/cli/#socket-permissions)).

## A file comes back `LIMITS-EXCEEDED`

The reason names the limit that stopped the scan; raise that one. The flags bound
different things, and raising the wrong one changes nothing (see
[which one do I change](/scanner/reference/limits/#which-one-do-i-change)).

The common case is a large file. One over `--max-object-bytes` (256 MiB by
default) gets the full engine, but the checks that parse a file whole (a PE's
structure, YARA's `pe` module, a RAR, 7z or OLE container) do not run on it.
With `--spill-dir off`, a large text file also skips its HTML and script views,
and an archive member that decodes past the limit is not scanned. Raise
`--max-object-bytes` to have those checks run, at the cost of memory. See
[Streaming & memory](/scanner/concepts/streaming-memory/).

## A file came back `PASSWORD-PROTECTED` or `UNSCANNABLE`

- **`PASSWORD-PROTECTED`**: an encrypted member. Supply passwords with
  `--passwords` (repeatable), `--passwords-from FILE` or a `.pwdb` database in
  the signature directory, then scan again. See
  [Encryption and passwords](/scanner/reference/formats/#encryption-and-passwords).
- **`UNSCANNABLE`**: the container was recognised but could not be decoded (an
  unsupported codec, a RAR member split across volumes, a compressed stream
  damaged part way). Inspect it manually.

## exav uses a lot of memory when loading signatures

Parsing a large raw signature set and building its index takes more memory than
the loaded database, for a short time. Do it once: build a prebuilt `.exavdb` on a
capable host and load that everywhere (see
[what it costs](/scanner/guides/prebuilt-database/#what-it-costs)). Memory during a scan is a separate matter, bounded by `--max-object-bytes`
and `--max-process-bytes` (see [sizing a server](/scanner/guides/sizing/)).

## Handling false positives

If a signature matches a file you trust, suppress that match rather than
disabling detection. exav loads ClamAV's formats for this from the signature
directory:

- `.fp` / `.sfp`: an allowlist by file hash (this file is trusted).
- `.ign` / `.ign2`: an ignore list by signature name (this signature is off).

For example, to trust one file (GNU `md5sum` and `stat`; use your own signature
directory):

```sh
f=trusted.bin
echo "$(md5sum "$f" | cut -d' ' -f1):$(stat -c%s "$f"):trusted-bin" >> /var/lib/exav/local.fp
```

A `.exavdb` loaded with `-d` is not affected until you rebuild it from that
directory.

Report a suspected false positive to the author of the signature (the feed it
came from); exav runs signatures, it does not write them.

## Does exav do real-time / on-access scanning?

No. exav has no on-access scanner (no equivalent of ClamAV's `clamonacc` and its
fanotify hooks). It is an on-demand scanner: a CLI for one-shot and scheduled
scans, and a resident [daemon](/scanner/guides/daemon/) other tools call over the `clamd`
protocol. To scan on events, drive the daemon from your own trigger (a file
watcher, an upload handler, a mail or proxy hook). For kernel-level blocking,
ClamAV's `clamonacc` remains the tool.

## Can I write my own signatures for exav?

exav loads the standard formats but ships no authoring tools. Write signatures
with the usual ecosystem tools and put the files in your signature directory (see
[Signatures](/scanner/guides/signatures/) and
[Comparison with ClamAV](/scanner/reference/comparison-with-clamav/#signature--format-support-whats-missing-whats-added)).
YARA `.yar`/`.yara` files are often the easiest route for custom rules (see
[YARA rules](/scanner/guides/yara/)).

## The daemon won't stop from a client

exav refuses the clamd `SHUTDOWN` command by default, so a client that can reach
the socket cannot stop the daemon. Stop it from the host (a signal, the service
manager), or pass `--allow-shutdown` (`EXAV_ALLOW_SHUTDOWN=1`) to honour the
command. See
[Security](/project/security/#daemon-exposure).
