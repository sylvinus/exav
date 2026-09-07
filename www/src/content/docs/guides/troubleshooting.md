---
title: Troubleshooting & FAQ
description: Common exav questions and problems — the no-database refusal, exit code 3, high memory at load, encrypted/unscannable members, handling false positives, and real-time scanning.
---

Answers to the questions that come up most often when running exav. See also
[Verdicts & exit codes](/reference/verdicts/) and [Configuration](/reference/configuration/).

## "No signature database loaded — refusing to run"

exav **refuses to scan with no real signature database** rather than answer every
file `OK` against near-zero coverage — a silently-passing scanner is the exact
bypass exav exists to prevent. Point `-d`/`--sigs-dir` at a directory (or a prebuilt
`.exavdb`) containing real signatures; see [Signatures](/guides/signatures/). The
tiny built-in EICAR-only baseline is opt-in for testing via `--allow-no-db`
(`EXAV_ALLOW_NO_DB=1`).

## exav exits `3` on files ClamAV called clean

Exit `3` is status `PARTIAL`: **at least one file could not be fully examined** —
`LIMITS-EXCEEDED`, `UNSCANNABLE`, or `PASSWORD-PROTECTED`. This is deliberate:
exav never reports an incompletely-scanned file as clean (see
[Never silently clean](/concepts/design-principles/#never-a-silent-clean)).

In CI, treat `3` as "not a pass", not as a scanner crash — that is still `2`,
with the same meaning it has in ClamAV. `--partial-as ok|found|error` folds `3`
into another status if your pipeline would rather read three codes than four.

If you are comparing against `clamscan` for a differential run, `--clamav-compat`
matches its documented limits *and* its answer here: it implies `--partial-as ok`,
so the two agree file for file. On its own the flag changes what exav reports, not
what it saw — an explicit `--partial-as` after it wins.

## A file came back `PASSWORD-PROTECTED` or `UNSCANNABLE`

- **`PASSWORD-PROTECTED`** — an encrypted member. Supply passwords with
  `--passwords` (repeatable) or a `.pwdb` password database in the signature
  directory, then re-scan. See [Migrating from ClamAV](/guides/migrating-from-clamav/#4-encrypted-archives--passwords).
- **`UNSCANNABLE`** — the container was recognized but couldn't be decoded (an
  unsupported codec, or a RAR member split across volumes). The file is flagged, not
  passed — treat it as "inspect manually".

## exav uses a lot of memory when loading signatures

Building the in-memory automaton from a large raw signature set is a one-shot
memory spike (several GB transiently for a full database). Do that work once and
reuse it: build a [prebuilt `.exavdb`](/guides/prebuilt-database/) on a capable
host, then load it cheaply everywhere (a fraction of the RAM, sub-second cold
start). Per-*scan* memory is unrelated and stays flat regardless of file size.

## Handling false positives (allowlisting)

If a signature matches a file you trust, add an **allowlist** entry rather than
disabling detection wholesale. exav loads ClamAV's allowlist formats from the
signature directory:

- `.fp` / `.sfp` — hash-based allowlist (a specific file digest is trusted).
- `.ign` / `.ign2` — signature-name allowlist (suppress a specific signature).

Drop the allowlist file alongside your other signatures and it is picked up on
load. When reporting a suspected false positive upstream, it belongs to the
signature *author* (the feed the signature came from), not to exav — exav runs the
signatures, it does not write them.

## Does exav do real-time / on-access scanning?

**Not today.** exav has no on-access scanner (there is no equivalent to ClamAV's
`clamonacc` / fanotify kernel hooks). exav is an on-demand scanner: a CLI for
one-shot and scheduled scans, and a resident [daemon](/guides/daemon/) that other
tools call over the `clamd` protocol. To scan on events, drive exav from your own
trigger (a file-watcher, an upload handler, a mail/proxy hook) against the daemon.
If you specifically need kernel-level real-time blocking, ClamAV's `clamonacc`
remains the tool for that.

## Can I write my own signatures for exav?

exav *loads* the standard signature formats but does not ship signature-authoring
tooling. Author signatures with the established ecosystem tools and drop the
resulting files into your signature directory — exav loads them like any other
(see [Signatures](/guides/signatures/) and
[Comparison with ClamAV](/project/comparison-with-clamav/#signature--format-support-whats-missing-whats-added)).
For custom rules, YARA `.yar`/`.yara` files are often the easiest path (see
[YARA rules](/guides/yara/)).

## The daemon won't stop from a client

By design: exav **refuses the clamd `SHUTDOWN` command by default**, so a client
that can reach the socket can't stop the daemon. Stop it from the host (signal /
service manager), or set `EXAV_ALLOW_SHUTDOWN=1` if you really want the verb
enabled. See [Security](/project/security/#daemon-exposure).
