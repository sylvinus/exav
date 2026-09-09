---
title: Introduction
description: What exav is — a fast, memory-safe malware scanner written in Rust, streaming any file size, drop-in compatible with ClamAV signature databases and tooling.
---

**exav is a fast, memory-safe malware scanner written in Rust.** It ships as a
single static, MIT-licensed binary with a scanning CLI, a resident daemon and an
ICAP server, scans files of any size in constant memory, and drops into an
existing ClamAV setup: it loads the signature databases you already have and
answers the protocols your tooling already speaks.

exav reads existing signature databases (`.cvd`/`.cld`, `.ndb`/`.ldb`/`.hdb`/
`.hsb`/`.mdb`/`.msb`/`.cdb`/`.imp`/`.cbc`, plus YARA `.yar`/`.yara`) and speaks two
wire protocols — `clamd`, so `clamdscan`, milters and existing tooling talk to it
unchanged, and [ICAP](/guides/icap/), so it can replace a `c-icap` container at a
proxy's or upload scanner's adaptation hook.

## Why exav exists

Traditional AV engines are large C codebases: memory-unsafe by construction, and
in practice they bound their own work and then report a file clean without saying
so. A common example: files over ~2 GB are read but scanned as **zero bytes** and
still reported **`OK` / clean** — a *silent* clean verdict on a file that wasn't
actually inspected. exav is a from-scratch, memory-safe answer to that class of
problem: modern, fast, and honest about what it did and didn't scan.

Those goals are captured as a set of [design principles](/concepts/design-principles/).
The one to state up front is the honesty property:

> **Never report a file clean unless it was actually, *fully* scanned.**

A scanner's clean verdict is a safety claim. If exav did not finish looking,
claiming `OK` is a lie an adversary will engineer. Anything that makes the
scanner *stop looking early* — for **any** reason, no exceptions — must surface,
never be swallowed into `OK`.

So anything exav couldn't fully examine gets its own verdict —
`LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED` — rather than a silent
`OK`. That holds for external resource limits *and* for exav's own internal work
bounds. See [Never a silent clean](/concepts/design-principles/#never-a-silent-clean)
for the rules this implies, and [Verdicts & exit codes](/reference/verdicts/) for
what each verdict means and how it maps to a status tag and exit code.

## What it looks like

Point it at the signatures you already have, and scan:

```console
$ exav -d ~/.cvdupdate/database suspicious.bin
suspicious.bin: Win.Trojan.Agent-1234 FOUND
```

Size is not a special case. A stream is scanned as it arrives, so an object
larger than the machine never has to land on disk first:

```console
$ aws s3 cp s3://bucket/backup-50gb.tar.gz - | exav -d /var/lib/exav -
stdin: OK
```

We have run this against a **6 GiB file on a 4.8 GiB-RAM machine** — three times
the size at which ClamAV stops scanning and reports clean anyway — with the
signature at the very end of the file. Detected. The file-scanning working set
stays **flat at about 2 MiB whatever the file weighs**, which is the
[constant-memory streaming core](/concepts/streaming-memory/).

Load the database once and serve it, over either protocol or both at once:

```console
$ exav --listen clamd://0.0.0.0:3310 --listen icap://0.0.0.0:1344 -d /var/lib/exav
exav: daemon listening on tcp:0.0.0.0:3310
exav: serving ICAP on tcp:0.0.0.0:1344 (services: avscan, srv_clamav, virus_scan; preview 4096 B)
```

That is one process over one loaded database, which is what replaces a
`c-icap` + `clamav` container pair.

With no signatures at all, exav declines rather than answering from near-zero
coverage — the honesty property above, applied to its own configuration:

```console
$ exav suspicious.bin
exav: no signature database loaded — refusing to run (it would report real
malware as clean). Load signatures with -d/--sig-dir, or pass --allow-no-db
to use the built-in EICAR-only baseline (testing only).
```

## Where to next

- [Installation](/getting-started/installation/) — build from source or grab a
  container.
- [Quick start](/getting-started/quick-start/) — signatures, first scan, output.
- [Comparison with ClamAV](/project/comparison-with-clamav/) — compatibility,
  performance, and where the two differ.
- [Migrating from ClamAV](/guides/migrating-from-clamav/) — swap `clamscan` /
  `clamd` in place.
