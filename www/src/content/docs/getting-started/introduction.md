---
title: Introduction
description: What exav is, a memory-safe malware scanner written in Rust that reads ClamAV signature databases and speaks the clamd and ICAP protocols.
---

exav is a malware scanner written in memory-safe Rust. It ships as one
MIT-licensed binary with a scanning CLI, a resident daemon and an ICAP server,
and it drops into an existing ClamAV setup: it loads the signature databases you
already have and answers the protocols your tooling already speaks.

It reads ClamAV databases (`.cvd`/`.cld`, `.ndb`/`.ldb`/`.hdb`/`.hsb`/`.mdb`/
`.msb`/`.cdb`/`.imp`/`.cbc`) and YARA rules (`.yar`/`.yara`), and speaks two wire
protocols: `clamd`, so `clamdscan`, milters and existing tooling talk to it
unchanged, and [ICAP](/guides/icap/), so it can replace a `c-icap` container
behind a proxy or an upload service.

## Why exav exists

Established engines are large C codebases, and they bound their own work and then
report a file clean without saying so. ClamAV, for instance, reads a file over
about 2 GB, scans none of it, and answers `OK`. exav is a memory-safe rewrite
built around one rule:

> Never report a file clean unless it was fully scanned.

A file exav could not fully examine gets a verdict of its own
(`LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`) instead of `OK`. See
[Never a silent clean](/concepts/design-principles/#never-a-silent-clean) for what
the rule implies, and [Verdicts & exit codes](/reference/verdicts/) for how each
verdict is reported.

## What it looks like

Point it at the signatures you already have:

```console
$ exav -d ~/.cvdupdate/database suspicious.bin
suspicious.bin: Win.Trojan.Agent-1234 FOUND
```

A stream on stdin is scanned like a file. It is held in memory up to
`--spill-threshold-bytes` (16 MiB) and in a temporary file past that, up to
`--max-spill-bytes` (2 GiB):

```console
$ curl -s https://example.com/download.zip | exav -d /var/lib/exav -
stdin: OK
```

Load the database once and serve it over either protocol, or both:

```console
$ exav --listen clamd://0.0.0.0:3310 --listen icap://0.0.0.0:1344 -d /var/lib/exav
exav: prefork daemon: 4 workers; per-job limits: wall 120s, mem 2048 MiB, cpu 120s; recycle every 1000 jobs
exav: serving ICAP on tcp:0.0.0.0:1344 (services: avscan, srv_clamav, virus_scan; preview 4096 B)
```

One process and one loaded database replace a `c-icap` + `clamav` container
pair.

With no signatures, exav refuses to run rather than answer from near-zero
coverage:

```console
$ exav suspicious.bin
exav: no signature database loaded — refusing to run (it would report real
malware as clean). Load signatures with -d/--sig-dir, or pass --allow-no-db
to use the built-in EICAR-only baseline (testing only).
```

## Where to next

- [Installation](/getting-started/installation/): build from source or pull a
  container.
- [Quick start](/getting-started/quick-start/): signatures, a first scan, the
  output.
- [Comparison with ClamAV](/project/comparison-with-clamav/): compatibility,
  performance, and where the two differ.
- [Migrating from ClamAV](/guides/migrating-from-clamav/): replace `clamscan` and
  `clamd` in place.
