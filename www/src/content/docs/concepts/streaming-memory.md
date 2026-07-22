---
title: Streaming & memory
description: exav's constant-memory streaming core scans inputs larger than RAM in a single forward pass — the 6 GiB-file demo, and where the memory actually goes.
---

The reason exav can scan a file ClamAV skips is its **constant-memory streaming
core**: Aho-Corasick multi-pattern matching plus MD5/SHA1/SHA256 hashing in a
single forward pass, matching across buffer boundaries, on inputs larger than
RAM.

## The demo

A **6 GiB file on a 4.8 GiB-RAM machine** — 3× ClamAV's ~2 GB silent-skip limit
— with the signature at the very end: **detected.** ClamAV would read that file,
scan zero bytes, and report `OK`.

The file-scanning working set stays **flat (~2 MiB) regardless of file size**.
That's the per-scan working set *on top of* the loaded signature database (which
is a separate, one-time cost). A 4 GiB stream through the daemon adds only a flat
~3 MiB to its working set.

## Why it's constant

The core never materializes the whole input. It reads the file in fixed-size
buffers and:

- feeds each buffer through the Aho-Corasick automaton, carrying just enough
  state at the boundary to match patterns that straddle two buffers;
- updates the running MD5/SHA1/SHA256 hashers incrementally.

Nothing scales with file size. A multi-gigabyte file and a one-kilobyte file use
the same forward-pass machinery and the same tiny working set.

## Streaming vs seekable

Structural unpacking (archives, embedded documents) needs to *seek*, so it isn't
available on a pure forward-only pipe — a raw stream does pattern+hash only.
Local files and `http(s)://` URLs are seekable and get full structural analysis;
only unbounded pipes are limited. In practice `cat archive.zip | exav -` still
inspects inside the archive, because exav buffers stdin to a seekable source
(RAM if small, a temp file if large) before running the container-aware scan.

## Where the memory actually goes: the database

The per-scan working set is tiny; the memory that matters is the **signature
database**, and specifically **building** it. For the full `daily.cvd` the phases
are:

| Phase | Peak RSS |
|---|---|
| After parsing all signatures, before building the automaton | ~740 MB |
| **Building** the automaton from raw signatures | **~3.6 GB** |
| Final live structures (bodies + automaton + groups + …) | ~470 MB |
| **Loading the same signatures from a prebuilt database** | **~1.0 GB** |

The ~2.9 GB spike is the daachorse double-array Aho-Corasick construction
transient — a one-shot allocation burst, not steady-state storage and not a leak.
It can't be reduced by freeing things between steps because it's a single
construction event.

The answer is the [prebuilt database](/guides/prebuilt-database/): compile the
automaton once on a capable host, serialize it to a portable `.exavdb`, and load
it cheaply everywhere — deserialization allocates ~the final size, skipping the
construction transient entirely.

## Tuning knobs

Memory and CPU/time budgets are separate on purpose:

- **`--max-object-bytes`** (default 256M) — the most memory any *single*
  materialized object (a decompressed member, an LZ window, a decrypted blob)
  may use.

  It bounds one buffer, not the total. Several are alive at once — a container,
  its member and that member's own member are each mid-scan while the walk is
  inside them — so what bounds live extraction memory is `max_extracted_bytes`
  (default 1G), charged cumulatively and never released. Measured: a 1.1 MB 7z
  peaked at 2.3 GB with `--max-object-bytes` at its 256M default.
- **`--max-extracted-bytes`** (which sets `max_extracted_bytes`) — the ceiling on
  how much extracted data can be resident at once. Under the daemon this is
  clamped to fit the per-job address space, so hitting it is reported as a limit
  rather than killing the worker.
- **`--max-matcher-bytes`** (default 10G) — the cumulative scan-reach limit: the most
  bytes fed to the matcher across one top-level file. This is a **CPU/time**
  bound, not a memory bound — streamed members are scanned without being held in
  RAM, so it can be set far higher to fully scan multi-gigabyte members, paying
  only in scan time.

See [Configuration](/reference/configuration/) for the full set.
