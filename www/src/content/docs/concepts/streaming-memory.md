---
title: Streaming & memory
description: Where exav holds a file in memory, where it streams, what each path matches, and where the memory really goes.
---

exav matches a file in one of two ways, chosen by size.

## Up to `--max-object-bytes`: the full engine, in memory

A file up to `--max-object-bytes` (256 MiB by default) is read into memory and
gets the full engine:

- every `.ndb` form: wildcards, gaps, anchored offsets, file-type targets;
- `.ldb` logical signatures, with their regexes and byte comparisons;
- the normalised views of HTML, text and scripts that those signatures are
  written against;
- YARA rules, bytecode programs, PE section hashes, whole-file hashes;
- structural analysis: unpacking, embedded files, heuristics.

Verifying a wildcard or logical signature means looking back and forth around
each candidate match, which is why this path holds the file. Memory is roughly
the file's size, plus a lowercase copy for case-insensitive signatures and, for
text, one normalised copy at a time.

Archives in a streamable format (ZIP, tar, 7z, CAB, gzip and most others; see
[archive extraction](/concepts/archive-extraction/)) are walked member by member,
and each member is treated like a file: in memory up to the same limit.

## Past it: the streaming core, and `LIMITS-EXCEEDED`

A larger file, or a larger member, goes through the streaming core instead. It
reads fixed-size buffers in one forward pass and runs:

- an Aho-Corasick automaton over the literal `.ndb` signatures (fixed bytes, any
  file type, any offset), carrying state across buffer boundaries;
- MD5, SHA1 and SHA256 over the whole input, for `.hdb`/`.hsb`.

Its memory does not grow with the input. But it covers only those two kinds of
signature, so a file scanned this way is reported `LIMITS-EXCEEDED` unless one of
them matches. Raise `--max-object-bytes` to give larger files the full engine, at
the cost of memory. A full engine that streams is on the
[roadmap](/project/roadmap/#a-streaming-full-engine).

## Stdin, `INSTREAM` and ICAP bodies

Container formats need to seek (a ZIP's directory is at its end), so a stream is
buffered before it is scanned: in memory up to `--spill-threshold-bytes`
(16 MiB), then in a temporary file up to `--max-spill-bytes` (2 GiB). The
buffered stream then goes through the same scan as a file. A stream past
`--max-input-bytes` or the spill ceiling is scanned as far as it was held and is
`LIMITS-EXCEEDED` unless that finds something, as a file past
`--max-input-bytes` is. See
[buffering a stream](/reference/cli/#buffering-a-stream-spill).

## Where the memory really goes: the database

Loading raw ClamAV databases builds a double-array Aho-Corasick automaton, and
for the full `main` + `daily` set that construction needs several GB for a short
time, far more than the structures it produces. It is one allocation burst, so it
cannot be reduced by freeing things between steps.

The [prebuilt database](/guides/prebuilt-database/) avoids it: build the
automaton once on a capable host, serialize it to a `.exavdb`, and load that
everywhere else. Loading allocates about the final size and skips the
construction.

## Tuning

Memory and CPU budgets are separate flags:

- **`--max-object-bytes`** (256M): the most memory one object may use (a file, a
  decompressed member, an LZ window, a decrypted blob), and the largest file the
  full engine scans. Several such buffers are alive at once across nesting
  levels, so it does not bound the total.
- **`--max-extracted-bytes`** (1G): what decompression may produce across one
  top-level file, charged cumulatively. Under the daemon it is clamped to fit the
  per-job address space, so reaching it is reported as a limit instead of the
  worker being killed.
- **`--max-matcher-bytes`** (10G): the most bytes fed to the matcher across one
  top-level file. A CPU bound, not a memory one.
- **`--max-pe-emulation-steps`** (1,000,000,000): the instructions the PE
  unpacking emulator may run across one top-level file.

See [Limits](/reference/limits/) and [Configuration](/reference/configuration/)
for the full set.
