---
title: Streaming & memory
description: Where exav holds a file in memory, where it streams, what each path matches, and why the database, not the file, is what uses memory.
---

Every file gets the same scan whatever its size, except the few checks that
parse it whole (below):

- every `.ndb` form: wildcards, gaps, anchored offsets, file-type targets;
- `.ldb` logical signatures, with their regexes and byte comparisons;
- the normalised views of HTML, text and scripts that those signatures are
  written against;
- YARA rules, bytecode programs, PE section hashes, whole-file hashes;
- structural analysis: unpacking, embedded files, heuristics.

What changes with size is where the file is while that runs.

## Up to `--max-object-bytes`: in memory

A file up to `--max-object-bytes` (256 MiB by default) is read into memory.
Memory is roughly the file's size, plus a lowercase copy for case-insensitive
signatures and, for text, one normalised copy at a time. The deobfuscated
JavaScript view stops at 32 MiB; a script whose view is longer is reported
`LIMITS-EXCEEDED` unless something is found, though its raw bytes are still
scanned in full.

## Past it: through a block cache

A larger file is read through a cache of 64 KiB blocks, of which at most 8 MiB
are held, least recently used dropped first. So are an HTTP range source and a
spill file (below). Verifying a match can still look anywhere in the file: the
cache bounds what is held at once, not how far a check may reach, and a block
that was dropped is read again when it is needed. The scan is the same one, with
the same results, only slower, since the file is read a few times over: once for
what format detection searches it for, what carving looks for and its digests
(when a hash signature has its size), once for the signature sweep (every
automaton at once), and again in the parts a check needs.
[Architecture](/concepts/architecture/#reading-an-object-not-held-in-memory)
shows what reads through the cache.

A few things parse a file whole and are not done past the limit:

- the structure of a PE: entry-point and section offsets, section hashes,
  imports, icons, the Authenticode signature, UPX and packer unpacking;
- YARA's `pe`, `elf` and `dotnet` modules;
- containers whose format is read whole (7z, RAR, OLE, PDF, the virtual-disk and
  filesystem images and others; see
  [Supported formats](/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)).

A file for which one of these applied is reported `LIMITS-EXCEEDED`, naming
`--max-object-bytes`, unless something is found. Raise the limit to have them
run, at the cost of memory.

The normalised views of a large text file are as large as the file, so they are
written to the same temporary files as a buffered stream (below), under the same
budgets. With `--spill-dir off` they are skipped and the file is
`LIMITS-EXCEEDED`.

## Archive members

Archives decoded as they are read (ZIP, tar, CAB, ISO/UDF, DMG, LHA, `ar`, cpio,
the single-stream compressors, self-extracting executables) are walked member by
member at any size and any depth. Such a member is held in memory up to the same
limit, and past it written to a temporary file and scanned from there. With
`--spill-dir off`, or past `--max-spill-bytes`, it is not scanned and the file is
`LIMITS-EXCEEDED`. 7z members stream the same way once the container is read.

A member that has to be decoded whole (an encrypted ZIP member, a member of a
format read whole) is `LIMITS-EXCEEDED` past `--max-object-bytes`.

## Stdin, `INSTREAM` and ICAP bodies

Container formats need to seek (a ZIP's directory is at its end), so a stream is
buffered before it is scanned: in memory up to `--spill-threshold-bytes`
(16 MiB), then in a temporary file up to `--max-spill-bytes` (2 GiB). The
buffered stream then goes through the same scan as a file. A stream past
`--max-input-bytes` or the spill ceiling is scanned as far as it was held and is
`LIMITS-EXCEEDED` unless that finds something, as a file past
`--max-input-bytes` is. See
[buffering a stream](/reference/cli/#buffering-a-stream-spill).

## The database, not the file, is what uses memory

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
  decompressed member, an LZ window, a decrypted blob); past it an object is read
  through the block cache or a temporary file. Several such buffers are alive at
  once across nesting levels, so it does not bound the total.
- **`--max-process-bytes`** (2G per worker in the pool): the memory a scan may
  use. What formats decoded whole hold across one top-level file is charged
  cumulatively against 1G, lowered to half of `--max-process-bytes`, so reaching
  it is reported as a limit instead of the scan being killed. Streamed members
  are not charged there: they are bounded by `--max-object-bytes` and the spill
  budgets.
- **`--max-matcher-bytes`** (10G): the most bytes fed to the matcher across one
  top-level file. A CPU bound, not a memory one.
- **`--max-pe-emulation-steps`** (1,000,000,000): the instructions the PE
  unpacking emulator may run across one top-level file.

See [Limits](/reference/limits/) and [Configuration](/reference/configuration/)
for the full set.
