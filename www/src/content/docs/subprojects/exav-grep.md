---
title: exav-grep
description: grep for the inside of archives, searching recursively through zip, rar, 7z, tar, iso, OLE, PDF and email members, including nested ones.
---

**grep, but it looks inside archives.** The flags you already know, with every
member of every container, recursively, as the haystack.

```bash
cargo install exav-grep
```

```bash
exav-grep -r "AKIA[0-9A-Z]{16}" ./backups/     # leaked keys inside tarballs
exav-grep -F "password" release.zip            # nested archives too
exav-grep -l "ProcessBuilder" suspicious.jar   # which member, not just which file
```

Matches are reported with the full path through the containers:

```text
backups/2026-01.tar.gz!db/dump.sql:412:AKIAIOSFODNN7EXAMPLE
suspicious.jar!kingDavid/00.class/!java-class-strings:65:java/lang/ProcessBuilder
```

## Why not `zgrep` and a loop

The loop stops at the first layer, and unreadable members disappear. `exav-grep`
recurses through archives inside archives and reports members it could not read,
so an encrypted or corrupt member does not look like a non-match. `--quiet-unreadable`
turns those reports off.

## Flags

The familiar set (`-i`, `-v`, `-c`, `-l`, `-r`, `-F`, `-A`/`-B`/`-C`, `-m`), plus
the ones extraction needs:

| Flag | Purpose |
|---|---|
| `--passwords <PASSWORD>` | Try on encrypted members (repeatable) |
| `--max-object-bytes <BYTES>` | Cap on what any single member may decompress to |
| `--max-members <N>` | Cap on members visited inside each input file |
| `--max-unpack-depth <N>` | Cap on archive-within-archive nesting |
| `--quiet-unreadable` | Suppress unreadable-member reports |

The limits are the scanner's decompression-bomb budget, spelled as
[`exav`](/reference/cli/#scan-limits) spells them, so pointing it at a hostile
archive is safe.

## What it searches

Everything [exav-unpack](/subprojects/exav-unpack/) opens: zip, rar, 7z, tar,
gzip/xz/bzip2/zstd, iso, cab, OLE2 documents, PDF, MIME email, disk images and the
filesystems inside them. Derived views are searched too, so a Java class is
searchable as its string constants rather than as opaque bytecode.
