---
title: exav-grep
description: grep for the inside of archives — search recursively through zip, rar, 7z, tar, iso, OLE, PDF and email members, including nested ones.
---

**grep, but it looks inside archives.** Same flags you already know, except the
haystack includes every member of every container, recursively.

```bash
cargo install exav-grep
```

```bash
exav-grep -r "AKIA[0-9A-Z]{16}" ./backups/     # leaked keys inside tarballs
exav-grep -F "password" release.zip            # nested archives too
exav-grep -l "ProcessBuilder" suspicious.jar   # which member, not just which file
```

Matches are reported with the full path *through* the containers, so you know
which member matched:

```text
backups/2026-01.tar.gz!db/dump.sql:412:AKIAIOSFODNN7EXAMPLE
suspicious.jar!kingDavid/00.class/!java-class-strings:65:java/lang/ProcessBuilder
```

## Why not `zgrep` and a for-loop

Because the loop stops at the first layer, and because unreadable members
disappear silently. `exav-grep` recurses through archives inside archives, and
**reports members it could not read** rather than letting them look like
non-matches:

> `--quiet-unreadable` — Don't report members that could not be read. Off by
> default, because hiding them turns "I couldn't look" into an indistinguishable
> "no match".

That default is why the tool exists. A grep that silently skips an encrypted or
corrupt member gives you a clean result that means nothing.

## Flags

The familiar set — `-i`, `-v`, `-c`, `-l`, `-r`, `-F`, `-A`/`-B`/`-C`,
`-m` — plus the ones extraction needs:

| Flag | Purpose |
|---|---|
| `--passwords <PASSWORD>` | Try on encrypted members (repeatable) |
| `--max-object-bytes <BYTES>` | Cap on what any single member may decompress to |
| `--max-members <N>` | Cap on members visited inside each input file |
| `--max-depth <N>` | Cap on archive-within-archive nesting |
| `--quiet-unreadable` | Suppress unreadable-member reports (see above) |

The limits are the same decompression-bomb budget the scanner uses, so pointing
this at a hostile archive is safe by construction rather than by luck, and they
are spelled the way [`exav`](/reference/cli/#scan-limits) spells them.

## What it searches

Everything [exav-unpack](/subprojects/exav-unpack/) opens — zip, rar, 7z, tar,
gzip/xz/bzip2/zstd, iso, cab, OLE2 documents, PDF, MIME email, disk images, and
the filesystems inside them. Derived views are searched too, so a Java class is
searchable as its string constants rather than as opaque bytecode.
