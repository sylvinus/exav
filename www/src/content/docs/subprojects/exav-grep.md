---
title: exav-grep
description: grep for the inside of archives, searching recursively through zip, rar, 7z, tar, iso, OLE, PDF and email members, including nested ones.
---

**grep, but it looks inside archives.** The flags you already know, with every
member of every container, recursively, as the haystack.

It is in each [release](/getting-started/installation/#prebuilt-binaries), as
`exav-grep-<tag>-<target>`, or:

```bash
cargo install exav-grep
```

```bash
exav-grep -r "AKIA[0-9A-Z]{16}" ./backups/     # leaked keys inside tarballs
exav-grep -F "password" release.zip            # nested archives too
exav-grep -l "ProcessBuilder" suspicious.jar   # which member, as well as which file
```

Matches are reported with the full path through the containers. A compressed
stream (the gzip around a tar) is a layer of its own, named for its content:

```text
backups/2026-01.tar.gz!gzip-content!db/dump.sql:412:AKIAIOSFODNN7EXAMPLE
suspicious.jar!kingDavid/00.class/!java-class-strings:65:java/lang/ProcessBuilder
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | matches found |
| `1` | no matches |
| `2` | a usage or I/O error |
| `3` | no matches, but some members could not be read: the search was incomplete |

`3` is the one a script looking for secrets or indicators has to handle: a clean
result and an incomplete one are different answers.

## As a library

```bash
cargo add exav-grep
```

```rust
use exav_grep::{Matcher, Options, Searcher};

let matcher = Matcher::fixed("password", false)?;
let mut searcher = Searcher::new(matcher, Options::default());
// The sink returns `true` to keep going, `false` to stop the search.
searcher.search_path(std::path::Path::new("backup.zip"), &mut |ev| {
    println!("{ev}");
    true
})?;
```

## Why not `zgrep` and a loop

The loop stops at the first layer, and unreadable members disappear. `exav-grep`
recurses through archives inside archives and reports members it could not read,
so an encrypted or corrupt member does not look like a non-match. `--quiet-unreadable`
turns those reports off.

## Flags

The familiar set (`-i`, `-v`, `-l`, `-r`, `-F`, `-A`/`-B`/`-C`), counted per
member rather than per file: `-m N` stops after N matches in each member, and
`-c` prints one total, the number of matching members. Plus the ones extraction
needs:

| Flag | Purpose |
|---|---|
| `--passwords <PASSWORD>` | Try on encrypted members (repeatable), before the [built-in passwords](/reference/formats/#encryption-support) |
| `--max-object-bytes <BYTES>` | Cap on what any single member may decompress to, and on the size of an input file (default 256 MiB) |
| `--max-members <N>` | Cap on members visited inside each input file |
| `--max-unpack-depth <N>` | Cap on archive-within-archive nesting |
| `--quiet-unreadable` | Suppress unreadable-member reports |

The limits are the scanner's decompression-bomb budget, spelled as
[`exav`](/reference/cli/#scan-limits) spells them, so pointing it at a hostile
archive is safe. Each input file is read whole into memory, so one larger than
`--max-object-bytes` is reported unreadable (exit `3`) rather than read; raise
the flag to search it.

## What it searches

Everything [exav-unpack](/subprojects/exav-unpack/) opens: zip, rar, 7z, tar,
gzip/xz/bzip2/zstd, iso, cab, OLE2 documents, PDF, MIME email, disk images and the
filesystems inside them. Derived views are searched too, so a Java class is
searchable as its string constants rather than as opaque bytecode.
