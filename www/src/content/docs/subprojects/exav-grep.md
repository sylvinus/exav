---
title: exav-grep
description: grep for the inside of archives, searching recursively through zip, rar, 7z, tar, iso, OLE, PDF and email members, including nested ones.
---

**grep, but it looks inside archives.** The flags you already know, with every
member of every container, recursively, as the haystack.

It is in each [release](/scanner/getting-started/installation/#prebuilt-binaries), as
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
| `--passwords <PASSWORD>` | Try on encrypted members (repeatable), before the [built-in passwords](/unpack/formats/#encryption-support) |
| `--max-object-bytes <BYTES>` | Cap on what any single member may decompress to, and on the size of an input file (default 256 MiB) |
| `--max-members <N>` | Cap on members visited inside each input file |
| `--max-unpack-depth <N>` | Cap on archive-within-archive nesting |
| `--quiet-unreadable` | Suppress unreadable-member reports |
| `--text` | Search the text a reader sees rather than the bytes, for the files that have one ([below](#searching-the-text)). Needs the `text` feature, which is a default. A text cut at its size limit is reported unreadable (exit `3`) |

The limits are the scanner's decompression-bomb budget, spelled as
[`exav`](/scanner/reference/cli/#scan-limits) spells them, so pointing it at a hostile
archive is safe. Each input file is read whole into memory, so one larger than
`--max-object-bytes` is reported unreadable (exit `3`) rather than read; raise
the flag to search it.

## Searching the text

`--text` searches the words a reader sees instead of the bytes of the file,
for the kinds of file that have some, in an archive too:

- Markdown (`.md`, `.markdown`), HTML, the XML parts of Word, PowerPoint,
  Excel and OpenDocument files, and DXF and DWG drawings, in the default
  build;
- PDF, with the `text-pdf` feature, which is not a default;
- with the `text-office` feature, which is not a default either, the legacy
  and flat office formats: DOC, XLS, PPT, RTF, Word 2003 XML, SpreadsheetML
  2003, SYLK, FODT, FODS, FODP, FODG, Numbers, Pages and Keynote.

Entities are decoded, and each link is followed by where it goes,
`label (target)`. Matches are reported under `file!text`, with the text's line
numbers. A workbook or a presentation is searched sheet by sheet and slide by
slide, and a match says which:

```text
$ exav-grep --text -F "Second sheet" book.xls
book.xls!text/sheet "Notes":2:Second sheet	1
$ exav-grep --text -F "Second slide" deck.ppt
deck.ppt!text/slide 2:2:Second slide text
$ exav-grep --text -F costs report.doc
report.doc!text:2:Revenue grew by twelve percent over the quarter, while costs stayed flat.
```

A document that is also a container (a PDF, a drawing) is walked for its
members as before. A compound file is read as an office document only by its
extension (`.doc`, `.dot`, `.xls`, `.xlt`, `.xlw`, `.ppt`, `.pps`, `.pot`), so
that an installer is not read whole to find out.

A document of those kinds whose text cannot be taken out (encrypted, past a
limit, damaged) is reported unreadable, with the reason, and its bytes are
searched instead. With no match the exit code is `3`, never `1`: finding
nothing in a document it could not read is not a clean answer.

```bash
cargo install exav-grep --features text-office
```

## What it searches

Everything [exav-unpack](/unpack/) opens: zip, rar, 7z, tar,
gzip/xz/bzip2/zstd, iso, cab, OLE2 documents, PDF, MIME email, disk images and the
filesystems inside them. Derived views are searched too, so a Java class is
searchable as its string constants rather than as opaque bytecode.
