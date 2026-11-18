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

`--profile fast-build` is a shorter build that needs less memory, for a larger
and slower binary (see [Installation](/scanner/getting-started/installation/#from-cratesio)).

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
| `--max-object-bytes <SIZE\|off>` | The most held in memory at once for one file or member (default 256 MiB); K/M/G/T suffixes, `off` or `0` sets no limit; see [Memory](#memory). Environment: `EXAV_MAX_OBJECT_BYTES` |
| `--max-extracted-bytes <SIZE\|off>` | The most bytes of members that a format decodes into memory itself (PDF streams, OLE streams, RTF objects and the like), summed over one file (default 1 GiB); K/M/G/T suffixes, `off` or `0` sets no limit. The bytes a PDF is read again to follow its objects count too. A file that reaches it is reported unreadable. Environment: `EXAV_MAX_EXTRACTED_BYTES` |
| `--object-cache-bytes <SIZE\|off>` | Memory of the block cache of an object that is read where it lies (default 32 MiB, one cache per such object being searched, nested ones included); never below two blocks, `off` or `0` is that least. Environment: `EXAV_OBJECT_CACHE_BYTES` |
| `--object-cache-block-bytes <SIZE\|off>` | One block of that cache (default 1 MiB); `off` or `0` is a byte. Environment: `EXAV_OBJECT_CACHE_BLOCK_BYTES` |
| `--max-members <N\|off>` | Cap on members visited inside each input file; `off` or `0` sets no limit. Environment: `EXAV_MAX_MEMBERS` |
| `--max-compression-ratio <N\|off>` | A member that decodes to more than N times its size in its container (default 1000), once it is past `--max-object-bytes`, is left out and reported unreadable; the other members are still searched. Below `--max-object-bytes` a member is held in memory, so with `--max-object-bytes off` the ratio never acts. `off` or `0` sets no limit. Environment: `EXAV_MAX_COMPRESSION_RATIO` |
| `--max-unpack-depth <N>` | Cap on archive-within-archive nesting; `0` opens no archive, and each file is searched as it stands. There is no `off`. Environment: `EXAV_MAX_UNPACK_DEPTH` |
| `--spill-dir <DIR\|off>` | Where a container inside a member over `--max-object-bytes` is written to be opened (default: the system temporary directory); `off` writes nothing. See [Memory](#memory). Environment: `EXAV_SPILL_DIR` |
| `--max-total-spill-bytes <SIZE\|off>` | The most the spill files open at once may hold (default 2 GiB); K/M/G/T suffixes, `off` or `0` sets no ceiling. Environment: `EXAV_MAX_TOTAL_SPILL_BYTES` |
| `--quiet-unreadable` | Suppress unreadable-member reports |
| `--text` | Search the text a reader sees rather than the bytes, for the files that have one ([below](#searching-the-text)). Needs the `text` feature, which is a default. A text cut at its size limit is reported unreadable (exit `3`) |
| `--qr` | Search the payloads of the QR codes in images as well as their bytes ([below](#qr-codes)). Needs the `qr` feature, which is not a default |
| `--max-qr-pixels <N\|off>` | Pixels an image may have for `--qr` to read it (default 50000000); a larger one is reported unreadable. Environment: `EXAV_MAX_QR_PIXELS` |
| `--max-qr-millis <MS\|off>` | Milliseconds `--qr` may spend on one image (default 5000); one cut short is reported unreadable. Environment: `EXAV_MAX_QR_MILLIS` |
| `--max-qr-codes <N\|off>` | QR codes `--qr` may read in one image (default 64); an image with more is reported unreadable. Environment: `EXAV_MAX_QR_CODES` |
| `--max-qr-finders <N\|off>` | Finder patterns `--qr` may find in one image (default 1000); an image with more is reported unreadable. Environment: `EXAV_MAX_QR_FINDERS` |
| `--max-qr-grids <N\|off>` | Groups of three finder patterns `--qr` may try as a QR code in one image (default 256); an image with more is reported unreadable. Environment: `EXAV_MAX_QR_GRIDS` |

The limits are the scanner's decompression-bomb budget, spelled as
[`exav`](/scanner/reference/cli/#scan-limits) spells them, so pointing it at a hostile
archive is safe.

## Memory

`--max-object-bytes` is what may be held at once for one file or member. A file
or member up to it is held, so that a container inside it can be opened. A
larger file is read where it lies, through a block cache (`--object-cache-bytes`,
`--object-cache-block-bytes`): a container in it is walked from there, anything
else is searched a megabyte at a time, a line at a time. A member of a ZIP that
is stored, not compressed, is read where it lies in the same way, whatever its
size. A larger member that is decoded as it is read is searched as it comes. A
container inside such a member cannot be opened without seeking in it, so it is
written to an anonymous temporary file in `--spill-dir`, opened from there, and
the file is deleted when its search ends; the spill files open at once hold at
most `--max-total-spill-bytes`. With `--spill-dir off`, or past that budget, the
container is reported unreadable (exit `3`), never skipped quietly, and so is a
line longer than the limit. A format the extractor [reads
whole](/unpack/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)
is reported unreadable past the limit, as it is by the scanner.

A member that is decoded as it is read is held whole, whatever
`--max-object-bytes` is, when it ends or fails within 4 MiB + 1 KiB: the start
that is read to tell what it is. A limit under that does not make it smaller.

A decoded member over `--max-object-bytes` is searched as it is read, before
it is known whether its end makes it a container (a disk image whose footer is
at its end, a ZIP with a prefix) or whether it is a packed executable. It is
searched as it comes either way, and it is reported unreadable with that reason
(exit `3` when nothing matches).

## Searching the text

`--text` searches the words a reader sees instead of the bytes of the file,
for the kinds of file that have some, in an archive too:

- Markdown, HTML, the XML parts of Office and OpenDocument files (speaker
  notes included), the hyperlinks of a DOCX, PPTX or XLSX with the targets
  their `.rels` parts give, an email's headers (RFC 2047 words decoded), the
  targets of a PDF's links, IFC models (names, descriptions and property
  values) and DXF and DWG drawings, in the default build;
- PDF, with the `text-pdf` feature, which is not a default;
- the legacy and flat office formats, with the `text-office` feature, which is
  not a default either.

[The scanner's page](/scanner/reference/formats/#the-text-a-reader-sees) lists
the formats of each.

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
extension, so that an installer is not read whole to find out.

A drawing past a limit, and a document of the `text-office` formats whose
text cannot be taken out (encrypted, past a limit, damaged), are reported
unreadable, with the reason, and their bytes are searched instead. A text cut
short is searched as far as it goes and reported unreadable too. With no
match the exit code is `3`, never `1`: finding nothing in a document it could
not read is not a clean answer.

```bash
cargo install exav-grep --features text-office
```

## QR codes

`--qr` reads the QR codes in every image the viewer's decoders read (PNG,
JPEG, GIF, BMP, TIFF, WebP and the others), in an archive or a document too,
and the images of a PDF (JPEG, raw samples, CCITT, JBIG2), and searches their
payloads, one to a line, under `image.png!qr`. The image's bytes are searched
as well. An image past `--max-qr-pixels`, whose reading takes longer than
`--max-qr-millis`, or that holds more than `--max-qr-codes` codes,
`--max-qr-finders` finder patterns or `--max-qr-grids` candidate grids, is
reported unreadable. An image that does not decode, or a PDF image in a color
space or with a predictor that is not read, is reported unreadable (exit `3`)
like one past a limit. For all five, `off` or `0` sets no limit. To print the
payloads rather than search them, use [exav-qr](/subprojects/exav-qr/).

```text
$ exav-grep --qr evil.example mail.zip
mail.zip!scan.png!qr:1:https://evil.example/login
```

```bash
cargo install exav-grep --features qr
```

## What it searches

Everything [exav-unpack](/unpack/) opens: zip, rar, 7z, tar,
gzip/xz/bzip2/zstd, iso, cab, OLE2 documents, PDF, MIME email, disk images and the
filesystems inside them. Derived views are searched too, so a Java class is
searchable as its string constants rather than as opaque bytecode.
