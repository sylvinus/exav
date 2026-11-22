---
title: exav-qr
description: Print the payloads of the QR codes in images and in what holds them (archives, documents, PDFs), as a command and as the QR reader behind exav's --qr.
---

**The QR codes in a file, and in everything inside it.** `exav-qr` opens every
archive, document and disk image it is given, as [exav-grep](/subprojects/exav-grep/)
does, and prints the payload of each QR code in the images it finds. It is for
the question a text search cannot answer: where does the link behind this code
lead, and in which member of which file is it.

It is in each [release](/scanner/getting-started/installation/#prebuilt-binaries), as
`exav-qr-<tag>-<target>`, or:

```bash
cargo install exav-grep --features qr    # installs exav-grep and exav-qr
```

```bash
exav-qr scan.png                      # the codes of one image
exav-qr -r ./inbox/                   # a directory, archives and documents inside it too
exav-qr --max-qr-millis 1000 mail.zip
```

## Output

One payload to a line, after the nesting path of its image and the number of
the code among those read in it, the way `exav-grep` prints a match:

```text
$ exav-qr mail.zip
mail.zip!scan.png:1:https://evil.example/login
mail.zip!docs/invoice.pdf!pdf-obj-12-0:1:WIFI:T:WPA;S:guest;P:secret;;
```

The images it reads are the ones the viewer's decoders read (PNG, JPEG, GIF,
BMP, TIFF, WebP and the others), in a file, an archive or a document, and the
images of a PDF: JPEG, CCITT, JBIG2 (with its globals) and raw samples (1 to
16 bits, grey, RGB, CMYK or indexed colors, image masks).
A payload is text, with invalid UTF-8 replaced. The control characters in it
(a newline, an escape, a right-to-left override) are written as escapes, `\n`,
`\r`, `\t` and `\u{1b}`, and the backslash itself as `\\`, so that a code
cannot add a line or a terminal escape sequence to the output.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | a code was found |
| `1` | no code was found |
| `2` | a usage or I/O error |
| `3` | no code was found, but something could not be read |

`3` is the one a script has to handle. What could not be read is said on
stderr, one line each, and is never taken for "no code":

- an image that does not decode, or a PDF image whose dictionary or color
  space (Lab, Separation, DeviceN) is not read;
- an image that a limit stopped: past `--max-qr-pixels`, `--max-qr-millis`,
  `--max-qr-codes`, `--max-qr-finders`, `--max-qr-grids`, or past
  `--max-object-bytes`;
- a member that could not be opened (encrypted, damaged, past a budget).

When a code is found the exit code is `0` whatever else was left unread, and
stderr still says it.

## Flags

The names and the environment variables are those of [`exav`](/scanner/reference/cli/)
and [`exav-grep`](/subprojects/exav-grep/#flags). `off` or `0` sets no limit
unless said, and a flag wins over its variable.

| Flag | Purpose |
|---|---|
| `-r`, `--recursive` | Read the files of the directories named. Without it a directory is an error |
| `--max-object-bytes <SIZE\|off>` | The most held in memory at once for one file or member (default 256 MiB); K/M/G/T suffixes. An image over it is reported unread. Environment: `EXAV_MAX_OBJECT_BYTES` |
| `--max-extracted-bytes <SIZE\|off>` | The most bytes of members that a format decodes into memory itself (PDF streams, OLE streams, RTF objects and the like), summed over one file (default 1 GiB). The bytes a PDF is read again to follow its objects count too. A file that reaches it is reported unread. Environment: `EXAV_MAX_EXTRACTED_BYTES` |
| `--max-matcher-bytes <SIZE\|off>` | The most bytes read for one file named on the command line, its members summed (default 10 GiB): a CPU and time bound. A file that reaches it is reported unread. Environment: `EXAV_MAX_MATCHER_BYTES` |
| `--max-hole-bytes <SIZE\|off>` | The most bytes of holes of sparse files in a filesystem image read as zeros for one file named on the command line (default 10 GiB), counted apart from `--max-matcher-bytes`. Environment: `EXAV_MAX_HOLE_BYTES` |
| `--max-members <N\|off>` | Cap on members visited inside each input file (default 100000). Environment: `EXAV_MAX_MEMBERS` |
| `--max-compression-ratio <N\|off>` | A member past `--max-object-bytes` that decodes to more than N times its size (default 1000) is left out and reported unread. Environment: `EXAV_MAX_COMPRESSION_RATIO` |
| `--max-pe-emulation-steps <N\|off>` | Most x86 instructions the emulator that unpacks packed executables may run for one file named on the command line (default 1000000000). Environment: `EXAV_MAX_PE_EMULATION_STEPS` |
| `--max-pe-stub-steps <N\|off>` | Most x86 instructions that emulator may run for one packed executable (default 500000000). Environment: `EXAV_MAX_PE_STUB_STEPS` |
| `--max-pe-idle-steps <N\|off>` | Most instructions a packed executable's stub may run in that emulator without writing a page it has not written before (default 64000000). Environment: `EXAV_MAX_PE_IDLE_STEPS` |
| `--max-unpack-depth <N>` | Cap on archive-within-archive nesting; `0` opens no archive, and each file is read as it stands. There is no `off`. Environment: `EXAV_MAX_UNPACK_DEPTH` |
| `--spill-dir <DIR\|off>` | Where a container inside a member over `--max-object-bytes` is written to be opened (default: the system temporary directory); `off` writes nothing. Environment: `EXAV_SPILL_DIR` |
| `--max-total-spill-bytes <SIZE\|off>` | The most the spill files open at once may hold (default 2 GiB). Environment: `EXAV_MAX_TOTAL_SPILL_BYTES` |
| `--object-cache-bytes <SIZE\|off>` | Memory of the block cache of an object read where it lies (default 32 MiB); never below two blocks. Environment: `EXAV_OBJECT_CACHE_BYTES` |
| `--object-cache-block-bytes <SIZE\|off>` | One block of that cache (default 1 MiB). Environment: `EXAV_OBJECT_CACHE_BLOCK_BYTES` |
| `--max-qr-pixels <N\|off>` | Pixels an image may have (default 50000000). Environment: `EXAV_MAX_QR_PIXELS` |
| `--max-qr-millis <MS\|off>` | Milliseconds the reading of one image may take (default 5000). Environment: `EXAV_MAX_QR_MILLIS` |
| `--max-qr-codes <N\|off>` | QR codes read in one image (default 64). Environment: `EXAV_MAX_QR_CODES` |
| `--max-qr-finders <N\|off>` | Finder patterns (the square a code has in three corners) found in one image (default 1000). Environment: `EXAV_MAX_QR_FINDERS` |
| `--max-qr-grids <N\|off>` | Groups of three finder patterns tried as a code in one image (default 256). Environment: `EXAV_MAX_QR_GRIDS` |

The memory of a search is counted against `--max-object-bytes` too (and never
more than the decoders' own ceiling). A reading that a limit stops prints the
codes found before it and says why on stderr.

## In exav and exav-grep

`exav --qr` matches the payloads as text and judges the links in them with
`--detect phishing`; `exav-grep --qr PATTERN` searches them, under
`image.png!qr`. All three commands read codes the same way, through one
function, with the same limits.

## As a library

Two crates, both `#![forbid(unsafe_code)]`:

- **exav-qr** is [rqrr](https://github.com/WanzenBug/rqrr) 0.11.0, a port of
  [quirc](https://github.com/dlbeer/quirc), vendored, with no dependency. Its
  search stops at a deadline, at a memory budget and at caps on finder
  patterns and candidate grids, by counting its steps in its own loops, so it
  never unwinds for a limit and builds with `panic = "abort"`. The pixels come
  from a function: `PreparedImage::prepare_from_greyscale`, or
  `prepare_from_greyscale_within` for a search under a `SearchLimits`.
  `PreparedImage::detect` returns the grids found and, in `Detection::stop`,
  the `Stop` that ended the search early.
- **exav-render** (feature `qr`) reads the image: `exav_render::qr::wants`
  says from the first 64 bytes whether `search` reads a file, and
  `exav_render::qr::search(data, raster, &Settings)` decodes it, with the
  limits of the table above as `Settings`, and returns the payloads and, when
  a limit stopped the reading, why. This is the one entry point the three
  commands share.

```rust
use exav_render::qr::{Settings, search};

let settings = Settings {
    max_pixels: Some(50_000_000),
    max_millis: Some(5_000),
    max_codes: Some(64),
    max_finders: Some(1_000),
    max_grids: Some(256),
    max_buffer_bytes: 256 << 20,
};
if let Some(found) = search(&std::fs::read("scan.png")?, None, &settings) {
    for payload in &found.payloads {
        println!("{payload}");
    }
    if let Some(why) = &found.cut {
        eprintln!("not all read: {why}");
    }
}
```

`None` is returned for data that is not an image the build decodes, or that
does not decode: a caller that must not take that for "no code", as `exav-qr`
does not, checks `wants` first.

To walk containers the way `exav-qr` does, use [exav-grep](/subprojects/exav-grep/#as-a-library):
`Searcher::qr_codes(options)` is the same walk with each payload an
`Event::Qr`.
