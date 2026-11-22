---
title: Roadmap
description: What's next for exav, from signature-matching performance and one read pass for large files to broader bytecode coverage, streaming the containers still read whole, volume sets inside archives, the viewer's Office converters, document text search and less dependency unsafe.
---

exav is beta and `0.0.x`: any release may change behaviour or APIs. What has
already changed is in the
[CHANGELOG](https://github.com/sylvinus/exav/blob/main/CHANGELOG.md). The current
focus is the known gaps below, none of which lets an incomplete scan pass as
clean.

An input for which exav reports `OK` while ClamAV detects malware is a bug, not
a roadmap item: please [open an issue](https://github.com/sylvinus/exav/issues)
(see [silent false negatives](/scanner/reference/comparison-with-clamav/#silent-false-negatives)).
The exceptions are the documented detection gaps: unimplemented
[`Target:` values](/scanner/reference/comparison-with-clamav/#targets) and ClamAV's
[per-family heuristics](/scanner/reference/comparison-with-clamav/#heuristic-alerts).

## Now → next

- **Signature-matching performance** on large inputs against the full database.
  Wildcard verification is already non-backtracking (see
  [Performance](/scanner/reference/comparison-with-clamav/#performance)), so what remains
  is the raw throughput of the anchor search and of the bytecode interpreter.
- **Broader bytecode coverage.** Trigger-gated execution is
  [live](/scanner/concepts/bytecode-sandbox/) and every program in a live `bytecode.cvd`
  runs to completion, but many of ClamAV's host APIs are still stubs returning
  fail-safe values. The groups a real program could need (buffer pipes, maps,
  `inflate`) come first, with differential validation against `clamscan`.
- **Extended and continuous fuzzing**, and a large no-silent-skip CI suite.

## Large files: fewer passes, PE structure, HTTP

A file larger than `--max-object-bytes` gets the full engine, read through a
block cache (see [Streaming & memory](/scanner/concepts/streaming-memory/)). Two things
remain:

- **One forward pass.** Format detection, carving, the digests, the signature
  sweep and YARA are fed from one read. Left: the walk that looks for what
  follows an unbounded gap, a YARA regexp whose first atom comes late re-reading
  what lies before it, and a PE's image read twice.
- **Packed PEs past the limit.** A PE's structure is read from its image, so a
  small executable with a large overlay gets the full PE checks. A PE whose
  image is over the limit, ELF and Mach-O executables, and the readers that
  hold a packed PE whole (NSIS, AutoIt, UPX, PE packers) are still
  `LIMITS-EXCEEDED`.

## Streaming the containers read whole

Most containers, disk images, filesystems, RAR, OLE and email included, are
walked member by member off the source, so peak memory is one member rather
than the whole decoded object (see [how extraction works](/unpack/how-it-works/)):
a stored member past `--max-object-bytes` is read where it lies, a compressed
one through a spill file. ARJ and a few others are still read whole (see
[Supported formats](/scanner/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)):
past `--max-object-bytes` their own bytes get the full scan but their members are
not extracted, and the file is `LIMITS-EXCEEDED` unless something is found.
Streaming them needs their readers rewritten. PDF holds only the file plus one
bounded object, so streaming it would save little memory; raising
`--max-object-bytes` covers larger PDFs.

## Later

- A trained static model (the current static scorer is a hand-weighted
  heuristic, not a trained classifier).
- Broader fuzzy/similarity matching.
- Widening what the PE stub emulator can follow. Together with the static
  decoders, the [x86 interpreter](/scanner/concepts/pe-emulation/) already unpacks most
  packers in the measured corpus, but a stub
  can still outrun it: an instruction outside the implemented set, a Windows
  export with no implementation, an anti-emulation trick. Each is reported and
  counted, so the list of what to add is measured.
- Verifying Authenticode signatures cryptographically. Parsing, digest checks
  and `.crb` matching exist today.
- **Volume sets met inside a container.** RAR, ZIP and CAB volume sets are
  joined when their volumes sit next to each other on disk, or arrive together
  at the daemon (see [split archives](/scanner/guides/daemon/#split-archives)),
  but not when the volumes are members of another archive: each is then scanned
  on its own and the member continued in another volume is reported.
- The unimplemented `Target:` values (internal, other, and ClamAV's reserved
  slot 8), `EP` on Mach-O files (clamscan does not resolve it either), and the
  unloaded database extensions (`.cat`, `.ioc`, and the legacy
  `.sdb`/`.zmd`/`.rmd`).
  None appears in a stock official database; all matter for third-party feeds.
  See [Targets](/scanner/reference/comparison-with-clamav/#targets).

## Maybe

- QEMU/KVM dynamic detonation: a separate, heavyweight feature, only if there is
  demand.

## Documents, search and the viewer

The viewer opens JPEG XL (a fork of the libjxl team's jxl-rs, `forbid(unsafe_code)`
and built without SIMD), camera RAW previews, and converts the old Office
formats in the browser. What is not done:

- **The text-document converter is a prototype.** On the project's test files,
  32% of the pages of DOC files come out close to a reference rendering,
  against 50% for DOCX drawn natively. What it reports unsupported (Pages '09,
  Word 1 and 2) goes on to the external converter where one is set. Open
  decisions: making it the default even where an external converter is set,
  keeping tracked changes in DOC, and Pages tables, pictures and headers.
- **Presentations.** PowerPoint 2, 3 and 4 are recognised and reported
  unsupported. PowerPoint 95 pictures, freeforms and arcs are left out. The
  first slide could be drawn while the rest converts. Binary Visio, CorelDRAW,
  Publisher and the other page layout formats are read only by an
  [external converter](/viewer/integration/#the-external-converter).
- **Searching documents.** `exav-grep --text` and the scanner's text view read
  Markdown, HTML, the XML parts of Office and OpenDocument files with their
  hyperlinks, an email's headers, IFC names and property values, DXF and DWG
  (a DWG's hyperlinks too), and, behind opt-in features, PDF and the legacy and flat office formats; QR
  codes in images are read behind an opt-in feature. Still to do: the labels
  of PDF links, the speaker notes of PPT and FODP files, and matches located
  by page and by drawing entity. PDF text and the office readers are not
  defaults because of hayro's `unsafe` and the size of the readers. OCR for
  images and scanned pages is proposed.
- **Drawings and models.** DWG before R13 is reported unsupported. Large
  drawings have no level of detail, annotative objects and linked images are
  not resolved (external references are, from the files around the drawing),
  and 3D is out of scope. IFC geometry has
  [known gaps](/subprojects/exav-render/#ifc-and-stl-models). glTF with Draco
  or meshopt, and PLY point clouds, are not drawn.
- **Camera RAW.** The sensor data is never decoded, so a file with no preview
  (most phones' DNG, Minolta MRW, CR3 whose preview is HEIF) shows an error.
- **Other viewer gaps.** Replacing a document in a sandboxed frame starts the
  zoom and position over. Archives left out on purpose: email, OLE
  containers, OpenDocument and EPUB, packers and installers. Text previews
  have no line numbers, tree view or search. The browser's own JPEG XL decoder
  could spare the module's size where it exists.

## Hardening: less dependency `unsafe`

exav's own scanning, extraction and emulation crates are
`#![forbid(unsafe_code)]`, and the default build runs no C, no UnRAR and no
native JIT. The remaining `unsafe` is in dependencies: SIMD, syscalls, and buffer
handling in some decoders that read scanned bytes (see
[Dependencies](/project/dependencies/) for counts per crate). Reducing it is an
ongoing goal:

- **Audit** each dependency's `unsafe` by reachability from a hostile-input scan
  path (the per-crate counts are done).
- **Drop** dependencies exav does not need (done for `tar`'s `xattr`, which was
  the largest source of syscall `unsafe`, for `half` and `zerocopy`, and for
  zstd's checksum, `twox-hash`).
- **Make safe** what can be: portable builds without SIMD where the speed cost is
  acceptable, and vendoring then removing `unsafe` (the RAR PPMd, LZFSE and
  InstallShield Z decoders have none).
- **Reuse exav's own safe code** where it duplicates an `unsafe` dependency.
- **Verify** the rest with `cargo-fuzz` and Miri (`make miri`), and document the
  containment (panic isolation, the prefork process boundary, the WASM build).

