# Architecture

How the crates fit together, where each file format is read, and the rule that
keeps one format from being parsed twice. The format list itself is
`formats/registry.json`, from which the format matrix of the documentation is
generated.

## Crates

| Crate | Role | Depends on |
|---|---|---|
| `exav-unpack` | Opens containers within bounds: detects a format, walks the members of an archive, a disk image or a document, and holds the readers of the file formats (see below). Memory-safe, no C. | none of the others |
| `exav-render` | Turns a file into something to draw: images into pixels, drawings and models into geometry, office documents into XLSX, PPTX and DOCX. Also the text a reader sees, for the scanner. | `exav-unpack` |
| `exav-imagehash` | Perceptual hashes of the pixels `exav-render` decodes, equal to ClamAV's. | `exav-render` |
| `exav-core` | The scanner: signature databases, pattern and hash matching, YARA, the bytecode interpreter, the scan of every object that comes out of `exav-unpack`. | `exav-unpack`; optionally `exav-render` (text views) |
| `exav` | The CLI and the clamd and ICAP daemon around `exav-core`. | `exav-core` |
| `exav-grep` | Search inside archives. | `exav-unpack`; optionally `exav-render` |
| `exav-update` | Fetches signature databases. Kept apart so that the scanner links no TLS. | none |
| `exav-pe-emu`, `exav-x86` | Emulator and decoder for runtime-packed PE files. | none |
| `exav-unpack-wasm` | `exav-unpack` for the browser. | `exav-unpack` |
| `exav-viewer` | The WebAssembly modules of `@exav/viewer` (images, drawings, models, office conversion), built from `exav-render`, and the TypeScript viewer around them. | `exav-render` |

The arrow only points one way: the readers are at the bottom, and what draws
or scans sits above them.

## The rule: one reader per format

A format is read by one piece of code, whatever asks. Two readers of the same
bytes can disagree, and a scanner that sees one thing where the viewer shows
another is an evasion. So:

- A **reader** is a module of `exav-unpack` that turns bytes into the format's
  own structures and nothing else: none of the scan's state (its `Budget`, its
  member count, its depth), no model of a document. The limits it needs come in
  as arguments (a stream is read with a cap), it never reads past its input,
  and it never allocates by a count the file declares. It is public, so that
  `exav-render` uses it.
- The **scanner's adapter** sits on the reader in `exav-unpack`: it walks the
  structures, charges the scan's budget, names the members, and reports what it
  could not read.
- The **converter's adapter** sits on the same reader in `exav-render`: it
  builds the model of a document and writes it as XLSX, PPTX or DOCX.

Readers that exist today:

| Module (`exav_unpack::`) | Format | Used by |
|---|---|---|
| `cfb` | OLE2 compound files (Word, Excel, PowerPoint 97 to 2003, Publisher, Visio, MSI, the package of an encrypted OOXML file) | the scanner (`ole`), every legacy converter |
| `biff` | BIFF, the records of Excel 2 to 2003: the record stream (CONTINUE joined), the workbook tables formulas need (sheets, names, external references) and the formula tokens, written as Excel writes them (`=EXEC("calc")`) | the scanner (Excel 4.0 macro sheets), the XLS converter |
| `charset` | Text in a Windows code page number | the BIFF reader, the office converters |
| `html` | HTML as tokens (html5gum), and a page's bytes as text in the encoding it names | the scanner's text view, the spreadsheet and text document converters |
| `offcrypto` | Excel workbooks with a password: RC4, RC4 CryptoAPI, XOR | the scanner, the XLS converter |
| `rtf` | The RTF tokenizer | the scanner (embedded objects), the RTF converter |
| `dxf`, `dwg` | AutoCAD drawings | the scanner (embedded payloads), the drawing model of `exav-render` |
| `text` | The text of HTML, the XML parts of office files and PDF | the scanner's text views, `exav-render`'s `text` |

The readers sit behind the same Cargo features as the formats, and
`exav-render` turns on the ones its converters need (`exav-unpack/ole`,
`html`, `offcrypto`, `rtf`), so a build of one converter links only those.

## How a file is read

**Scan.** `exav-core` hands a file to `exav_unpack::walk`, which names the
format and yields the members one at a time (decoded as they are read where the
format allows). Each member is scanned as an object of its own, and the
members of members the same way, within the budget of the scan. A document that
has a text view is scanned as its text too. A format that is recognised and not
opened is reported, never passed as clean.

**View.** The viewer sniffs the file in TypeScript (`ts/core/formats.ts`, kept
equal to the registry by a test), picks the plugin, and hands the bytes to the
WebAssembly module built from `exav-render` for that kind of file: pixels for
an image, geometry for a drawing, a DOCX, XLSX or PPTX for an office document.
The viewer draws those. Archives are listed through `exav-unpack-wasm`.

## Budgets

The scan counts members, bytes and depth in `exav_unpack::Budget`, plus
key derivations over the whole scan (`kdf`). The converters of `exav-render`
count the paragraphs, cells or shapes of a model and an estimate of the memory
it takes, each in its own `limits.rs`. The estimates follow the size of the
model's types, so that a limit a host sets is a limit on memory. The XML tree
(`common/xml.rs`) tells the memory it builds to the converter's budget as it
grows, and drawings are read within `cad::limits_within(memory)`, so a
document made of many tiny elements costs what its tree takes, not a multiple
of its bytes.

## Where the same format is still read twice

These are the duplications left; each is a reader to extract into
`exav-unpack` and have the other side use. They are in `docs/BACKLOG.md`.

| Format | Scanner side | Converter side |
|---|---|---|
| PowerPoint records | `ole.rs` (embedded storages) | `slides/ppt/records.rs` |
| Word FIB | `ole.rs` (the encryption flag) | `docs/doc/fib.rs` |
| ZIP packages | `formats/zip.rs` | `common/package.rs` (the `zip` crate, its own limits) |
| XML trees | `text/xml.rs` | `common/xml.rs` (one tree for the three converters) |
| Code pages | `formats/codepage.rs` (drawings, by AutoCAD's names) | `formats/charset.rs` (by number, with the tables) |

## Testing the readers

Each reader has unit tests with the vectors of the format's own specification
or of real files, and the test inputs of the other side are built with an
independent writer where one exists (the `cfb` crate writes compound files for
the tests of `exav_unpack::cfb`; `offcrypto::encrypt` is written from the
specification apart from the decryptor). Every defect found in a reader gets a
test that fails without the fix.
