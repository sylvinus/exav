# Fuzzing exav

Coverage-guided fuzzing is how we hold the line on exav's core promise: **the
scanner must never crash, hang, or corrupt memory on the files it scans** —
and those files are, by definition, hostile.

## Why fuzz a `#![forbid(unsafe_code)]` codebase?

`forbid(unsafe_code)` removes *undefined behaviour* (the memory-corruption class
— buffer overflows, use-after-free, type confusion that turn into RCE/info-leak).
It does **not** make the process unkillable. Safe Rust still terminates on:

- **Panics** — out-of-bounds indexing (`s[i]`), integer overflow (in debug /
  `-Cdebug-assertions` builds), `unwrap()`/`expect()`, `assert!`, division by
  zero, slice-range start > end. A panic that reaches the top of a thread with no
  catcher kills the process.
- **Aborts** — OOM (`Vec::with_capacity(attacker_huge)` → `handle_alloc_error`),
  stack overflow from unbounded recursion (guard-page `SIGSEGV`), double-panic,
  `panic = "abort"`.
- **Hangs** — infinite loops or super-linear algorithms (algorithmic DoS).

These are all **denial-of-service, not memory corruption** — far less severe (no
code execution, no out-of-bounds disclosure), but the scanner must still
contain them. That reframing is what memory safety buys: the *same* logic error
that is a silent out-of-bounds read in a C parser (potential RCE) is a
deterministic, safe `panic_bounds_check` here (at worst a DoS). Fuzzing finds
those panics/aborts/hangs so we can eliminate or contain them.

We still run under **AddressSanitizer** because our *dependencies* (`cab`,
`sevenz`, `pdf`, `delharc`, `lzxd`, compression shims, and under the image
hash `crc32fast` and `simd-adler32`) carry their own `unsafe`;
ASan catches genuine UB in them, distinct from the safe panics that surface on
their own.

## Tooling

`cargo-fuzz` + libFuzzer (in `fuzz/`). libFuzzer is **coverage-guided**: it
instruments every branch edge (SanitizerCoverage) and evolves inputs to maximise
new coverage, under ASan, with `-Cdebug-assertions` (so overflow/underflow
panic instead of wrapping). Targets in `fuzz/fuzz_targets/`:

| target          | entry point                       | covers                                   |
|-----------------|-----------------------------------|------------------------------------------|
| `vdisk`         | `unpack::walk()` of QCOW2, VMDK, VHD, VHDX, NTFS, FAT and partition tables | the virtual disks and the volume walker, with a buffer limit of 64 KiB so any image of a few KiB declares a disk walked in place: the tables read as units are reached, compressed units and their cache, the filesystems read through a `Read + Seek`. The first byte picks the format. Each image is walked from memory and through a block cache of 512-byte blocks, which must find the same members and end the same way, and no member held whole may pass the buffer limit. |
| `fsimage`       | `unpack::walk()` of ext, exFAT, SquashFS, cramfs, romfs, EROFS, 7z, WIM, xar and partition tables | the filesystem readers on hostile images, and the archives read where they lie on a seekable source: the superblocks, the directories and their loops, extent trees and block maps, chunk maps, the sparse and the compressed blocks, a 7z's header and folders, a WIM's chunk tables and a xar's table of contents, with a buffer limit of 64 KiB so a volume of a few KiB declares more. A file past the limit is read as it goes, up to the 4 MiB the scan budget gives. The first byte picks the format. Each image is walked from memory and through a block cache of 512-byte blocks, and again from memory: the three must find the same members, the first two must end the same way, and no member held whole may pass the buffer limit. |
| `lzo`           | the LZO1X decoder (`exav_unpack::lzo_decompress`) | SquashFS's LZO blocks: the decoder never panics, never writes past the size it is given, and gives the same bytes twice; a stream of literals made from the input must come back as it is. |
| `analyze`       | `analyze()` — the whole scanner   | format detection → every extractor (recursively) → pattern/hash matching → PE/ML/fuzzy heuristics → bytecode, against the signature files of `fuzz/db/` (every signature kind, the YARA rules, a bytecode program), under options the input's last two bytes choose (`fuzz/options.rs`: the heuristics, every `alert_*`, the structured-data and phishing checks, tight or production bounds, an object read in memory or through the block cache). **Broadest; the primary target.** |
| `full_pipeline` | the scanner as a deployment builds it | up to eight database files (a kind byte, bit 7 official, and their text) go through `loader::Builder::add_named_bytes` as the CLI does, so every kind the loader reads is reached (signatures, hashes, container and file-type rules, YARA, bytecode, phishing and allow-lists, `.crb`, passwords); then the scan, held to what the entry points promise each other: the same bytes scanned twice agree, `analyze_all` is a superset of `analyze` and a clean scan lists nothing, a stream read in pieces answers what a buffer did, and a database written out and read back scans as the one it came from. **Widest single target.** |
| `seekable`      | `scan_seekable()` over a reader that returns a few bytes a call and fails part way | the block-cache read of an object over `deep_analysis_max`, which no other target reaches. Checked: a reader and a buffer give one answer, a reader that fails is an error unless a detection was already made, and an object read through the cache that found nothing is not `Clean`. |
| `yara`          | `yara::compile()` + `Scanner::scan()` | exav's native YARA engine: the rule text through the compiler, then the rules over fuzzed data (the `pe`, `elf`, `dotnet`, `math`, `hash` and `string` modules, which parse the scanned file; hex, regular-expression, `xor` and `base64` patterns). Checked: a scan twice agrees, every match lies in the data. |
| `pcre`          | `engine::compare_engines()`       | a PCRE subsignature rewritten for the two Rust engines (vendored fancy-regex and `regex`): neither panics or hangs, and where the translation is in the linear engine's subset the two answer the same. |
| `clamd`         | the daemon's command loop, over memory (`exav::fuzzing::clamd`) | the clamd protocol as any client of the socket speaks it: NUL or newline terminated lines, `IDSESSION`, and the `INSTREAM`, `EXINSTREAM` and `EXINSTREAM MULTI` framings, with lying chunk lengths and missing terminators. Paths are refused in this build. Checked: a plain `INSTREAM` or `EXINSTREAM` answers what `analyze` says of the same bytes. |
| `icap`          | the ICAP request loop, over memory (`exav::fuzzing::icap`) | RFC 3507 as a proxy sends it: the head, `Encapsulated` offsets, `Preview`, `Allow: 204`, the chunked body with its extensions, `ieof` and trailers. Checked: a plain `REQMOD` is blocked exactly when `analyze` calls the bytes anything but clean. |
| `volumes`       | `volume::Collector`, `join_rar_volumes` | multi-volume names, the collector that holds and joins the parts of a split archive (it loses nothing: every offered name comes out once, the bytes add up) and the RAR joiner with the extraction of what it joins. |
| `authenticode`  | `authenticode::analyze_pe()`      | the PE certificate table, the PKCS#7 `SignedData` and each certificate's DER. Checked: a `.crb` list naming a certificate's subject (with or without its serial) blocks it, and one naming another subject does not. |
| `database`      | `database::read()` / `write()`    | the prebuilt `.exavdb`: MessagePack whose lengths size allocations. Checked: what reads writes back to something that reads and scans the same. |
| `unpack`        | `unpack::extract()`               | every container format with tight budgets; every parser exercised on every input |
| `ndb_compile`   | `EngineBuilder::add_ndb/ldb`      | NDB/LDB signature compilation edge cases |
| `pe`            | PE parsing                        | section/import/resource parsing          |
| `filetype`      | magic/type detection              | type sniffing                            |
| `cvd`           | signature-DB container parsing, then the loader | `.cvd`/`.cld` header, gzip and tar under tight bounds, and each member through `loader::Builder::add_named_bytes` as a signed database's are |
| `sigs`          | signature compilation             | DB rule parsing                          |
| `bytecode`      | `.cbc` bytecode loader            | bytecode verification                    |
| `rar3_ppmd`     | RAR3 PPMd decompression          | PPMd/LZSS conversion path               |
| `pe_emulator`   | `exav_pe_emu::unpack()`               | the x86 emulator that runs packer stubs: instruction decode + semantics, the emulated Windows environment, SEH, and the dump path. **The only target where the input supplies control flow rather than data.** Its decoder, `exav-x86`, is hand-written and `forbid(unsafe_code)` like the emulator (`x86_decode` checks it against `iced-x86`); the target goes through the entry point the scanner uses. Asserts the invariant the scanner relies on: anything emitted parses as a PE. |
| `imagehash`     | `exav_imagehash::Hasher::hash()`, `exav_render::image::decode_any()`, `exav_render::pdf_image` | every image decoder behind `fuzzy_img#` (PNG, GIF, JPEG, TIFF, BMP, WebP, ICO, PNM, QOI, DDS, farbfeld, HDR, and JPEG 2000 and JBIG2 through hayro-jpeg2000 and hayro-jbig2, and JPEG XL through zenjxl-decoder (the `jxl` feature, which the scanner's builds leave off)), then the grey conversion, resize and DCT of both presets, with a 4 MiB decode budget (64 MiB for the other decoders). The scan reaches these only when a database has a `fuzzy_img#` signature, so `analyze` rarely does. Then the JPXDecode, JBIG2Decode and CCITTFaxDecode decoders `@exav/viewer` puts in place of pdf.js's, their parameters taken from the input's length. Those do not catch panics: in the browser a panic traps the wasm instance. |
| `raw_preview`   | `exav_render::image::raw::detect()` + `preview()`, `decode_any()` | camera RAW files as `@exav/viewer` opens them: detection by the bytes (TIFF-structured files told from plain TIFFs, ISO base media, Fujifilm, Sigma, CIFF and Minolta signatures), the TIFF directories (chains, SubIFDs, Exif pointers, strips, JPEGInterchangeFormat, 8 and 16-bit samples), the JPEG stream search over the whole file, the Exif orientation of the files and of the streams, and the budgets, with a 16 MiB decode budget. The scanner does not read RAW files, so no other target reaches it. A panic `preview` would catch counts: in the browser it traps the wasm instance. |
| `drawing`       | `exav_render::dwg::Document::parse()` + `tessellate()` | DXF, ASCII and binary, and DWG (R13 to 2018), into the drawing model, then the tessellation of every layout on a light and a dark ground: what `@exav/viewer`'s DWG module runs on any file a user opens. The scanner does not read drawings, so no other target reaches it. A panic `parse` would catch counts: in the browser it traps the wasm instance. |
| `cad_dxf`       | `exav_render::cad::read_dxf_with()` + `to_json()`, `cad::preview()` | DXF, ASCII and binary, R12 to 2018, into the drawing model: the meaning of each group code in each record (hatch boundaries, multileader context data, R12 viewport extended data, subclass splits, proxy graphics streams), and the thumbnail found from the end of the file. `unpack` and `analyze` reach DXF's tokenizer and the payload extraction through exav-unpack's `dxf` format, but not this reading of it. |
| `ifc`           | `exav_render::ifc::read()` + `exav_render::stl::read()` | IFC (IFC2X3, IFC4, IFC4X3) and STL into triangle meshes, as `@exav/viewer`'s model module reads them: the STEP index and parameter parser, units, placements (local, grid and linear), profiles, curves (alignment curve segments among them), swept and tessellated solids, B-reps with their curved faces, booleans (BSP trees) and openings, within a 200,000-triangle budget; and binary and ASCII STL. No other target reaches them. |
| `mesh`          | `exav_render::obj::read()`, `ply::read()`, `gltf::read()` | Wavefront OBJ, Stanford PLY (ASCII and binary, both byte orders) and glTF 2.0 (`.gltf` with `data:` buffers, `.glb`) into triangle meshes, within a 200,000-triangle budget: polygon triangulation, PLY headers and list types, glTF's own JSON reader, accessors, sparse accessors, node transforms and trees, base64. The target also checks that every scene it gets back has whole triangles, indices in range and finite positions. |
| `markdown`      | `exav_render::markdown::parse()` + `to_json()`, `visible_text()` | Markdown (CommonMark, tables, strikethrough) into the tree `@exav/viewer`'s text module draws, through pulldown-cmark: the nesting, column and node bounds, the link targets the tree may carry (http, https and mailto, no space, control, separator, bidirectional control or credentials, checked on their own terms), padded table rows, and that the JSON is balanced and ends as the page expects. |
| `sheets_xls`    | `exav_render::sheets::convert(.., Format::Xls, ..)` | XLS into the XLSX `@exav/viewer`'s sheets module shows: the lenient compound file reader, BIFF2 to BIFF8 records and their CONTINUE joins, decryption with the default password (XOR, RC4, RC4 CryptoAPI), code pages, formulas, conditional formats, validations, the drawing layer (pictures, shapes, charts) and the XLSX writer, within 200,000 cells and 64 MiB. Checks that what converts is a ZIP whose first parts are XML without a C0 control character. No other target reaches it. |
| `sheets_ods`    | `exav_render::sheets::convert(.., Format::Ods / Fods, ..)` | ODS (a ZIP) and FODS (anything else): the XML tree's bounds, styles and data styles, OpenFormula conversion, conditional formats and validations, frames and charts, the repeated rows and columns, then the XLSX writer, under the same limits and checks. |
| `sheets_numbers` | `exav_render::sheets::convert(.., Format::Numbers, ..)` | Apple Numbers: the input is an IWA stream the target stores as `Index/Document.iwa`, or a Numbers '08/'09 `index.xml` when it starts with `<` (`index.xml.gz` when gzipped), or a whole document when it is a ZIP, so the mutations reach the Snappy blocks, the protobuf archives, the tiles and cell records, the '09 XML's styles, data source and formulas, not the ZIP around them. Same limits and checks. |
| `sheets_text` | `exav_render::sheets::convert(.., Format::SpreadsheetMl / Html / Sylk, ..)` | The text formats Excel opens from a .xls file, the first byte picking the reader: XML Spreadsheet 2003 (declared encodings, styles and their parents, R1C1 formulas), HTML tables (the bounded tokenizer, CSS and `mso-` properties, spans, conditional markup, character sets) and SYLK (records, ISO 6937 escapes, shared formulas). Same limits and checks. |
| `slides_ppt` | `exav_render::slides::convert(.., Format::Ppt, ..)` | PowerPoint 95 and 97 to 2003 into the PPTX `@exav/viewer`'s slides module shows: the input is the `PowerPoint Document` stream, which the target stores in a compound file it builds, or a whole compound file (or a file of PowerPoint 2 to 4, or BinHex text), so the mutations reach the record tree, the persist directory and user edits, the text and style atoms, the OfficeArt drawing layer (property tables, shapes, custom paths), the blip store, the PowerPoint 95 records and the OLE charts, then the PPTX writer, within 20,000 shapes and 64 MiB. Checks that what converts is a ZIP holding the parts the viewer reads first, whose XML parts have no C0 control character, and that a document of several slides also converts with its first slide alone (`convert_first`), counting the same slides. No other target reaches it. |
| `slides_odp` | `exav_render::slides::convert(.., Format::Odp / Fodp, ..)` | ODP (a ZIP) and FODP (anything else): the XML tree's bounds, styles and their parents, list styles, masters, enhanced geometry and its formulas, SVG paths, text and fields, tables, pictures and chart objects (through the `sheets` chart writer), then the PPTX writer, under the same limits and checks. |
| `slides_odg` | `exav_render::slides::convert(.., Format::Odg / Fodg, ..)` | OpenDocument drawings, ODG (a ZIP) and FODG (anything else), into the PPTX `@exav/viewer`'s slides module shows, a page to a slide: what `slides_odp` reaches, and the master pages' page sizes (the largest becomes the PPTX's), the layers that are not displayed and the pages' names, under the same limits and checks. |
| `slides_vsdx` | `exav_render::slides::convert(.., Format::Vsdx, ..)` | Visio 2013 and later drawings (an Open Packaging package of XML parts) into the PPTX `@exav/viewer`'s slides module shows: the package and its relationships, document, pages and masters, shape sheets and their inheritance from masters and style sheets, formulas, geometry rows and splines, text, pictures and themes, under the same limits and checks. |
| `slides_keynote` | `exav_render::slides::convert(.., Format::Keynote, ..)` | Apple Keynote: the input is an IWA stream the target stores as `Index/Document.iwa` (Keynote 6 and later), or a whole document when it is a ZIP, or an `.apxl` file when it starts with `<` or is gzipped (Keynote 1 to 5), so the mutations reach the Snappy blocks, the protobuf archives, the XML trees, the slides, masters, placeholders, styles, shapes, paths, tables and text storages, not the ZIP around them. Same limits and checks. |
| `docs_doc` | `exav_render::docs::convert(.., Format::Doc, ..)` | Word 97 to 2003, and Word 6 and 95 (a `WordDocument` stream whose first word says so, which the mutations reach), into the DOCX `@exav/viewer`'s docs module shows: the input is the `WordDocument` stream, which the target stores in a compound file it builds next to table streams made of its second half, or a whole compound file, so the mutations reach the FIB, the piece table, the character and paragraph FKPs, the sprms, the stylesheet, lists, sections, tables, notes, comments, fields and the OfficeArt layer, then the DOCX writer, within 20,000 paragraphs and cells and 64 MiB. Checks that what converts is a ZIP holding the parts the viewer reads first, whose XML parts have no C0 control character. |
| `docs_odt` | `exav_render::docs::convert(.., Format::Odt / Fodt, ..)` | ODT (a ZIP) and FODT (anything else): the XML tree's bounds, automatic and named styles and their parents, master pages, lists, tables, frames, pictures, notes and fields, then the DOCX writer, under the same limits and checks. |
| `docs_rtf` | `exav_render::docs::convert(.., Format::Rtf, ..)` | RTF: the tokenizer, the group stack and its destinations, font and color tables, code pages, `\u` and its skip count, list tables, tables, fields, pictures in hex and `\bin`, notes and headers, then the DOCX writer, under the same limits and checks. |
| `docs_wml` | `exav_render::docs::convert(.., Format::Wml2003, ..)` | Word 2003 XML in UTF-8 or UTF-16: styles, lists, sections, tables, fields, `binData` pictures and comments, under the same limits and checks. |
| `docs_html` | `exav_render::docs::convert(.., Format::Html, ..)` | Web pages as documents, Word's "Save as Web Page" and its MIME form included: the tokenizer, style sheets, tables with spans, lists, links, pictures in `data:` addresses and MIME parts, then the DOCX writer, under the same limits and checks. |
| `docs_pages` | `exav_render::docs::convert(.., Format::Pages, ..)` | Apple Pages: the input is an IWA stream the target stores as `Index/Document.iwa`, or a whole document when it is a ZIP, so the mutations reach the Snappy blocks, the protobuf archives and the text storages, not the ZIP around them. Same limits and checks. |
| `visible_text`  | `exav_render::text::visible_text()` | The text of a document as a reader sees it, for the scanner and `exav-grep --text`: the first byte picks the reader (Markdown, HTML, each Office and OpenDocument XML part, PDF through hayro, DXF, DWG, and with `text-office` DOC, XLS, PPT, RTF, Word 2003 XML, SYLK, the flat OpenDocument files, Numbers, Pages, Keynote), the rest is hostile bytes. Checks the text stays within its cap, the links within their bound, the sections in order on character boundaries, and that `wants` announces whatever is read. The PDF path takes every stream through exav-unpack's budget first, so a decompression bomb is refused rather than inflated. |
| `cad_dwg`       | `exav_render::cad::read_dwg_with()` + `to_json()`, `cad::preview()` | DWG, R13 to R2018, into the drawing model: exav-unpack's `dwg` bit codes, the sections the file header locates (R2004 on: the encrypted file header, the page and section maps, page checksums and the LZ77 decompression; R2007: the Reed-Solomon coded file header, maps and pages, their CRCs and copies, and its own LZ77 variant), the classes, the object map and each object's common data and string stream, then the header variables, the tables and the blocks with their entities, each entity type's own data and the proxy graphics streams of the others, and the thumbnail read alone. `unpack` and `analyze` reach the file header, the preview images and, opening the drawing, the OLE2FRAME objects. |
| `parser_recursion` | nesting depth, constructed        | Builds deep nesting from a couple of input bytes rather than waiting for the mutator to find it — every extra level needs another well-formed delimiter pair, so byte mutation stalls at two or three while this reaches thousands. Targets the failure the panic boundary cannot contain: `catch_unwind` catches a bounds check, not a stack overflow, and `max_recursion` bounds containers-inside-containers rather than a grammar that nests into itself. A finding looks like a crash with **no panic message**. |
| `x86_decode`    | `exav_x86::decode()`                  | **differential against `iced-x86`**, which is compiled in as the oracle. Asserts six properties per input: never claim an encoding iced rejects; agree on length; agree on mnemonic; agree on the memory operand's base/index/scale/displacement and on every register operand's file, number and position; re-decoding from exactly the reported length gives the same answer; and no proper prefix of an instruction decodes. Declining is not a failure — `None` means "not an encoding this decoder claims", which the caller reports as unsupported. |

`x86_decode` earns its place beside the crate's own differential tests because
those sweep the opcode maps with a **fixed instruction body** — one ModRM byte
and a constant tail. The mistakes that survive a sweep live in the body: a SIB
byte that decides whether a displacement exists, a `mod` field that changes its
width, a prefix run that pushes the instruction past fifteen bytes. Mutation
reaches those combinations; enumeration does not. A wrong length is the failure
to watch, because it desynchronises every instruction after it rather than
staying local.

Run it with `ASAN_OPTIONS=detect_leaks=0`, as CI's `fuzz-smoke` does: iced-x86
builds its decoder tables in a `lazy_static` it never frees, and the newest
nightly's LeakSanitizer reports them at exit (552 bytes in 12 allocations,
whatever the input). It is the oracle's, not exav's, and every other target
keeps the check.

The fuzz crate builds `exav-core` with the default features off and then what
the scanner ships with that matters here: **`yara`** (the in-tree engine, which
has no wasmtime and does not slow the ASan build much), `all-formats`,
`decrypt`, `checksums` and `image-hash`. An earlier version left YARA out, and
with it the rule compiler, the evaluator and the `pe`/`elf`/`dotnet`/`math`/
`hash` modules that parse the scanned file: nothing fuzzed them.

All fuzz targets live in a single workspace (`fuzz/`). The `unpack` target
exercises every container format with tight budgets; `full_pipeline` exercises
the full scan path through the real loader and holds the entry points to each
other; `ndb_compile` exercises signature compilation edge cases. `analyze()`
reaches every extractor recursively, so there is no separate `exav-unpack` fuzz
workspace. `fuzz/support` (its own crate, no dependencies) holds the custom
mutator and the input framing, so that their tests run on their own:
`cargo test --manifest-path fuzz/Cargo.toml -p exav-fuzz-support`.

## The signature files, and what the input chooses

`analyze` and `full_pipeline` scan against `fuzz/db/`: one or more lines of
every kind the loader reads, written for exav (no ClamAV content), each the
shape of a feature (an anchor at `EP+0`, an alternative group, a PCRE
subsignature with a back-reference, a YARA `for` over a module's array). A line
the loader rejects is a line no input reaches, so `fuzz/db.rs` refuses to start
a target when one does not load or a YARA rule does not compile.
`EXAV_FUZZ_DB_SKIP=yar,ldb` leaves files out, to see what one costs a scan.

The options a scan runs under are the input's too (`fuzz/options.rs`): each
`alert_*` heuristic, the structured-data and phishing checks, bounds tight
(three inputs in four, so that a run is short) or production's, an object read
in memory or through the block cache. A seed of any length works unchanged:
`analyze` takes the selector from the input's last two bytes and does not scan
them, `full_pipeline` and `seekable` from a short header the seed script puts
in front.

`exav` ships no library, and a fuzz target can only call a library. So
`fuzz/exav-cli` is a crate whose `[lib]` points at `crates/exav/src/main.rs`:
the source of the binary, built as a library (`exav_cli`), so that the `clamd`
and `icap` targets drive the daemon's parsers over memory and what is fuzzed is
what ships. Its dependencies repeat `crates/exav/Cargo.toml`'s; one added there
and not here fails its build. Its `fuzzing` feature, which no shipped build has,
adds the entry points (`crates/exav/src/fuzzing.rs`) and makes the clamd verbs
that take a path answer an error instead of opening it.

## Seeding strategy (the multiplier)

Random bytes rarely form a valid `xar!` / `MSCF` / `Rar!` header, so a cold
fuzzer never reaches the deep parsers. We seed aggressively:

`scripts/fuzz-seeds.sh OUT` builds one seed directory per target from the
committed fixtures, which CI's `fuzz-smoke` job and `scripts/fuzz-campaign.sh`
pass as an extra, read-only corpus directory:

1. **Format fixtures**, for `analyze`, `full_pipeline`, `unpack` and
   `filetype`: every `crates/*/tests/fixtures/**` file of at most 64 KiB
   (`MAX_BYTES`), `.xor` ones unmasked, which is why `OUT` belongs outside the
   repository. The PE files among them seed `pe` and `pe_emulator`.
2. **Images**, for `imagehash`: exav-imagehash's committed test images
   (`crates/exav-imagehash/tests/fixtures/img`) and, for the three formats
   they lack, one tiny DDS, farbfeld and HDR file in `fuzz/seeds/imagehash`;
   exav-render's JPEG 2000, JBIG2 and CCITT fixtures
   (`crates/exav-render/tests/fixtures/images`) and the viewer's PDF image
   streams (`crates/exav-viewer/e2e/fixtures/pdf-images`). For `raw_preview`:
   the synthetic RAW files of `crates/exav-render/tests/fixtures/raw`
   (`make.py`, one per family) and the TIFF and JPEG images above.
3. **Drawings**, for `drawing`: exav-render's fuzz-finding fixtures and the
   viewer tests' `plan.dxf` and `plan.dwg`, which
   `crates/exav-viewer/e2e/fixtures/make-plan.py` writes with ezdxf and the
   ODA File Converter, and the proxy graphics drawings
   (`crates/exav-render/tests/fixtures/cad/proxy`: streams its `make.py`
   writes chunk by chunk, as DXF and the converter's DWG of each version).
   LibreDWG's test drawings are GPL and are not used.
4. **DXF**, for `cad_dxf`: the drawing model's fixtures
   (`crates/exav-render/tests/fixtures/cad`, ezdxf's drawings as the ODA File
   Converter saved them in each version, ASCII and binary) and exav-unpack's
   (`crates/exav-unpack/tests/fixtures/dxf`), unzipped, of at most 64 KiB;
   and the viewer demo's `plan.dxf`. The unzipped ones go to the format
   targets' seeds too.
5. **DWG**, for `cad_dwg`: the same drawings as the converter saved them as
   R13, R14, 2000, 2004, 2010, 2013 and 2018 DWG
   (`crates/exav-render/tests/fixtures/cad/dwg`), the proxy graphics
   drawings' DWGs (`cad/proxy/dwg`) and exav-unpack's
   (`crates/exav-unpack/tests/fixtures/dwg`), unzipped, of at most 64 KiB
   (which leaves the 2000 ones out: the converter's smallest is 94 KiB; from
   2004 the sections are compressed). They go to the format targets' seeds
   too.
6. **IFC and STL**, for `ifc`: exav-render's fixtures
   (`crates/exav-render/tests/fixtures/ifc` and `stl`, STEP text and STL
   written by their `make.py`, a file per kind of geometry) and the viewer
   tests' `house.ifc` and `house.stl` (`tests/fixtures/viewer`).
   **Meshes**, for `mesh`: a few files written by the script itself (a quad
   and a triangle as OBJ, PLY in the three encodings, and a tetrahedron as
   glTF with an embedded buffer and as GLB).
   **Document text**, for `visible_text`: one document of each kind the target
   reads, behind a byte that picks its reader (HTML pages and fragments, a part
   of each Office and OpenDocument kind, PDFs plain and deflated, a DXF, the
   drawing seeds of `cad_dxf` and `cad_dwg`, and the office fixtures behind
   their names: a DOC, an XLS, a PPT, an RTF, a Word 2003 XML and a
   SpreadsheetML 2003 file, a SYLK file, the flat OpenDocument files, a
   Numbers, a Pages and a Keynote document).
   **Markdown**, for `markdown`: three files written by the script (every
   construct the reader folds, the link targets it must refuse, deep quotes and
   lists), and a dictionary of Markdown's punctuation (`fuzz/dicts/markdown.dict`).
   **Spreadsheets**, for `sheets_xls`, `sheets_ods`, `sheets_numbers` and
   `sheets_text` (its three text fixtures behind their reader's byte):
   the `sheets` fixtures (`crates/exav-render/tests/fixtures/office/sheets`:
   an Excel 97 workbook, an ODS and a FODS, a Numbers document), and for
   `sheets_numbers` the Numbers document's IWA streams joined into one and a
   Numbers '09 `index.xml` (`fuzz/seeds/sheets_numbers/`), plain and gzipped.
   **Presentations and drawings**, for `slides_ppt`, `slides_odp`,
   `slides_odg`, `slides_vsdx` and `slides_keynote` (`slides_odg` and
   `slides_vsdx` get the ODG, FODG and VSDX files of
   `tests/fixtures/office/draw`):
   the `slides` fixtures (`crates/exav-render/tests/fixtures/office/slides`):
   the PowerPoint 97 file's `PowerPoint Document` stream (the file is over
   the size cap with its thumbnail), the ODP and the FODP, and the Keynote
   document's IWA streams joined into one, but its package metadata, and
   hand-written seeds (`fuzz/seeds/slides_keynote/`: a Keynote 1 and a
   Keynote 2 to 5 `.apxl`; `fuzz/seeds/slides_ppt/`: a PowerPoint 95
   stream).
   **Documents**, for `docs_doc`, `docs_odt`, `docs_rtf`, `docs_wml`,
   `docs_html` and `docs_pages`: the `docs` fixtures
   (`crates/exav-render/tests/fixtures/office/docs`: a Word 97 file, an ODT, a FODT, an
   RTF, a Word 2003 XML file and a web page), a Word 6 document for `docs_doc`
   (`fuzz/seeds/docs_doc/`, written by the reader's tests) and for `docs_pages`
   the Keynote IWA streams, which share the archive layer.
   **Virtual disks and volumes**, for `vdisk`: the QCOW2 fixtures and the
   hand-written images of `fuzz/seeds/vdisk/` (QCOW2, VHD and VMDK), behind the
   byte that picks the format; and, from the filesystem fixtures, which are
   gzipped images of mostly zeros, the part a walk reads first: the FAT image
   up to its last used byte and the NTFS image up to the end of the first run
   of its `$MFT`, each alone and as the partition of an MBR and of a GPT disk
   (`scripts/fuzz-seeds-synth.py`). There is no VHDX seed: the fixture is 9 MiB, almost all
   zeros, and its structures lie megabytes apart.

   **Filesystem images and LZO blocks**, for `fsimage` and `lzo`: small images
   of a tree of three files in each of ext2, ext4 with inline data, exFAT,
   SquashFS (in each of its compressions), cramfs, romfs and EROFS, a 7z, a
   WIM (whose chunks are stored as they are, so that it needs no codec) and a
   xar, the filesystems again behind a partition table that declares more than
   the target's buffer limit, and the first blocks `lzop` makes of two inputs at
   its levels 1 and 9
   (`fuzz/seeds/fsimage/make.py` and `fuzz/seeds/lzo/make.py`, which say what
   they need).

7. **Framed targets**, written by the script: `full_pipeline` and `seekable` get
   every fixture behind their header (and `full_pipeline` each file of
   `fuzz/db/` as its database, alone and eight together), `volumes` the RAR sets
   of exav-unpack's fixtures, `yara` the rules of `fuzz/db/fuzz.yar` and
   `fuzz/seeds/yara/` each over a PE, an ELF and some text, `pcre` the lines of
   `fuzz/seeds/pcre/patterns.txt`, `cvd` a container of `fuzz/db/` and `database`
   the prebuilt database `exav --build-db` makes of it (so the script builds
   `exav`, or uses `$EXAV`), `authenticode` the signed PEs.

`sigs`, `ndb_compile`, `bytecode`, `rar3_ppmd`, `parser_recursion`, `x86_decode`,
`clamd` and `icap` get no seeds: no committed file is in their input format, and
the last two decode any bytes into commands and requests.

`fuzz/dicts/` holds strings to splice in for the targets whose input is text or
a protocol (`yara`, `pcre`, `icap`, `clamd` and `signatures`, which
`full_pipeline`, `ndb_compile`, `sigs` and `cvd` use). The campaign script and
CI pass them.

Locally, small (≤ 64 KB) files sampled from the MalwareBazaar corpus can be
added to a target's work directory. They carry valid PE, archive and document
structure, so the mutator starts *inside* the parsers instead of rediscovering
magic.

Seeds and fuzzer-discovered inputs live in a **gitignored** work dir
(`tmp/data/fuzzwork_analyze`), never the committed corpus, so a run never bloats
the tree. The corpus accumulates across runs — coverage climbs monotonically.

> One pitfall: don't seed a deliberately-pathological input. The
> `ppmd_lzss_conversion.rar` fixture decodes ~241 MB (its real test is
> `#[ignore]`d); seeded, it just makes libFuzzer time out on it immediately and
> abort. Exclude known-slow fixtures from the seed set.

## Synthesized seeds

`scripts/fuzz-seeds-synth.py` (run by `scripts/fuzz-seeds.sh`) writes small
seeds from what each target's source reads: for each input format, the shapes
the code branches on. Measured, as the coverage (edges) libFuzzer reports right
after loading the seed corpus, before any mutation (`-runs=0`, ASan build, the
fixture seeds as "old"):

| target | no seeds | old seeds | old + synthesized | synthesized alone |
|---|---|---|---|---|
| `sigs` | 280 | 280 (none) | 575 | 575 |
| `ndb_compile` | 339 | 339 (none) | 3,362 | 3,356 |
| `bytecode` | 76 | 76 (none) | 643 | 643 |
| `parser_recursion` | 19 | 19 (none) | 540 | 543 |
| `rar3_ppmd` | 19 | 19 (none) | 329 | 329 |
| `x86_decode` | 1,855 | 1,855 (none) | 4,250 | 4,250 |
| `pe_emulator` | 65 | 1,385 | 1,721 | 1,586 |
| `cvd` | 40 | 20,086 | 20,179 | 20,038 |
| `authenticode` | 25 | 1,770 | 1,793 | 1,070 |
| `seekable` | 19 | 65,002 | 65,018 | 19,052 |
| `analyze` | 183 | 44,219 | 44,958 | 19,443 |
| `full_pipeline` | 25 | 76,707 | 77,120 | 36,647 |
| `pe` | 56 | 1,298 | 1,298 | 426 |
| `vdisk` | 293 | 3,818 | 4,683 | 1,544 |

Where there were no seeds the gain is large (five to ten times); where the
fixtures already open the parser it is small, and the point is the inputs the
fixtures do not have: the option bits, a reader that fails, a PE of the shapes a
packer's stub takes. `database` has none of its own: its per-file databases are
in the old count, so it is not measured alone. A seed that breaks a check is
the best kind: one found the `--alert-exceeds-max` all-match bug in the table
below the moment `full_pipeline` first loaded it. `clamd` and `icap` are not
here: their input is `arbitrary`'s encoding, which no one writes by hand, and
they reach 17,000 edges within seconds without seeds.

## Reference decoders as oracles

exav-unpack's in-tree LZFSE and DCL ("implode") decoders are checked on
damaged streams against the reference sources they were written from: Apple's
`lzfse` (BSD-3-Clause) and zlib's `contrib/blast` (zlib licence). The sources
are fetched and compiled by `crates/exav-unpack/tests/oracle/build.sh` (with
AddressSanitizer and UndefinedBehaviorSanitizer, so a stream the reference
itself mishandles is reported); nothing of them is committed. Two
`#[ignore]`d tests feed it streams cut and damaged in many ways (bit flips,
fields set to extremes, cuts, insertions, repeats) and compare the bytes
written and the verdict (whole, output past the limit, cut, damaged):

```sh
crates/exav-unpack/tests/oracle/build.sh DIR
EXAV_LZFSE_ORACLE=DIR/lzfse_oracle EXAV_DCL_ORACLE=DIR/dcl_oracle \
  cargo test -p exav-unpack --lib -- --ignored oracle
```

They are ignored, not skipped: a run that did not ask for them lists them as
ignored, and a run that did fails when the oracle is not built.
`EXAV_DEBUG_ORACLE_ROUNDS` sets the streams per base (3000 and 5000 by default),
`EXAV_DEBUG_ORACLE_DUMP` a directory to write a stream that differs to. A stream
whose output depends on what the reference's destination held before (an LZVN
match reaching bytes never written) is told by running it with two fills; it
is invalid here.

The reference reports a damaged LZVN payload as "destination full", counts a
failed block's last instruction out of the bytes it returns, and writes the
part of a match that fits a block's declared size; the tests state which of
these differences they allow. Where the two decoders disagree on a stream the
reference accepts, or accept one it refuses, the test fails.

The unpack target reaches both decoders through `dmg/udif_lzfse.dmg` (two
LZFSE runs, an LZVN block and FSE blocks) and the `ishieldz/` archives, which
`scripts/fuzz-seeds.sh` takes with every fixture of at most 64 KiB. They were
also fuzzed on their own, through the DMG extractor with one LZFSE run of the
input's bytes and through InstallShield Z archives (whole, or the input as the
one member of a well-formed one), in a standalone `cargo fuzz` crate outside
the repository, under AddressSanitizer: 741,736 executions in 40 minutes for
LZFSE and 1.4 million for InstallShield Z, no crash, hang or out-of-memory
(one 36-second stall inside `malloc` on a loaded machine, an input that runs in
56 ms alone).

## Running a campaign

CI's `fuzz-smoke` job runs every target for 60 seconds on each push, from the
seeds and from the corpus the last run left (`actions/cache`), and runs the
tests of `fuzz/support`. The `fuzz-nightly` workflow runs the campaign below
for three hours every night and fails if it finds a crash, a timeout or an OOM,
uploading `fuzz/artifacts`.

`scripts/fuzz-campaign.sh` splits a wall-clock budget across every target, in
fork mode, and reports what each one found:

```sh
scripts/fuzz-campaign.sh                          # one hour, one worker
TOTAL=25200 WORKERS=3 scripts/fuzz-campaign.sh    # seven hours, three at a time
TARGETS="analyze x86_decode" scripts/fuzz-campaign.sh
```

It runs every `fuzz/fuzz_targets/*.rs` unless `TARGETS` names some, `WORKERS`
at a time (one per core). A target's slice is what is left of `TOTAL` shared
among the targets not started, so a slow build shortens the slices and not the
campaign. The timeout and memory limit are those of `fuzz-smoke`, so a finding
is one CI would have made, and a unit over `SLOW` seconds (4) is kept as a
`slow-unit-*` artifact: those time out on a slower machine. A target's binary
is deleted once it has run (`KEEP_BINARIES=1` keeps them); each is hundreds of
megabytes.

A target that does not build is reported with its log, and the script exits
non-zero: a compile error must not read as a target that "ran" and found
nothing, which is the worst possible way to be wrong about test coverage. It
reports only the artifacts *this* campaign produced, so a stale directory does
not read as new findings. The logs are in `tmp/data/fuzzlogs/`.

The seeds are `scripts/fuzz-seeds.sh`'s, which also takes the files of a
directory of wild samples (`tmp/samples-issues`, or `WILD`) for the targets that
read a whole file of a format (`scripts/fuzz-seeds-wild.sh`).

### Memory

Building `exav-core` under AddressSanitizer is the memory peak of the whole
repository: one rustc process, full instrumentation, and `codegen-units=1`,
which `cargo fuzz` sets by default. On a small host that combination is what the
OOM killer reaches for, and rustc dies with `signal: 9` rather than an error
message. The campaign script therefore passes `--codegen-units 16` and builds
one crate at a time; raise `CODEGEN_UNITS` on a larger machine for slightly
faster fuzzing.

## Run modes

- **Single-shot** (find the first crash fast): aborts on the first
  crash/timeout, writes the artifact.
  ```sh
  cargo +nightly fuzz run analyze tmp/data/fuzzwork_analyze -- \
    -max_total_time=600 -timeout=25 -rss_limit_mb=4096
  ```
- **Fork mode** (collect *many* distinct crashes without rebuilding between
  them): the parent keeps fuzzing after each child crash/timeout/OOM. This is
  the efficient campaign mode — one run yields a batch of distinct artifacts to
  triage, so we rebuild once per batch instead of once per bug.
  ```sh
  cargo +nightly fuzz run analyze tmp/data/fuzzwork_analyze -- \
    -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
    -timeout=60 -rss_limit_mb=4096 -max_total_time=1500
  ```

`-timeout` is the DoS threshold (an input slower than this is a finding);
`-rss_limit_mb` catches runaway allocation as an OOM.

## Triage & fix workflow

For each artifact (`fuzz/artifacts/<target>/{crash,timeout,oom}-*`):

1. **Reproduce** with a backtrace:
   `RUST_BACKTRACE=1 ./fuzz/target/*/release/analyze <artifact>`.
2. **Classify by where the panic originates:**
   - **Our code** (e.g. `formats/cpio.rs`) → **fix the root cause**: bounds-check
     before slicing, `saturating_*` arithmetic, `.min(len)` clamps on
     attacker-controlled offsets/sizes. A parser must tolerate any byte string.
   - **A third-party decoder** (e.g. `cab`, which panics instead of returning
     `Err`) → contain it at the **`walk` `catch_unwind` boundary**, which
     turns any decoder panic into a clean `LimitHit`. (We can't easily fix the
     dep in place; the boundary makes hostile input a non-event for *every*
     decoder uniformly.)
   - **Timeout** → decide algorithmic-DoS vs budget-bound. RAR/PPMd decode is
     CPU-heavy but bounded by `max_buffer_bytes`/`max_extracted_bytes`; in production
     the daemon's `RLIMIT_CPU`/`SIGALRM` cap wall-clock. A *super-linear* loop on
     small input is a real bug to fix.
   - **OOM** → an allocation sized from an attacker length field escaped the
     budget; tighten the budget check.
3. **Lock it** with a regression test in `crates/exav-unpack/tests/
   panic_containment.rs` (or the relevant crate), embedding the minimal
   artifact as a committed fixture (these are tiny, malformed-but-benign inputs,
   safe to commit — unlike the malware corpus).
4. **Rebuild** the fuzz binary and resume; the prior corpus is reused, so the
   fuzzer doesn't re-discover fixed paths and pushes into new ones.

## Containment layers (defence in depth)

Even with every known panic fixed, new ones can hide in deps. The layers:

| layer | contains | mechanism |
|-------|----------|-----------|
| Root-cause fixes in our parsers | our own panics | bounds checks, saturating math |
| `walk` `catch_unwind` | third-party decoder panics | panic → `LimitHit` (never a silent Clean) |
| Daemon prefork pool | OOM, stack overflow, hangs | per-job `RLIMIT_AS` / `RLIMIT_CPU` / `SIGALRM` → worker `_exit`, recycled |
| Verdict taxonomy | "couldn't fully scan" | `LimitsExceeded`/`Unscannable` — a not-fully-scanned file is never reported Clean |

The `catch_unwind` boundary protects the **library/CLI** path (which has no
process-level backstop); the prefork pool protects the **daemon** path against
the aborts `catch_unwind` can't catch (OOM, stack overflow). Note that libFuzzer
installs its own abort-on-panic hook, so the fuzzer surfaces *every* reachable
panic even ones `catch_unwind` would contain — which is what we want: the
boundary is a backstop, not an excuse to leave our own parsers panicky.

## Findings log

| input            | site                              | root cause                                              | fix |
|------------------|-----------------------------------|---------------------------------------------------------|-----|
| `MSCF` cabinet   | `cab-0.6.0` `folder.rs:134`       | dep indexes an empty vector on a crafted cabinet (panics instead of `Err`) | `catch_unwind` boundary in `walk` → `Unscannable` |
| `0o070707` cpio  | `formats/cpio.rs` (bin/newc/odc)  | `data_start` from attacker `namesize`, unclamped → `data[start..end]` with start > len | clamp `data_start` to `data.len()` (all 3 variants) |
| ISO9660          | `formats/iso.rs:54/57`            | dir record's self-declared `rec_len < 33`, then `rec[2..32]` indexed | require `rec_len >= 33` before slicing |
| UPX (NRV2B/D/E)  | `formats/upx.rs` (4 gamma loops)  | corrupt bitstream doubles the gamma value until `usize` overflow (and downstream `(m-3)*256`) | cap gamma at `NRV_GAMMA_MAX` (`u32::MAX`) → `Unscannable` |
| `fuzzy_img#` sig | `engine.rs` `parse_fuzzy_subsig`  | multi-byte UTF-8 chars in hash field caused `&hash[i*2..]` to slice inside char boundary | `hash.is_ascii()` guard — reject non-ASCII hash fields |
| NDB anchor sig   | `engine.rs` `pick_anchor`         | `fixed += w` overflowed on crafted input | `fixed = fixed.saturating_add(w)` |
| truncated CAB (LZX) | `cab` → `lzxd` `bitstream.rs:37` | dep reads `buffer[1]` when buffer has 1 byte | `catch_unwind` boundary → `Unscannable` |
| LHA level 3      | `delharc` `header/parser.rs:265`  | dep adds `parser.len + first_header_len` which overflows u32 | `catch_unwind` boundary → `Unscannable` |
| ARC, 69 bytes (`full_pipeline`, OOM) | `formats/arc.rs` `lzw` | a code past the next free one was taken for KwKwK; it then became a code's own prefix, and expanding it never ended | refuse `code > next` |
| ZOO LZD (review of the above) | `formats/zoo.rs` `decode` | output was not capped at the declared size the budget checked, and LZW expands a few thousand times | a writer that stops at `org_size` |
| PE import directory at 4 GiB (`pe_emulator`) | `exav-pe-emu` `win.rs` `bind_imports` | `is_mapped` saturated, so a descriptor past the top passed, and reading its fields overflowed; API output pointers had the same `p + off` | `is_mapped` refuses a range past 4 GiB; guest pointer offsets wrap |
| `67 F3 0F AE /6` (`x86_decode`) | `exav-x86` | UMONITOR's register was sized by the operand size, not the address size | 16 bits under `67` |
| VSIB gathers and scatters (`x86_decode`) | `exav-x86` | claimed under `67` (no SIB in 16-bit addressing), and gathers whose destination, index and mask registers overlap, which are #UD | refused |
| DWG arc ending at -1.2e99 (`drawing`, timeout) | `exav-render` `dwg/curves.rs` `flatten_arc`, `flatten_ellipse` | the sweep was brought into (0, 2π] by adding 2π until positive, which a float that size never becomes | `rem_euclid`; a non-finite angle draws nothing (`tests/fixtures/fuzz/arc-end-angle-1e99.dwg`) |
| (review of the above) hatch dashes far from the origin | `dwg/hatch.rs` `apply_dashes` | the same pattern: adding a fine period to a cycle start of 1e20 left it unchanged, with nothing drawn to stop the loop | the cycles counted first; too many draw the span solid |
| (review of the above) a hatch or line a float's range wide | `dwg/hatch.rs` `pattern_segments`, `dwg/linetype.rs` | indices cast to `i64` and lengths to `usize` saturated, and their difference or product overflowed | `saturating_sub`; the dash count guard in `f64` |
| JPX decoded at a reduced size (`imagehash`, 7 panics) | hayro-jpeg2000 0.4.1 `j2c/decode.rs` `store`, through exav-render's `pdf_image::decode_jpx` | a reduced decode places its samples with full-resolution coordinates: an image area offset or a subsampled component in a second tile underflows a subtraction or slices past a row (or, offset, draws nothing), and a column of tiles empty at that size is a zero chunk size | `decode_jpx` refuses a reduced decode of those layouts (`Siz::reducible`), as pdf.js's decoder failing; full-size decodes unchanged (`a_reduced_jpx_decode_the_decoder_cannot_place_fails_cleanly`, files written by OpenJPEG in `tests/fixtures/images/make.py`) |
| JBIG2 stream of 418 bytes declaring a 16,504 by 65,359 region on a 120 by 64 page (`imagehash`, timeout) | exav-render `pdf_image/jbig2.rs` and `image/jbig2.rs`, through hayro-jbig2 0.3.1 `decode/generic.rs` | the budget counted the page bitmap only; hayro-jbig2 decodes each region at its declared size (up to 65,535 by 65,535) wherever it lies, so a region far off the page took 135 MB and minutes | the bitmaps the region segments declare count against the budget too, in both organisations of a file (`region_pixels`; `a_jbig2_region_larger_than_the_budget_is_refused`, segments written in the test). Symbol dictionaries, whose symbol sizes are coded in the data, are still bounded by hayro-jbig2's own limits only |
| TIFF LZW strip without a clear code (`imagehash`, panic in debug builds) | `weezl` 0.1.10 `decode.rs` (the vendored TIFF decoder's LZW) | a `debug_assert!` held that a TIFF table never reaches 4,095 codes; release builds decode the strip | weezl 0.1.12, whose only change is that assertion, corrected upstream (`a_tiff_lzw_strip_filling_its_table_without_a_clear_code_decodes`, a strip written in the test) |
| streamOptimized VMDK, grain-table marker counting 2^64 - 1 sectors (`analyze`, CI smoke run, overflow panic) | `formats/vmdk.rs` `read_markers` | the marker's skip saturated the walk position to `usize::MAX`, and the loop condition then added 512 to it | `pos.saturating_add(512)` (`a_metadata_marker_that_skips_past_the_end_of_the_file_ends_the_walk`) |
| ZIP Implode member whose Huffman table has 256 length bytes (`unpack`, 2 overflow panics) | `zip` 8.6.0 `legacy/implode.rs` `read_huffman_code`, through `formats/zip.rs` | the table's byte count was computed as `byte + 1` in `u8`, so 255 overflowed; containment turned it into a corrupt archive, losing the other members | `zip` 9.0.1, which counts in `usize` (`implode_tree_size_255_is_not_a_panic`, a ZIP written in the test) |
| JBIG2 stream of 227 bytes, generic region of hundreds of millions of pixels (`imagehash`, timeout and 2 slow units) | exav-render `pdf_image/jbig2.rs` and `image/jbig2.rs`, through hayro-jbig2 0.3.1 | regions were charged at a bit a pixel against the budget, a memory measure, but decoding costs time per pixel: ~5 s in a release build at a 64 MiB budget, and the viewer's 1 GiB budget allows 16 times as much | a region's declared pixels are also charged at a byte each (`a_region_declaring_more_pixels_than_the_budget_is_refused`, `tests/fixtures/images/jbig2_region_bomb.seg`) |
| JPEG of 206 by 64,540 pixels, 1.6 KB (`imagehash`, slow unit) | none | a real 13 MP decode and hash: 0.1 s in a release build, 9 s only under the fuzzer's sanitizer and coverage | not a bug; no change |
| 12.6 KB archive reaching the 100,000-member limit (`full_pipeline`, slow unit) | none | the member limit working as designed: ~1.1 s at `opt-level` 1 for 100,000 members, ~22 s per scan under the fuzzer, four scans per input | not a bug; no change |
| PCRE `\bword` on `1\x9aword` (`pcre`, the two engines disagreed) | vendored fancy-regex 0.19.2 `vm.rs`, `\b`, `\B` and their half forms | in `BytesMode::Ascii` the VM asked regex-automata's Unicode word boundary, which reads the bytes beside the position as UTF-8: a byte over 0x7F was taken with the byte before it for a letter, so no boundary was found where `regex` and PCRE2 find one. A signature using `\b` beside a high byte missed | the ASCII boundary functions in that mode (`a_word_boundary_beside_a_high_byte_reads_the_same_in_both_engines`; `fancy_regex/README.md` records the change) |
| PCRE `(\bb)x*` on `c\b\x9e` (`pcre`, the two engines disagreed) | vendored fancy-regex `compile.rs` `options_to_rabuilder` | the delegated engines kept regex-automata's default `utf8_empty(true)` in bytes mode: an empty match at a position before a byte over 0x7F was skipped as splitting a UTF-8 character, so a delegated repeat that can match nothing failed the whole pattern there | `utf8_empty` only in `BytesMode::Unicode` (same test) |
| safetensors sniff of an object whose first read failed (`seekable`, CI smoke run, index out of bounds) | `formats/aimodel.rs` `is_safetensors_in` | `Probe::head` is the start of the object and `len` its length; the sniff checked `len` and then indexed `head`, which a failed read leaves empty or short | the head's own length is checked, and the header is read as far as the head goes (`a_head_shorter_than_the_object_is_not_sniffed_past_its_end`) |
| JPEG 2000 stream of 486 bytes declaring 2,097,181 by 17 pixels (`analyze`, CI smoke run, timeout) | none | the decode behind a `fuzzy_img#` signature, within the budget an object held whole may take (256 MiB by default): 1.5 s in a release build, over 14 s under the sanitizer | not a bug; the fuzz options give a scan 8 MiB for it (`fuzz/options.rs`), as `imagehash` does with 64 MiB |
| bz2 bomb under `--alert-exceeds-max`, all-match mode (`full_pipeline`, found by a synthesized seed) | `lib.rs` `analyze_all_source` | the walk stopped by a budget ends as the alert (`limits_outcome`), and the match on its outcome had arms for `Limits`, `Unscannable` and `PasswordProtected` but not for that: the alert was dropped and the scan reported `Complete` with nothing found, which `--all-matches` printed as clean | the alert is a name in the list, as the unfinished-search arm already did (`all_matches_names_the_budget_that_stopped_the_walk`) |
| RAR volume numbered 65535 (RAR4) or 2^64 - 1 (RAR5) (`volumes`, overflow panic) | `formats/rar.rs` `join_rar4`, `join_rar5` | the refusal message added one to the number it had read, in its own width; release builds check overflow, so the panic was real and became `Unscannable` for the whole set instead of the volume being named | the sum in `usize` / saturating (`a_volume_numbered_65535_is_refused_by_name_not_by_a_panic`, `a_rar5_volume_numbered_2_pow_64_minus_1_is_refused_by_name_not_by_a_panic`) |
| `"secret" xor(1-255)` over 64 KB (`analyze`, 6 execs a second after the YARA rules were added; 3 s a scan) | `yara/matcher.rs` `PatternMatcher::search` | every position was compared with every key in the range, 255 times the work, and an `xor` pattern is never gated by an atom, so every scan paid it; a 16 MiB object took 9 s | the one key a position can match with is its first byte's (`a_wide_xor_range_does_not_cost_a_comparison_per_key_per_position`, `xor_finds_each_key_where_it_was_used`) |
| `/a.{0,32}b[^\x00-\x1f]+c\b/s` over 2 MiB of text (`full_pipeline`, timeout, all-match mode) | the YARA regex matcher | a start position's match runs to the end of the text, so the work is quadratic in it; yara's own engine has the same shape | not a bug in exav: the rule is the cost (`fuzz/db/fuzz.yar` bounds its repetition) |
| InstallShield Z table of 498 bytes (`unpack`, 8-hour run, OOM at 1.5 GB, 10 s) | `formats/ishield_z.rs` `declared_members` | `unshield` builds an entry for each of `dirs` x `dir_files` (two `u16`) before checking anything, and a directory record whose chunk size is 0 is read again for the next, so a few bytes ask for billions of entries; the walk's `MAX_ENTRIES` came after | the members the records declare are summed first, as `unshield` walks them, and a table over `MAX_ENTRIES` is reported as unexamined (`a_table_declaring_more_members_than_the_walk_bound_is_reported_not_built`, `a_table_of_many_directories_each_declaring_many_members_stays_small`) |
| 3.5 KB YARA rule with an error inside 15 open parentheses (`yara`, 8-hour run, timeout; 5.6 s in a release build) | `yara/compiler.rs` `check_paren_depth` | `yara-x-parser` (1.21 too) tries each `(` as a boolean group and as an arithmetic one and keeps nothing of the first try, so a rule that fails inside `d` parentheses costs about 2^d steps; its fuel (100M steps) is not configurable | nesting past 10 is refused before the parse (it was 12, until a rule with 12 took 6 s under the sanitizer), strings, comments and regular expressions skipped (`a_rule_with_an_error_deep_in_parentheses_is_refused_fast`, `a_rule_with_an_error_in_twelve_parentheses_is_refused_fast`, `nesting_up_to_the_bound_compiles_and_one_more_is_refused`) |
| RAR5 encrypted headers asking for 2^24 PBKDF2 iterations (`full_pipeline`, 8-hour run, two slow units of 21 and 28 s under the sanitizer) | `formats/rar5_crypt.rs` `find_keys_within` | one derivation at the largest count RAR writes is 2.6 s in a release build, and the bound on a scan's derivations (2^25 iterations) allowed two. The bound was also kept in each archive's cache, and an archive inside another starts a cache of its own; RAR3's (256 derivations of 2^18 SHA-1 rounds) was kept the same way | the bound is 2^22 and the scan's (0.65 s; the two units still take 11 and 14 s under the sanitizer because `full_pipeline` scans an input four times to compare the answers), counted in `Budget`: a count past it is reported as encrypted like a member no password opens, and a refused derivation is not charged (`a_count_whose_derivation_exceeds_the_scan_bound_is_not_derived`, `archives_of_one_scan_share_the_derivation_bound`, and RAR3's `archives_of_one_scan_share_the_derivation_limit`) |
| 805-byte JPEG declaring a large image (`imagehash`, 8-hour run, slow unit, 10 s under the sanitizer) | none | the grey conversion and Lanczos resize of a 16 MiB image: 0.44 s in a release build. A different filter would change the hash, which must be ClamAV's | not a bug; the target gives the hasher 4 MiB (`HASH_BUDGET`), as for the JPEG 2000 row above |
| LZVN block (DMG, from the differential test against Apple's decoder, not the fuzzer) whose payload ends before its end opcode, or whose declared payload is longer than the input yet ends | `formats/lzfse.rs` `lzvn_block` | any shortfall of the payload was called "cut" when the input was shorter than declared, even when the end opcode had been read; a cut run is not reported as damaged by DMG | cut only when the payload ends without its end opcode and the input ends there; otherwise damaged (`an_lzvn_payload_longer_than_the_input_that_still_ends_is_damaged_not_cut`) |
| LZVN instruction past the block's declared size, under a tighter output limit (same test) | `formats/lzfse.rs` `lzvn_block` | the size check ran before the limit and before the part that fits was written, so output past the limit was reported as damage and the fitting part dropped | the block's size is a lowered output limit; whichever is reached first ends the block (`an_lzvn_instruction_past_the_block_size_is_damaged_and_clipped`, `the_output_limit_comes_before_a_block_size_it_is_inside_of`) |
| DCL stream of one byte, `02` (same test, against `blast.c`) | `formats/dcl_explode.rs` `run` | both header bytes were read before either was judged, so a bad first byte with no second one was called cut | each byte judged as read (`a_bad_header_or_distance_is_invalid`) |
| InstallShield Z member that stops short or is damaged part way (review) | `formats/ishield_z.rs` `extract_ishield_z` | a stream that ran out of input came out as a whole member with nothing said, and one that failed part way dropped what it had decoded | the decoded start is kept and the member reported, as for NSIS (`a_member_cut_inside_its_stream_keeps_its_prefix_and_is_reported`, `a_member_damaged_part_way_keeps_its_prefix_and_is_reported`, `a_member_whose_range_runs_past_the_file_is_reported`) |
| FAT12 volume with a directory at cluster 1, inside a sparse VMDK (`vdisk`, first run, 3 overflow panics) | `fatfs` 0.3.6 `fs.rs` `sector_from_cluster`, through `formats/fat.rs` | the crate subtracts 2 from any cluster number it reads (a directory entry's, or the next one of a chain) without looking at it; the panic reached the walk's boundary and ended the whole volume as undecodable. Upstream master has the same line | the crate was replaced by the in-tree reader, which takes no cluster number on trust; a directory at cluster 1 is reported as damage after the rest of the volume is walked, and `vdisk` and `fsimage` assert no walk ends as "panicked" (`a_directory_at_cluster_1_ends_the_walk_as_damaged_after_the_rest_of_the_volume`, `a_file_at_cluster_1_is_reported_and_the_other_files_come_out`) |
| PowerPoint 95 paragraph with a bullet size over 4,294,967 (`slides_ppt`, 4 overflow panics) | `slides/ppt/ppt95.rs` `para_props` | the size is kept from 25 to 400, but `bool::then_some(bsize * 1000)` takes its argument whether or not the condition holds, so a `u32` that large overflowed (a panic in release builds, which check overflow, and in the viewer's wasm a wrapped value that was then dropped) | the product is taken only of a size in range (`a_bullet_size_out_of_range_is_dropped`) |
| 1.4 MB of `Content-Type: message/rfc822` (the `nesting` suite, not the fuzzer; stack overflow) | `formats/email.rs`, `mail-parser` 0.11.9 | the parser keeps messages in messages (`PartType::Message`) with no depth limit, and dropping the chain recursed once per level | the result is taken apart without recursion (`Parsed`); the same review found that the parts of attached messages were never read, so an attachment of a forwarded mail scanned clean (`mime_parts`, `the_parts_of_an_attached_message_are_members_too`) |
| 40 KB YARA condition of `not not not ...`, `1 << 1 << ...`, `a contains b contains ...` (the `nesting` suite; stack overflow on 2 MiB) | `yara/compiler.rs` `check_paren_depth`, `yara-x-parser` | one recursion per operator of a chain, in the parser and in the tree built from it | a chain past 256 operators, and brackets nested past 12, are refused before the parse (`a_long_chain_of_operators_is_refused_not_recursed_into`) |
| 200,000 signs in a Visio formula (the `nesting` suite; stack overflow on 256 KB) | `slides/vsdx/formula.rs` `unary` | a call per sign, outside the step counter that bounds the rest of the parser | the signs are read in a loop, and counted (`a_formula_of_signs_is_refused_not_recursed_into`) |
| 32 nested `draw:g` of an ODP, 11 nested Visio shapes (the `nesting` suite; stack overflow on 512 KB) | `slides/model.rs` `ListStyle` | the nine outline levels were inline (6 KB), so every `TextBody` and `Sp` on a function's stack took that, and the shape builders had frames of 28 to 40 KB | the levels, which no reader ever filled, are a list empty until one is (`odf_drawings_and_presentations`, `visio_pages`, `make stack-frames`) |
| a ZIP in a ZIP, 15 levels (a CLI run under `ulimit -s`, then `scripts/stack-frames.py`) | `formats/zip.rs` `walk`, `formats/xz.rs` `XzReader` | a `ZipFile` (decoders inline, 40 KB) and the XZ decoder tables (30 KB) lived in the frame of the walk while a member was scanned | opened in functions of their own, and boxed (`make stack-frames`) |
| 19 KB image whose HFS+ catalog leaves are each other's next (`vdisk`, 7-hour run, timeout: 21 s under the sanitizer, 1 s in a release build) | `formats/hfsplus.rs` `Tree::scan` | the chain was bounded by the nodes the catalog fork declares (the virtual disk's size over the node size), and each is read as valid from a disk of zeros | a leaf met again is damage (Brent's cycle check) (`a_leaf_chain_that_loops_is_damage_not_a_walk_to_the_end_of_the_fork`) |
| PPMd header declaring a 4 GiB model (`saturate`) | `formats/ppmd7/model.rs`, `ppmd8/model.rs` | the arena was filled with zeros as it was made, so the pages were touched | `vec![0; n]`, which asks for zeroed pages (`saturate`) |

Header numbers at the top of their range are what unchecked sums overflow on,
and libFuzzer's stock mutations seldom put one in a chosen field. Two things
cover that. The `unpack` and `analyze` targets share a custom mutator
(`fuzz/extreme.rs`) that sets one 2-, 4- or 8-byte field to such a value a
quarter of the time. And `crates/exav-unpack/tests/suites/extreme.rs` does it
exhaustively and deterministically for the disk-image formats: every field of a
valid container, one at a time, must not panic the decoder. `make test-wasm`
runs it on wasm32 too, where the production build wraps silently and a test
build aborts.

exav-render's `tests/fixtures/fuzz/` also holds damaged drawings from early
`drawing` runs (an over-long run of modular-number continuation words, an
entity declaring 2.3 GB of graphic data, a handle seed of `u64::MAX`, a
viewport with 2^31 frozen layers). They run against the DWG reader in
`the_fuzzers_findings_fail_quickly_and_cleanly` (`tests/dwg.rs`), which also
bounds the memory a finding may take; the modular-number reader refuses an
over-long run (`modular_numbers_read_as_the_spec_examples` in
`exav_unpack::dwg`'s `bits.rs`).

Verdict note: decoder panics and corrupt-stream errors map to **`Unscannable`**
(recognised format, undecodable bytes), distinguished from genuine resource
bounds (`LimitsExceeded`) via `LimitHit`'s `LimitKind`. An 8-hour fuzz campaign
across 10 targets found 2 engine bugs and 2 dep panics, deduplicated from 27
crash artifacts (25 ndb_compile = root causes #5/#6, 2 unpack = dep panics
contained by `catch_unwind`). All 4 dep panics (CAB×2, lzxd, delharc) are
caught by the same `catch_unwind` boundary.
