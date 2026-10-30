# Replacing pdf.js with hayro in @exav/viewer: what it would bring and cost

Measured on 1370 PDFs (13 October 2026) with the harness in `scripts/pdf-compare/`, plus a
reading of hayro's documentation and issues. hayro 0.8.0, pdfjs-dist 6.4.299 (the viewer's), poppler
25.03.0 (`pdftoppm`, as the reference), Chromium from Playwright.

## What was measured

The corpus is the 990 PDFs of `test/pdfs` in mozilla/pdf.js, the 364 of `hayro-tests/pdfs` in
LaurenzV/hayro, and 16 of ours, deduplicated by hash. Both projects' sets are regression tests chosen for
hard cases (broken files, odd fonts, shadings, bombs), so they say more about edge cases than about PDFs
in the wild, and each favours its own project. The first three pages of each were rendered at 72 dpi on
white by hayro (native), pdf.js (in Chromium), poppler, and hayro compiled to wasm (in the same Chromium,
with and without SIMD). A page's distance to poppler is the mean absolute difference of luminance after a
3 by 3 blur, and the share of pixels more than 64 off ("far").

## Results

**Opening.** Of 1370 files, at least one page rendered for hayro 1279, pdf.js 1276, poppler 1267. Where
poppler renders, hayro failed on 9 and pdf.js on 8; where poppler fails (103), hayro rendered 21 and pdf.js
17. hayro cannot open an encrypted PDF at all (19 files fail with a decryption error), including at least
one that pdf.js and poppler open without a password.

**Fidelity** (1141 pages with the same size in all three):

| | hayro | pdf.js |
|---|---|---|
| pages with under 0.5% of pixels far from poppler | 80.7% | 74.1% |
| pages with over 5% far | 5.4% | 5.6% |
| pages closer to poppler (by more than a point) | 42 | 26 |
| shadings, pages under 0.5% far | 23 of 26 | 15 of 26 |
| fonts (by file name) | 70 of 73 | 56 of 73 |
| tiling patterns | 26 of 35 | 21 of 35 |
| JPEG 2000 | 4 of 9 | 1 of 9 |
| masks, blends, transparency | 30 of 41 | 30 of 41 |
| annotations and forms | 34 of 37 | 34 of 37 |

Poppler is not the truth, and hayro and poppler may share habits (anti-aliasing, hinting) that pdf.js does
not. A page rendered **blank** by hayro where the others draw something: 18 (the non-embedded CJK fonts
`noembed_jis7` and `noembed_sjis` among them), against 4 for pdf.js. Page sizes: pdf.js equals poppler's on
1406 pages and differs on 72; hayro equals it on 1150, is one pixel off on 260 (rounding) and differs on 70.

**Time**, per page, first three pages, in milliseconds:

| | median | p90 | p99 | max |
|---|---|---|---|---|
| hayro, native | 1 | 8 | 64 | 3370 |
| hayro, wasm with SIMD, in Chromium | 19 | 46 | 212 | 3979 |
| hayro, wasm without SIMD, in Chromium | 45 | 169 | 833 | 20550 |
| pdf.js, in Chromium | 20 | 49 | 217 | 5129 |

The four rows are the 1481 pages all four rendered. Over every page a renderer drew, hayro native took
up to 47084 ms (one page), and poppler's median was 19 ms, its p99 570 and its max 41696 (process time
divided by pages, startup included).

In the browser the SIMD build is on par with pdf.js (faster on 874 pages, slower on 603); without SIMD it is
twice as slow at the median and four times at the tail. Two pages cost hayro native 47 s and 8 s where pdf.js
took 0.6 s and 2.1 s.

**Memory.** hayro native: median 7 MB of resident memory, p99 41 MB, but 8.9 GB (killed) on
`bomb_giant.pdf`, a 123 KB file whose JBIG2 data declares 100000 by 100000 pixels. In wasm the memory is
capped by the module's maximum (the viewer sets one per module), median 6 MiB after a page, p99 58 MiB, max
211 MiB.

**Size.** hayro as wasm: 4.3 MB raw, 3.0 MB with SIMD after `wasm-opt -Oz` (1.2 MB brotli), including its
JPEG 2000, JBIG2 and CCITT decoders and the 14 standard fonts (`embed-fonts`). pdf.js: `pdf.min.mjs` 459 KB
plus `pdf.worker.min.mjs` 1.26 MB (about 0.5 MB gzipped), 0.8 MB of standard fonts, 1.7 MB of CMaps and its
own wasm (1.6 MB). The viewer today also ships hayro's JPEG 2000 and JBIG2 decoders as two more wasm modules
for pdf.js; a hayro viewer would not need them.

## What hayro is not (its documentation, issues and the files above)

hayro is a rasterizer and an interpreter, not a viewer. It has no encryption support ("the main missing
feature"), no blending and isolation, no knockout groups, no color-key masking, and no support for
non-embedded CID fonts. It has no JavaScript, no XFA, and no forms beyond what appears on the page. The
project calls itself experimental, is at 0.8 with one main maintainer, and says no work has gone into speed.
Open issues include a `q` flood exhausting memory, a crash on large pattern steps, a panic in `ArrayIter`
and a memory allocation failure. I found no CVE for hayro, nor any fuzzing beyond a `hayro-fuzz` crate.

hayro does hand over what a text layer needs: each glyph with its Unicode (from `ToUnicode`, else its
name) and its transform, from `Device::draw_glyph_run`. It does not build a text layer, selection, search,
link or outline handling, page labels or thumbnails; open issues say Type 3 fonts without `ToUnicode` have no
Unicode and that the glyph-name table is incomplete.

## What the viewer would have to rebuild

`ts/pdf/engine.ts` (520 lines) is the adapter to pdf.js, and `ts/pdf/reader.ts` (663) the reader on top of
it. Of what pdf.js does for them, hayro would replace the rendering only. To rebuild: the text layer
(positioned spans for selection and the browser's find, from glyph runs), link annotations (hayro has
`render_annotations` but I found no link list in it), the outline and named destinations, page labels, and
passwords. The viewer reads no password today, so encrypted files fail with both; what changes is the
owner-password-only files pdf.js opens. Forms and annotations would be drawn but not editable, as now.

## Security

pdf.js has had arbitrary code execution through a crafted font (CVE-2024-4367), a class that needs `eval`
and does not exist in a Rust renderer. hayro's core forbids `unsafe_code`, but `hayro-interpret` turns on
`hayro-syntax`'s `unsafe` feature (zlib-rs, SIMD in the image decoders), and panics and out-of-memory are the
failures to expect, not corruption. In the viewer a wasm module is contained by its memory cap and its
worker (the crash costs the page it was reading); in the scanner the same OOM kills the process, which is why
exav's PDF text reader screens a PDF before giving it to hayro (see `exav_unpack::text`).

## Reading

- On this corpus hayro draws as well as pdf.js or better against poppler (shadings, fonts, JPEG 2000), and
  in wasm with SIMD it costs the same time per page; native it is twenty times faster.
- It is not a replacement: the interactive parts of the viewer sit on pdf.js, and hayro cannot open
  encrypted files, draws some pages blank, and has outliers (47 s, 8.9 GB) that pdf.js does not.
- A path that costs less than a swap: an optional hayro rasterizer behind the viewer's existing engine
  interface (`pdf({ engine: "hayro" })`), pdf.js kept for the text layer, links and outline of the same
  document, and as the fallback for encrypted files and for pages hayro draws blank. That would drop the two
  image-decoder modules and gain a memory-safe renderer with a bounded footprint, for 3 MB of wasm. A full
  replacement would also mean building the text layer from glyph runs.
- To settle it with more evidence: a corpus of real documents (the first three pages of a sample of public
  PDFs), a human look at the pages where the three disagree, the speed with the text layer, and hayro run
  under the viewer's CSP and memory cap.

## Not measured

Pages past the third. Rotation and `UserUnit` beyond the page sizes. Text layer quality. Print. Zoom
levels other than 1. Memory of pdf.js (Chromium's, not per page). Anything on Firefox or WebKit. The harness
runs hayro once per PDF with a 60 s limit, so a hang past it is a timeout, not a time.
