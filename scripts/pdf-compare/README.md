# Comparing PDF renderers: hayro, pdf.js, poppler

The harness behind `docs/PDF-RENDERER-EVALUATION.md`. It renders the first pages of every PDF of a
directory with three renderers at 72 dpi on white, and compares them page by page, with poppler as the
reference.

| Step | Command |
|---|---|
| hayro, native | `cd hayro-eval && cargo build --release`, then `python3 run_hayro.py CORPUS OUT 3` |
| pdf.js, in Chromium | `ls CORPUS/*.pdf > OUT/list.txt; node pdfjs.mjs OUT/list.txt OUT/png-pdfjs 3 > OUT/pdfjs.jsonl` (needs the viewer's `node_modules`: `EXAV_VIEWER_DIR`) |
| poppler | `python3 run_poppler.py CORPUS OUT 3` (needs `pdftoppm`) |
| hayro, in wasm, in Chromium | `cd hayro-wasm && cargo rustc --release --target wasm32-unknown-unknown --crate-type cdylib` (add `RUSTFLAGS="-C target-feature=+simd128"` for the SIMD build), `wasm-bindgen --target web`, `wasm-opt -Oz --enable-simd`, then `node hayro-wasm.mjs OUT/list.txt 3 > OUT/hayrowasm.jsonl` (`HAYRO_WASM_PKG`) |
| compare | `python3 compare3.py OUT` (numpy, Pillow) |

`run_hayro.py` rewrites its output whole every 25 PDFs, as the scripts here never append.

The corpus of the evaluation is the 990 PDFs of `test/pdfs` in mozilla/pdf.js, the 364 of
`hayro-tests/pdfs` in LaurenzV/hayro, and 16 of our own, deduplicated by hash. Both projects' corpora are
regression tests chosen for hard cases, not a sample of PDFs in the wild.
