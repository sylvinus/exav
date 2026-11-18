# zenjxl-decoder as exav ships it

Version 0.3.10 of [zenjxl-decoder](https://crates.io/crates/zenjxl-decoder)
(BSD-3-Clause, `LICENSE` beside this file), itself a fork of the libjxl team's
[jxl-rs](https://github.com/libjxl/jxl-rs). Used by `@exav/viewer`'s image
module, through `[patch.crates-io]` in `../../Cargo.toml`, and by the
`raw_preview` fuzz target (`fuzz/Cargo.toml`), so that the decoder fuzzed is
the one shipped.

What differs from the published crate:

- `src/util/clock.rs` is new, and the decoder takes its `Instant` from it
  (`src/api/inner/codestream_parser/sections.rs`, `src/frame/decode.rs`,
  `src/frame/render.rs`). `std::time::Instant::now()` panics on
  `wasm32-unknown-unknown`, and the decoder called it for every frame whether
  or not phase timing (`JXL_PHASE_TIMING`) was asked for. On that target the
  clock reads zero; everywhere else it is `std`'s.
- A section's buffer is sized by the bytes the input holds, not by the length
  the table of contents declares (`grow_section_buffer` in
  `src/api/inner/codestream_parser/mod.rs`, and the move of the pre-section
  bytes in `non_section.rs`). One entry can declare about 1 GiB, and 0.3.10
  allocated and zeroed it before reading a byte, outside its memory limit: a
  file of 34 bytes took 1 GB. Ported by hand from upstream's commit 5f1b834
  (jxl-rs #856), unreleased when taken; `../../tests/jxl_sections.rs` checks
  it.
- `tests/`, `benches/` and `src/tests/` are left out, and their targets
  removed from `Cargo.toml`.

Nothing else is changed. The crate is `forbid(unsafe_code)` unless its
`allow-unsafe` feature is on, which exav does not turn on.
