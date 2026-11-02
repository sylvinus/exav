# zenjxl-decoder as exav ships it

Version 0.3.10 of [zenjxl-decoder](https://crates.io/crates/zenjxl-decoder)
(BSD-3-Clause, `LICENSE` beside this file), itself a fork of the libjxl team's
[jxl-rs](https://github.com/libjxl/jxl-rs). Used by `@exav/viewer`'s image
module, through `[patch.crates-io]` in `../../Cargo.toml`; nothing else of
exav builds this copy.

What differs from the published crate:

- `src/util/clock.rs` is new, and the decoder takes its `Instant` from it
  (`src/api/inner/codestream_parser/sections.rs`, `src/frame/decode.rs`,
  `src/frame/render.rs`). `std::time::Instant::now()` panics on
  `wasm32-unknown-unknown`, and the decoder called it for every frame whether
  or not phase timing (`JXL_PHASE_TIMING`) was asked for. On that target the
  clock reads zero; everywhere else it is `std`'s.
- `tests/`, `benches/` and `src/tests/` are left out, and their targets
  removed from `Cargo.toml`.

Nothing else is changed. The crate is `forbid(unsafe_code)` unless its
`allow-unsafe` feature is on, which exav does not turn on.
