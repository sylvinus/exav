# zenjxl-decoder-macros as exav ships it

Version 0.3.9 of [zenjxl-decoder-macros](https://crates.io/crates/zenjxl-decoder-macros)
(BSD-3-Clause, `LICENSE` beside this file), the derive macros of
[zenjxl-decoder](../zenjxl-decoder/EXAV.md). Used by `@exav/viewer`'s image
module, through `[patch.crates-io]` in `../../Cargo.toml`; nothing else of exav
builds this copy.

What differs from the published crate:

- `proc-macro-error2` is gone: it is unmaintained (RUSTSEC-2026-0173), and
  cargo reports it as code a future Rust will reject. `abort!` is a local macro
  in `src/lib.rs` that panics with the same message, and `#[proc_macro_error]` is
  removed. The macros only run on the decoder's own structs, so an error is a
  mistake in the decoder's source and the message is what is needed; rustc no
  longer points at the field.
- `Cargo.toml.orig`, `Cargo.lock` and the dependency line of
  `proc-macro-error2` are left out.

Nothing else is changed. Checked by decoding the six JPEG XL files of the
repository's fixtures and demo with this copy and with the published one: the
pixels are identical.
