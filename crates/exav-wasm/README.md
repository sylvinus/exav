# exav-wasm

The scanning core of [**exav**](https://github.com/sylvinus/exav) compiled to
WebAssembly. Build it for `wasm32-wasip1` and run it inside a WASM runtime
(wasmi/wasmtime) to scan files in a fully sandboxed environment.

```sh
cargo build -p exav-wasm --target wasm32-wasip1 --release
```

YARA is intentionally omitted (no WASM-in-WASM runtime); archive formats forward
to [`exav-unpack`](https://crates.io/crates/exav-unpack) via Cargo features
(`--no-default-features --features zip` for a minimal module).

For in-browser archive extraction, see the `exav-unpack-wasm` crate in the
[repository](https://github.com/sylvinus/exav). Licensed under MIT.
