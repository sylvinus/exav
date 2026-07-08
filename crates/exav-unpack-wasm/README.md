# exav-unpack-wasm

WebAssembly bindings for [`exav-unpack`](../exav-unpack) — **memory-safe,
in-browser archive extraction** with no server round-trip and no native/C
dependencies. Because `exav-unpack` is pure Rust, the whole extractor (zip, rar,
7z, cab, arj, lha, tar, gz, xz, bz2, iso, cpio, ar, xar, ole, pdf, email, upx)
compiles to `wasm32-unknown-unknown`.

> Excluded from the workspace (it's a wasm32-target artifact, like `fuzz/`).
> Build it with its own manifest / `wasm-pack`.

## Build

```
# one-time
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# from this directory:
wasm-pack build --release --target web      # or --target bundler / nodejs
```

This emits a `pkg/` directory with the `.wasm` module + JS bindings, ready to
publish to npm or import directly.

## JavaScript API

```js
import init, { detect_format, unpack } from "./pkg/exav_unpack_wasm.js";

await init();

const buf = new Uint8Array(await file.arrayBuffer());

detect_format(buf);   // -> "Zip" | "Rar" | "Arj" | ... | null

const members = unpack(buf);   // throws on unrecognised format / extraction error
for (const m of members) {
  console.log(m.name, m.data.length);   // m.data is a Uint8Array
}
```

- `detect_format(bytes)` → the format name (or `null` if unrecognised).
- `unpack(bytes)` → array of `{ name: string, data: Uint8Array }`. Member names
  are returned **verbatim** — sanitize paths before writing them anywhere.

## Notes

- **Sandboxed**: wasm is itself a sandbox, and extraction is bounded
  (decompression-bomb limits), so untrusted input is safe to feed client-side.
- **getrandom**: a transitive dependency (`lopdf`'s mandatory `rand`) links
  `getrandom`, which on wasm needs its JS backend — enabled here via the
  `getrandom/wasm_js` feature. It is never actually *called* during extraction
  (which is fully deterministic); the feature only satisfies the linker.
- **Size**: the raw `.wasm` is a few MB unoptimized; `wasm-pack` runs `wasm-opt`
  to shrink it considerably.
