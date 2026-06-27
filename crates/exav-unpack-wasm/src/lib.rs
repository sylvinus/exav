//! WebAssembly bindings for `exav-unpack` — memory-safe, in-browser archive
//! extraction with no native/C dependencies.
//!
//! Build a browser package with `wasm-pack build --target web` (or `bundler`),
//! then from JavaScript:
//!
//! ```js
//! import init, { detect_format, unpack } from "./pkg/exav_unpack_wasm.js";
//! await init();
//! const members = unpack(new Uint8Array(await file.arrayBuffer()));
//! for (const m of members) console.log(m.name, m.data.length); // m.data: Uint8Array
//! ```

use exav_unpack::{detect, extract, Budget, Limits};
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

/// Detect the archive/container format from magic bytes. Returns the format name
/// (e.g. `"Zip"`, `"Rar"`, `"Arj"`) or `null` if unrecognised.
#[wasm_bindgen]
pub fn detect_format(data: &[u8]) -> Option<String> {
    detect(data).map(|f| format!("{f:?}"))
}

/// Extract a container's members. Returns a JS array of `{ name: string, data:
/// Uint8Array }`. Throws a string error if the format is unrecognised or
/// extraction fails (including when the built-in decompression-bomb limits are
/// hit). Members are returned with hostile names verbatim — the caller is
/// responsible for sanitising paths before writing to disk.
#[wasm_bindgen]
pub fn unpack(data: &[u8]) -> Result<Array, JsValue> {
    let fmt = detect(data).ok_or_else(|| JsValue::from_str("unrecognised archive format"))?;
    let mut budget = Budget::new(Limits::default());
    let entries =
        extract(fmt, data, &mut budget).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = Array::new();
    for e in entries {
        let obj = Object::new();
        Reflect::set(&obj, &JsValue::from_str("name"), &JsValue::from_str(&e.name))?;
        let bytes = Uint8Array::from(e.data.as_slice());
        Reflect::set(&obj, &JsValue::from_str("data"), &bytes)?;
        out.push(&obj);
    }
    Ok(out)
}
