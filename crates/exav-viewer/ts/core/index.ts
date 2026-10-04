/**
 * `@exav/viewer`: the framework-free core. Detection, sources, sessions and
 * the plugin contract; each format is a plugin imported from its own subpath
 * (`@exav/viewer/pdf`, `@exav/viewer/cad`...), and the default UI is
 * `@exav/viewer/react`.
 */
export * from "./types.js";
export { writable, derived, type WritableStore } from "./store.js";
export { createViewer, errorCode } from "./viewer.js";
export { createDetector, sniff, HEAD_BYTES } from "./detect.js";
export { MATCHERS, WASM_IMAGES, SIGNATURES, UNKNOWN_TYPES, BUILTIN_ORDER } from "./formats.js";
export { canOpenInTab, createSourceReader, sameSource, type OwnedSourceReader } from "./source.js";
