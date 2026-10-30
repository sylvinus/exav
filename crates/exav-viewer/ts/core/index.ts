/**
 * `@exav/viewer`: the framework-free core. Detection, sources, sessions and
 * the plugin contract; each format is a plugin imported from its own subpath
 * (`@exav/viewer/pdf`, `@exav/viewer/cad`...), and the default UI is
 * `@exav/viewer/react`.
 */
export * from "./types.js";
export { writable, derived, type Store, type WritableStore } from "./store.js";
export { createViewer, errorCode } from "./viewer.js";
export { createDetector, sniff, HEAD_BYTES } from "./detect.js";
export { MATCHERS, WASM_IMAGES, SIGNATURES, UNKNOWN_TYPES, BUILTIN_ORDER, CONVERTED_FORMATS } from "./formats.js";
export { canOpenInTab, createSourceReader, sameSource, type OwnedSourceReader } from "./source.js";
export { resolveInTree } from "./tree.js";
export {
  fitCamera,
  fitRect,
  MAX_PICTURE_EDGE,
  MAX_PICTURE_PIXELS,
  planRect,
  RasterError,
  rasterSize,
  tilePlan,
  tileRect,
  type RasterErrorCode,
  type RectPlan,
  type Tile,
} from "./pictures.js";
export { createPictures, drawTiled, encodeBitmap, picturesOver } from "./raster.js";
export { TOKENS, themeOf, type FrameTheme, type Token } from "./theme.js";
export { builtinTranslate, MESSAGES, type MessageKey, type Translate } from "./messages.js";
export { printPictures, type PrintOptions } from "./print.js";
