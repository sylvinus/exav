/**
 * `@exav/viewer`: the framework-free core. Detection, sources, sessions and
 * the plugin contract; each format is a plugin imported from its own subpath
 * (`@exav/viewer/pdf`, `@exav/viewer/cad`...), and the default UI is
 * `@exav/viewer/react`.
 */
export * from "./types.js";
export { writable, derived, type Store, type WritableStore } from "./store.js";
export { createViewer, errorCode } from "./viewer.js";
export { createDetector, HEAD_BYTES, type Finding, type Inspector, type OfficeFinding, type Officer, type Sniffer } from "./detect.js";
export { FormatMismatch, mismatchOf } from "./mismatch.js";
export { MATCHERS, WASM_IMAGES, CONTAINER_TYPES, UNKNOWN_TYPES, BUILTIN_ORDER, CONVERTED_FORMATS } from "./formats.js";
export { canOpenInTab, createSourceReader, sameSource, type FilePart, type OwnedSourceReader } from "./source.js";
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
export { createHighlights, findQuote, fold, highlightId, MAX_HIGHLIGHT_RECTS, MAX_HIGHLIGHT_TEXT, MAX_HIGHLIGHTS, type HighlightTarget, type Highlights } from "./highlights.js";
export { TOKENS, themeOf, type FrameTheme, type Token } from "./theme.js";
export { builtinTranslate, MESSAGES, type MessageKey, type Translate } from "./messages.js";
export { printPictures, type PrintOptions } from "./print.js";
