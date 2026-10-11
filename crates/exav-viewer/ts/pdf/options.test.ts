import { expect, it } from "vitest";

import { documentOptions, pdfjsAssetDir, pdfjsWasmDir } from "./index.js";

// A host that opens PDFs with pdf.js itself, beside the viewer, reads the
// options and the asset directories from the package's index.
it("the document options and asset directories are exported, and agree", () => {
  const dir = pdfjsAssetDir("/app/", "6.4.299");
  expect(dir).toBe("/app/pdfjs/6.4.299/");
  const options = documentOptions("/app/", "6.4.299");
  expect(options).toMatchObject({ isEvalSupported: false, useSystemFonts: false, cMapUrl: `${dir}cmaps/`, standardFontDataUrl: `${dir}standard_fonts/`, iccUrl: `${dir}iccs/` });
  expect(options.wasmUrl).toBe(pdfjsWasmDir("/app/", "6.4.299"));
  expect(options.wasmUrl.startsWith(`${dir}wasm-`)).toBe(true);
});
