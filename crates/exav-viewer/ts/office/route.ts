/** Which converter takes a file: kept apart from the converters, so that the plugins' definitions load none of them. */
import type { ConversionOptions, ConvertedFormat } from "./index.js";

/** The package's own converter each kind goes to first, where it does. */
export type Native = "sheets" | "slides" | "docs";

const NATIVE: Partial<Record<ConvertedFormat, Native>> = {
  xls: "sheets",
  ods: "sheets",
  numbers: "sheets",
  ppt: "slides",
  odp: "slides",
  keynote: "slides",
  odg: "slides",
  // Visio 2013 and later (.vsdx); a binary .vsd is not recognised and goes on.
  visio: "slides",
  doc: "docs",
  odt: "docs",
  rtf: "docs",
};

/**
 * Which of the package's converters a file of `kind` goes to first, if any:
 * none with `converter: "external"`; text documents only with `converter:
 * "exav"`, or where no external converter is set, since the external one
 * is better at them where there is one.
 */
export function nativeFirst(kind: ConvertedFormat, options: ConversionOptions): Native | null {
  const native = NATIVE[kind] ?? null;
  if (!native || options.converter === "external") return null;
  if (native === "docs") return options.converter === "exav" || options.externalConverter === undefined ? "docs" : null;
  return native;
}

/** Whether a file of `kind` goes to exav-render's `slides` first. */
export const slidesFirst = (kind: ConvertedFormat, options: ConversionOptions) => nativeFirst(kind, options) === "slides";

/** Whether a file of `kind` goes to exav-render's `docs` first. */
export const docsFirst = (kind: ConvertedFormat, options: ConversionOptions) => nativeFirst(kind, options) === "docs";
