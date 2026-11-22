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
  pages: "docs",
  rtf: "docs",
};

/** The package's converter for `kind`, whichever goes first. */
export const nativeOf = (kind: ConvertedFormat): Native | null => NATIVE[kind] ?? null;

/** What `options.converter` says for `kind`: one word for every format, or the format's entry. */
function chosen(kind: ConvertedFormat, options: ConversionOptions): "exav" | "external" | undefined {
  const c = options.converter;
  return typeof c === "string" ? c : c?.[kind];
}

/**
 * Which of the package's converters a file of `kind` goes to first, if any:
 * none where `converter` says "external" for it; text documents only where
 * it says "exav", or where no external converter is set, since the external
 * one is better at them where there is one.
 */
export function nativeFirst(kind: ConvertedFormat, options: ConversionOptions): Native | null {
  const native = nativeOf(kind);
  const choice = chosen(kind, options);
  if (!native || choice === "external") return null;
  if (native === "docs") return choice === "exav" || options.externalConverter === undefined ? "docs" : null;
  return native;
}

/** Whether a file of `kind` goes to exav-render's `slides` first. */
export const slidesFirst = (kind: ConvertedFormat, options: ConversionOptions) => nativeFirst(kind, options) === "slides";

/** Whether a file of `kind` goes to exav-render's `docs` first. */
export const docsFirst = (kind: ConvertedFormat, options: ConversionOptions) => nativeFirst(kind, options) === "docs";
