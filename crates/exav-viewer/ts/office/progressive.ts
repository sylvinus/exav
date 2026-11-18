/**
 * Whether a deck or a document is large enough for the engines' progressive
 * layout: `load()` then resolves once the first slides or pages are laid
 * out, and the rest follows in the background. On a short file it costs
 * more than it saves (the first slide comes later), so it is only asked for
 * past a size read off the ZIP's central directory (`zipDirectory`), without
 * inflating anything.
 */
import type { ZipDirectory } from "./zip.js";

/** Slides from which a deck is laid out progressively. */
export const PROGRESSIVE_SLIDES = 32;

/** Bytes of `word/document.xml`, uncompressed, from which a document is. */
export const PROGRESSIVE_DOCUMENT_BYTES = 64 << 10;

/** Whether the engine should lay a PPTX or a DOCX with `directory` out progressively. */
export function wantsProgressive(kind: "pptx" | "docx", directory: ZipDirectory | null): boolean {
  if (!directory) return false;
  const { members } = directory;
  if (kind === "docx") return (members.get("word/document.xml") ?? 0) >= PROGRESSIVE_DOCUMENT_BYTES;
  let slides = 0;
  for (const name of members.keys()) if (/^ppt\/slides\/slide\d+\.xml$/.test(name)) slides++;
  return slides >= PROGRESSIVE_SLIDES;
}
