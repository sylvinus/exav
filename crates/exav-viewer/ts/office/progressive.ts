/**
 * Whether a deck or a document is large enough for the engines' progressive
 * layout: `load()` then resolves once the first slides or pages are laid
 * out, and the rest follows in the background. On a short file it costs
 * more than it saves (the first slide comes later), so it is only asked for
 * past a size read off the ZIP's central directory, without inflating
 * anything.
 */

/** Slides from which a deck is laid out progressively. */
export const PROGRESSIVE_SLIDES = 32;

/** Bytes of `word/document.xml`, uncompressed, from which a document is. */
export const PROGRESSIVE_DOCUMENT_BYTES = 64 << 10;

const EOCD = 22;
const CENTRAL = 46;

/**
 * The uncompressed size of each member of a ZIP, by name, from its central
 * directory; `null` for anything else (ZIP64, a damaged directory), which
 * is left to the engine to judge.
 */
export function zipMembers(bytes: Uint8Array): Map<string, number> | null {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lowest = Math.max(0, bytes.length - EOCD - 0xffff - 1024);
  for (let at = bytes.length - EOCD; at >= lowest; at--) {
    if (view.getUint32(at, true) !== 0x06054b50) continue;
    const count = view.getUint16(at + 10, true);
    const size = view.getUint32(at + 12, true);
    const offset = view.getUint32(at + 16, true);
    // A ZIP64 directory has 0xffffffff here, and is left to the engine.
    if (offset + size > at) continue;
    const members = new Map<string, number>();
    const names = new TextDecoder();
    let p = offset;
    for (let i = 0; i < count; i++) {
      if (p + CENTRAL > offset + size || view.getUint32(p, true) !== 0x02014b50) return null;
      const nameLength = view.getUint16(p + 28, true);
      const skip = nameLength + view.getUint16(p + 30, true) + view.getUint16(p + 32, true);
      if (p + CENTRAL + skip > offset + size) return null;
      members.set(names.decode(bytes.subarray(p + CENTRAL, p + CENTRAL + nameLength)), view.getUint32(p + 24, true));
      p += CENTRAL + skip;
    }
    return members;
  }
  return null;
}

/** Whether the engine should lay `bytes`, a PPTX or a DOCX, out progressively. */
export function wantsProgressive(kind: "pptx" | "docx", bytes: Uint8Array): boolean {
  const members = zipMembers(bytes);
  if (!members) return false;
  if (kind === "docx") return (members.get("word/document.xml") ?? 0) >= PROGRESSIVE_DOCUMENT_BYTES;
  let slides = 0;
  for (const name of members.keys()) if (/^ppt\/slides\/slide\d+\.xml$/.test(name)) slides++;
  return slides >= PROGRESSIVE_SLIDES;
}
