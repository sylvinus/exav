/**
 * A ZIP whose members are named and sized as given. Their bytes are not
 * stored: only the central directory is, which is all `zipMembers` reads.
 */
export function zipOf(members: [string, number][]): Uint8Array {
  const names = members.map(([n]) => new TextEncoder().encode(n));
  const central = names.reduce((n, name) => n + 46 + name.length, 0);
  const out = new Uint8Array(central + 22);
  const v = new DataView(out.buffer);
  let at = 0;
  members.forEach(([, size], i) => {
    v.setUint32(at, 0x02014b50, true);
    v.setUint32(at + 24, size, true);
    v.setUint16(at + 28, names[i]!.length, true);
    out.set(names[i]!, at + 46);
    at += 46 + names[i]!.length;
  });
  v.setUint32(at, 0x06054b50, true);
  v.setUint16(at + 10, members.length, true);
  v.setUint32(at + 12, central, true);
  return out;
}

/** A PPTX's directory with `slides` slide parts. */
export const deckOf = (slides: number) =>
  zipOf([["[Content_Types].xml", 10], ["ppt/presentation.xml", 10], ...Array.from({ length: slides }, (_, i): [string, number] => [`ppt/slides/slide${i + 1}.xml`, 10])]);

/** A DOCX's directory with a body of `bytes` once inflated. */
export const documentOf = (bytes: number) => zipOf([["[Content_Types].xml", 10], ["word/document.xml", bytes]]);
