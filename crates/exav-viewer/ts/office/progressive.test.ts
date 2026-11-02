import { describe, expect, it } from "vitest";

import { deckOf, documentOf, zipOf } from "../test/zip-members.js";
import { PROGRESSIVE_DOCUMENT_BYTES, PROGRESSIVE_SLIDES, wantsProgressive, zipMembers } from "./progressive.js";

describe("zipMembers", () => {
  it("lists the members and their uncompressed sizes", () => {
    expect(zipMembers(zipOf([["a/b.xml", 7], ["c", 0xfffff]]))).toEqual(new Map([["a/b.xml", 7], ["c", 0xfffff]]));
  });

  it("gives nothing for what is not a ZIP, or whose directory does not add up", () => {
    expect(zipMembers(new Uint8Array(100))).toBeNull();
    const bad = zipOf([["a", 1]]);
    // The directory names more members than it holds.
    new DataView(bad.buffer, bad.byteOffset).setUint16(bad.length - 22 + 10, 5, true);
    expect(zipMembers(bad)).toBeNull();
    // A name that runs past the directory.
    const long = zipOf([["a", 1]]);
    new DataView(long.buffer, long.byteOffset).setUint16(28, 4000, true);
    expect(zipMembers(long)).toBeNull();
  });

  it("leaves a ZIP64 directory to the engine", () => {
    const z = zipOf([["a", 1]]);
    new DataView(z.buffer, z.byteOffset).setUint32(z.length - 22 + 16, 0xffffffff, true);
    expect(zipMembers(z)).toBeNull();
  });
});

describe("wantsProgressive", () => {
  it("is for decks of PROGRESSIVE_SLIDES slides or more", () => {
    expect(wantsProgressive("pptx", deckOf(PROGRESSIVE_SLIDES - 1))).toBe(false);
    expect(wantsProgressive("pptx", deckOf(PROGRESSIVE_SLIDES))).toBe(true);
  });

  it("counts slide parts only", () => {
    const parts = Array.from({ length: PROGRESSIVE_SLIDES }, (_, i): [string, number] => [`ppt/slideLayouts/slideLayout${i}.xml`, 10]);
    expect(wantsProgressive("pptx", zipOf(parts))).toBe(false);
  });

  it("is for documents whose body is PROGRESSIVE_DOCUMENT_BYTES or more once inflated", () => {
    expect(wantsProgressive("docx", documentOf(PROGRESSIVE_DOCUMENT_BYTES - 1))).toBe(false);
    expect(wantsProgressive("docx", documentOf(PROGRESSIVE_DOCUMENT_BYTES))).toBe(true);
    expect(wantsProgressive("docx", zipOf([["word/styles.xml", PROGRESSIVE_DOCUMENT_BYTES * 8]]))).toBe(false);
  });

  it("is not for what is not a ZIP", () => {
    expect(wantsProgressive("pptx", new Uint8Array(64))).toBe(false);
    expect(wantsProgressive("docx", new Uint8Array())).toBe(false);
  });
});
