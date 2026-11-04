import { describe, expect, it, vi } from "vitest";

import { deckOf, documentOf, zipOf } from "../test/zip-members.js";
import { PROGRESSIVE_DOCUMENT_BYTES, PROGRESSIVE_SLIDES, wantsProgressive } from "./progressive.js";
import { zipDirectory } from "./zip.js";

// The ZIP reader in this process: the page has it in a worker.
vi.mock("./zip-engine.js", () => import("../test/sniff.js"));

const wants = async (kind: "pptx" | "docx", bytes: Uint8Array) => wantsProgressive(kind, await zipDirectory(bytes));

describe("wantsProgressive", () => {
  it("is for decks of PROGRESSIVE_SLIDES slides or more", async () => {
    expect(await wants("pptx", deckOf(PROGRESSIVE_SLIDES - 1))).toBe(false);
    expect(await wants("pptx", deckOf(PROGRESSIVE_SLIDES))).toBe(true);
  });

  it("counts slide parts only", async () => {
    const parts = Array.from({ length: PROGRESSIVE_SLIDES }, (_, i): [string, number] => [`ppt/slideLayouts/slideLayout${i}.xml`, 10]);
    expect(await wants("pptx", zipOf(parts))).toBe(false);
  });

  it("is for documents whose body is PROGRESSIVE_DOCUMENT_BYTES or more once inflated", async () => {
    expect(await wants("docx", documentOf(PROGRESSIVE_DOCUMENT_BYTES - 1))).toBe(false);
    expect(await wants("docx", documentOf(PROGRESSIVE_DOCUMENT_BYTES))).toBe(true);
    expect(await wants("docx", zipOf([["word/styles.xml", PROGRESSIVE_DOCUMENT_BYTES * 8]]))).toBe(false);
  });

  it("is not for what is not a ZIP", async () => {
    expect(await wants("pptx", new Uint8Array(64))).toBe(false);
    expect(await wants("docx", new Uint8Array())).toBe(false);
  });
});
