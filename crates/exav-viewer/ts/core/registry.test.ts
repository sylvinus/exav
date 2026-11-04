// What exav's detection says of the signatures in the format registry
// (formats/registry.json), against the plugin the registry says opens each.
// The viewer's extensions and types are generated from the registry
// (formats.generated.ts), so there is nothing to compare them with; the
// registry itself is checked against the rest of the code by
// scripts/formats.mjs.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { sniffInWorker } from "../test/sniff.js";
import { createDetector } from "./detect.js";
import { BUILTIN_ORDER, MATCHERS, WASM_IMAGES } from "./formats.js";

interface Entry {
  id: string;
  /** Bytes by offset, as "0:504b0304": every condition of one alternative holds. */
  magic?: string[][];
  viewer: string | null;
}

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "formats", "registry.json");
const entries: Entry[] = JSON.parse(fs.readFileSync(file, "utf8")).formats;

/** The image plugin with the decoders of exav-render, as the frame has it. */
const wasmImage = { ...MATCHERS.image, types: [...MATCHERS.image.types!, ...WASM_IMAGES.types!], extensions: [...MATCHERS.image.extensions!, ...WASM_IMAGES.extensions!] };
const detector = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: id === "image" ? wasmImage : MATCHERS[id] })));

const hex = (bytes: readonly number[]) => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");

describe("the registry's signatures against the viewer's plugins", () => {
  it("types the bytes the registry gives a format as the plugin it says opens it", async () => {
    // Where exav's detection says what a head of those bytes is, it is a type
    // the viewer's plugin of that registry entry claims. A head of nothing but
    // the magic is not always a file: the detector may say nothing.
    let typed = 0;
    for (const e of entries) {
      for (const alternative of e.magic ?? []) {
        const head = new Uint8Array(300);
        for (const condition of alternative) {
          const [offset, hexBytes] = condition.split(":") as [string, string];
          const at = Number(offset);
          for (let i = 0; i < hexBytes.length; i += 2) head[at + i / 2] = parseInt(hexBytes.slice(i, i + 2), 16);
        }
        const type = await sniffInWorker(head, head.length);
        if (!type) continue;
        typed += 1;
        const plugin = detector.detect({ type, name: "" });
        const compound = type === "application/x-ole-storage";
        expect(compound || plugin === e.viewer, `${e.id} (${hex([...head.subarray(0, 8)])}) is typed ${type}, which ${plugin} claims, not ${e.viewer}`).toBe(true);
      }
    }
    expect(typed).toBeGreaterThan(25);
  });
});
