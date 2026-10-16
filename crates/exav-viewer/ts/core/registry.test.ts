// The viewer's matchers and signatures against the format registry
// (formats/registry.json, checked against the rest of the code by
// scripts/formats.mjs): the registry is where a format's names live, and the
// viewer must claim exactly what it says the viewer claims.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { BUILTIN_ORDER, MATCHERS, SIGNATURES, WASM_IMAGES } from "./formats.js";

interface Entry {
  id: string;
  ext: string[];
  mime: string[];
  /** Types the viewer sniffs from the bytes that its matcher does not claim. */
  sniffs?: string[];
  magic?: string[][];
  viewer: string | null;
}

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "formats", "registry.json");
const entries: Entry[] = JSON.parse(fs.readFileSync(file, "utf8")).formats;

const hex = (bytes: readonly number[]) => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");

/**
 * What the plugin's matcher names, with the images exav-render decodes for
 * the image plugin: its types, those it takes after the extension, and those
 * the extension answers over.
 */
function claimed(plugin: string) {
  const matchers = plugin === "image" ? [MATCHERS.image, WASM_IMAGES] : [MATCHERS[plugin as keyof typeof MATCHERS]];
  return {
    extensions: new Set(matchers.flatMap((m) => m.extensions ?? [])),
    types: new Set(matchers.flatMap((m) => [...(m.types ?? []), ...(m.containerTypes ?? []), ...(m.extensionOverrides ?? [])])),
  };
}

describe("the viewer's matchers against the registry", () => {
  for (const plugin of BUILTIN_ORDER) {
    it(`${plugin} claims the extensions of its registry entries, and no other`, () => {
      const mine = entries.filter((e) => e.viewer === plugin);
      const registered = new Set(mine.flatMap((e) => e.ext));
      const { extensions } = claimed(plugin);
      expect([...registered].filter((e) => !extensions.has(e)), "in the registry, not claimed by the viewer").toEqual([]);
      expect([...extensions].filter((e) => !registered.has(e)), "claimed by the viewer, not in the registry").toEqual([]);
    });

    it(`${plugin} claims the types of its registry entries`, () => {
      const registered = entries.filter((e) => e.viewer === plugin).flatMap((e) => e.mime);
      const { types } = claimed(plugin);
      expect(registered.filter((t) => !types.has(t))).toEqual([]);
    });
  }

  it("has an entry for every plugin", () => {
    for (const plugin of BUILTIN_ORDER) expect(entries.some((e) => e.viewer === plugin), plugin).toBe(true);
  });

  it("sniffs the bytes the registry gives its format", () => {
    for (const s of SIGNATURES) {
      const conditions = [`${s.offset ?? 0}:${hex(s.prefix)}`, ...(s.also ? [`${s.alsoOffset ?? 0}:${hex(s.also)}`] : [])];
      const entry = entries.find((e) => e.mime.includes(s.type) || e.sniffs?.includes(s.type));
      expect(entry, `a registry entry typed ${s.type}`).toBeDefined();
      // The registry may give more bytes than the viewer reads (RAR's seven, the viewer's four).
      const same = (alt: string[]) => alt.length === conditions.length && conditions.every((c, i) => alt[i] === c || (i === 0 && alt[i]!.startsWith(c)));
      expect(entry!.magic?.some(same), `${s.type}: ${conditions.join(" ")} among the magic of ${entry!.id}`).toBe(true);
    }
  });
});
