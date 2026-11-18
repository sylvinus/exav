import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { readingOf } from "../test/text-wasm.js";
import { readText } from "./read.js";

// The cases exav-unpack's decoder (encoding_rs) is tested on, in its own suite.
const cases = fs
  .readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "exav-unpack", "tests", "fixtures", "text", "decode_file.txt"), "utf8")
  .split("\n")
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => {
    const [name, partial, label, input, text] = line.split(";") as [string, string, string, string, string];
    return { name, partial: partial === "1", label, input: Buffer.from(input, "hex"), text: Buffer.from(text, "hex").toString("utf8") };
  });

describe("readText", () => {
  it("gives the text exav-unpack's decoder gives, in every encoding the rule picks", async () => {
    expect(new Set(cases.map((c) => c.label))).toEqual(new Set(["utf-8", "utf-16le", "utf-16be", "windows-1252"]));
    for (const c of cases) {
      const reading = await readingOf(c.input, c.partial);
      expect(reading?.encoding, c.name).toBe(c.label);
      expect(readText(c.input, reading!), c.name).toBe(c.text);
    }
  });
});
