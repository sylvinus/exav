// @vitest-environment node
// What an IFC model is framed by is worked out by the reader (exav-render,
// `ifc/framing.rs`, where its cases are tested). Here, the generated house.ifc
// (made by e2e/fixtures/make-samples.mjs, and equal to the copy exav-render's
// tests read) read by the model engine itself gives it in the meta.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { ModelMeta } from "./engine.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

describe("meta.framing", () => {
  it("of the generated house.ifc, as the engine reads it, is the whole of it", async () => {
    const wasm = path.join(root, "wasm");
    const { default: init, parseIfc } = await import(/* @vite-ignore */ path.join(wasm, "exav_viewer_model.js"));
    await init({ module_or_path: fs.readFileSync(path.join(wasm, "exav_viewer_model_bg.wasm")) });
    // As the browser tests get it, and as exav-render's tests keep it.
    execFileSync(process.execPath, [path.join(root, "e2e", "fixtures", "make-samples.mjs")], { stdio: "ignore" });
    const house = fs.readFileSync(path.join(root, "e2e", ".out", "samples", "house.ifc"));
    expect(house.equals(fs.readFileSync(path.join(root, "..", "exav-render", "tests", "fixtures", "viewer", "house.ifc")))).toBe(true);
    const model = parseIfc(new Uint8Array(house), 1_000_000);
    const meta = JSON.parse(model.metaJson()) as ModelMeta;
    model.free();
    // Four walls and a slab (make-samples.mjs), nothing far from the rest.
    expect(meta.elements).toHaveLength(5);
    expect(meta.framing).toEqual(meta.bounds);
  });
});
