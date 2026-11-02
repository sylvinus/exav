import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { BUILTIN_ORDER } from "../core/formats.js";
import { ENGINES, FRAME_FORMATS_META } from "../frame/engines.js";
import { checkFrameFormats, frameSubset, pageFor, type FrameFilesManifest } from "./subset.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const manifest: FrameFilesManifest = {
  core: ["app.js", "index.html"],
  engines: { pdf: ["pdf.js", "pdfjs.worker.js", "licenses/pdfjs-dist/LICENSE"], image: ["decode.worker.js"], three: ["three.js"], meshes: ["model.worker.js"], model: ["stl.js"] },
  notices: { header: ["notices"], packages: { "pdfjs-dist": ["pdfjs-dist 1: Apache-2.0"], three: ["three 1: MIT"] } },
};

describe("a frame for some formats", () => {
  it("has the core and the files of their engines, and of the engines these need", () => {
    expect([...frameSubset(manifest, ["pdf"]).files].sort()).toEqual(["app.js", "index.html", "licenses/pdfjs-dist/LICENSE", "pdf.js", "pdfjs.worker.js"]);
    expect([...frameSubset(manifest, ["stl"]).files].sort()).toEqual(["app.js", "index.html", "model.worker.js", "stl.js", "three.js"]);
    expect([...frameSubset(manifest, []).files].sort()).toEqual(["app.js", "index.html"]);
  });

  it("opens the formats of the engines it has", () => {
    expect(frameSubset(manifest, ["obj"]).formats.sort()).toEqual(["gltf", "obj", "ply", "stl"]);
    expect(frameSubset(manifest, ["image", "pdf"]).formats.sort()).toEqual(["image", "pdf"]);
  });

  it("lists the notices of the packages that are left", () => {
    expect(frameSubset(manifest, ["image"]).readme).toBe("notices\n");
    expect(frameSubset(manifest, ["pdf"]).readme).toBe("notices\npdfjs-dist 1: Apache-2.0\n");
    expect(frameSubset(manifest, ["pdf", "stl"]).readme).toBe("notices\npdfjs-dist 1: Apache-2.0\nthree 1: MIT\n");
  });

  it("says in its page which formats it opens", () => {
    const html = `<head><meta name="${FRAME_FORMATS_META}" content="*" /></head>`;
    expect(pageFor(html, ["pdf", "image"])).toBe(`<head><meta name="${FRAME_FORMATS_META}" content="pdf,image" /></head>`);
    expect(() => pageFor("<head></head>", ["pdf"])).toThrow(/does not list/);
  });

  it("refuses a name that is no format, and an empty list", () => {
    expect(checkFrameFormats(["pdf", "dxf"])).toEqual(["pdf", "dxf"]);
    expect(() => checkFrameFormats(["pdf", "tiff"])).toThrow(/tiff/);
    expect(() => checkFrameFormats([])).toThrow(/at least one/);
  });
});

describe.runIf(fs.existsSync(path.join(root, "dist", "frame", "files.json")))("the built frame's files", () => {
  // Read when the suite runs: the body of a skipped suite still runs on collection.
  let built: FrameFilesManifest;
  beforeAll(() => {
    built = JSON.parse(fs.readFileSync(path.join(root, "dist", "frame", "files.json"), "utf8")) as FrameFilesManifest;
  });
  const app = path.join(root, "dist", "frame", "app");

  it("exist, and none is the core's and an engine's", () => {
    for (const f of [...built.core, ...Object.values(built.engines).flat()]) expect(fs.existsSync(path.join(app, f)), f).toBe(true);
    for (const f of built.core) expect(Object.values(built.engines).some((files) => files.includes(f)), `${f} is the core's and an engine's`).toBe(false);
  });

  it("leave out nothing the frame is made of", () => {
    const all = new Set<string>();
    const walk = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) (e.isDirectory() ? walk : (p: string) => all.add(path.relative(app, p).split(path.sep).join("/")))(path.join(dir, e.name));
    };
    walk(app);
    const listed = new Set([...built.core, ...Object.values(built.engines).flat()]);
    expect([...all].filter((f) => !listed.has(f))).toEqual([]);
  });

  it("have every engine's files for every format, and the core's alone for none", () => {
    for (const f of BUILTIN_ORDER) {
      const { files } = frameSubset(built, [f]);
      for (const c of built.core) expect(files.has(c), `${f}: ${c}`).toBe(true);
    }
    expect(frameSubset(built, ["video"]).files.size).toBe(built.core.length);
  });

  it("hold, with the engines each needs, every file their own code names", () => {
    // The chunks, workers and wasm a script of an engine refers to by name.
    const NAMED = /["'`](?:\.\/)?([\w.-]+\.(?:js|mjs|wasm))["'`]|["'`]\.\.?\/(?:assets\/)?([\w.-]+\.(?:js|wasm))["'`]/g;
    const everything = new Set([...built.core, ...Object.values(built.engines).flat()]);
    const basenames = new Map<string, string[]>();
    for (const f of everything) basenames.set(path.posix.basename(f), [...(basenames.get(path.posix.basename(f)) ?? []), f]);
    for (const [id, own] of Object.entries(built.engines)) {
      const e = ENGINES[id]!;
      const formats = e.formats.length ? e.formats : (Object.values(ENGINES).find((o) => (o.needs ?? []).includes(id))?.formats ?? []);
      if (!formats.length) continue;
      const shipped = new Set(frameSubset(built, formats, true).files);
      // The engines built on this one are named by it, and loaded for their own formats only
      // (the Office page names the DOCX, XLSX and PPTX viewers).
      for (const [other, o] of Object.entries(ENGINES)) if ((o.needs ?? []).includes(id)) for (const f of built.engines[other] ?? []) shipped.add(f);
      for (const f of own.filter((f) => /\.(js|mjs)$/.test(f))) {
        const source = fs.readFileSync(path.join(app, f), "utf8");
        for (const m of source.matchAll(NAMED)) {
          const name = m[1] ?? m[2]!;
          const files = basenames.get(name);
          // A name that is no file of the frame is the engine's own business.
          if (!files) continue;
          expect(
            files.some((n) => shipped.has(n)),
            `${f} (engine ${id}) names ${name}, which a frame for ${formats.join(", ")} lacks`,
          ).toBe(true);
        }
      }
    }
  });

  it("are much smaller for one format than for all", () => {
    const size = (files: Iterable<string>) => [...files].reduce((n, f) => n + fs.statSync(path.join(app, f)).size, 0);
    const all = size(frameSubset(built, BUILTIN_ORDER).files);
    expect(size(frameSubset(built, ["pdf"]).files)).toBeLessThan(all / 4);
    expect(size(frameSubset(built, ["image"]).files)).toBeLessThan(all / 5);
  });
});
