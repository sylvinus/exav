import { describe, expect, it } from "vitest";

import { BUILTIN_ORDER } from "../core/formats.js";
import { engineClosure, engineOf, ENGINES, pluginFormats, shippedFormats } from "./engines.js";

describe("the frame's engines", () => {
  it("open every built-in format, each in one engine", () => {
    for (const f of BUILTIN_ORDER) expect(Object.values(ENGINES).filter((e) => e.formats.includes(f)), f).toHaveLength(1);
    const listed = Object.values(ENGINES).flatMap((e) => e.formats);
    expect([...listed].sort()).toEqual([...BUILTIN_ORDER].sort());
  });

  it("need engines that exist", () => {
    for (const [id, e] of Object.entries(ENGINES)) {
      for (const n of [...(e.needs ?? []), ...(e.external?.needs ?? [])]) expect(ENGINES[n], `${id} needs ${n}`).toBeDefined();
    }
  });

  it("bring the engines a format needs, and no others", () => {
    expect([...engineClosure(["pdf"])]).toEqual(["pdf"]);
    expect([...engineClosure(["stl"])].sort()).toEqual(["meshes", "model", "three"]);
    // CSV and XLSX are one engine, and the Office viewers' shared page comes with it.
    expect([...engineClosure(["csv"])].sort()).toEqual(["office", "xlsx"]);
    expect([...engineClosure(["ppt"])].sort()).toEqual(["convert", "office", "pptx", "slides"]);
    expect([...engineClosure([])]).toEqual([]);
  });

  it("bring the engine of every format they show a file as", () => {
    for (const [id, e] of Object.entries(ENGINES)) {
      const closure = engineClosure(e.formats, true);
      if (e.formats.length) for (const f of [...(e.shows ?? []), ...(e.external?.shows ?? [])]) expect(closure.has(engineOf(f)), `${id} shows ${f}`).toBe(true);
      // And without an external converter, what the engine itself converts to.
      for (const f of e.shows ?? []) if (e.formats.length) expect(engineClosure(e.formats).has(engineOf(f)), `${id} shows ${f}`).toBe(true);
    }
  });

  it("bring PDF and the spreadsheet viewer with a converted format only where an external converter is set", () => {
    expect(engineClosure(["rtf"]).has("pdf")).toBe(false);
    for (const f of ["rtf", "xls", "ppt", "wpg"] as const) {
      expect(engineClosure([f], true).has("pdf"), f).toBe(true);
      expect(engineClosure([f], true).has("xlsx"), f).toBe(true);
    }
  });

  it("add the plugins a converted file is shown with", () => {
    expect(pluginFormats(["pdf", "image"])).toEqual(["pdf", "image"]);
    expect(pluginFormats(["ppt"])).toEqual(["ppt", "pptx"]);
    expect(pluginFormats(["rtf", "docx"])).toEqual(["rtf", "docx"]);
    expect(pluginFormats(["xls"])).toEqual(["xls", "xlsx"]);
    expect(pluginFormats(["xls"], true)).toEqual(["xls", "xlsx", "pdf"]);
    expect(pluginFormats(["wpg"], true).sort()).toEqual(["pdf", "wpg", "xlsx"]);
    expect(pluginFormats(["wpg"])).toEqual(["wpg"]);
  });

  it("open the other formats of an engine that is shipped", () => {
    expect(shippedFormats(["gltf"]).sort()).toEqual(["gltf", "obj", "ply", "stl"]);
    expect(shippedFormats(["dxf"]).sort()).toEqual(["dwg", "dxf"]);
    expect(shippedFormats(["video"]).sort()).toEqual(["audio", "video"]);
  });

  it("name the engine of a format", () => {
    expect(engineOf("csv")).toBe("xlsx");
    expect(engineOf("odg")).toBe("slides");
    expect(engineOf("odt")).toBe("docs");
  });
});
