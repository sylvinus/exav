// The copy step against what the engines ask for at runtime, with the
// engines installed for the package's own tests.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { FRAME_CSP, frameCsp } from "../frame/policy.js";
import { documentOptions } from "../pdf/engine.js";
import { collectAssets, frameFileBytes, frameFiles, packageDir } from "./assets.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const { assets, manifest } = collectAssets(root);
const copied = new Set(assets.map((a) => a.path));
const version = (name: string) => JSON.parse(fs.readFileSync(path.join(packageDir(name, root)!, "package.json"), "utf8")).version;

describe("collectAssets", () => {
  it("copies a file under every directory pdf.js is pointed at", () => {
    const options = documentOptions("/base/", version("pdfjs-dist"));
    for (const [key, url] of Object.entries(options).filter(([k]) => k.endsWith("Url"))) {
      const dir = (url as string).replace(/^\/base\//, "");
      expect([...copied].some((p) => p.startsWith(dir)), `${key}: ${url}`).toBe(true);
    }
  });

  it("copies the files pdf.js fetches by name", () => {
    const dir = `pdfjs/${version("pdfjs-dist")}/`;
    const wasm = documentOptions("/", version("pdfjs-dist")).wasmUrl.slice(1);
    // The ICC engine, the image decoders and a packed CMap pdf.js loads by name.
    for (const file of [
      `${wasm}qcms_bg.wasm`,
      `${wasm}openjpeg.wasm`,
      `${wasm}openjpeg_nowasm_fallback.js`,
      `${wasm}jbig2.wasm`,
      `${wasm}jbig2_nowasm_fallback.js`,
      `${dir}cmaps/UniJIS-UCS2-H.bcmap`,
      `${dir}standard_fonts/FoxitDingbats.pfb`,
    ])
      expect(copied.has(file), file).toBe(true);
  });

  it("puts this package's image decoders where pdf.js has OpenJPEG and PDFium's", () => {
    const pdfjs = packageDir("pdfjs-dist", root)!;
    const wasm = documentOptions("/", version("pdfjs-dist")).wasmUrl.slice(1);
    // Nothing of pdf.js's decoders is copied, their licences included...
    const theirs = assets.filter((a) => a.source.startsWith(pdfjs) && /openjpeg|jbig2/i.test(path.basename(a.source)));
    expect(theirs).toEqual([]);
    // ...though pdf.js ships them.
    for (const file of ["openjpeg.wasm", "openjpeg_nowasm_fallback.js", "jbig2.wasm", "jbig2_nowasm_fallback.js", "LICENSE_OPENJPEG", "LICENSE_JBIG2"]) expect(fs.existsSync(path.join(pdfjs, "wasm", file)), file).toBe(true);
    const at = (name: string) => assets.find((a) => a.path === `${wasm}${name}`)!.source;
    // The .wasm pdf.js tries first fails to compile: it is empty.
    for (const name of ["openjpeg.wasm", "jbig2.wasm"]) expect(fs.statSync(at(name)).size, name).toBe(0);
    // The fallback it then imports is this package's.
    expect(at("openjpeg_nowasm_fallback.js")).toBe(path.join(root, "wasm", "openjpeg_nowasm_fallback.js"));
    expect(at("jbig2_nowasm_fallback.js")).toBe(path.join(root, "wasm", "jbig2_nowasm_fallback.js"));
    // The ICC engine stays pdf.js's.
    expect(at("qcms_bg.wasm")).toBe(path.join(pdfjs, "wasm", "qcms_bg.wasm"));
    expect(wasm).toMatch(new RegExp(`^pdfjs/${version("pdfjs-dist").replace(/\./g, "\\.")}/wasm-[0-9a-f]{10}/$`));
  });

  it("keeps the ICC engine and PostScript functions on (`useWasm`)", () => {
    expect(documentOptions("/", "6.0.0").useWasm).toBe(true);
  });

  it("leaves out the scripting sandbox's JavaScript engine, which is never loaded", () => {
    expect([...copied].filter((p) => p.includes("quickjs"))).toEqual([]);
    // It is there to leave out.
    expect(fs.existsSync(path.join(packageDir("pdfjs-dist", root)!, "wasm", "quickjs-eval.wasm"))).toBe(true);
  });

  it("copies nothing for the IFC and STL engines, which are the package's own", () => {
    expect([...copied].filter((p) => !p.startsWith("pdfjs/"))).toEqual([]);
  });

  it("lists every copied file in the manifest, each copied from a file that exists", () => {
    expect([...manifest.all].sort()).toEqual([...copied].sort());
    for (const a of assets) expect(fs.statSync(a.source).isFile()).toBe(true);
  });
});

describe("the frame app's files", () => {
  /** A page and a script as build-frame.mjs writes them. */
  const built = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "frame-"));
    fs.writeFileSync(path.join(dir, "index.html"), `<meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}" />`);
    fs.writeFileSync(path.join(dir, "app.js"), 'console.log("content=")');
    return { dir, page: { source: path.join(dir, "index.html"), path: "index.html" }, script: { source: path.join(dir, "app.js"), path: "app.js" } };
  };

  it("publish the page with the frame's origin in its policy, the rest as built", () => {
    const { dir, page, script } = built();
    const html = frameFileBytes(page, "https://frame.example.com").toString("utf8");
    expect(html).toBe(`<meta http-equiv="Content-Security-Policy" content="${frameCsp("https://frame.example.com")}" />`);
    expect(frameFileBytes(page).equals(fs.readFileSync(page.source))).toBe(true);
    expect(frameFileBytes(script, "https://frame.example.com").equals(fs.readFileSync(script.source))).toBe(true);
    // The media and connect origins too, with or without the frame's own.
    const origins = { media: ["https://media.test"], connect: ["https://files.test"] };
    expect(frameFileBytes(page, undefined, origins).toString("utf8")).toBe(`<meta http-equiv="Content-Security-Policy" content="${frameCsp(undefined, origins)}" />`);
    expect(frameFileBytes(page, undefined, origins).toString("utf8")).toContain("media-src blob: https://media.test;");
    fs.rmSync(dir, { recursive: true });
  });

  it("refuse a page whose policy is not the one this package writes", () => {
    const { dir, page } = built();
    fs.writeFileSync(page.source, '<meta http-equiv="Content-Security-Policy" content="default-src *">');
    expect(() => frameFileBytes(page, "https://frame.example.com")).toThrow();
    // And an origin that is not one.
    fs.writeFileSync(page.source, `<meta content="${FRAME_CSP}">`);
    expect(() => frameFileBytes(page, "https://x.test; script-src *")).toThrow();
    fs.rmSync(dir, { recursive: true });
  });

  it.runIf(fs.existsSync(path.join(root, "dist", "frame", "app")))("are the built app, page and scripts", () => {
    const paths = frameFiles().map((f) => f.path);
    for (const f of ["index.html", "app.js", "cad.worker.js", "pdfjs.worker.js", "ranges.worker.js", "exav-viewer/manifest.json"]) expect(paths, f).toContain(f);
  });
});
