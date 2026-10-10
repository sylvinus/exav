// @vitest-environment node
// This package's stand-ins for pdf.js's OpenJPEG and PDFium decoders
// (wasm/*_nowasm_fallback.js, from `npm run build:wasm`), called as pdf.js
// calls them, against pdf.js's own: its `*_nowasm_fallback.js`, the same C and
// C++ as its .wasm compiled to JavaScript, run as black boxes. The streams and
// the parameters pdf.js passes for each are e2e/fixtures/pdf-images/ (see
// make.py there).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const fixtures = path.join(root, "e2e", "fixtures", "pdf-images");
const fixture = (name: string) => new Uint8Array(fs.readFileSync(path.join(fixtures, name)));

interface Decoder {
  _malloc(size: number): number;
  _free(ptr: number): void;
  writeArrayToMemory(array: Uint8Array, ptr: number): void;
  _jp2_decode?(ptr: number, size: number, numComponents: number, indexed: boolean, smask: boolean, reducePower: number): number;
  _jbig2_decode?(ptr: number, size: number, width: number, height: number, globalsPtr: number, globalsSize: number): void;
  _ccitt_decode?(ptr: number, size: number, width: number, height: number, k: number, eol: number, align: number, blackIs1: number, columns: number, rows: number): void;
  imageData: Uint8Array | Uint8ClampedArray | null;
  errorMessages?: string;
}

const load = async (file: string): Promise<Decoder> => (await import(/* @vite-ignore */ pathToFileURL(file).href)).default();
const ours = {
  jpx: load(path.join(root, "wasm", "openjpeg_nowasm_fallback.js")),
  jbig2: load(path.join(root, "wasm", "jbig2_nowasm_fallback.js")),
};
const pdfjs = path.join(root, "node_modules", "pdfjs-dist", "wasm");
const theirs = {
  jpx: load(path.join(pdfjs, "openjpeg_nowasm_fallback.js")),
  jbig2: load(path.join(pdfjs, "jbig2_nowasm_fallback.js")),
};

type Outcome = { data: Uint8Array | Uint8ClampedArray | null; type: string | null; failed: boolean };

/** `JpxImage.decode` and `JBig2CCITTFaxImage.decode`, as pdf.js 6 makes them. */
function jpx(m: Decoder, bytes: Uint8Array, nc: number, indexed: boolean, smask: boolean, reducePower: number): Outcome {
  const ptr = m._malloc(bytes.length);
  m.writeArrayToMemory(bytes, ptr);
  const ret = m._jp2_decode!(ptr, bytes.length, nc, indexed, smask, reducePower);
  m._free(ptr);
  const data = m.imageData;
  m.imageData = null;
  const failed = ret !== 0;
  if (failed) {
    expect(typeof m.errorMessages).toBe("string");
    delete m.errorMessages;
  }
  return { data, type: data?.constructor.name ?? null, failed };
}

function bilevel(m: Decoder, bytes: Uint8Array, width: number, height: number, globals?: Uint8Array, ccitt?: number[]): Outcome {
  const ptr = m._malloc(bytes.length);
  m.writeArrayToMemory(bytes, ptr);
  let g = 0;
  if (globals?.length) {
    g = m._malloc(globals.length);
    m.writeArrayToMemory(globals, g);
  }
  if (ccitt) m._ccitt_decode!(ptr, bytes.length, width, height, ...(ccitt as [number, number, number, number, number, number]));
  else m._jbig2_decode!(ptr, bytes.length, width, height, g, globals?.length ?? 0);
  m._free(ptr);
  if (g) m._free(g);
  const data = m.imageData;
  m.imageData = null;
  return { data, type: data?.constructor.name ?? null, failed: !data };
}

interface Case {
  pdf: string;
  stream: string;
  filter: "jpx" | "jbig2" | "ccitt";
  numComponents?: number;
  isIndexedColormap?: boolean;
  smaskInData?: boolean;
  width?: number;
  height?: number;
  globals?: string;
  K?: number;
  EndOfLine?: boolean;
  EncodedByteAlign?: boolean;
  BlackIs1?: boolean;
  Columns?: number;
  Rows?: number;
}
const cases: Case[] = JSON.parse(fs.readFileSync(path.join(fixtures, "cases.json"), "utf8"));

function same(a: Outcome, b: Outcome, what: string) {
  expect(a.failed, what).toBe(b.failed);
  expect(a.type, what).toBe(b.type);
  if (a.data && b.data) {
    expect(a.data.length, what).toBe(b.data.length);
    expect(Buffer.from(a.data.buffer, a.data.byteOffset, a.data.length).equals(Buffer.from(b.data.buffer, b.data.byteOffset, b.data.length)), what).toBe(true);
  }
}

describe("JPXDecode", () => {
  // Every layout pdf.js asks for, on every stream: lossless streams decode to
  // the same bytes as OpenJPEG gives.
  const streams = [...new Set(cases.filter((c) => c.filter === "jpx" && c.stream !== "lossy.jp2").map((c) => c.stream))];
  it.each(streams)("%s, in every layout, as OpenJPEG gives it", async (stream) => {
    const [a, b] = [await ours.jpx, await theirs.jpx];
    const bytes = fixture(stream);
    for (const nc of [0, 1, 3, 4])
      for (const indexed of [false, true])
        for (const smask of [false, true])
          for (const reducePower of [0, 1, 2]) {
            const what = `${stream} nc=${nc} indexed=${indexed} smask=${smask} reduce=${reducePower}`;
            same(jpx(a, bytes, nc, indexed, smask, reducePower), jpx(b, bytes, nc, indexed, smask, reducePower), what);
          }
  });

  it("decodes a lossy stream within a level of OpenJPEG", async () => {
    // Both reconstruct truncated coefficients at the middle of their
    // interval; rounding differs on a few samples.
    const bytes = fixture("lossy.jp2");
    const a = jpx(await ours.jpx, bytes, 0, false, false, 0).data!;
    const b = jpx(await theirs.jpx, bytes, 0, false, false, 0).data!;
    expect(a.length).toBe(b.length);
    let sum = 0;
    let max = 0;
    for (let i = 0; i < a.length; i++) {
      sum += Math.abs(a[i]! - b[i]!);
      max = Math.max(max, Math.abs(a[i]! - b[i]!));
    }
    expect(sum / a.length).toBeLessThan(0.01);
    expect(max).toBeLessThanOrEqual(1);
  });

  it("fails where OpenJPEG fails, with a message", async () => {
    const rgb = fixture("rgb.jp2");
    for (const [what, bytes] of [
      ["empty", new Uint8Array(0)],
      ["not JPEG 2000", new TextEncoder().encode("not an image, just text")],
      ["cut in half", rgb.subarray(0, rgb.length >> 1)],
      ["header only", rgb.subarray(0, 120)],
      ["no end of codestream", rgb.subarray(0, rgb.length - 2)],
    ] as const) {
      expect(jpx(await ours.jpx, bytes, 0, false, false, 0).failed, what).toBe(true);
      expect(jpx(await theirs.jpx, bytes, 0, false, false, 0).failed, what).toBe(true);
    }
  });
});

describe("JBIG2Decode and CCITTFaxDecode", () => {
  const bilevelCases = cases.filter((c) => c.filter !== "jpx");
  it.each(bilevelCases.map((c) => [c.pdf, c] as const))("%s, as PDFium gives it", async (_, c) => {
    const [a, b] = [await ours.jbig2, await theirs.jbig2];
    const bytes = fixture(c.stream);
    const globals = c.globals ? fixture(c.globals) : undefined;
    const ccitt = c.filter === "ccitt" ? [c.K!, +c.EndOfLine!, +c.EncodedByteAlign!, +c.BlackIs1!, c.Columns!, c.Rows!] : undefined;
    // At the image's size, and at others, which cut the page or pad it.
    for (const [w, h] of [[c.width!, c.height!], [c.width! - 9, c.height! - 5], [c.width! + 13, c.height! + 7]]) {
      if (ccitt && w > c.Columns!) continue; // PDFium reads past its row there
      same(bilevel(a, bytes, w!, h!, globals, ccitt), bilevel(b, bytes, w!, h!, globals, ccitt), `${c.pdf} ${w}x${h}`);
    }
  });

  it("fails where PDFium fails", async () => {
    const symbols = fixture("symbol.jbig2");
    // Text regions without the symbols of their /JBIG2Globals; no data.
    for (const [what, bytes] of [
      ["no globals", symbols],
      ["empty", new Uint8Array(0)],
    ] as const) {
      expect(bilevel(await ours.jbig2, bytes, 120, 64).failed, what).toBe(true);
      expect(bilevel(await theirs.jbig2, bytes, 120, 64).failed, what).toBe(true);
    }
  });
});

describe("the module object", () => {
  it("hands out distinct, non-zero handles and frees them", async () => {
    const m = await ours.jpx;
    const [a, b] = [m._malloc(4), m._malloc(0)];
    expect(a).not.toBe(0);
    expect(b).not.toBe(a);
    m._free(a);
    m._free(b);
  });

  it("is a new decoder each time pdf.js asks for one", async () => {
    const mod = await import(/* @vite-ignore */ pathToFileURL(path.join(root, "wasm", "openjpeg_nowasm_fallback.js")).href);
    const [x, y] = [await mod.default(), await mod.default()];
    expect(x).not.toBe(y);
    expect(jpx(x, fixture("rgb.jp2"), 3, false, false, 0).data!.length).toBe(48 * 32 * 3);
  });
});
