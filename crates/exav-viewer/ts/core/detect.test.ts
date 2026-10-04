/**
 * Which plugin opens a file. The tables are the acceptance tables the viewer
 * was specified with; they run here against the data-driven detector built
 * from the built-in matchers.
 */
import { describe, expect, it } from "vitest";

import { createDetector, sniff } from "./detect.js";
import { BUILTIN_ORDER, MATCHERS, WASM_IMAGES } from "./formats.js";

const detector = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: MATCHERS[id] })));
const kind = (over: { type?: string; path?: string; kind?: "file" | "link" } = {}) =>
  detector.detect({ name: "", type: "", path: "", kind: "file", ...over });

describe("what the viewer can show", () => {
  it("reads a PDF and a picture", () => {
    expect(kind({ type: "application/pdf" })).toBe("pdf");
    for (const type of ["image/png", "image/jpeg", "image/webp", "image/gif"]) expect(kind({ type })).toBe("image");
  });

  it("opens a drawing, by its registered type, an application's, or its extension", () => {
    expect(kind({ type: "image/vnd.dwg" })).toBe("dwg");
    expect(kind({ type: "application/acad" })).toBe("dwg");
    expect(kind({ type: "application/octet-stream", path: "documents/EXE.DWG" })).toBe("dwg");
    expect(kind({ path: "documents/exe.dwg" })).toBe("dwg");
    expect(kind({ type: "image/vnd.dxf" })).toBe("dxf");
    expect(kind({ path: "x/survey.DXF" })).toBe("dxf");
  });

  it("does not claim a HEIC photograph: there is no HEIC plugin", () => {
    expect(kind({ type: "image/heic" })).toBeNull();
    expect(kind({ path: "documents/IMG_4021.HEIC" })).toBeNull();
  });

  it("opens Word, Excel and PowerPoint, each with its own engine", () => {
    const ooxml = "application/vnd.openxmlformats-officedocument";
    expect(kind({ type: `${ooxml}.wordprocessingml.document` })).toBe("docx");
    expect(kind({ type: `${ooxml}.spreadsheetml.sheet` })).toBe("xlsx");
    expect(kind({ type: `${ooxml}.presentationml.presentation` })).toBe("pptx");
    expect(kind({ type: "application/vnd.ms-excel.sheet.macroenabled.12" })).toBe("xlsx");
    // Every Open XML file is a zip: the name answers over the container.
    expect(kind({ type: "application/zip", path: "documents/budget.xlsx" })).toBe("xlsx");
    expect(kind({ type: "application/zip", path: "documents/photos.zip" })).toBe("archive");
  });

  it("opens a table saved as text, and tells it from a spreadsheet and a note", () => {
    expect(kind({ type: "text/csv" })).toBe("csv");
    expect(kind({ type: "text/tab-separated-values" })).toBe("csv");
    expect(kind({ type: "text/csv; charset=utf-8" })).toBe("csv");
    expect(kind({ type: "application/vnd.ms-excel", path: "x/table.CSV" })).toBe("csv");
    expect(kind({ type: "application/vnd.ms-excel", path: "x/table.xls" })).toBeNull();
    expect(kind({ type: "text/plain", path: "x/lots.csv" })).toBe("csv");
    expect(kind({ type: "text/plain", path: "x/notes.txt" })).toBeNull();
    expect(kind({ path: "x/export.TSV" })).toBe("csv");
  });

  it("plays what the browser can play, and nothing else", () => {
    expect(kind({ type: "video/mp4" })).toBe("video");
    expect(kind({ type: "video/quicktime" })).toBe("video");
    expect(kind({ type: "audio/mpeg" })).toBe("audio");
    expect(kind({ path: "x/clip.MOV" })).toBe("video");
    expect(kind({ path: "x/note.m4a" })).toBe("audio");
    expect(kind({ type: "video/x-msvideo" })).toBeNull();
  });

  it("opens an archive, after asking whether it is an Open XML document", () => {
    expect(kind({ type: "application/x-7z-compressed" })).toBe("archive");
    expect(kind({ type: "application/zip", path: "x/delivery.zip" })).toBe("archive");
    expect(kind({ path: "x/delivery.tar.gz" })).toBe("archive");
    expect(kind({ type: "application/zip", path: "x/d.docx" })).toBe("docx");
    // A zip named .pdf is a zip: the extension is a fallback.
    expect(kind({ type: "application/zip", path: "x/plan.pdf" })).toBe("archive");
  });

  it("opens a model and a mesh", () => {
    expect(kind({ path: "x/building.ifc" })).toBe("ifc");
    expect(kind({ type: "model/ifc" })).toBe("ifc");
    expect(kind({ path: "x/bracket.STL" })).toBe("stl");
    expect(kind({ type: "model/stl" })).toBe("stl");
    expect(kind({ type: "application/sla" })).toBe("stl");
    expect(kind({ path: "x/building.ifczip" })).toBeNull();
  });

  it("leaves everything else to the browser", () => {
    expect(kind({ type: "application/vnd.ms-excel" })).toBeNull();
    expect(kind({ type: "application/msword" })).toBeNull();
    expect(kind({ type: "image/svg+xml" })).toBeNull();
  });

  it("follows a link rather than drawing it", () => {
    expect(kind({ kind: "link", type: "application/pdf" })).toBeNull();
  });

  it("falls back to the extension only where the type says nothing", () => {
    expect(kind({ path: "documents/old.PDF" })).toBe("pdf");
    expect(kind({ path: "documents/old.JPG" })).toBe("image");
    expect(kind({ path: "documents/quote.xls" })).toBeNull();
    expect(kind({ type: "application/octet-stream", path: "documents/photo.jpg" })).toBe("image");
    expect(kind({ type: "application/octet-stream", path: "documents/notes.rtf" })).toBeNull();
    // A picture named plan.pdf is a picture: the type is believed.
    expect(kind({ type: "image/png", path: "documents/plan.pdf" })).toBe("image");
    expect(kind({ type: "application/pdf", path: "x/scan.png" })).toBe("pdf");
  });

  it("reads the extension from the path, the name only when there is none", () => {
    expect(detector.detect({ name: "report.pdf", type: "" })).toBe("pdf");
    expect(detector.detect({ name: "report.pdf", path: "store/91af", type: "" })).toBeNull();
  });
});

const bytes = (...parts: (string | number[])[]): Uint8Array => {
  const out: number[] = [];
  for (const part of parts) {
    if (typeof part === "string") out.push(...[...part].map((c) => c.charCodeAt(0)));
    else out.push(...part);
  }
  return new Uint8Array(out);
};
const isoBmff = (brand: string) => bytes([0, 0, 0, 0x1c], "ftyp", brand, [0, 0, 0, 0]);

describe("what the first bytes say", () => {
  it("knows the common signatures", () => {
    expect(sniff(bytes("%PDF-1.7"))).toBe("application/pdf");
    expect(sniff(bytes([0x89], "PNG", [0x0d, 0x0a, 0x1a, 0x0a]))).toBe("image/png");
    expect(sniff(bytes([0xff, 0xd8, 0xff, 0xe0]))).toBe("image/jpeg");
    expect(sniff(bytes("AC1032", [0, 0]))).toBe("image/vnd.dwg");
    expect(sniff(bytes([0x50, 0x4b, 0x03, 0x04]))).toBe("application/zip");
    expect(sniff(isoBmff("heic"))).toBe("image/heic");
    expect(sniff(bytes("II*", [0]))).toBe("image/tiff");
  });

  it("knows JPEG 2000 and JBIG2, which only the WebAssembly decoders open", () => {
    expect(sniff(bytes([0, 0, 0, 0x0c], "jP  ", [0x0d, 0x0a, 0x87, 0x0a, 0, 0, 0, 0x14], "ftyp"))).toBe("image/jp2");
    expect(sniff(bytes([0xff, 0x4f, 0xff, 0x51, 0, 0x2f]))).toBe("image/j2c");
    expect(sniff(bytes([0x97], "JB2", [0x0d, 0x0a, 0x1a, 0x0a, 1]))).toBe("image/x-jbig2");
    const wasm = createDetector([{ id: "image", match: { types: [...MATCHERS.image.types!, ...WASM_IMAGES.types!], extensions: [...MATCHERS.image.extensions!, ...WASM_IMAGES.extensions!] } }]);
    for (const name of ["scan.jp2", "scan.jpf", "scan.jpx", "scan.j2k", "scan.j2c", "fax.jb2", "fax.jbig2"]) {
      expect(wasm.detect({ name, type: "" }), name).toBe("image");
      expect(detector.detect({ name, type: "" }), name).toBeNull();
    }
    expect(wasm.detectBytes("scan", bytes([0, 0, 0, 0x0c], "jP  ", [0x0d, 0x0a, 0x87, 0x0a]))).toBe("image");
  });

  it("tells a film from a photograph, both being ftyp boxes", () => {
    expect(sniff(isoBmff("qt  "))).toBe("video/quicktime");
    expect(sniff(isoBmff("isom"))).toBe("video/mp4");
  });

  it("says nothing when the bytes say nothing", () => {
    expect(sniff(bytes("Hello, this is a note."))).toBe("");
    expect(sniff(new Uint8Array())).toBe("");
  });
});

describe("which plugin opens a member of an archive", () => {
  const member = (name: string, b: Uint8Array) => detector.detectBytes(name, b);

  it("believes the bytes over the name", () => {
    expect(member("plan.pdf", bytes([0xff, 0xd8, 0xff, 0xe0]))).toBe("image");
    expect(member("quote", bytes("%PDF-1.4"))).toBe("pdf");
  });

  it("falls back to the name for formats with no signature", () => {
    const dxf = bytes("0\nSECTION\n2\nENTITIES\n");
    expect(member("survey.dxf", dxf)).toBe("dxf");
    expect(member("notes", dxf)).toBeNull();
    const csv = bytes("lot;label;amount\n03;Render;1200\n");
    expect(member("quantities.csv", csv)).toBe("csv");
    expect(member("readme", csv)).toBeNull();
  });

  it("opens a model, and does not take a STEP part for one", () => {
    expect(member("building.ifc", bytes("ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4'));\n"))).toBe("ifc");
    expect(member("model", bytes("ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC2X3'));\n"))).toBe("ifc");
    expect(member("part.stp", bytes("ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('AUTOMOTIVE_DESIGN'));\n"))).toBeNull();
    const stl = bytes("solid railing\nfacet normal 0 0 1\n");
    expect(member("railing.stl", stl)).toBe("stl");
    expect(member("railing", stl)).toBeNull();
  });

  it("opens an archive inside an archive, but not an Open XML document as one", () => {
    expect(member("lot-03.zip", bytes([0x50, 0x4b, 0x03, 0x04]))).toBe("archive");
    expect(member("budget.xlsx", bytes([0x50, 0x4b, 0x03, 0x04]))).toBe("xlsx");
  });
});

describe("the table", () => {
  it("never has two built-in formats claim the same type or extension", () => {
    // What makes the answer independent of registration order.
    const seen = new Map<string, string>();
    const claims = [
      ...BUILTIN_ORDER.map((id) => [id, MATCHERS[id]] as const),
      ["image", WASM_IMAGES] as const,
    ];
    for (const [id, m] of claims) {
      for (const key of [
        ...(m.types ?? []).map((t) => `type ${t}`),
        ...(m.containerTypes ?? []).map((t) => `type ${t}`),
        ...(m.extensions ?? []).map((e) => `ext ${e}`),
      ]) {
        const other = seen.get(key);
        expect(other === undefined || other === id, `${key}: ${other} and ${id}`).toBe(true);
        seen.set(key, id);
      }
    }
    // And no extension is a suffix of another's, which `endsWith` would let
    // both claim.
    const exts = [...seen.keys()].filter((k) => k.startsWith("ext ")).map((k) => k.slice(4));
    for (const a of exts)
      for (const b of exts)
        if (a !== b && a.endsWith(b)) expect(seen.get(`ext ${a}`), `${a} ends with ${b}`).toBe(seen.get(`ext ${b}`));
  });

  it("gives the same answers in any registration order", () => {
    const reversed = createDetector([...BUILTIN_ORDER].reverse().map((id) => ({ id, match: MATCHERS[id] })));
    const cases = [
      { type: "application/zip", path: "a.docx" },
      { type: "application/zip", path: "a.zip" },
      { type: "", path: "a.tar.gz" },
      { type: "text/plain", path: "a.csv" },
      { type: "application/octet-stream", path: "a.pdf" },
    ];
    for (const c of cases) expect(reversed.detect({ name: "", ...c })).toBe(detector.detect({ name: "", ...c }));
  });

  it("exports as JSON a server can mirror", () => {
    const table = JSON.parse(JSON.stringify(detector.table()));
    expect(table.formats.map((f: { id: string }) => f.id)).toEqual(BUILTIN_ORDER);
    expect(table.unknownTypes).toContain("application/octet-stream");
    expect(table.signatures[0]).toEqual({ type: "application/pdf", prefix: [37, 80, 68, 70, 45] });
    // A detector rebuilt from the JSON alone answers the same.
    const mirror = createDetector(table.formats.map((f: { id: string; matcher: object }) => ({ id: f.id, match: f.matcher })));
    for (const path of ["a.dwg", "a.xlsx", "a.csv", "a.mov", "a.ifc"]) expect(mirror.detect({ name: path })).toBe(detector.detect({ name: path }));
  });
});
