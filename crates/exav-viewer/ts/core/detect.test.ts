/**
 * Which plugin opens a file. The tables are the acceptance tables the viewer
 * was specified with; they run here against the data-driven detector built
 * from the built-in matchers.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import { contentTypes, officeInWorker, packageKinds, sniffInWorker } from "../test/sniff.js";
import { storedZip } from "../test/stored-zip.js";
import { createDetector, PACKAGE_FORMATS } from "./detect.js";
import { BUILTIN_ORDER, CONTAINER_TYPES, MATCHERS, WASM_IMAGES } from "./formats.js";
import type { BuiltinFormat } from "./types.js";

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

  it("plays FLAC, by its type or its name", () => {
    expect(kind({ type: "audio/flac" })).toBe("audio");
    expect(kind({ path: "valse.FLAC" })).toBe("audio");
  });

  it("shows SVG as an image, never as text", () => {
    expect(kind({ path: "logo.svg" })).toBe("image");
    expect(kind({ type: "image/svg+xml" })).toBe("image");
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
    expect(kind({ type: "application/vnd.ms-excel", path: "x/table.xls" })).toBe("xls");
    expect(kind({ type: "text/plain", path: "x/lots.csv" })).toBe("csv");
    expect(kind({ type: "text/plain", path: "x/notes.txt" })).toBe("text");
    expect(kind({ type: "text/plain", path: "x/notes" })).toBeNull();
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

  it("opens the archives, packages and images a person looks inside, by name or by type", () => {
    const named = [
      "a.tar.zst", "a.tzst", "a.zst", "a.lz4", "a.lz", "a.tlz", "a.Z", "a.taz", "a.tbz",
      "setup.cab", "help.chm", "disc.ISO", "old.lzh", "old.lha", "old.arj", "libx.a", "x.ar", "tool.deb", "tool.udeb",
      "initrd.cpio", "app.xar", "app.pkg", "Xcode.xip", "Install.dmg", "install.wim", "install.esd",
      "winmail.dat", "dir/WINMAIL.DAT", "disk.vhd", "disk.vhdx", "disk.vmdk", "disk.qcow2", "vm.ova",
      "old.zoo", "old.arc", "kr.alz", "kr.egg",
      "lib.jar", "site.war", "app.apk", "split.apks", "store.xapk", "bundle.aab", "app.ipa", "ext.xpi", "pkg.whl", "pkg.nupkg", "ext.vsix", "map.kmz",
      "app.appx", "app.appxbundle", "app.msix", "app.msixbundle", "sd-card.img",
      "comic.cbz", "comic.cbr", "comic.cb7", "comic.cbt",
      "big.7z.001", "docs.ZIP.001", "set.rar.001", "set.tar.001", "span.z01",
    ];
    for (const path of named) {
      expect(kind({ path }), path).toBe("archive");
      expect(kind({ type: "application/octet-stream", path }), path).toBe("archive");
    }
    const typed = [
      "application/zstd", "application/x-lz4", "application/x-lzip", "application/x-lzma", "application/x-rpm", "application/x-compress", "application/vnd.ms-cab-compressed",
      "application/x-iso9660-image", "application/x-lzh-compressed", "application/x-arj", "application/x-archive",
      "application/vnd.debian.binary-package", "application/x-cpio", "application/x-xar", "application/x-apple-diskimage",
      "application/x-ms-wim", "application/vnd.ms-tnef", "application/java-archive", "application/vnd.android.package-archive",
      "application/vnd.comicbook+zip", "application/vnd.comicbook-rar",
    ];
    for (const type of typed) expect(kind({ type }), type).toBe("archive");
    // What a desktop's own tables give by extension (shared-mime-info, Windows, Playwright's).
    const desktop: [string, string][] = [
      ["application/x-compressed-tar", "a.tgz"], ["application/x-xz-compressed-tar", "a.txz"],
      ["application/x-bzip2-compressed-tar", "a.tbz2"], ["application/x-zstd-compressed-tar", "a.tzst"],
      ["application/x-tarz", "a.taz"], ["application/x-compressed", "a.tgz"],
      ["application/vnd.efi.iso", "a.iso"], ["application/x-sega-cd-rom", "a.iso"], ["application/x-gamecube-rom", "a.iso"],
      ["application/x-freearc", "a.arc"], ["application/x-newton-compatible-pkg", "a.pkg"], ["application/ovf", "a.ova"],
      ["application/x-vhd-disk", "a.vhd"], ["application/x-vhdx-disk", "a.vhdx"], ["application/x-vmdk-disk", "a.vmdk"],
    ];
    for (const [type, path] of desktop) expect(kind({ type, path }), `${type} ${path}`).toBe("archive");
    // VHDL source is not a virtual disk.
    expect(kind({ type: "text/x-vhdl", path: "alu.vhd" })).toBeNull();
    // Documents that are zips, and what another reader opens, are not archives to a viewer.
    for (const path of ["a.epub", "a.msg", "a.eml", "a.sit", "a.ace", "a.exe"]) {
      expect(kind({ type: "application/octet-stream", path }), path).toBeNull();
    }
    for (const path of ["a.odt", "a.ods", "a.doc"]) expect(kind({ type: "application/octet-stream", path }), path).toBe(path.slice(2));
    expect(kind({ type: "application/zip", path: "a.odp" })).toBe("odp");
  });

  it("opens a model and a mesh", () => {
    expect(kind({ path: "x/building.ifc" })).toBe("ifc");
    expect(kind({ type: "model/ifc" })).toBe("ifc");
    expect(kind({ path: "x/bracket.STL" })).toBe("stl");
    expect(kind({ type: "model/stl" })).toBe("stl");
    expect(kind({ type: "application/sla" })).toBe("stl");
    expect(kind({ path: "x/building.ifczip" })).toBeNull();
  });

  it("opens OBJ, PLY and glTF by type, and by extension where the type is unknown or plain text", () => {
    expect(kind({ type: "model/obj" })).toBe("obj");
    expect(kind({ path: "x/chair.OBJ" })).toBe("obj");
    expect(kind({ type: "text/plain", path: "x/chair.obj" })).toBe("obj");
    expect(kind({ type: "application/x-tgif", path: "x/chair.obj" })).toBe("obj");
    expect(kind({ type: "model/ply" })).toBe("ply");
    expect(kind({ type: "application/x-ply" })).toBe("ply");
    expect(kind({ type: "text/plain", path: "scan.ply" })).toBe("ply");
    expect(kind({ type: "model/gltf+json" })).toBe("gltf");
    expect(kind({ type: "model/gltf-binary" })).toBe("gltf");
    expect(kind({ path: "x/chair.gltf" })).toBe("gltf");
    expect(kind({ type: "application/octet-stream", path: "x/chair.glb" })).toBe("gltf");
    // Plain text is claimed by name only, and only for these extensions.
    expect(kind({ type: "text/plain", path: "x/chair.txt" })).not.toBe("obj");
    expect(kind({ type: "text/plain" })).toBeNull();
    expect(kind({ type: "image/png", path: "x/chair.obj" })).toBe("image");
  });

  it("opens text by its name or its type, and only a name or a type it knows", () => {
    for (const path of ["a.txt", "a.LOG", "README.md", "a.markdown", "a.json", "a.xml", "a.kml", "a.gpx", "a.yaml", "a.yml", "a.toml", "a.ini", "a.conf", "a.js", "a.ts", "a.py", "a.sh", "a.css", "a.c", "a.h", "a.rs", "a.go", "a.java", "a.html", "a.htm", "a.srt", "a.vtt", "a.diff", "a.patch"]) {
      expect(kind({ path }), path).toBe("text");
      expect(kind({ type: "application/octet-stream", path }), path).toBe("text");
      expect(kind({ type: "text/plain", path }), path).toBe("text");
    }
    for (const type of ["text/markdown", "application/json", "text/xml", "application/xml", "application/atom+xml", "text/html", "text/vtt", "application/yaml", "text/x-diff", "text/css"]) {
      expect(kind({ type }), type).toBe("text");
    }
    // Browsers type .ts as an MPEG transport stream and .js as a script.
    expect(kind({ type: "video/mp2t", path: "src/app.ts" })).toBe("text");
    expect(kind({ type: "text/javascript", path: "src/app.js" })).toBe("text");
    // A file is not text because it happens to be: an unknown name stays unclaimed.
    expect(kind({ type: "text/plain", path: "a.xyz" })).toBeNull();
    expect(kind({ type: "text/plain", path: "LICENSE" })).toBeNull();
    expect(kind({ type: "text/plain" })).toBeNull();
    expect(kind({ type: "application/octet-stream", path: "a.bin" })).toBeNull();
    // SVG is a document that can carry scripts: drawn as an image, never shown as XML.
    expect(kind({ type: "text/plain", path: "a.svg" })).toBeNull();
    expect(kind({ type: "image/svg+xml", path: "a.svg" })).toBe("image");
    // The table reader keeps its files.
    expect(kind({ type: "text/plain", path: "a.csv" })).toBe("csv");
    expect(kind({ path: "a.tsv" })).toBe("csv");
  });

  it("claims the Office formats no browser engine reads, which are converted", () => {
    expect(kind({ type: "application/msword" })).toBe("doc");
    expect(kind({ type: "text/rtf" })).toBe("rtf");
    expect(kind({ path: "x/letter.RTF" })).toBe("rtf");
    expect(kind({ type: "application/vnd.oasis.opendocument.text" })).toBe("odt");
    expect(kind({ type: "application/vnd.ms-powerpoint" })).toBe("ppt");
    expect(kind({ path: "x/show.pps" })).toBe("ppt");
    expect(kind({ type: "application/vnd.oasis.opendocument.presentation" })).toBe("odp");
    expect(kind({ type: "application/vnd.oasis.opendocument.spreadsheet" })).toBe("ods");
    expect(kind({ type: "application/x-msexcel" })).toBe("xls");
    // Windows types every .csv so when Excel is installed: the 1997 workbook needs its extension.
    expect(kind({ type: "application/vnd.ms-excel" })).toBeNull();
    expect(kind({ type: "application/vnd.ms-excel", path: "x/quote.xls" })).toBe("xls");
    // Templates, slide shows and flat XML, with their documents.
    for (const [path, format] of [
      ["x/letter.dot", "doc"],
      ["x/letter.ott", "odt"],
      ["x/letter.fodt", "odt"],
      ["x/deck.pps", "ppt"],
      ["x/deck.pot", "ppt"],
      ["x/deck.otp", "odp"],
      ["x/deck.fodp", "odp"],
      ["x/sheet.xlt", "xls"],
      ["x/sheet.ots", "ods"],
      ["x/sheet.fods", "ods"],
    ]) expect(kind({ path }), path).toBe(format);
    expect(kind({ type: "application/vnd.oasis.opendocument.text-flat-xml" })).toBe("odt");
    expect(kind({ type: "application/vnd.oasis.opendocument.spreadsheet-template" })).toBe("ods");
    // Apple's, zipped: by type, or by name over a zip type.
    expect(kind({ type: "application/vnd.apple.keynote" })).toBe("keynote");
    expect(kind({ type: "application/zip", path: "x/talk.key" })).toBe("keynote");
    expect(kind({ type: "application/x-iwork-numbers-sffnumbers" })).toBe("numbers");
    expect(kind({ path: "x/budget.numbers" })).toBe("numbers");
  });

  it("claims the drawing and page layout formats, which are converted", () => {
    expect(kind({ type: "application/vnd.oasis.opendocument.graphics" })).toBe("odg");
    expect(kind({ type: "application/vnd.visio" })).toBe("visio");
    expect(kind({ type: "application/vnd.ms-visio.drawing.macroEnabled.main+xml" })).toBe("visio");
    expect(kind({ type: "application/x-coreldraw" })).toBe("coreldraw");
    expect(kind({ type: "application/vnd.ms-publisher" })).toBe("publisher");
    expect(kind({ type: "application/x-pagemaker" })).toBe("pagemaker");
    expect(kind({ type: "application/x-wpg" })).toBe("wpg");
    for (const [path, format] of [
      ["x/plan.otg", "odg"],
      ["x/plan.fodg", "odg"],
      ["x/plan.vsd", "visio"],
      ["x/plan.vdx", "visio"],
      ["x/plan.vstx", "visio"],
      ["x/logo.cmx", "coreldraw"],
      ["x/flyer.pub", "publisher"],
      ["x/flyer.p65", "pagemaker"],
      ["x/logo.fh11", "freehand"],
      ["x/flyer.qxd", "quarkxpress"],
      ["x/logo.zmf", "zonerdraw"],
      ["x/clip.wpg", "wpg"],
    ]) expect(kind({ path }), path).toBe(format);
    // Zips by name: Open XML Visio, CorelDRAW X4 and later, Zoner Draw 5.
    expect(kind({ type: "application/zip", path: "x/plan.vsdx" })).toBe("visio");
    expect(kind({ type: "application/zip", path: "x/logo.cdr" })).toBe("coreldraw");
    expect(kind({ type: "application/zip", path: "x/logo.zmf" })).toBe("zonerdraw");
    expect(kind({ type: "application/zip", path: "x/plan.odg" })).toBe("odg");
  });

  it("opens Open XML templates and slide shows as their documents, unconverted", () => {
    expect(kind({ path: "x/letter.dotx" })).toBe("docx");
    expect(kind({ type: "application/zip", path: "x/show.ppsx" })).toBe("pptx");
    expect(kind({ path: "x/deck.potx" })).toBe("pptx");
    expect(kind({ type: "application/vnd.openxmlformats-officedocument.presentationml.slideshow" })).toBe("pptx");
  });

  it("leaves everything else to the browser", () => {
    expect(kind({ type: "application/vnd.ms-excel" })).toBeNull();
    expect(kind({ type: "application/vnd.ms-project" })).toBeNull();
    expect(kind({ type: "application/x-iwork-pages-sffpages" })).toBeNull();
  });

  it("follows a link rather than drawing it", () => {
    expect(kind({ kind: "link", type: "application/pdf" })).toBeNull();
  });

  it("falls back to the extension only where the type says nothing", () => {
    expect(kind({ path: "documents/old.PDF" })).toBe("pdf");
    expect(kind({ path: "documents/old.JPG" })).toBe("image");
    expect(kind({ path: "documents/quote.xls" })).toBe("xls");
    expect(kind({ path: "documents/plan.mpp" })).toBeNull();
    expect(kind({ type: "application/octet-stream", path: "documents/photo.jpg" })).toBe("image");
    expect(kind({ type: "application/octet-stream", path: "documents/notes.rtf" })).toBe("rtf");
    expect(kind({ type: "application/octet-stream", path: "documents/notes.pages" })).toBeNull();
    // RTF is text, and typed so by some systems.
    expect(kind({ type: "text/plain", path: "documents/notes.rtf" })).toBe("rtf");
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

/** The detectors of this file, with exav's detection in this process, for the image plugin with and without the WebAssembly decoders. */
const rust = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: MATCHERS[id] })), sniffInWorker);
const wasmImages = { ...MATCHERS.image, types: [...MATCHERS.image.types!, ...WASM_IMAGES.types!], extensions: [...MATCHERS.image.extensions!, ...WASM_IMAGES.extensions!], extensionOverrides: WASM_IMAGES.extensionOverrides! };
const rustWasm = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: id === "image" ? wasmImages : MATCHERS[id] })), sniffInWorker);

describe("what the first bytes say", () => {
  it("is what exav's detection says: the types it gives are claimed by a matcher", async () => {
    const types = await contentTypes();
    expect(types.length).toBeGreaterThan(40);
    const family = (t: string) => (t.startsWith("image/") && !["image/vnd.dwg", "image/vnd.dxf"].includes(t) ? "image" : null);
    for (const t of types) {
      const id = rustWasm.detect({ type: t, name: "" });
      if (CONTAINER_TYPES.includes(t)) {
        // Claimed by the name alone, or by the archive plugin when no name is.
        expect(["archive", null], t).toContain(id);
        continue;
      }
      expect(id, t).not.toBeNull();
      if (family(t)) expect(id, t).toBe("image");
      else if (t === "application/pdf") expect(id).toBe("pdf");
      else if (t === "application/rtf") expect(id).toBe("rtf");
      else if (t === "image/vnd.dwg") expect(id).toBe("dwg");
      else if (t === "image/vnd.dxf") expect(id).toBe("dxf");
      else if (t.startsWith("model/")) expect(id, t).toBe({ "model/gltf-binary": "gltf", "model/ifc": "ifc", "model/ply": "ply" }[t]);
      else expect(id, t).toBe("archive");
    }
  });

  it("has its ZIP directory checked against the limits for the formats exav's readers check as packages", async () => {
    expect([...PACKAGE_FORMATS].sort()).toEqual((await packageKinds()).sort());
  });

  it("is nothing where there is no engine", async () => {
    const alone = createDetector([{ id: "pdf", match: MATCHERS.pdf }]);
    expect(await alone.sniff(bytes("%PDF-1.7"))).toBe("");
    expect(await alone.detectBytes("plan.png", bytes("%PDF-1.7"))).toBeNull();
    expect(await alone.detectBytes("plan.pdf", bytes("%PDF-1.7"))).toBe("pdf");
  });

  it("knows the common signatures", async () => {
    expect(await rust.sniff(bytes("%PDF-1.7\n"))).toBe("application/pdf");
    expect(await rust.sniff(bytes([0x89], "PNG", [0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13], "IHDR"))).toBe("image/png");
    expect(await rust.sniff(bytes([0xff, 0xd8, 0xff, 0xe0, 0, 0x10], "JFIF", [0]))).toBe("image/jpeg");
    expect(await rust.sniff(bytes([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0]))).toBe("application/zip");
    expect(await rust.sniff(bytes("II*", [0, 8, 0, 0, 0, 0, 0]))).toBe("image/tiff");
    expect(await rust.sniff(bytes("BM", [0x36, 0x10, 0x0e, 0], [0, 0, 0, 0, 0x36, 0, 0, 0]))).toBe("image/bmp");
  });

  it("is given the file's size, which the end of a file needs", async () => {
    // A ZIP behind a stub is told by its end record: not by the start of a long file.
    const stub = new Uint8Array(4000).fill(0x80);
    expect(await rust.sniff(stub, 4000)).toBe("");
    expect(await rust.sniff(stub, 4_000_000)).toBe("");
    // A head of a longer file that is a PNG's is one.
    expect(await rust.sniff(bytes([0x89], "PNG", [0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13], "IHDR"), 5_000_000)).toBe("image/png");
  });

  it("knows JPEG 2000, JBIG2 and JPEG XL, which only the WebAssembly decoders open", async () => {
    expect(await rust.sniff(bytes([0, 0, 0, 0x0c], "jP  ", [0x0d, 0x0a, 0x87, 0x0a, 0, 0, 0, 0x14], "ftyp"))).toBe("image/jp2");
    expect(await rust.sniff(bytes([0xff, 0x4f, 0xff, 0x51, 0, 0x2f, 0, 0]))).toBe("image/jp2");
    expect(await rust.sniff(bytes([0x97], "JB2", [0x0d, 0x0a, 0x1a, 0x0a, 1, 0, 0, 0]))).toBe("image/x-jbig2");
    expect(await rust.sniff(bytes([0, 0, 0, 0x0c], "JXL ", [0x0d, 0x0a, 0x87, 0x0a, 0, 0, 0, 0x14]))).toBe("image/jxl");
    expect(await rust.sniff(bytes([0xff, 0x0a, 0x4c, 0, 0, 0]))).toBe("image/jxl");
    for (const name of ["scan.jp2", "scan.jpf", "scan.jpx", "scan.j2k", "scan.j2c", "fax.jb2", "fax.jbig2", "photo.jxl"]) {
      expect(rustWasm.detect({ name, type: "" }), name).toBe("image");
      expect(detector.detect({ name, type: "" }), name).toBeNull();
    }
    expect(await rustWasm.detectBytes("scan", bytes([0, 0, 0, 0x0c], "jP  ", [0x0d, 0x0a, 0x87, 0x0a, 0, 0, 0, 0]))).toBe("image");
    // The plugin without the decoders has no claim to it.
    expect(await rust.detectBytes("scan", bytes([0, 0, 0, 0x0c], "jP  ", [0x0d, 0x0a, 0x87, 0x0a, 0, 0, 0, 0]))).toBeNull();
  });

  it("knows the camera RAW files that are not TIFF underneath", async () => {
    const cases: [string, Uint8Array][] = [
      ["image/x-olympus-orf", bytes("IIRO", [8, 0, 0, 0, 0, 0])],
      ["image/x-olympus-orf", bytes("IIRS", [8, 0, 0, 0, 0, 0])],
      ["image/x-olympus-orf", bytes("MMOR", [0, 0, 0, 8, 0, 0])],
      ["image/x-panasonic-rw2", bytes("IIU", [0, 8, 0, 0, 0, 0, 0])],
      ["image/x-fuji-raf", bytes("FUJIFILMCCD-RAW 0201FF129504", [0, 0, 0])],
      ["image/x-sigma-x3f", bytes("FOVb", [2, 0, 2, 0, 0, 0])],
      ["image/x-canon-crw", bytes("II", [0x1a, 0, 0, 0], "HEAPCCDR", [0, 0, 0, 0])],
      ["image/x-minolta-mrw", bytes([0], "MRM", [0, 1, 0, 0, 0, 0])],
      ["image/x-canon-cr3", bytes([0, 0, 0, 0x18], "ftyp", "crx ", [0, 0, 0, 1], "crx ", [0, 0, 0, 0])],
    ];
    for (const [type, head] of cases) {
      expect(await rust.sniff(head), type).toBe(type);
      expect(await rustWasm.detectBytes("download", head), type).toBe("image");
    }
    // The TIFF-structured ones (DNG, CR2, NEF, ARW, PEF...) start as a TIFF.
    expect(await rust.sniff(bytes("II*", [0, 0x10, 0, 0, 0], "CR", [2, 0]))).toBe("image/tiff");
    expect(await rust.sniff(bytes("MM", [0], "*", [0, 0, 0, 8, 0, 0]))).toBe("image/tiff");
  });

  it("opens camera RAW files in the image plugin with WebAssembly decoders, by name or type, and by no other", () => {
    const wasm = rustWasm;
    const names = [
      "IMG_0001.CR2", "IMG_0001.CR3", "IMG_0001.crw", "DSC_0001.NEF", "DSC_0001.NRW", "DSC_0001.ARW", "DSC_0001.SR2", "DSC_0001.SRF", "P1000001.ORF", "P1000001.RW2",
      "P1000001.RAW", "P1000001.RWL", "DSCF0001.RAF", "IMGP0001.PEF", "SAM_0001.SRW", "B0001.3FR", "C0001.IIQ", "SDIM0001.X3F", "photo.dng", "PHOTO.GPR", "DiMAGE.MRW",
    ];
    for (const name of names) {
      expect(wasm.detect({ name, type: "" }), name).toBe("image");
      expect(detector.detect({ name, type: "" }), name).toBeNull();
    }
    for (const type of ["image/x-adobe-dng", "image/x-canon-cr2", "image/x-nikon-nef", "image/x-sony-arw", "image/x-fuji-raf", "image/x-canon-cr3"]) {
      expect(wasm.detect({ name: "file", type }), type).toBe("image");
    }
    // A desktop types a Kodak .dcr as the Shockwave file it also is: the name answers.
    expect(wasm.detect({ name: "K0001.DCR", type: "application/x-director" })).toBe("image");
    expect(wasm.detect({ name: "movie.dir", type: "application/x-director" })).toBeNull();
  });

  it("knows the archives and compressed streams by their first bytes", async () => {
    const at = (offset: number, ...parts: (string | number[])[]) => bytes(new Array(offset).fill(0), ...parts);
    const cases: [string, Uint8Array][] = [
      ["application/x-bzip2", bytes("BZh9", "1AY&SY", [0, 0, 0, 0])],
      ["application/x-xz", bytes([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 4])],
      ["application/zstd", bytes([0x28, 0xb5, 0x2f, 0xfd, 0x24, 0, 0, 0])],
      ["application/x-lz4", bytes([0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0, 0, 0])],
      ["application/x-lzip", bytes("LZIP", [1, 12, 0, 0])],
      ["application/x-rpm", bytes([0xed, 0xab, 0xee, 0xdb, 3, 0], new Array(100).fill(0))],
      ["application/x-compress", bytes([0x1f, 0x9d, 0x90, 0, 0, 0])],
      ["application/x-tar", at(257, "ustar", [0], "00")],
      ["application/vnd.ms-cab-compressed", bytes("MSCF", [0, 0, 0, 0, 0x10, 0, 0, 0])],
      ["application/vnd.ms-htmlhelp", bytes("ITSF", [3, 0, 0, 0, 0x60, 0, 0, 0])],
      ["application/x-archive", bytes("!<arch>\n", "debian-binary   ", [0, 0])],
      ["application/x-cpio", bytes("070701", "00000001", [0, 0])],
      ["application/x-xar", bytes("xar!", [0, 0x1c, 0, 1])],
      ["application/vnd.ms-tnef", bytes([0x78, 0x9f, 0x3e, 0x22, 1, 0])],
      ["application/x-vmdk", bytes("KDMV", [1, 0, 0, 0], new Array(520).fill(0))],
      ["application/x-qemu-disk", bytes([0x51, 0x46, 0x49, 0xfb, 0, 0, 0, 3], new Array(80).fill(0))],
    ];
    for (const [type, head] of cases) {
      expect(await rust.sniff(head), type).toBe(type);
      expect(await rust.detectBytes("member", head), type).toBe("archive");
    }
  });

  it("knows the real archives, compressed streams and documents of the fixtures", async () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
    const unpack = "exav-unpack/tests/fixtures";
    const render = "exav-render/tests/fixtures";
    const cases: [string, string][] = [
      [`${unpack}/lz4/one.lz4`, "application/x-lz4"],
      [`${unpack}/lzip_simple.lz`, "application/x-lzip"],
      [`${unpack}/lzma_simple.lzma`, "application/x-lzma"],
      [`${unpack}/checksum/clean.wim`, "application/x-ms-wim"],
      [`${unpack}/checksum/clean.bz2`, "application/x-bzip2"],
      [`${unpack}/egg/posix_small.egg`, "application/x-egg"],
      [`${unpack}/alz/defaults.alz`, "application/x-alz"],
      [`${unpack}/lzw/short.b12.Z`, "application/x-compress"],
      [`${unpack}/xz/simple.xz`, "application/x-xz"],
      [`${unpack}/rpm/hello.rpm`, "application/x-rpm"],
      [`${unpack}/zoo/default.zoo`, "application/x-zoo"],
      [`${unpack}/7z/lzma.7z`, "application/x-7z-compressed"],
      [`${unpack}/chm/benign-lzx.chm`, "application/vnd.ms-htmlhelp"],
      [`${unpack}/cab/mszip_lzx_qtm.cab`, "application/vnd.ms-cab-compressed"],
      [`${unpack}/pdf/qpdf_actions_aes128.pdf`, "application/pdf"],
      [`${render}/office/slides/sample.ppt`, "application/x-ole-storage"],
      [`${render}/images/rgb.png`, "image/png"],
      [`${render}/images/sequential-interleaved.jpg`, "image/jpeg"],
      [`${render}/images/rgb.jp2`, "image/jp2"],
      [`${render}/images/rgb.jxl`, "image/jxl"],
      [`${render}/images/generic.jb2`, "image/x-jbig2"],
    ];
    for (const [file, type] of cases) {
      const head = new Uint8Array(fs.readFileSync(path.join(root, file))).subarray(0, 65536);
      expect(await rust.sniff(head), file).toBe(type);
    }
  });

  it("does not take text for an archive or a picture", async () => {
    // Magic numbers that start with letters: a note that begins the same way is a note.
    for (const text of ["BZh is the bzip2 header", "LZIP is a format", "xar! is a shout", "MSCF is a type", "MSWIM is a word", "ITSF is not it", "BM is a name", "P1,Alice,12", "070701,Alice"]) {
      expect(await rust.detectBytes("notes.txt", bytes(text)), text).toBe("text");
      expect(await rust.detectBytes("table.csv", bytes(text)), text).toBe("csv");
      expect(await rust.detectBytes("notes", bytes(text)), text).toBeNull();
    }
    expect(await rust.sniff(bytes("-lh5- at the front"))).toBe("");
    expect(await rust.sniff(bytes("MSCF", [0, 0, 0, 1]))).toBe("");
  });

  it("says nothing when the bytes say nothing", async () => {
    expect(await rust.sniff(bytes("Hello, this is a note."))).toBe("");
    expect(await rust.sniff(new Uint8Array())).toBe("");
  });

  it("tells a PLY, GLB or IFC model by the check its reader owns, whatever its name", async () => {
    const glb = bytes("glTF", [2, 0, 0, 0, 0x20, 0, 0, 0]);
    const ifc = bytes("ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4'));\n");
    const ply = bytes("ply\nformat ascii 1.0\nelement vertex 3\n");
    expect(await rust.sniff(glb)).toBe("model/gltf-binary");
    expect(await rust.sniff(ifc)).toBe("model/ifc");
    expect(await rust.sniff(ply)).toBe("model/ply");
    expect(await rust.detectBytes("chair", glb)).toBe("gltf");
    expect(await rust.detectBytes("building.txt", ifc)).toBe("ifc");
    expect(await rust.detectBytes("scan.bin", ply)).toBe("ply");
    // Another STEP schema, a text that opens with the word, a GLB of another version.
    expect(await rust.detectBytes("part", bytes("ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('AUTOMOTIVE_DESIGN'));\n"))).toBeNull();
    expect(await rust.detectBytes("note", bytes("ply wood is cheap\n"))).toBeNull();
    expect(await rust.detectBytes("old", bytes("glTF", [1, 0, 0, 0, 0x20, 0, 0, 0]))).toBeNull();
  });

  it("does not tell audio, video or HEIC photographs: their type or their name does", async () => {
    // No detection of the scanner's says what they are, and the viewer has none of its own.
    const silent: [string, Uint8Array][] = [
      ["fLaC", bytes("fLaC", [0, 0, 0, 0x22])],
      ["ID3", bytes("ID3", [3, 0, 0, 0, 0, 0, 0, 0])],
      ["OggS", bytes("OggS", [0, 2, 0, 0, 0, 0, 0, 0])],
      ["WAVE", bytes("RIFF", [0x24, 0, 0, 0], "WAVE", "fmt ", [16, 0, 0, 0])],
      ["WebM", bytes([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01])],
      ["MP4", isoBmff("isom")],
      ["QuickTime", isoBmff("qt  ")],
      ["HEIC", isoBmff("heic")],
    ];
    for (const [what, head] of silent) {
      expect(await rust.sniff(head), what).toBe("");
      expect(await rust.detectBytes("member", head), what).toBeNull();
    }
    // By the name, as before.
    expect(await rust.detectBytes("clip.mp4", isoBmff("isom"))).toBe("video");
    expect(await rust.detectBytes("track.flac", bytes("fLaC", [0, 0, 0, 0x22]))).toBe("audio");
  });
});

describe("which plugin opens a member of an archive", () => {
  const member = (name: string, b: Uint8Array) => rust.detectBytes(name, b);
  const jpeg = bytes([0xff, 0xd8, 0xff, 0xe0, 0, 0x10], "JFIF", [0, 1, 1]);
  const zip = bytes([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0]);

  it("opens a text member by its name, and believes the bytes over the name", async () => {
    const text = bytes("hello\n");
    expect(await member("docs/notes.txt", text)).toBe("text");
    expect(await member("data.json", text)).toBe("text");
    expect(await member("notes", text)).toBeNull();
    expect(await member("notes.txt", bytes("%PDF-1.4\n"))).toBe("pdf");
    expect(await member("table.csv", text)).toBe("csv");
  });

  it("believes the bytes over the name", async () => {
    expect(await member("plan.pdf", jpeg)).toBe("image");
    expect(await member("quote", bytes("%PDF-1.4"))).toBe("pdf");
    expect(await member("quote.png", bytes("%PDF-1.4"))).toBe("pdf");
  });

  it("tells a drawing by its bytes, and the formats with no signature by their name", async () => {
    const dxf = bytes("0\nSECTION\n2\nENTITIES\n");
    expect(await member("survey.dxf", dxf)).toBe("dxf");
    expect(await member("notes", dxf)).toBe("dxf");
    const csv = bytes("lot;label;amount\n03;Render;1200\n");
    expect(await member("quantities.csv", csv)).toBe("csv");
    expect(await member("readme", csv)).toBeNull();
    const stl = bytes("solid railing\nfacet normal 0 0 1\n");
    expect(await member("railing.stl", stl)).toBe("stl");
    expect(await member("railing", stl)).toBeNull();
    expect(await member("chair.obj", bytes("v 0 0 0\n"))).toBe("obj");
    expect(await member("chair", bytes("v 0 0 0\n"))).toBeNull();
    expect(await member("chair.gltf", bytes('{"asset":{}}'))).toBe("gltf");
  });

  it("opens an archive inside an archive, but not an Open XML document as one", async () => {
    expect(await member("lot-03.zip", zip)).toBe("archive");
    expect(await member("lot-03", zip)).toBe("archive");
    expect(await member("budget.xlsx", zip)).toBe("xlsx");
    expect(await member("letter.docx", zip)).toBe("docx");
  });
});

describe("a file whose bytes say one type and whose name says another", () => {
  const pdf = bytes("%PDF-1.7\n%", [0xe2, 0xe3, 0xcf, 0xd3, 10]);
  const png = bytes([0x89], "PNG", [0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13], "IHDR", [0, 0, 0, 1]);
  const jpeg = bytes([0xff, 0xd8, 0xff, 0xe0, 0, 0x10], "JFIF", [0, 1, 1]);
  const zip = bytes([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0]);
  const gzip = bytes([0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0]);
  const ole = bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], new Array(120).fill(0));
  const file = (name: string, type: string, head: Uint8Array, size?: number) => rustWasm.detectFile({ name, path: name, type }, head, size);
  const here = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "e2e", "fixtures");

  it("is shown as the bytes say: a PDF named .png is a PDF", async () => {
    expect(await file("plan.png", "image/png", pdf)).toBe("pdf");
    expect(await file("plan.png", "", pdf)).toBe("pdf");
    expect(await file("scan.pdf", "application/pdf", png)).toBe("image");
    expect(await file("scan.pdf", "application/pdf", jpeg)).toBe("image");
    expect(await file("notes.txt", "text/plain", zip)).toBe("archive");
    expect(await file("report.pdf", "application/pdf", gzip)).toBe("archive");
    expect(await file("photos.zip", "application/zip", pdf)).toBe("pdf");
    // The host's metadata alone would have said the other.
    expect(rustWasm.detect({ name: "plan.png", type: "image/png" })).toBe("image");
    expect(rustWasm.detect({ name: "scan.pdf", type: "application/pdf" })).toBe("pdf");
  });

  it("is shown as the bytes say, for a drawing, an RTF and a file that starts as a longer one does", async () => {
    const plan = new Uint8Array(fs.readFileSync(path.join(here, "plan.dwg")));
    const dxf = new Uint8Array(fs.readFileSync(path.join(here, "plan.dxf")));
    expect(await file("plan.pdf", "application/pdf", plan.subarray(0, 65536), plan.length)).toBe("dwg");
    expect(await file("plan.png", "image/png", dxf.subarray(0, 65536), dxf.length)).toBe("dxf");
    expect(await file("letter.pdf", "application/pdf", bytes("{\\rtf1\\ansi\\deff0 {\\fonttbl}}"))).toBe("rtf");
    // A file of 4 GB starts with the PDF's first kilobytes, the rest being unknown.
    expect(await file("big.png", "image/png", pdf, 4_000_000_000)).toBe("pdf");
  });

  it("is shown as its name says where the bytes are what a file of that name can be", async () => {
    // A .docx is a zip, a .doc a compound file.
    expect(await file("report.docx", "", zip)).toBe("docx");
    expect(await file("report", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", zip)).toBe("docx");
    expect(await file("report.doc", "", zip)).toBe("doc");
    expect(await file("budget.xls", "application/vnd.ms-excel", zip)).toBe("xls");
    for (const [name, format] of [["a.doc", "doc"], ["a.dot", "doc"], ["a.xls", "xls"], ["a.ppt", "ppt"], ["a.pps", "ppt"], ["a.pub", "publisher"], ["a.vsd", "visio"]]) {
      expect(await file(name!, "", ole), name).toBe(format);
      expect(await file(name!, "application/octet-stream", ole), name).toBe(format);
    }
    expect(await file("a.docx", "", ole)).toBe("docx");
    // A zip is an archive when the name says no document.
    expect(await file("photos.zip", "application/zip", zip)).toBe("archive");
    expect(await file("download", "application/octet-stream", zip)).toBe("archive");
    // An RTF saved as .doc is read as RTF.
    expect(await file("letter.doc", "application/msword", bytes("{\\rtf1\\ansi\\deff0 {\\fonttbl}}"))).toBe("rtf");
  });

  it("opens nothing where the bytes say what the viewer has no plugin for", async () => {
    expect(await file("plan.png", "image/png", ole)).toBeNull();
    expect(await file("plan.pdf", "application/pdf", ole)).toBeNull();
    // A TIFF named .jpg, with the plugin that has no decoder for it.
    const tiff = bytes("II*", [0, 8, 0, 0, 0, 0, 0]);
    expect(await rust.detectFile({ name: "a.jpg", type: "image/jpeg" }, tiff)).toBeNull();
    expect(await rustWasm.detectFile({ name: "a.jpg", type: "image/jpeg" }, tiff)).toBe("image");
  });

  it("leaves a note a note and a table a table, whatever they start with", async () => {
    for (const text of ["BM is a name\n", "P1,Alice,12\nP2,Bob,13\n", "070701,Alice\n", "!<arch>\nis how an ar file starts\n", "Notes\nif (head.startsWith(\"%PDF-1.\")) {}\n"]) {
      expect(await file("table.csv", "text/csv", bytes(text)), text).toBe("csv");
      expect(await file("table.csv", "", bytes(text)), text).toBe("csv");
      expect(await file("notes.txt", "text/plain", bytes(text)), text).toBe("text");
      expect(await file("notes.md", "", bytes(text)), text).toBe("text");
    }
  });

  it("is opened by its bytes when its name says nothing", async () => {
    expect(await file("download", "", png)).toBe("image");
    expect(await file("download", "application/octet-stream", pdf)).toBe("pdf");
    expect(await file("a8f3e2", "", jpeg)).toBe("image");
    expect(await file("a8f3e2", "", bytes("hello\n"))).toBeNull();
  });

  it("is shown by its name and type where the bytes say nothing", async () => {
    expect(await file("plan.pdf", "application/pdf", new Uint8Array())).toBe("pdf");
    expect(await file("table.csv", "text/csv", bytes("a;b\n1;2\n"))).toBe("csv");
    expect(await file("clip.mp4", "video/mp4", isoBmff("isom"))).toBe("video");
    expect(await file("a.xyz", "", bytes([1, 2, 3, 4, 5, 6, 7, 8]))).toBeNull();
    // A link has no bytes.
    expect(await rustWasm.detectFile({ name: "a.pdf", kind: "link" }, pdf)).toBeNull();
  });

  it("is shown by its name and type, with a warning, where the engine fails", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const broken = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: MATCHERS[id] })), () => Promise.reject(new Error("the module trapped")));
    expect(await broken.detectFile({ name: "plan.png", type: "image/png" }, pdf)).toBe("image");
    expect(warn).toHaveBeenCalledOnce();
    warn.mockRestore();
  });

  it("rejects when it is stopped", async () => {
    const stop = new AbortController();
    const slow = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: MATCHERS[id] })), (_h, _s, signal) => new Promise((_, reject) => signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))));
    const asked = slow.detectFile({ name: "plan.png", type: "image/png" }, pdf, undefined, stop.signal);
    stop.abort();
    await expect(asked).rejects.toThrow("aborted");
  });
});

describe("a ZIP told by its members", () => {
  const text = (s: string) => new TextEncoder().encode(s);
  const zipOf = (...members: [string, string][]) => storedZip(members.map(([name, data]) => [name, text(data)]));
  const registered = (ids: readonly BuiltinFormat[]) => createDetector(ids.map((id) => ({ id, match: MATCHERS[id] })), sniffInWorker, undefined, undefined, undefined, officeInWorker);
  const office = registered(BUILTIN_ORDER);
  /** The last `n` bytes of `file`, as a reader of ranges gives them. */
  const tailOf = (file: Uint8Array) => async (n: number) => ({ bytes: file.subarray(Math.max(0, file.length - n)), size: file.length });
  const as = (name: string, file: Uint8Array, type = "", detector = office) => detector.detectFile({ name, path: name, type }, file, file.length, undefined, tailOf(file));

  // Some writers put the document properties before the content types.
  const docx = zipOf(["docProps/app.xml", "<Properties/>"], ["[Content_Types].xml", "<Types/>"], ["word/document.xml", "<w:document/>"]);

  it("opens an Office package that no name claims in the plugin of its format", async () => {
    for (const name of ["x.zip", "", "attachment.bin", "x.7z"]) expect(await as(name, docx), name).toBe("docx");
    expect(await as("x", docx, "application/zip")).toBe("docx");
    expect(await as("x", docx, "application/octet-stream")).toBe("docx");
    const parts = (main: string) => zipOf(["[Content_Types].xml", "<Types/>"], [main, "<x/>"]);
    expect(await as("x.zip", parts("xl/workbook.xml"))).toBe("xlsx");
    expect(await as("x.zip", parts("xl/workbook.bin"))).toBe("xlsx");
    expect(await as("x.zip", parts("ppt/presentation.xml"))).toBe("pptx");
    expect(await as("x.zip", parts("visio/document.xml"))).toBe("visio");
  });

  it("opens an OpenDocument package, by its mimetype or by its members", async () => {
    const odf = (kind: string) => zipOf(["mimetype", `application/vnd.oasis.opendocument.${kind}`], ["content.xml", "<office:document-content/>"]);
    expect(await as("x.zip", odf("text"))).toBe("odt");
    expect(await as("x.zip", odf("spreadsheet"))).toBe("ods");
    expect(await as("x.zip", odf("presentation"))).toBe("odp");
    expect(await as("x.zip", odf("graphics"))).toBe("odg");
    // Without a usable mimetype the members do not say which of the three: an archive.
    expect(await as("x.zip", zipOf(["content.xml", "<a/>"], ["styles.xml", "<a/>"]))).toBe("archive");
  });

  it("reads the end of the file as it is given, a part at a time, when the head is not all of it", async () => {
    const pad = new Uint8Array(300_000).fill(0x61);
    const big = storedZip([["docProps/app.xml", pad], ["[Content_Types].xml", text("<Types/>")], ["word/document.xml", text("<w:document/>")]]);
    const asked: number[] = [];
    const tail = async (n: number) => {
      asked.push(n);
      return tailOf(big)(n);
    };
    const found = await office.detectFile({ name: "x.zip", type: "" }, big.subarray(0, 64 * 1024), big.length, undefined, tail);
    expect(found).toBe("docx");
    expect(asked.length).toBeGreaterThan(0);
    expect(Math.max(...asked)).toBeLessThan(big.length);
  });

  it("keeps the routing of a file whose name claims a format, or that is told nothing", async () => {
    expect(await as("x.docx", docx)).toBe("docx");
    // A name that claims another zip format stays: a workbook's name on a Word package is the engine's to find wrong.
    expect(await as("x.xlsx", docx)).toBe("xlsx");
    expect(await as("x.png", docx)).toBe("archive");
    expect(await as("x.pdf", docx)).toBe("archive");
    // No way to read the end of the file: the name and the type decide.
    expect(await office.detectFile({ name: "x.zip", type: "" }, docx, docx.length)).toBe("archive");
    // And with no engine for the members.
    expect(await as("x.zip", docx, "", rust)).toBe("archive");
  });

  it("is an archive when the members do not make it one package of a format the viewer opens", async () => {
    const plain = zipOf(["readme.txt", "hello"]);
    expect(await as("x.zip", plain)).toBe("archive");
    // The names of parts written in a member are not members.
    expect(await as("x.zip", zipOf(["notes.txt", "[Content_Types].xml word/document.xml"]))).toBe("archive");
    // Neither is a part deeper in the tree.
    expect(await as("x.zip", zipOf(["[Content_Types].xml", "<Types/>"], ["backup/word/document.xml", "<a/>"]))).toBe("archive");
    // Two formats: which one is not for the members to say.
    expect(await as("x.zip", zipOf(["[Content_Types].xml", "<Types/>"], ["word/document.xml", "<a/>"], ["xl/workbook.xml", "<a/>"]))).toBe("archive");
    // iWork's members are told apart by names any ZIP may have: a site's feed is not a spreadsheet.
    expect(await as("x.zip", zipOf(["public/index.xml", "<rss/>"], ["public/about/index.html", "<p/>"]))).toBe("archive");
    // A directory that will not open.
    const cut = docx.subarray(0, docx.length - 30);
    expect(await as("x.zip", cut)).toBe("archive");
  });

  it("is an archive where the format's plugin is not registered, or the reader fails, and rejects when stopped", async () => {
    const archives = registered(["archive"]);
    expect(await as("x.zip", docx, "", archives)).toBe("archive");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const broken = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: MATCHERS[id] })), sniffInWorker, undefined, undefined, undefined, () => Promise.reject(new Error("the module trapped")));
    expect(await as("x.zip", docx, "", broken)).toBe("archive");
    expect(warn).toHaveBeenCalledOnce();
    warn.mockRestore();
    const stop = new AbortController();
    const slow = createDetector(BUILTIN_ORDER.map((id) => ({ id, match: MATCHERS[id] })), sniffInWorker, undefined, undefined, undefined, (_h, _t, _s, signal) => new Promise((_, reject) => signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))));
    const asked = slow.detectFile({ name: "x.zip", type: "" }, docx, docx.length, stop.signal, tailOf(docx));
    // Let the first bytes be typed, so that the reader is the one waited for.
    await new Promise((r) => setTimeout(r, 25));
    stop.abort();
    await expect(asked).rejects.toThrow("aborted");
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
    expect(table.containerTypes).toEqual(["application/zip", "application/x-zip-compressed", "application/x-ole-storage"]);
    expect(table.signatures).toBeUndefined();
    // A detector rebuilt from the JSON alone answers the same.
    const mirror = createDetector(table.formats.map((f: { id: string; matcher: object }) => ({ id: f.id, match: f.matcher })));
    for (const path of ["a.dwg", "a.xlsx", "a.csv", "a.mov", "a.ifc"]) expect(mirror.detect({ name: path })).toBe(detector.detect({ name: path }));
  });
});
