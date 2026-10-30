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

  it("plays FLAC, by its type, its name or its bytes", () => {
    expect(kind({ type: "audio/flac" })).toBe("audio");
    expect(kind({ path: "valse.FLAC" })).toBe("audio");
    expect(detector.detectBytes("track", new TextEncoder().encode("fLaC\0\0\0\x22"))).toBe("audio");
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

  it("opens a text member by its name, and believes the bytes over the name", () => {
    const text = new TextEncoder().encode("hello\n");
    expect(detector.detectBytes("docs/notes.txt", text)).toBe("text");
    expect(detector.detectBytes("data.json", text)).toBe("text");
    expect(detector.detectBytes("notes", text)).toBeNull();
    expect(detector.detectBytes("notes.txt", new TextEncoder().encode("%PDF-1.4\n"))).toBe("pdf");
    expect(detector.detectBytes("table.csv", text)).toBe("csv");
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
    expect(sniff(bytes([0, 0, 0, 0x0c], "JXL ", [0x0d, 0x0a, 0x87, 0x0a, 0, 0, 0, 0x14]))).toBe("image/jxl");
    expect(sniff(bytes([0xff, 0x0a, 0x4c]))).toBe("image/jxl");
    expect(sniff(bytes([0xff, 0xd8, 0xff, 0xe0]))).toBe("image/jpeg");
    for (const name of ["scan.jp2", "scan.jpf", "scan.jpx", "scan.j2k", "scan.j2c", "fax.jb2", "fax.jbig2", "photo.jxl"]) {
      expect(wasm.detect({ name, type: "" }), name).toBe("image");
      expect(detector.detect({ name, type: "" }), name).toBeNull();
    }
    expect(wasm.detectBytes("scan", bytes([0, 0, 0, 0x0c], "jP  ", [0x0d, 0x0a, 0x87, 0x0a]))).toBe("image");
  });

  it("knows the camera RAW files that are not TIFF underneath, and takes a CR3 for a photograph, not a video", () => {
    // What exav-render's fixtures start with (tests/fixtures/raw/make.py).
    const cases: [string, Uint8Array][] = [
      ["image/x-olympus-orf", bytes("IIRO", [8, 0, 0, 0])],
      ["image/x-olympus-orf", bytes("IIRS", [8, 0, 0, 0])],
      ["image/x-olympus-orf", bytes("MMOR", [0, 0, 0, 8])],
      ["image/x-panasonic-rw2", bytes("IIU", [0, 8, 0, 0, 0])],
      ["image/x-fuji-raf", bytes("FUJIFILMCCD-RAW 0201FF129504")],
      ["image/x-sigma-x3f", bytes("FOVb", [2, 0, 2, 0])],
      ["image/x-canon-crw", bytes("II", [0x1a, 0, 0, 0], "HEAPCCDR")],
      ["image/x-minolta-mrw", bytes([0], "MRM", [0, 1, 0, 0])],
      ["image/x-canon-cr3", bytes([0, 0, 0, 0x18], "ftyp", "crx ", [0, 0, 0, 1], "crx ")],
    ];
    for (const [type, head] of cases) expect(sniff(head), type).toBe(type);
    // Another brand is the video it was.
    expect(sniff(bytes([0, 0, 0, 0x18], "ftyp", "isom", [0, 0, 0, 1]))).toBe("video/mp4");
    // The TIFF-structured ones (DNG, CR2, NEF, ARW, PEF...) start as a TIFF.
    expect(sniff(bytes("II*", [0, 0x10, 0, 0, 0], "CR", [2, 0]))).toBe("image/tiff");
    expect(sniff(bytes("MM", [0], "*", [0, 0, 0, 8]))).toBe("image/tiff");
  });

  it("opens camera RAW files in the image plugin with WebAssembly decoders, by name, type or bytes, and by no other", () => {
    const wasm = createDetector([
      {
        id: "image",
        match: {
          types: [...MATCHERS.image.types!, ...WASM_IMAGES.types!],
          extensions: [...MATCHERS.image.extensions!, ...WASM_IMAGES.extensions!],
          extensionOverrides: WASM_IMAGES.extensionOverrides!,
        },
      },
    ]);
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
    // Their bytes alone, under a name that says nothing.
    expect(wasm.detectBytes("download", bytes("FUJIFILMCCD-RAW 0201"))).toBe("image");
    expect(wasm.detectBytes("download", bytes([0, 0, 0, 0x18], "ftyp", "crx ", [0, 0, 0, 1]))).toBe("image");
    expect(wasm.detectBytes("download", bytes("IIRO", [8, 0, 0, 0]))).toBe("image");
    expect(wasm.detectBytes("download", bytes("II*", [0, 8, 0, 0, 0]))).toBe("image");
  });

  it("knows the archives and compressed streams by their first bytes", () => {
    const at = (offset: number, ...parts: (string | number[])[]) => bytes(new Array(offset).fill(0), ...parts);
    const cases: [string, Uint8Array][] = [
      ["application/x-bzip2", bytes("BZh9", "1AY&SY")],
      ["application/x-xz", bytes([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 4])],
      ["application/zstd", bytes([0x28, 0xb5, 0x2f, 0xfd, 0x24])],
      ["application/x-lz4", bytes([0x04, 0x22, 0x4d, 0x18, 0x64])],
      ["application/x-lzip", bytes("LZIP", [1, 12])],
      ["application/x-rpm", bytes([0xed, 0xab, 0xee, 0xdb, 3, 0])],
      ["application/x-compress", bytes([0x1f, 0x9d, 0x90])],
      ["application/x-tar", at(257, "ustar", [0], "00")],
      ["application/vnd.ms-cab-compressed", bytes("MSCF", [0, 0, 0, 0, 0x10])],
      ["application/vnd.ms-htmlhelp", bytes("ITSF", [3, 0, 0, 0])],
      ["application/x-lzh-compressed", bytes([0x20, 0x4f], "-lh5-", [0])],
      ["application/x-lzh-compressed", bytes([0x20, 0x4f], "-lzs-", [0])],
      ["application/x-arj", bytes([0x60, 0xea, 0x2e, 0x00])],
      ["application/x-archive", bytes("!<arch>\n", "debian-binary   ")],
      ["application/x-cpio", bytes("070701", "00000001")],
      ["application/x-xar", bytes("xar!", [0, 0x1c])],
      ["application/x-ms-wim", bytes("MSWIM", [0, 0, 0, 0xd0, 0])],
      ["application/vnd.ms-tnef", bytes([0x78, 0x9f, 0x3e, 0x22, 1, 0])],
      ["application/x-vhdx", bytes("vhdxfile")],
      ["application/x-vmdk", bytes("KDMV", [1, 0, 0, 0])],
      ["application/x-qemu-disk", bytes([0x51, 0x46, 0x49, 0xfb, 0, 0, 0, 3])],
    ];
    for (const [type, head] of cases) {
      expect(sniff(head), type).toBe(type);
      expect(detector.detectBytes("member", head), type).toBe("archive");
    }
  });

  it("does not take text for an archive", () => {
    // Magic numbers that start with letters: a note that begins the same way is a note.
    for (const text of ["BZh is the bzip2 header", "LZIP is a format", "xar! is a shout", "MSCF is a type", "MSWIM is a word", "ITSF is not it"]) {
      expect(detector.detectBytes("notes.txt", bytes(text)), text).toBe("text");
      expect(detector.detectBytes("notes", bytes(text)), text).toBeNull();
    }
    expect(sniff(bytes("-lh5- at the front"))).toBe("");
    expect(sniff(bytes("MSCF", [0, 0, 0, 1]))).toBe("");
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

  it("recognises a PLY by its header and a GLB by its magic, and leaves other text alone", () => {
    const ply = bytes("ply\nformat ascii 1.0\nelement vertex 3\n");
    expect(member("scan", ply)).toBe("ply");
    expect(member("scan.bin", bytes("ply\r\nformat binary_little_endian 1.0\n"))).toBe("ply");
    expect(member("scan.ply", bytes("whatever"))).toBe("ply");
    // A note that starts with the word is a note.
    expect(member("notes.txt", bytes("ply\nthe plywood order\n"))).toBe("text");
    expect(member("notes", bytes("ply\nthe plywood order\n"))).toBeNull();
    const glb = bytes([0x67, 0x6c, 0x54, 0x46, 2, 0, 0, 0, 0x20, 0, 0, 0]);
    expect(member("chair", glb)).toBe("gltf");
    expect(member("chair.glb", bytes([1, 2, 3]))).toBe("gltf");
    // "glTF" with another version, or as text.
    expect(member("chair", bytes([0x67, 0x6c, 0x54, 0x46, 1, 0, 0, 0]))).toBeNull();
    expect(member("notes", bytes("glTF is a format"))).toBeNull();
    // Text with no signature: the name.
    expect(member("chair.obj", bytes("v 0 0 0\n"))).toBe("obj");
    expect(member("chair.gltf", bytes('{"asset":{}}'))).toBe("gltf");
    expect(member("chair", bytes("v 0 0 0\n"))).toBeNull();
  });

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
