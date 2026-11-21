/**
 * Presentations and OpenDocument drawings go to exav-render's `slides` by
 * their bytes; to the external converter what it does not recognise, or
 * everything when the options say so.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { RenderContext } from "../core/types.js";
import { compoundFile } from "../test/compound.js";
import { officeKindsNow, start } from "../test/sniff.js";
import { storedZip } from "../test/stored-zip.js";
import type { ConversionOptions } from "./index.js";
import { SlideConversionError, sniffSlides as sniff } from "./slides.js";

// The containers are read by exav's readers, which the tests run in this process.
vi.mock("./zip-engine.js", () => import("../test/sniff.js"));
beforeAll(start);
const sniffSlides = (b: Uint8Array) => sniff(b, officeKindsNow(b));

const bytes = (...parts: (string | number[])[]) =>
  new Uint8Array(parts.flatMap((p) => (typeof p === "string" ? [...p].map((c) => c.charCodeAt(0)) : p)));

const utf16 = (s: string) => [...s].flatMap((c) => [c.charCodeAt(0), 0]);

/** A stored ZIP whose members are the words of `rest`; a first word `mimetype...` is the member of that name holding the rest of the word. */
const zip = (rest: string): Uint8Array =>
  storedZip(
    rest
      .split(/\s+/)
      .filter((w) => w && w !== "...")
      .map((w, i) => (i === 0 && w.startsWith("mimetype") ? ["mimetype", bytes(w.slice(8))] : [w, new Uint8Array()]) as [string, Uint8Array]),
  );

const CFB = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

/** A compound file directory entry: the name padded to 64 bytes, its length with the terminator, the type. */
const entry = (name: string, type = 2) => {
  const units = utf16(name);
  return [...units, ...new Array(64 - units.length).fill(0), (name.length + 1) * 2, 0, type, 0];
};

const PPT = compoundFile(["Current User", "PowerPoint Document"]);

describe("what the bytes are", () => {
  it("reads compound files with a PowerPoint stream as PPT, whatever its version", () => {
    expect(sniffSlides(PPT)).toBe("ppt");
    // PowerPoint 95 has no "Current User" stream of that kind; PowerPoint 4 has a "PP40" stream.
    expect(sniffSlides(compoundFile(["PowerPoint Document"]))).toBe("ppt");
    // One the reader could not look into (`officeKinds` says `null`) is taken as its name says.
    expect(sniff(compoundFile(["WordDocument"]), null)).toBe("ppt");
    expect(sniffSlides(compoundFile(["PP40"]))).toBe("ppt");
    // A workbook is not one, nor is a file that only mentions the name.
    expect(sniffSlides(compoundFile(["Workbook"]))).toBeNull();
    expect(sniffSlides(bytes(CFB, utf16("PowerPoint Document")))).toBeNull();
    expect(sniffSlides(compoundFile([["PP40", new Uint8Array(), 0]]))).toBeNull();
    // Names compare without regard to ASCII case, as the converter's reader does.
    expect(sniffSlides(compoundFile(["PowerPoint DocUment"]))).toBe("ppt");
    expect(sniffSlides(compoundFile(["pp40"]))).toBe("ppt");
  });

  it("tells a compound file by its directory, not by a stream name written in its content", () => {
    const quoted = compoundFile([["Notes", bytes(entry("PowerPoint Document"))]]);
    expect(sniffSlides(quoted)).toBeNull();
  });

  it("reads the presentation of a compound file that holds a Word document and a workbook too", () => {
    expect(sniffSlides(compoundFile(["WordDocument", "Workbook", "PowerPoint Document"]))).toBe("ppt");
  });

  it("reads PowerPoint 2 to 4 files, Windows and Macintosh, and their BinHex text", () => {
    expect(sniffSlides(bytes([0xed, 0xde, 0xad, 0x0b, 2, 0, 0, 0]))).toBe("ppt");
    expect(sniffSlides(bytes([0x0b, 0xad, 0xde, 0xed, 0, 0, 0, 3]))).toBe("ppt");
    // The header of a BinHex 4.0 file named "powerpoint", type SLDS, creator PPNT.
    const banner = "(This file must be converted with BinHex 4.0)\r\r:";
    expect(sniffSlides(bytes(banner + `#R"[Gf9bF'pTER3!8da%8e"36P3!!!!!#DB!!!!!`))).toBe("ppt");
    // A text file named "other", type TEXT, creator ttxt.
    expect(sniffSlides(bytes(banner + `"@pdD'9b!&4&@&4dG(Kd!!!!!!QQ!!!!!!`))).toBeNull();
    expect(sniffSlides(bytes("(not binhex)"))).toBeNull();
  });

  it("tells the packages apart by their members", () => {
    expect(sniffSlides(zip("mimetypeapplication/vnd.oasis.opendocument.presentation"))).toBe("odp");
    expect(sniffSlides(zip("mimetypeapplication/vnd.oasis.opendocument.presentation-template"))).toBe("odp");
    expect(sniffSlides(zip("mimetypeapplication/vnd.oasis.opendocument.text"))).toBeNull();
    expect(sniffSlides(zip("[Content_Types].xml ... ppt/presentation.xml"))).toBe("pptx");
    expect(sniffSlides(zip("Index/Document.iwa Index/Slide-1.iwa Index/MasterSlide.iwa"))).toBe("key");
    expect(sniffSlides(zip("Doc.key/Index.zip"))).toBe("key");
    // Keynote 1 to 5: XML, gzipped or not.
    expect(sniffSlides(zip("index.apxl.gz"))).toBe("key");
    expect(sniffSlides(zip("Contents/PkgInfo index.apxl"))).toBe("key");
    expect(sniffSlides(zip("presentation.apxl"))).toBe("key");
    expect(sniffSlides(zip("Index/Document.iwa Index/Tables/Tile.iwa"))).toBeNull();
    expect(sniffSlides(zip("index.xml.gz"))).toBeNull();
  });

  it("tells a package by the members of its directory, not by bytes inside a member", () => {
    // A ZIP that holds a deck, stored: the deck's own directory is in the last bytes.
    const inner = zip("[Content_Types].xml ppt/presentation.xml");
    expect(sniffSlides(storedZip([["backup.zip", inner]]))).toBeNull();
  });

  it("reads flat OpenDocument presentations, and nothing else as text", () => {
    const fodp = '<?xml version="1.0"?>\n<office:document office:mimetype="application/vnd.oasis.opendocument.presentation">';
    expect(sniffSlides(bytes(fodp))).toBe("fodp");
    expect(sniffSlides(bytes("<html><body>"))).toBeNull();
    expect(sniffSlides(new Uint8Array())).toBeNull();
  });

  it("reads a Visio 2013 package by its visio/ directory, and not a PPTX or a binary Visio file", () => {
    expect(sniffSlides(zip("[Content_Types].xml visio/document.xml visio/pages/page1.xml"))).toBe("vsdx");
    expect(sniffSlides(zip("[Content_Types].xml ppt/presentation.xml"))).toBe("pptx");
    expect(sniffSlides(zip("[Content_Types].xml word/document.xml"))).toBeNull();
    expect(sniffSlides(bytes("Visio (TM) Drawing\r\n"))).toBeNull();
  });

  it("reads OpenDocument drawings, packaged or flat, and OpenOffice 1.x's media type", () => {
    expect(sniffSlides(zip("mimetypeapplication/vnd.oasis.opendocument.graphics"))).toBe("odg");
    expect(sniffSlides(zip("mimetypeapplication/vnd.oasis.opendocument.graphics-template"))).toBe("odg");
    expect(sniffSlides(zip("mimetypeapplication/vnd.oasis.opendocument.drawing"))).toBe("odg");
    expect(sniffSlides(zip("mimetypeapplication/vnd.oasis.opendocument.text"))).toBeNull();
    const fodg = '<?xml version="1.0"?>\n<office:document office:mimetype="application/vnd.oasis.opendocument.graphics">';
    expect(sniffSlides(bytes(fodg))).toBe("fodg");
    expect(sniffSlides(bytes(fodg.replace("graphics", "drawing")))).toBe("fodg");
    expect(sniffSlides(bytes('<office:document office:mimetype="application/vnd.oasis.opendocument.text">'))).toBeNull();
  });
});

const convertSlides = vi.fn();
vi.mock("./slides.js", async (original) => ({ ...(await original<typeof import("./slides.js")>()), convertSlides: (...a: unknown[]) => convertSlides(...a) }));

// The external converter, a function the tests answer for.
const convertExternal = vi.fn();
vi.mock("./external.js", async (original) => ({
  ...(await original<typeof import("./external.js")>()),
  externalUrl: async (spec: string) => `https://converter.test/${spec}`,
  loadExternal: async () => ({ convert: (...a: unknown[]) => convertExternal(...a) }),
}));

afterEach(() => {
  convertSlides.mockReset();
  convertExternal.mockReset();
});

/** A context over `data`, with an external converter set or not. */
function context(data: Uint8Array, options: ConversionOptions, external: boolean) {
  const nested = vi.fn(() => ({ resize() {}, destroy() {} }));
  const statuses: unknown[] = [];
  const ctx = {
    file: { id: "f", name: "a.ppt" },
    options: { ...options, ...(external && { externalConverter: "ext" }) },
    source: { bytes: async () => data },
    signal: new AbortController().signal,
    assetBase: "/assets/",
    status: (s: unknown) => statuses.push(s),
    controllers() {},
    mountNested: nested,
  } as unknown as RenderContext<ConversionOptions>;
  return { ctx, nested, statuses };
}

/** The error `mount` fails with. */
const failure = async (kind: "ppt" | "odp" | "keynote" | "odg", ctx: RenderContext<ConversionOptions>) => {
  const { rendererFor } = await import("./convert.js");
  return Promise.resolve(rendererFor(kind).mount(document.createElement("div"), ctx)).then(
    () => null,
    (e: unknown) => e,
  );
};

describe("a presentation opened", () => {
  it("is converted by exav-render's slides and shown as PPTX", async () => {
    const { rendererFor } = await import("./convert.js");
    convertSlides.mockResolvedValue({ pptx: new Uint8Array([1, 2, 3]).buffer, slides: 1, warnings: "" });
    const { ctx, nested, statuses } = context(PPT, {}, false);
    await rendererFor("ppt").mount(document.createElement("div"), ctx);
    expect(convertSlides).toHaveBeenCalledWith(PPT, "ppt", expect.objectContaining({ signal: ctx.signal }));
    const [, file] = nested.mock.calls[0] as unknown as [unknown, { format: string; source: { bytes: Uint8Array } }];
    expect(file.format).toBe("pptx");
    expect([...file.source.bytes]).toEqual([1, 2, 3]);
    expect(statuses).toContainEqual({ phase: "converting", step: "convert" });
  });

  it("fails with its converter's error and its kind when it recognised the file and could not read it", async () => {
    for (const [reason, kind] of [
      ["encrypted", "encrypted"],
      ["too-large", "too-large"],
      ["malformed", "malformed"],
      ["unsupported", "unsupported"],
      ["not-format", "not-format"],
      ["no answer within 120000 ms", "timeout"],
      ["unreachable", "crashed"],
    ]) {
      convertSlides.mockRejectedValue(new Error(reason));
      // With an external converter set, as without: an external converter set
      // gets the file next, and failing too, leaves the first error the file's.
      for (const external of [true, false]) {
        convertExternal.mockClear();
        const { ctx, nested } = context(PPT, {}, external);
        const error = await failure("ppt", ctx);
        expect(error, reason).toBeInstanceOf(SlideConversionError);
        expect((error as SlideConversionError).kind).toBe(kind);
        expect(nested).not.toHaveBeenCalled();
        expect(convertExternal).toHaveBeenCalledTimes(external ? 1 : 0);
      }
    }
  });

  it("is converted as a drawing, a page to a slide, when it is an OpenDocument drawing", async () => {
    const { rendererFor } = await import("./convert.js");
    convertSlides.mockResolvedValue({ pptx: new Uint8Array([7]).buffer, slides: 2, warnings: "" });
    for (const [data, format] of [
      [zip("mimetypeapplication/vnd.oasis.opendocument.graphics"), "odg"],
      [bytes('<office:document office:mimetype="application/vnd.oasis.opendocument.graphics">'), "fodg"],
    ] as const) {
      const { ctx, nested } = context(data, {}, false);
      await rendererFor("odg").mount(document.createElement("div"), ctx);
      expect(convertSlides).toHaveBeenLastCalledWith(data, format, expect.anything());
      expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("pptx");
    }
    expect(convertExternal).not.toHaveBeenCalled();
  });

  it("fails with the converter's kind for a drawing it recognised and could not read", async () => {
    convertSlides.mockRejectedValue(new Error("malformed"));
    const { ctx } = context(zip("mimetypeapplication/vnd.oasis.opendocument.graphics"), {}, true);
    const error = await failure("odg", ctx);
    expect(error).toBeInstanceOf(SlideConversionError);
    expect((error as SlideConversionError).kind).toBe("malformed");
    expect((error as SlideConversionError).format).toBe("odg");
    // Tried by the external converter after it, which failed too.
    expect(convertExternal).toHaveBeenCalledTimes(1);
  });

  it("goes on to the external converter for a version of PowerPoint or of Keynote the converter does not read", async () => {
    const { rendererFor } = await import("./convert.js");
    convertSlides.mockRejectedValue(new Error("unsupported"));
    convertExternal.mockResolvedValue({ format: "pdf", bytes: new Uint8Array([5]) });
    for (const [kind, data, format] of [
      ["ppt", bytes([0xed, 0xde, 0xad, 0x0b, 2, 0, 0, 0]), "ppt"],
      ["keynote", zip("index.apxl.gz"), "key"],
    ] as const) {
      const { ctx, nested } = context(data, {}, true);
      await rendererFor(kind).mount(document.createElement("div"), ctx);
      expect(convertSlides).toHaveBeenLastCalledWith(data, format, expect.anything());
      expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("pdf");
      // Without an external converter it fails with the converter's reason.
      const alone = context(data, {}, false);
      expect(await failure(kind, alone.ctx)).toBeInstanceOf(SlideConversionError);
    }
  });

  it("goes to the external converter with what it does not recognise", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "pdf", bytes: new Uint8Array([5]) });
    const { ctx, nested } = context(zip("something.bin"), {}, true);
    await rendererFor("keynote").mount(document.createElement("div"), ctx);
    expect(convertSlides).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ hint: "keynote" }));
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("pdf");
  });

  it("ends in the needs-converter error with what it does not recognise and no external converter", async () => {
    const { rendererFor } = await import("./convert.js");
    const { ctx, statuses } = context(zip("something.bin"), {}, false);
    await rendererFor("keynote").mount(document.createElement("div"), ctx);
    const last = statuses.at(-1) as { error: { code: string; cause: { kind: string; format: string } } };
    expect(last.error.code).toBe("needs_converter");
    expect(last.error.cause).toMatchObject({ kind: "needs-converter", format: "keynote" });
    expect(convertSlides).not.toHaveBeenCalled();
  });

  it("is shown as it is when it is a PPTX under another name", async () => {
    const { rendererFor } = await import("./convert.js");
    const { ctx, nested } = context(zip("[Content_Types].xml ppt/presentation.xml"), {}, false);
    await rendererFor("odp").mount(document.createElement("div"), ctx);
    expect(convertSlides).not.toHaveBeenCalled();
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("pptx");
  });

  it("goes to the external converter alone when the options say so", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "pdf", bytes: new Uint8Array([5]) });
    const { ctx } = context(PPT, { converter: "external" }, true);
    await rendererFor("ppt").mount(document.createElement("div"), ctx);
    expect(convertSlides).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalledWith(PPT, expect.objectContaining({ hint: "ppt" }));
  });
});
