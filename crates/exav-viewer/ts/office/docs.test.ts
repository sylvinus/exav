/**
 * Text documents go to exav-render's `docs` by their bytes when the options
 * say `converter: "exav"`, or when no external converter is set; to the
 * external converter when one is, and what `docs` does not recognise.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RenderContext } from "../core/types.js";
import { DocConversionError, sniffDocs } from "./docs.js";
import type { ConversionOptions } from "./index.js";

const bytes = (...parts: (string | number[])[]) =>
  new Uint8Array(parts.flatMap((p) => (typeof p === "string" ? [...p].map((c) => c.charCodeAt(0)) : p)));

const utf16 = (s: string) => [...s].flatMap((c) => [c.charCodeAt(0), 0]);

/** A ZIP's first local header (30 bytes), then `rest`. */
const zip = (rest: string) => bytes([0x50, 0x4b, 0x03, 0x04, ...new Array(26).fill(0)], rest);

const CFB = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

/** A compound file directory entry: the name padded to 64 bytes, its length with the terminator, the type. */
const entry = (name: string, type = 2) => {
  const units = utf16(name);
  return [...units, ...new Array(64 - units.length).fill(0), (name.length + 1) * 2, 0, type, 0];
};

const DOC = bytes(CFB, entry("1Table"), entry("WordDocument"));

describe("what the bytes are", () => {
  it("reads compound files with a Word document stream as DOC", () => {
    expect(sniffDocs(DOC)).toBe("doc");
    expect(sniffDocs(bytes(CFB, entry("wordDOCUMENT")))).toBe("doc");
    // A workbook is not one, nor is a file that only mentions the name.
    expect(sniffDocs(bytes(CFB, entry("Workbook")))).toBeNull();
    expect(sniffDocs(bytes(CFB, utf16("WordDocument")))).toBeNull();
    expect(sniffDocs(bytes(CFB, entry("WordDocument", 0)))).toBeNull();
  });

  it("reads RTF whatever the name, after white space or a byte order mark", () => {
    expect(sniffDocs(bytes("{\\rtf1\\ansi "))).toBe("rtf");
    expect(sniffDocs(bytes("\r\n  {\\rtf1"))).toBe("rtf");
    expect(sniffDocs(bytes([0xef, 0xbb, 0xbf], "{\\rtf1"))).toBe("rtf");
    expect(sniffDocs(bytes("{\\rt"))).toBeNull();
  });

  it("tells the packages apart by their members", () => {
    expect(sniffDocs(zip("mimetypeapplication/vnd.oasis.opendocument.text"))).toBe("odt");
    expect(sniffDocs(zip("mimetypeapplication/vnd.oasis.opendocument.text-template"))).toBe("odt");
    expect(sniffDocs(zip("mimetypeapplication/vnd.oasis.opendocument.presentation"))).toBeNull();
    expect(sniffDocs(zip("[Content_Types].xml ... word/document.xml"))).toBe("docx");
    expect(sniffDocs(zip("[Content_Types].xml ... ppt/presentation.xml"))).toBeNull();
    expect(sniffDocs(zip("Index/Document.iwa Index/DocumentStylesheet.iwa"))).toBe("pages");
    expect(sniffDocs(zip("Index/Document.iwa Index/Tables/Tile.iwa"))).toBeNull();
    expect(sniffDocs(zip("Index/Document.iwa Index/Slide-1.iwa"))).toBeNull();
    // An OpenDocument package whose mimetype is not first: told by its members, unless they are a deck's or a workbook's.
    expect(sniffDocs(zip("content.xml styles.xml META-INF/manifest.xml"))).toBe("odt");
    expect(sniffDocs(zip("content.xml styles.xml ppt/slides/slide1.xml"))).toBeNull();
    expect(sniffDocs(zip("content.xml styles.xml xl/workbook.xml"))).toBeNull();
  });

  it("reads flat OpenDocument text and Word 2003 XML, and nothing else as text", () => {
    expect(sniffDocs(bytes('<?xml version="1.0"?>\n<office:document office:mimetype="application/vnd.oasis.opendocument.text">'))).toBe("fodt");
    expect(sniffDocs(bytes('<office:document office:mimetype="application/vnd.oasis.opendocument.spreadsheet">'))).toBeNull();
    expect(sniffDocs(bytes('<?xml version="1.0"?><w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">'))).toBe("wml2003");
    expect(sniffDocs(bytes("<html><body>"))).toBeNull();
    expect(sniffDocs(new Uint8Array())).toBeNull();
  });

  it("reads Word's Web Page, alone or in its MIME message, and no other HTML", () => {
    const word = '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word"><body>';
    expect(sniffDocs(bytes(word))).toBe("html");
    expect(sniffDocs(bytes(`<!DOCTYPE html>\n${word}`))).toBe("html");
    expect(sniffDocs(bytes(`MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary="b"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n${word}`))).toBe("html");
    // An Excel page, a plain page and a mail with no Word in it.
    expect(sniffDocs(bytes('<html xmlns:x="urn:schemas-microsoft-com:office:excel"><body>'))).toBeNull();
    expect(sniffDocs(bytes("MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello"))).toBeNull();
  });
});

const convertDocs = vi.fn();
vi.mock("./docs.js", async (original) => ({ ...(await original<typeof import("./docs.js")>()), convertDocs: (...a: unknown[]) => convertDocs(...a) }));

// The external converter, a function the tests answer for.
const convertExternal = vi.fn();
vi.mock("./external.js", async (original) => ({
  ...(await original<typeof import("./external.js")>()),
  externalUrl: async (spec: string) => `https://converter.test/${spec}`,
  loadExternal: async () => ({ convert: (...a: unknown[]) => convertExternal(...a), prefetch: () => ["pkg/data.br"] }),
}));

afterEach(() => {
  convertDocs.mockReset();
  convertExternal.mockReset();
});

/** A context over `data`, with an external converter set or not. */
function context(data: Uint8Array, options: ConversionOptions, external: boolean) {
  const nested = vi.fn(() => ({ resize() {}, destroy() {} }));
  const statuses: unknown[] = [];
  const ctx = {
    file: { id: "f", name: "a.doc" },
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

const EXAV: ConversionOptions = { converter: "exav" };

/** The error `mount` fails with. */
const failure = async (kind: "doc" | "odt" | "rtf", ctx: RenderContext<ConversionOptions>) => {
  const { rendererFor } = await import("./convert.js");
  return Promise.resolve(rendererFor(kind).mount(document.createElement("div"), ctx)).then(
    () => null,
    (e: unknown) => e,
  );
};

describe("a text document opened with converter: exav", () => {
  it("is converted by exav-render's docs and shown as DOCX", async () => {
    const { rendererFor } = await import("./convert.js");
    convertDocs.mockResolvedValue({ docx: new Uint8Array([1, 2, 3]).buffer, paragraphs: 1, warnings: "" });
    const { ctx, nested, statuses } = context(DOC, EXAV, false);
    await rendererFor("doc").mount(document.createElement("div"), ctx);
    expect(convertDocs).toHaveBeenCalledWith(DOC, "doc", expect.objectContaining({ signal: ctx.signal }));
    const [, file] = nested.mock.calls[0] as unknown as [unknown, { format: string; source: { bytes: Uint8Array } }];
    expect(file.format).toBe("docx");
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
      convertDocs.mockRejectedValue(new Error(reason));
      // With an external converter set, as without: it never gets the file.
      for (const external of [true, false]) {
        const { ctx, nested } = context(DOC, EXAV, external);
        const error = await failure("doc", ctx);
        expect(error, reason).toBeInstanceOf(DocConversionError);
        expect((error as DocConversionError).kind).toBe(kind);
        expect(nested).not.toHaveBeenCalled();
        expect(convertExternal).not.toHaveBeenCalled();
      }
    }
  });

  it("converts RTF under any name, and an ODT", async () => {
    convertDocs.mockRejectedValue(new Error("unsupported"));
    for (const [kind, data, format] of [
      ["doc", bytes("{\\rtf1 x}"), "rtf"],
      ["rtf", bytes("{\\rtf1 x}"), "rtf"],
      ["odt", zip("mimetypeapplication/vnd.oasis.opendocument.text"), "odt"],
    ] as const) {
      const { ctx } = context(data, EXAV, true);
      const error = await failure(kind, ctx);
      expect(error).toBeInstanceOf(DocConversionError);
      expect(convertDocs).toHaveBeenLastCalledWith(data, format, expect.anything());
    }
  });

  it("fails with the abort, not with a conversion error, when the session was stopped", async () => {
    convertDocs.mockRejectedValue(new Error("destroyed"));
    const { ctx } = context(DOC, EXAV, false);
    const abort = new AbortController();
    abort.abort();
    const error = await failure("doc", { ...ctx, signal: abort.signal } as RenderContext<ConversionOptions>);
    expect(error).not.toBeInstanceOf(DocConversionError);
    expect(String(error)).toMatch(/destroyed/);
  });

  it("goes to the external converter with what it does not recognise", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "pdf", bytes: new Uint8Array([5]) });
    const { ctx, nested } = context(zip("something.bin"), EXAV, true);
    await rendererFor("odt").mount(document.createElement("div"), ctx);
    expect(convertDocs).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ hint: "odt" }));
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("pdf");
  });

  it("ends in the needs-converter error with what it does not recognise and no external converter", async () => {
    const { rendererFor } = await import("./convert.js");
    const { ctx, statuses } = context(zip("something.bin"), EXAV, false);
    await rendererFor("odt").mount(document.createElement("div"), ctx);
    const last = statuses.at(-1) as { error: { code: string; cause: { kind: string; format: string } } };
    expect(last.error.code).toBe("needs_converter");
    expect(last.error.cause).toMatchObject({ kind: "needs-converter", format: "odt" });
  });

  it("is shown as it is when it is a DOCX under another name", async () => {
    const { rendererFor } = await import("./convert.js");
    const { ctx, nested } = context(zip("[Content_Types].xml word/document.xml"), EXAV, false);
    await rendererFor("doc").mount(document.createElement("div"), ctx);
    expect(convertDocs).not.toHaveBeenCalled();
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("docx");
  });
});

describe("prefetching a text document", () => {
  it("names nothing for the kinds `docs` converts, whose module is the viewer's, but the external converter's files where it takes them", async () => {
    const { prefetchUrls } = await import("./convert.js");
    for (const kind of ["doc", "odt", "rtf"] as const) {
      expect(await prefetchUrls(kind, "/assets/", EXAV)).toEqual([]);
      expect(await prefetchUrls(kind, "/assets/", {})).toEqual([]);
      // With an external converter set the kind goes to it by default: its module, and what it names.
      expect(await prefetchUrls(kind, "/assets/", { externalConverter: "ext" })).toEqual(["https://converter.test/ext", "https://converter.test/pkg/data.br"]);
      expect(await prefetchUrls(kind, "/assets/", { converter: "external", externalConverter: "ext" })).toHaveLength(2);
      expect(await prefetchUrls(kind, "/assets/", { converter: "exav", externalConverter: "ext" })).toEqual([]);
    }
  });
});

describe("a text document opened by default", () => {
  it("goes to the external converter when there is one, not to exav-render's docs", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "pdf", bytes: new Uint8Array([5]) });
    const { ctx } = context(DOC, {}, true);
    await rendererFor("doc").mount(document.createElement("div"), ctx);
    expect(convertDocs).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalledWith(DOC, expect.objectContaining({ hint: "doc" }));
  });

  it("goes to exav-render's docs when there is no external converter", async () => {
    const { rendererFor } = await import("./convert.js");
    convertDocs.mockResolvedValue({ docx: new Uint8Array([1]).buffer, paragraphs: 1, warnings: "" });
    const { ctx } = context(DOC, {}, false);
    await rendererFor("doc").mount(document.createElement("div"), ctx);
    expect(convertDocs).toHaveBeenCalled();
    expect(convertExternal).not.toHaveBeenCalled();
  });

  it("goes to the external converter when the options say so", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "pdf", bytes: new Uint8Array([5]) });
    const { ctx } = context(DOC, { converter: "external" }, true);
    await rendererFor("doc").mount(document.createElement("div"), ctx);
    expect(convertDocs).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalled();
  });
});
