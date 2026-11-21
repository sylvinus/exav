/**
 * Text documents go to exav-render's `docs` by their bytes when the options
 * say `converter: "exav"`, or when no external converter is set; to the
 * external converter when one is, and what `docs` does not recognise.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { RenderContext } from "../core/types.js";
import { compoundFile } from "../test/compound.js";
import { officeKindsNow, start } from "../test/sniff.js";
import { storedZip } from "../test/stored-zip.js";
import { DocConversionError, sniffDocs as sniff } from "./docs.js";
import type { ConversionOptions } from "./index.js";

// The containers are read by exav's readers, which the tests run in this process.
vi.mock("./zip-engine.js", () => import("../test/sniff.js"));
beforeAll(start);
const sniffDocs = (b: Uint8Array) => sniff(b, officeKindsNow(b));

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

const DOC = compoundFile(["1Table", "WordDocument"]);

describe("what the bytes are", () => {
  it("reads compound files with a Word document stream as DOC", () => {
    expect(sniffDocs(DOC)).toBe("doc");
    expect(sniffDocs(compoundFile(["wordDOCUMENT"]))).toBe("doc");
    // A workbook is not one, nor is a file that only mentions the name.
    expect(sniffDocs(compoundFile(["Workbook"]))).toBeNull();
    expect(sniffDocs(bytes(CFB, utf16("WordDocument")))).toBeNull();
    expect(sniffDocs(compoundFile([["WordDocument", new Uint8Array(), 0]]))).toBeNull();
  });

  it("tells a compound file by its directory, not by a stream name written in its content", () => {
    // A stream whose bytes are a directory entry called WordDocument.
    const quoted = compoundFile([["Notes", bytes(entry("WordDocument"))]]);
    expect(sniffDocs(quoted)).toBeNull();
  });

  it("reads the Word document of a compound file that holds a workbook too", () => {
    expect(sniffDocs(compoundFile(["Workbook", "WordDocument"]))).toBe("doc");
  });

  it("takes a compound file the reader could not look into as its name says", () => {
    // `officeKinds` says `null` for one past the reader's memory.
    expect(sniff(compoundFile(["Workbook"]), null)).toBe("doc");
    expect(sniff(bytes("{\\rtf1"), null)).toBeNull();
  });

  it("reads RTF whatever the name, after white space or a byte order mark", () => {
    expect(sniffDocs(bytes("{\\rtf1\\ansi "))).toBe("rtf");
    expect(sniffDocs(bytes("\r\n  {\\rtf1"))).toBe("rtf");
    expect(sniffDocs(bytes([0xef, 0xbb, 0xbf], "{\\rtf1"))).toBe("rtf");
    expect(sniffDocs(bytes("{\\r hello}"))).toBeNull();
  });

  it("reads RTF whose header is only {\\rt", () => {
    expect(sniffDocs(bytes("{\\rt0\\ansi hello}"))).toBe("rtf");
    expect(sniffDocs(bytes("{\\rt"))).toBe("rtf");
    expect(sniffDocs(bytes("\r\n  {\\rt0\\ansi"))).toBe("rtf");
    expect(sniffDocs(bytes([0xef, 0xbb, 0xbf], "{\\rt0"))).toBe("rtf");
    expect(sniffDocs(bytes("{\\RT0\\ansi"))).toBeNull();
  });

  it("tells the packages apart by their members", () => {
    expect(sniffDocs(zip("mimetypeapplication/vnd.oasis.opendocument.text"))).toBe("odt");
    expect(sniffDocs(zip("mimetypeapplication/vnd.oasis.opendocument.text-template"))).toBe("odt");
    expect(sniffDocs(zip("mimetypeapplication/vnd.oasis.opendocument.presentation"))).toBeNull();
    expect(sniffDocs(zip("[Content_Types].xml ... word/document.xml"))).toBe("docx");
    expect(sniffDocs(zip("[Content_Types].xml ... ppt/presentation.xml"))).toBeNull();
    expect(sniffDocs(zip("Index/Document.iwa Index/DocumentStylesheet.iwa"))).toBe("pages");
    // Pages '09: an XML package, which `docs` recognises to say it is unsupported.
    expect(sniffDocs(zip("QuickLook/Thumbnail.jpg index.xml"))).toBe("pages");
    expect(sniffDocs(zip("Doc.pages/index.xml.gz"))).toBe("pages");
    expect(sniffDocs(zip("Index/Document.iwa Index/Tables/Tile.iwa"))).toBeNull();
    expect(sniffDocs(zip("Index/Document.iwa Index/Slide-1.iwa"))).toBeNull();
    // An OpenDocument package whose mimetype is not first: told by its members, unless they are a deck's or a workbook's.
    expect(sniffDocs(zip("content.xml styles.xml META-INF/manifest.xml"))).toBe("odt");
    expect(sniffDocs(zip("content.xml styles.xml ppt/slides/slide1.xml"))).toBeNull();
    expect(sniffDocs(zip("content.xml styles.xml xl/workbook.xml"))).toBeNull();
  });

  it("tells a package by the members of its directory, not by bytes inside a member", () => {
    // A ZIP that holds a document, stored: the document's own directory is in the last bytes.
    const inner = zip("[Content_Types].xml word/document.xml");
    expect(sniffDocs(storedZip([["backup.zip", inner]]))).toBeNull();
  });

  it("reads flat OpenDocument text and Word 2003 XML, and nothing else as text", () => {
    expect(sniffDocs(bytes('<?xml version="1.0"?>\n<office:document office:mimetype="application/vnd.oasis.opendocument.text">'))).toBe("fodt");
    expect(sniffDocs(bytes('<office:document office:mimetype="application/vnd.oasis.opendocument.spreadsheet">'))).toBeNull();
    expect(sniffDocs(bytes('<?xml version="1.0"?><w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">'))).toBe("wml2003");
    expect(sniffDocs(bytes("<html><body>"))).toBeNull();
    expect(sniffDocs(new Uint8Array())).toBeNull();
  });

  it("reads Word 2003 XML by its root element, not by a mention of its namespace", () => {
    const ns = 'xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml" xmlns:w10="urn:schemas-microsoft-com:office:word"';
    const word = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<?mso-application progid="Word.Document"?>\r\n<!-- saved by Word -->\r\n<w:wordDocument ${ns}><w:body>`;
    expect(sniffDocs(bytes(word))).toBe("wml2003");
    expect(sniffDocs(bytes([0xef, 0xbb, 0xbf], word))).toBe("wml2003");
    expect(sniffDocs(bytes(`<!DOCTYPE w:wordDocument [<!ENTITY a "<b>">]>\n<w:wordDocument ${ns}>`))).toBe("wml2003");
    // A schema and a stylesheet of the format, and a Word 2007 XML package, which shares the instruction.
    expect(sniffDocs(bytes(`<?xml version="1.0"?><xsd:schema ${ns}><xsd:element name="wordDocument"/>`))).toBeNull();
    expect(sniffDocs(bytes(`<xsl:stylesheet ${ns}><xsl:template match="w:wordDocument">`))).toBeNull();
    expect(sniffDocs(bytes('<?xml version="1.0"?><?mso-application progid="Word.Document"?><pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">'))).toBeNull();
    // Text that mentions it, and a root left unfinished.
    expect(sniffDocs(bytes("Notes on w:wordDocument and urn:schemas-microsoft-com:office:word"))).toBeNull();
    expect(sniffDocs(bytes("<?xml version="))).toBeNull();
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
const failure = async (kind: "doc" | "odt" | "rtf" | "pages", ctx: RenderContext<ConversionOptions>) => {
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
      // With an external converter set, as without: an external converter set
      // gets the file next, and failing too, leaves the first error the file's.
      for (const external of [true, false]) {
        convertExternal.mockClear();
        const { ctx, nested } = context(DOC, EXAV, external);
        const error = await failure("doc", ctx);
        expect(error, reason).toBeInstanceOf(DocConversionError);
        expect((error as DocConversionError).kind).toBe(kind);
        expect(nested).not.toHaveBeenCalled();
        expect(convertExternal).toHaveBeenCalledTimes(external ? 1 : 0);
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

describe("a Pages document", () => {
  const IWA = zip("Index/Document.iwa Index/DocumentStylesheet.iwa");
  const XML = zip("QuickLook/Thumbnail.jpg index.xml");

  it("is converted by exav-render's docs, as pages, and shown as DOCX", async () => {
    const { rendererFor } = await import("./convert.js");
    convertDocs.mockResolvedValue({ docx: new Uint8Array([1, 2, 3]).buffer, paragraphs: 1, warnings: "" });
    const { ctx, nested } = context(IWA, {}, false);
    await rendererFor("pages").mount(document.createElement("div"), ctx);
    expect(convertDocs).toHaveBeenCalledWith(IWA, "pages", expect.objectContaining({ signal: ctx.signal }));
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("docx");
  });

  it("fails with the converter's reason when it is a Pages '09 file and no external converter is set", async () => {
    convertDocs.mockRejectedValue(new Error("unsupported"));
    const { ctx, nested } = context(XML, {}, false);
    const error = await failure("pages", ctx);
    expect(error).toBeInstanceOf(DocConversionError);
    expect(error).toMatchObject({ kind: "unsupported", format: "pages", message: "the pages file could not be converted: unsupported" });
    expect(nested).not.toHaveBeenCalled();
  });

  it("goes on to the external converter when `docs` cannot read it", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "pdf", bytes: new Uint8Array([5]) });
    convertDocs.mockRejectedValue(new Error("unsupported"));
    const { ctx, nested } = context(XML, { converter: { pages: "exav" } }, true);
    await rendererFor("pages").mount(document.createElement("div"), ctx);
    expect(convertDocs).toHaveBeenCalledTimes(1);
    expect(convertExternal).toHaveBeenCalledWith(XML, expect.objectContaining({ hint: "pages" }));
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("pdf");
  });
});

describe("prefetching a text document", () => {
  it("names nothing for the kinds `docs` converts, whose module is the viewer's, but the external converter's files where it takes them", async () => {
    const { prefetchUrls } = await import("./convert.js");
    for (const kind of ["doc", "odt", "rtf", "pages"] as const) {
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
