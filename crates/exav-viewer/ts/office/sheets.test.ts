/**
 * Spreadsheets go to exav-render's `sheets` by their bytes; to the external
 * converter only what it does not recognise, or everything when the options
 * say so.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { RenderContext } from "../core/types.js";
import { compoundFile } from "../test/compound.js";
import { officeKindsNow, start } from "../test/sniff.js";
import { storedZip } from "../test/stored-zip.js";
import type { ConversionOptions } from "./index.js";
import { SheetConversionError, sniffSheet as sniff } from "./sheets.js";

// The containers are read by exav's readers, which the tests run in this process.
vi.mock("./zip-engine.js", () => import("../test/sniff.js"));
beforeAll(start);
const sniffSheet = (b: Uint8Array) => sniff(b, officeKindsNow(b));

const bytes = (...parts: (string | number[])[]) =>
  new Uint8Array(parts.flatMap((p) => (typeof p === "string" ? [...p].map((c) => c.charCodeAt(0)) : p)));

/** A stored ZIP whose members are the words of `rest`; a first word `mimetype...` is the member of that name holding the rest of the word. */
const zip = (rest: string): Uint8Array =>
  storedZip(
    rest
      .split(/\s+/)
      .filter((w) => w && w !== "...")
      .map((w, i) => (i === 0 && w.startsWith("mimetype") ? ["mimetype", bytes(w.slice(8))] : [w, new Uint8Array()]) as [string, Uint8Array]),
  );

describe("what the bytes are", () => {
  it("reads compound files with a workbook stream and BIFF2 to BIFF4 worksheets as XLS", () => {
    expect(sniffSheet(compoundFile(["Workbook"]))).toBe("xls");
    expect(sniffSheet(compoundFile(["SummaryInformation", "Book"]))).toBe("xls");
    expect(sniffSheet(bytes([0x09, 0x00, 0x04, 0x00, 0x02, 0x00, 0x10, 0x00]))).toBe("xls");
    expect(sniffSheet(bytes([0x09, 0x04, 0x06, 0x00, 0x00, 0x00, 0x10, 0x00]))).toBe("xls");
  });

  it("does not read the other compound files as XLS", () => {
    // A Word document, a presentation, and a compound file that is neither.
    expect(sniffSheet(compoundFile(["WordDocument"]))).toBeNull();
    expect(sniffSheet(compoundFile(["PowerPoint Document"]))).toBeNull();
    expect(sniffSheet(compoundFile(["Contents"]))).toBeNull();
    // The workbook of a file that holds a Word document too.
    expect(sniffSheet(compoundFile(["WordDocument", "Workbook"]))).toBe("xls");
    // One the reader could not look into (`officeKinds` says `null`) is taken as its name says.
    expect(sniff(compoundFile(["WordDocument"]), null)).toBe("xls");
  });

  it("tells the packages apart by their members", () => {
    expect(sniffSheet(zip("mimetypeapplication/vnd.oasis.opendocument.spreadsheet"))).toBe("ods");
    expect(sniffSheet(zip("mimetypeapplication/vnd.oasis.opendocument.text"))).toBeNull();
    // A deflated mimetype: the members tell.
    const deflated = zip("mimetype\u0005Á\u0081 ... content.xml");
    deflated[8] = 8;
    expect(sniffSheet(deflated)).toBe("ods");
    expect(sniffSheet(zip("[Content_Types].xml ... xl/workbook.xml"))).toBe("xlsx");
    expect(sniffSheet(zip("Index/Document.iwa Index/Tables/Tile.iwa"))).toBe("numbers");
    expect(sniffSheet(zip("Doc.numbers/Index.zip"))).toBe("numbers");
    // Numbers '08 and '09.
    expect(sniffSheet(zip("QuickLook/Thumbnail.jpg index.xml"))).toBe("numbers");
    expect(sniffSheet(zip("Doc.numbers/index.xml.gz"))).toBe("numbers");
    expect(sniffSheet(zip("word/document.xml"))).toBeNull();
  });

  it("tells a package by the members of its directory, not by bytes inside a member", () => {
    // A ZIP that holds a workbook, stored: the workbook's own directory is in the last bytes.
    const inner = zip("[Content_Types].xml xl/workbook.xml");
    expect(sniffSheet(storedZip([["backup.zip", inner]]))).toBeNull();
  });

  it("reads flat OpenDocument and the text formats Excel opens, nothing else as text", () => {
    const fods = '<?xml version="1.0"?>\n<office:document office:mimetype="application/vnd.oasis.opendocument.spreadsheet">';
    expect(sniffSheet(bytes(fods))).toBe("fods");
    expect(sniffSheet(bytes("\n<HTML><table>"))).toBe("html");
    expect(sniffSheet(bytes("<table border=1><tr>"))).toBe("html");
    const ssml = '<?xml version="1.0"?>\n<?mso-application progid="Excel.Sheet"?>\n<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:html="http://www.w3.org/TR/REC-html40">';
    expect(sniffSheet(bytes(ssml))).toBe("xml");
    // UTF-16, as some exports are.
    const utf16 = new Uint8Array([0xff, 0xfe, ...[...ssml].flatMap((c) => [c.charCodeAt(0), 0])]);
    expect(sniffSheet(utf16)).toBe("xml");
    expect(sniffSheet(bytes("ID;PWXL;N;E\r\nC;Y1;X1;K1\r\nE\r\n"))).toBe("slk");
    expect(sniffSheet(bytes("ID,Name\n1,Ann"))).toBeNull();
    expect(sniffSheet(bytes("a,b,c\n1,2,3"))).toBeNull();
    expect(sniffSheet(bytes("<?xml version=\"1.0\"?><svg/>"))).toBeNull();
    expect(sniffSheet(new Uint8Array())).toBeNull();
  });
});

const convertSheet = vi.fn();
vi.mock("./sheets.js", async (original) => ({ ...(await original<typeof import("./sheets.js")>()), convertSheet: (...a: unknown[]) => convertSheet(...a) }));

// The external converter, a function the tests answer for.
const convertExternal = vi.fn();
vi.mock("./external.js", async (original) => ({
  ...(await original<typeof import("./external.js")>()),
  externalUrl: async (spec: string) => `https://converter.test/${spec}`,
  loadExternal: async () => ({ convert: (...a: unknown[]) => convertExternal(...a) }),
}));

afterEach(() => {
  convertSheet.mockReset();
  convertExternal.mockReset();
});

/** A context over `data`, with an external converter set or not. */
function context(data: Uint8Array, options: ConversionOptions, external: boolean) {
  const nested = vi.fn(() => ({ resize() {}, destroy() {} }));
  const statuses: unknown[] = [];
  const ctx = {
    file: { id: "f", name: "a.xls" },
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

const XLS = compoundFile(["Workbook"]);

describe("a spreadsheet opened", () => {
  it("is converted by exav-render's sheets and shown as XLSX", async () => {
    const { rendererFor } = await import("./convert.js");
    convertSheet.mockResolvedValue({ xlsx: new Uint8Array([1, 2, 3]).buffer, warnings: "" });
    const { ctx, nested, statuses } = context(XLS, {}, false);
    await rendererFor("xls").mount(document.createElement("div"), ctx);
    expect(convertSheet).toHaveBeenCalledWith(XLS, "xls", expect.objectContaining({ signal: ctx.signal }));
    const [, file] = nested.mock.calls[0] as unknown as [unknown, { format: string; source: { bytes: Uint8Array } }];
    expect(file.format).toBe("xlsx");
    expect([...file.source.bytes]).toEqual([1, 2, 3]);
    expect(statuses).toContainEqual({ phase: "converting", step: "convert" });
  });

  /** The error `mount` fails with. */
  const failure = async (kind: "xls" | "ods", ctx: RenderContext<ConversionOptions>) => {
    const { rendererFor } = await import("./convert.js");
    return Promise.resolve(rendererFor(kind).mount(document.createElement("div"), ctx)).then(
      () => null,
      (e: unknown) => e,
    );
  };

  it("fails with its converter's error and its kind, an external converter set or not", async () => {
    for (const [reason, kind] of [
      ["encrypted", "encrypted"],
      ["too-large", "too-large"],
      ["malformed", "malformed"],
      ["unsupported", "unsupported"],
      ["no answer within 120000 ms", "timeout"],
      ["unreachable", "crashed"],
    ]) {
      for (const external of [false, true]) {
        convertSheet.mockRejectedValue(new Error(reason));
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
        const { ctx, nested } = context(XLS, {}, external);
        const error = await failure("xls", ctx);
        expect(error, `${reason}, external ${external}`).toBeInstanceOf(SheetConversionError);
        expect((error as SheetConversionError).kind).toBe(kind);
        expect((error as SheetConversionError).format).toBe("xls");
        expect(nested).not.toHaveBeenCalled();
        // The external converter never got the file.
        expect(convertExternal).not.toHaveBeenCalled();
        warn.mockRestore();
      }
    }
  });

  it("converts the text formats Excel opens from a .xls", async () => {
    const { rendererFor } = await import("./convert.js");
    for (const [text, format] of [
      ["<html><table><tr><td>1</td></tr></table></html>", "html"],
      ["ID;PWXL\nC;Y1;X1;K1\nE\n", "slk"],
    ]) {
      convertSheet.mockResolvedValue({ xlsx: new Uint8Array([1]).buffer, warnings: "" });
      const data = bytes(text!);
      const { ctx, nested } = context(data, {}, true);
      await rendererFor("xls").mount(document.createElement("div"), ctx);
      expect(convertSheet).toHaveBeenLastCalledWith(data, format, expect.anything());
      expect(nested).toHaveBeenCalled();
    }
  });

  const DIF = bytes('TABLE\r\n0,1\r\n""\r\nVECTORS\r\n0,1\r\n""\r\n');

  it("goes to the external converter only with what it does not recognise", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "xlsx", bytes: new Uint8Array([9]) });
    const { ctx, nested } = context(DIF, {}, true);
    await rendererFor("xls").mount(document.createElement("div"), ctx);
    expect(convertSheet).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalledWith(DIF, expect.objectContaining({ hint: "xls" }));
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("xlsx");
  });

  it("ends in the needs-converter error with what it does not recognise and no external converter", async () => {
    const { rendererFor } = await import("./convert.js");
    const { ctx, nested, statuses } = context(DIF, {}, false);
    await rendererFor("xls").mount(document.createElement("div"), ctx);
    const error = statuses.at(-1) as { phase: string; error: { code: string; cause: { kind: string; format: string } } };
    expect(error.phase).toBe("error");
    expect(error.error.code).toBe("needs_converter");
    expect(error.error.cause).toMatchObject({ kind: "needs-converter", format: "xls" });
    expect(convertSheet).not.toHaveBeenCalled();
    expect(nested).not.toHaveBeenCalled();
  });

  it("sends a Word document named .xls to the external converter, not to sheets", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "xlsx", bytes: new Uint8Array([9]) });
    const word = compoundFile(["WordDocument"]);
    const { ctx } = context(word, {}, true);
    await rendererFor("xls").mount(document.createElement("div"), ctx);
    expect(convertSheet).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalledWith(word, expect.objectContaining({ hint: "xls" }));
  });

  it("is shown as it is when it is an XLSX under another name", async () => {
    const { rendererFor } = await import("./convert.js");
    const data = zip("[Content_Types].xml xl/workbook.xml");
    const { ctx, nested } = context(data, {}, false);
    await rendererFor("ods").mount(document.createElement("div"), ctx);
    expect(convertSheet).not.toHaveBeenCalled();
    expect((nested.mock.calls[0] as unknown as [unknown, { format: string }])[1].format).toBe("xlsx");
  });

  it("goes to the external converter alone when the options say so", async () => {
    const { rendererFor } = await import("./convert.js");
    convertExternal.mockResolvedValue({ format: "xlsx", bytes: new Uint8Array([9]) });
    const { ctx } = context(XLS, { converter: "external" }, true);
    await rendererFor("xls").mount(document.createElement("div"), ctx);
    expect(convertSheet).not.toHaveBeenCalled();
    expect(convertExternal).toHaveBeenCalledWith(XLS, expect.objectContaining({ hint: "xls" }));
  });

  it("ends in the needs-converter error when the options ask for an external converter and there is none", async () => {
    const { rendererFor } = await import("./convert.js");
    const { ctx, statuses } = context(XLS, { converter: "external" }, false);
    await rendererFor("xls").mount(document.createElement("div"), ctx);
    expect((statuses.at(-1) as { error: { code: string } }).error.code).toBe("needs_converter");
    expect(convertSheet).not.toHaveBeenCalled();
  });
});
