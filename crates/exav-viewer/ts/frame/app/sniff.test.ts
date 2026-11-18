// What the frame says a file is, from the bytes it reads itself at an address:
// a ZIP is told by its members as the viewer tells it.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUILTIN_ORDER } from "../../core/formats.js";
import { officeInWorker, sniffInWorker } from "../../test/sniff.js";
import { storedZip } from "../../test/stored-zip.js";
import type { SniffMessage } from "../protocol.js";
import { sniffed } from "./sniff.js";

const text = (s: string) => new TextEncoder().encode(s);
const docx = storedZip([
  ["docProps/app.xml", text("<Properties/>")],
  ["[Content_Types].xml", text("<Types/>")],
  ["word/document.xml", text("<w:document/>")],
]);

/** A server of `file` that answers range requests. */
function serve(file: Uint8Array) {
  vi.stubGlobal("fetch", async (_url: string, init?: RequestInit) => {
    const range = new Headers(init?.headers).get("range") ?? "";
    const [, from = "", to = ""] = /^bytes=(\d*)-(\d*)$/.exec(range) ?? [];
    const start = from === "" ? Math.max(0, file.length - Number(to)) : Number(from);
    const end = from === "" ? file.length - 1 : Math.min(file.length - 1, Number(to));
    return new Response(file.slice(start, end + 1), { status: 206, headers: { "content-range": `bytes ${start}-${end}/${file.length}` } });
  });
}

const ask = (name: string, source: SniffMessage["source"]): SniffMessage => ({ type: "sniff", call: 1, formats: BUILTIN_ORDER, file: { name, type: "", path: name }, source, sniff: {} });

beforeEach(() => serve(docx));
afterEach(() => vi.unstubAllGlobals());

describe("a ZIP the frame reads at an address", () => {
  const url = { kind: "url", url: "https://files.test/attachment" } as const;

  it("is the format its members say, when it is given the means to read them", async () => {
    expect(await sniffed(ask("x.zip", url), sniffInWorker, null, officeInWorker)).toBe("docx");
    expect(await sniffed(ask("", url), sniffInWorker, null, officeInWorker)).toBe("docx");
    expect(await sniffed(ask("x.zip", url), sniffInWorker, null)).toBe("archive");
  });

  it("is an archive when the frame was not published with the format", async () => {
    expect(await sniffed(ask("x.zip", url), sniffInWorker, new Set(["archive"]), officeInWorker)).toBe("archive");
  });

  it("is told by the first bytes the host gives only when they are all of the file", async () => {
    const head = docx.slice().buffer as ArrayBuffer;
    expect(await sniffed(ask("x.zip", { kind: "head", head, size: docx.length }), sniffInWorker, null, officeInWorker)).toBe("docx");
    const part = docx.slice(0, 40).buffer as ArrayBuffer;
    expect(await sniffed(ask("x.zip", { kind: "head", head: part, size: docx.length }), sniffInWorker, null, officeInWorker)).toBe("archive");
  });
});
