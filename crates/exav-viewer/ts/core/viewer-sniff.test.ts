// A file is shown as its first bytes say, by exav's own detection (the module
// of ts/test/sniff.ts, in this process: the page has it in a worker), where
// they say something: a PDF named .png is a PDF.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { storedZip } from "../test/stored-zip.js";
import { MATCHERS } from "./formats.js";
import { createSniffer } from "./sniff-engine.js";
import type { ByteRanges, FormatPlugin, RenderContext, RendererHandle, ViewerConfig, ViewerFile } from "./types.js";
import { createViewer } from "./viewer.js";

// The one detection every viewer here is given, which a test can watch and replace.
vi.mock("./sniff-engine.js", async () => {
  const real = await import("../test/sniff.js");
  const sniffer = vi.fn(real.sniffInWorker);
  return { createSniffer: vi.fn(() => sniffer), createInspector: vi.fn(() => real.inspectInWorker), createOfficer: vi.fn(() => real.officeInWorker) };
});

const sniffInWorker = createSniffer();

/** Long enough for the reads and the detection of a mount to be over. */
const tick = () => new Promise((r) => setTimeout(r, 25));
const bytes = (...parts: (string | number[])[]): Uint8Array => new Uint8Array(parts.flatMap((p) => (typeof p === "string" ? [...p].map((c) => c.charCodeAt(0)) : p)));

const pdf = bytes("%PDF-1.7\n%", [0xe2, 0xe3, 0xcf, 0xd3, 10]);
const png = bytes([0x89], "PNG", [0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13], "IHDR", [0, 0, 0, 1]);
const zip = bytes([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0]);

/** Where the central directory of a ZIP begins: its first central header. */
const centralDirectory = (file: Uint8Array): number => file.findIndex((_, i) => file[i] === 0x50 && file[i + 1] === 0x4b && file[i + 2] === 1 && file[i + 3] === 2);

/** The built-in matcher of a format, its plugin recording what it was given. */
function plugin(id: "pdf" | "image" | "archive" | "text" | "docx") {
  const mounted: string[] = [];
  const p: FormatPlugin = {
    id,
    match: MATCHERS[id],
    capabilities: [],
    options: {},
    load: async () => ({
      mount(host: HTMLElement, c: RenderContext): RendererHandle {
        mounted.push(c.file.name);
        c.status({ phase: "ready" });
        return { controllers: {}, destroy() {} };
      },
    }),
  };
  return { plugin: p, mounted };
}

const make = () => {
  const pdfs = plugin("pdf");
  const images = plugin("image");
  const archives = plugin("archive");
  const viewer = createViewer({ plugins: [pdfs.plugin, images.plugin, archives.plugin] });
  return { viewer, pdfs, images, archives };
};
const mount = (viewer: ReturnType<typeof createViewer>, file: Parameters<ReturnType<typeof createViewer>["mount"]>[1]) => viewer.mount(document.createElement("div"), file);

// The module starts once for the whole file.
beforeAll(async () => {
  await sniffInWorker(new Uint8Array(1), 1);
});
beforeEach(() => {
  URL.createObjectURL = vi.fn(() => "blob:test/0");
  URL.revokeObjectURL = vi.fn();
  vi.mocked(sniffInWorker).mockClear();
});
afterEach(() => vi.restoreAllMocks());

describe("a file whose bytes say one type and whose name says another", () => {
  it("is shown as a PDF when it is named .png, whatever its source", async () => {
    for (const source of [
      { bytes: pdf },
      { blob: new Blob([pdf as BlobPart]) },
      { ranges: { size: pdf.length, read: async (at: number, n: number) => pdf.slice(at, at + n) } as ByteRanges },
      { resolve: async () => pdf },
      { resolve: async () => new Blob([pdf as BlobPart]) },
    ]) {
      const { viewer, pdfs, images } = make();
      const s = mount(viewer, { id: "a", name: "plan.png", type: "image/png", source });
      // Until the bytes are read, what the name says.
      expect(s.format).toBe("image");
      await tick();
      expect(s.format, Object.keys(source)[0]).toBe("pdf");
      expect(pdfs.mounted).toEqual(["plan.png"]);
      expect(images.mounted).toEqual([]);
      expect(s.status.get()).toEqual({ phase: "ready" });
    }
  });

  it("is shown as an image when it is named .pdf, and as an archive when it is named .txt", async () => {
    const { viewer, pdfs, images, archives } = make();
    mount(viewer, { id: "a", name: "scan.pdf", type: "application/pdf", source: { bytes: png } });
    mount(viewer, { id: "b", name: "notes.txt", type: "text/plain", source: { bytes: zip } });
    await tick();
    expect(images.mounted).toEqual(["scan.pdf"]);
    expect(archives.mounted).toEqual(["notes.txt"]);
    expect(pdfs.mounted).toEqual([]);
  });

  it("is shown as a Word document when it is a ZIP of one, whatever it is named and however it is read", async () => {
    const text = (s: string) => new TextEncoder().encode(s);
    const docx = storedZip([
      ["docProps/app.xml", text("<Properties/>")],
      ["[Content_Types].xml", text("<Types/>")],
      ["word/document.xml", text("<w:document/>")],
    ]);
    const plain = storedZip([["readme.txt", text("hello")]]);
    const ranges = (file: Uint8Array) => ({ ranges: { size: file.length, read: async (at: number, n: number) => file.slice(at, at + n) } as ByteRanges });
    for (const source of [{ bytes: docx }, ranges(docx)]) {
      const words = plugin("docx");
      const archives = plugin("archive");
      const viewer = createViewer({ plugins: [words.plugin, archives.plugin] });
      mount(viewer, { id: "a", name: "x.zip", source });
      mount(viewer, { id: "b", name: "attachment", source });
      await tick();
      expect(words.mounted, Object.keys(source)[0]).toEqual(["x.zip", "attachment"]);
      expect(archives.mounted).toEqual([]);
    }
    // A ZIP of anything else is an archive.
    const words = plugin("docx");
    const archives = plugin("archive");
    mount(createViewer({ plugins: [words.plugin, archives.plugin] }), { id: "c", name: "x.zip", source: { bytes: plain } });
    await tick();
    expect(archives.mounted).toEqual(["x.zip"]);
    expect(words.mounted).toEqual([]);
  });

  it("is shown by its name where its bytes say nothing", async () => {
    const { viewer, pdfs } = make();
    mount(viewer, { id: "a", name: "plan.pdf", type: "application/pdf", source: { bytes: bytes("hello, this is not a PDF") } });
    mount(viewer, { id: "b", name: "empty.pdf", source: { bytes: new Uint8Array() } });
    await tick();
    expect(pdfs.mounted).toEqual(["plan.pdf", "empty.pdf"]);
  });

  it("is shown as no format when its bytes are one no plugin opens, and its name another", async () => {
    const { viewer, pdfs, images } = make();
    const ole = bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], new Array(60).fill(0));
    const s = mount(viewer, { id: "a", name: "plan.pdf", type: "application/pdf", source: { bytes: ole } });
    await tick();
    expect(s.format).toBeNull();
    expect(s.status.get()).toEqual({ phase: "error", error: { code: "file" } });
    expect(pdfs.mounted).toEqual([]);
    expect(images.mounted).toEqual([]);
  });

  it("reads only the first bytes of a file read by ranges, once", async () => {
    const { viewer, pdfs } = make();
    const size = 5_000_000;
    const read = vi.fn(async (at: number, n: number) => {
      const out = new Uint8Array(Math.min(n, size - at));
      if (at === 0) out.set(pdf.subarray(0, out.length));
      return out;
    });
    mount(viewer, { id: "a", name: "plan.png", type: "image/png", source: { ranges: { size, read } } });
    await tick();
    expect(pdfs.mounted).toEqual(["plan.png"]);
    expect(read).toHaveBeenCalledOnce();
    expect(read.mock.calls[0]!.slice(0, 2)).toEqual([0, 65536]);
    // The detection is told how long the file is.
    expect(vi.mocked(sniffInWorker).mock.calls[0]![1]).toBe(size);
  });

  it("is not read at all when it is given with a format", async () => {
    const { viewer, pdfs, images } = make();
    const fetched = vi.spyOn(globalThis, "fetch");
    const chosen = mount(viewer, { id: "b", name: "plan.png", type: "image/png", format: "image", source: { bytes: pdf } });
    const link = mount(viewer, { id: "a", name: "plan.png", type: "image/png", format: "image", source: { url: "https://example.test/plan.png" } });
    await tick();
    expect(chosen.format).toBe("image");
    expect(link.format).toBe("image");
    expect(images.mounted).toEqual(["plan.png", "plan.png"]);
    expect(pdfs.mounted).toEqual([]);
    expect(sniffInWorker).not.toHaveBeenCalled();
    expect(fetched).not.toHaveBeenCalled();
  });

  describe("given by an address", () => {
    /** A server of `file` that answers a range request as asked, or (`ranges` false) ignores it. */
    const serve = (file: Uint8Array, ranges: boolean) =>
      vi.fn(async (_url: string, init?: RequestInit) => {
        const m = /^bytes=0-(\d+)$/.exec(new Headers(init?.headers).get("range") ?? "");
        if (!m || !ranges) return new Response(file as BodyInit, { headers: { "content-length": String(file.length) } });
        const end = Math.min(Number(m[1]), file.length - 1);
        return new Response(file.slice(0, end + 1) as BodyInit, { status: 206, headers: { "content-range": `bytes 0-${end}/${file.length}` } });
      });
    afterEach(() => vi.unstubAllGlobals());

    it("is told by a range request for its first bytes, from a server that answers it and from one that ignores it", async () => {
      for (const ranges of [true, false]) {
        // A PDF of 200 KB: only the first 64 KiB are read for the detection.
        const file = new Uint8Array(200_000);
        file.set(pdf);
        const fetcher = serve(file, ranges);
        vi.stubGlobal("fetch", fetcher);
        const { viewer, pdfs, images } = make();
        const s = mount(viewer, { id: "a", name: "plan.png", type: "image/png", source: { url: "https://example.test/plan.png" } });
        expect(s.format, String(ranges)).toBe("image");
        await tick();
        expect(s.format, String(ranges)).toBe("pdf");
        expect(pdfs.mounted).toEqual(["plan.png"]);
        expect(images.mounted).toEqual([]);
        expect(new Headers(fetcher.mock.calls[0]![1]!.headers).get("range")).toBe("bytes=0-65535");
        // The detection is told the file's size, and only its head.
        const [head, size] = vi.mocked(sniffInWorker).mock.calls.at(-1)!;
        expect([head.length, size]).toEqual([65536, 200_000]);
      }
    });

    it("is told by its name, with no request for it, when sniffBytes is 0", async () => {
      const fetcher = serve(pdf, true);
      vi.stubGlobal("fetch", fetcher);
      const images = plugin("image");
      const viewer = createViewer({ plugins: [images.plugin], sniffBytes: 0 });
      mount(viewer, { id: "a", name: "plan.png", type: "image/png", source: { bytes: pdf } });
      mount(viewer, { id: "b", name: "plan.png", type: "image/png", source: { url: "https://example.test/plan.png" } });
      await tick();
      expect(images.mounted).toEqual(["plan.png", "plan.png"]);
      expect(sniffInWorker).not.toHaveBeenCalled();
      expect(fetcher).not.toHaveBeenCalled();
    });

    it("asks for sniffBytes bytes", async () => {
      const fetcher = serve(pdf, true);
      vi.stubGlobal("fetch", fetcher);
      const images = plugin("image");
      mount(createViewer({ plugins: [images.plugin], sniffBytes: 8 }), { id: "a", name: "plan.png", source: { url: "https://example.test/plan.png" } });
      await tick();
      expect(new Headers(fetcher.mock.calls[0]![1]!.headers).get("range")).toBe("bytes=0-7");
    });

    it("is told by its name, with a warning, when the server refuses the range request", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      vi.stubGlobal("fetch", vi.fn(async () => new Response("no", { status: 403 })));
      const { viewer, images } = make();
      mount(viewer, { id: "a", name: "plan.png", type: "image/png", source: { url: "https://example.test/plan.png" } });
      await tick();
      expect(images.mounted).toEqual(["plan.png"]);
      expect(warn).toHaveBeenCalledOnce();
    });
  });

  it("is shown by its name, with a warning, where the detection fails", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(sniffInWorker).mockRejectedValueOnce(new Error("the module trapped"));
    const { viewer, images } = make();
    mount(viewer, { id: "a", name: "plan.png", type: "image/png", source: { bytes: pdf } });
    await tick();
    expect(images.mounted).toEqual(["plan.png"]);
    expect(warn).toHaveBeenCalledOnce();
  });

  it("is not opened, and not refused, when the session ends before the bytes are read", async () => {
    for (const type of ["application/pdf", "application/x-ole-storage"]) {
      let release!: (type: string) => void;
      vi.mocked(sniffInWorker).mockImplementationOnce(() => new Promise<string>((r) => (release = r)));
      const { viewer, pdfs } = make();
      const s = mount(viewer, { id: "a", name: "plan.png", type: "image/png", source: { bytes: pdf } });
      await tick();
      s.destroy();
      release(type);
      await tick();
      expect(pdfs.mounted, type).toEqual([]);
      expect(s.status.get(), type).toEqual({ phase: "loading" });
    }
  });

  it("gives a nested session the format it was given", async () => {
    const pdfs = plugin("pdf");
    const images = plugin("image");
    const outer: FormatPlugin = {
      id: "text",
      match: { extensions: [".bundle"] },
      capabilities: [],
      options: {},
      load: async () => ({
        mount(host: HTMLElement, c: RenderContext): RendererHandle {
          const inner = c.mountNested(host, { id: "in", name: "inner.png", format: "image", source: { bytes: pdf } });
          return { controllers: {}, destroy: () => inner.destroy() };
        },
      }),
    };
    const v = createViewer({ plugins: [outer, pdfs.plugin, images.plugin] });
    mount(v, { id: "o", name: "a.bundle", source: { bytes: bytes("x") } });
    await tick();
    expect(images.mounted).toEqual(["inner.png"]);
    expect(pdfs.mounted).toEqual([]);
  });
});

describe("a file that fails to open", () => {
  /** A plugin of the format whose renderer cannot open anything. */
  const failing = (id: "docx" | "pdf"): FormatPlugin => ({
    id,
    match: MATCHERS[id],
    capabilities: [],
    options: {},
    load: async () => ({
      mount(): RendererHandle {
        throw new Error("could not open");
      },
    }),
  });
  const docx = (parts: string[]) => storedZip(parts.map((p) => [p, bytes("<x/>")] as [string, Uint8Array]));
  const sound = ["[Content_Types].xml", "word/document.xml"];
  const code = async (name: string, source: ViewerFile["source"], extra: Partial<ViewerFile> = {}) => {
    const s = mount(createViewer({ plugins: [failing("docx"), failing("pdf")] }), { id: name, name, source, ...extra });
    await tick();
    const status = s.status.get();
    return status.phase === "error" ? status.error.code : status.phase;
  };
  beforeEach(() => void vi.spyOn(console, "warn").mockImplementation(() => {}));
  afterEach(() => vi.unstubAllGlobals());

  it("is damaged when its package lacks a part or its directory, and the wrong type when its bytes are no package", async () => {
    expect(await code("a.docx", { bytes: docx(["[Content_Types].xml", "word/styles.xml"]) })).toBe("damaged");
    expect(await code("b.docx", { bytes: docx(sound).subarray(0, 100) })).toBe("damaged");
    expect(await code("c.docx", { bytes: bytes("hello, not a package") })).toBe("wrong_type");
    expect(await code("d.pdf", { bytes: bytes("hello, not a PDF") })).toBe("wrong_type");
  });

  it("keeps the format's own error where nothing is wrong that the readers check, or where they were not asked", async () => {
    // A sound package, a PDF by its signature.
    expect(await code("e.docx", { bytes: docx(sound) })).toBe("office");
    expect(await code("f.pdf", { bytes: pdf })).toBe("pdf");
    // An address of a format the host chose is not asked for anything.
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    expect(await code("g.docx", { url: "https://example.test/g.docx" }, { format: "docx" })).toBe("office");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("is judged by the first and last bytes of an address, asked for by range requests", async () => {
    const file = docx(["[Content_Types].xml", "word/styles.xml", "padding.bin"]);
    const fetcher = vi.fn(async (_url: string, init?: RequestInit) => {
      const range = new Headers(init?.headers).get("range") ?? "";
      const head = /^bytes=0-(\d+)$/.exec(range);
      const tail = /^bytes=-(\d+)$/.exec(range);
      if (head) return new Response(file.slice(0, Number(head[1]) + 1) as BodyInit, { status: 206, headers: { "content-range": `bytes 0-${Math.min(Number(head[1]), file.length - 1)}/${file.length}` } });
      if (tail) {
        const from = Math.max(0, file.length - Number(tail[1]));
        return new Response(file.slice(from) as BodyInit, { status: 206, headers: { "content-range": `bytes ${from}-${file.length - 1}/${file.length}` } });
      }
      return new Response(file as BodyInit);
    });
    vi.stubGlobal("fetch", fetcher);
    expect(await code("h.docx", { url: "https://example.test/h.docx" })).toBe("damaged");
  });

  it("reads a directory that starts before the last megabyte, as the Office page does", async () => {
    // 20,000 members make a directory of more than 1 MiB, with no main part among them.
    const members = ["[Content_Types].xml", ...Array.from({ length: 20_000 }, (_, i) => `padding/${i}.bin`)];
    const file = docx(members);
    expect(file.length - centralDirectory(file)).toBeGreaterThan(1 << 20);
    const s = mount(createViewer({ plugins: [failing("docx")], maxMembers: 0 }), { id: "big", name: "big.docx", source: { bytes: file } });
    await tick();
    const status = s.status.get();
    expect(status.phase === "error" && status.error.code).toBe("damaged");
  });
});

describe("a ZIP-based file whose directory goes past a limit", () => {
  const ok = plugin("docx");
  const archives = plugin("archive");
  const members = (n: number, size = 4) => Array.from({ length: n }, (_, i) => [i === 0 ? "[Content_Types].xml" : i === 1 ? "word/document.xml" : `m/${i}.xml`, new Uint8Array(size)] as [string, Uint8Array]);
  /** `file` with the uncompressed size its first member declares in the directory set to `size`. */
  const declaring = (file: Uint8Array, size: number): Uint8Array => {
    const out = file.slice();
    new DataView(out.buffer).setUint32(centralDirectory(out) + 24, size, true);
    return out;
  };
  /** The error code (or phase) of `file` opened by a viewer with `limits`. */
  const open = async (file: Uint8Array, name: string, limits: Partial<ViewerConfig>) => {
    const s = mount(createViewer({ plugins: [ok.plugin, archives.plugin], ...limits }), { id: name, name, source: { bytes: file } });
    await tick();
    const status = s.status.get();
    return status.phase === "error" ? status.error.code : status.phase;
  };
  beforeEach(() => {
    ok.mounted.length = 0;
    archives.mounted.length = 0;
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("is refused for more members than maxMembers, and opened when it is 0", async () => {
    const file = storedZip(members(6));
    expect(await open(file, "a.docx", { maxMembers: 5 })).toBe("too_many_entries");
    expect(ok.mounted).toEqual([]);
    expect(await open(file, "b.docx", { maxMembers: 6 })).toBe("ready");
    expect(await open(file, "c.docx", { maxMembers: 0 })).toBe("ready");
    expect(ok.mounted).toEqual(["b.docx", "c.docx"]);
  });

  it("is refused for more bytes than maxExtractedBytes, and opened when it is 0", async () => {
    const file = storedZip(members(3, 100));
    expect(await open(file, "a.docx", { maxExtractedBytes: 299 })).toBe("too_large");
    expect(ok.mounted).toEqual([]);
    expect(await open(file, "b.docx", { maxExtractedBytes: 300 })).toBe("ready");
    expect(await open(file, "c.docx", { maxExtractedBytes: 0 })).toBe("ready");
  });

  it("is refused for a member past maxCompressionRatio, and opened when it is 0", async () => {
    // A member of 4 bytes that says it inflates to 300 MiB, past the 256 MiB
    // below which a member is not asked its ratio.
    const file = declaring(storedZip(members(3)), 300 << 20);
    expect(await open(file, "a.docx", { maxCompressionRatio: 200 })).toBe("too_compressed");
    expect(ok.mounted).toEqual([]);
    expect(await open(file, "b.docx", { maxCompressionRatio: 0 })).toBe("ready");
  });

  it("is judged for an archive too, by the same limits", async () => {
    const file = storedZip(members(6));
    expect(await open(file, "a.zip", { maxMembers: 5 })).toBe("too_many_entries");
    expect(archives.mounted).toEqual([]);
    expect(await open(file, "b.zip", { maxMembers: 0 })).toBe("ready");
  });

  it("is refused with exav-unpack's reason as the cause", async () => {
    const s = mount(createViewer({ plugins: [ok.plugin], maxMembers: 2 }), { id: "r", name: "r.docx", source: { bytes: storedZip(members(3)) } });
    await tick();
    const status = s.status.get();
    expect(status.phase === "error" && String((status.error.cause as Error).message)).toBe("file count > 2");
  });

  it("is a limit that must be a whole number, 0 for none", () => {
    expect(() => createViewer({ plugins: [], maxMembers: -1 })).toThrow(RangeError);
    expect(() => createViewer({ plugins: [], maxCompressionRatio: 1.5 })).toThrow(RangeError);
  });
});
