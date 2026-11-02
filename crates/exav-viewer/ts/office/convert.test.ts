/**
 * Which converter takes a file, and the external converter's contract: a
 * module loaded from a URL, its progress shown as the viewer's steps, its
 * errors, its abort, the memory option, and what it fetches for
 * `Viewer.prefetch`.
 */
import path from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { RenderContext } from "../core/types.js";
import { nativeFirst, prefetchUrls, rendererFor, statusOf } from "./convert.js";
import { ExternalConversionError, externalUrl, loadExternal, NeedsConverterError } from "./external.js";
import type { ConversionOptions, ConvertedFormat } from "./index.js";

describe("the converter's progress", () => {
  it("is the viewer's steps, with the share of each where it is counted", () => {
    expect(statusOf({ stage: "download", loaded: 5, total: 20 })).toEqual({ phase: "loading", step: "engine", progress: 0.25 });
    expect(statusOf({ stage: "download", loaded: 5, total: 0 })).toEqual({ phase: "loading", step: "engine" });
    expect(statusOf({ stage: "start" })).toEqual({ phase: "converting", step: "start" });
    expect(statusOf({ stage: "load", done: 1, total: 4 })).toEqual({ phase: "converting", step: "read", progress: 0.25 });
    expect(statusOf({ stage: "export", done: 3, total: 4 })).toEqual({ phase: "converting", step: "convert", progress: 0.75 });
  });
});

describe("which converter takes a file", () => {
  const kinds = ["rtf", "doc", "odt", "ppt", "odp", "keynote", "xls", "ods", "numbers", "odg", "visio", "coreldraw", "publisher", "pagemaker", "freehand", "quarkxpress", "zonerdraw", "wpg"] as const;

  it("is the package's own for spreadsheets, presentations and OpenDocument drawings, by default", () => {
    for (const kind of ["xls", "ods", "numbers"] as const) expect(nativeFirst(kind, {})).toBe("sheets");
    for (const kind of ["ppt", "odp", "keynote", "odg", "visio"] as const) expect(nativeFirst(kind, {})).toBe("slides");
    // With an external converter too: it gets only what they do not read.
    for (const kind of ["xls", "ppt", "odg"] as const) expect(nativeFirst(kind, { externalConverter: "x" })).not.toBeNull();
  });

  it("is the package's `docs` for text documents without an external converter, or when asked, the external one otherwise", () => {
    for (const kind of ["doc", "odt", "rtf"] as const) {
      expect(nativeFirst(kind, {})).toBe("docs");
      expect(nativeFirst(kind, { externalConverter: "x" })).toBeNull();
      expect(nativeFirst(kind, { converter: "exav", externalConverter: "x" })).toBe("docs");
    }
  });

  it("is none for the formats nothing of the package reads, and for converter: external", () => {
    for (const kind of ["coreldraw", "publisher", "pagemaker", "freehand", "quarkxpress", "zonerdraw", "wpg"] as const) {
      expect(nativeFirst(kind, {})).toBeNull();
      expect(nativeFirst(kind, { converter: "exav" })).toBeNull();
    }
    for (const kind of kinds) expect(nativeFirst(kind, { converter: "external" }), kind).toBeNull();
  });
});

/** The contract's own fixture: an external converter in a file, imported by its URL. */
const FAKE = pathToFileURL(path.join(import.meta.dirname, "..", "..", "e2e", "fixtures", "fake-converter.js")).href;

const text = (s: string) => new TextEncoder().encode(s);

let contexts = 0;

function context(data: Uint8Array, options: ConversionOptions, signal = new AbortController().signal) {
  const nested = vi.fn(() => ({ resize() {}, destroy() {} }));
  const statuses: { phase: string; step?: string; progress?: number; error?: { code: string; cause?: unknown } }[] = [];
  const ctx = {
    file: { id: `f${contexts++}`, name: "a.vsdx" },
    options,
    source: { bytes: async () => data },
    signal,
    assetBase: "/assets/",
    status: (s: (typeof statuses)[number]) => statuses.push(s),
    controllers() {},
    mountNested: nested,
  } as unknown as RenderContext<ConversionOptions>;
  return { ctx, nested, statuses };
}

const mount = async (kind: ConvertedFormat, ctx: RenderContext<ConversionOptions>) => rendererFor(kind).mount(document.createElement("div"), ctx);

const shown = (nested: ReturnType<typeof vi.fn>) => (nested.mock.calls[0] as unknown as [unknown, { format: string; source: { bytes: Uint8Array } }])[1];

afterEach(() => vi.unstubAllGlobals());

describe("an external converter, loaded from a URL", () => {
  it("is imported once and must export convert", async () => {
    const a = await loadExternal(FAKE);
    expect(await loadExternal(FAKE)).toBe(a);
    expect(typeof a.convert).toBe("function");
    await expect(loadExternal(`data:text/javascript,export const x = 1`)).rejects.toThrow(/does not export convert/);
  });

  it("converts what no converter of the package reads, and its PDF is shown", async () => {
    const { ctx, nested } = context(text("hello"), { externalConverter: FAKE });
    await mount("visio", ctx);
    const file = shown(nested);
    expect(file.format).toBe("pdf");
    // The hint, the file's size and no memory option: what the converter was handed.
    expect(new TextDecoder().decode(file.source.bytes)).toContain("fake converter: visio, 5 bytes, memory unset");
  });

  it("is handed the memory option, in bytes, when the host set one", async () => {
    const { ctx, nested } = context(text("hello"), { externalConverter: FAKE, maxMemory: 123456 });
    await mount("coreldraw", ctx);
    expect(new TextDecoder().decode(shown(nested).source.bytes)).toContain("coreldraw, 5 bytes, memory 123456");
  });

  it("shows an XLSX result as an XLSX", async () => {
    const { ctx, nested } = context(text("SHEET"), { externalConverter: FAKE });
    await mount("wpg", ctx);
    expect(shown(nested).format).toBe("xlsx");
  });

  it("has its progress shown as the viewer's steps", async () => {
    const { ctx, statuses } = context(text("hello"), { externalConverter: FAKE });
    await mount("visio", ctx);
    expect(statuses).toContainEqual({ phase: "loading", step: "engine", progress: 0.5 });
    expect(statuses).toContainEqual({ phase: "converting", step: "start" });
    expect(statuses).toContainEqual({ phase: "converting", step: "read", progress: 0.5 });
    expect(statuses).toContainEqual({ phase: "converting", step: "convert", progress: 1 });
  });

  it("fails with its own error as the cause, a failed conversion", async () => {
    const { ctx, nested } = context(text("FAIL"), { externalConverter: FAKE });
    const error = await mount("visio", ctx).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ExternalConversionError);
    expect(error).toMatchObject({ kind: "failed", format: "visio" });
    expect(String((error as Error).cause)).toMatch(/asked to fail/);
    expect(nested).not.toHaveBeenCalled();
  });

  it("is stopped with the session: the signal it was given is aborted", async () => {
    const abort = new AbortController();
    const { ctx, nested } = context(text("HANG"), { externalConverter: FAKE }, abort.signal);
    const pending = mount("visio", ctx).then(
      () => null,
      (e: unknown) => e,
    );
    await new Promise((r) => setTimeout(r, 20));
    abort.abort(new Error("closed"));
    const error = await pending;
    // Not a conversion failure: the viewer ignores what ends with its own session.
    expect(error).not.toBeInstanceOf(ExternalConversionError);
    expect(nested).not.toHaveBeenCalled();
  });

  it("ends after timeoutMs, with a timeout, even when the module never looks at its signal", async () => {
    const { ctx } = context(text("DEAF"), { externalConverter: FAKE, timeoutMs: 30 });
    const error = await mount("visio", ctx).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ExternalConversionError);
    expect(error).toMatchObject({ kind: "timeout" });
  });

  it("is aborted by the timeout too: a module that looks at its signal is told", async () => {
    const { ctx } = context(text("HANG"), { externalConverter: FAKE, timeoutMs: 30 });
    const error = await mount("visio", ctx).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toMatchObject({ name: "ExternalConversionError", kind: "timeout" });
  });

  it("is refused when it resolves to something the contract does not allow", async () => {
    const { ctx } = context(text("BAD"), { externalConverter: FAKE });
    const error = await mount("visio", ctx).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ExternalConversionError);
    expect(String((error as Error).cause)).toMatch(/did not resolve/);
  });

  it("ends in the needs-converter error, naming the format, where none is set", async () => {
    const { ctx, statuses, nested } = context(text("hello"), {});
    await mount("freehand", ctx);
    const last = statuses.at(-1)!;
    expect(last.phase).toBe("error");
    expect(last.error?.code).toBe("needs_converter");
    expect(last.error?.cause).toBeInstanceOf(NeedsConverterError);
    expect(last.error?.cause).toMatchObject({ kind: "needs-converter", format: "freehand" });
    expect(nested).not.toHaveBeenCalled();
  });
});

describe("where the module is", () => {
  const serve = (manifest: unknown) =>
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(manifest), { status: 200 })),
    );

  it("is a URL as given, relative ones against the page", async () => {
    expect(await externalUrl("https://c.test/x.js", "/a/")).toBe("https://c.test/x.js");
    expect(await externalUrl("/conv/index.js", "/a/")).toBe(new URL("/conv/index.js", document.baseURI).href);
    expect(await externalUrl("./conv/index.js", "/a/")).toBe(new URL("./conv/index.js", document.baseURI).href);
  });

  it("is the entry the asset manifest names for a package's name", async () => {
    serve({ dirs: {}, files: {}, converters: { "@acme/to-pdf": "converters/acme__to-pdf/1.2.3/js/index.js" }, all: [] });
    expect(await externalUrl("@acme/to-pdf", "/m1/")).toBe(new URL("/m1/converters/acme__to-pdf/1.2.3/js/index.js", document.baseURI).href);
    await expect(externalUrl("@acme/other", "/m1/")).rejects.toThrow(/not in the asset manifest/);
  });
});

describe("prefetching a converted format", () => {
  it("names nothing for what the package's own converters take, whose modules are the viewer's", async () => {
    for (const kind of ["xls", "ods", "numbers", "ppt", "odp", "keynote", "odg", "visio"] as const) {
      expect(await prefetchUrls(kind, "/a/")).toEqual([]);
      expect(await prefetchUrls(kind, "/a/", { externalConverter: FAKE })).toEqual([]);
    }
  });

  it("names nothing for a kind without an external converter", async () => {
    expect(await prefetchUrls("coreldraw", "/a/")).toEqual([]);
  });

  it("names the external converter's module and what it says it fetches, relative to the module", async () => {
    expect(await prefetchUrls("coreldraw", "/a/", { externalConverter: FAKE })).toEqual([FAKE, new URL("fake-data-coreldraw.bin", FAKE).href]);
    expect(await prefetchUrls("doc", "/a/", { externalConverter: FAKE })).toEqual([FAKE, new URL("fake-data-doc.bin", FAKE).href]);
    // The package's own `docs` takes a text document when the options say so.
    expect(await prefetchUrls("doc", "/a/", { converter: "exav", externalConverter: FAKE })).toEqual([]);
  });
});
