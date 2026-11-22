/**
 * Which converter a file goes to after the first could not read it: the
 * external converter after the package's, and the package's after the
 * external one. The package's `docs` converter is played by the test (it runs
 * in a worker, which jsdom has none of); the external one is the contract's
 * fixture (e2e/fixtures/fake-converter.js, which fails on FAIL and answers BAD
 * with what the contract does not allow).
 */
import path from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect, it, vi } from "vitest";

import type { RenderContext } from "../core/types.js";
import type { ConversionOptions, ConvertedFormat } from "./index.js";

/** The played `docs` converter cannot read a file that starts with NOPE or FAIL. */
const docs = vi.hoisted(() => ({ calls: 0 }));
vi.mock("./zip.js", () => ({ officeKinds: async () => [] }));
vi.mock("./docs.js", async (real) => {
  const actual = await real<typeof import("./docs.js")>();
  return {
    ...actual,
    sniffDocs: () => "doc",
    convertDocs: async (bytes: Uint8Array) => {
      docs.calls += 1;
      if (/^(NOPE|FAIL)/.test(new TextDecoder().decode(bytes.subarray(0, 4)))) throw new Error("the played docs converter cannot read it");
      return { docx: new Uint8Array([0x50, 0x4b]).buffer, paragraphs: 1, warnings: "" };
    },
  };
});

const { rendererFor } = await import("./convert.js");
const { nativeFirst } = await import("./route.js");
const { DocConversionError } = await import("./docs.js");
const { ExternalConversionError } = await import("./external.js");

const FAKE = pathToFileURL(path.join(import.meta.dirname, "..", "..", "e2e", "fixtures", "fake-converter.js")).href;
const text = (s: string) => new TextEncoder().encode(s);

function context(data: string, options: ConversionOptions) {
  const nested = vi.fn(() => ({ resize() {}, destroy() {} }));
  const ctx = {
    file: { id: "f", name: "a.doc" },
    options,
    source: { bytes: async () => text(data) },
    signal: new AbortController().signal,
    assetBase: "/assets/",
    status: () => {},
    controllers() {},
    mountNested: nested,
  } as unknown as RenderContext<ConversionOptions>;
  return { ctx, nested };
}

const shownAs = (nested: ReturnType<typeof vi.fn>) => (nested.mock.calls[0] as unknown as [unknown, { format: string }] | undefined)?.[1].format;
const outcome = (kind: ConvertedFormat, ctx: RenderContext<ConversionOptions>) =>
  Promise.resolve(rendererFor(kind).mount(document.createElement("div"), ctx)).then(
      () => null,
      (e: unknown) => e,
    );

describe("the converter a format goes to first", () => {
  it("is one per format where the option names it, the default for the others", () => {
    const options: ConversionOptions = { converter: { doc: "exav", ppt: "external" }, externalConverter: "x" };
    expect(nativeFirst("doc", options)).toBe("docs");
    expect(nativeFirst("odt", options)).toBeNull();
    expect(nativeFirst("ppt", options)).toBeNull();
    expect(nativeFirst("xls", options)).toBe("sheets");
  });
});

describe("a file the first converter cannot read", () => {
  it("goes on from the package's converter to the external one, whose picture is shown", async () => {
    docs.calls = 0;
    const { ctx, nested } = context("NOPE, but the external converter reads it", { converter: "exav", externalConverter: FAKE });
    expect(await outcome("doc", ctx)).toBeNull();
    expect(docs.calls).toBe(1);
    expect(shownAs(nested)).toBe("pdf");
  });

  it("goes on from the external converter to the package's, whose picture is shown", async () => {
    docs.calls = 0;
    // A text document goes to the external converter first where one is set.
    const { ctx, nested } = context("BAD for the external converter", { externalConverter: FAKE });
    expect(await outcome("doc", ctx)).toBeNull();
    expect(docs.calls).toBe(1);
    expect(shownAs(nested)).toBe("docx");
  });

  it("fails with the first converter's error when the other fails too", async () => {
    const exavFirst = context("FAIL", { converter: "exav", externalConverter: FAKE });
    expect(await outcome("doc", exavFirst.ctx)).toBeInstanceOf(DocConversionError);
    const externalFirst = context("FAIL", { externalConverter: FAKE });
    expect(await outcome("doc", externalFirst.ctx)).toBeInstanceOf(ExternalConversionError);
    // With no external converter, the package's says why.
    const alone = context("FAIL", { converter: "external" });
    expect(await outcome("doc", alone.ctx)).toBeInstanceOf(DocConversionError);
    expect(alone.nested).not.toHaveBeenCalled();
  });
});
