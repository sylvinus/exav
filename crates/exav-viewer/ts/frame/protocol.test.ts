import { describe, expect, it } from "vitest";

import { BUILTIN_ORDER } from "../core/formats.js";
import { checkBytes, checkCommand, checkFrameMessage, checkOpen, checkOptions, isColor, linkTarget, MAX_ITEMS, MAX_TEXT, PROTOCOL, READS } from "./protocol.js";

describe("colours the host puts in a style", () => {
  it("are hex, or rgb()/hsl() of numbers, as the engines write them", () => {
    for (const c of ["#fff", "#212830", "#21283080", "rgb(255 0 0)", "rgb(1, 2, 3)", "hsl(120 42% 58%)", "rgba(1 2 3 / 0.5)"]) expect(isColor(c), c).toBe(true);
  });
  it("are nothing that could fetch, escape the declaration or be a keyword trick", () => {
    for (const c of ["url(https://x.test/)", "red", "#fff; background: url(x)", "rgb(1 2 3) url(x)", "var(--x)", "expression(alert(1))", "image-set(x)", `#${"0".repeat(100)}`, "", 1]) {
      expect(isColor(c), String(c)).toBe(false);
    }
  });
});

describe("frame messages", () => {
  it("are copied field by field: nothing beyond the protocol's fields reaches the host", () => {
    const m = checkFrameMessage({
      type: "controllers",
      session: 0,
      values: { selection: { name: "Wall", category: "IFCWALL", extra: "x" }, info: { triangles: 30 } },
      statics: { pages: { goTo: true, step: false, more: 1 } },
      sneaky: true,
    });
    expect(m).toEqual({ type: "controllers", session: 0, values: { selection: { name: "Wall", category: "IFCWALL" }, info: { triangles: 30 } }, statics: { pages: { goTo: true, step: false } } });
    // A selection's storey is text too.
    const s = (storey: unknown) => checkFrameMessage({ type: "controllers", session: 0, values: { selection: { name: "Wall", category: "IFCWALL", storey } }, statics: {} });
    expect(s("Level 1")).toMatchObject({ values: { selection: { name: "Wall", category: "IFCWALL", storey: "Level 1" } } });
    expect(s({ toString: 1 })).toMatchObject({ values: { selection: { name: "Wall", category: "IFCWALL" } } });
  });

  it("are refused when a list is longer, or a string, than the limits", () => {
    const items = (n: number, name = "a") => Array.from({ length: n }, (_, i) => ({ id: String(i), name, color: "#000", visible: true }));
    const layers = (list: unknown[]) => ({ type: "state", session: 0, key: "layers", value: { kind: "layers", items: list } });
    expect(checkFrameMessage(layers(items(3)))).not.toBeNull();
    expect(checkFrameMessage(layers(items(MAX_ITEMS + 1)))).toBeNull();
    expect(checkFrameMessage(layers(items(1, "x".repeat(MAX_TEXT))))).not.toBeNull();
    expect(checkFrameMessage(layers(items(1, "x".repeat(MAX_TEXT + 1))))).toBeNull();
  });

  it("are refused when a number is not one", () => {
    for (const value of [
      { unit: "page", current: 1.5, total: 2 },
      { unit: "page", current: -1, total: 2 },
      { unit: "page", current: "1", total: 2 },
      { unit: "pages", current: 1, total: 2 },
    ]) {
      expect(checkFrameMessage({ type: "state", session: 0, key: "pages", value }), JSON.stringify(value)).toBeNull();
    }
    expect(checkFrameMessage({ type: "state", session: 0, key: "pages", value: null })).toEqual({ type: "state", session: 0, key: "pages", value: null });
    expect(checkFrameMessage({ type: "state", session: 0.5, key: "pages", value: null })).toBeNull();
  });

  it("carry warnings and info under keys of plain words only", () => {
    expect(checkFrameMessage({ type: "state", session: 0, key: "warnings", value: [{ key: "scene_truncated", count: 1 }] })).not.toBeNull();
    expect(checkFrameMessage({ type: "state", session: 0, key: "warnings", value: [{ key: "__proto__", count: 1 }] })).toBeNull();
    expect(checkFrameMessage({ type: "state", session: 0, key: "warnings", value: [{ key: "a.b", count: 1 }] })).toBeNull();
    expect(checkFrameMessage({ type: "state", session: 0, key: "info", value: { constructor: 1 } })).toBeNull();
  });

  it("list a member of undeclared size, and refuse any other negative size", () => {
    // @exav/unpack-wasm gives -1 for a size a gzip or xz stream does not declare.
    const archive = (uncompressedSize: number) => ({
      type: "state",
      session: 0,
      key: "archive",
      value: { members: [{ index: 0, name: "quote.csv", uncompressedSize, encrypted: false }], opening: null, opened: null, refused: null },
    });
    expect(checkFrameMessage(archive(-1))).not.toBeNull();
    expect(checkFrameMessage(archive(1024))).not.toBeNull();
    expect(checkFrameMessage(archive(-2))).toBeNull();
  });

  it("name an archive's refusal only with the four known keys", () => {
    const archive = (refused: unknown) => ({ type: "state", session: 0, key: "archive", value: { members: [], opening: null, opened: null, refused } });
    expect(checkFrameMessage(archive({ key: "archive_no_reader" }))).not.toBeNull();
    expect(checkFrameMessage(archive({ key: "error" }))).toBeNull();
  });
});

describe("links", () => {
  it("are absolute http(s) URLs, normalised", () => {
    expect(linkTarget("https://example.com/a b")).toBe("https://example.com/a%20b");
    expect(linkTarget("HTTP://EXAMPLE.com")).toBe("http://example.com/");
    for (const u of ["javascript:alert(1)", " javascript:alert(1)", "/a", "a.html", "data:,x", "blob:https://x/1", "file:///x", "mailto:a@b.c"]) expect(linkTarget(u), u).toBeNull();
  });
});

describe("reads and the policy the frame reports", () => {
  it("are whole numbers, checked for shape only: the host judges the range", () => {
    expect(checkFrameMessage({ type: "read", id: 1, offset: 0, length: 10, extra: 1 })).toEqual({ type: "read", id: 1, offset: 0, length: 10 });
    for (const [offset, length] of [
      [-1, 10],
      [0.5, 10],
      [2 ** 60, 1],
      ["0", 1],
      [0, Infinity],
      [0, NaN],
    ]) {
      expect(checkFrameMessage({ type: "read", id: 1, offset, length }), `${offset} ${length}`).toBeNull();
    }
    expect(checkFrameMessage({ type: "cancel", id: 3 })).toEqual({ type: "cancel", id: 3 });
    expect(checkFrameMessage({ type: "cancel", id: "3" })).toBeNull();
  });

  it("come as lists of sources, or null", () => {
    const policy = { script: ["'self'"], connect: ["'self'", "https://a.test"], img: [], media: ["blob:"] };
    expect(checkFrameMessage({ type: "ready", protocol: PROTOCOL, policy })).toEqual({ type: "ready", protocol: PROTOCOL, policy });
    expect(checkFrameMessage({ type: "ready", protocol: PROTOCOL, policy: null })).toEqual({ type: "ready", protocol: PROTOCOL, policy: null });
    expect(checkFrameMessage({ type: "ready", protocol: PROTOCOL })).toBeNull();
    expect(checkFrameMessage({ type: "ready", protocol: PROTOCOL, policy: { ...policy, media: ["<b>"] } })).not.toBeNull();
    expect(checkFrameMessage({ type: "ready", protocol: PROTOCOL, policy: { ...policy, media: ["a b"] } })).toBeNull();
    expect(checkFrameMessage({ type: "ready", protocol: PROTOCOL, policy: { ...policy, img: "x" } })).toBeNull();
  });
});

describe("what the frame takes from the host", () => {
  const blob = new Blob(["x"]);
  const open = (over: Record<string, unknown> = {}) => ({
    type: "open",
    formats: ["pdf", "dwg"],
    file: { name: "a.pdf", type: "", path: "a.pdf", format: null },
    source: { kind: "blob", blob },
    options: {},
    ...over,
  });

  it("is an open with a blob, and formats it knows", () => {
    expect(checkOpen(open(), BUILTIN_ORDER)).toMatchObject({ formats: ["pdf", "dwg"], file: { name: "a.pdf", format: null }, source: { kind: "blob", blob } });
    expect(checkOpen(open({ formats: ["pdf", "evil"] }), BUILTIN_ORDER)?.formats).toEqual(["pdf"]);
    expect(checkOpen(open({ source: { kind: "blob", blob: "x" } }), BUILTIN_ORDER)).toBeNull();
    expect(checkOpen(open({ blob, source: undefined }), BUILTIN_ORDER)).toBeNull();
    expect(checkOpen(open({ file: { name: "a", type: "", path: "a", format: "evil" } }), BUILTIN_ORDER)).toBeNull();
  });

  it("is an open with an http(s) URL, or a size and the first bytes", () => {
    expect(checkOpen(open({ source: { kind: "url", url: "https://media.test/a.mp4" } }), BUILTIN_ORDER)?.source).toEqual({ kind: "url", url: "https://media.test/a.mp4" });
    for (const url of ["javascript:alert(1)", "/a.mp4", "blob:https://x/1"]) expect(checkOpen(open({ source: { kind: "url", url } }), BUILTIN_ORDER), url).toBeNull();
    const head = new ArrayBuffer(READS.head);
    expect(checkOpen(open({ source: { kind: "ranges", size: 1e6, head } }), BUILTIN_ORDER)?.source).toEqual({ kind: "ranges", size: 1e6, head });
    expect(checkOpen(open({ source: { kind: "ranges", size: 10, head: new ArrayBuffer(10) } }), BUILTIN_ORDER)).not.toBeNull();
    expect(checkOpen(open({ source: { kind: "ranges", size: 1e6, head: new ArrayBuffer(10) } }), BUILTIN_ORDER)).toBeNull();
    expect(checkOpen(open({ source: { kind: "ranges", size: 0, head: new ArrayBuffer(0) } }), BUILTIN_ORDER)).toBeNull();
  });

  it("answers a read with bytes or a known refusal", () => {
    const data = new ArrayBuffer(4);
    expect(checkBytes({ type: "bytes", id: 2, data })).toEqual({ type: "bytes", id: 2, data });
    expect(checkBytes({ type: "bytes", id: 2, error: "refused" })).toEqual({ type: "bytes", id: 2, error: "refused" });
    expect(checkBytes({ type: "bytes", id: 2, error: "other" })).toBeNull();
    expect(checkBytes({ type: "bytes", id: -2, data })).toBeNull();
  });

  it("keeps known options of the right type, and drops the rest", () => {
    expect(
      checkOptions({
        pdf: { maxZoom: 4, minZoom: "1", prerenderMargin: "50%" },
        cad: { ground: "dark", colors: { light: "#fff", dark: "url(x)" }, timeoutMs: Infinity, maxDecompressedBytes: 1e8 },
        image: { maxDecodeBytes: 1e6, detail: () => null },
        ifc: { highlight: "red" },
        evil: {},
      }),
    ).toEqual({ pdf: { maxZoom: 4, prerenderMargin: "50%" }, cad: { ground: "dark", maxDecompressedBytes: 1e8 }, image: { maxDecodeBytes: 1e6 }, ifc: {} });
    expect(checkOptions({ cad: { maxDecompressedBytes: "1e8" } })).toEqual({ cad: {} });
    // The IFC and STL engine's limits reach the frame's plugins.
    expect(checkOptions({ ifc: { timeoutMs: 5000, maxTriangles: 1e6, more: 1 }, model: { maxTriangles: "9", timeoutMs: 10 } })).toEqual({
      ifc: { timeoutMs: 5000, maxTriangles: 1e6 },
      model: { timeoutMs: 10 },
    });
    expect(checkOptions({ pdf: { prerenderMargin: "1px; }" } })).toEqual({ pdf: {} });
  });

  it("is a command of a known target with few arguments", () => {
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "layers", action: "setAll", args: [true] })).not.toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "drag", action: "choose", args: ["pan"] })).not.toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "image", action: "x", args: [] })).toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "zoom", action: "fit", args: [1, 2, 3, 4, 5] })).toBeNull();
  });
});
