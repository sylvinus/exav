import { describe, expect, it, vi } from "vitest";

import { BUILTIN_ORDER } from "../core/formats.js";
import { MAX_PICTURE_EDGE, MAX_PICTURE_PIXELS } from "../core/pictures.js";
import {
  checkBytes,
  checkCommand,
  checkFrameMessage,
  checkOpen,
  checkOptions,
  checkRaster,
  checkReplace,
  checkThemeMessage,
  checkUnraster,
  checkWatch,
  isColor,
  linkTarget,
  MAX_ITEMS,
  MAX_TEXT,
  PROTOCOL,
  READS,
  refusedRasterId,
} from "./protocol.js";

describe("a status from the frame", () => {
  const status = (s: unknown) => checkFrameMessage({ type: "status", session: 0, status: s });
  it("keeps a load's step and progress", () => {
    expect(status({ phase: "converting", step: "convert", progress: 0.25 })).toEqual({
      type: "status",
      session: 0,
      status: { phase: "converting", step: "convert", progress: 0.25 },
    });
  });
  it("is refused with a step that is none of the viewer's, or a progress out of range", () => {
    expect(status({ phase: "loading", step: "mining" })).toBeNull();
    expect(status({ phase: "loading", step: "file", progress: 2 })).toBeNull();
  });
});

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

  it("carry the storeys of a model, each with its elevation or none, and refuse a malformed one", () => {
    const state = (items: unknown[]) => ({ type: "state", session: 0, key: "storeys", value: { items } });
    const item = { id: "3", name: "Level 1", elevation: 3, visible: true };
    expect(checkFrameMessage(state([item, { ...item, id: "4", elevation: null }]))).toEqual(state([item, { ...item, id: "4", elevation: null }]));
    for (const bad of [{ ...item, elevation: "3" }, { ...item, elevation: Infinity }, { ...item, elevation: undefined }, { ...item, visible: 1 }, { ...item, name: 7 }]) {
      expect(checkFrameMessage(state([bad])), JSON.stringify(bad)).toBeNull();
    }
    expect(checkFrameMessage(state(Array.from({ length: MAX_ITEMS + 1 }, (_, i) => ({ ...item, id: String(i) }))))).toBeNull();
    // A command to them.
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "storeys", action: "setVisible", args: ["3", false] })).not.toBeNull();
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

  it("carry the names a warning lists, as text, at most 16", () => {
    const warning = (names: unknown) => ({ type: "state", session: 0, key: "warnings", value: [{ key: "external_references", count: 1, names }] });
    expect(checkFrameMessage(warning(["walls.dwg"]))).toMatchObject({ value: [{ names: ["walls.dwg"] }] });
    expect(checkFrameMessage(warning([1]))).toBeNull();
    expect(checkFrameMessage(warning("walls.dwg"))).toBeNull();
    expect(checkFrameMessage(warning(Array(17).fill("x")))).toBeNull();
    expect(checkFrameMessage(warning(["x".repeat(257)]))).toBeNull();
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
    expect(checkFrameMessage({ type: "read", id: 1, generation: 0, offset: 0, length: 10, extra: 1 })).toEqual({ type: "read", id: 1, generation: 0, offset: 0, length: 10 });
    for (const [offset, length] of [
      [-1, 10],
      [0.5, 10],
      [2 ** 60, 1],
      ["0", 1],
      [0, Infinity],
      [0, NaN],
    ]) {
      expect(checkFrameMessage({ type: "read", id: 1, generation: 0, offset, length }), `${offset} ${length}`).toBeNull();
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
    expect(checkOptions({ cad: { monochrome: true, lineweights: "always" } })).toEqual({ cad: { monochrome: true, lineweights: "always" } });
    expect(checkOptions({ cad: { monochrome: "yes", lineweights: "thick" } })).toEqual({ cad: {} });
    // The IFC and STL engine's limits reach the frame's plugins.
    expect(checkOptions({ ifc: { timeoutMs: 5000, maxTriangles: 1e6, more: 1 }, model: { maxTriangles: "9", timeoutMs: 10 } })).toEqual({
      ifc: { timeoutMs: 5000, maxTriangles: 1e6 },
      model: { timeoutMs: 10 },
    });
    expect(checkOptions({ pdf: { prerenderMargin: "1px; }" } })).toEqual({ pdf: {} });
    expect(checkOptions({ conversion: { timeoutMs: 60_000, baseUrl: "https://evil.test/" } })).toEqual({ conversion: { timeoutMs: 60_000 } });
    expect(checkOptions({ conversion: { timeoutMs: "1" } })).toEqual({ conversion: {} });
    expect(checkOptions({ conversion: { converter: "external" } })).toEqual({ conversion: { converter: "external" } });
    expect(checkOptions({ conversion: { converter: "excel" } })).toEqual({ conversion: {} });
    // The external converter: a package name the manifest lists, a path or an http(s) URL; nothing else.
    for (const ok of ["@acme/to-pdf", "to-pdf", "/conv/index.js", "./conv/index.js", "https://converter.example.com/index.js"]) {
      expect(checkOptions({ conversion: { externalConverter: ok } }), ok).toEqual({ conversion: { externalConverter: ok } });
    }
    for (const bad of ["javascript:alert(1)", "data:text/javascript,1", "@Acme/To PDF", "a b", "", "x".repeat(600), "/a\nb", 5, null]) {
      expect(checkOptions({ conversion: { externalConverter: bad } }), String(bad)).toEqual({ conversion: {} });
    }
  });

  it("is a command of a known target with few arguments", () => {
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "layers", action: "setAll", args: [true] })).not.toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "drag", action: "choose", args: ["pan"] })).not.toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "image", action: "x", args: [] })).toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "zoom", action: "fit", args: [1, 2, 3, 4, 5] })).toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "media", action: "seek", args: [3] })).not.toBeNull();
    expect(checkCommand({ type: "command", call: 1, session: 0, target: "sheets", action: "select", args: [1] })).not.toBeNull();
  });

  it("takes a player's controls as an option, and nothing else of it", () => {
    expect(checkOptions({ media: { controls: "none", autoplay: true } })).toEqual({ media: { controls: "none" } });
    expect(checkOptions({ media: { controls: "hidden" } })).toEqual({ media: {} });
  });

  it("takes the theme's known properties when their value is of their kind", () => {
    const head = new ArrayBuffer(3);
    const theme = {
      tokens: {
        "--exav-viewer-text": "rgb(1 2 3)",
        "--exav-viewer-panel": "url(https://x.test/a.png)",
        "--exav-viewer-surface": "var(--x)",
        "--exav-viewer-radius": "6px",
        "--exav-viewer-tap": "expression(1)",
        "--exav-viewer-font": "Marianne, sans-serif",
        "--exav-viewer-accent": "oklch(0.5 0.1 250)",
        "--evil": "#fff",
      },
      scheme: "dark",
    };
    const m = checkOpen({ type: "open", formats: ["pdf"], file: { name: "a.pdf", type: "", path: "a.pdf", format: "pdf" }, source: { kind: "ranges", size: 3, head }, options: {}, theme }, BUILTIN_ORDER);
    expect(m?.theme).toEqual({
      tokens: { "--exav-viewer-text": "rgb(1 2 3)", "--exav-viewer-radius": "6px", "--exav-viewer-font": "Marianne, sans-serif", "--exav-viewer-accent": "oklch(0.5 0.1 250)" },
      scheme: "dark",
    });
    expect(checkThemeMessage({ type: "theme", theme: { tokens: { "--exav-viewer-font": "x; background: url(y)" }, scheme: "dim" } })).toEqual({ type: "theme", theme: { tokens: {}, scheme: null } });
  });

  it("draws a page of a request whose options are well formed, and no other", () => {
    const options = { width: 800, height: 600, region: { x: 0.1, y: 0.2, width: 0.5, height: 0.5 }, fit: "cover", background: "#fff" };
    expect(checkRaster({ type: "raster", id: 1, session: 0, page: 2, options })).toEqual({ type: "raster", id: 1, session: 0, page: 2, options });
    expect(checkRaster({ type: "raster", id: 1, session: 0, page: 2, options: { longEdge: 300, region: "current" } })?.options).toEqual({ longEdge: 300, region: "current" });
    // A camera, as a model's region.
    const camera = { position: [1, 2, 3], target: [0, 0, 0], projection: { type: "perspective", fov: 50 }, aspect: 1.5 };
    expect(checkRaster({ type: "raster", id: 1, session: 0, page: 1, options: { longEdge: 10, region: camera } })?.options.region).toEqual(camera);
    const bad: Record<string, unknown>[] = [
      { longEdge: 0 },
      { longEdge: Infinity },
      { width: NaN },
      { height: -1 },
      { longEdge: 1e12 },
      { longEdge: 10, region: { x: 0, y: 0, width: 0, height: 1 } },
      { longEdge: 10, region: { x: NaN, y: 0, width: 1, height: 1 } },
      { longEdge: 10, region: "all" },
      { longEdge: 10, region: { ...camera, projection: { type: "perspective", fov: 180 } } },
      { longEdge: 10, region: { ...camera, position: [1, 2] } },
      { longEdge: 10, fit: "stretch" },
      { longEdge: 10, lineweight: "thick" },
      { longEdge: 10, layout: "x".repeat(2000) },
      { longEdge: 10, background: "url(https://example.test/x)" },
      { longEdge: 10, background: "red; background: url(x)" },
    ];
    for (const options of bad) expect(checkRaster({ type: "raster", id: 1, session: 0, page: 1, options }), JSON.stringify(options)).toBeNull();
    expect(checkRaster({ type: "raster", id: 1, session: 0, page: 0, options: { longEdge: 100 } })).toBeNull();
    expect(checkRaster({ type: "raster", id: -1, session: 0, page: 1, options: { longEdge: 100 } })).toBeNull();
    expect(checkRaster({ type: "raster", id: 1, session: 0, page: 1 })).toBeNull();
  });

  it("owes an answer to a raster it refuses when it has a number, and to no other message", () => {
    const refused = (m: unknown) => refusedRasterId(m);
    expect(refused({ type: "raster", id: 7, session: 0, page: 1, options: { longEdge: -5 } })).toBe(7);
    expect(refused({ type: "raster", id: 7, session: 0, page: 0, options: { longEdge: 100 } })).toBe(7);
    expect(refused({ type: "raster", id: 7, session: 0, page: 1 })).toBe(7);
    expect(refused({ type: "raster", id: 7, session: "0", page: 1, options: { longEdge: 100 } })).toBe(7);
    // One that checks is answered by the drawing; no number, nobody to answer; not a raster, not ours.
    expect(refused({ type: "raster", id: 7, session: 0, page: 1, options: { longEdge: 100 } })).toBeNull();
    expect(refused({ type: "raster", id: -1, session: 0, page: 1, options: { longEdge: -5 } })).toBeNull();
    expect(refused({ type: "raster", session: 0, page: 1, options: {} })).toBeNull();
    expect(refused({ type: "unraster", id: 7 })).toBeNull();
    expect(refused(null)).toBeNull();
  });

  it("follows a store on request, for the stores that are followed so", () => {
    expect(checkWatch({ type: "watch", session: 0, key: "viewport" })).toEqual({ type: "watch", session: 0, key: "viewport" });
    expect(checkWatch({ type: "unwatch", session: 3, key: "viewport", extra: 1 })).toEqual({ type: "unwatch", session: 3, key: "viewport" });
    for (const bad of [
      { type: "watch", session: 0, key: "zoom" },
      { type: "watch", session: 0, key: "__proto__" },
      { type: "watch", session: -1, key: "viewport" },
      { type: "watch", key: "viewport" },
      { type: "watching", session: 0, key: "viewport" },
    ])
      expect(checkWatch(bad), JSON.stringify(bad)).toBeNull();
    expect(checkWatch("watch")).toBeNull();
  });

  it("stops a picture by its number, and takes the next document with its file and generation", () => {
    expect(checkUnraster({ type: "unraster", id: 4 })).toEqual({ type: "unraster", id: 4 });
    expect(checkUnraster({ type: "unraster", id: 1.5 })).toBeNull();
    const file = { name: "a.pdf", type: "", path: "a.pdf", format: "pdf" };
    const source = { kind: "blob", blob: new Blob(["x"]) };
    expect(checkReplace({ type: "replace", call: 3, generation: 1, file, source }, BUILTIN_ORDER)).toEqual({ type: "replace", call: 3, generation: 1, file, source });
    // Generation 0 is the document `open` gave.
    expect(checkReplace({ type: "replace", call: 3, generation: 0, file, source }, BUILTIN_ORDER)).toBeNull();
    expect(checkReplace({ type: "replace", call: 3, generation: 1, file: { ...file, format: "nope" }, source }, BUILTIN_ORDER)).toBeNull();
    expect(checkReplace({ type: "replace", call: 3, generation: 1, file, source: { kind: "url", url: "javascript:alert(1)" } }, BUILTIN_ORDER)).toBeNull();
    expect(checkReplace({ type: "replace", call: 3, generation: 1, file: { ...file, name: "x".repeat(5000) }, source }, BUILTIN_ORDER)).toBeNull();
  });

  it("names the document a read is for, and answers a replacement", () => {
    expect(checkFrameMessage({ type: "read", id: 5, generation: 2, offset: 10, length: 20 })).toEqual({ type: "read", id: 5, generation: 2, offset: 10, length: 20 });
    expect(checkFrameMessage({ type: "read", id: 5, offset: 10, length: 20 })).toBeNull();
    expect(checkFrameMessage({ type: "read", id: 5, generation: -1, offset: 10, length: 20 })).toBeNull();
    expect(checkFrameMessage({ type: "replaced", call: 3, ok: true })).toEqual({ type: "replaced", call: 3, ok: true });
    expect(checkFrameMessage({ type: "replaced", call: 3, ok: "yes" })).toBeNull();
    expect(checkFrameMessage({ type: "replaced", ok: true })).toBeNull();
  });
});

describe("what the frame says of a player, of sheets and of pictures", () => {
  const MEDIA = { kind: "audio", paused: true, ended: false, currentTime: 1, duration: Infinity, buffered: 2, volume: 0.5, muted: false, rate: 1, waiting: false, blocked: false };
  const state = (key: string, value: unknown) => checkFrameMessage({ type: "state", session: 0, key, value });

  it("is a player's state of numbers in their range", () => {
    // A live stream lasts forever.
    expect(state("media", { ...MEDIA, extra: 1 })).toEqual({ type: "state", session: 0, key: "media", value: MEDIA });
    for (const bad of [{ volume: 2 }, { currentTime: -1 }, { currentTime: NaN }, { duration: NaN }, { rate: 0 }, { rate: 100 }, { kind: "image" }, { paused: "no" }, { blocked: undefined }]) {
      expect(state("media", { ...MEDIA, ...bad }), JSON.stringify(bad)).toBeNull();
    }
  });

  it("is sheets named in text no longer than the limit", () => {
    expect(state("sheets", { items: [{ index: 0, name: "A" }], current: 0 })).not.toBeNull();
    expect(state("sheets", { items: [{ index: 0, name: "x".repeat(MAX_TEXT + 1) }], current: 0 })).toBeNull();
    expect(state("sheets", { items: [{ index: -1, name: "A" }], current: 0 })).toBeNull();
    expect(state("pictures", { count: 3, space: "page" })).toEqual({ type: "state", session: 0, key: "pictures", value: { count: 3, space: "page" } });
    expect(state("pictures", { count: 1.5, space: "page" })).toBeNull();
    expect(state("pictures", { count: 3, space: "world" })).toBeNull();
    expect(state("pictures", { count: 3 })).toBeNull();
  });

  it("is a viewport only in the coordinates its space has", () => {
    const rect = { x: 0.1, y: 0.2, width: 0.5, height: 0.4 };
    expect(state("viewport", null)).toEqual({ type: "state", session: 0, key: "viewport", value: null });
    expect(state("viewport", { space: "page", page: 2, region: rect })).toEqual({ type: "state", session: 0, key: "viewport", value: { space: "page", page: 2, region: rect } });
    expect(state("viewport", { space: "drawing", page: 1, layout: "A1", region: rect })).toMatchObject({ value: { layout: "A1" } });
    const camera = { position: [1, 2, 3], target: [0, 0, 0], up: [0, 0, 1], projection: { type: "orthographic", height: 5 }, aspect: 2 };
    expect(state("viewport", { space: "camera", page: 1, region: camera })).toMatchObject({ value: { space: "camera", region: camera } });
    for (const bad of [
      { space: "camera", page: 1, region: rect },
      { space: "page", page: 1, region: camera },
      { space: "page", page: 0, region: rect },
      { space: "page", page: 1, region: { ...rect, width: -1 } },
      { space: "page", page: 1 },
      { space: "frame", page: 1, region: rect },
      { space: "page", page: 1, layout: "x".repeat(MAX_TEXT + 1), region: rect },
    ]) {
      expect(state("viewport", bad), JSON.stringify(bad)).toBeNull();
    }
  });

  it("is a picture only when it is a bitmap of a size the host takes", () => {
    class FakeBitmap {
      closed = false;
      constructor(
        public width: number,
        public height: number,
      ) {}
      close() {
        this.closed = true;
      }
    }
    vi.stubGlobal("ImageBitmap", FakeBitmap);
    const rect = { x: 0, y: 0, width: 1, height: 1 };
    const result = (bitmap: unknown, extra: Record<string, unknown> = {}) =>
      checkFrameMessage({ type: "rastered", id: 3, result: { ok: true, bitmap, width: (bitmap as FakeBitmap).width, height: (bitmap as FakeBitmap).height, page: 1, space: "page", region: rect, ...extra } });
    const failed = { type: "rastered", id: 3, result: { ok: false, code: "failed" } };
    try {
      const ok = new FakeBitmap(10, 20);
      expect(result(ok)).toEqual({ type: "rastered", id: 3, result: { ok: true, bitmap: ok, width: 10, height: 20, page: 1, space: "page", region: rect } });
      expect(ok.closed).toBe(false);
      // Past the edge, or past the pixels (both sides under the edge): refused, and freed.
      const huge = new FakeBitmap(MAX_PICTURE_EDGE + 1, 10);
      expect(result(huge)).toEqual(failed);
      expect(huge.closed).toBe(true);
      const wide = new FakeBitmap(MAX_PICTURE_EDGE, Math.floor(MAX_PICTURE_PIXELS / MAX_PICTURE_EDGE) + 1);
      expect(result(wide)).toEqual(failed);
      expect(wide.closed).toBe(true);
      // A size that is not the bitmap's, a region of another kind, a page that is none, a space that is none.
      for (const extra of [{ width: 11 }, { region: { position: [0, 0, 0] } }, { region: undefined }, { page: 0 }, { space: "world" }, { layout: "x".repeat(MAX_TEXT + 1) }, { region: { ...rect, width: 0 } }]) {
        const bitmap = new FakeBitmap(10, 20);
        expect(result(bitmap, extra), JSON.stringify(extra)).toEqual(failed);
        expect(bitmap.closed, JSON.stringify(extra)).toBe(true);
      }
      expect(checkFrameMessage({ type: "rastered", id: 3, result: { ok: true, bitmap: { width: 10, height: 10 }, width: 10, height: 10, page: 1, space: "page", region: rect } })).toEqual(failed);
      // A video frame has no region; the failure keeps its code.
      expect(result(new FakeBitmap(4, 4), { space: "frame", region: undefined })).toMatchObject({ result: { ok: true, space: "frame" } });
      expect(result(new FakeBitmap(4, 4), { space: "frame" })).toEqual(failed);
      expect(checkFrameMessage({ type: "rastered", id: 3, result: { ok: false, code: "too-large" } })).toEqual({ type: "rastered", id: 3, result: { ok: false, code: "too-large" } });
      expect(checkFrameMessage({ type: "rastered", id: 3, result: { ok: false, code: "boom" } })).toEqual(failed);
      // No id: the bitmap is freed all the same.
      const orphan = new FakeBitmap(10, 20);
      expect(checkFrameMessage({ type: "rastered", result: { ok: true, bitmap: orphan } })).toBeNull();
      expect(orphan.closed).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("is a key among the navigation keys", () => {
    expect(checkFrameMessage({ type: "key", key: "PageDown", shift: false, repeat: true })).toEqual({ type: "key", key: "PageDown", shift: false, repeat: true });
    for (const key of ["Delete", "Enter", " ", "a", "F5", "Tab"]) expect(checkFrameMessage({ type: "key", key, shift: false, repeat: false }), key).toBeNull();
    expect(checkFrameMessage({ type: "key", key: "Escape", shift: "yes", repeat: false })).toBeNull();
  });
});
