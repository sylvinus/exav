import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RasterError } from "./pictures.js";
import { createPictures, drawTiled, encodeBitmap } from "./raster.js";
import type { Raster } from "./types.js";

/** A canvas that records what is drawn on it. */
class FakeCanvas {
  static made: FakeCanvas[] = [];
  /** What `convertToBlob` answers, as the mime type of the blob. */
  static encodes: (type: string) => string = (type) => type;
  draws: unknown[][] = [];
  fills: unknown[][] = [];
  fillStyle = "";
  transferred = 0;
  /** The size it was made at. */
  readonly made: [number, number];
  constructor(
    public width: number,
    public height: number,
  ) {
    this.made = [width, height];
    FakeCanvas.made.push(this);
  }
  getContext() {
    const canvas = this;
    return {
      drawImage: (...a: unknown[]) => this.draws.push(a),
      fillRect: (...a: unknown[]) => this.fills.push([this.fillStyle, ...a]),
      set fillStyle(v: string) {
        canvas.fillStyle = v;
      },
    };
  }
  transferToImageBitmap() {
    this.transferred++;
    return new FakeBitmap(this.width, this.height);
  }
  async convertToBlob(o: { type: string; quality?: number }) {
    return new Blob(["x"], { type: FakeCanvas.encodes(o.type) });
  }
}

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

beforeEach(() => {
  FakeCanvas.made = [];
  FakeCanvas.encodes = (t) => t;
  vi.stubGlobal("OffscreenCanvas", FakeCanvas);
  vi.stubGlobal("ImageBitmap", FakeBitmap);
});
afterEach(() => vi.unstubAllGlobals());

const bitmap = (w: number, h: number) => new FakeBitmap(w, h) as unknown as ImageBitmap;
const code = async (p: Promise<unknown>) => p.then(() => "none", (e) => (e instanceof RasterError ? e.code : `other: ${String(e)}`));

describe("a picture drawn in tiles", () => {
  it("has each tile copied where it belongs, then freed, and its canvas given away whole", async () => {
    const drawn: FakeBitmap[] = [];
    const result = await drawTiled(250, 120, 100, async (t) => {
      const b = new FakeBitmap(t.width, t.height);
      drawn.push(b);
      return b as unknown as ImageBitmap;
    });
    const canvas = FakeCanvas.made[0]!;
    expect(canvas.made).toEqual([250, 120]);
    expect(canvas.draws.map((a) => a.slice(1))).toEqual([
      [0, 0],
      [100, 0],
      [200, 0],
      [0, 100],
      [100, 100],
      [200, 100],
    ]);
    expect(drawn).toHaveLength(6);
    expect(drawn.every((b) => b.closed)).toBe(true);
    expect(canvas.transferred).toBe(1);
    expect(result).toMatchObject({ width: 250, height: 120 });
    // The canvas the result came from is released: the bitmap owns the pixels.
    expect([canvas.width, canvas.height]).toEqual([0, 0]);
  });

  it("is filled with the ground first when it has one", async () => {
    await drawTiled(10, 10, 10, async (t) => new FakeBitmap(t.width, t.height) as unknown as ImageBitmap, { background: "#123456" });
    expect(FakeCanvas.made[0]!.fills).toEqual([["#123456", 0, 0, 10, 10]]);
    await drawTiled(10, 10, 10, async (t) => new FakeBitmap(t.width, t.height) as unknown as ImageBitmap);
    expect(FakeCanvas.made[1]!.fills).toEqual([]);
  });

  it("stops between tiles when aborted, frees the canvas and the tile in hand", async () => {
    const abort = new AbortController();
    const drawn: FakeBitmap[] = [];
    const p = drawTiled(
      300,
      100,
      100,
      async (t) => {
        const b = new FakeBitmap(t.width, t.height);
        drawn.push(b);
        if (drawn.length === 2) abort.abort();
        return b as unknown as ImageBitmap;
      },
      { signal: abort.signal },
    );
    expect(await code(p)).toBe("aborted");
    // The third tile was never asked for; the two that were are closed; the canvas is empty again.
    expect(drawn).toHaveLength(2);
    expect(drawn.every((b) => b.closed)).toBe(true);
    expect(FakeCanvas.made[0]).toMatchObject({ width: 0, height: 0, transferred: 0 });
  });

  it("fails with a tile that is not the size it was drawn for, or a drawing that throws, and frees as before", async () => {
    const wrong = new FakeBitmap(99, 100);
    expect(await code(drawTiled(200, 100, 100, async (t) => (t.x === 0 ? (wrong as unknown as ImageBitmap) : bitmap(t.width, t.height))))).toBe("failed");
    expect(wrong.closed).toBe(true);
    expect(FakeCanvas.made[0]).toMatchObject({ width: 0, height: 0 });
    expect(await code(drawTiled(200, 100, 100, async () => Promise.reject(new Error("lost context"))))).toBe("failed");
    expect(FakeCanvas.made[1]).toMatchObject({ width: 0, height: 0 });
  });

  it("is refused before anything is allocated when it is past the limits", async () => {
    expect(await code(drawTiled(20_000, 10, 100, async () => bitmap(1, 1)))).toBe("too-large");
    expect(await code(drawTiled(10_000, 10_000, 4096, async () => bitmap(1, 1)))).toBe("too-large");
    expect(FakeCanvas.made).toHaveLength(0);
  });
});

describe("a picture encoded", () => {
  it("is a file of the type asked for", async () => {
    const png = await encodeBitmap(bitmap(4, 3));
    expect(png.type).toBe("image/png");
    expect((await encodeBitmap(bitmap(4, 3), { type: "jpeg", quality: 0.5 })).type).toBe("image/jpeg");
    // A canvas made for the encoding is released.
    expect(FakeCanvas.made.every((c) => c.width === 0)).toBe(true);
  });

  it("draws a JPEG on white, or on the ground asked for, never on transparency", async () => {
    await encodeBitmap(bitmap(4, 3), { type: "jpeg" });
    await encodeBitmap(bitmap(4, 3), { type: "jpeg", background: "#102030" });
    await encodeBitmap(bitmap(4, 3), { type: "jpeg", background: "transparent" });
    await encodeBitmap(bitmap(4, 3), { type: "png" });
    expect(FakeCanvas.made.map((c) => c.fills.length)).toEqual([1, 1, 1, 0]);
  });

  it("says so when the browser cannot encode a type, instead of handing back a PNG under its name", async () => {
    FakeCanvas.encodes = (t) => (t === "image/webp" ? "image/png" : t);
    expect(await code(encodeBitmap(bitmap(4, 3), { type: "webp" }))).toBe("unsupported");
  });

  it("says a picture from another origin, which taints the canvas, cannot be read back", async () => {
    vi.spyOn(FakeCanvas.prototype, "convertToBlob").mockRejectedValue(new DOMException("tainted", "SecurityError"));
    try {
      expect(await code(encodeBitmap(bitmap(4, 3)))).toBe("unsupported");
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("refuses a type and a quality that are none", async () => {
    expect(await code(encodeBitmap(bitmap(4, 3), { type: "gif" as never }))).toBe("invalid");
    for (const quality of [-0.1, 1.1, NaN]) expect(await code(encodeBitmap(bitmap(4, 3), { quality })), String(quality)).toBe("invalid");
  });
});

describe("the pictures of a plugin", () => {
  const raster = (over: Partial<Raster> = {}): Raster => ({ bitmap: bitmap(10, 5), width: 10, height: 5, page: 1, space: "page", ...over });

  it("are drawn for a page that exists only, and the plugin is asked nothing else", async () => {
    const draw = vi.fn(async () => raster());
    const { controller } = createPictures({ count: 3, space: "page", raster: draw });
    expect(controller.get()).toEqual({ count: 3, space: "page" });
    for (const page of [0, 4, 1.5, NaN]) expect(await code(controller.raster(page, { longEdge: 10 })), String(page)).toBe("invalid");
    expect(draw).not.toHaveBeenCalled();
    await controller.raster(3, { longEdge: 10 });
    expect(draw).toHaveBeenCalledWith(3, { longEdge: 10 });
  });

  it("are asked of the plugin with options that check, and refused before it otherwise", async () => {
    const draw = vi.fn(async () => raster());
    const { controller } = createPictures({ count: 1, space: "page", raster: draw });
    const signal = new AbortController().signal;
    await controller.raster(1, { longEdge: 10, extra: 1, signal } as never);
    expect(draw).toHaveBeenCalledWith(1, { longEdge: 10, signal });
    for (const bad of [{ longEdge: "10" }, { longEdge: 10, layout: "x".repeat(2000) }, { longEdge: 10, background: "url(x)" }, { longEdge: 10, region: { x: 0, y: 0, width: 0, height: 1 } }]) {
      expect(await code(controller.raster(1, bad as never)), JSON.stringify(bad)).toBe("invalid");
    }
    expect(draw).toHaveBeenCalledTimes(1);
  });

  it("follow a document replaced by another of more pages", async () => {
    const { controller, state } = createPictures({ count: 1, space: "page", raster: async () => raster() });
    expect(await code(controller.raster(2))).toBe("invalid");
    state.set({ count: 2, space: "page" });
    expect(await code(controller.raster(2))).toBe("none");
  });

  it("are not drawn when already aborted, and a picture that arrives after the abort is closed", async () => {
    const abort = new AbortController();
    abort.abort();
    const draw = vi.fn(async () => raster());
    const { controller } = createPictures({ count: 1, space: "page", raster: draw });
    expect(await code(controller.raster(1, { longEdge: 10, signal: abort.signal }))).toBe("aborted");
    expect(draw).not.toHaveBeenCalled();

    const late = new AbortController();
    const arrived = raster();
    const slow = createPictures({
      count: 1,
      space: "page",
      raster: async () => {
        late.abort();
        return arrived;
      },
    }).controller;
    expect(await code(slow.raster(1, { longEdge: 10, signal: late.signal }))).toBe("aborted");
    expect((arrived.bitmap as unknown as FakeBitmap).closed).toBe(true);
  });

  it("fail as RasterErrors, whatever the plugin threw", async () => {
    const throwing = (e: unknown) => createPictures({ count: 1, space: "page", raster: async () => Promise.reject(e) }).controller;
    expect(await code(throwing(new Error("boom")).raster(1))).toBe("failed");
    expect(await code(throwing("text").raster(1))).toBe("failed");
    expect(await code(throwing(new RasterError("too-large")).raster(1))).toBe("too-large");
    expect(await code(throwing(new DOMException("x", "AbortError")).raster(1))).toBe("aborted");
  });

  it("render a page by its longest edge, and give null where a raster is refused", async () => {
    const draw = vi.fn(async () => raster());
    const { controller } = createPictures({ count: 1, space: "page", raster: draw });
    const b = await controller.render(1, 300);
    expect(b).toBeTruthy();
    expect(draw).toHaveBeenCalledWith(1, { longEdge: 300 });
    expect(await controller.render(2, 300)).toBeNull();
  });

  it("encode a raster through toBlob, with its region and without the bitmap, and close the bitmap", async () => {
    const region = { x: 0, y: 0, width: 1, height: 1 };
    const drawn = raster({ region });
    const { controller } = createPictures({ count: 1, space: "page", raster: async () => drawn });
    const out = await controller.toBlob(1, { longEdge: 10, type: "webp", quality: 0.8 });
    expect(out.blob.type).toBe("image/webp");
    expect(out).toMatchObject({ width: 10, height: 5, page: 1, space: "page", region });
    expect("bitmap" in out).toBe(false);
    expect((drawn.bitmap as unknown as FakeBitmap).closed).toBe(true);
    // Refused before the plugin is asked.
    const draw = vi.fn(async () => raster());
    const again = createPictures({ count: 1, space: "page", raster: draw }).controller;
    expect(await code(again.toBlob(1, { longEdge: 10, type: "tiff" as never }))).toBe("invalid");
    expect(draw).not.toHaveBeenCalled();
  });

  it("do not let a host change the count: the store is read-only", () => {
    const { controller } = createPictures({ count: 1, space: "page", raster: async () => raster() });
    expect("set" in controller).toBe(false);
    expect("update" in controller).toBe(false);
  });
});
