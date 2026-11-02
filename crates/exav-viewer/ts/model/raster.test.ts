import * as THREE from "three";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RasterError, tilePlan } from "../core/pictures.js";
import type { CameraRegion, RasterOptions } from "../core/types.js";
import { sceneCamera, viewOffset, type ModelFrame, type Vec3 } from "./camera.js";
import { cloneScene, createModelRaster, inTurn, makeCamera, planJob, VIEWPORT_INTERVAL_MS, type ModelRasterConfig } from "./raster.js";

const code = async (p: unknown) => {
  try {
    await (typeof p === "function" ? p() : p);
    return "none";
  } catch (e) {
    return e instanceof RasterError ? e.code : `other: ${String(e)}`;
  }
};

const zUp: ModelFrame = { zUp: true, origin: [100, 200, 0], offset: [1, 2, 3] };
const view: CameraRegion = { position: [110, 190, 8], target: [100, 200, 0], projection: { type: "perspective", fov: 40 }, aspect: 2 };
const views = { current: () => ({ ...view, position: [120, 200, 0] as Vec3 }), whole: () => view };

describe("planning a picture", () => {
  it("takes the whole view by default, in the shape of its aspect, and the current one for 'current'", () => {
    const whole = planJob({ longEdge: 400 }, zUp, views);
    expect([whole.width, whole.height]).toEqual([400, 200]);
    expect(whole.region.position).toEqual(view.position);
    expect(whole.background).toBeUndefined();
    const current = planJob({ longEdge: 400, region: "current" }, zUp, views);
    expect(current.region.position).toEqual([120, 200, 0]);
  });

  it("reports the up it drew with: the model's own when the region gave none", () => {
    expect(planJob({ longEdge: 100 }, zUp, views).region.up).toEqual([0, 0, 1]);
    expect(planJob({ longEdge: 100 }, { ...zUp, zUp: false }, views).region.up).toEqual([0, 1, 0]);
    expect(planJob({ longEdge: 100, region: { ...view, up: [0, 1, 0] } }, zUp, views).region.up).toEqual([0, 1, 0]);
  });

  it("keeps the region the caller gave, and reports the camera drawn with the picture's own aspect", () => {
    const given: CameraRegion = { ...view, position: [130, 200, 0], aspect: 3 };
    const job = planJob({ longEdge: 300, region: given }, zUp, views);
    expect([job.width, job.height]).toEqual([300, 100]);
    expect(job.region.position).toEqual([130, 200, 0]);
    expect(job.region.aspect).toBeCloseTo(3, 9);
    expect(job.camera.position[0]).toBeCloseTo(130 - 100 + 1, 9);
  });

  it("widens the view of a taller picture to contain it, and narrows it to cover", () => {
    const contain = planJob({ width: 100, height: 100, fit: "contain" }, zUp, views);
    const cover = planJob({ width: 100, height: 100, fit: "cover" }, zUp, views);
    expect(contain.region.aspect).toBe(1);
    expect(cover.region.aspect).toBe(1);
    // Aspect 2 -> 1: containing keeps the width (a wider field vertically), covering keeps the height.
    const half = (r: CameraRegion) => Math.tan(((r.projection as { fov: number }).fov * Math.PI) / 360);
    expect(half(contain.region)).toBeCloseTo(Math.tan((40 * Math.PI) / 360) * 2, 9);
    expect(half(cover.region)).toBeCloseTo(Math.tan((40 * Math.PI) / 360), 9);
  });

  it("scales an orthographic height with the same rule", () => {
    const ortho: CameraRegion = { ...view, projection: { type: "orthographic", height: 10 } };
    const contain = planJob({ width: 100, height: 100, region: ortho }, zUp, views);
    expect(contain.region.projection).toEqual({ type: "orthographic", height: 20 });
    expect(planJob({ width: 100, height: 100, region: ortho, fit: "cover" }, zUp, views).region.projection).toEqual({ type: "orthographic", height: 10 });
  });

  it("refuses what is not a request, before anything is made", async () => {
    const bad = (o: RasterOptions) => code(() => planJob(o, zUp, views));
    expect(await bad({})).toBe("invalid");
    expect(await bad({ longEdge: 100, region: { x: 0, y: 0, width: 1, height: 1 } })).toBe("invalid");
    expect(await bad({ longEdge: 100, region: { ...view, aspect: -1 } })).toBe("invalid");
    expect(await bad({ longEdge: 100, region: { ...view, projection: { type: "perspective", fov: 180 } } })).toBe("invalid");
    expect(await bad({ longEdge: 100, region: { ...view, target: view.position } })).toBe("invalid");
    expect(await bad({ longEdge: 100, fit: "stretch" as never })).toBe("invalid");
    expect(await bad({ longEdge: 100, background: "url(http://x/a.png)" })).toBe("invalid");
    expect(await bad({ width: 100000, height: 100 })).toBe("too-large");
    expect(await bad({ longEdge: 100, width: 10 })).toBe("invalid");
    expect(await bad({ longEdge: 100, background: "transparent" })).toBe("none");
    expect(await bad({ longEdge: 100, background: "rgba(10, 20, 30, 0.5)" })).toBe("none");
  });

  it("holds a longEdge to the pixel budget", () => {
    const job = planJob({ longEdge: 1e9, region: { ...view, aspect: 1 } }, zUp, views);
    expect(job.width).toBeLessThanOrEqual(16384);
    expect(job.width * job.height).toBeLessThanOrEqual(64 * 1024 * 1024);
  });
});

describe("tiles of a picture", () => {
  // A world point to its pixel in a picture drawn with `samples` per pixel.
  const pixel = (cam: THREE.Camera, p: THREE.Vector3, w: number, h: number) => {
    const n = p.clone().project(cam);
    return [((n.x + 1) / 2) * w, ((1 - n.y) / 2) * h] as const;
  };
  const points = [new THREE.Vector3(0, 0, 0), new THREE.Vector3(0.7, 0.4, -0.5), new THREE.Vector3(-1, 0.8, 0.3), new THREE.Vector3(0.1, -0.9, 0.2)];
  const regions: CameraRegion[] = [
    { position: [4, 3, 5], target: [0, 0, 0], up: [0, 1, 0], projection: { type: "perspective", fov: 50 }, aspect: 1.5 },
    { position: [4, 3, 5], target: [0, 0, 0], up: [0, 1, 0], projection: { type: "orthographic", height: 4 }, aspect: 1.5 },
  ];
  const yUp: ModelFrame = { zUp: false, origin: [0, 0, 0], offset: [0, 0, 0] };

  for (const region of regions) {
    for (const samples of [1, 2]) {
      it(`a tile's pixels are the picture's, shifted by the tile (${region.projection.type}, ${samples} per pixel)`, () => {
        const W = 150;
        const H = 100;
        const cam = sceneCamera(yUp, region);
        const depth = { near: 0.1, far: 50 };
        const full = makeCamera(THREE, cam, depth);
        full.setViewOffset(W * samples, H * samples, 0, 0, W * samples, H * samples);
        const tiles = tilePlan(W, H, 64);
        expect(tiles.length).toBe(6);
        for (const t of tiles) {
          const o = viewOffset(W, H, t, samples);
          const tile = makeCamera(THREE, cam, depth);
          tile.setViewOffset(o.fullWidth, o.fullHeight, o.x, o.y, o.width, o.height);
          for (const p of points) {
            const [fu, fv] = pixel(full, p, W * samples, H * samples);
            const [tu, tv] = pixel(tile, p, o.width, o.height);
            expect(tu).toBeCloseTo(fu - t.x * samples, 6);
            expect(tv).toBeCloseTo(fv - t.y * samples, 6);
          }
        }
      });
    }
  }

  it("draws the camera where the region says: the target is in the middle", () => {
    const cam = sceneCamera(yUp, regions[0]!);
    const camera = makeCamera(THREE, cam, { near: 0.1, far: 50 });
    const n = new THREE.Vector3(0, 0, 0).project(camera);
    expect(n.x).toBeCloseTo(0, 9);
    expect(n.y).toBeCloseTo(0, 9);
  });
});

describe("a copy of the scene for another renderer", () => {
  const build = () => {
    const scene = new THREE.Scene();
    scene.background = new THREE.Color("#ff0000");
    scene.environment = new THREE.Texture();
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.BufferAttribute(new Float32Array(9), 3));
    geometry.setIndex(new THREE.BufferAttribute(new Uint32Array([0, 1, 2]), 1));
    geometry.drawRange = { start: 0, count: 3 };
    const material = new THREE.MeshLambertMaterial({ color: 0x336699 });
    const world = new THREE.Group();
    world.rotation.x = -Math.PI / 2;
    const a = new THREE.Mesh(geometry, material);
    const b = new THREE.Mesh(geometry, material);
    b.visible = false;
    const grid = new THREE.GridHelper(2, 2);
    world.add(a, b);
    scene.add(world, grid, new THREE.DirectionalLight(0xffffff, 1));
    return { scene, geometry, material, world, a, b, grid };
  };

  it("shares the vertex data but not the geometry or material objects, and keeps what is hidden hidden", () => {
    const { scene, geometry, material, a, grid } = build();
    const copy = cloneScene(THREE, scene, (o) => o === grid);
    const world = copy.scene.children[0]!;
    expect(world.rotation.x).toBeCloseTo(-Math.PI / 2, 9);
    const [ca, cb] = world.children as THREE.Mesh[];
    expect(ca!.geometry).not.toBe(geometry);
    expect(ca!.geometry.attributes.position).toBe(geometry.attributes.position);
    expect(ca!.geometry.index).toBe(geometry.index);
    expect(ca!.geometry.drawRange).toEqual({ start: 0, count: 3 });
    expect(ca!.material).not.toBe(material);
    expect((ca!.material as THREE.MeshLambertMaterial).color.getHex()).toBe(0x336699);
    // One material copy for the two meshes that shared one.
    expect(ca!.material).toBe(cb!.material);
    expect(ca!.visible).toBe(true);
    expect(cb!.visible).toBe(false);
    expect(a.visible).toBe(true);
    // The viewer's helper is left out; the lamp is kept; neither ground nor environment comes along.
    expect(copy.scene.children.some((c) => c.type === "GridHelper")).toBe(false);
    expect(copy.scene.children.some((c) => (c as THREE.Light).isLight)).toBe(true);
    expect(copy.scene.background).toBeNull();
    expect(copy.scene.environment).toBeNull();
  });

  it("frees only its own geometry and materials", () => {
    const { scene, geometry, material } = build();
    const freed = { geometry: 0, material: 0 };
    geometry.addEventListener("dispose", () => freed.geometry++);
    material.addEventListener("dispose", () => freed.material++);
    const copy = cloneScene(THREE, scene);
    const [ca] = copy.scene.children[0]!.children as THREE.Mesh[];
    const own = { geometry: 0, material: 0 };
    ca!.geometry.addEventListener("dispose", () => own.geometry++);
    (ca!.material as THREE.Material).addEventListener("dispose", () => own.material++);
    copy.dispose();
    expect(own).toEqual({ geometry: 1, material: 1 });
    expect(freed).toEqual({ geometry: 0, material: 0 });
  });
});

describe("one picture at a time", () => {
  const gate = () => {
    let open!: () => void;
    const opened = new Promise<void>((r) => (open = r));
    return { opened, open };
  };

  it("runs tasks in order, one at a time", async () => {
    const log: string[] = [];
    const g = gate();
    const first = inTurn(undefined, async () => {
      log.push("a start");
      await g.opened;
      log.push("a end");
      return 1;
    });
    const second = inTurn(undefined, async () => {
      log.push("b start");
      return 2;
    });
    await Promise.resolve();
    await new Promise((r) => setTimeout(r, 5));
    expect(log).toEqual(["a start"]);
    g.open();
    expect(await Promise.all([first, second])).toEqual([1, 2]);
    expect(log).toEqual(["a start", "a end", "b start"]);
  });

  it("rejects an aborted wait at once, without running the task", async () => {
    const g = gate();
    const first = inTurn(undefined, () => g.opened);
    const stop = new AbortController();
    let ran = false;
    const second = inTurn(stop.signal, async () => {
      ran = true;
    });
    stop.abort();
    expect(await code(second)).toBe("aborted");
    g.open();
    await first;
    await new Promise((r) => setTimeout(r, 5));
    expect(ran).toBe(false);
  });

  it("hands a value produced after the abort to discard", async () => {
    const g = gate();
    const stop = new AbortController();
    const discarded: number[] = [];
    const run = inTurn(
      stop.signal,
      async () => {
        await g.opened;
        return 7;
      },
      (v) => discarded.push(v),
    );
    await new Promise((r) => setTimeout(r, 5));
    stop.abort();
    expect(await code(run)).toBe("aborted");
    g.open();
    await new Promise((r) => setTimeout(r, 5));
    expect(discarded).toEqual([7]);
  });

  it("goes on after a task failed", async () => {
    expect(await code(inTurn(undefined, () => Promise.reject(new RasterError("failed"))))).toBe("failed");
    expect(await inTurn(undefined, async () => 3)).toBe(3);
  });
});

// ── With a fake GPU ──────────────────────────────────────────────────────────

class FakeCanvas {
  static made: FakeCanvas[] = [];
  constructor(
    public width: number,
    public height: number,
  ) {
    FakeCanvas.made.push(this);
  }
  getContext() {
    return {
      drawImage() {},
      fillRect() {},
      createRadialGradient: () => ({ addColorStop() {} }),
      set fillStyle(_: unknown) {},
      set imageSmoothingEnabled(_: unknown) {},
      set imageSmoothingQuality(_: unknown) {},
    };
  }
  transferToImageBitmap() {
    return new FakeBitmap(this.width, this.height);
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

interface Gpu {
  renderers: FakeRenderer[];
  /** Throws on the n-th render (1-based). */
  failAt?: number;
  /** The drawing buffer is this much smaller than asked. */
  shrink: number;
  multisampled: boolean;
  max: number;
  /** Runs at each render. */
  onRender?: (r: FakeRenderer) => void;
  fail: boolean;
}
let gpu: Gpu;

class FakeRenderer {
  disposed = 0;
  lost = 0;
  rendered: { width: number; height: number; matrix: number[]; scene: THREE.Scene }[] = [];
  size = { width: 1, height: 1 };
  shadowMap = { enabled: false, type: 0, autoUpdate: true, needsUpdate: false };
  clippingPlanes: THREE.Plane[] = [];
  localClippingEnabled = false;
  toneMapping = 0;
  toneMappingExposure = 1;
  outputColorSpace = "srgb";
  sortObjects = true;
  pixelRatio = 0;
  contextLost = false;
  constructor() {
    if (gpu.fail) throw new Error("Error creating WebGL context.");
    gpu.renderers.push(this);
  }
  setPixelRatio(v: number) {
    this.pixelRatio = v;
  }
  setClearColor() {}
  setSize(w: number, h: number) {
    this.size = { width: w, height: h };
  }
  getContext() {
    const self = this;
    return {
      MAX_TEXTURE_SIZE: 1,
      MAX_RENDERBUFFER_SIZE: 2,
      MAX_VIEWPORT_DIMS: 3,
      getParameter: (p: number) => (p === 3 ? [gpu.max, gpu.max] : gpu.max),
      getContextAttributes: () => ({ antialias: gpu.multisampled }),
      get drawingBufferWidth() {
        return self.size.width - gpu.shrink;
      },
      get drawingBufferHeight() {
        return self.size.height - gpu.shrink;
      },
      isContextLost: () => this.contextLost,
    };
  }
  render(scene: THREE.Scene, camera: THREE.Camera) {
    this.rendered.push({ ...this.size, matrix: camera.projectionMatrix.toArray(), scene });
    gpu.onRender?.(this);
    if (gpu.failAt === this.rendered.length) throw new Error("render failed");
  }
  dispose() {
    this.disposed++;
  }
  forceContextLoss() {
    this.lost++;
    this.contextLost = true;
  }
}

const fakeThree = { ...THREE, WebGLRenderer: FakeRenderer } as unknown as typeof THREE;

function config(over: Partial<ModelRasterConfig> = {}): ModelRasterConfig {
  const scene = new THREE.Scene();
  const mesh = new THREE.Mesh(new THREE.BufferGeometry(), new THREE.MeshBasicMaterial());
  scene.add(mesh);
  const camera = new THREE.PerspectiveCamera(45, 2, 0.1, 100);
  camera.position.set(5, 4, 6);
  const controls = { target: new THREE.Vector3(0, 0, 0) };
  camera.lookAt(controls.target);
  return {
    three: fakeThree,
    scene,
    camera,
    controls,
    renderer: new FakeRenderer() as unknown as THREE.WebGLRenderer,
    frame: { zUp: false, origin: [0, 0, 0], offset: [0, 0, 0] },
    sphere: { center: [0, 0, 0], radius: 1 },
    ground: () => ({ type: "none" }),
    ...over,
  };
}

beforeEach(() => {
  FakeCanvas.made = [];
  gpu = { renderers: [], shrink: 0, multisampled: true, max: 4096, fail: false };
  vi.stubGlobal("OffscreenCanvas", FakeCanvas);
  vi.stubGlobal("ImageBitmap", FakeBitmap);
});
afterEach(() => vi.unstubAllGlobals());

/** The renderers a picture made, leaving out the stand-in for the viewer's own. */
const made = () => gpu.renderers.slice(1);

describe("drawing a picture", () => {
  it("renders every tile on one renderer at the tile's size, then frees all of it", async () => {
    const raster = createModelRaster(config({ tile: 64 }));
    const r = await raster.pictures.raster(1, { width: 150, height: 100 });
    expect(r).toMatchObject({ width: 150, height: 100, page: 1, space: "camera" });
    expect(r.bitmap).toBeInstanceOf(FakeBitmap);
    expect(made()).toHaveLength(1);
    const g = made()[0]!;
    expect(g.rendered.map((x) => [x.width, x.height])).toEqual([
      [64, 64],
      [64, 64],
      [22, 64],
      [64, 36],
      [64, 36],
      [22, 36],
    ]);
    expect(g.pixelRatio).toBe(1);
    expect([g.disposed, g.lost]).toEqual([1, 1]);
    // Its canvas is given back whole: 0 x 0.
    expect(FakeCanvas.made[0]!.width).toBe(0);
  });

  it("renders the elements of the viewer's scene as they are now, on a copy", async () => {
    const c = config();
    const raster = createModelRaster(c);
    c.scene.children[0]!.visible = false;
    await raster.pictures.raster(1, { longEdge: 100 });
    const copy = made()[0]!.rendered[0]!.scene;
    expect(copy).not.toBe(c.scene);
    expect(copy.children[0]!.visible).toBe(false);
  });

  it("uses one tile where the GPU holds the picture, and tiles where it does not", async () => {
    gpu.max = 100;
    const raster = createModelRaster(config());
    await raster.pictures.raster(1, { width: 250, height: 100 });
    expect(made()[0]!.rendered).toHaveLength(3);
    expect(Math.max(...made()[0]!.rendered.map((x) => x.width))).toBe(100);
  });

  it("draws each picture pixel from more where the context has no multisampling", async () => {
    gpu.multisampled = false;
    const raster = createModelRaster(config({ tile: 50 }));
    await raster.pictures.raster(1, { width: 100, height: 50 });
    // Tiles of 50 px, drawn at 100.
    expect(made()[0]!.rendered.map((x) => [x.width, x.height])).toEqual([
      [100, 100],
      [100, 100],
    ]);
  });

  it("frees the renderer when a render fails", async () => {
    gpu.failAt = 2;
    const raster = createModelRaster(config({ tile: 64 }));
    expect(await code(raster.pictures.raster(1, { width: 150, height: 100 }))).toBe("failed");
    expect([made()[0]!.disposed, made()[0]!.lost]).toEqual([1, 1]);
    expect(FakeCanvas.made.every((c) => c.width === 0)).toBe(true);
  });

  it("frees the renderer when the picture is stopped between tiles, and draws no more", async () => {
    const stop = new AbortController();
    gpu.onRender = (r) => {
      if (r.rendered.length === 2) stop.abort();
    };
    const raster = createModelRaster(config({ tile: 64 }));
    expect(await code(raster.pictures.raster(1, { width: 150, height: 100, signal: stop.signal }))).toBe("aborted");
    // Give the interrupted drawing time to unwind.
    await new Promise((r) => setTimeout(r, 30));
    expect(made()[0]!.rendered).toHaveLength(2);
    expect([made()[0]!.disposed, made()[0]!.lost]).toEqual([1, 1]);
  });

  it("does not make a renderer for a request that is refused or already stopped", async () => {
    const raster = createModelRaster(config());
    expect(await code(raster.pictures.raster(1, {}))).toBe("invalid");
    expect(await code(raster.pictures.raster(2, { longEdge: 10 }))).toBe("invalid");
    expect(await code(raster.pictures.raster(1, { longEdge: 10, signal: AbortSignal.abort() }))).toBe("aborted");
    expect(made()).toHaveLength(0);
  });

  it("says unsupported where there is no WebGL, and too-large where the GPU gives a smaller buffer", async () => {
    const raster = createModelRaster(config());
    gpu.fail = true;
    expect(await code(raster.pictures.raster(1, { longEdge: 10 }))).toBe("unsupported");
    gpu.fail = false;
    gpu.shrink = 1;
    expect(await code(raster.pictures.raster(1, { longEdge: 10 }))).toBe("too-large");
    expect([made()[0]!.disposed, made()[0]!.lost]).toEqual([1, 1]);
  });

  it("says failed when the context is lost while drawing", async () => {
    gpu.onRender = (r) => (r.contextLost = true);
    const raster = createModelRaster(config());
    expect(await code(raster.pictures.raster(1, { longEdge: 10 }))).toBe("failed");
    expect(made()[0]!.lost).toBeGreaterThanOrEqual(1);
  });

  it("makes one renderer at a time for pictures asked together", async () => {
    let live = 0;
    let most = 0;
    gpu.onRender = () => {
      live = made().filter((r) => r.lost === 0).length;
      most = Math.max(most, live);
    };
    const raster = createModelRaster(config());
    await Promise.all([1, 2, 3].map(() => raster.pictures.raster(1, { longEdge: 20 })));
    expect(made()).toHaveLength(3);
    expect(most).toBe(1);
  });

  it("stops what is drawing, and refuses more, once the viewer is closed", async () => {
    const raster = createModelRaster(config({ tile: 16 }));
    gpu.onRender = (r) => {
      if (r.rendered.length === 1) raster.destroy();
    };
    expect(await code(raster.pictures.raster(1, { width: 100, height: 100 }))).toBe("aborted");
    await new Promise((r) => setTimeout(r, 30));
    expect([made()[0]!.disposed, made()[0]!.lost]).toEqual([1, 1]);
    expect(await code(raster.pictures.raster(1, { longEdge: 10 }))).toBe("failed");
  });
});

describe("the viewport", () => {
  const setup = () => {
    let clock = 0;
    const c = config({ now: () => clock, frame: { zUp: true, origin: [10, 20, 30], offset: [0, 0, 0] } });
    const raster = createModelRaster(c);
    return { c, raster, tick: (ms: number) => (clock += ms) };
  };

  it("is the live camera in the model's coordinates, with an up and the canvas's aspect", () => {
    const { c, raster } = setup();
    const v = raster.viewport.get()!;
    expect(v).toMatchObject({ space: "camera", page: 1 });
    const region = v.region as CameraRegion;
    expect(region.aspect).toBe(2);
    expect(region.projection).toEqual({ type: "perspective", fov: expect.closeTo(45, 9) });
    expect(region.up).toEqual([expect.closeTo(0, 9), expect.closeTo(0, 9), expect.closeTo(1, 9)]);
    // Scene (5, 4, 6) is model (15, 14, 34): X as is, Y = -scene Z, Z = scene Y.
    expect(region.position[0]).toBeCloseTo(5 + 10, 9);
    expect(region.position[1]).toBeCloseTo(-6 + 20, 9);
    expect(region.position[2]).toBeCloseTo(4 + 30, 9);
    expect(c.camera.fov).toBe(45);
  });

  it("follows a zoomed camera as a narrower field of view", () => {
    const { c, raster, tick } = setup();
    c.camera.zoom = 2;
    tick(1000);
    raster.sync();
    const fov = ((raster.viewport.get()!.region as CameraRegion).projection as { fov: number }).fov;
    expect(Math.tan((fov * Math.PI) / 360)).toBeCloseTo(Math.tan((45 * Math.PI) / 360) / 2, 9);
  });

  it("is published when the view changes, at most every interval, and the last move still lands", () => {
    const { c, raster, tick } = setup();
    const seen: unknown[] = [];
    raster.viewport.subscribe((v) => seen.push(v));
    const start = seen.length;
    raster.sync();
    expect(seen.length).toBe(start);
    c.camera.position.x += 1;
    tick(10);
    raster.sync();
    expect(seen.length).toBe(start);
    tick(VIEWPORT_INTERVAL_MS);
    raster.sync();
    expect(seen.length).toBe(start + 1);
    c.camera.position.x += 1;
    tick(VIEWPORT_INTERVAL_MS + 1);
    raster.sync();
    raster.sync();
    expect(seen.length).toBe(start + 2);
    expect((raster.viewport.get()!.region as CameraRegion).position[0]).toBeCloseTo(7 + 10, 9);
  });

  it("can only be read by the host", () => {
    const { raster } = setup();
    expect(Object.keys(raster.viewport).sort()).toEqual(["get", "subscribe"]);
  });

  it("read back as region 'current' is the same view", async () => {
    const { c, raster, tick } = setup();
    c.camera.position.set(-3, 2, 9);
    c.camera.lookAt(c.controls.target);
    tick(1000);
    raster.sync();
    const shown = raster.viewport.get()!.region as CameraRegion;
    const viaCurrent = await raster.pictures.raster(1, { width: 40, height: 20, region: "current" });
    const viaViewport = await raster.pictures.raster(1, { width: 40, height: 20, region: shown });
    for (const r of [viaCurrent, viaViewport]) {
      const got = r.region as CameraRegion;
      expect(got.aspect).toBeCloseTo(2, 9);
      shown.position.forEach((v, i) => expect(got.position[i]).toBeCloseTo(v, 9));
      shown.target.forEach((v, i) => expect(got.target[i]).toBeCloseTo(v, 9));
      expect((got.projection as { fov: number }).fov).toBeCloseTo((shown.projection as { fov: number }).fov, 9);
    }
    // The same projection went to the GPU both times.
    expect(made()[0]!.rendered[0]!.matrix).toEqual(made()[1]!.rendered[0]!.matrix);
  });

  it("the default region is the view the viewer opened on, whatever it shows since", async () => {
    const { c, raster } = setup();
    const opened = (raster.viewport.get()!.region as CameraRegion).position;
    c.camera.position.set(50, 50, 50);
    const r = await raster.pictures.raster(1, { longEdge: 40 });
    expect((r.region as CameraRegion).position).toEqual(opened);
  });
});
