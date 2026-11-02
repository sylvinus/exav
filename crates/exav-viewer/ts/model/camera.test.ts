import { describe, expect, it } from "vitest";

import { RasterError } from "../core/pictures.js";
import type { CameraRegion } from "../core/types.js";
import {
  cameraRegion,
  depthRange,
  groundCircle,
  MAX_TILE,
  modelUp,
  parseGround,
  sameRegion,
  sceneCamera,
  supersampling,
  tileSize,
  toModelPoint,
  toModelVector,
  toScenePoint,
  toSceneVector,
  viewOffset,
  type ModelFrame,
  type Vec3,
} from "./camera.js";

const close = (a: readonly number[], b: readonly number[], digits = 9) => {
  expect(a).toHaveLength(b.length);
  a.forEach((v, i) => expect(v).toBeCloseTo(b[i]!, digits));
};
const code = (f: () => unknown) => {
  try {
    f();
    return "none";
  } catch (e) {
    return e instanceof RasterError ? e.code : `other: ${String(e)}`;
  }
};

const zUp: ModelFrame = { zUp: true, origin: [0, 0, 0], offset: [0, 0, 0] };
const yUp: ModelFrame = { zUp: false, origin: [0, 0, 0], offset: [0, 0, 0] };

describe("the model's coordinates against the scene's", () => {
  it("stands a Z-up model up: model Z is scene Y, model Y is scene -Z", () => {
    close(toScenePoint(zUp, [1, 2, 3]), [1, 3, -2]);
    close(toSceneVector(zUp, [0, 0, 1]), [0, 1, 0]);
    close(toSceneVector(zUp, [0, 1, 0]), [0, 0, -1]);
    close(modelUp(zUp), [0, 0, 1]);
  });

  it("leaves a Y-up model's axes alone", () => {
    close(toScenePoint(yUp, [1, 2, 3]), [1, 2, 3]);
    close(modelUp(yUp), [0, 1, 0]);
  });

  it("subtracts the engine's origin, then adds the viewer's offset, and undoes both", () => {
    const f: ModelFrame = { zUp: true, origin: [1000, 2000, 30], offset: [5, 6, 7] };
    close(toScenePoint(f, [1001, 2002, 33]), [1 + 5, 3 + 6, -2 + 7]);
    const p: Vec3 = [1234.5, 2345.25, 12.125];
    close(toModelPoint(f, toScenePoint(f, p)), p, 9);
    close(toModelVector(f, toSceneVector(f, [0.2, -0.3, 0.9])), [0.2, -0.3, 0.9]);
  });
});

describe("a region as a camera", () => {
  const region: CameraRegion = { position: [10, 0, 5], target: [0, 0, 0], projection: { type: "perspective", fov: 40 }, aspect: 1.5 };

  it("takes the model's up axis when the region names none, and always names it going back", () => {
    const c = sceneCamera(zUp, region);
    close(c.up, [0, 1, 0]);
    close(c.position, [10, 5, 0]);
    const back = cameraRegion(zUp, c);
    close(back.up!, [0, 0, 1]);
    close(back.position, region.position);
    close(back.target, region.target);
    expect(back.projection).toEqual(region.projection);
    expect(back.aspect).toBe(1.5);
    // Y up: the default is Y.
    close(sceneCamera(yUp, region).up, [0, 1, 0]);
    close(cameraRegion(yUp, sceneCamera(yUp, region)).up!, [0, 1, 0]);
  });

  it("keeps an up the region gives", () => {
    close(sceneCamera(zUp, { ...region, up: [0, 1, 0] }).up, [0, 0, -1]);
  });

  it("refuses a camera with no view", () => {
    expect(code(() => sceneCamera(zUp, { ...region, target: region.position }))).toBe("invalid");
    expect(code(() => sceneCamera(zUp, { ...region, position: [0, 0, 5], target: [0, 0, 0] }))).toBe("invalid");
    expect(code(() => sceneCamera(zUp, { ...region, up: [0, 0, 0] }))).toBe("invalid");
    expect(code(() => sceneCamera(zUp, { ...region, position: [0, 0, 5], target: [0, 0, 0], up: [0, 1, 0] }))).toBe("none");
  });
});

describe("two views being one", () => {
  const a: CameraRegion = { position: [10, 0, 5], target: [0, 0, 0], up: [0, 0, 1], projection: { type: "perspective", fov: 40 }, aspect: 1.5 };
  it("ignores what a settling orbit leaves, and sees any real move", () => {
    expect(sameRegion(a, { ...a, position: [10 + 1e-9, 0, 5] })).toBe(true);
    expect(sameRegion(a, { ...a, position: [10.01, 0, 5] })).toBe(false);
    expect(sameRegion(a, { ...a, target: [0, 0.01, 0] })).toBe(false);
    expect(sameRegion(a, { ...a, aspect: 1.6 })).toBe(false);
    expect(sameRegion(a, { ...a, projection: { type: "perspective", fov: 41 } })).toBe(false);
    expect(sameRegion(a, { ...a, projection: { type: "orthographic", height: 3 } })).toBe(false);
    expect(sameRegion(a, { ...a, up: [0, 1, 0] })).toBe(false);
  });
});

describe("near and far planes", () => {
  const sphere = { center: [0, 0, 0] as Vec3, radius: 1 };
  const viewer = { near: 0.01, far: 100 };
  const persp = (position: Vec3) => sceneCamera(yUp, { position, target: [0, 0, 0], projection: { type: "perspective", fov: 45 }, aspect: 1 });
  it("keeps the viewer's for a perspective camera near the model, goes further for a far one", () => {
    expect(depthRange(persp([0, 0, 5]), sphere, viewer)).toEqual({ near: 0.01, far: 100 });
    expect(depthRange(persp([0, 0, 500]), sphere, viewer)).toEqual({ near: 0.01, far: 502 });
  });
  it("takes the model's depth for an orthographic one, behind the camera if need be", () => {
    const o = sceneCamera(yUp, { position: [0, 0, 5], target: [0, 0, 0], projection: { type: "orthographic", height: 4 }, aspect: 1 });
    expect(depthRange(o, sphere, viewer)).toEqual({ near: 3, far: 7 });
    const inside = sceneCamera(yUp, { position: [0, 0, 0.5], target: [0, 0, -1], projection: { type: "orthographic", height: 4 }, aspect: 1 });
    expect(depthRange(inside, sphere, viewer).near).toBeLessThan(0);
  });
});

describe("tiles", () => {
  const limits = { texture: 8192, renderbuffer: 4096, viewport: [16384, 16384] as const };
  it("is the smallest limit, never past MAX_TILE, and less when each pixel takes samples", () => {
    expect(MAX_TILE).toBe(2048);
    expect(tileSize(limits, 1)).toBe(2048);
    expect(tileSize({ ...limits, renderbuffer: 1000 }, 1)).toBe(1000);
    expect(tileSize({ ...limits, viewport: [512, 16384] }, 1)).toBe(512);
    expect(tileSize({ ...limits, texture: 1000 }, 2)).toBe(500);
  });
  it("can be forced smaller and never larger", () => {
    expect(tileSize(limits, 1, 64)).toBe(64);
    expect(tileSize(limits, 1, 100000)).toBe(2048);
    expect(tileSize({ ...limits, renderbuffer: 300 }, 1, 1000)).toBe(300);
    expect(code(() => tileSize(limits, 1, 0))).toBe("invalid");
    expect(code(() => tileSize(limits, 1, 1.5))).toBe("invalid");
    expect(code(() => tileSize(limits, 0))).toBe("invalid");
    expect(code(() => tileSize({ texture: 0, renderbuffer: 4096, viewport: [4096, 4096] }, 1))).toBe("too-large");
  });
  it("supersamples where the context does not antialias", () => {
    expect(supersampling(true)).toBe(1);
    expect(supersampling(false)).toBe(2);
    expect(supersampling(true, 3)).toBe(3);
  });
  it("places a tile within the picture in rendered pixels", () => {
    expect(viewOffset(300, 200, { x: 128, y: 64, width: 100, height: 50 }, 2)).toEqual({ fullWidth: 600, fullHeight: 400, x: 256, y: 128, width: 200, height: 100 });
  });
});

describe("the ground", () => {
  const authored = "radial-gradient(circle at 50% 30%, #ffffff 0%, #e2e8f0 55%, #cbd5e1 100%)";
  const computed = "radial-gradient(circle at 50% 30%, rgb(255, 255, 255) 0%, rgb(226, 232, 240) 55%, rgb(203, 213, 225) 100%)";
  it("reads the viewer's gradient, as authored and as a browser computes it", () => {
    for (const [image, first] of [
      [authored, "#ffffff"],
      [computed, "rgb(255, 255, 255)"],
    ] as const) {
      expect(parseGround(image, "rgba(0, 0, 0, 0)")).toEqual({
        type: "radial",
        at: [0.5, 0.3],
        stops: [
          { offset: 0, color: first },
          { offset: 0.55, color: expect.any(String) },
          { offset: 1, color: expect.any(String) },
        ],
      });
    }
  });
  it("falls back to the middle colour for a gradient it does not read, and refuses a url", () => {
    expect(parseGround("radial-gradient(#ffffff 0%, #e2e8f0 55%, #cbd5e1 100%)", "")).toEqual({ type: "solid", color: "#e2e8f0" });
    expect(parseGround("url(http://x/y.png)", "")).toEqual({ type: "none" });
    expect(parseGround("none", "rgb(1, 2, 3)")).toEqual({ type: "solid", color: "rgb(1, 2, 3)" });
    expect(parseGround("none", "rgba(0, 0, 0, 0)")).toEqual({ type: "none" });
  });
  it("reaches the farthest corner", () => {
    const c = groundCircle([0.5, 0.3], 200, 100);
    expect([c.x, c.y]).toEqual([100, 30]);
    expect(c.radius).toBeCloseTo(Math.hypot(100, 70), 9);
  });
});
