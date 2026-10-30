/**
 * The pictures and the viewport of a 3D model (`@exav/viewer/ifc`, `/model`).
 *
 * A picture is drawn again from the model's geometry by a renderer of its
 * own, off screen, at the picture's size, in tiles when that is more than
 * the GPU holds; the viewer's canvas is never read. The renderer and
 * everything on it are freed when the picture is done, failed or stopped.
 *
 * Regions are cameras (`CameraRegion`) in the model's own coordinates, see
 * `ModelFrame`. `region: "current"` is the camera of the viewer now.
 */
import type * as THREE from "three";

import { asRasterError, fitCamera, isCamera, RasterError, rasterSize, throwIfAborted } from "../core/pictures.js";
import { createCanvas, createPictures, drawTiled, release } from "../core/raster.js";
import { writable } from "../core/store.js";
import { isColor } from "../core/theme.js";
import type { CameraRegion, PicturesController, Raster, RasterOptions, Viewport, ViewportController } from "../core/types.js";
import {
  cameraRegion,
  depthRange,
  groundCircle,
  modelUp,
  sameRegion,
  sceneCamera,
  supersampling,
  tileSize,
  viewOffset,
  type Ground,
  type GlLimits,
  type ModelFrame,
  type SceneCamera,
  type Vec3,
} from "./camera.js";

type Three = typeof THREE;
type Canvas = HTMLCanvasElement | OffscreenCanvas;

/** The viewport is published at most this often (ms) while the view moves, and once more when it stops. */
export const VIEWPORT_INTERVAL_MS = 100;

/** Shape of a picture when the viewer has no size yet. */
const FALLBACK_ASPECT = 4 / 3;

export interface ModelRasterConfig {
  three: Three;
  /** The scene as the viewer shows it: its objects (as they are now, hidden ones included) are what the pictures draw. */
  scene: THREE.Scene;
  /** The viewer's camera, and the point it orbits. */
  camera: THREE.PerspectiveCamera;
  controls: { target: THREE.Vector3 };
  /** The viewer's renderer: read for tone mapping, shadows and clipping, never drawn with. */
  renderer: THREE.WebGLRenderer;
  frame: ModelFrame;
  /** Bounds the model, in the scene. */
  sphere: { center: Vec3; radius: number };
  /** The background of a picture that asks for none: the viewer's ground. */
  ground(): Ground;
  /** Objects of the scene that are the viewer's own and not the model (a grid, a selection). */
  skip?(object: THREE.Object3D): boolean;
  /** The image-based light of the scene, made for the picture's renderer; freed with it. */
  environment?(renderer: THREE.WebGLRenderer): { texture: THREE.Texture; dispose(): void };
  /** Testing and tuning: a smaller tile than the GPU allows. */
  tile?: number;
  /** Testing and tuning: rendered pixels along a side for each picture pixel (default 1 with multisampling, else 2). */
  supersample?: number;
  /** For the viewport's throttle. */
  now?(): number;
}

export interface ModelRaster {
  pictures: PicturesController;
  viewport: ViewportController;
  /** Publishes the viewer's camera if it changed; the viewer's frame loop and resize call it. */
  sync(): void;
  /** Stops the pictures being drawn. */
  destroy(): void;
}

// ── One picture at a time ────────────────────────────────────────────────────

let tail: Promise<unknown> = Promise.resolve();

/**
 * Runs `task` after the ones before it, for all the sessions of the page:
 * one picture holds a GPU context and up to a tile of memory, and N
 * together would hold N times that. A `signal` that fires while it waits
 * (or while it runs) rejects at once with "aborted"; a value the task
 * still produces then goes to `discard`.
 */
export function inTurn<T>(signal: AbortSignal | undefined, task: () => Promise<T>, discard: (value: T) => void = () => {}): Promise<T> {
  throwIfAborted(signal);
  const run = tail.then(() => {
    throwIfAborted(signal);
    return task();
  });
  tail = run.then(
    () => {},
    () => {},
  );
  if (!signal) return run;
  return new Promise<T>((resolve, reject) => {
    let over = false;
    const stop = () => {
      if (over) return;
      over = true;
      reject(new RasterError("aborted", "aborted"));
    };
    signal.addEventListener("abort", stop, { once: true });
    run.then(
      (value) => {
        signal.removeEventListener("abort", stop);
        if (over) discard(value);
        else {
          over = true;
          resolve(value);
        }
      },
      (error) => {
        signal.removeEventListener("abort", stop);
        if (!over) {
          over = true;
          reject(error);
        }
      },
    );
  });
}

// ── The picture's renderer ───────────────────────────────────────────────────

/** A WebGL renderer on a canvas of its own: off screen where the browser has it, else a canvas that is never attached. */
function openRenderer(three: Three): { renderer: THREE.WebGLRenderer; canvas: Canvas } {
  const make = (canvas: Canvas) =>
    new three.WebGLRenderer({ canvas, antialias: true, alpha: true, premultipliedAlpha: true, preserveDrawingBuffer: false, stencil: false });
  if (typeof OffscreenCanvas === "function") {
    const canvas = new OffscreenCanvas(1, 1);
    try {
      return { renderer: make(canvas), canvas };
    } catch {
      release(canvas);
    }
  }
  const canvas = Object.assign(document.createElement("canvas"), { width: 1, height: 1 });
  try {
    return { renderer: make(canvas), canvas };
  } catch (error) {
    release(canvas);
    throw new RasterError("unsupported", "WebGL is not available", { cause: error });
  }
}

function limitsOf(gl: WebGLRenderingContext | WebGL2RenderingContext): GlLimits {
  const view = gl.getParameter(gl.MAX_VIEWPORT_DIMS) as ArrayLike<number>;
  return {
    texture: gl.getParameter(gl.MAX_TEXTURE_SIZE) as number,
    renderbuffer: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE) as number,
    viewport: [view[0] ?? 0, view[1] ?? 0],
  };
}

/** What the viewer's renderer is set to and the picture's must be too, so that it looks the same. */
function matchRenderer(from: THREE.WebGLRenderer, to: THREE.WebGLRenderer): void {
  // The size is explicit: the viewer's pixel ratio does not apply.
  to.setPixelRatio(1);
  to.setClearColor(0x000000, 0);
  to.outputColorSpace = from.outputColorSpace;
  to.toneMapping = from.toneMapping;
  to.toneMappingExposure = from.toneMappingExposure;
  to.sortObjects = from.sortObjects;
  to.localClippingEnabled = from.localClippingEnabled;
  to.clippingPlanes = from.clippingPlanes.map((p) => p.clone());
  to.shadowMap.enabled = from.shadowMap.enabled;
  to.shadowMap.type = from.shadowMap.type;
  // The shadow does not depend on the camera: made for the first tile, kept for the others.
  to.shadowMap.autoUpdate = false;
}

/** What `cloneScene` made and must free. */
interface Copy {
  scene: THREE.Scene;
  dispose(): void;
}

/**
 * The objects of `source` for another renderer: new objects, sharing the
 * vertex data (no copy) but not the geometry or material objects, which hold
 * a renderer's uploads and are freed with the copy. `skip`ped objects and
 * what is under them are left out; visibility, draw ranges and clipping are
 * kept as they are now.
 */
export function cloneScene(three: Three, source: THREE.Scene, skip?: (o: THREE.Object3D) => boolean): Copy {
  const geometries: THREE.BufferGeometry[] = [];
  const materials = new Map<THREE.Material, THREE.Material>();
  const shadows: THREE.LightShadow[] = [];
  const material = (m: THREE.Material) => {
    let c = materials.get(m);
    if (!c) {
      c = m.clone();
      c.onBeforeCompile = m.onBeforeCompile;
      materials.set(m, c);
    }
    return c;
  };
  const geometry = (g: THREE.BufferGeometry) => {
    const c = new three.BufferGeometry();
    for (const [name, attribute] of Object.entries(g.attributes)) c.setAttribute(name, attribute);
    if (g.index) c.setIndex(g.index);
    c.groups = g.groups.map((x) => ({ ...x }));
    c.drawRange = { ...g.drawRange };
    c.boundingSphere = g.boundingSphere?.clone() ?? null;
    c.boundingBox = g.boundingBox?.clone() ?? null;
    geometries.push(c);
    return c;
  };
  const copy = (o: THREE.Object3D): THREE.Object3D | null => {
    if (skip?.(o)) return null;
    const c = o.clone(false);
    const drawn = o as THREE.Mesh;
    if (drawn.isMesh || (o as THREE.Line).isLine || (o as THREE.Points).isPoints) {
      const into = c as THREE.Mesh;
      into.geometry = geometry(drawn.geometry);
      into.material = Array.isArray(drawn.material) ? drawn.material.map(material) : material(drawn.material);
    }
    const shadow = (c as { shadow?: THREE.LightShadow }).shadow;
    if (shadow) shadows.push(shadow);
    for (const child of o.children) {
      const k = copy(child);
      if (k) c.add(k);
    }
    return c;
  };
  const scene = new three.Scene();
  scene.environmentIntensity = source.environmentIntensity;
  scene.environmentRotation.copy(source.environmentRotation);
  for (const child of source.children) {
    const k = copy(child);
    if (k) scene.add(k);
  }
  return {
    scene,
    dispose() {
      for (const g of geometries) g.dispose();
      for (const m of materials.values()) m.dispose();
      for (const s of shadows) s.dispose();
    },
  };
}

/** The camera a picture is drawn with: the viewer's near and far planes for a perspective one. */
export function makeCamera(three: Three, c: SceneCamera, depth: { near: number; far: number }): THREE.PerspectiveCamera | THREE.OrthographicCamera {
  let camera: THREE.PerspectiveCamera | THREE.OrthographicCamera;
  if (c.projection.type === "perspective") camera = new three.PerspectiveCamera(c.projection.fov, c.aspect, depth.near, depth.far);
  else {
    const h = c.projection.height / 2;
    const w = h * c.aspect;
    camera = new three.OrthographicCamera(-w, w, h, -h, depth.near, depth.far);
  }
  camera.up.set(...c.up);
  camera.position.set(...c.position);
  camera.lookAt(...c.target);
  camera.updateMatrixWorld();
  camera.updateProjectionMatrix();
  return camera;
}

/** The ground of a tile of the picture, drawn on the tile's canvas. */
function paintGround(ctx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D, ground: Ground, picture: { width: number; height: number }, tile: { x: number; y: number; width: number; height: number }): void {
  if (ground.type === "none") return;
  if (ground.type === "solid") {
    ctx.fillStyle = ground.color;
  } else {
    const c = groundCircle(ground.at, picture.width, picture.height);
    const gradient = ctx.createRadialGradient(c.x - tile.x, c.y - tile.y, 0, c.x - tile.x, c.y - tile.y, c.radius);
    try {
      for (const s of ground.stops) gradient.addColorStop(s.offset, s.color);
    } catch {
      // A colour the browser does not take: the first one, flat.
      ctx.fillStyle = ground.stops[0]?.color ?? "#ffffff";
      ctx.fillRect(0, 0, tile.width, tile.height);
      return;
    }
    ctx.fillStyle = gradient;
  }
  ctx.fillRect(0, 0, tile.width, tile.height);
}

const yieldToLoop = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** What a request resolves to, before anything is allocated. */
interface Job {
  /** The camera as drawn, in the scene. */
  camera: SceneCamera;
  /** The same as a region, in the model's coordinates. */
  region: CameraRegion;
  width: number;
  height: number;
  /** A CSS colour or "transparent"; undefined for the viewer's ground. */
  background: string | undefined;
}

/**
 * Plans a request: the camera, the size, the ground. Throws `RasterError`
 * "invalid" or "too-large" and has touched nothing.
 */
export function planJob(
  options: RasterOptions,
  frame: ModelFrame,
  views: { current(): CameraRegion; whole(): CameraRegion },
): Job {
  let region: CameraRegion;
  if (options.region === undefined) region = views.whole();
  else if (options.region === "current") region = views.current();
  else if (isCamera(options.region)) region = options.region;
  else throw new RasterError("invalid", "a 3D model takes a camera for a region");
  if (options.fit !== undefined && options.fit !== "contain" && options.fit !== "cover") throw new RasterError("invalid", "fit is contain or cover");
  if (options.background !== undefined && !isColor(options.background)) throw new RasterError("invalid", "background is a colour or transparent");
  const { width, height } = rasterSize(options, region.aspect);
  // The picture's own shape, to the pixel: the camera is made for it.
  const used = fitCamera(region, width / height, options.fit);
  const camera = sceneCamera(frame, used);
  // The up it was drawn with is the model's own when none was given.
  return { camera, region: { ...used, up: used.up ?? modelUp(frame) }, width, height, background: options.background };
}

/** Draws the job. Everything made here is freed before it returns or throws. */
async function drawJob(c: ModelRasterConfig, job: Job, signal: AbortSignal | undefined): Promise<ImageBitmap> {
  const { three } = c;
  const { renderer, canvas } = openRenderer(three);
  let copy: Copy | null = null;
  let environment: { dispose(): void } | null = null;
  try {
    throwIfAborted(signal);
    const gl = renderer.getContext();
    const samples = supersampling(gl.getContextAttributes()?.antialias === true, c.supersample);
    const tile = tileSize(limitsOf(gl), samples, c.tile);
    matchRenderer(c.renderer, renderer);
    copy = cloneScene(three, c.scene, c.skip);
    if (c.environment) {
      const made = c.environment(renderer);
      environment = made;
      copy.scene.environment = made.texture;
    }
    const camera = makeCamera(three, job.camera, depthRange(job.camera, c.sphere, c.camera));
    const ground: Ground = job.background === undefined ? c.ground() : job.background === "transparent" ? { type: "none" } : { type: "solid", color: job.background };
    const picture = { width: job.width, height: job.height };
    let first = true;
    return await drawTiled(
      job.width,
      job.height,
      tile,
      async (t) => {
        // Between tiles, so that an abort is heard.
        await yieldToLoop();
        throwIfAborted(signal);
        const o = viewOffset(job.width, job.height, t, samples);
        renderer.setSize(o.width, o.height, false);
        if (gl.drawingBufferWidth !== o.width || gl.drawingBufferHeight !== o.height) throw new RasterError("too-large", `the GPU gave a ${gl.drawingBufferWidth} x ${gl.drawingBufferHeight} px buffer for ${o.width} x ${o.height}`);
        camera.setViewOffset(o.fullWidth, o.fullHeight, o.x, o.y, o.width, o.height);
        renderer.shadowMap.needsUpdate = first;
        first = false;
        renderer.render(copy!.scene, camera);
        if (gl.isContextLost()) throw new RasterError("failed", "the GPU context was lost");
        // Read in the same task as the render: the drawing buffer is not kept.
        const { canvas: out, ctx } = createCanvas(t.width, t.height);
        try {
          paintGround(ctx, ground, picture, t);
          ctx.imageSmoothingEnabled = true;
          ctx.imageSmoothingQuality = "high";
          ctx.drawImage(canvas, 0, 0, o.width, o.height, 0, 0, t.width, t.height);
        } catch (error) {
          release(out);
          throw error;
        }
        return out;
      },
      { signal },
    );
  } finally {
    // Each step on its own: the context must go whatever else fails.
    for (const free of [() => copy?.dispose(), () => environment?.dispose(), () => renderer.dispose(), () => renderer.forceContextLoss()]) {
      try {
        free();
      } catch {
        // Nothing more can be done for it.
      }
    }
    release(canvas);
  }
}

// ── The controllers ──────────────────────────────────────────────────────────

const toVec = (v: THREE.Vector3): Vec3 => [v.x, v.y, v.z];

export function createModelRaster(config: ModelRasterConfig): ModelRaster {
  const { camera, controls, frame } = config;
  const now = config.now ?? (() => performance.now());

  /** The viewer's camera, as a region. A zoomed camera is a narrower field of view. */
  const current = (): CameraRegion => {
    const fov = (2 * Math.atan(Math.tan((camera.fov * Math.PI) / 360) / (camera.zoom > 0 ? camera.zoom : 1)) * 180) / Math.PI;
    return cameraRegion(frame, {
      position: toVec(camera.position),
      target: toVec(controls.target),
      up: toVec(camera.up),
      projection: { type: "perspective", fov },
      aspect: camera.aspect > 0 ? camera.aspect : FALLBACK_ASPECT,
    });
  };
  // The view the viewer opens on, as it is when this is made.
  const initial = current();
  const whole = (): CameraRegion => ({ ...initial, aspect: current().aspect });

  const store = writable<Viewport | null>(null);
  let published: CameraRegion | null = null;
  let last = -Infinity;
  const sync = () => {
    const region = current();
    if (published && sameRegion(published, region)) return;
    const t = now();
    // The frame loop calls again: what is held back here is published then.
    if (published && t - last < VIEWPORT_INTERVAL_MS) return;
    published = region;
    last = t;
    store.set({ space: "camera", page: 1, region });
  };
  sync();

  const running = new Set<AbortController>();
  let destroyed = false;
  const { controller: pictures } = createPictures({
    count: 1,
    space: "camera",
    async raster(page, options): Promise<Raster> {
      if (destroyed) throw new RasterError("failed", "the viewer is closed");
      const job = planJob(options, frame, { current, whole });
      const stop = new AbortController();
      const onAbort = () => stop.abort();
      options.signal?.addEventListener("abort", onAbort, { once: true });
      running.add(stop);
      try {
        const bitmap = await inTurn(
          stop.signal,
          () => drawJob(config, job, stop.signal),
          (late) => late.close(),
        );
        return { bitmap, width: job.width, height: job.height, page, space: "camera", region: job.region };
      } catch (error) {
        throw asRasterError(error, stop.signal);
      } finally {
        options.signal?.removeEventListener("abort", onAbort);
        running.delete(stop);
      }
    },
  });

  return {
    pictures,
    viewport: { get: store.get, subscribe: store.subscribe },
    sync,
    destroy() {
      destroyed = true;
      for (const stop of running) stop.abort();
    },
  };
}
