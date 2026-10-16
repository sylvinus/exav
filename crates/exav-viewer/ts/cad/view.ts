/**
 * A DWG or DXF drawing: parsed and tessellated in a worker
 * (`exav_viewer_dwg.wasm`), drawn by the WebGL2 renderer.
 *
 * Pan with one finger or the mouse, pinch or wheel to zoom (a trackpad pinch
 * is ctrl+wheel, or Safari's gesture events), double-click to fit. A zoom scales the canvas as drawn and
 * draws sharp once it pauses (`./zoom-gesture.ts`), and `zoom` and `viewport`
 * follow it once per animation frame. Layer toggles never re-tessellate;
 * switching layout, or the ground between light and dark (indexed colours
 * resolve against it, as in AutoCAD), tessellates again from the parsed
 * document without reading the file again.
 *
 * `pictures` draws any layout again at a requested size and region
 * (`./export.ts`), and `viewport` is the region of the layout in the canvas,
 * both in drawing units (`./raster.ts`).
 */
import { RasterError, throwIfAborted } from "../core/pictures.js";
import { createPictures } from "../core/raster.js";
import { writable } from "../core/store.js";
import { isColor } from "../core/theme.js";
import type { GroundController, LayersController, LayoutsController, Raster, RasterOptions, Renderer as PluginRenderer, Viewport, Warning, ZoomController } from "../core/types.js";
import { createWorkerHost } from "../core/worker-host.js";
import { drawPicture, parseColor } from "./export.js";
import type { CadOptions } from "./plugin.js";
import {
  abortable,
  checkScale,
  currentFor,
  defaultRegion,
  exportView,
  layoutFor,
  lineweightFactors,
  linked,
  planExport,
  sameRect,
  serial,
  viewportRegion,
} from "./raster.js";
import { familiesFor, loadFamilies, setFontsUrl } from "./renderer/fonts.js";
import { Renderer } from "./renderer/renderer.js";
import { facesUsed } from "./renderer/text-layout.js";
import type { DrawingPreview, ParsedDrawing } from "./types.js";
import { cadWarnings } from "./warnings.js";
import { createZoomGesture, viewTransform } from "./zoom-gesture.js";
import type { CadAnswer, CadRequest } from "./cad.worker.js";

export const GROUNDS = { light: "#ffffff", dark: "#212830" } as const;

/** exav-render's `SCENE_BUDGET`. */
const DEFAULT_MAX_PRIMITIVES = 8_000_000;
/** 512 MiB: half the native reader's default, the module's memory being smaller. */
const DEFAULT_MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024;

/** WebGL2, which the renderer needs. */
export function isCadSupported(): boolean {
  try {
    return typeof document !== "undefined" && !!document.createElement("canvas").getContext("webgl2");
  } catch {
    return false;
  }
}

/**
 * A CSS colour as 0..1 RGB, through the canvas's own parser, so "#222",
 * "rgb(...)" and names work as they do in CSS. Null for what CSS rejects.
 */
function rgb(css: string): [number, number, number] | null {
  const c = document.createElement("canvas").getContext("2d");
  if (!c) return null;
  c.fillStyle = "#010203";
  c.fillStyle = css;
  const parsed = String(c.fillStyle);
  if (parsed === "#010203" && css.trim().toLowerCase() !== "#010203") return null;
  const hex = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(parsed);
  if (hex) return [parseInt(hex[1]!, 16) / 255, parseInt(hex[2]!, 16) / 255, parseInt(hex[3]!, 16) / 255];
  // Translucent colours come back as rgba(): the alpha is dropped.
  const fn = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)/i.exec(parsed);
  return fn ? [Number(fn[1]) / 255, Number(fn[2]) / 255, Number(fn[3]) / 255] : null;
}

/** Rec. 709 luma, the test the shader and the palette use. */
const isLight = (c: [number, number, number]) => 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2] > 0.5;

/** A layer colour, packed little-endian RGBA (`0xAABBGGRR`), as CSS. */
export function layerColor(packed: number): string {
  return `rgb(${packed & 0xff} ${(packed >>> 8) & 0xff} ${(packed >>> 16) & 0xff})`;
}

export const renderer: PluginRenderer<CadOptions> = {
  async mount(host, ctx) {
    ctx.status({ phase: "loading" });
    // A colour CSS rejects falls back to the default for that ground.
    const pick = (asked: string | undefined, fallback: string) => (asked && rgb(asked) ? asked : fallback);
    const colors = { light: pick(ctx.options.colors?.light, GROUNDS.light), dark: pick(ctx.options.colors?.dark, GROUNDS.dark) };
    if (ctx.options.fontsUrl !== undefined) setFontsUrl(ctx.options.fontsUrl);

    const root = document.createElement("div");
    root.className = "exav-viewer-cad";
    const canvas = document.createElement("canvas");
    canvas.className = "exav-viewer-cad-canvas";
    root.append(canvas);
    host.append(root);

    // A zoom gesture moves the canvas as drawn (`./zoom-gesture.ts`); a frame
    // drawn from the camera puts it back.
    canvas.style.transformOrigin = "0 0";
    const wire = (r: Renderer) => {
      r.onDraw = () => {
        if (canvas.style.transform) canvas.style.transform = "";
      };
    };
    let gl = new Renderer(canvas);
    wire(gl);
    gl.lineweights = ctx.options.lineweights ?? "drawing";
    gl.monochrome = ctx.options.monochrome ?? false;
    const engine = createWorkerHost<CadRequest, CadAnswer>(
      () => new Worker(new URL("./cad.worker.js", import.meta.url), { type: "module" }),
    );
    let ground: "light" | "dark" = ctx.options.ground ?? "light";
    const timeoutMs = ctx.options.timeoutMs ?? 120_000;
    const maxPrimitives = ctx.options.maxPrimitives ?? DEFAULT_MAX_PRIMITIVES;
    const maxDecompressedBytes = ctx.options.maxDecompressedBytes ?? DEFAULT_MAX_DECOMPRESSED_BYTES;
    let drawing: ParsedDrawing | null = null;
    let visible: boolean[] = [];
    let destroyed = false;
    let request = 0;
    // Until the user pans or zooms, a resize (the rails opening beside the
    // canvas, a window turned) fits the drawing again.
    let fitted = true;

    const groundStore = writable(ground);
    const layersStore = writable<{ kind: "layers" | "categories"; items: readonly { id: string; name: string; color: string; visible: boolean }[] }>({
      kind: "layers",
      items: [],
    });
    const layoutsStore = writable<{ items: readonly { id: string; name: string; isModel: boolean }[]; current: string }>({ items: [], current: "" });
    const zoomStore = writable({ scale: 1, min: 0, max: Infinity });
    const warnings = writable<readonly Warning[]>([]);
    // The part of the layout in the canvas, in drawing units (see `./raster.ts`).
    const viewportStore = writable<Viewport | null>(null);

    const applyGround = () => {
      const c = rgb(colors[ground]) ?? [1, 1, 1];
      gl.background = c;
      // The element painted its box from this before the first frame.
      root.style.background = colors[ground];
    };
    applyGround();

    const backgroundBytes = () => new Uint8Array(gl.background.map((v) => Math.round(Math.max(0, Math.min(1, v)) * 255)));

    const publishLayers = () => {
      if (!drawing) return;
      layersStore.set({
        kind: "layers",
        items: drawing.layers.map((l, i) => ({ id: l.name, name: l.name, color: layerColor(l.color), visible: visible[i] ?? false })),
      });
    };

    /** The camera scale that fits the drawing, without moving the camera. */
    const fitScale = () => {
      if (!drawing) return 1;
      const { cx, cy, scale } = gl.camera;
      gl.camera.fit(drawing.extents);
      const fitted = gl.camera.scale;
      Object.assign(gl.camera, { cx, cy, scale });
      return fitted;
    };
    /** The viewport follows the camera; a store is set only when the region moved. */
    const publishView = () => {
      const d = drawing;
      if (!d) return;
      const region = viewportRegion(gl.camera, d.origin);
      const now = viewportStore.get();
      const before = now && "width" in now.region ? now.region : null;
      if (now && now.layout === d.layout && before && sameRect(before, region)) return;
      const page = Math.max(1, d.layouts.findIndex((l) => (l.isModel ? "" : l.name) === d.layout) + 1);
      viewportStore.set({ space: "drawing", page, layout: d.layout, region });
    };
    const publishZoom = () => {
      const fit = fitScale();
      const { scale, minScale, maxScale } = gl.camera;
      zoomStore.set({ scale: fit / scale, min: fit / maxScale, max: minScale > 0 ? fit / minScale : Infinity });
      publishView();
    };

    // The drawing's thumbnail while it parses, when it has one.
    let placeholder: HTMLImageElement | null = null;
    const dropPreview = () => {
      if (!placeholder) return;
      URL.revokeObjectURL(placeholder.src);
      placeholder.remove();
      placeholder = null;
    };
    const showPreview = async (p: DrawingPreview) => {
      const img = document.createElement("img");
      img.className = "exav-viewer-cad-preview";
      img.alt = "";
      img.src = URL.createObjectURL(new Blob([p.data], { type: p.mime }));
      try {
        await img.decode();
      } catch {
        // Not an image this browser reads.
        URL.revokeObjectURL(img.src);
        return;
      }
      if (destroyed || drawing) return URL.revokeObjectURL(img.src);
      placeholder = img;
      root.append(img);
    };

    /** Shows what the worker answered, unless a newer request overtook it. */
    const show = async (answer: Promise<CadAnswer>, keepVisibility: boolean) => {
      const mine = ++request;
      const d = (await answer) as ParsedDrawing;
      if (mine !== request || destroyed) return;
      // Canvas falls back to a system font, silently, when asked to draw one
      // that is not loaded: wait for the faces the drawing names.
      await loadFamilies(familiesFor(facesUsed(d.texts)), (file, err) =>
        console.warn(`dwg: could not load ${file}; its text is drawn with another face`, err),
      );
      if (mine !== request || destroyed) return;
      const previous = drawing;
      drawing = d;
      visible =
        keepVisibility && previous && previous.layers.length === d.layers.length
          ? visible
          : d.layers.map((l) => !l.off && !l.frozen);
      // A new file or layout is framed; the same one drawn again on another
      // ground keeps the view.
      const reframe = !previous || previous.layout !== d.layout;
      if (reframe) fitted = true;
      gl.setDrawing(d, visible, reframe);
      gl.requestDraw();
      // A drawing with nothing this viewer draws (a 3D model) keeps the
      // thumbnail it was saved with.
      const blank = d.strokes.byteLength === 0 && d.fills.byteLength === 0 && d.texts.byteLength === 0;
      // The geometry is on the GPU now: the page keeps only what describes
      // it. A lost context asks the worker for it again (`onRestored`).
      d.strokes = d.fills = d.strokeTiles = d.fillTiles = new ArrayBuffer(0);
      const previewShown = blank && placeholder !== null;
      if (!previewShown) dropPreview();
      publishLayers();
      layoutsStore.set({
        items: d.layouts.map((l) => ({ id: l.isModel ? "" : l.name, name: l.name, isModel: l.isModel })),
        current: d.layout,
      });
      if (pictures.state.get().count !== d.layouts.length) pictures.state.set({ count: d.layouts.length, space: "drawing" });
      warnings.set(cadWarnings(d.warnings, previewShown));
      publishZoom();
      ctx.status({ phase: "ready" });
    };

    // ── input ──
    const dpr = () => Math.min(window.devicePixelRatio || 1, 2);
    // The root's box, which is the canvas's: the canvas's own moves with a zoom gesture.
    const toFb = (e: { clientX: number; clientY: number }): [number, number] => {
      const r = root.getBoundingClientRect();
      return [(e.clientX - r.left) * dpr(), (r.bottom - e.clientY) * dpr()];
    };
    const zoomGesture = createZoomGesture({
      settleMs: 100,
      staleMs: 500,
      frame() {
        const { drawn, camera } = gl;
        if (drawn.width !== camera.width || drawn.height !== camera.height) {
          // Nothing drawn at this size yet.
          gl.requestDraw();
        } else {
          const t = viewTransform(drawn, camera, dpr());
          canvas.style.transform = `translate(${t.x}px, ${t.y}px) scale(${t.k})`;
        }
        publishZoom();
      },
      draw: () => gl.requestDraw(),
    });
    /** A frame drawn from the camera is on its way: what a gesture had pending is over. */
    const settled = () => {
      zoomGesture.flush();
      zoomGesture.cancel();
    };
    const pointers = new Map<number, { x: number; y: number }>();
    let lastPinch = 0;
    const pinchDistance = () => {
      const [a, b] = [...pointers.values()];
      return a && b ? Math.hypot(a.x - b.x, a.y - b.y) : 0;
    };
    // Safari's trackpad pinch: gesture events, whose `scale` is the total since the start.
    let gestureScale = 0;
    const onGestureStart = (e: Event) => {
      e.preventDefault();
      gestureScale = 1;
    };
    const onGestureChange = (e: Event) => {
      e.preventDefault();
      const g = e as Event & { scale: number; clientX: number; clientY: number };
      if (!drawing || !gestureScale || !(g.scale > 0)) return;
      const [sx, sy] = toFb(g);
      gl.camera.zoomAt(sx, sy, g.scale / gestureScale);
      gestureScale = g.scale;
      fitted = false;
      zoomGesture.touch();
    };
    const onGestureEnd = (e: Event) => {
      e.preventDefault();
      gestureScale = 0;
    };
    const onWheel = (e: WheelEvent) => {
      if (!drawing) return;
      e.preventDefault();
      // Safari reports the same pinch as a ctrl+wheel too: the gesture is the one that counts.
      if (gestureScale && e.ctrlKey) return;
      const [sx, sy] = toFb(e);
      const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 100 : 1;
      gl.camera.zoomAt(sx, sy, Math.exp((-e.deltaY * unit) / 320));
      fitted = false;
      zoomGesture.touch();
    };
    const onDown = (e: PointerEvent) => {
      try {
        canvas.setPointerCapture(e.pointerId);
      } catch {
        // Already released.
      }
      const [x, y] = toFb(e);
      pointers.set(e.pointerId, { x, y });
      if (pointers.size === 2) lastPinch = pinchDistance();
    };
    const onUp = (e: PointerEvent) => {
      pointers.delete(e.pointerId);
      if (pointers.size < 2) lastPinch = 0;
    };
    const onMove = (e: PointerEvent) => {
      const prev = pointers.get(e.pointerId);
      if (!prev || !drawing) return;
      const [x, y] = toFb(e);
      if (pointers.size === 1) {
        gl.camera.panPixels(x - prev.x, y - prev.y);
        if (x !== prev.x || y !== prev.y) fitted = false;
        pointers.set(e.pointerId, { x, y });
        settled();
        gl.requestDraw();
        publishView();
        return;
      }
      pointers.set(e.pointerId, { x, y });
      if (pointers.size === 2) {
        const dist = pinchDistance();
        if (lastPinch > 0 && dist > 0) {
          const [a, b] = [...pointers.values()];
          gl.camera.zoomAt((a!.x + b!.x) / 2, (a!.y + b!.y) / 2, dist / lastPinch);
          fitted = false;
          zoomGesture.touch();
        }
        lastPinch = dist;
      }
    };
    const fit = () => {
      if (!drawing) return;
      zoomGesture.cancel();
      gl.resize();
      gl.camera.fit(drawing.extents);
      fitted = true;
      gl.requestDraw();
      publishZoom();
    };
    const onResize = () => {
      if (!gl.resize()) return;
      zoomGesture.cancel();
      if (drawing && fitted) gl.camera.fit(drawing.extents);
      gl.requestDraw();
      publishZoom();
    };
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointercancel", onUp);
    canvas.addEventListener("dblclick", fit);
    canvas.addEventListener("gesturestart", onGestureStart);
    canvas.addEventListener("gesturechange", onGestureChange);
    canvas.addEventListener("gestureend", onGestureEnd);
    const ro = new ResizeObserver(onResize);
    ro.observe(root);

    const destroy = () => {
      if (destroyed) return;
      destroyed = true;
      zoomGesture.cancel();
      ro.disconnect();
      engine.destroy();
      canvas.removeEventListener("webglcontextlost", onLost);
      canvas.removeEventListener("webglcontextrestored", onRestored);
      gl.dispose();
      // Give the context back now: a browser holds about sixteen, and a
      // folder of drawings walked with the arrows would exhaust them.
      canvas.getContext("webgl2")?.getExtension("WEBGL_lose_context")?.loseContext();
      canvas.width = 0;
      canvas.height = 0;
      dropPreview();
      root.remove();
    };

    const layers: LayersController = {
      ...layersStore,
      setVisible(id, v) {
        if (!drawing) return;
        const i = drawing.layers.findIndex((l) => l.name === id);
        if (i < 0 || visible[i] === v) return;
        visible = visible.map((x, j) => (j === i ? v : x));
        gl.setLayerVisibility(visible);
        publishLayers();
      },
      setAll(v) {
        if (!drawing) return;
        visible = drawing.layers.map(() => v);
        gl.setLayerVisibility(visible);
        publishLayers();
      },
    };
    const layouts: LayoutsController = {
      ...layoutsStore,
      async select(id) {
        if (!drawing || drawing.layout === id) return;
        ctx.status({ phase: "loading" });
        try {
          // Each layout has its own layers: visibility starts from the file's.
          await show(engine.call({ kind: "layout", layout: id, background: backgroundBytes(), maxPrimitives }, [], timeoutMs), false);
        } catch (error) {
          if (!destroyed) ctx.status({ phase: "error", error: { code: "drawing", cause: error } });
        }
      },
    };
    const groundController: GroundController = {
      ...groundStore,
      colors,
      set(next) {
        if (next === ground) return;
        const wasLight = isLight(gl.background);
        ground = next;
        groundStore.set(next);
        applyGround();
        if (drawing && wasLight !== isLight(gl.background)) {
          // Indexed colours resolve against the ground: tessellated again,
          // layers kept as they are.
          void show(engine.call({ kind: "layout", layout: drawing.layout, background: backgroundBytes(), maxPrimitives }, [], timeoutMs), true).catch(
            (error) => !destroyed && ctx.status({ phase: "error", error: { code: "drawing", cause: error } }),
          );
        } else gl.requestDraw();
      },
    };
    // A lost context (a GPU reset, too many contexts, a phone putting the
    // tab away) takes every buffer with it. When it comes back, the renderer
    // is made again with the view as it was, and the worker, which keeps the
    // document, tessellates the layout again.
    const onLost = (e: Event) => {
      e.preventDefault();
      // Now, while every GL call is a no-op: deleting the dead objects on
      // the restored context would leave an error for the next check.
      gl.dispose();
    };
    const onRestored = () => {
      if (destroyed) return;
      const { camera, background, lineweights, monochrome } = gl;
      gl = new Renderer(canvas);
      wire(gl);
      Object.assign(gl, { background, lineweights, monochrome });
      Object.assign(gl.camera, { cx: camera.cx, cy: camera.cy, scale: camera.scale });
      if (!drawing) return;
      void show(engine.call({ kind: "layout", layout: drawing.layout, background: backgroundBytes(), maxPrimitives }, [], timeoutMs), true).catch(
        (error) => !destroyed && ctx.status({ phase: "error", error: { code: "drawing", cause: error } }),
      );
    };
    canvas.addEventListener("webglcontextlost", onLost);
    canvas.addEventListener("webglcontextrestored", onRestored);

    const zoom: ZoomController = {
      ...zoomStore,
      setScale(scale, anchor) {
        if (!drawing) return;
        zoomGesture.cancel();
        const r = root.getBoundingClientRect();
        const a = anchor ?? { x: r.width / 2, y: r.height / 2 };
        gl.camera.zoomAt(a.x * dpr(), (r.height - a.y) * dpr(), scale / (fitScale() / gl.camera.scale));
        fitted = false;
        gl.requestDraw();
        publishZoom();
      },
      fit,
    };

    // ── pictures ──
    // A layout drawn again at the picture's size, in a context of its own
    // (`./export.ts`); `./raster.ts` has the semantics of regions and line
    // weights. One picture at a time.
    const queue = serial();
    const picture = async (page: number, options: RasterOptions, signal: AbortSignal): Promise<Raster> => {
      if (destroyed || !drawing) throw new RasterError("failed", "nothing is drawn");
      const { id, page: at } = layoutFor(layoutsStore.get().items, page, options);
      // The ground: the session's, or the picture's own.
      const sessionGround = gl.background;
      const hex = (bytes: Uint8Array) => `#${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
      const background = options.background ?? hex(backgroundBytes());
      const parsed = typeof background === "string" ? parseColor(background) : null;
      if (!parsed || !isColor(background)) throw new RasterError("invalid", "background is a colour or transparent");
      // What indexed colours are resolved against, and the ink chosen for: the
      // picture's ground, or the session's when the picture has none.
      const ground = parsed.alpha === 0 ? sessionGround : parsed.rgb;
      const bytes = new Uint8Array(ground.map((v) => Math.round(Math.max(0, Math.min(1, v)) * 255)));
      // A zoom gesture publishes once per frame: the camera is the truth.
      publishView();
      const current = currentFor(viewportStore.get(), id);
      const early = planExport(options, null, current, hex(backgroundBytes()));

      const answer = await abortable(engine.call({ kind: "layout", layout: id, background: bytes, maxPrimitives }, [], timeoutMs), signal);
      const d = answer as ParsedDrawing;
      throwIfAborted(signal);
      if (d.layout !== id) throw new RasterError("failed", "the layout could not be drawn");
      const plan = early ?? planExport(options, defaultRegion(d.extents, d.origin), current, hex(backgroundBytes()))!;
      const view = exportView(plan);
      checkScale(view.scale, d.extents);
      // The layers as the viewer shows them where it shows this layout, else as the file has them.
      const shown = drawing;
      const layerVisible = shown && shown.layout === id && visible.length === d.layers.length ? [...visible] : d.layers.map((l) => !l.off && !l.frozen);
      const bitmap = await drawPicture({
        drawing: d,
        visible: layerVisible,
        view,
        width: plan.width,
        height: plan.height,
        ground,
        alpha: parsed.alpha,
        lineweights: gl.lineweights,
        monochrome: gl.monochrome,
        dpr: dpr(),
        factors: lineweightFactors(options.lineweight, view.region, view.scale, gl.camera),
        tile: ctx.options.rasterTile,
        signal,
      });
      if (signal.aborted) {
        bitmap.close();
        throw new RasterError("aborted", "aborted");
      }
      return { bitmap, width: plan.width, height: plan.height, page: at, layout: id, space: "drawing", region: view.region };
    };
    const pictures = createPictures({
      count: 0,
      space: "drawing",
      async raster(page, options) {
        const { signal, dispose } = linked([options.signal, ctx.signal]);
        try {
          return await queue(signal, () => picture(page, options, signal));
        } finally {
          dispose();
        }
      },
    });
    const viewport = { get: viewportStore.get, subscribe: viewportStore.subscribe };

    // A session closed while the file is still being read or parsed: the
    // worker is stopped now, not when it would have finished.
    ctx.signal.addEventListener("abort", destroy, { once: true });
    try {
      const bytes = (await ctx.source.bytes()).slice();
      if (ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
      ctx.status({ phase: "loading", step: "read" });
      // The file goes to the worker once, which answers its thumbnail at
      // once; the thumbnail is up before the parse starts. Should the load
      // fail (a module that traps is replaced, the file with it), the parse
      // is given the file again.
      let again: ArrayBuffer | undefined;
      let unsupported: string | null = null;
      try {
        const loaded = (await engine.call({ kind: "load", bytes: bytes.buffer as ArrayBuffer }, [bytes.buffer as ArrayBuffer], timeoutMs)) as {
          preview: DrawingPreview | null;
          unsupported: string | null;
        };
        unsupported = loaded.unsupported;
        if (loaded.preview) await showPreview(loaded.preview);
      } catch (error) {
        if (destroyed) throw error;
        again = (await ctx.source.bytes()).slice().buffer as ArrayBuffer;
      }
      if (unsupported) {
        // A DWG release the engine does not read (R12 and older) is said
        // so, rather than as a file that would not parse.
        console.warn(`cad: DWG version ${unsupported} is not supported`);
        ctx.status({ phase: "error", error: { code: "drawing_version" } });
        return { controllers: {}, resize: onResize, destroy };
      }
      await show(
        engine.call(
          { kind: "parse", bytes: again, layout: "", background: backgroundBytes(), maxPrimitives, maxDecompressedBytes },
          again ? [again] : [],
          timeoutMs,
        ),
        false,
      );
    } catch (error) {
      destroy();
      throw error;
    }

    return {
      controllers: { layers, layouts, ground: groundController, zoom, warnings, pictures: pictures.controller, viewport },
      resize: onResize,
      destroy,
    };
  },
};
