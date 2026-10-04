/**
 * A DWG or DXF drawing: parsed and tessellated in a worker
 * (`exav_viewer_dwg.wasm`), drawn by the WebGL2 renderer.
 *
 * Pan with one finger or the mouse, pinch or wheel to zoom (a trackpad pinch
 * is ctrl+wheel), double-click to fit. Layer toggles never re-tessellate;
 * switching layout, or the ground between light and dark (indexed colours
 * resolve against it, as in AutoCAD), tessellates again from the parsed
 * document without reading the file again.
 */
import { writable } from "../core/store.js";
import type { GroundController, LayersController, LayoutsController, Renderer as PluginRenderer, ZoomController } from "../core/types.js";
import { createWorkerHost } from "../core/worker-host.js";
import type { CadOptions } from "./plugin.js";
import { familiesFor, loadFamilies, setFontsUrl } from "./renderer/fonts.js";
import { Renderer } from "./renderer/renderer.js";
import { facesUsed } from "./renderer/text-layout.js";
import type { DrawingPreview, ParsedDrawing } from "./types.js";
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
    root.className = "exv-cad";
    const canvas = document.createElement("canvas");
    canvas.className = "exv-cad-canvas";
    root.append(canvas);
    host.append(root);

    const gl = new Renderer(canvas);
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
    const warnings = writable<readonly { key: string; count: number }[]>([]);

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
    const publishZoom = () => zoomStore.set({ scale: fitScale() / gl.camera.scale, min: 0, max: Infinity });

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
      img.className = "exv-cad-preview";
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
      dropPreview();
      publishLayers();
      layoutsStore.set({
        items: d.layouts.map((l) => ({ id: l.isModel ? "" : l.name, name: l.name, isModel: l.isModel })),
        current: d.layout,
      });
      warnings.set([
        ...(d.warnings.externalReferences > 0 ? [{ key: "external_references", count: d.warnings.externalReferences }] : []),
        ...(d.warnings.sceneTruncated > 0 ? [{ key: "scene_truncated", count: d.warnings.sceneTruncated }] : []),
        ...(d.warnings.proxyWithoutGraphics > 0 ? [{ key: "proxy_without_graphics", count: d.warnings.proxyWithoutGraphics }] : []),
      ]);
      publishZoom();
      ctx.status({ phase: "ready" });
    };

    // ── input ──
    const dpr = () => Math.min(window.devicePixelRatio || 1, 2);
    const toFb = (e: { clientX: number; clientY: number }): [number, number] => {
      const r = canvas.getBoundingClientRect();
      return [(e.clientX - r.left) * dpr(), (r.bottom - e.clientY) * dpr()];
    };
    const pointers = new Map<number, { x: number; y: number }>();
    let lastPinch = 0;
    const pinchDistance = () => {
      const [a, b] = [...pointers.values()];
      return a && b ? Math.hypot(a.x - b.x, a.y - b.y) : 0;
    };
    const onWheel = (e: WheelEvent) => {
      if (!drawing) return;
      e.preventDefault();
      const [sx, sy] = toFb(e);
      const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 100 : 1;
      gl.camera.zoomAt(sx, sy, Math.exp((-e.deltaY * unit) / 320));
      fitted = false;
      gl.requestDraw();
      publishZoom();
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
        gl.requestDraw();
        return;
      }
      pointers.set(e.pointerId, { x, y });
      if (pointers.size === 2) {
        const dist = pinchDistance();
        if (lastPinch > 0 && dist > 0) {
          const [a, b] = [...pointers.values()];
          gl.camera.zoomAt((a!.x + b!.x) / 2, (a!.y + b!.y) / 2, dist / lastPinch);
          fitted = false;
          gl.requestDraw();
          publishZoom();
        }
        lastPinch = dist;
      }
    };
    const fit = () => {
      if (!drawing) return;
      gl.resize();
      gl.camera.fit(drawing.extents);
      fitted = true;
      gl.requestDraw();
      publishZoom();
    };
    const onResize = () => {
      if (!gl.resize()) return;
      if (drawing && fitted) gl.camera.fit(drawing.extents);
      gl.requestDraw();
      publishZoom();
    };
    // Safari's trackpad pinch would otherwise zoom the page.
    const cancel = (e: Event) => e.preventDefault();
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointercancel", onUp);
    canvas.addEventListener("dblclick", fit);
    canvas.addEventListener("gesturestart", cancel);
    canvas.addEventListener("gesturechange", cancel);
    const ro = new ResizeObserver(onResize);
    ro.observe(root);

    const destroy = () => {
      if (destroyed) return;
      destroyed = true;
      ro.disconnect();
      engine.destroy();
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
    const zoom: ZoomController = {
      ...zoomStore,
      setScale(scale, anchor) {
        if (!drawing) return;
        const r = canvas.getBoundingClientRect();
        const a = anchor ?? { x: r.width / 2, y: r.height / 2 };
        gl.camera.zoomAt(a.x * dpr(), (r.height - a.y) * dpr(), scale / (fitScale() / gl.camera.scale));
        fitted = false;
        gl.requestDraw();
        publishZoom();
      },
      fit,
    };

    // A session closed while the file is still being read or parsed: the
    // worker is stopped now, not when it would have finished.
    ctx.signal.addEventListener("abort", destroy, { once: true });
    try {
      const bytes = (await ctx.source.bytes()).slice();
      if (ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
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
      controllers: { layers, layouts, ground: groundController, zoom, warnings },
      resize: onResize,
      destroy,
    };
  },
};
