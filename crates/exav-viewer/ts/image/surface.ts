/**
 * The image stage: a picture fitted to its container, panned and zoomed by
 * wheel, pinch and drag, with layers a host draws on in page coordinates.
 *
 * - Fit: inside the container (`min(cw / nw, ch / nh)`), centred; again on
 *   every resize of the container.
 * - Wheel (see `wheelAction`): `1 ± wheelStep` about the pointer, or with
 *   `wheel: "pan"` a move of the sheet. A ctrl+wheel is a trackpad pinch in
 *   Chrome and Firefox, and Safari's own gesture events are one too: both
 *   zoom continuously about the pointer.
 * - Two pointers pinch about their midpoint and pan with it, one update per
 *   animation frame. One pointer drags.
 * - A tap is the primary pointer, moved less than `tapSlop`, with no second
 *   pointer down meanwhile, released inside the page; reported in fractions.
 * - Past the raster's resolution, after `detailDelayMs` of stillness, the
 *   visible region is asked of the detail source and drawn over the picture.
 */
import { writable } from "../core/store.js";
import type { DetailSource, ImageSurface, Region, ViewState, ZoomController } from "../core/types.js";

export interface SurfaceOptions {
  minScale: number;
  maxScale: number;
  wheelStep: number;
  /** What a plain wheel does. Default "zoom". */
  wheel?: "zoom" | "pan";
  tapSlop: number;
  detailDelayMs: number;
  detailMargin: number;
  detailMaxPixels: number;
  detail?: DetailSource;
  onTap?: (point: { x: number; y: number }, event: PointerEvent, screen: { x: number; y: number }) => void;
}

/** Largest `deltaY` (px) one wheel event counts for when it zooms: a mouse notch is 100 or more. */
const MAX_ZOOM_DELTA = 30;

/**
 * What a wheel event does. With Ctrl or ⌘ (a trackpad pinch in Chrome and
 * Firefox sends Ctrl) it zooms by `exp(-delta / 100)`, the delta brought to
 * pixels and clamped to `MAX_ZOOM_DELTA`, so that one notch of a mouse is
 * about ×1.35 and not ×2.7; small pinch deltas pass unchanged. Without,
 * it zooms by `1 ± wheelStep`, or with `wheel: "pan"` moves the sheet by the
 * delta, as a document reader scrolls. `deltaMode` is lines (Firefox) or
 * pages. `pageHeight` is the container's.
 */
export function wheelAction(
  e: Pick<WheelEvent, "deltaX" | "deltaY" | "deltaMode" | "ctrlKey" | "metaKey">,
  wheel: "zoom" | "pan",
  wheelStep: number,
  pageHeight: number,
): { pan: { dx: number; dy: number } } | { zoom: number } {
  const modifier = e.ctrlKey || e.metaKey;
  if (wheel === "pan" && !modifier) {
    const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? pageHeight : 1;
    return { pan: { dx: e.deltaX * unit, dy: e.deltaY * unit } };
  }
  if (!modifier) return { zoom: 1 + (e.deltaY > 0 ? -1 : 1) * wheelStep };
  const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 400 : 1;
  const delta = Math.max(-MAX_ZOOM_DELTA, Math.min(MAX_ZOOM_DELTA, e.deltaY * unit));
  return { zoom: Math.exp(-delta / 100) };
}

export const SURFACE_DEFAULTS: Omit<SurfaceOptions, "detail" | "onTap"> = {
  minScale: 0.5,
  maxScale: 8,
  wheelStep: 0.08,
  tapSlop: 8,
  detailDelayMs: 150,
  detailMargin: 64,
  detailMaxPixels: 16_000_000,
};

export interface Surface extends ImageSurface {
  zoom: ZoomController;
  /** Another picture in place of this one; the view stays when the shape does. */
  replacePicture(picture: HTMLImageElement | HTMLCanvasElement, natural: { width: number; height: number }): void;
  resize(): void;
  destroy(): void;
}

let slots = 0;

/** `picture` is an `<img>` (loaded) or a canvas; `natural` its pixel size. */
export function createSurface(
  host: HTMLElement,
  picture: HTMLImageElement | HTMLCanvasElement,
  natural: { width: number; height: number },
  options: SurfaceOptions,
): Surface {
  const root = document.createElement("div");
  root.className = "exv-image";
  root.style.touchAction = "none";
  const stage = document.createElement("div");
  stage.className = "exv-image-stage";
  picture.classList.add("exv-image-picture");
  picture.draggable = false;
  const detailCanvas = document.createElement("canvas");
  detailCanvas.className = "exv-image-detail";
  detailCanvas.setAttribute("aria-hidden", "true");
  const pageLayer = document.createElement("div");
  pageLayer.className = "exv-image-page-layer";
  const screenLayer = document.createElement("div");
  screenLayer.className = "exv-image-screen-layer";
  stage.append(picture, detailCanvas, pageLayer);
  root.append(stage, screenLayer);
  host.append(root);

  const slot = `exv-image-${++slots}`;
  const view = writable<ViewState>({ page: { width: 0, height: 0 }, container: { width: 0, height: 0 }, scale: 1, x: 0, y: 0 });
  const zoomState = writable({ scale: 1, min: options.minScale, max: options.maxScale });
  let frame = 0;
  let pending: { scale: number; x: number; y: number } | null = null;
  let detailTimer: ReturnType<typeof setTimeout> | undefined;
  let detailAbort: AbortController | null = null;
  let destroyed = false;

  const apply = () => {
    const v = view.get();
    stage.style.width = `${v.page.width}px`;
    stage.style.height = `${v.page.height}px`;
    stage.style.transform = `translate(${v.x}px, ${v.y}px) scale(${v.scale})`;
    stage.style.setProperty("--exv-scale", String(v.scale));
    zoomState.set({ scale: v.scale, min: options.minScale, max: options.maxScale });
  };

  const setView = (next: Partial<ViewState>) => {
    view.set({ ...view.get(), ...next });
    apply();
    scheduleDetail();
  };

  const clamp = (s: number) => Math.min(options.maxScale, Math.max(options.minScale, s));

  /** Zoom to `scale` keeping the container point `(px, py)` still. */
  const zoomAbout = (scale: number, px: number, py: number) => {
    const v = view.get();
    const next = clamp(scale);
    const fx = (px - v.x) / v.scale;
    const fy = (py - v.y) / v.scale;
    setView({ scale: next, x: px - fx * next, y: py - fy * next });
  };

  const fit = () => {
    const cw = root.clientWidth;
    const ch = root.clientHeight;
    if (!cw || !ch || !natural.width || !natural.height) return;
    const base = Math.min(cw / natural.width, ch / natural.height);
    const page = { width: natural.width * base, height: natural.height * base };
    setView({ page, container: { width: cw, height: ch }, scale: 1, x: (cw - page.width) / 2, y: (ch - page.height) / 2 });
  };

  const local = (clientX: number, clientY: number) => {
    const r = root.getBoundingClientRect();
    return { x: clientX - r.left, y: clientY - r.top };
  };

  const toPage = (clientX: number, clientY: number) => {
    const v = view.get();
    const p = local(clientX, clientY);
    const fx = (p.x - v.x) / v.scale / (v.page.width || 1);
    const fy = (p.y - v.y) / v.scale / (v.page.height || 1);
    return fx >= 0 && fx <= 1 && fy >= 0 && fy <= 1 ? { x: fx, y: fy } : null;
  };

  const toScreen = (fx: number, fy: number) => {
    const v = view.get();
    return { x: v.x + fx * v.page.width * v.scale, y: v.y + fy * v.page.height * v.scale };
  };

  const pick = <T extends { x: number; y: number }>(markers: Iterable<T>, at: { x: number; y: number }, radius = 22): T | null => {
    let best: T | null = null;
    let nearest = Infinity;
    for (const m of markers) {
      const s = toScreen(m.x, m.y);
      const d = Math.hypot(s.x - at.x, s.y - at.y);
      if (d <= radius && d < nearest) {
        best = m;
        nearest = d;
      }
    }
    return best;
  };

  // ── detail ──
  const dropDetail = () => {
    detailAbort?.abort();
    detailAbort = null;
    detailCanvas.width = 0;
    detailCanvas.height = 0;
    detailCanvas.style.display = "";
  };

  const drawDetail = async () => {
    const source = options.detail;
    const v = view.get();
    if (!source || destroyed || !v.page.width) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const pageWidth = v.page.width * v.scale * dpr;
    if (pageWidth <= natural.width) {
      dropDetail();
      return;
    }
    const visible = (marginPx: number) => {
      const m = marginPx / v.scale;
      const x = Math.max(0, -v.x / v.scale - m);
      const y = Math.max(0, -v.y / v.scale - m);
      return {
        x,
        y,
        width: Math.min(v.page.width, (v.container.width - v.x) / v.scale + m) - x,
        height: Math.min(v.page.height, (v.container.height - v.y) / v.scale + m) - y,
      };
    };
    const pixels = (r: { width: number; height: number }) => r.width * r.height * (v.scale * dpr) ** 2;
    let area = visible(options.detailMargin);
    if (pixels(area) > options.detailMaxPixels) area = visible(0);
    if (area.width <= 0 || area.height <= 0 || pixels(area) > options.detailMaxPixels) return;
    const region: Region = {
      x: area.x / v.page.width,
      y: area.y / v.page.height,
      width: area.width / v.page.width,
      height: area.height / v.page.height,
    };
    detailAbort?.abort();
    const abort = new AbortController();
    detailAbort = abort;
    const drawn = await source({ pageWidth, region, slot, signal: abort.signal }).catch(() => null);
    if (!drawn) return;
    if (abort.signal.aborted || destroyed) {
      if (drawn instanceof ImageBitmap) drawn.close();
      return;
    }
    detailCanvas.width = drawn.width;
    detailCanvas.height = drawn.height;
    detailCanvas.getContext("2d")?.drawImage(drawn, 0, 0);
    if (drawn instanceof ImageBitmap) drawn.close();
    Object.assign(detailCanvas.style, {
      left: `${region.x * 100}%`,
      top: `${region.y * 100}%`,
      width: `${region.width * 100}%`,
      height: `${region.height * 100}%`,
      display: "block",
    });
  };

  function scheduleDetail() {
    if (!options.detail) return;
    clearTimeout(detailTimer);
    detailTimer = setTimeout(() => {
      if (pointers.size < 2) void drawDetail();
    }, options.detailDelayMs);
  }

  // ── input ──
  const pointers = new Map<number, { x: number; y: number }>();
  let pan: { x: number; y: number; vx: number; vy: number } | null = null;
  let pinch: { dist: number; scale: number; origin: { x: number; y: number } } | null = null;
  let tap: { id: number; x: number; y: number; cancelled: boolean } | null = null;

  const flush = () => {
    frame = 0;
    if (pending) setView(pending);
    pending = null;
  };
  const queue = (next: { scale: number; x: number; y: number }) => {
    pending = next;
    if (!frame) frame = requestAnimationFrame(flush);
  };

  const startPinch = () => {
    const [a, b] = [...pointers.values()];
    if (!a || !b) return;
    const v = view.get();
    const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    pinch = {
      dist: Math.max(1, Math.hypot(b.x - a.x, b.y - a.y)),
      scale: v.scale,
      origin: { x: (mid.x - v.x) / v.scale, y: (mid.y - v.y) / v.scale },
    };
    pan = null;
  };

  const onPointerDown = (e: PointerEvent) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    const p = local(e.clientX, e.clientY);
    pointers.set(e.pointerId, p);
    try {
      root.setPointerCapture(e.pointerId);
    } catch {
      // Already released.
    }
    if (pointers.size === 1) {
      const v = view.get();
      pan = { x: p.x, y: p.y, vx: v.x, vy: v.y };
      tap = e.isPrimary ? { id: e.pointerId, x: p.x, y: p.y, cancelled: false } : null;
    } else {
      if (tap) tap.cancelled = true;
      if (pointers.size === 2) startPinch();
    }
  };

  const onPointerMove = (e: PointerEvent) => {
    if (!pointers.has(e.pointerId)) return;
    const p = local(e.clientX, e.clientY);
    pointers.set(e.pointerId, p);
    if (tap && tap.id === e.pointerId && Math.hypot(p.x - tap.x, p.y - tap.y) > options.tapSlop) tap.cancelled = true;
    if (pinch && pointers.size >= 2) {
      const [a, b] = [...pointers.values()];
      if (!a || !b) return;
      const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      const scale = clamp(pinch.scale * (Math.hypot(b.x - a.x, b.y - a.y) / pinch.dist));
      queue({ scale, x: mid.x - pinch.origin.x * scale, y: mid.y - pinch.origin.y * scale });
    } else if (pan && pointers.size === 1) {
      queue({ scale: view.get().scale, x: pan.vx + p.x - pan.x, y: pan.vy + p.y - pan.y });
    }
  };

  const onPointerEnd = (e: PointerEvent) => {
    if (!pointers.has(e.pointerId)) return;
    pointers.delete(e.pointerId);
    if (tap && tap.id === e.pointerId) {
      const t = tap;
      tap = null;
      // A release outside the element (the pointer is captured) or a cancel
      // ends the tap like a release.
      if (!t.cancelled) {
        const at = toPage(e.clientX, e.clientY);
        if (at) options.onTap?.(at, e, local(e.clientX, e.clientY));
      }
    }
    if (pointers.size < 2) pinch = null;
    if (pointers.size === 1) {
      // Back to one finger: it pans from where it is.
      const [only] = [...pointers.values()];
      const v = pending ?? view.get();
      if (only) pan = { x: only.x, y: only.y, vx: v.x, vy: v.y };
    } else if (pointers.size === 0) {
      pan = null;
    }
  };

  const onWheel = (e: WheelEvent) => {
    e.preventDefault();
    const p = local(e.clientX, e.clientY);
    const v = view.get();
    const action = wheelAction(e, options.wheel ?? "zoom", options.wheelStep, v.container.height);
    if ("pan" in action) setView({ x: v.x - action.pan.dx, y: v.y - action.pan.dy });
    else zoomAbout(v.scale * action.zoom, p.x, p.y);
  };

  let gestureStart = 1;
  const onGestureStart = (e: Event) => {
    e.preventDefault();
    gestureStart = view.get().scale;
  };
  const onGestureChange = (e: Event) => {
    e.preventDefault();
    if (pointers.size >= 2) return;
    const g = e as Event & { scale: number; clientX: number; clientY: number };
    const p = local(g.clientX, g.clientY);
    zoomAbout(gestureStart * g.scale, p.x, p.y);
  };
  const onGestureEnd = (e: Event) => e.preventDefault();

  root.addEventListener("pointerdown", onPointerDown);
  root.addEventListener("pointermove", onPointerMove);
  root.addEventListener("pointerup", onPointerEnd);
  root.addEventListener("pointercancel", onPointerEnd);
  root.addEventListener("lostpointercapture", onPointerEnd);
  root.addEventListener("wheel", onWheel, { passive: false });
  root.addEventListener("gesturestart", onGestureStart);
  root.addEventListener("gesturechange", onGestureChange);
  root.addEventListener("gestureend", onGestureEnd);

  const ro = new ResizeObserver(fit);
  ro.observe(root);
  fit();

  /**
   * Shows another picture in place of this one. Zoom and position stay when it
   * has the same proportions (the same document redrawn); another shape is
   * fitted.
   */
  const replacePicture = (next: HTMLImageElement | HTMLCanvasElement, size: { width: number; height: number }) => {
    const sameShape = Math.abs(size.width / size.height - natural.width / natural.height) < 1e-3;
    next.classList.add("exv-image-picture");
    next.draggable = false;
    const old = picture;
    old.replaceWith(next);
    if (old instanceof HTMLCanvasElement) {
      old.width = 0;
      old.height = 0;
    } else {
      old.src = "";
    }
    picture = next;
    natural = size;
    dropDetail();
    if (sameShape && view.get().page.width) scheduleDetail();
    else fit();
  };

  return {
    ...view,
    toPage,
    toScreen,
    pick,
    replacePicture,
    pageLayer,
    screenLayer,
    zoom: {
      ...zoomState,
      setScale(scale, anchor) {
        const v = view.get();
        const a = anchor ?? { x: v.container.width / 2, y: v.container.height / 2 };
        zoomAbout(scale, a.x, a.y);
      },
      fit,
    },
    resize: fit,
    destroy() {
      destroyed = true;
      clearTimeout(detailTimer);
      if (frame) cancelAnimationFrame(frame);
      dropDetail();
      ro.disconnect();
      if (picture instanceof HTMLCanvasElement) {
        picture.width = 0;
        picture.height = 0;
      }
      root.remove();
    },
  };
}
