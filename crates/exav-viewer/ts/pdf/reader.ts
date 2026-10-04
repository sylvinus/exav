/**
 * A PDF in one vertical scroll.
 *
 * Only what is near the viewport is drawn (a page is ~18 MB of bitmap; forty
 * of them do not fit in an iPad), every page box has its final size before
 * anything is drawn so the scrollbar never jumps, and pages scrolled far
 * past are released.
 *
 * Two fingers, Safari's trackpad gesture, or ctrl+wheel (how Chrome and
 * Firefox report a trackpad pinch) zoom. During the gesture the content is
 * only scaled with a CSS transform; on release it is laid out at the new
 * width in the same frame and the scroll set so the point under the fingers
 * stays there. Past `pageMaxPixels` a page's own bitmap stops growing, and
 * what is on screen is redrawn sharp on a canvas laid over it.
 *
 * Over each page near the viewport lie its text, transparent, to select and
 * copy (pdf.js's text layer), and its links. A link to another place in the
 * document scrolls there; one to an address calls `window.open`, which the
 * sandboxed frame turns into the host's question.
 */
import { writable } from "../core/store.js";
import type { DragController, OutlineEntry, PagesController, ZoomController, OutlineController } from "../core/types.js";
import { renderDpr, type LoadedPdf, type PageRegion, type PdfLink } from "./engine.js";

export interface ReaderOptions {
  minZoom: number;
  maxZoom: number;
  /** What a mouse drag does on a page larger than the viewer (see `DragController`). */
  drag: "pan" | "select";
  prerenderMargin: string;
  pageMaxPixels: number;
  detailMaxPixels: number;
  detailMargin: number;
  detailDelayMs: number;
}

export const READER_DEFAULTS: ReaderOptions = {
  minZoom: 1,
  maxZoom: 6,
  drag: "pan",
  prerenderMargin: "100%",
  // Half of iOS Safari's per-canvas ceiling: a few pages are alive at once.
  pageMaxPixels: 8_388_608,
  // Under iOS Safari's ceiling of 16,777,216.
  detailMaxPixels: 16_000_000,
  detailMargin: 64,
  detailDelayMs: 150,
};

/** Air left above a heading jumped to. */
const JUMP_MARGIN = 12;
const PADDING = 12;
/** How long a ctrl+wheel pinch waits for its next event before it ends. */
const WHEEL_PINCH_IDLE_MS = 160;

interface Point {
  x: number;
  y: number;
}

interface Pinch {
  content: Point;
  scroll: Point;
  origin: Point;
  anchor: { page: number; fx: number; fy: number };
  scale: number;
  mid: Point;
}

interface GestureEventLike extends UIEvent {
  scale: number;
  clientX: number;
  clientY: number;
}

export interface Reader {
  pages: PagesController;
  zoom: ZoomController;
  drag: DragController;
  outline: OutlineController;
  /**
   * Shows another document in place of this one, at the same zoom and scroll
   * position. The old `doc` is the caller's to destroy afterwards.
   */
  replace(doc: LoadedPdf, sizes: { width: number; height: number }[]): void;
  resize(): void;
  destroy(): void;
}

/** A page counts as larger than the viewer, and a drag as a pan, from this zoom above the minimum. */
const ZOOMED = 1.001;
/** A drag that moved less is a click. */
const DRAG_SLOP = 4;

/** `sizes`: each page's, in PDF points (`LoadedPdf.pageSize`). */
export function createReader(
  host: HTMLElement,
  initial: LoadedPdf,
  initialSizes: { width: number; height: number }[],
  options: ReaderOptions,
  onError: (error: unknown) => void,
): Reader {
  let doc = initial;
  let sizes = initialSizes;
  let aspects = sizes.map((s) => s.width / s.height);
  const root = document.createElement("div");
  root.className = "exv-pdf";
  // Scrolling stays the browser's, zooming never is: its zoom takes the page.
  root.style.touchAction = "pan-x pan-y";
  const scroller = document.createElement("div");
  scroller.className = "exv-pdf-scroller";
  const content = document.createElement("div");
  content.className = "exv-pdf-content";
  scroller.append(content);
  root.append(scroller);
  host.append(root);

  const boxes: HTMLDivElement[] = [];
  const canvases: HTMLCanvasElement[] = [];
  const details: HTMLCanvasElement[] = [];
  /** One box per page of the current document, empty until drawn. */
  const build = () => {
    aspects.forEach((_, page) => {
      const box = document.createElement("div");
      box.className = "exv-pdf-page";
      box.dataset.page = String(page);
      const canvas = document.createElement("canvas");
      canvas.className = "exv-pdf-bitmap";
      const detail = document.createElement("canvas");
      detail.className = "exv-pdf-detail";
      detail.setAttribute("aria-hidden", "true");
      box.append(canvas, detail);
      content.append(box);
      boxes.push(box);
      canvases.push(canvas);
      details.push(detail);
    });
  };
  build();

  let fitWidth = 0;
  let zoom = 1;
  let pinch: Pinch | null = null;
  let detailTimer: ReturnType<typeof setTimeout> | undefined;
  let destroyed = false;
  const near = new Set<number>([0]);
  const drawnAt = new Map<number, number>();

  const pages = writable<{ unit: "page" | "slide"; current: number; total: number } | null>({
    unit: "page",
    current: 1,
    total: aspects.length,
  });
  const zoomState = writable({ scale: 1, min: options.minZoom, max: options.maxZoom });
  const outline = writable<readonly OutlineEntry[]>([]);

  // A drag pans where a page is larger than the viewer, if the user did not
  // choose to select; below that it selects, as there is nothing to pan.
  let choice = options.drag;
  const dragState = writable<{ mode: "pan" | "select"; available: boolean }>({ mode: "select", available: false });
  const updateDrag = () => {
    const available = zoom > options.minZoom * ZOOMED;
    const mode = available ? choice : "select";
    root.dataset.drag = mode;
    const now = dragState.get();
    if (now.mode !== mode || now.available !== available) dragState.set({ mode, available });
  };

  const pageWidth = () => Math.round(fitWidth * zoom);
  const bitmapWidth = (page: number) => {
    const aspect = aspects[page] ?? 1;
    return Math.min(pageWidth(), Math.floor(Math.sqrt(options.pageMaxPixels * aspect) / renderDpr()));
  };

  const layout = () => {
    const w = pageWidth();
    boxes.forEach((box, i) => {
      box.style.width = `${w}px`;
      box.style.height = `${w / (aspects[i] ?? 1)}px`;
      // What the text layer is sized by.
      box.style.setProperty("--scale-factor", String(w / (sizes[i]?.width || 1)));
    });
  };

  // ── text and links ──
  const overlays = new Map<number, () => void>();

  const follow = (link: PdfLink) => {
    if ("url" in link) {
      window.open(link.url, "_blank", "noopener,noreferrer");
      return;
    }
    void doc.destination(link.dest).then((d) => {
      if (d && !destroyed) goTo(d.pageNumber, d.offset, true);
    });
  };

  const linkElement = (link: PdfLink, area: PageRegion) => {
    const a = document.createElement("a");
    a.className = "exv-pdf-link";
    a.style.left = `${area.x * 100}%`;
    a.style.top = `${area.y * 100}%`;
    a.style.width = `${area.width * 100}%`;
    a.style.height = `${area.height * 100}%`;
    // An address shows where it goes; a destination has none to show.
    a.href = "url" in link ? link.url : "#";
    if ("url" in link) a.rel = "noopener noreferrer";
    a.addEventListener("click", (e) => {
      e.preventDefault();
      follow(link);
    });
    return a;
  };

  const addOverlay = (page: number) => {
    const box = boxes[page];
    if (!box) return;
    const text = document.createElement("div");
    text.className = "exv-pdf-text";
    const links = document.createElement("div");
    links.className = "exv-pdf-links";
    box.append(text, links);
    let live = true;
    const task = doc.textLayer(page + 1, text);
    task.done.then(
      () => {
        // What a selection dragged past the text lands on (see the stylesheet).
        const end = document.createElement("div");
        end.className = "exv-pdf-text-end";
        if (live) text.append(end);
      },
      // Without its text, the page is still shown.
      () => {},
    );
    void doc.links(page + 1).then((list) => {
      if (!live) return;
      for (const link of list) for (const area of link.areas) links.append(linkElement(link, area));
    });
    overlays.set(page, () => {
      live = false;
      task.cancel();
      text.remove();
      links.remove();
    });
  };

  const refreshOverlays = () => {
    for (const page of near) if (!overlays.has(page)) addOverlay(page);
    for (const [page, remove] of overlays) {
      if (near.has(page)) continue;
      remove();
      overlays.delete(page);
    }
  };

  // While a selection is being dragged, the end of each text layer covers it
  // whole, so that the pointer off the text leaves the selection where it
  // was: Firefox and WebKit otherwise move its start to the page's top (how
  // pdf.js's viewer does it).
  const onSelectStart = (e: MouseEvent) => {
    (e.target as Element | null)?.closest?.(".exv-pdf-text")?.classList.add("exv-pdf-selecting");
  };
  const onSelectEnd = () => {
    for (const layer of content.querySelectorAll(".exv-pdf-selecting")) layer.classList.remove("exv-pdf-selecting");
  };

  const draw = (page: number) => {
    const canvas = canvases[page];
    if (!canvas || pageWidth() === 0) return;
    const width = bitmapWidth(page);
    if (drawnAt.get(page) === width) return;
    drawnAt.set(page, width);
    doc.renderPageTo(canvas, page + 1, width).catch((error) => {
      drawnAt.delete(page);
      if (!destroyed) onError(error);
    });
  };

  const release = (canvas: HTMLCanvasElement) => {
    doc.cancelRender(canvas);
    canvas.width = 0;
    canvas.height = 0;
  };

  const releaseDetail = (detail: HTMLCanvasElement) => {
    release(detail);
    detail.style.display = "";
  };

  const refresh = () => {
    for (const page of near) draw(page);
    canvases.forEach((canvas, page) => {
      if (near.has(page) || !drawnAt.has(page)) return;
      release(canvas);
      drawnAt.delete(page);
    });
    refreshOverlays();
  };

  const drawDetail = () => {
    if (destroyed || pageWidth() === 0) return;
    const view = scroller.getBoundingClientRect();
    const dpr = renderDpr();
    details.forEach((detail, page) => {
      const box = boxes[page]!;
      if (!near.has(page) || bitmapWidth(page) >= pageWidth()) {
        if (detail.width > 0) releaseDetail(detail);
        return;
      }
      const rect = box.getBoundingClientRect();
      const visible = (margin: number): PageRegion => {
        const x = Math.max(0, view.left - rect.left - margin);
        const y = Math.max(0, view.top - rect.top - margin);
        return {
          x,
          y,
          width: Math.min(rect.width, view.right - rect.left + margin) - x,
          height: Math.min(rect.height, view.bottom - rect.top + margin) - y,
        };
      };
      const fits = (r: PageRegion) => r.width * r.height * dpr * dpr <= options.detailMaxPixels;
      let region = visible(options.detailMargin);
      if (!fits(region)) region = visible(0);
      if (region.width <= 0 || region.height <= 0 || !fits(region)) {
        if (detail.width > 0) releaseDetail(detail);
        return;
      }
      doc
        .renderPageTo(detail, page + 1, pageWidth(), region)
        .then((drew) => {
          if (!drew) return;
          // In fractions of the page, so it stays in place after the next zoom
          // resizes the page and before it is redrawn.
          detail.style.left = `${(region.x / rect.width) * 100}%`;
          detail.style.top = `${(region.y / rect.height) * 100}%`;
          detail.style.width = `${(region.width / rect.width) * 100}%`;
          detail.style.height = `${(region.height / rect.height) * 100}%`;
          detail.style.display = "block";
        })
        .catch(() => releaseDetail(detail));
    });
  };

  const scheduleDetail = () => {
    clearTimeout(detailTimer);
    detailTimer = setTimeout(() => {
      if (!pinch) drawDetail();
    }, options.detailDelayMs);
  };

  const measure = () => {
    const w = Math.max(320, scroller.clientWidth - 2 * PADDING);
    if (w === fitWidth) return;
    fitWidth = w;
    layout();
    refresh();
    scheduleDetail();
  };

  const currentPage = () => {
    const top = scroller.getBoundingClientRect().top;
    const middle = scroller.clientHeight / 2;
    let page = 1;
    boxes.forEach((box, i) => {
      if (box.getBoundingClientRect().top - top <= middle) page = i + 1;
    });
    return page;
  };

  const onScroll = () => {
    pages.set({ unit: "page", current: currentPage(), total: aspects.length });
    scheduleDetail();
  };

  // ── zoom ──
  const begin = (mid: Point) => {
    if (pinch) return;
    clearTimeout(detailTimer);
    let anchor = { page: 0, fx: 0, fy: 0 };
    let nearest = Infinity;
    boxes.forEach((box, page) => {
      const r = box.getBoundingClientRect();
      const distance = Math.max(r.top - mid.y, 0, mid.y - r.bottom);
      if (distance < nearest) {
        nearest = distance;
        anchor = { page, fx: (mid.x - r.left) / (r.width || 1), fy: (mid.y - r.top) / (r.height || 1) };
      }
    });
    const c = content.getBoundingClientRect();
    pinch = {
      content: { x: c.left, y: c.top },
      scroll: { x: scroller.scrollLeft, y: scroller.scrollTop },
      origin: { x: mid.x - c.left, y: mid.y - c.top },
      anchor,
      scale: 1,
      mid,
    };
    content.style.transformOrigin = "0 0";
    content.style.willChange = "transform";
  };

  const update = (mid: Point, factor: number) => {
    if (!pinch) return;
    const scale = Math.min(options.maxZoom / zoom, Math.max(options.minZoom / zoom, factor));
    pinch.scale = scale;
    pinch.mid = mid;
    // Where the content sits now without the transform: a scroll may still run.
    const left = pinch.content.x - (scroller.scrollLeft - pinch.scroll.x);
    const top = pinch.content.y - (scroller.scrollTop - pinch.scroll.y);
    const tx = mid.x - left - scale * pinch.origin.x;
    const ty = mid.y - top - scale * pinch.origin.y;
    content.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
  };

  const end = () => {
    const p = pinch;
    pinch = null;
    if (!p) return;
    zoom = Math.min(options.maxZoom, Math.max(options.minZoom, zoom * p.scale));
    // Laid out now, so the transform goes and the scroll is set before paint.
    layout();
    content.style.transform = "";
    content.style.willChange = "";
    const box = boxes[p.anchor.page];
    if (box) {
      const r = box.getBoundingClientRect();
      scroller.scrollLeft += r.left + p.anchor.fx * r.width - p.mid.x;
      scroller.scrollTop += r.top + p.anchor.fy * r.height - p.mid.y;
    }
    zoomState.set({ scale: zoom, min: options.minZoom, max: options.maxZoom });
    updateDrag();
    refresh();
    scheduleDetail();
  };

  const pair = (e: TouchEvent) => {
    const a = e.touches[0];
    const b = e.touches[1];
    if (!a || !b) return null;
    return {
      mid: { x: (a.clientX + b.clientX) / 2, y: (a.clientY + b.clientY) / 2 },
      distance: Math.max(1, Math.hypot(b.clientX - a.clientX, b.clientY - a.clientY)),
    };
  };
  let touching = false;
  let startDistance = 1;
  const onTouchStart = (e: TouchEvent) => {
    const two = pair(e);
    if (!two || touching) return;
    touching = true;
    startDistance = two.distance;
    begin(two.mid);
  };
  const onTouchMove = (e: TouchEvent) => {
    if (!touching) return;
    const two = pair(e);
    if (!two) return;
    if (e.cancelable) e.preventDefault();
    update(two.mid, two.distance / startDistance);
  };
  const onTouchEnd = (e: TouchEvent) => {
    if (!touching || e.touches.length >= 2) return;
    touching = false;
    end();
  };
  // Safari's trackpad pinch. Cancelled in every case: unhandled, it zooms the page.
  const onGestureStart = (e: Event) => {
    e.preventDefault();
    if (touching) return;
    const g = e as GestureEventLike;
    begin({ x: g.clientX, y: g.clientY });
  };
  const onGestureChange = (e: Event) => {
    e.preventDefault();
    if (touching) return;
    const g = e as GestureEventLike;
    update({ x: g.clientX, y: g.clientY }, g.scale);
  };
  const onGestureEnd = (e: Event) => {
    e.preventDefault();
    if (!touching) end();
  };
  // Chrome and Firefox report a trackpad pinch as a wheel with ctrlKey.
  let wheelFactor = 1;
  let wheelTimer: ReturnType<typeof setTimeout> | undefined;
  const onWheel = (e: WheelEvent) => {
    if (!e.ctrlKey) return;
    e.preventDefault();
    if (!pinch) {
      wheelFactor = 1;
      begin({ x: e.clientX, y: e.clientY });
    }
    wheelFactor *= Math.exp(-e.deltaY / 100);
    update({ x: e.clientX, y: e.clientY }, wheelFactor);
    clearTimeout(wheelTimer);
    wheelTimer = setTimeout(end, WHEEL_PINCH_IDLE_MS);
  };

  // ── a mouse drag pans, when it is chosen and the page is larger than the viewer ──
  let panning: { x: number; y: number; left: number; top: number; moved: boolean } | null = null;
  const swallowClick = (e: MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };
  const onPanMove = (e: MouseEvent) => {
    if (!panning) return;
    const dx = e.clientX - panning.x;
    const dy = e.clientY - panning.y;
    if (!panning.moved && Math.hypot(dx, dy) < DRAG_SLOP) return;
    panning.moved = true;
    scroller.scrollLeft = panning.left - dx;
    scroller.scrollTop = panning.top - dy;
  };
  const onPanEnd = () => {
    const was = panning;
    panning = null;
    root.classList.remove("exv-pdf-panning");
    document.removeEventListener("mousemove", onPanMove);
    document.removeEventListener("mouseup", onPanEnd);
    if (!was?.moved) return;
    // The click that ends a drag follows no link under the pointer. It comes
    // right after the release, or not at all (released elsewhere).
    scroller.addEventListener("click", swallowClick, { capture: true, once: true });
    setTimeout(() => scroller.removeEventListener("click", swallowClick, { capture: true }), 0);
  };
  const onPanStart = (e: MouseEvent) => {
    if (e.button !== 0 || dragState.get().mode !== "pan") return;
    // The scrollbars are the scroller's own and take the press themselves.
    const r = scroller.getBoundingClientRect();
    if (e.clientX >= r.left + scroller.clientWidth || e.clientY >= r.top + scroller.clientHeight) return;
    // Before the text layer's own handler, and no selection starts.
    e.preventDefault();
    e.stopPropagation();
    panning = { x: e.clientX, y: e.clientY, left: scroller.scrollLeft, top: scroller.scrollTop, moved: false };
    root.classList.add("exv-pdf-panning");
    document.addEventListener("mousemove", onPanMove);
    document.addEventListener("mouseup", onPanEnd);
  };
  scroller.addEventListener("mousedown", onPanStart, { capture: true });

  scroller.addEventListener("scroll", onScroll, { passive: true });
  scroller.addEventListener("touchstart", onTouchStart, { passive: true });
  scroller.addEventListener("touchmove", onTouchMove, { passive: false });
  scroller.addEventListener("touchend", onTouchEnd);
  scroller.addEventListener("touchcancel", onTouchEnd);
  scroller.addEventListener("gesturestart", onGestureStart);
  scroller.addEventListener("gesturechange", onGestureChange);
  scroller.addEventListener("gestureend", onGestureEnd);
  scroller.addEventListener("wheel", onWheel, { passive: false });
  content.addEventListener("mousedown", onSelectStart);
  document.addEventListener("pointerup", onSelectEnd);
  window.addEventListener("blur", onSelectEnd);

  const io = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const page = Number((entry.target as HTMLElement).dataset.page);
        if (entry.isIntersecting) near.add(page);
        else near.delete(page);
      }
      refresh();
      scheduleDetail();
    },
    { root: scroller, rootMargin: `${options.prerenderMargin} 0px` },
  );
  for (const box of boxes) io.observe(box);
  const ro = new ResizeObserver(measure);
  ro.observe(scroller);
  measure();

  // The outline after the pages, never in their way. The old one stays until the new one is read.
  const loadOutline = () => {
    const of = doc;
    void of
      .outline()
      .then((entries) => {
        if (!destroyed && of === doc) outline.set(entries.map((e) => ({ title: e.title, page: e.pageNumber, depth: e.depth, offset: e.offset })));
      })
      .catch(() => {});
  };
  loadOutline();
  updateDrag();

  const goTo = (page: number, offset: number | null, smooth: boolean) => {
    const box = boxes[page - 1];
    if (!box) return;
    const pageTop = scroller.scrollTop + box.getBoundingClientRect().top - scroller.getBoundingClientRect().top;
    const into = offset === null ? 0 : offset * box.getBoundingClientRect().height;
    scroller.scrollTo({
      top: Math.max(0, pageTop + into - (offset === null ? 0 : JUMP_MARGIN)),
      behavior: smooth ? "smooth" : "auto",
    });
  };

  const setScale = (scale: number, anchor?: Point) => {
    const r = scroller.getBoundingClientRect();
    const mid = anchor ? { x: r.left + anchor.x, y: r.top + anchor.y } : { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    begin(mid);
    update(mid, scale / zoom);
    end();
  };

  const replace = (next: LoadedPdf, nextSizes: { width: number; height: number }[]) => {
    if (destroyed) return;
    // A pinch in flight ends where it is: its transform is on the old pages.
    if (pinch) end();
    const left = scroller.scrollLeft;
    const top = scroller.scrollTop;
    io.disconnect();
    for (const remove of overlays.values()) remove();
    overlays.clear();
    // Released through the old document, which still knows these renders.
    for (const c of [...canvases, ...details]) release(c);
    for (const box of boxes) box.remove();
    boxes.length = canvases.length = details.length = 0;
    near.clear();
    near.add(0);
    drawnAt.clear();
    doc = next;
    sizes = nextSizes;
    aspects = sizes.map((s) => s.width / s.height);
    build();
    layout();
    for (const box of boxes) io.observe(box);
    // The same zoom, at the same place: what the reader was checking stays under the eye.
    scroller.scrollLeft = left;
    scroller.scrollTop = top;
    pages.set({ unit: "page", current: currentPage(), total: aspects.length });
    refresh();
    scheduleDetail();
    loadOutline();
  };

  return {
    pages: { ...pages, goTo: (page) => goTo(page, null, true) },
    zoom: { ...zoomState, setScale, fit: () => setScale(1) },
    drag: {
      ...dragState,
      choose(mode) {
        choice = mode;
        updateDrag();
      },
    },
    outline: { ...outline, goTo: (entry) => goTo(entry.page, entry.offset, true) },
    replace,
    resize: measure,
    destroy() {
      destroyed = true;
      clearTimeout(detailTimer);
      clearTimeout(wheelTimer);
      io.disconnect();
      ro.disconnect();
      document.removeEventListener("pointerup", onSelectEnd);
      window.removeEventListener("blur", onSelectEnd);
      document.removeEventListener("mousemove", onPanMove);
      document.removeEventListener("mouseup", onPanEnd);
      for (const c of [...canvases, ...details]) release(c);
      for (const remove of overlays.values()) remove();
      overlays.clear();
      root.remove();
    },
  };
}
