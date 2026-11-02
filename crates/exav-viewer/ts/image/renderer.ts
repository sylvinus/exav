import { planRect, type RectPlan } from "../core/pictures.js";
import { bitmapOf, createCanvas, createPictures, release } from "../core/raster.js";
import { derived } from "../core/store.js";
import type { DetailSource, RasterRect, Renderer, SourceReader, Viewport, ViewportController, ViewerFile } from "../core/types.js";
import { decodeInWorker, toCanvas } from "./decode.js";
import type { ImageOptions } from "./index.js";
import { createSurface, SURFACE_DEFAULTS, type SurfaceOptions } from "./surface.js";
import { isSvg, svgDetail, svgSize } from "./svg.js";

type Picture = {
  picture: HTMLImageElement | HTMLCanvasElement;
  natural: { width: number; height: number };
  /** An SVG the browser draws, at any size. */
  vector: boolean;
};

/** The host's detail source, or for an SVG one that draws it again at the zoom's resolution. */
function detailOf(o: ImageOptions<unknown>, file: ViewerFile<unknown>, shown: Picture): DetailSource | undefined {
  const own = o.detail?.(file);
  if (own) return own;
  return shown.picture instanceof HTMLImageElement && isSvg(file) ? svgDetail(shown.picture, shown.natural) : undefined;
}

/**
 * `shown` drawn as a picture: `region` (pixels of the picture) at the plan's
 * size, on its background, which is transparent unless one was asked for.
 */
async function drawRegion(shown: Picture, plan: RectPlan): Promise<ImageBitmap> {
  const { canvas, ctx } = createCanvas(plan.width, plan.height);
  try {
    if (plan.background !== "transparent") {
      ctx.fillStyle = plan.background;
      ctx.fillRect(0, 0, plan.width, plan.height);
    }
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = "high";
    const { x, y, width, height } = plan.region;
    if (shown.vector) {
      // The whole picture at the plan's scale, moved so the region falls on the canvas, which cuts it:
      // browsers differ in what a source rectangle of an SVG with no size of its own is.
      const kx = plan.width / width;
      const ky = plan.height / height;
      ctx.drawImage(shown.picture, -x * kx, -y * ky, shown.natural.width * kx, shown.natural.height * ky);
      return await bitmapOf(canvas);
    }
    // A region reaching past the picture shows the background there: the source rectangle is cut to the picture, the target with it.
    const sx = Math.max(0, x);
    const sy = Math.max(0, y);
    const sw = Math.min(shown.natural.width, x + width) - sx;
    const sh = Math.min(shown.natural.height, y + height) - sy;
    if (sw > 0 && sh > 0) {
      const kx = plan.width / width;
      const ky = plan.height / height;
      ctx.drawImage(shown.picture, sx, sy, sw, sh, (sx - x) * kx, (sy - y) * ky, sw * kx, sh * ky);
    }
    return await bitmapOf(canvas);
  } catch (error) {
    release(canvas);
    throw error;
  }
}

const DEFAULT_MAX_DECODE = 256 * 1024 * 1024;

function loadImg(url: string, crossOrigin: "anonymous" | "use-credentials" | null, signal: AbortSignal): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    if (crossOrigin) img.crossOrigin = crossOrigin;
    img.decoding = "async";
    const abort = () => {
      img.src = "";
      reject(new DOMException("aborted", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
    img.onload = () => {
      signal.removeEventListener("abort", abort);
      resolve(img);
    };
    img.onerror = () => {
      signal.removeEventListener("abort", abort);
      reject(new Error("the browser could not decode the image"));
    };
    img.src = url;
  });
}

/** The picture of a file: the browser's own, or exav-render's where it does not draw the format. */
async function pictureOf(
  file: ViewerFile<unknown>,
  source: SourceReader,
  signal: AbortSignal,
  o: ImageOptions<unknown>,
): Promise<Picture> {
  let picture: HTMLImageElement | HTMLCanvasElement;
  let natural: { width: number; height: number };
  let vector = false;
  try {
    // An `<img>` cannot send `init` (headers, credentials): such a URL is
    // fetched by the source and shown from an object URL. Nor does it sniff
    // SVG: bytes the host gave are typed as what they were detected as.
    const given = file.source;
    const byUrl = !!given && "url" in given;
    const svg = isSvg(file) && !(byUrl && !given.init);
    const fetched = (byUrl && !!given.init) || svg;
    const src = fetched ? URL.createObjectURL(svg ? new Blob([(await source.bytes()).slice()], { type: "image/svg+xml" }) : await source.blob()) : await source.url();
    let img: HTMLImageElement;
    try {
      img = await loadImg(src, o.crossOrigin === undefined ? "anonymous" : o.crossOrigin, signal);
    } finally {
      // Decoded once loaded: the object URL is no longer needed.
      if (fetched) URL.revokeObjectURL(src);
    }
    picture = img;
    vector = isSvg(file);
    natural = { width: img.naturalWidth, height: img.naturalHeight };
    // An SVG may state no size, or one the browser does not report.
    if (isSvg(file) && (!natural.width || !natural.height)) natural = svgSize(await source.bytes());
  } catch (error) {
    if (signal.aborted || !o.wasmDecoders) throw error;
    // What the browser does not draw, exav-render does. A copy is
    // transferred, so the source's own bytes stay usable.
    const bytes = (await source.bytes()).slice();
    const decoded = await decodeInWorker(bytes.buffer as ArrayBuffer, o.maxDecodeBytes ?? DEFAULT_MAX_DECODE, signal);
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
    picture = toCanvas(decoded);
    vector = false;
    natural = { width: decoded.width, height: decoded.height };
  }
  if (!natural.width || !natural.height) throw new Error("the image has no size");
  return { picture, natural, vector };
}

export const renderer: Renderer<ImageOptions<unknown>> = {
  async mount(host, ctx) {
    const o = ctx.options;
    let file = ctx.file as ViewerFile<unknown>;
    ctx.status({ phase: "loading" });

    let first: Picture;
    try {
      first = await pictureOf(file, ctx.source, ctx.signal, o);
    } catch (error) {
      // A camera RAW file that embeds no preview is said so, not as an image
      // that would not decode.
      if (!ctx.signal.aborted && error instanceof Error && error.message === "no-preview") {
        ctx.status({ phase: "error", error: { code: "image_no_preview", cause: error } });
        return { controllers: {}, resize: () => {}, destroy: () => {} };
      }
      throw error;
    }
    let shown = first;
    let picture = first.picture;

    let surfaceRef: ReturnType<typeof createSurface> | null = null;
    const surfaceOptions: SurfaceOptions = {
      ...SURFACE_DEFAULTS,
      ...(o.minScale !== undefined && { minScale: o.minScale }),
      ...(o.maxScale !== undefined && { maxScale: o.maxScale }),
      ...(o.wheelStep !== undefined && { wheelStep: o.wheelStep }),
      ...(o.wheel !== undefined && { wheel: o.wheel }),
      ...(o.tapSlop !== undefined && { tapSlop: o.tapSlop }),
      ...(o.detailDelayMs !== undefined && { detailDelayMs: o.detailDelayMs }),
      ...(o.detailMargin !== undefined && { detailMargin: o.detailMargin }),
      ...(o.detailMaxPixels !== undefined && { detailMaxPixels: o.detailMaxPixels }),
      detail: detailOf(o, file, first),
      onTap: o.onTap && ((point, event, screen) => surfaceRef && o.onTap!(file, point, { surface: surfaceRef, event, screen })),
    };
    const surface = createSurface(host, picture, first.natural, surfaceOptions);
    surfaceRef = surface;
    let overlay = o.overlay?.(file)?.mount(surface);
    const { controller: pictures } = createPictures({
      count: 1,
      space: "pixels",
      async raster(page, options) {
        const { width, height } = shown.natural;
        const view = viewport.get();
        const plan = planRect(options, { x: 0, y: 0, width, height }, { x: 1, y: 1 }, view ? (view.region as RasterRect) : null, "transparent");
        return { bitmap: await drawRegion(shown, plan), width: plan.width, height: plan.height, page, space: "pixels", region: plan.region };
      },
    });
    // What the surface shows, as pixels of the picture.
    const viewport: ViewportController = derived(surface, (v): Viewport | null => {
      const { width, height } = shown.natural;
      if (!(v.page.width > 0 && v.page.height > 0 && v.scale > 0)) return null;
      const w = v.page.width * v.scale;
      const h = v.page.height * v.scale;
      const left = Math.max(0, -v.x / w);
      const top = Math.max(0, -v.y / h);
      const right = Math.min(1, (v.container.width - v.x) / w);
      const bottom = Math.min(1, (v.container.height - v.y) / h);
      if (!(right > left && bottom > top)) return null;
      return { space: "pixels", page: 1, region: { x: left * width, y: top * height, width: (right - left) * width, height: (bottom - top) * height } };
    });
    const controllers = { image: surface, zoom: surface.zoom, pictures, viewport };
    // Before "ready", as the plugin contract says: a plugin that shows this one
    // in a nested session follows the controllers from the status.
    ctx.controllers(controllers);
    ctx.status({ phase: "ready" });
    return {
      controllers,
      resize: surface.resize,
      // The same picture drawn again (marks added, a plan redrawn): the zoom
      // and position stay when its proportions do.
      async replace(next) {
        const incoming = await pictureOf(next.file as ViewerFile<unknown>, next.source, next.signal, o);
        if (next.signal.aborted) throw new DOMException("aborted", "AbortError");
        file = next.file as ViewerFile<unknown>;
        surfaceOptions.detail = detailOf(o, file, incoming);
        overlay?.destroy();
        surface.replacePicture(incoming.picture, incoming.natural);
        shown = incoming;
        picture = incoming.picture;
        overlay = o.overlay?.(file)?.mount(surface);
      },
      destroy() {
        overlay?.destroy();
        surface.destroy();
        if (picture instanceof HTMLImageElement) picture.src = "";
      },
    };
  },
};
