import type { Renderer, SourceReader, ViewerFile } from "../core/types.js";
import { decodeInWorker, toCanvas } from "./decode.js";
import type { ImageOptions } from "./index.js";
import { createSurface, SURFACE_DEFAULTS, type SurfaceOptions } from "./surface.js";

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
): Promise<{ picture: HTMLImageElement | HTMLCanvasElement; natural: { width: number; height: number } }> {
  let picture: HTMLImageElement | HTMLCanvasElement;
  let natural: { width: number; height: number };
  try {
    // An `<img>` cannot send `init` (headers, credentials): such a URL is
    // fetched by the source and shown from an object URL.
    const given = file.source;
    const fetched = !!given && "url" in given && !!given.init;
    const src = fetched ? URL.createObjectURL(await source.blob()) : await source.url();
    let img: HTMLImageElement;
    try {
      img = await loadImg(src, o.crossOrigin === undefined ? "anonymous" : o.crossOrigin, signal);
    } finally {
      // Decoded once loaded: the object URL is no longer needed.
      if (fetched) URL.revokeObjectURL(src);
    }
    picture = img;
    natural = { width: img.naturalWidth, height: img.naturalHeight };
  } catch (error) {
    if (signal.aborted || !o.wasmDecoders) throw error;
    // What the browser does not draw, exav-render does. A copy is
    // transferred, so the source's own bytes stay usable.
    const bytes = (await source.bytes()).slice();
    const decoded = await decodeInWorker(bytes.buffer as ArrayBuffer, o.maxDecodeBytes ?? DEFAULT_MAX_DECODE, signal);
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
    picture = toCanvas(decoded);
    natural = { width: decoded.width, height: decoded.height };
  }
  if (!natural.width || !natural.height) throw new Error("the image has no size");
  return { picture, natural };
}

export const renderer: Renderer<ImageOptions<unknown>> = {
  async mount(host, ctx) {
    const o = ctx.options;
    let file = ctx.file as ViewerFile<unknown>;
    ctx.status({ phase: "loading" });

    const first = await pictureOf(file, ctx.source, ctx.signal, o);
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
      detail: o.detail?.(file),
      onTap: o.onTap && ((point, event, screen) => surfaceRef && o.onTap!(file, point, { surface: surfaceRef, event, screen })),
    };
    const surface = createSurface(host, picture, first.natural, surfaceOptions);
    surfaceRef = surface;
    let overlay = o.overlay?.(file)?.mount(surface);
    // Before "ready", as the plugin contract says: a plugin that shows this one
    // in a nested session follows the controllers from the status.
    ctx.controllers({ image: surface, zoom: surface.zoom });
    ctx.status({ phase: "ready" });
    return {
      controllers: { image: surface, zoom: surface.zoom },
      resize: surface.resize,
      // The same picture drawn again (marks added, a plan redrawn): the zoom
      // and position stay when its proportions do.
      async replace(next) {
        const shown = await pictureOf(next.file as ViewerFile<unknown>, next.source, next.signal, o);
        if (next.signal.aborted) throw new DOMException("aborted", "AbortError");
        file = next.file as ViewerFile<unknown>;
        surfaceOptions.detail = o.detail?.(file);
        overlay?.destroy();
        surface.replacePicture(shown.picture, shown.natural);
        picture = shown.picture;
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
