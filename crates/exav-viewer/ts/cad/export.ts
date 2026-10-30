/**
 * A drawing drawn again as a picture (`pictures.raster`): the layout's
 * geometry in a WebGL2 context of its own, at the picture's pixel size and
 * region, never the visible canvas. A picture past what the GPU holds is drawn
 * in tiles and composed on a 2D canvas.
 *
 * The geometry is tessellated again by the worker for each picture (the page
 * keeps none of it after the visible upload), uploaded to this context, and
 * the page's copy dropped before anything is drawn: while a picture is drawn
 * the memory is the visible renderer's buffers plus this context's, not a
 * third copy on the CPU. Everything the picture allocated is freed on
 * success, error and abort.
 */
import { asRasterError, RasterError, throwIfAborted, tilePlan } from "../core/pictures.js";
import { drawTiled, release } from "../core/raster.js";
import { glTile, tileEdge, type ExportView } from "./raster.js";
import { familiesFor, loadFamilies } from "./renderer/fonts.js";
import { Renderer } from "./renderer/renderer.js";
import { facesUsed } from "./renderer/text-layout.js";
import type { ParsedDrawing } from "./types.js";

type Surface = HTMLCanvasElement | OffscreenCanvas;

/** A CSS colour as 0..1 RGB and an opacity; null for what CSS rejects. */
export function parseColor(css: string): { rgb: [number, number, number]; alpha: number } | null {
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 1;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  // A colour the canvas rejects leaves its fill as it was: read twice from two
  // starting points, it gives away that it was not taken.
  const read = (start: string) => {
    ctx.fillStyle = start;
    ctx.fillStyle = css;
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillRect(0, 0, 1, 1);
    return ctx.getImageData(0, 0, 1, 1).data;
  };
  const a = read("#010203");
  const b = read("#fcfdfe");
  if (a.some((v, i) => v !== b[i])) return null;
  return { rgb: [a[0]! / 255, a[1]! / 255, a[2]! / 255], alpha: a[3]! / 255 };
}

const yieldToBrowser = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** A canvas with a WebGL2 context: off screen where the browser can, else a detached element. */
function openRenderer(alpha: boolean): { renderer: Renderer; surface: Surface } {
  const makers: (() => Surface)[] = [];
  if (typeof OffscreenCanvas === "function") makers.push(() => new OffscreenCanvas(1, 1));
  makers.push(() => document.createElement("canvas"));
  let last: unknown;
  for (const make of makers) {
    const surface = make();
    try {
      return { renderer: new Renderer(surface, { alpha }), surface };
    } catch (error) {
      last = error;
      surface.width = surface.height = 0;
    }
  }
  throw new RasterError("unsupported", "WebGL2 is not available", { cause: last });
}

function resize(surface: Surface, renderer: Renderer, width: number, height: number): void {
  if (surface.width !== width) surface.width = width;
  if (surface.height !== height) surface.height = height;
  const [w, h] = renderer.drawingBufferSize();
  if (w !== width || h !== height) throw new RasterError("too-large", `the GPU cannot hold a ${width} x ${height} px picture`);
}

/** The canvas's pixels as a bitmap that owns them; the canvas is left empty. */
async function takeBitmap(surface: Surface): Promise<ImageBitmap> {
  if ("transferToImageBitmap" in surface && typeof surface.transferToImageBitmap === "function") return surface.transferToImageBitmap();
  return createImageBitmap(surface);
}

export interface Picture {
  /** The layout as the worker tessellated it. Its geometry buffers are dropped once uploaded. */
  drawing: ParsedDrawing;
  /** Layer visibility, by layer index. */
  visible: boolean[];
  /** What the picture shows, in drawing units. */
  view: ExportView;
  width: number;
  height: number;
  /** The ground, as 0..1 RGB. With `alpha` under 1 it is the colour that decides the ink (and a wipeout's), and is not drawn. */
  ground: [number, number, number];
  /** 1: opaque. 0: transparent. In between: translucent. */
  alpha: number;
  lineweights: "drawing" | "always" | "never";
  monochrome: boolean;
  /** Device pixels per CSS pixel the line widths are for, and the factors on them (`lineweightFactors`). */
  dpr: number;
  factors: { pixel: number; paper: number };
  /** The plugin's `rasterTile`. */
  tile?: number;
  signal?: AbortSignal;
}

/** Draws `picture`; the bitmap is the caller's to close. */
export async function drawPicture(picture: Picture): Promise<ImageBitmap> {
  const { drawing: d, view, width, height, signal } = picture;
  throwIfAborted(signal);
  // Canvas falls back to a system font, silently, when asked for one that is
  // not loaded (see `loadFamilies`).
  await loadFamilies(familiesFor(facesUsed(d.texts)), (file, err) => console.warn(`dwg: could not load ${file}; its text is drawn with another face`, err));
  throwIfAborted(signal);

  const { renderer, surface } = openRenderer(picture.alpha < 1);
  try {
    const edge = tileEdge(renderer.limits(), picture.tile);
    const whole = width <= edge && height <= edge;
    // Too many tiles is refused before anything is uploaded.
    if (!whole) tilePlan(width, height, edge);

    renderer.background = picture.ground;
    renderer.backgroundAlpha = picture.alpha;
    renderer.lineweights = picture.lineweights;
    renderer.monochrome = picture.monochrome;
    renderer.pixelRatio = picture.dpr * picture.factors.pixel;
    renderer.paperWidthScale = picture.factors.paper;
    // The glyph atlas is sized from the whole picture's view: the same text
    // resolution in every tile.
    renderer.setPictureView({ cx: view.cx - d.origin[0], cy: view.cy - d.origin[1], scale: view.scale, width, height });
    renderer.setDrawing(d, picture.visible, false);
    d.strokes = d.fills = d.strokeTiles = d.fillTiles = new ArrayBuffer(0);
    if (renderer.isLost()) throw new RasterError("failed", "the GPU context was lost");

    // Lets a pending abort (or the page) in before the drawing.
    await yieldToBrowser();
    throwIfAborted(signal);

    // A picture in one pass is one tile. Its pixels are copied to a 2D canvas
    // before the context goes: a bitmap taken from a WebGL canvas is still
    // backed by that context.
    return await drawTiled(
      width,
      height,
      whole ? Math.max(width, height) : edge,
      async (tile) => {
        await yieldToBrowser();
        throwIfAborted(signal);
        resize(surface, renderer, tile.width, tile.height);
        renderer.showTile(glTile({ height }, tile));
        renderer.paint();
        if (renderer.isLost()) throw new RasterError("failed", "the GPU context was lost");
        return takeBitmap(surface);
      },
      { signal },
    );
  } catch (error) {
    throw asRasterError(error, signal);
  } finally {
    renderer.dispose();
    renderer.loseContext();
    release(surface);
  }
}
