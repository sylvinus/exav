/** SVG drawn by the browser from an `<img>`: its size, and its detail redrawn sharp. */
import type { DetailSource, ViewerFile } from "../core/types.js";

/** What browsers give an SVG that states no size at all. */
const DEFAULT_SIZE = { width: 300, height: 150 };

export function isSvg(file: Pick<ViewerFile, "type" | "name" | "path">): boolean {
  return file.type === "image/svg+xml" || (file.path ?? file.name).toLowerCase().endsWith(".svg");
}

const length = (v: string | undefined) => {
  const m = v === undefined ? null : /^\s*([\d.]+)\s*(px)?\s*$/.exec(v);
  const n = m ? Number(m[1]) : NaN;
  return n > 0 && Number.isFinite(n) ? n : null;
};

/**
 * The size an SVG states on its root element: `width` and `height` in px,
 * else its `viewBox`, else the browsers' default. Read from the first bytes,
 * for an `<img>` that reports none (Firefox, for a `viewBox` alone).
 */
export function svgSize(head: Uint8Array): { width: number; height: number } {
  const text = new TextDecoder().decode(head.subarray(0, 65_536));
  const tag = /<svg\b([^>]*)>/i.exec(text)?.[1] ?? "";
  const attr = (name: string) => new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)')`, "i").exec(tag)?.slice(2).find((v) => v !== undefined);
  const width = length(attr("width"));
  const height = length(attr("height"));
  const box = attr("viewBox")
    ?.trim()
    .split(/[\s,]+/)
    .map(Number);
  const boxSize = box && box.length === 4 && box[2]! > 0 && box[3]! > 0 ? { width: box[2]!, height: box[3]! } : null;
  if (width && height) return { width, height };
  if (boxSize && width) return { width, height: (width * boxSize.height) / boxSize.width };
  if (boxSize && height) return { width: (height * boxSize.width) / boxSize.height, height };
  return boxSize ?? DEFAULT_SIZE;
}

/**
 * The visible part drawn again at the zoom's resolution: an SVG is drawn at
 * any size, where the `<img>` is scaled as a bitmap.
 */
export function svgDetail(img: HTMLImageElement, natural: { width: number; height: number }): DetailSource {
  return async ({ pageWidth, region }) => {
    const pageHeight = (pageWidth * natural.height) / natural.width;
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(region.width * pageWidth));
    canvas.height = Math.max(1, Math.round(region.height * pageHeight));
    try {
      canvas.getContext("2d")?.drawImage(img, -region.x * pageWidth, -region.y * pageHeight, pageWidth, pageHeight);
      return await createImageBitmap(canvas);
    } finally {
      canvas.width = 0;
      canvas.height = 0;
    }
  };
}
