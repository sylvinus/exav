/**
 * Printing what a session shows, from its pages drawn as pictures: the
 * sandboxed frame cannot open the print dialog, and a format the browser
 * does not draw (TIFF, JPEG 2000, a PDF in most of them) cannot be printed
 * from its URL.
 */
import type { PicturesController } from "./types.js";

export interface PrintOptions {
  /** Longest side of each page, in px. Default 2480 (A4 at 300 dpi). */
  longEdge?: number;
  /** The pages to print, 1-based. Default all of them. */
  pages?: readonly number[];
  /** Stops drawing the pages; nothing is printed. */
  signal?: AbortSignal;
  /** Each page drawn, for a progress bar. */
  onProgress?: (done: number, total: number) => void;
}

/** As PNG; null when it cannot be read back (an image shown from another origin without CORS). */
function toBlob(bitmap: ImageBitmap): Promise<Blob | null> {
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  canvas.getContext("2d")?.drawImage(bitmap, 0, 0);
  return new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"))
    .catch(() => null)
    .finally(() => {
      canvas.width = 0;
      canvas.height = 0;
    });
}

/**
 * Draws the pages, then opens the browser's print dialog on them in a hidden
 * frame of this page, built element by element. Resolves once the dialog
 * has closed, false when nothing was printed (no page drawn, or aborted).
 * A page that cannot be read back (an image the frame showed from another
 * origin without CORS) is left out. The page's policy must allow `blob:`
 * images.
 */
export async function printPictures(pictures: PicturesController, options: PrintOptions = {}): Promise<boolean> {
  const count = pictures.get().count;
  const pages = (options.pages ?? Array.from({ length: count }, (_, i) => i + 1)).filter((p) => Number.isSafeInteger(p) && p >= 1 && p <= count);
  const urls: string[] = [];
  const frame = document.createElement("iframe");
  try {
    for (const [i, page] of pages.entries()) {
      if (options.signal?.aborted) return false;
      const bitmap = await pictures.render(page, options.longEdge ?? 2480);
      if (bitmap) {
        const blob = await toBlob(bitmap);
        bitmap.close();
        if (blob) urls.push(URL.createObjectURL(blob));
      }
      options.onProgress?.(i + 1, pages.length);
    }
    if (!urls.length || options.signal?.aborted) return false;

    frame.setAttribute("aria-hidden", "true");
    frame.tabIndex = -1;
    Object.assign(frame.style, { position: "fixed", width: "0", height: "0", border: "0", visibility: "hidden" });
    document.body.append(frame);
    const doc = frame.contentDocument;
    const win = frame.contentWindow;
    if (!doc || !win) return false;
    Object.assign(doc.body.style, { margin: "0" });
    const loads: Promise<unknown>[] = [];
    for (const [i, url] of urls.entries()) {
      const img = doc.createElement("img");
      Object.assign(img.style, { display: "block", maxWidth: "100%", maxHeight: "100vh", margin: "0 auto", breakAfter: i < urls.length - 1 ? "page" : "auto" });
      loads.push(img.decode().catch(() => undefined));
      img.src = url;
      doc.body.append(img);
    }
    await Promise.all(loads);
    if (options.signal?.aborted) return false;
    await new Promise<void>((resolve) => {
      win.addEventListener("afterprint", () => resolve(), { once: true });
      win.focus();
      const start = performance.now();
      win.print();
      // A `print` that blocked until the dialog closed is over, `afterprint` or not.
      if (performance.now() - start > 500) resolve();
    });
    return true;
  } finally {
    // After the dialog: some browsers read the images while it is open.
    setTimeout(() => {
      frame.remove();
      for (const u of urls) URL.revokeObjectURL(u);
    }, 1000);
  }
}
