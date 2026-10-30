/**
 * Converts the formats the Office engines do not read, then shows the result
 * in a nested session of the same viewer, whose status and controllers become
 * this one's.
 *
 * Spreadsheets (XLS, ODS, Numbers) are converted to XLSX by exav-render's
 * `sheets`, presentations and OpenDocument drawings (PPT, ODP, Keynote, ODG)
 * to PPTX by `slides`, and, unless `converter: "external"`, text documents
 * (DOC, ODT, RTF) to DOCX by `docs` where no external converter is set. A
 * file such a converter recognises and cannot convert fails with its reason
 * (`SheetConversionError`, `SlideConversionError`, `DocConversionError`),
 * never going on to the external converter; one it does not recognise goes
 * to the external converter (`external.ts`), or ends in a
 * `NeedsConverterError` where there is none.
 */
import type { Renderer, RenderContext, ViewerFile } from "../core/types.js";
import type { ConversionOptions, ConvertedFormat } from "./index.js";
import { convertDocs, DocConversionError, sniffDocs } from "./docs.js";
import { ExternalConversionError, externalUrl, loadExternal, NeedsConverterError, statusOf } from "./external.js";
import { nativeFirst } from "./route.js";
import { convertSheet, SheetConversionError, sniffSheet } from "./sheets.js";
import { convertSlides, SlideConversionError, sniffSlides } from "./slides.js";

export { statusOf };
export { docsFirst, nativeFirst, slidesFirst } from "./route.js";

/**
 * What a file of `kind` fetches besides the viewer's code, for
 * `Viewer.prefetch`: nothing where the package's own converter takes it,
 * their modules being the viewer's; else the external converter's module and
 * what it names (`prefetch`).
 */
export async function prefetchUrls(kind: ConvertedFormat, assetBase: string, options: ConversionOptions = {}): Promise<string[]> {
  if (nativeFirst(kind, options) || options.externalConverter === undefined) return [];
  const url = await externalUrl(options.externalConverter, assetBase);
  const module = await loadExternal(url);
  const named = (await module.prefetch?.(kind)) ?? [];
  return [url, ...named.map((u) => new URL(u, url).href)];
}

/** The file as XLSX from `sheets`, or `null` when it is not one it reads. */
async function bySheets(bytes: Uint8Array, ctx: RenderContext<ConversionOptions>): Promise<Uint8Array | null> {
  const format = sniffSheet(bytes);
  if (format === "xlsx") return bytes;
  if (!format) return null;
  ctx.status({ phase: "converting", step: "convert" });
  let converted;
  try {
    converted = await convertSheet(bytes, format, { signal: ctx.signal, timeoutMs: ctx.options.timeoutMs, maxMemory: ctx.options.maxMemory });
  } catch (error) {
    if (ctx.signal.aborted) throw error;
    throw new SheetConversionError(format, error);
  }
  const { xlsx, warnings } = converted;
  if (warnings) console.warn(`office: ${format}: ${warnings.replaceAll("\n", "; ")}`);
  return new Uint8Array(xlsx);
}

/** The file as PPTX from `slides`, or `null` when it is not a presentation or drawing it recognises. */
async function bySlides(bytes: Uint8Array, ctx: RenderContext<ConversionOptions>): Promise<Uint8Array | null> {
  const format = sniffSlides(bytes);
  if (format === "pptx") return bytes;
  if (!format) return null;
  ctx.status({ phase: "converting", step: "convert" });
  let converted;
  try {
    converted = await convertSlides(bytes, format, { signal: ctx.signal, timeoutMs: ctx.options.timeoutMs, maxMemory: ctx.options.maxMemory });
  } catch (error) {
    if (ctx.signal.aborted) throw error;
    throw new SlideConversionError(format, error);
  }
  const { pptx, warnings } = converted;
  if (warnings) console.warn(`office: ${format}: ${warnings.replaceAll("\n", "; ")}`);
  return new Uint8Array(pptx);
}

/** The file as DOCX from `docs`, or `null` when it is not a document it recognises. */
async function byDocs(bytes: Uint8Array, ctx: RenderContext<ConversionOptions>): Promise<Uint8Array | null> {
  const format = sniffDocs(bytes);
  if (format === "docx") return bytes;
  if (!format) return null;
  ctx.status({ phase: "converting", step: "convert" });
  let converted;
  try {
    converted = await convertDocs(bytes, format, { signal: ctx.signal, timeoutMs: ctx.options.timeoutMs, maxMemory: ctx.options.maxMemory });
  } catch (error) {
    if (ctx.signal.aborted) throw error;
    throw new DocConversionError(format, error);
  }
  const { docx, warnings } = converted;
  if (warnings) console.warn(`office: ${format}: ${warnings.replaceAll("\n", "; ")}`);
  return new Uint8Array(docx);
}

/** A conversion that takes longer than this is stopped, as the package's own converters are. */
const DEFAULT_TIMEOUT_MS = 120_000;

/**
 * The file converted by the external converter: its progress shown as the
 * viewer's steps, aborted with the session or when it takes too long, and
 * ended at once then even if the module does not look at its signal.
 */
async function byExternal(kind: ConvertedFormat, bytes: Uint8Array, ctx: RenderContext<ConversionOptions>): Promise<{ format: "pdf" | "xlsx"; bytes: Uint8Array }> {
  const spec = ctx.options.externalConverter;
  if (spec === undefined) throw new NeedsConverterError(kind);
  const url = await externalUrl(spec, ctx.assetBase);
  const converter = await loadExternal(url);

  const controller = new AbortController();
  const follow = () => controller.abort(ctx.signal.reason);
  if (ctx.signal.aborted) follow();
  else ctx.signal.addEventListener("abort", follow, { once: true });
  const timeoutMs = ctx.options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const ended = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new ExternalConversionError(kind, "timeout");
      controller.abort(error);
      reject(error);
    }, timeoutMs);
    controller.signal.addEventListener("abort", () => reject(controller.signal.reason ?? new DOMException("aborted", "AbortError")), { once: true });
  });
  ended.catch(() => {});
  try {
    // A copy: the caller keeps its bytes.
    const result = await Promise.race([
      converter.convert(bytes.slice(), {
        hint: kind,
        ...(ctx.options.maxMemory !== undefined && { maxMemory: ctx.options.maxMemory }),
        signal: controller.signal,
        onProgress: (p) => ctx.status(statusOf(p)),
      }),
      ended,
    ]);
    // Checked by shape: bytes made in another realm (a frame, a worker) are no `instanceof` Uint8Array.
    const out = result?.bytes;
    if (!result || (result.format !== "pdf" && result.format !== "xlsx") || !ArrayBuffer.isView(out) || (out as { BYTES_PER_ELEMENT?: number }).BYTES_PER_ELEMENT !== 1) {
      throw new ExternalConversionError(kind, "failed", new Error('the converter did not resolve to { format: "pdf" | "xlsx", bytes: Uint8Array }'));
    }
    return { format: result.format, bytes: new Uint8Array(out.buffer, out.byteOffset, out.byteLength) };
  } catch (error) {
    if (ctx.signal.aborted || error instanceof ExternalConversionError) throw error;
    throw new ExternalConversionError(kind, "failed", error);
  } finally {
    clearTimeout(timer);
    ctx.signal.removeEventListener("abort", follow);
  }
}

/** Shows `bytes`, of `format`, in a nested session. */
function show(host: HTMLElement, ctx: RenderContext<ConversionOptions>, format: "pdf" | "xlsx" | "pptx" | "docx", bytes: Uint8Array) {
  const file: ViewerFile = { id: `${ctx.file.id}#${format}`, name: ctx.file.name, source: { bytes }, format };
  const session = ctx.mountNested(host, file, { forward: true });
  return { controllers: {}, resize: () => session.resize(), destroy: () => session.destroy() };
}

export function rendererFor(kind: ConvertedFormat): Renderer<ConversionOptions> {
  return {
    async mount(host, ctx) {
      ctx.status({ phase: "loading" });
      const bytes = await ctx.source.bytes();
      // What the package's own converter recognises is converted by it alone:
      // its failure is the file's (its error, with its kind). The external
      // converter gets only what it does not recognise.
      const native = nativeFirst(kind, ctx.options);
      if (native === "sheets") {
        const xlsx = await bySheets(bytes, ctx);
        if (xlsx) return show(host, ctx, "xlsx", xlsx);
      } else if (native === "slides") {
        const pptx = await bySlides(bytes, ctx);
        if (pptx) return show(host, ctx, "pptx", pptx);
      } else if (native === "docs") {
        const docx = await byDocs(bytes, ctx);
        if (docx) return show(host, ctx, "docx", docx);
      }
      let shown;
      try {
        shown = await byExternal(kind, bytes, ctx);
      } catch (error) {
        // Said as its own kind of failure: the viewer's message is about the converter.
        if (!(error instanceof NeedsConverterError) || ctx.signal.aborted) throw error;
        ctx.status({ phase: "error", error: { code: "needs_converter", cause: error } });
        return { controllers: {}, resize: () => {}, destroy: () => {} };
      }
      return show(host, ctx, shown.format, shown.bytes);
    },
  };
}
