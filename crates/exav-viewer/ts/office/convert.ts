/**
 * Converts the formats the Office engines do not read, then shows the result
 * in a nested session of the same viewer, whose status and controllers become
 * this one's.
 *
 * Spreadsheets (XLS, ODS, Numbers) are converted to XLSX by exav-render's
 * `sheets`, presentations and OpenDocument drawings (PPT, ODP, Keynote, ODG)
 * to PPTX by `slides`, and text documents (DOC, ODT, RTF, Pages) to DOCX by `docs`,
 * in the order `ConversionOptions.converter` and `nativeFirst` give with the
 * external converter (`external.ts`): a file the first cannot read goes on
 * to the other. Where both fail, the first one's error is the file's; the
 * package's converters say why (`SheetConversionError`,
 * `SlideConversionError`, `DocConversionError`). A file neither takes ends
 * in a `NeedsConverterError` where no external converter is set.
 */
import type { Renderer, RenderContext, ViewerFile } from "../core/types.js";
import type { ConversionOptions, ConvertedFormat } from "./index.js";
import { convertDocs, DocConversionError, sniffDocs } from "./docs.js";
import { ExternalConversionError, externalUrl, loadExternal, NeedsConverterError, statusOf } from "./external.js";
import { nativeFirst, nativeOf, type Native } from "./route.js";
import { convertSheet, SheetConversionError, sniffSheet } from "./sheets.js";
import { convertSlides, SlideConversionError, sniffSlides } from "./slides.js";
import { officeKinds } from "./zip.js";

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
  const format = sniffSheet(bytes, await officeKinds(bytes, ctx.signal));
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
  const format = sniffSlides(bytes, await officeKinds(bytes, ctx.signal));
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
  const format = sniffDocs(bytes, await officeKinds(bytes, ctx.signal));
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
  const { highlights, focusHighlight } = ctx.file;
  // A PDF made by the external converter has pages to find the file's highlights on.
  const marks = format === "pdf" ? { ...(highlights && { highlights }), ...(focusHighlight !== undefined && { focusHighlight }) } : {};
  const file: ViewerFile = { id: `${ctx.file.id}#${format}`, name: ctx.file.name, source: { bytes }, format, ...marks };
  const session = ctx.mountNested(host, file, { forward: true });
  return { controllers: {}, resize: () => session.resize(), destroy: () => session.destroy() };
}

/** The file converted by the package's converter `native`, or `null` when it is not one it recognises. */
async function byNative(native: Native, bytes: Uint8Array, ctx: RenderContext<ConversionOptions>): Promise<{ format: "xlsx" | "pptx" | "docx"; bytes: Uint8Array } | null> {
  const format = native === "sheets" ? "xlsx" : native === "slides" ? "pptx" : "docx";
  const made = await (native === "sheets" ? bySheets : native === "slides" ? bySlides : byDocs)(bytes, ctx);
  return made && { format, bytes: made };
}

export function rendererFor(kind: ConvertedFormat): Renderer<ConversionOptions> {
  return {
    async mount(host, ctx) {
      ctx.status({ phase: "loading" });
      const bytes = await ctx.source.bytes();
      const native = nativeOf(kind);
      const first = nativeFirst(kind, ctx.options);
      const external = ctx.options.externalConverter !== undefined;
      // The package's converter first: what it recognises and cannot convert
      // goes on to the external converter, and fails with its own error
      // (with its kind) where that one fails too or there is none.
      if (first) {
        let made;
        try {
          made = await byNative(first, bytes, ctx);
        } catch (error) {
          if (ctx.signal.aborted || !external) throw error;
          console.warn(`office: ${kind}: the package's converter could not convert it, the external converter is tried`, error);
          try {
            const shown = await byExternal(kind, bytes, ctx);
            return show(host, ctx, shown.format, shown.bytes);
          } catch (late) {
            if (ctx.signal.aborted) throw late;
            throw error;
          }
        }
        if (made) return show(host, ctx, made.format, made.bytes);
      }
      let shown;
      try {
        shown = await byExternal(kind, bytes, ctx);
      } catch (error) {
        if (ctx.signal.aborted) throw error;
        // The external converter first and failing, or none set: the
        // package's converter, where it has one it did not try already.
        if (!first && native) {
          if (external) console.warn(`office: ${kind}: the external converter failed, the package's converter is tried`, error);
          let made;
          try {
            made = await byNative(native, bytes, ctx);
          } catch (late) {
            // Its own reason, where there was no external converter to fail first.
            if (ctx.signal.aborted || !external) throw late;
            throw error;
          }
          if (made) return show(host, ctx, made.format, made.bytes);
        }
        // Said as its own kind of failure: the viewer's message is about the converter.
        if (!(error instanceof NeedsConverterError)) throw error;
        ctx.status({ phase: "error", error: { code: "needs_converter", cause: error } });
        return { controllers: {}, resize: () => {}, destroy: () => {} };
      }
      return show(host, ctx, shown.format, shown.bytes);
    },
  };
}
