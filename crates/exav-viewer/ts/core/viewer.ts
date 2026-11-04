import { checkPackageLimits, checkSniffBytes, checksDirectory, createDetector, HEAD_BYTES, readsHead } from "./detect.js";
import { FormatMismatch } from "./mismatch.js";
import { createInspector, createOfficer, createSniffer } from "./sniff-engine.js";
import { createSourceReader, type FilePart, type OwnedSourceReader } from "./source.js";
import { writable } from "./store.js";
import type {
  Controllers,
  FormatId,
  FormatPlugin,
  Renderer,
  RendererHandle,
  Session,
  Status,
  Viewer,
  ViewerConfig,
  ViewerError,
  ViewerFile,
} from "./types.js";

/** The error code each built-in format reports under, for its message. */
const ERROR_CODES: Record<string, ViewerError["code"]> = {
  pdf: "pdf",
  image: "image",
  dwg: "drawing",
  dxf: "drawing",
  docx: "office",
  xlsx: "office",
  pptx: "office",
  csv: "office",
  rtf: "office",
  doc: "office",
  odt: "office",
  ppt: "office",
  odp: "office",
  keynote: "office",
  xls: "office",
  ods: "office",
  numbers: "office",
  odg: "office",
  visio: "office",
  coreldraw: "office",
  publisher: "office",
  pagemaker: "office",
  freehand: "office",
  quarkxpress: "office",
  zonerdraw: "office",
  wpg: "office",
  text: "text",
  ifc: "model",
  stl: "model",
  obj: "model",
  ply: "model",
  gltf: "model",
  video: "media",
  audio: "media",
  archive: "archive",
};

/** A format no built-in plugin handles (none at all, or a host's own) is "file". */
export function errorCode(format: FormatId | null): ViewerError["code"] {
  return (format && ERROR_CODES[format]) || "file";
}

function isAbort(error: unknown, signal: AbortSignal): boolean {
  return signal.aborted || (error instanceof DOMException && error.name === "AbortError");
}

/** Assets fetched per format by `prefetch`, a few at a time. */
const PREFETCH_BATCH = 6;

/** One document of a session: its bytes' reader, and what stops its reads. */
interface Document {
  file: ViewerFile;
  abort: AbortController;
  reader: OwnedSourceReader | null;
}

export function createViewer(config: ViewerConfig): Viewer {
  const plugins = [...config.plugins];
  const assetBase = config.assetBase ?? "/exav-viewer/";
  const detector = createDetector(
    plugins.map((p) => ({ id: p.id, match: p.match })),
    createSniffer(config.sniffTimeoutMs),
    createInspector(config.sniffTimeoutMs),
    checkSniffBytes(config.sniffBytes),
    checkPackageLimits(config),
    createOfficer(config.sniffTimeoutMs),
  );
  // A load that failed is forgotten, so that one lost connection does not
  // break every later file of that format in the tab.
  const loads = new Map<FormatId, Promise<Renderer<unknown>>>();
  const prefetched = new Set<FormatId>();

  const load = (plugin: FormatPlugin<unknown>) => {
    let p = loads.get(plugin.id);
    if (!p) {
      p = plugin.load();
      loads.set(plugin.id, p);
      p.catch(() => loads.delete(plugin.id));
    }
    return p;
  };
  const mount = (host: HTMLElement, file: ViewerFile): Session => {
    // What the name and the type say; the first bytes of the file overrule it
    // where they are read (below).
    let format = file.format ?? detector.detect(file);
    let plugin = plugins.find((p) => p.id === format) ?? null;
    const sniffed = readsHead(file, detector.headBytes);
    const status = writable<Status>({ phase: "loading" });
    const controllers = writable<Controllers>({});
    const abort = new AbortController();
    const signal = abort.signal;
    const nested = new Set<Session>();
    let handle: RendererHandle | null = null;
    let ended = false;
    // A session's reads stop with it; a document's, also when another replaces it.
    const begin = (f: ViewerFile): Document => {
      const own = new AbortController();
      if (signal.aborted) own.abort();
      else signal.addEventListener("abort", () => own.abort(), { once: true });
      return { file: f, abort: own, reader: f.source ? createSourceReader(f.source, own.signal) : null };
    };
    const close = (d: Document) => {
      d.abort.abort();
      d.reader?.dispose();
    };
    let doc = begin(file);
    let replacing: Document | null = null;
    // A plugin that shows another file (`mountNested` with `forward`) owns
    // the controllers from then on; the handle's own would clear them.
    let forwarding = false;

    /**
     * "damaged" or "wrong_type" when exav's readers find `d`'s file to be
     * that, else null. A file whose bytes are at hand is always looked at; an
     * address is asked for ranges only when the viewer chose the format, not
     * when the host gave `format` (as the frame is, for an address it reads
     * itself or cannot reach).
     */
    const isLocal = (d: Document): boolean => {
      const s = d.file.source;
      return !!s && !("url" in s) && !("resolve" in s);
    };
    const diagnosable = (d: Document): boolean => !!d.reader && !!format && detector.headBytes > 0 && (d.file.format === undefined || isLocal(d));
    const diagnose = async (d: Document): Promise<ViewerError["code"] | null> => {
      try {
        const head = await d.reader!.head(detector.headBytes);
        if (!head) return null;
        const found = await detector.inspect(format!, head.bytes, head.size, (n) => d.reader!.tail(n), d.abort.signal);
        return found === "signature-mismatch" ? "wrong_type" : found === "invalid-package" || found === "missing-part" ? "damaged" : null;
      } catch {
        // Stopped, or the file cannot be read again: the failure stands as it was.
        return null;
      }
    };

    /**
     * Shows `error` of document `d` (null: not diagnosed, its reader is
     * closed). The format's own code, when the host's `translate` has not
     * worded it, becomes `damaged` or `wrong_type` if the readers say so.
     */
    const report = (error: ViewerError, d: Document | null): Promise<void> => {
      const show = (code: ViewerError["code"] | null) => {
        if (!ended) status.set({ phase: "error", error: code ? { ...error, code } : error });
      };
      if (!d || error.message || error.code !== errorCode(format) || !diagnosable(d)) {
        show(null);
        return Promise.resolve();
      }
      return diagnose(d).then(show);
    };
    /**
     * The error to show when the ZIP directory of `d`'s file goes past a limit
     * (`maxExtractedBytes`, `maxMembers`, `maxCompressionRatio`), else null.
     * `known` is the start of the file when it has been read. A file whose
     * directory cannot be read is left to its engine. As for `diagnose`, an
     * address is asked for ranges only when the viewer chose the format and
     * `sniffBytes` is not 0.
     */
    const refusal = async (d: Document, known: FilePart | null): Promise<ViewerError | null> => {
      if (!format || !d.reader || !checksDirectory(format, detector.limits)) return null;
      if (!isLocal(d) && (d.file.format !== undefined || detector.headBytes === 0)) return null;
      try {
        const head = known ?? (await d.reader.head(detector.headBytes || HEAD_BYTES));
        if (!head) return null;
        const found = await detector.exceeds(format, head.bytes, head.size, (n) => d.reader!.tail(n), d.abort.signal);
        return found && { code: found.code, cause: new Error(found.reason) };
      } catch (error) {
        if (isAbort(error, d.abort.signal)) throw error;
        return null;
      }
    };
    const fail = async (cause: unknown, d: Document | null) => {
      if (ended || isAbort(cause, signal)) return;
      console.warn(`${format ?? "viewer"}: could not render`, cause);
      await report({ code: errorCode(format), cause }, d);
    };

    if ((plugin || sniffed) && doc.reader) {
      const first = doc;
      // The file's bytes arriving, while the plugin says nothing more precise.
      const stopFileProgress = first.reader!.progress.subscribe((p) => {
        const s = status.get();
        if (ended || !p || s.phase !== "loading" || s.label !== undefined || (s.step !== undefined && s.step !== "file")) return;
        status.set(p.total !== null && p.loaded >= p.total ? { phase: "loading" } : { phase: "loading", step: "file", ...(p.total ? { progress: Math.min(1, p.loaded / p.total) } : {}) });
      });
      first.abort.signal.addEventListener("abort", stopFileProgress, { once: true });
      void (async () => {
        try {
          let head: FilePart | null = null;
          if (sniffed) {
            // The first bytes: in place, or by a range request for an address.
            head = await first.reader!.head(detector.headBytes);
            if (ended) return;
            if (head) {
              format = await detector.detectFile(file, head.bytes, head.size, first.abort.signal, (n) => first.reader!.tail(n));
              plugin = plugins.find((p) => p.id === format) ?? null;
              if (ended) return;
            }
          }
          if (!plugin) {
            status.set({ phase: "error", error: { code: errorCode(format) } });
            return;
          }
          const refused = await refusal(first, head);
          if (ended) return;
          if (refused) {
            console.warn(`${format ?? "viewer"}: refused`, refused.cause);
            status.set({ phase: "error", error: refused });
            return;
          }
          /** The plugin's renderer showing the file, or null when the session ended first. */
          const mountWith = async (chosen: FormatPlugin<unknown>): Promise<RendererHandle | null> => {
            const renderer = await load(chosen);
            if (ended) return null;
            return renderer.mount(host, {
              file,
              options: chosen.options,
              source: first.reader!,
              signal: first.abort.signal,
              assetBase,
              status: (next) => {
                if (ended) return;
                if (next.phase === "error") void report(next.error, first);
                else status.set(next);
              },
              controllers: (next) => {
                if (!ended) controllers.set(next);
              },
              detector,
              mountNested: (h2, f2, options) => {
                const s = mount(h2, f2);
                nested.add(s);
                const stops: (() => void)[] = [];
                if (options?.forward) {
                  forwarding = true;
                  // What the nested session loads is, here, the drawing of the result.
                  const follow = () => {
                    if (ended) return;
                    const n = s.status.get();
                    status.set(n.phase === "loading" ? { phase: "loading", step: "render", ...(n.label !== undefined && { label: n.label }) } : n);
                  };
                  const mirror = () => {
                    if (!ended) controllers.set(s.controllers.get());
                  };
                  stops.push(s.status.subscribe(follow), s.controllers.subscribe(mirror));
                  follow();
                  mirror();
                }
                return {
                  get file() {
                    return s.file;
                  },
                  get format() {
                    return s.format;
                  },
                  status: s.status,
                  controllers: s.controllers,
                  replace: (f3) => s.replace(f3),
                  resize: () => s.resize(),
                  destroy() {
                    for (const stop of stops) stop();
                    nested.delete(s);
                    s.destroy();
                  },
                };
              },
            });
          };
          let h: RendererHandle | null;
          try {
            h = await mountWith(plugin);
          } catch (error) {
            // The engine found the bytes are another format: the file is
            // routed to that format's engine, once. The second engine's
            // refusal, a mismatch included, is the file's.
            const next = error instanceof FormatMismatch && !isAbort(error, signal) ? plugins.find((p) => p.id === error.format) : undefined;
            if (!next || next === plugin || ended) throw error;
            format = next.id;
            plugin = next;
            h = await mountWith(next);
          }
          if (!h) return;
          if (ended) {
            h.destroy();
            return;
          }
          handle = h;
          if (!forwarding || Object.keys(h.controllers).length > 0) controllers.set(h.controllers);
        } catch (error) {
          await fail(error, first);
        }
      })();
    } else if (!plugin && file.source) {
      status.set({ phase: "error", error: { code: errorCode(format) } });
    }

    return {
      get file() {
        return doc.file;
      },
      get format() {
        return format;
      },
      status,
      controllers,
      async replace(next) {
        // Not mounted yet, or an engine that cannot: the caller starts over.
        if (ended || !handle?.replace || !next.source) return false;
        replacing?.abort.abort();
        const incoming = begin(next);
        replacing = incoming;
        try {
          const refused = await refusal(incoming, null);
          if (refused && !ended && replacing === incoming) {
            console.warn(`${format ?? "viewer"}: refused`, refused.cause);
            close(incoming);
            replacing = null;
            status.set({ phase: "error", error: refused });
            return true;
          }
          await handle.replace({ file: next, source: incoming.reader!, signal: incoming.abort.signal });
        } catch (error) {
          // Superseded or closed: not a failure. Otherwise the old document stays, under the error.
          close(incoming);
          if (replacing === incoming) replacing = null;
          await fail(error, null);
          return true;
        }
        if (ended || replacing !== incoming) {
          close(incoming);
          return true;
        }
        replacing = null;
        close(doc);
        doc = incoming;
        return true;
      },
      resize: () => handle?.resize?.(),
      destroy() {
        if (ended) return;
        ended = true;
        abort.abort();
        for (const s of [...nested]) s.destroy();
        try {
          handle?.destroy();
        } finally {
          handle = null;
          close(doc);
          if (replacing) close(replacing);
        }
      },
    };
  };

  const prefetch = async (formats: readonly FormatId[]) => {
    if (typeof navigator !== "undefined" && navigator.onLine === false) return;
    for (const id of formats) {
      const plugin = plugins.find((p) => p.id === id);
      if (!plugin || prefetched.has(id)) continue;
      prefetched.add(id);
      try {
        await load(plugin);
        const urls = (await plugin.prefetch?.(assetBase)) ?? [];
        let failed = false;
        for (let i = 0; i < urls.length; i += PREFETCH_BATCH) {
          await Promise.all(
            urls.slice(i, i + PREFETCH_BATCH).map((u) =>
              fetch(u)
                .then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(new Error(`HTTP ${r.status}`))))
                .catch(() => (failed = true)),
            ),
          );
        }
        // The rest is fetched anyway; the format is tried again next time.
        if (failed) prefetched.delete(id);
      } catch {
        // Offline or blocked: the next call tries again.
        prefetched.delete(id);
      }
    }
  };

  return { ...detector, plugins, assetBase, mount, prefetch };
}
