import { createDetector } from "./detect.js";
import { createSourceReader, type OwnedSourceReader } from "./source.js";
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
  ifc: "model",
  stl: "model",
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
  const detector = createDetector(plugins.map((p) => ({ id: p.id, match: p.match })));
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
    const format = file.format ?? detector.detect(file);
    const plugin = plugins.find((p) => p.id === format) ?? null;
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

    const fail = (error: unknown, code = errorCode(format)) => {
      if (ended || isAbort(error, signal)) return;
      console.warn(`${format ?? "viewer"}: could not render`, error);
      status.set({ phase: "error", error: { code, cause: error } });
    };

    if (plugin && doc.reader) {
      const first = doc;
      void (async () => {
        try {
          const renderer = await load(plugin);
          if (ended) return;
          const h = await renderer.mount(host, {
            file,
            options: plugin.options,
            source: first.reader!,
            signal: first.abort.signal,
            assetBase,
            status: (next) => {
              if (!ended) status.set(next);
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
                const follow = () => {
                  if (!ended) status.set(s.status.get());
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
                format: s.format,
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
          if (ended) {
            h.destroy();
            return;
          }
          handle = h;
          if (!forwarding || Object.keys(h.controllers).length > 0) controllers.set(h.controllers);
        } catch (error) {
          fail(error);
        }
      })();
    } else if (!plugin && file.source) {
      status.set({ phase: "error", error: { code: errorCode(format) } });
    }

    return {
      get file() {
        return doc.file;
      },
      format,
      status,
      controllers,
      async replace(next) {
        // Not mounted yet, or an engine that cannot: the caller starts over.
        if (ended || !handle?.replace || !next.source) return false;
        replacing?.abort.abort();
        const incoming = begin(next);
        replacing = incoming;
        try {
          await handle.replace({ file: next, source: incoming.reader!, signal: incoming.abort.signal });
        } catch (error) {
          // Superseded or closed: not a failure. Otherwise the old document stays, under the error.
          close(incoming);
          if (replacing === incoming) replacing = null;
          fail(error);
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
