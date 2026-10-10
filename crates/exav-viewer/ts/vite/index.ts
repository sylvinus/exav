/**
 * `@exav/viewer/vite`: what a Vite host needs for the viewer.
 *
 * - Copies the engines' runtime files into `assetBase` on build, and serves
 *   them from node_modules in development (see `assets.ts`), with a
 *   `manifest.json` describing them.
 * - With `frameDir`, publishes the sandboxed frame app (`@exav/viewer/frame`)
 *   there, and serves it with its headers in development and preview.
 * - Keeps the packages that reach their own `.wasm` with
 *   `new URL(..., import.meta.url)` out of the dev pre-bundler, which would
 *   move them away from their files.
 * - Builds workers as ES modules: the viewer's workers use `import`.
 */
import fs from "node:fs";
import type { ServerResponse } from "node:http";

import type { Connect, Plugin } from "vite";

import { frameCsp, frameHeaders } from "../frame/policy.js";
import { collectAssets, contentType, frameFileBytes, frameFiles, type Asset } from "./assets.js";

export interface ExavViewerPluginOptions {
  /**
   * The directory the assets are published in, under Vite's `base`. Default
   * "exav-viewer". The viewer's `assetBase` is then `${base}exav-viewer/`:
   * "/exav-viewer/", its default, when `base` is "/".
   */
  assetDir?: string;
  /**
   * The directory the sandboxed frame app is published in, under Vite's
   * `base` ("exav-frame": the frame's `url` is then `${base}exav-frame/`).
   * Not published by default. In production, serve it with the headers the
   * documentation lists, ideally from a domain of its own.
   */
  frameDir?: string;
  /**
   * The origin the frame is served from ("https://viewer.example.com"),
   * written into its policy beside `'self'`: WebKit matches `'self'` against
   * nothing in the frame's opaque origin, so Safari needs it.
   */
  frameOrigin?: string;
  /**
   * Origins the frame may show images and play media from, by URL
   * (`delivery: { media: "url", images: "url" }`). Written into its policy;
   * give the viewer the same `origins.media`.
   */
  mediaOrigins?: string[];
  /**
   * Origins the frame may fetch from (`delivery: { pdf: "url" }`). Written
   * into its policy; give the viewer the same `origins.connect`.
   */
  connectOrigins?: string[];
}

const trim = (dir: string) => `${dir.replace(/^\/+|\/+$/g, "")}/`;

export function exavViewer(options: ExavViewerPluginOptions = {}): Plugin {
  const dir = trim(options.assetDir ?? "exav-viewer");
  const frameDir = options.frameDir === undefined ? null : trim(options.frameDir);
  const origins = { media: options.mediaOrigins ?? [], connect: options.connectOrigins ?? [] };
  // A bad origin fails the build here, not in the browser.
  frameCsp(options.frameOrigin, origins);
  let base = `/${dir}`;
  let frameBase = frameDir && `/${frameDir}`;
  let root = process.cwd();

  /** The frame's files, with its headers, under `frameBase`. */
  const frame = (): Connect.NextHandleFunction => {
    const headers = frameHeaders("'self'", options.frameOrigin, origins);
    return (req, res: ServerResponse, next) => {
      const asked = (req.url ?? "").split("?")[0] ?? "";
      if (!frameBase || !asked.startsWith(frameBase)) return next();
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
      next();
    };
  };

  return {
    name: "exav-viewer",
    // No `apply: "build"`: the dev middleware below would go with it, and
    // every asset would then be answered by the SPA fallback's `index.html`.
    config(config) {
      root = config.root ?? root;
      return {
        optimizeDeps: { exclude: ["@exav/viewer", "@exav/unpack-wasm", "@silurus/ooxml"] },
        worker: { format: "es" },
      };
    },
    configResolved(config) {
      root = config.root;
      // The dev server sees full paths, `base` included. A relative or
      // absolute-URL `base` is not a path the dev server is under.
      const prefix = config.base.startsWith("/") ? config.base.replace(/\/*$/, "/") : "/";
      base = `${prefix}${dir}`;
      frameBase = frameDir && `${prefix}${frameDir}`;
    },
    generateBundle() {
      const { assets, manifest } = collectAssets(root);
      for (const a of assets) this.emitFile({ type: "asset", fileName: `${dir}${a.path}`, source: fs.readFileSync(a.source) });
      this.emitFile({ type: "asset", fileName: `${dir}manifest.json`, source: JSON.stringify(manifest) });
      if (frameDir) for (const f of frameFiles()) this.emitFile({ type: "asset", fileName: `${frameDir}${f.path}`, source: frameFileBytes(f, options.frameOrigin, origins) });
    },
    configurePreviewServer(server) {
      server.middlewares.use(frame());
    },
    configureServer(server) {
      const { assets, manifest } = collectAssets(root);
      const served = new Map<string, Asset>(assets.map((a) => [`${base}${a.path}`, a]));
      if (frameDir) for (const f of frameFiles()) served.set(`${frameBase}${f.path}`, f);
      server.middlewares.use(frame());
      server.middlewares.use((req, res, next) => {
        const asked = (req.url ?? "").split("?")[0] ?? "";
        if (!asked.startsWith(base) && !(frameBase && asked.startsWith(frameBase))) return next();
        // Decoded: a browser may send a name percent-encoded.
        let decoded = asked;
        try {
          decoded = decodeURIComponent(asked);
        } catch {
          // A malformed escape is not one of ours.
        }
        if (decoded === `${base}manifest.json`) {
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify(manifest));
          return;
        }
        const file = served.get(decoded) ?? (frameBase && decoded === frameBase ? served.get(`${frameBase}index.html`) : undefined);
        // Not the SPA fallback's index.html: a missing .wasm must be a 404.
        if (!file) {
          res.statusCode = 404;
          res.end();
          return;
        }
        res.setHeader("Content-Type", contentType(file.source));
        res.end(frameBase && decoded.startsWith(frameBase) ? frameFileBytes(file, options.frameOrigin, origins) : fs.readFileSync(file.source));
      });
    },
  };
}

export default exavViewer;
export { collectAssets, frameFileBytes, frameFiles, type Asset } from "./assets.js";
