---
title: Integration
description: "Serving @exav/viewer's assets: the Vite plugin, other bundlers, caching, offline use with a service worker, the reverse proxy and the Content-Security-Policy."
---

`@exav/viewer` fetches nothing from another origin. In the page, its files
reach the browser two ways, and a host deals with each once. In the
sandboxed mode, the frame carries its own ([below](#the-sandboxed-frame)).

## Two kinds of files

**The package's own**: its wasm modules, its workers, the fonts the
drawing renderer uses. The code references each one with
`new URL("...", import.meta.url)`, so the host's bundler finds them, gives
them hashed names and emits them with the rest of the build. A host does
nothing for these. They are fetched when the first file of their format
opens: the DWG module, 1.9 MB (816 KB gzipped), only when a drawing does;
the IFC and STL module, 290 KB (131 KB gzipped), only when a model does.

**The engines' runtime files**, which no import reaches: pdf.js's CMaps,
standard fonts, ICC profiles and image decoders. They come from the host's own `node_modules`, so their
versions are those of the libraries it bundles, and are copied into one
directory, the viewer's `assetBase` (default `/exav-viewer/`), with a
`manifest.json` saying where each is:

```
exav-viewer/
  manifest.json
  pdfjs/6.4.299/{cmaps,standard_fonts,iccs}/...
  pdfjs/6.4.299/wasm-0bd79e32b1/...
```

Each directory is named after the version it came from, and the bytes'
hash where a rebuilt package could keep its version: everything under
`assetBase` but `manifest.json` can be cached forever.

pdf.js's `wasm` directory holds its ICC engine (qcms, Rust) but not its
JPEG 2000 and JBIG2 decoders, OpenJPEG (C) and PDFium's (C++). In their
place are this package's, exav-render's decoders in WebAssembly, as
`openjpeg_nowasm_fallback.js` and `jbig2_nowasm_fallback.js`: the modules
pdf.js imports when its own `.wasm` does not load. Its `openjpeg.wasm` and
`jbig2.wasm` are copied empty, so that they fail to compile at once (pdf.js
warns once per decoder) rather than be requested and answered 404. The
directory is named after this package's decoders too.

Only the engines installed are copied. A host without `pdfjs-dist` gets no
`pdfjs/` directory.

## Vite

```ts
// vite.config.ts
import { exavViewer } from "@exav/viewer/vite";

export default { plugins: [exavViewer()] };
```

The plugin:

- copies the runtime files into the build under `exav-viewer/`, and serves
  them from `node_modules` in development (a missing file there is a 404,
  never the SPA's `index.html`);
- keeps `@exav/viewer`, `@exav/unpack-wasm` and `@silurus/ooxml` out of
  the dev pre-bundler, which would move their code away from the wasm
  beside it;
- builds workers as ES modules.

`assetDir` (default `"exav-viewer"`) changes the directory. It is under
Vite's `base`, so with `base: "/app/"` the viewer's `assetBase` is
`"/app/exav-viewer/"`:

```tsx
<ViewerProvider plugins={plugins} assetBase={`${import.meta.env.BASE_URL}exav-viewer/`}>
```

## Other bundlers

The package installs a command that does the copy:

```bash
npx exav-viewer-assets public/exav-viewer            # from the current project
npx exav-viewer-assets dist/exav-viewer --root ../app
```

Run it at build time, so the copy follows the engines' versions, and serve
the directory at `assetBase`.

The package's own files: webpack 5 follows `new URL("...", import.meta.url)`
and `new Worker(new URL(...))` as they are, with no configuration (the
package's tests build a page with it and draw a DWG and a TIFF), and Parcel
does too. Rollup needs `@web/rollup-plugin-import-meta-assets`, and esbuild
a plugin for it; workers must be bundled as ES modules.

## The sandboxed frame

In the sandboxed mode ([Security](/viewer/security/)) the
engines run in a page of their own, `dist/frame/app/` in the package,
already built with every engine and its runtime files. The host serves that
directory, with its headers, and points the viewer at its `index.html`:

```ts
// vite.config.ts: published under `${base}exav-frame/`
export default { plugins: [exavViewer({ frameDir: "exav-frame", frameOrigin: "https://viewer-frame.example-files.com" })] };
```

```bash
# other bundlers
npx exav-viewer-assets public/exav-viewer --frame public/exav-frame --frame-origin https://viewer-frame.example-files.com
```

```tsx
import { SandboxedViewerProvider } from "@exav/viewer/react/sandbox";

<SandboxedViewerProvider sandbox={{ url: "https://viewer-frame.example-files.com/exav-frame/index.html" }}>
```

`frameOrigin` is where the frame will be served from: it is written into
the frame's policy for Safari, which matches `'self'` against nothing in an
opaque origin. In development and `vite preview` the plugin serves the
frame with its headers; in production, the host's server sets them
([Serving the frame](/viewer/security/#serving-the-frame)),
or the frame's meta tag carries the policy on a static host.

The frame does not use `assetBase`, `@exav/viewer/vite`'s copy of the
host's engines, or the host's peer dependencies: in this mode a host
installs `@exav/viewer` and, for the default UI, React.

### How the bytes reach the frame

By default the host page reads the file (a URL is fetched from there, with
its `init`, and a `resolve` source is signed there) and the frame never
fetches it:

- a PDF or an archive is read by ranges: the host asks the server for the
  parts the frame needs (pdf.js's pages on screen, a ZIP's central
  directory and the members opened) and passes them over. The server must
  answer range requests (`206`, `Content-Range`; across origins,
  `Access-Control-Expose-Headers: Content-Range`); one that does not gets a
  whole download, and the viewer says so (the `source_read_whole` warning).
  Local files are sliced. Formats other than ZIP are read whole, and so is a
  ZIP the frame cannot read by ranges.
- every other file goes whole.

For a video to stream and seek, or an image to load as the browser loads
one, the frame can be given the file's URL instead. Its origin must be in
the frame's policy, written when the frame is deployed, and in the viewer's
`origins`:

```ts
// vite.config.ts
exavViewer({ frameDir: "exav-frame", frameOrigin, mediaOrigins: ["https://media.example-files.com"] });
```

```bash
npx exav-viewer-assets public/exav-viewer --frame public/exav-frame --frame-origin https://viewer-frame.example-files.com \
  --media-origin https://media.example-files.com
```

```tsx
const sandbox = {
  url: "https://viewer-frame.example-files.com/exav-frame/index.html",
  origins: { media: ["https://media.example-files.com"] },
};
```

Video, audio and images on that origin then go by URL; a URL elsewhere, or
one with `init`, still goes whole. `delivery: { media: "url" }` makes it a
requirement: any other address is an error. The frame's elements request it
without CORS and, from an opaque origin, without cookies the browser would
count on: use public or signed URLs.

A PDF can also go by URL, fetched by pdf.js in the frame with range
requests: `delivery: { pdf: "url" }`, with its origin in `connectOrigins` /
`--connect-origin` and `origins.connect`. The server answers CORS to any
origin (`Access-Control-Allow-Origin: *`), allows the `Range` header and
exposes `Accept-Ranges`, `Content-Range` and `Content-Length`. This lets a
compromised frame read what that origin serves to anyone
([Security](/viewer/security/#how-a-file-reaches-the-frame)).

```ts
createSandboxedViewer({
  url,
  delivery: { media: "url", images: "blob", pdf: "ranges", archive: "ranges" },
  origins: { media: ["https://media.example-files.com"], connect: [] },
});
```

The frame reports its policy when it starts, and the viewer refuses one
whose origins differ from its `origins`: rebuild the frame with the same
flags after changing them.

## Choosing the formats

A host imports the plugins of the formats it opens, from their subpaths,
and installs their engines. Nothing else is resolved by its bundler:

```ts
import { pdf } from "@exav/viewer/pdf";
import { image } from "@exav/viewer/image";

const plugins = [pdf(), image({ wasmDecoders: true })];
```

A file of a format no plugin claims is reported by the detector as `null`:
the host offers a download instead. `viewer.detect(info)` answers from the
name and type alone, synchronously, to decide before opening anything.

`@exav/viewer/all` imports every plugin, so every peer dependency must be
installed.

## Caching and the reverse proxy

| Path | Cache-Control | SPA fallback |
|---|---|---|
| `assetBase` (`/exav-viewer/`), but `manifest.json` | `public, max-age=31536000, immutable` | excluded |
| `assetBase` `manifest.json` | `no-cache` | excluded |
| the bundle's hashed files (`/assets/` in Vite) | `public, max-age=31536000, immutable` | excluded |

Exclude `assetBase` from the SPA fallback: a missing `.wasm` answered with
`index.html` fails as "expected magic word 00 61 73 6d, found 3c 21 64 6f".
`.wasm` must be served as `application/wasm`, or the browser refuses to
compile it while it downloads. With Caddy:

```
root * /srv
@immutable {
	path /assets/* /exav-viewer/*
	not path /exav-viewer/manifest.json
}
header @immutable Cache-Control "public, max-age=31536000, immutable"
header /exav-viewer/manifest.json Cache-Control "no-cache"
handle /exav-viewer/* {
	file_server
}
handle {
	try_files {path} /index.html
	file_server
}
```

## Offline

With a service worker that precaches the build (Workbox's `globPatterns`),
the bundle is cached: every engine's code, workers, wasm and fonts.
`assetBase` holds many small files (pdf.js's CMaps are around 170) that a
precache list is better without; cache them as they are used, and warm them
with `prefetch`:

```ts
// workbox, in vite-plugin-pwa's `workbox` options
globIgnores: ["exav-viewer/**"],
runtimeCaching: [
  {
    urlPattern: ({ url }) => url.pathname.startsWith("/exav-viewer/") && !url.pathname.endsWith("/manifest.json"),
    handler: "CacheFirst",
    options: { cacheName: "exav-viewer", expiration: { maxEntries: 1000 } },
  },
  { urlPattern: ({ url }) => url.pathname === "/exav-viewer/manifest.json", handler: "NetworkFirst" },
],
```

```ts
// once online, for the formats the user will open offline
await viewer.prefetch(["pdf"]);
```

What a precache list should keep out is what is large and used only when a
file of its format is opened: the engines' workers and wasm (`*.worker-*.js`,
`*_bg-*.wasm`, whose names keep a stable prefix after the bundler hashes
them), `three`, the `@silurus/ooxml` engines and the CAD fonts. On a real
app this was 21.8 MB of precache against 3.6 MB without them; the
runtime cache above takes them when a file needs them.

`prefetch` loads each format's code and fetches the assets its plugin
lists, six at a time; for PDF, the CMaps, standard fonts, ICC profiles and
decoders. It does each format once per page, and a format whose fetch
failed is tried again on the next call.

## Content-Security-Policy

In the sandboxed mode, the host page runs no engine: its policy needs only
`frame-src` for the frame's origin, and the frame has its own
([Security](/viewer/security/#serving-the-frame)). In the
page, every format needs:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' blob: data:;
font-src 'self' blob: data:;
media-src 'self' blob:;
worker-src 'self' blob:;
connect-src 'self' blob: data:;
object-src 'none';
base-uri 'self'
```

- `'wasm-unsafe-eval'` lets the page compile WebAssembly: the engines'
  modules run in its workers. It does not allow `eval`.
- `worker-src blob:` and `style-src 'unsafe-inline'` are for the Office
  engine only, which starts workers from blob URLs and writes `<style>`
  elements; without it, `'self'` alone for both.
- `blob:` in `img-src` and `media-src`: a file given as a `Blob` or bytes is
  shown from an object URL the session revokes when it ends.

pdf.js is opened with `isEvalSupported: false`, so it never compiles a
PDF's PostScript functions or fonts with `new Function`, and its scripting
is never loaded: a document's JavaScript does not run. The Office plugin's
`useGoogleFonts` must stay `false` (the default) under this policy.

The demo is served with this policy, and its frame with the frame's; its
browser tests run each file both ways and fail on any violation a page or
frame reports.

## Files and where their bytes come from

```ts
{ id: "42", name: "plan.dwg", source: { url: "/files/42" } }              // fetched by the engine
{ id: "42", name: "plan.dwg", source: { blob: file } }                    // a File from an <input> or a drop
{ id: "42", name: "plan.dwg", source: { bytes } }                         // a Uint8Array
{ id: "42", name: "plan.dwg", source: { resolve: (signal) => sign(42) } } // a URL signed when opened
{ id: "42", name: "plan.pdf", source: { ranges: { size, read } } }         // read by offset, on demand
```

`id` is the file's identity: a new id is a new session, which frees the
previous one's workers and WebGL context. `type`, when the host knows it,
is trusted over the extension; `path` (a storage key a user cannot rename)
over `name` for the extension. A `url` source is fetched by the engines
that stream (pdf.js, `<img>`, `<video>`) and read whole by the others.
`init` passes headers or credentials to the fetch: a PDF or an image with
`init` is then read whole rather than streamed, since pdf.js's and `<img>`'s
own requests cannot carry it. `<video>` and `<audio>` cannot either: give
them a URL that needs no headers (a signed one, through `resolve`). A
`ranges` source is read by pdf.js and the ZIP reader as they need it, and
whole by the other engines. A file whose bytes are not there yet has
`source: null` and a `placeholder`.

Files from users are untrusted. Every engine bounds what a file may cost:
the image decoders refuse more than 256 MiB of pixels (`maxDecodeBytes`),
a drawing's layout stops at eight million strokes and fill vertices
(`maxPrimitives`; lower it for devices with little memory) and a DWG's
compressed sections at 512 MiB expanded (`maxDecompressedBytes`), archives stop at 512 MiB extracted, 5000 members and a ratio of 200 (the
`archive()` options). exav's own decoders run in workers, and one that
fails on a file is replaced for the next; the page is not affected.
