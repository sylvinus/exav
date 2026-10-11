---
title: Security
description: "What a hostile file can reach in @exav/viewer: the sandboxed frame and the in-page mode, the guarantees per browser, the headers to serve the frame with, the checks that keep them, and what remains."
---

A file opened in the viewer is untrusted, and so is every engine that
parses it: pdf.js, @silurus/ooxml, three.js, exav's own decoders, the
browser's. The question this
page answers is what a file can reach when one of them is made to run its
code: the host page, its session and its data, or a way to send anything
out.

## Two modes

| | Sandboxed frame | In the page |
|---|---|---|
| Set up with | `SandboxedViewerProvider sandbox` (`@exav/viewer/react/sandbox`), `createSandboxedViewer` (`@exav/viewer/frame`) | `ViewerProvider plugins`, `createViewer` |
| The engines run in | an `<iframe sandbox="allow-scripts">` per file, in an opaque origin | the host's page, in its origin |
| A compromised engine reaches | its own frame: the file it was given, and nothing else | the host's DOM, cookies, storage, and same-origin requests with them |
| Engines bundled by | the package (`dist/frame/app/`, built with it) | the host, from the peers it installs |
| Plugin options | plain data only | anything, functions included (overlays, `detail`, `onTap`) |
| A link the user follows in a document | opened by the host, after its question (`confirmLink`) | opened by the engine in a new tab (`noopener,noreferrer`), without a question |
| Extra serving | the frame's directory, with its headers | none |

The in-page mode stays for hosts that cannot serve a second origin or need
the image surface's overlays. It runs under the host's
[Content-Security-Policy](/viewer/integration/#content-security-policy)
and the checks below, but a bug in an engine there is a bug in the host.

## The sandboxed frame

```tsx
import { ViewerBody } from "@exav/viewer/react";
import { SandboxedViewerProvider } from "@exav/viewer/react/sandbox";

const sandbox = { url: "https://viewer-frame.example-files.com/index.html" };

<SandboxedViewerProvider sandbox={sandbox} locale="en">
  <ViewerBody file={file} />
</SandboxedViewerProvider>
```

The default UI (rails, pager, archive list, dialog) stays in the host page;
what the engine draws is in the frame.

### What makes it hold

These are properties of the browser, not of the viewer's code:

- **Opaque origin.** The iframe has `sandbox="allow-scripts"` and no
  `allow-same-origin`: its origin is `"null"`. It has no cookies and no
  storage (`document.cookie`, `localStorage`, `sessionStorage` and
  IndexedDB throw), it cannot touch the host's document, and every request
  it makes is cross-origin, without credentials.
- **No way out of the frame.** Without `allow-popups`,
  `allow-top-navigation`, `allow-downloads`, `allow-forms` or
  `allow-modals`, it cannot open a window, navigate the page, start a
  download, submit a form or show a dialog. `allow=""` refuses it every
  powerful feature (camera, microphone, location, clipboard, fullscreen,
  payment...).
- **Its own policy.** The frame's page is served with this
  Content-Security-Policy:

  ```
  default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src blob:;
  connect-src 'self'; img-src 'self' blob: data:; font-src 'self' blob: data:;
  media-src blob:; style-src 'self' 'sha256-cNjvEN1YtFd5aB7iXA1oXslKUFoYbgxutdTl7pOEOTA=';
  base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none';
  require-trusted-types-for 'script'; trusted-types exav-worker default
  ```

  No `eval` or `new Function`; nothing fetched, shown or played from
  another origin; no plugin, no nested frame. `style-src` allows one inline
  stylesheet by its hash: the spreadsheet engine's own, checked against the
  installed engine when the package is built. Origins given when the frame
  is deployed (below) are added: media origins to `img-src` and
  `media-src`, connect origins to `connect-src`. None by default.
- **Trusted Types.** Every sink that turns a string into markup or a script
  URL needs a policy's value. There are two: `exav-worker`, which accepts
  only the `blob:` URLs the frame makes to start its workers, and
  `default`, which accepts what the engines write into `innerHTML` when it
  is inert SVG (shapes and their geometry and paint, no event handler, no
  link, no style, no text) and refuses the rest. The Office engine clears
  elements and draws an arrow that way, the IFC engine its logo.
- **One frame per file.** A new file gets a new frame; closing a file
  removes its frame, and its workers, wasm memory and WebGL contexts go
  with it. Nothing of one file is in the realm the next one opens in.

### The messages

The host makes a `MessageChannel` and hands one port to the frame in its
only `window.postMessage`, which names no origin (an opaque origin cannot
be named) and carries nothing else. Everything else goes over the port:

| From | Messages |
|---|---|
| host | `open` (the file as its delivery says, below; its name and type, the formats, the plugin options as plain data), `command` (go to a page, zoom, fit, a layer on or off, a layout, the ground, open or leave an archive member), `bytes` (the answer to a `read`) |
| frame | `ready` (with its page's policy), `status`, `controllers` and `state` (each controller's value), `done` (a command finished), `link`, `read` and `cancel` (bytes of a file read by ranges) |

The host treats every message from the frame as hostile: each is checked
against the protocol's shapes (`ts/frame/protocol.ts`), copied field by
field, and dropped whole if any part does not match. Strings have length
limits and lists item limits; a colour must be hex, `rgb()` or `hsl()` of
numbers (a CSS value could otherwise be a `url()` the host would fetch);
message keys are plain words. The default UI shows every string as text.
A frame that loads a second document, having navigated itself away, is
removed and its file reported unreadable.

A link the user follows in a document (a PDF's links, Word, Excel and
PowerPoint hyperlinks) becomes a `link` message. The host takes absolute `http:` and
`https:` URLs only, asks first (`confirmLink`, by default the browser's
`confirm`, translated in the React UI), one question at a time, and opens
it with `noopener,noreferrer`. Downloads and "open in a new tab" are the
host's, from the URLs and bytes it already has.

### How a file reaches the frame

`createSandboxedViewer({ delivery })` (and `SandboxedViewerProvider sandbox`)
choose it per kind of file:

```ts
delivery: {
  media: "url" | "blob",            // video, audio
  images: "url" | "blob",           // PNG, JPEG, GIF, WebP: what browsers decode
  pdf: "ranges" | "blob" | "url",
  archive: "ranges" | "blob",
}                                   // every other format: "blob"
```

Defaults: PDF and archives `"ranges"`; video, audio and images `"url"` when
the file's URL is on one of `origins.media`, else `"blob"`. With no origins
configured, the frame can reach nothing beyond its own files, whatever the
delivery.

| Delivery | The frame is given | It can | It cannot |
|---|---|---|---|
| `"blob"` | the whole file, read by the host | read that file | reach the network, see the file's URL or the host's credentials |
| `"ranges"` | the size and the first 64 KiB; the rest when it asks, over the port | read any part of that file; make the host read parts of it again, up to 8 reads and 16 MiB outstanding at once | name another file or address (the host reads its own source, with its `init` and its re-signing), reach the network, see the URL |
| `"url"`, media and images | the file's address, on an `origins.media` origin | show or play anything on those origins in `<img>`, `<video>`, `<audio>`, without CORS; learn the address (a signed URL's query included); see an image's size, a video's duration; send requests to those origins with whatever it puts in their URLs | read the bytes (a cross-origin image taints a canvas), fetch from those origins |
| `"url"`, PDF | the file's address, on an `origins.connect` origin | fetch anything on those origins, and read what answers CORS to any origin (`Access-Control-Allow-Origin: *` or `null`); send requests to them with what it likes in them | send cookies (an opaque origin has none, and its requests are cross-site) |

`"url"` for a PDF is opt-in and weaker than `"ranges"`: a compromised
frame reads whatever its connect origins serve to an anonymous CORS
request. Give it an origin that serves only files meant for the user, by
signed URLs.

For `"ranges"`, the host treats every `read` as hostile: offsets and lengths
must be whole numbers, within the file, at most 4 MiB, with at most 8 reads
and 16 MiB outstanding; anything else is refused, and the frame's own
client keeps to the same limits. A read the frame cancels, or every read of
a session that ends, is aborted. The host checks each answer from the
server (`206`, the `Content-Range` asked, as many bytes); a server that
answers the first range request with the whole file (`200`), or without a
`Content-Range` it can read, gets a whole download instead, and the viewer
says so (a `source_read_whole` warning), as does the console.

For `"url"`, the host gives only an absolute `http(s)` address, without
credentials in it, from a source without `init` (an element cannot send
headers), on one of the origins the frame's policy names. With an explicit
`"url"`, any other address is an error before the frame gets anything; by
default, the file goes as a `Blob`. The image engine shows such an image
without `crossOrigin`, so nothing in the frame reads its pixels back.

The origins are fixed where the frame is deployed: its policy is a header
or its page's meta tag, not something the host can change at run time.
When it starts, the frame reports its page's policy; the host compares its
own `origins` with it and refuses a frame whose media or connect sources
are not exactly those (its own origin aside), with an error naming the
difference, rather than leave the policy to block requests quietly. A policy
served as a header only cannot be read by the frame: keep the meta tag the
deploy step writes in step with the headers.

### Serving the frame

The frame app is in the package, built: `dist/frame/app/`. The Vite plugin
publishes it with `exavViewer({ frameDir: "exav-frame" })`; other bundlers
copy it with `npx exav-viewer-assets public/exav-viewer --frame
public/exav-frame` ([Integration](/viewer/integration/#the-sandboxed-frame)).

Serve it from a registrable domain of its own that sets no cookies
(`example-files.com` beside `example.com`, as user content is often
served). The opaque origin already isolates it from the host's origin,
wherever it is served from; a separate site adds two things: the frame's
`connect-src 'self'` then reaches only the frame's own files (requests from
it carry no cookies, but a host endpoint that trusts its network position
would answer), and Chromium puts a cross-site frame in a process of its
own.

Every file under the frame's directory gets these headers:

| Header | Value |
|---|---|
| `Content-Security-Policy` | the policy above, then `; frame-ancestors https://app.example.com; sandbox allow-scripts` |
| `Permissions-Policy` | every feature refused: `accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), storage-access=(), usb=(), window-management=(), xr-spatial-tracking=()` |
| `Referrer-Policy` | `no-referrer` |
| `X-Content-Type-Options` | `nosniff` |
| `Access-Control-Allow-Origin` | `*`: required, the opaque-origin frame and its workers fetch their own scripts and wasm in CORS mode |
| `Cross-Origin-Resource-Policy` | `cross-origin`, for a host that sets `Cross-Origin-Embedder-Policy` |

`frame-ancestors` (which hosts may embed the frame) and `sandbox` (the
frame stays sandboxed even when opened on its own) work only as headers. The
frame's `index.html` carries the policy in a meta tag as well, for static
hosts that set no headers (GitHub Pages): there, the iframe's `sandbox`
attribute is what isolates it. `frameHeaders(frameAncestors, origin)` from
`@exav/viewer/frame` returns these headers, and the Vite plugin sets them
in development and `vite preview`.

WebKit matches `'self'` against nothing in a document whose origin is
opaque, where Chromium and Firefox match the document's URL. For Safari,
give the frame's own origin: `exavViewer({ frameOrigin })`,
`exav-viewer-assets --frame-origin`, or `frameCsp(origin)` in the headers;
it is written beside `'self'`.

The origins of `"url"` delivery go the same way: `exavViewer({
mediaOrigins, connectOrigins })`, `exav-viewer-assets --media-origin <o>
--connect-origin <o>` (each repeatable; the command prints the policy for
the headers), or `frameHeaders(frameAncestors, origin, { media, connect })`.
The viewer is given the same lists as `origins`.

nginx (the frame on its own site; `Permissions-Policy` abridged, take the
full list above):

```nginx
location /exav-frame/ {
    add_header Content-Security-Policy "default-src 'none'; script-src 'self' https://viewer-frame.example-files.com 'wasm-unsafe-eval'; worker-src blob:; connect-src 'self' https://viewer-frame.example-files.com; img-src 'self' https://viewer-frame.example-files.com blob: data:; font-src 'self' https://viewer-frame.example-files.com blob: data:; media-src blob:; style-src 'self' https://viewer-frame.example-files.com 'sha256-cNjvEN1YtFd5aB7iXA1oXslKUFoYbgxutdTl7pOEOTA='; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; require-trusted-types-for 'script'; trusted-types exav-worker default; frame-ancestors https://app.example.com; sandbox allow-scripts" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(), clipboard-write=(), fullscreen=()" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Access-Control-Allow-Origin "*" always;
    add_header Cross-Origin-Resource-Policy "cross-origin" always;
    types { application/wasm wasm; text/javascript js mjs; }
}
```

Caddy:

```
@frame path /exav-frame/*
header @frame {
	Content-Security-Policy "default-src 'none'; script-src 'self' https://viewer-frame.example-files.com 'wasm-unsafe-eval'; worker-src blob:; connect-src 'self' https://viewer-frame.example-files.com; img-src 'self' https://viewer-frame.example-files.com blob: data:; font-src 'self' https://viewer-frame.example-files.com blob: data:; media-src blob:; style-src 'self' https://viewer-frame.example-files.com 'sha256-cNjvEN1YtFd5aB7iXA1oXslKUFoYbgxutdTl7pOEOTA='; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; require-trusted-types-for 'script'; trusted-types exav-worker default; frame-ancestors https://app.example.com; sandbox allow-scripts"
	Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(), clipboard-write=(), fullscreen=()"
	Referrer-Policy "no-referrer"
	X-Content-Type-Options "nosniff"
	Access-Control-Allow-Origin "*"
	Cross-Origin-Resource-Policy "cross-origin"
}
```

The policy's hash changes when the spreadsheet engine's stylesheet does;
take the strings from `frameHeaders` rather than from this page when the
package is updated. The frame's files are named without hashes: serve them
`Cache-Control: no-cache`, or under a path with the package's version.

The host page needs `frame-src` (or `child-src`) to allow the frame's
origin. In this mode it needs none of what the engines need: no
`'wasm-unsafe-eval'`, no `worker-src blob:`, no `blob:` sources.

## Per browser

The frame's guarantees are asserted from inside the frame
(`e2e/frame.spec.ts`), served with its headers and again with its meta
policy alone, and its deliveries from the network (`e2e/delivery.spec.ts`:
who fetched what, in which ranges, how much of the file), in each browser
Playwright runs:

| Guarantee | Chromium | Firefox | WebKit |
|---|---|---|---|
| opaque origin, no referrer | tested | tested | tested |
| no cookie, storage or access to the parent | tested | tested | tested |
| no `eval`, `new Function`, string timer, `data:` import | tested | tested | tested |
| Trusted Types: no markup or script URL from a string | tested | tested | tested |
| nothing fetched, loaded or sent elsewhere (fetch, image, font, WebSocket, beacon) | tested | tested | tested |
| no popup, top navigation, download or form | tested | tested | tested |
| links only through the host, asked first, `noopener` | tested | tested | tested |
| a video by URL plays and seeks from its origin; an address elsewhere refused by the host and blocked by the policy | tested | tested | tested |
| a PDF and a ZIP by ranges read in part; reads outside the file or the limits refused | tested | tested | tested |
| a frame that navigates away is dropped | tested | tested | tested |
| every format opens | tested | tested, but WebGL formats (DWG, DXF, IFC, STL): no WebGL in the headless Firefox of the test machine | tested |

Browsers implement `Permissions-Policy` unevenly; the iframe's `allow=""`
refuses the same features from the host's side. In Firefox and WebKit, a
frame that tries a download navigates itself to the file instead: the
host's `frame-src` refuses it, and the host drops the frame.

What is structural, in every browser above: the opaque origin, the sandbox
flags, the policy, Trusted Types. What relies on review: the host's checks
of the frame's messages, the frame app's own code (`ts/frame/app/`, which
installs the policies and starts the workers), the default Trusted Types
policy's SVG rule, and the reviewed sinks in the dependencies (below).

## The checks that keep it

`scripts/test-viewer.sh`, in CI:

- **The package's own code** (`ts/`, `demo/src/`): `check-sinks.mjs` reads
  the syntax tree and fails on `eval`, the `Function` constructor, string
  timers, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
  `createContextualFragment`, `parseFromString`, `dangerouslySetInnerHTML`,
  `javascript:` URLs, `window.open`, `postMessage` to `"*"`, event-handler
  attributes, `href` or `src` set from a variable, `import()` or `new
  Worker` of a variable, unless the occurrence is on its reviewed list
  (seven, each with its reason). An entry that matches nothing fails too.
- **The dependencies**, as built into the frame and the demo:
  `check-bundle-sinks.mjs` finds the same sinks in the minified code and
  allows only the reviewed occurrences, each recognised by the code around
  it: React's own `innerHTML` and `dangerouslySetInnerHTML` handling and its
  `javascript:` placeholders, @silurus/ooxml's `innerHTML = ""` clears and
  constant SVG, pdf.js's own XML parser,
  three's `DOMParser` for a response type the viewer never asks for. A
  dependency update that brings another fails the build.
- **WebAssembly**: `check-wasm-imports.mjs` lists, for every module the
  frame and the demo ship, the imports it may have:

  | Module | May import | Memory |
  |---|---|---|
  | exav_viewer_image, exav_viewer_dwg, exav_viewer_model, the two pdf.js decoders | wasm-bindgen's plumbing (errors, its tables): no global, clock, randomness or I/O | capped: 1 GiB, 2 GiB, 3 GiB, 1 GiB, 1 GiB |
  | @exav/unpack-wasm | plumbing, `FileReaderSync` on the archive's `Blob`, a reader function the caller passes, arrays of members | 4 GiB |
  | @silurus/ooxml's three parsers | plumbing, and a panic's message to `console.error` | 4 GiB |
  | pdf.js's qcms | plumbing, a callback copying converted colours out | 4 GiB |

  A new import name, or one of this package's modules without its cap,
  fails the build.
- **Memory caps.** exav's modules are linked with a maximum
  (`--max-memory` in `scripts/build-wasm.sh`): past it an allocation
  fails, the module traps, its worker reports the file unreadable and is
  replaced. 1 GiB for images (the default decode limit is 256 MiB of
  RGBA, and the file, the decoded pixels and their RGBA copy are held at
  once), 2 GiB for drawings (the largest real drawing measured, 14 MB with
  75 layouts, peaks at 1.2 GiB), 3 GiB for IFC and STL models (the file,
  its index and the meshes twice for the default 6 million triangles fit in
  1.5), 1 GiB for each image pdf.js hands its
  decoders. A test decodes a picture whose RGBA copy needs more than its
  module's cap, and expects the trap and a fresh instance to work.
- **The policies, in the browser**: the demo's browser tests run each
  format in the frame under its policy, and fail on any violation any of
  its documents reports; the frame's guarantees run in Chromium, Firefox
  and WebKit. Each was seen to fail with its guarantee removed: the
  iframe's `sandbox` attribute (served with the meta policy alone, the
  frame reads the page's cookie), Trusted Types (`innerHTML` runs), `eval`
  allowed, `connect-src *`.

## What remains

- **Denial of service.** A file can keep its engine busy or make it use
  memory up to the caps (exav's modules) or to what the browser allows (the
  others) inside its frame. Timeouts stop exav's decoders; the frame is
  removed when the user moves on. In Chromium a cross-site frame has a
  process of its own; a same-site one may share the host's.
- **Misleading content.** A document draws what it likes in its frame,
  including what looks like the host's own UI or a message telling the user
  to visit an address. It cannot submit a form, open a window or send
  anything; its links go through the host's question.
- **The clipboard.** On a key press or a click in it, a frame can put
  text on the clipboard, as any page can: the copy of a selection, or of a
  spreadsheet's cells, goes through it. It reads the clipboard only from a
  paste the user makes into it.
- **What the host is told.** Layer names, outline titles, member names,
  page counts come from the document by design. They reach the host as
  checked text.
- **The frame's origin.** The frame can read any file its own origin
  serves, without credentials: serve nothing else there.
- **Delivery by URL.** Each media or connect origin is a place the frame can
  send requests to, with what it likes in their URLs, and, for connect
  origins, read from. Name only origins that serve the files themselves.
- **Reads by ranges.** A frame can make the host read its file again and
  again, within the limits on what is outstanding: traffic, not access.
- **Browsers.** A bug in the browser's sandbox, or a side channel between
  processes, is out of this design's reach; a separate site for the frame
  keeps it in another process where the browser isolates sites.
- **Static hosts.** Without headers, `frame-ancestors` and the CSP
  `sandbox` are absent: any page may embed the frame (it waits for a
  host's message and opens nothing on its own), and isolation rests on the
  embedding page's `sandbox` attribute.
