/**
 * The frame app's policy: what its page may load and do, and the headers to
 * serve it with. The build writes `FRAME_CSP` into the page's meta tag (for
 * hosts that set no headers); headers are stronger, as only they carry
 * `frame-ancestors` and `sandbox`.
 *
 * WebKit matches `'self'` against nothing in a document whose origin is
 * opaque, where Chromium and Firefox match the document's URL: for Safari the
 * frame's own origin must be written out (`frameCsp(origin)`).
 */

/**
 * The one `<style>` element an engine adds: the spreadsheet engine's own
 * stylesheet (`data-xlsx-viewer-styles`). Allowed by its hash rather than
 * with 'unsafe-inline'; `build-frame.mjs` checks it against the installed
 * engine.
 */
export const OFFICE_STYLE_HASH = "sha256-cNjvEN1YtFd5aB7iXA1oXslKUFoYbgxutdTl7pOEOTA=";

/**
 * Origins the frame may reach besides its own, fixed when it is deployed.
 * `media`: shown or played by URL (`<img>`, `<video>`, `<audio>`), never
 * read. `connect`: fetched, and read where the server allows CORS.
 */
export interface FrameOrigins {
  media?: readonly string[];
  connect?: readonly string[];
}

/** `scheme://host[:port]`, as `URL.origin` writes it. */
export function isOrigin(v: unknown): v is string {
  return typeof v === "string" && /^https?:\/\/[a-z0-9.-]+(:\d{1,5})?$/.test(v);
}

/**
 * - Scripts and fetches only from the frame's own origin and `connect`;
 *   wasm compiled, no `eval`.
 * - Workers only from `blob:` URLs, which the frame makes itself.
 * - Images, fonts and media from its origin or from what it decoded, and
 *   images and media from `media`.
 * - Styles from its origin, and the one stylesheet above.
 * - Trusted Types: `exav-worker` for the workers' blobs, `default` for the
 *   inert SVG some engines write as HTML (see `app/workers.ts`).
 * - No plugins, no nested frames, no forms, no `<base>`.
 */
export function frameCsp(origin?: string, origins: FrameOrigins = {}): string {
  for (const o of [...(origin === undefined ? [] : [origin]), ...(origins.media ?? []), ...(origins.connect ?? [])]) {
    if (!isOrigin(o)) throw new Error(`not an origin: ${o}`);
  }
  const self = origin ? ["'self'", origin] : ["'self'"];
  const media = origins.media ?? [];
  // Each source once, in order.
  const sources = (...s: (string | readonly string[])[]) => [...new Set(s.flat())].join(" ");
  return [
    "default-src 'none'",
    `script-src ${sources(self, "'wasm-unsafe-eval'")}`,
    "worker-src blob:",
    `connect-src ${sources(self, origins.connect ?? [])}`,
    `img-src ${sources(self, "blob:", "data:", media)}`,
    `font-src ${sources(self, "blob:", "data:")}`,
    `media-src ${sources("blob:", media)}`,
    `style-src ${sources(self, `'${OFFICE_STYLE_HASH}'`)}`,
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types exav-worker default",
  ].join("; ");
}

/** The policy with `'self'` alone: Chromium and Firefox. */
export const FRAME_CSP = frameCsp();

/** The sources of a policy's directives that name origins, as the frame reports them. */
export interface FramePolicy {
  script: string[];
  connect: string[];
  img: string[];
  media: string[];
}

/** The directives of `csp` the host checks; the first of each name counts, as in a browser. */
export function readPolicy(csp: string): FramePolicy {
  const directives = new Map<string, string[]>();
  for (const part of csp.split(";")) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name && !directives.has(name.toLowerCase())) directives.set(name.toLowerCase(), sources);
  }
  const get = (name: string) => directives.get(name) ?? [];
  return { script: get("script-src"), connect: get("connect-src"), img: get("img-src"), media: get("media-src") };
}

/**
 * Why the frame's policy (null: its page carries none) does not give the
 * host's origins exactly, or null when it does: each configured origin
 * allowed, and nothing else beyond the frame's own sources. The frame's own
 * origin, written for WebKit, is the one in `script-src`.
 */
export function policyMismatch(policy: FramePolicy | null, origins: FrameOrigins): string | null {
  const media = origins.media ?? [];
  const connect = origins.connect ?? [];
  if (!policy) return media.length || connect.length ? "the frame's page carries no Content-Security-Policy to check its origins against" : null;
  const own = policy.script.filter(isOrigin);
  const problems: string[] = [];
  const check = (directive: string, sources: string[], wanted: readonly string[], base: string[]) => {
    const missing = wanted.filter((o) => !sources.includes(o));
    const extra = sources.filter((s) => !wanted.includes(s) && !base.includes(s) && !own.includes(s));
    if (missing.length) problems.push(`its ${directive} lacks ${missing.join(" ")}`);
    if (extra.length) problems.push(`its ${directive} also allows ${extra.join(" ")}`);
  };
  check("media-src", policy.media, media, ["blob:"]);
  check("img-src", policy.img, media, ["'self'", "blob:", "data:"]);
  check("connect-src", policy.connect, connect, ["'self'"]);
  if (!problems.length) return null;
  return `the frame's policy does not match this viewer's origins (media: ${media.join(" ") || "none"}; connect: ${connect.join(" ") || "none"}): ${problems.join("; ")}`;
}

/** Every powerful feature, refused. */
export const FRAME_PERMISSIONS = [
  "accelerometer",
  "autoplay",
  "camera",
  "clipboard-read",
  "clipboard-write",
  "display-capture",
  "encrypted-media",
  "fullscreen",
  "gamepad",
  "geolocation",
  "gyroscope",
  "hid",
  "identity-credentials-get",
  "idle-detection",
  "local-fonts",
  "magnetometer",
  "microphone",
  "midi",
  "otp-credentials",
  "payment",
  "picture-in-picture",
  "publickey-credentials-create",
  "publickey-credentials-get",
  "screen-wake-lock",
  "serial",
  "storage-access",
  "usb",
  "window-management",
  "xr-spatial-tracking",
]
  .map((f) => `${f}=()`)
  .join(", ");

/**
 * The headers for every file under the frame's directory. `frameAncestors`:
 * the origins allowed to embed it ("'self'" when the host serves it itself).
 * `origin`: the frame's own, for WebKit. `origins`: as given to `frameCsp`.
 *
 * `Access-Control-Allow-Origin: *` is required: the frame's origin is
 * opaque, so its scripts, workers and wasm are fetched cross-origin.
 */
export function frameHeaders(frameAncestors: string, origin?: string, origins?: FrameOrigins): Record<string, string> {
  return {
    "Content-Security-Policy": `${frameCsp(origin, origins)}; frame-ancestors ${frameAncestors}; sandbox allow-scripts`,
    "Permissions-Policy": FRAME_PERMISSIONS,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "*",
    "Cross-Origin-Resource-Policy": "cross-origin",
  };
}
