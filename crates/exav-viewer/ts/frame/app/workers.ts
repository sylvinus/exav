/**
 * Workers and Trusted Types in the frame.
 *
 * The frame's origin is opaque: `new Worker(url)` on its own scripts throws,
 * and a module worker from a `blob:` URL does not start. A classic worker
 * from a `blob:` URL does. So every worker an engine asks for (ours, pdf.js's,
 * the Office engine's) is started from a blob made here,
 * which holds one `importScripts` of the script the engine named. That script
 * must be one of the frame's own: the frame's build puts a classic bundle
 * where each module worker was.
 *
 * Under `require-trusted-types-for 'script'` a worker's URL must come from a
 * policy: `exav-worker` accepts only the blobs made here. The `default`
 * policy takes what the engines write into `innerHTML` (the Office engine
 * clears elements and draws an arrow) when it is
 * inert SVG, and refuses the rest.
 */

type Policy = { createScriptURL(url: string): unknown };
type Factory = { createPolicy(name: string, rules: Record<string, (value: string) => string | null>): Policy };

const tt = (globalThis as { trustedTypes?: Factory }).trustedTypes;

/** Shapes only: no `<a>`, `<use>`, `<image>`, `<foreignObject>`, `<script>` or `<style>`. */
const SVG_ELEMENTS = new Set(["svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon"]);
/** Geometry and paint: no event handler, no `href`, no `style`. */
const SVG_ATTRIBUTES = new Set([
  "xmlns",
  "viewbox",
  "width",
  "height",
  "x",
  "y",
  "cx",
  "cy",
  "r",
  "rx",
  "ry",
  "x1",
  "y1",
  "x2",
  "y2",
  "d",
  "points",
  "transform",
  "fill",
  "fill-rule",
  "fill-opacity",
  "clip-rule",
  "stroke",
  "stroke-width",
  "stroke-linecap",
  "stroke-linejoin",
  "stroke-opacity",
  "opacity",
  "aria-hidden",
  "aria-label",
]);
const TAG = /<(\/?)([a-zA-Z]+)((?:\s+[a-zA-Z:-]+="[^"<>&]*")*)\s*(\/?)>/y;
const ATTRIBUTE = /\s+([a-zA-Z:-]+)="([^"<>&]*)"/g;

/**
 * HTML a sink may take in the frame: "" (an element cleared), or markup that
 * is SVG shapes and nothing else: tags of `SVG_ELEMENTS` with attributes of
 * `SVG_ATTRIBUTES`, quoted values without markup or entities, whitespace
 * between them. Such a fragment cannot run code or load anything.
 */
export function allowedHtml(html: string): boolean {
  if (html === "") return true;
  if (html.length > 65_536) return false;
  let at = 0;
  let depth = 0;
  while (at < html.length) {
    const space = /\s*/y;
    space.lastIndex = at;
    at += space.exec(html)![0].length;
    if (at >= html.length) break;
    TAG.lastIndex = at;
    const tag = TAG.exec(html);
    if (!tag) return false;
    at = TAG.lastIndex;
    const [, closing, name, attributes, selfClosing] = tag;
    if (!SVG_ELEMENTS.has(name!.toLowerCase())) return false;
    if (closing) {
      if (attributes || selfClosing || depth === 0) return false;
      depth -= 1;
      continue;
    }
    for (const [, attribute] of attributes!.matchAll(ATTRIBUTE)) if (!SVG_ATTRIBUTES.has(attribute!.toLowerCase())) return false;
    if (!selfClosing) depth += 1;
  }
  return depth === 0;
}

/** What a worker's blob runs: the script named, through a policy of its own that accepts only it. */
export function workerBoot(script: string): string {
  const url = JSON.stringify(script);
  return [
    `self.EXAV_SCRIPT = ${url};`,
    "(() => {",
    "  const t = self.trustedTypes;",
    `  const p = t && t.createPolicy("exav-worker", { createScriptURL: (u) => { if (u !== ${url}) throw new TypeError("not this worker's script"); return u; } });`,
    `  importScripts(p ? p.createScriptURL(${url}) : ${url});`,
    "})();",
  ].join("\n");
}

/**
 * Installs the policies and replaces `Worker` with a constructor that starts
 * a classic worker for any script under `base`, and refuses anything else.
 */
export function installWorkers(base: URL): void {
  const ours = new Set<string>();
  tt?.createPolicy("default", { createHTML: (html) => (allowedHtml(html) ? html : null) });
  const policy = tt?.createPolicy("exav-worker", {
    createScriptURL(url) {
      if (!ours.has(url)) throw new TypeError("not a worker this frame made");
      return url;
    },
  });
  const Native = globalThis.Worker;
  class FrameWorker extends Native {
    constructor(url: string | URL, options?: WorkerOptions) {
      const script = new URL(String(url), base);
      if (script.origin !== base.origin || !script.pathname.startsWith(base.pathname) || !/\.m?js$/.test(script.pathname)) {
        throw new TypeError(`not one of the frame's workers: ${script.href}`);
      }
      const blob = URL.createObjectURL(new Blob([workerBoot(script.href)], { type: "text/javascript" }));
      ours.add(blob);
      // Classic, whatever was asked: the build made every worker one.
      super((policy ? policy.createScriptURL(blob) : blob) as string, options?.name ? { name: options.name } : {});
    }
  }
  globalThis.Worker = FrameWorker;
}
