/**
 * What the Markdown reader (exav-render's `markdown`, in `exav_viewer_text.wasm`)
 * gives back: a tree of data, never markup. Raw HTML in a document is text
 * in it, an image is its alt text, and a link is kept by the reader only
 * when its target is an absolute http, https or mailto address; `safeTarget`
 * checks it again with the browser's own URL reader, which is the one that
 * will follow it.
 */

export type Inline =
  | { t: "text"; s: string }
  | { t: "code"; s: string }
  | { t: "br" }
  | { t: "em" | "strong" | "del"; c: Inline[] }
  | { t: "link"; url: string; c: Inline[] }
  | { t: "image"; alt: string };

export type Block =
  | { t: "p"; c: Inline[] }
  | { t: "h"; level: number; c: Inline[] }
  | { t: "code"; s: string }
  | { t: "hr" }
  | { t: "quote"; c: Block[] }
  | { t: "list"; ordered: boolean; start: number; tight: boolean; items: Block[][] }
  | { t: "table"; align: ("left" | "center" | "right" | null)[]; head: Inline[][]; rows: Inline[][][] }
  | { t: "raw"; s: string };

export interface Parsed {
  blocks: Block[];
  /** The node limit was reached: the rest of the document is left out. */
  truncated: boolean;
}

/** The text of inlines, without their marks. */
export function plain(nodes: Inline[]): string {
  let s = "";
  for (const n of nodes) {
    if (n.t === "text" || n.t === "code") s += n.s;
    else if (n.t === "image") s += n.alt;
    else if (n.t !== "br") s += plain(n.c);
  }
  return s;
}

/** White space, controls, line and paragraph separators and bidirectional controls: none may be in a target. */
function unsafeChar(c: number): boolean {
  return c <= 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029 || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
}

/**
 * The normalised address when `dest` is an absolute http, https or mailto URL
 * without credentials (`https://bank.example@evil.example` is refused), else
 * `null`. Relative paths, `javascript:`, `data:`, `file:`, `vbscript:` and
 * every other scheme give `null`.
 */
export function safeTarget(dest: string): string | null {
  if (dest.length === 0 || dest.length > 2048) return null;
  for (let i = 0; i < dest.length; i++) if (unsafeChar(dest.charCodeAt(i))) return null;
  let url: URL;
  try {
    url = new URL(dest);
  } catch {
    return null;
  }
  if (url.username || url.password) return null;
  if (url.protocol === "mailto:") return url.pathname ? url.href : null;
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  return url.hostname ? url.href : null;
}
