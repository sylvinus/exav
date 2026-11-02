import { TEXT_KINDS } from "../core/formats.js";
import { writable } from "../core/store.js";
import type { Renderer } from "../core/types.js";
import { clip, decodeText, MAX_BYTES, MAX_LINE, MAX_LINES, sanitize, splitLines } from "./decode.js";
import { formatJson } from "./json.js";
import { lineLength, type Line } from "./lines.js";
import type { Parsed } from "./markdown.js";
import { readMarkdown } from "./markdown-engine.js";
import { drawBlocks } from "./markdown-view.js";
import { formatXml } from "./xml.js";

export type TextKind = keyof typeof TEXT_KINDS;

/** How `path` (or, failing that, `type`) says the text is to be shown. */
export function kindOf(path: string, type = ""): TextKind {
  const p = path.toLowerCase();
  const t = type.toLowerCase().split(";")[0]!.trim();
  const kinds = Object.entries(TEXT_KINDS) as [TextKind, (typeof TEXT_KINDS)[TextKind]][];
  return (
    kinds.find(([, m]) => m.extensions.some((e) => p.endsWith(e)))?.[0] ?? kinds.find(([, m]) => m.types.includes(t))?.[0] ?? "plain"
  );
}

/** Lines drawn together, in one element that the browser may skip while it is off screen. */
const CHUNK = 200;
/** Chunks drawn before the first paint; the others follow without blocking. */
const FIRST_CHUNKS = 5;
/** Time the following chunks may take before the page gets a turn. */
const SLICE_MS = 12;

/** A diff line's class: what it adds, removes or introduces. */
function diffClass(line: string): string | undefined {
  if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ") || line.startsWith("index ")) return "exav-viewer-text-meta";
  if (line.startsWith("@@")) return "exav-viewer-text-hunk";
  if (line[0] === "+") return "exav-viewer-text-add";
  if (line[0] === "-") return "exav-viewer-text-del";
  return undefined;
}

/** Draws `lines[from, to)` as one block of text. */
function chunk(lines: Line[], from: number, to: number): HTMLElement {
  const pre = document.createElement("pre");
  pre.className = "exav-viewer-text-chunk";
  let buffer = "";
  const flush = () => {
    if (buffer) pre.appendChild(document.createTextNode(buffer));
    buffer = "";
  };
  for (let i = from; i < to; i++) {
    if (i > from) buffer += "\n";
    const line = lines[i]!;
    if (typeof line === "string") {
      buffer += line;
      continue;
    }
    for (const [text, cls] of line) {
      if (!cls) buffer += text;
      else {
        flush();
        const span = document.createElement("span");
        span.className = cls;
        span.textContent = text;
        pre.appendChild(span);
      }
    }
  }
  flush();
  return pre;
}

/** `line` cut to `MAX_LINE` characters; null when it already fits. */
function clipped(line: Line): Line | null {
  if (lineLength(line) <= MAX_LINE) return null;
  if (typeof line === "string") return clip(line);
  const out: [string, string?][] = [];
  let room = MAX_LINE;
  for (const [text, cls] of line) {
    if (room <= 0) break;
    out.push([clip(text, room), cls]);
    room -= text.length;
  }
  return out;
}

export const renderer: Renderer<Record<string, never>> = {
  async mount(host, ctx) {
    ctx.status({ phase: "loading" });
    const blob = await ctx.source.blob();
    const partial = blob.size > MAX_BYTES;
    const bytes = new Uint8Array(await blob.slice(0, MAX_BYTES).arrayBuffer());
    if (ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
    const decoded = decodeText(bytes, partial);
    if (!decoded) {
      ctx.status({ phase: "error", error: { code: "text_binary" } });
      return { controllers: {}, destroy() {} };
    }

    const kind = kindOf(ctx.file.path ?? ctx.file.name, ctx.file.type);
    const text = sanitize(decoded.text);
    const warnings: { key: string; count: number }[] = [];
    let truncated = partial;
    let lines: Line[];
    let markdown: Parsed | null = null;

    const plain = () => {
      const split = splitLines(text);
      truncated ||= split.more;
      return split.lines;
    };
    if (kind === "markdown") {
      const split = splitLines(text);
      truncated ||= split.more;
      lines = split.lines.map((l) => clip(l));
      try {
        markdown = await readMarkdown((lines as string[]).join("\n"), ctx.signal);
        truncated ||= markdown.truncated;
      } catch {
        if (ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
        // The reader failed (its worker was stopped, or the module did not load): the text is shown as it is.
        warnings.push({ key: "text_markdown_failed", count: 1 });
      }
    } else if (kind === "json") {
      // A cut file is not valid JSON: it is not judged.
      const r = partial ? null : formatJson(text);
      if (r) {
        lines = r.lines;
        truncated ||= r.more;
      } else {
        lines = plain();
        if (!partial) warnings.push({ key: "text_not_json", count: 1 });
      }
    } else if (kind === "xml") {
      const r = formatXml(text);
      if (r) {
        lines = r.lines;
        truncated ||= r.more;
        if (!r.wellFormed && !partial) warnings.push({ key: "text_not_xml", count: 1 });
      } else {
        lines = plain();
        warnings.push({ key: "text_not_xml", count: 1 });
      }
    } else if (kind === "diff") {
      lines = plain().map((l): Line => {
        const cls = diffClass(l);
        return cls ? [[l, cls]] : l;
      });
    } else {
      lines = plain();
      if (kind === "html") warnings.push({ key: "text_html_source", count: 1 });
    }
    // The newline that ends the file is not a line.
    if (lines.length > 1 && lineLength(lines[lines.length - 1]!) === 0) lines.pop();

    let cut = 0;
    if (!markdown) {
      lines = lines.map((l) => {
        const c = clipped(l);
        if (c) cut++;
        return c ?? l;
      });
    } else cut = (lines as string[]).filter((l) => l.length > MAX_LINE).length;
    if (truncated) warnings.push({ key: "text_truncated", count: Math.min(lines.length, MAX_LINES) });
    if (cut) warnings.push({ key: "text_long_lines", count: cut });

    const root = document.createElement("div");
    root.className = `exav-viewer-text exav-viewer-text-${kind}`;
    root.tabIndex = 0;
    host.append(root);
    let destroyed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    if (markdown) drawBlocks(root, markdown.blocks);
    else {
      let at = 0;
      const next = (count: number) => {
        for (let k = 0; k < count && at < lines.length; k++) {
          root.appendChild(chunk(lines, at, Math.min(at + CHUNK, lines.length)));
          at += CHUNK;
        }
      };
      next(FIRST_CHUNKS);
      const more = () => {
        timer = undefined;
        if (destroyed || at >= lines.length) return;
        // As many blocks as fit in a slice of time, so that the page stays responsive.
        const start = performance.now();
        do next(1);
        while (at < lines.length && performance.now() - start < SLICE_MS);
        timer = setTimeout(more, 0);
      };
      if (at < lines.length) timer = setTimeout(more, 0);
    }

    ctx.status({ phase: "ready" });
    return {
      controllers: { warnings: writable(warnings) },
      destroy() {
        destroyed = true;
        if (timer !== undefined) clearTimeout(timer);
        root.remove();
      },
    };
  },
};
