/**
 * An XML pretty printer that only reads tokens: no DOM, no entity is
 * expanded (a document's `&xxe;` or nested entities are shown as written), no
 * DTD or stylesheet is fetched or even followed. Used for display, so
 * markup is re-indented where that adds no text, and text is trimmed.
 */
import { MAX_LINES, splitLines } from "./decode.js";
import { LineBuilder, type Line } from "./lines.js";

type Kind = "text" | "comment" | "cdata" | "pi" | "decl" | "open" | "empty" | "close" | "bad";

interface Token {
  kind: Kind;
  end: number;
}

/** A text longer than this is not put on its element's line. */
const INLINE_TEXT = 200;
/** Indentation stops growing here. */
const MAX_INDENT = 100;

const isSpace = (c: number) => c === 32 || c === 9 || c === 10 || c === 13;
const isNameStart = (c: string | undefined) => c !== undefined && (/[A-Za-z_:]/.test(c) || c.charCodeAt(0) >= 0xc0);

/**
 * The token at `at`. A construct with no end becomes a `bad` token that takes
 * the rest of the text, so that no construct is searched for twice.
 */
function token(s: string, at: number): Token {
  const n = s.length;
  if (s[at] !== "<") {
    const next = s.indexOf("<", at);
    return { kind: "text", end: next < 0 ? n : next };
  }
  const until = (kind: Kind, mark: string, from: number): Token => {
    const e = s.indexOf(mark, from);
    return e < 0 ? { kind: "bad", end: n } : { kind, end: e + mark.length };
  };
  if (s.startsWith("<!--", at)) return until("comment", "-->", at + 4);
  if (s.startsWith("<![CDATA[", at)) return until("cdata", "]]>", at + 9);
  if (s[at + 1] === "?") return until("pi", "?>", at + 2);
  if (s[at + 1] === "!") {
    // A declaration; its internal subset sits in brackets and may hold `>`.
    let quote = "";
    let brackets = 0;
    for (let j = at + 2; j < n; j++) {
      const ch = s[j]!;
      if (quote) {
        if (ch === quote) quote = "";
      } else if (ch === '"' || ch === "'") quote = ch;
      else if (ch === "[") brackets++;
      else if (ch === "]") brackets = Math.max(0, brackets - 1);
      else if (ch === ">" && brackets === 0) return { kind: "decl", end: j + 1 };
    }
    return { kind: "bad", end: n };
  }
  const closing = s[at + 1] === "/";
  if (!isNameStart(s[at + (closing ? 2 : 1)])) return { kind: "text", end: at + 1 };
  let quote = "";
  for (let j = at + 2; j < n; j++) {
    const ch = s[j]!;
    if (quote) {
      if (ch === quote) quote = "";
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ">") return { kind: closing ? "close" : s[j - 1] === "/" ? "empty" : "open", end: j + 1 };
  }
  return { kind: "bad", end: n };
}

function nameOf(s: string, at: number): string {
  let j = at + (s[at + 1] === "/" ? 2 : 1);
  const start = j;
  while (j < s.length && !isSpace(s.charCodeAt(j)) && s[j] !== "/" && s[j] !== ">") j++;
  return s.slice(start, j);
}

/** Writes the tag in `s[at..end)` with its parts coloured. */
function writeTag(out: LineBuilder, s: string, at: number, end: number): void {
  const closing = s[at + 1] === "/";
  const name = nameOf(s, at);
  out.add(closing ? "</" : "<");
  out.add(name, "exav-viewer-text-tag");
  let j = at + (closing ? 2 : 1) + name.length;
  const stop = end - 1;
  while (j < stop) {
    const c = s.charCodeAt(j);
    if (isSpace(c)) {
      j++;
      continue;
    }
    if (s[j] === "/") break;
    let k = j;
    while (k < stop && !isSpace(s.charCodeAt(k)) && s[k] !== "=" && s[k] !== "/") k++;
    if (k === j) k = j + 1;
    out.add(" ");
    out.add(s.slice(j, k), "exav-viewer-text-attr");
    j = k;
    while (j < stop && isSpace(s.charCodeAt(j))) j++;
    if (s[j] !== "=") continue;
    out.add("=");
    j++;
    while (j < stop && isSpace(s.charCodeAt(j))) j++;
    const q = s[j];
    let v = j;
    if (q === '"' || q === "'") {
      v = s.indexOf(q, j + 1);
      v = v < 0 || v > stop ? stop : v + 1;
    } else while (v < stop && !isSpace(s.charCodeAt(v))) v++;
    out.add(s.slice(j, v), "exav-viewer-text-str");
    j = Math.max(v, j + 1);
  }
  out.add(s[end - 2] === "/" && !closing ? "/>" : ">");
}

export interface Formatted {
  lines: Line[];
  more: boolean;
  /** Every construct ended and every tag was closed by its own. */
  wellFormed: boolean;
}

/** The lines of `text` indented, or `null` when it does not start with markup. */
export function formatXml(text: string, maxLines = MAX_LINES): Formatted | null {
  const n = text.length;
  let pos = 0;
  while (pos < n && isSpace(text.charCodeAt(pos))) pos++;
  if (text[pos] !== "<") return null;

  const out = new LineBuilder(maxLines);
  const open: string[] = [];
  let wellFormed = true;
  let depth = 0;
  const indent = () => out.add("  ".repeat(Math.min(depth, MAX_INDENT)));

  /** Raw text that may span lines, the first at the indent. */
  const raw = (s: string, cls: string) => {
    const { lines } = splitLines(s, maxLines);
    lines.forEach((l, k) => {
      if (k === 0) indent();
      out.add(l, cls);
      out.end();
    });
  };

  while (pos < n && !out.full) {
    const t = token(text, pos);
    const src = text.slice(pos, t.end);
    switch (t.kind) {
      case "text": {
        const body = src.trim();
        if (body) {
          for (const l of splitLines(body, maxLines).lines) {
            const line = l.trim();
            if (!line) continue;
            indent();
            out.add(line);
            out.end();
          }
        }
        break;
      }
      case "comment":
        raw(src, "exav-viewer-text-comment");
        break;
      case "cdata":
        raw(src, "exav-viewer-text-str");
        break;
      case "pi":
      case "decl":
        raw(src, "exav-viewer-text-meta");
        break;
      case "bad":
        wellFormed = false;
        raw(src, "");
        break;
      case "empty":
        indent();
        writeTag(out, text, pos, t.end);
        out.end();
        break;
      case "close": {
        const name = nameOf(text, pos);
        if (open.pop() !== name) wellFormed = false;
        depth = Math.max(0, depth - 1);
        indent();
        writeTag(out, text, pos, t.end);
        out.end();
        break;
      }
      case "open": {
        const name = nameOf(text, pos);
        // `<a>text</a>` and `<a></a>` stay on one line.
        const a = token(text, t.end);
        const body = a.kind === "text" ? text.slice(t.end, a.end) : "";
        const closeAt = a.kind === "text" ? a.end : t.end;
        const c = token(text, closeAt);
        if (
          (a.kind === "text" || a.kind === "close") &&
          c.kind === "close" &&
          nameOf(text, closeAt) === name &&
          body.length <= INLINE_TEXT &&
          !/[\r\n]/.test(body.trim())
        ) {
          indent();
          writeTag(out, text, pos, t.end);
          out.add(body.trim());
          writeTag(out, text, closeAt, c.end);
          out.end();
          pos = c.end;
          continue;
        }
        indent();
        writeTag(out, text, pos, t.end);
        out.end();
        open.push(name);
        depth++;
        break;
      }
    }
    pos = t.end;
  }
  if (open.length) wellFormed = false;
  out.finish();
  return { lines: out.lines, more: out.full, wellFormed };
}
