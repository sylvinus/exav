/**
 * A JSON pretty printer that works on the tokens and copies each one as it
 * is written: numbers keep their text (2^70 or 1.10 are not rounded by a
 * parse and a stringify), strings keep their escapes, key order and
 * duplicates stay. Strict: a trailing comma, a comment or a bare word make the
 * text invalid, and `null` is returned.
 */
import { MAX_LINES } from "./decode.js";
import { LineBuilder, type Line } from "./lines.js";

/** Deeper than this is refused: the output indents by two spaces per level. */
export const MAX_DEPTH = 100;

const ESCAPES = '"\\/bfnrtu';

/** The lines of `text` indented, or `null` when it is not valid JSON (or nests deeper than `MAX_DEPTH`). */
export function formatJson(text: string, maxLines = MAX_LINES): { lines: Line[]; more: boolean } | null {
  const out = new LineBuilder(maxLines);
  const n = text.length;
  let i = 0;
  /** true for an object, false for an array. */
  const stack: boolean[] = [];
  const indent = () => "  ".repeat(stack.length);
  const ws = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13) i++;
      else break;
    }
  };

  /** The end of the string starting at `i`, or -1. */
  const stringEnd = (): number => {
    let j = i + 1;
    while (j < n) {
      const c = text.charCodeAt(j);
      if (c === 34) return j + 1;
      if (c < 0x20) return -1;
      if (c === 92) {
        const e = text[j + 1];
        if (e === undefined || !ESCAPES.includes(e)) return -1;
        if (e === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(j + 2, j + 6))) return -1;
          j += 6;
        } else j += 2;
      } else j++;
    }
    return -1;
  };

  const digits = (j: number): number => {
    const start = j;
    while (j < n && text.charCodeAt(j) >= 48 && text.charCodeAt(j) <= 57) j++;
    return j === start ? -1 : j;
  };

  /** The end of the number starting at `i`, or -1. */
  const numberEnd = (): number => {
    let j = i;
    if (text[j] === "-") j++;
    if (text[j] === "0") j++;
    else {
      const d = digits(j);
      if (d < 0) return -1;
      j = d;
    }
    if (text[j] === ".") {
      const d = digits(j + 1);
      if (d < 0) return -1;
      j = d;
    }
    if (text[j] === "e" || text[j] === "E") {
      j++;
      if (text[j] === "+" || text[j] === "-") j++;
      const d = digits(j);
      if (d < 0) return -1;
      j = d;
    }
    return j;
  };

  type State = "value" | "key" | "after" | "end";
  // Set by `valueDone` too: typed so that the flow analysis does not narrow it.
  let state = "value" as State;

  const valueDone = () => {
    state = stack.length ? "after" : "end";
  };

  for (;;) {
    ws();
    if (i >= n) break;
    const ch = text[i]!;
    if (state === "end") return null;
    if (state === "key") {
      if (ch !== '"') return null;
      const e = stringEnd();
      if (e < 0) return null;
      out.add(text.slice(i, e), "exav-viewer-text-key");
      i = e;
      ws();
      if (text[i] !== ":") return null;
      i++;
      out.add(": ");
      state = "value";
    } else if (state === "after") {
      const object = stack[stack.length - 1]!;
      if (ch === ",") {
        i++;
        out.add(",");
        out.end();
        out.add(indent());
        state = object ? "key" : "value";
      } else if (ch === (object ? "}" : "]")) {
        i++;
        stack.pop();
        out.end();
        out.add(indent());
        out.add(ch);
        valueDone();
      } else return null;
    } else if (ch === "{" || ch === "[") {
      if (stack.length >= MAX_DEPTH) return null;
      i++;
      ws();
      const close = ch === "{" ? "}" : "]";
      if (text[i] === close) {
        i++;
        out.add(ch + close);
        valueDone();
      } else {
        stack.push(ch === "{");
        out.add(ch);
        out.end();
        out.add(indent());
        state = ch === "{" ? "key" : "value";
      }
    } else if (ch === '"') {
      const e = stringEnd();
      if (e < 0) return null;
      out.add(text.slice(i, e), "exav-viewer-text-str");
      i = e;
      valueDone();
    } else {
      let e = -1;
      let cls = "exav-viewer-text-lit";
      for (const word of ["true", "false", "null"]) if (text.startsWith(word, i)) e = i + word.length;
      if (e < 0) {
        e = numberEnd();
        cls = "exav-viewer-text-num";
      }
      if (e < 0) return null;
      out.add(text.slice(i, e), cls);
      i = e;
      valueDone();
    }
  }
  if (state !== "end") return null;
  out.finish();
  return { lines: out.lines, more: out.full };
}
