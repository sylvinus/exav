/**
 * Decoded text made safe to show: what could make it lie about itself
 * (control characters, bidirectional overrides) is made visible, and it is cut
 * into lines. What the bytes are as text (their encoding, whether they are
 * text at all) is decided by the text module, `engine.ts`.
 */

/** Bytes of a file that are read. */
export const MAX_BYTES = 2 * 1024 * 1024;
/** Lines shown. */
export const MAX_LINES = 50_000;
/** Characters shown of one line. */
export const MAX_LINE = 10_000;

/**
 * What is not shown as itself: C0 controls but tab, line feed and carriage
 * return, DEL, C1 controls, the line and paragraph separators, and the
 * bidirectional embeddings, overrides and isolates (CVE-2021-42574).
 */
const isHidden = (c: number) =>
  (c < 0x20 && c !== 9 && c !== 10 && c !== 13) ||
  (c >= 0x7f && c <= 0x9f) ||
  c === 0x2028 ||
  c === 0x2029 ||
  (c >= 0x202a && c <= 0x202e) ||
  (c >= 0x2066 && c <= 0x2069);

/**
 * C0 controls and DEL show as their Control Pictures glyph (U+2400 and up, one
 * character each); the others show as `<U+XXXX>`.
 */
export function sanitize(text: string): string {
  let out = "";
  let from = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (!isHidden(c)) continue;
    out += text.slice(from, i);
    if (c < 0x20) out += String.fromCharCode(0x2400 + c);
    else if (c === 0x7f) out += String.fromCharCode(0x2421);
    else out += `<U+${c.toString(16).toUpperCase().padStart(4, "0")}>`;
    from = i + 1;
  }
  return from === 0 ? text : out + text.slice(from);
}

export interface Lines {
  lines: string[];
  /** The text had more lines than `max`. */
  more: boolean;
}

/** Splits on LF, CRLF and CR, stopping after `max` lines. */
export function splitLines(text: string, max = MAX_LINES): Lines {
  const lines: string[] = [];
  let at = 0;
  const n = text.length;
  while (at <= n) {
    if (lines.length === max) return { lines, more: at < n };
    let end = at;
    while (end < n) {
      const c = text.charCodeAt(end);
      if (c === 10 || c === 13) break;
      end++;
    }
    lines.push(text.slice(at, end));
    if (end >= n) break;
    at = end + (text.charCodeAt(end) === 13 && text.charCodeAt(end + 1) === 10 ? 2 : 1);
  }
  return { lines, more: false };
}

/** `s` cut to `max` characters (not through a surrogate pair), with an ellipsis, or itself. */
export function clip(s: string, max = MAX_LINE): string {
  if (s.length <= max) return s;
  let end = max;
  const last = s.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end--;
  return `${s.slice(0, end)}…`;
}
