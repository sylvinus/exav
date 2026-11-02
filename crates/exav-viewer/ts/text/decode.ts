/**
 * Bytes to text that is safe to show: the encoding is read off the bytes, a
 * file that is not text is refused, and what could make the text lie about
 * itself (control characters, bidirectional overrides) is made visible.
 */

/** Bytes of a file that are read. */
export const MAX_BYTES = 2 * 1024 * 1024;
/** Lines shown. */
export const MAX_LINES = 50_000;
/** Characters shown of one line. */
export const MAX_LINE = 10_000;

/** How much of the head the binary check looks at. */
const SNIFF = 64 * 1024;

export interface Decoded {
  text: string;
  encoding: "utf-8" | "utf-16le" | "utf-16be" | "windows-1252";
}

/** One decode, `null` when the bytes are not valid in that encoding. */
function strict(bytes: Uint8Array, encoding: string, partial: boolean): string | null {
  try {
    // `stream`: a character cut in half by the end of the bytes is held back, not an error.
    return new TextDecoder(encoding, { fatal: true }).decode(bytes, { stream: partial });
  } catch {
    return null;
  }
}

/**
 * The text of `bytes`, or `null` when they are not text. `partial`: the bytes
 * are the start of a longer file.
 *
 * A byte-order mark settles the encoding (UTF-32 is refused). Otherwise a NUL
 * in the head means binary, then UTF-8 if the bytes are valid in it, else
 * windows-1252, which cannot fail and so comes last. A head where control
 * characters or replacement characters are one in ten is binary too.
 */
export function decodeText(bytes: Uint8Array, partial = false): Decoded | null {
  const [a = 0, b = 0, c = 0, d = 0] = bytes;
  if ((a === 0xff && b === 0xfe && c === 0 && d === 0) || (a === 0 && b === 0 && c === 0xfe && d === 0xff)) return null;
  let text: string | null;
  let encoding: Decoded["encoding"];
  if (a === 0xff && b === 0xfe) {
    encoding = "utf-16le";
    text = new TextDecoder(encoding).decode(bytes, { stream: partial });
  } else if (a === 0xfe && b === 0xff) {
    encoding = "utf-16be";
    text = new TextDecoder(encoding).decode(bytes, { stream: partial });
  } else {
    const head = Math.min(bytes.length, SNIFF);
    for (let i = 0; i < head; i++) if (bytes[i] === 0) return null;
    text = strict(bytes, "utf-8", partial);
    encoding = "utf-8";
    if (text === null) {
      text = new TextDecoder("windows-1252").decode(bytes);
      encoding = "windows-1252";
    }
  }
  return looksBinary(text.slice(0, SNIFF)) ? null : { text, encoding };
}

/** C0 controls but tab, line feed and carriage return, DEL, C1 controls, and U+FFFD. */
const isOdd = (c: number) => (c < 0x20 && c !== 9 && c !== 10 && c !== 13) || (c >= 0x7f && c <= 0x9f) || c === 0xfffd;

function looksBinary(sample: string): boolean {
  let odd = 0;
  for (let i = 0; i < sample.length; i++) if (isOdd(sample.charCodeAt(i))) odd++;
  return odd * 10 > sample.length;
}

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
