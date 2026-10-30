import { describe, expect, it } from "vitest";

import { clip, decodeText, MAX_LINE, sanitize, splitLines } from "./decode.js";

const bytes = (...parts: (string | number[])[]) =>
  Uint8Array.from(parts.flatMap((p) => (typeof p === "string" ? [...new TextEncoder().encode(p)] : p)));
const ch = (code: number) => String.fromCharCode(code);

/** UTF-16 of `s` with a byte-order mark. */
function utf16(s: string, order: "le" | "be"): Uint8Array {
  const out = [order === "le" ? 0xff : 0xfe, order === "le" ? 0xfe : 0xff];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out.push(...(order === "le" ? [c & 0xff, c >> 8] : [c >> 8, c & 0xff]));
  }
  return Uint8Array.from(out);
}

describe("decodeText", () => {
  it("reads UTF-8, with or without a byte-order mark", () => {
    expect(decodeText(bytes("naïve café ✓"))).toEqual({ text: "naïve café ✓", encoding: "utf-8" });
    expect(decodeText(bytes([0xef, 0xbb, 0xbf], "hello"))?.text).toBe("hello");
  });

  it("reads UTF-16 by its mark, in both byte orders, astral characters included", () => {
    const s = "Zażółć 😀 ok";
    expect(decodeText(utf16(s, "le"))).toEqual({ text: s, encoding: "utf-16le" });
    expect(decodeText(utf16(s, "be"))).toEqual({ text: s, encoding: "utf-16be" });
  });

  it("falls back to windows-1252 for bytes that are not UTF-8", () => {
    // 0xE9 alone is not UTF-8; 0x80 is the euro sign in windows-1252.
    expect(decodeText(bytes("caf", [0xe9], " ", [0x80]))).toEqual({ text: "café €", encoding: "windows-1252" });
  });

  it("does not take a character cut by the end of a partial read for an error", () => {
    const whole = bytes("é"); // 0xC3 0xA9
    expect(decodeText(whole.subarray(0, 1), true)?.encoding).toBe("utf-8");
    expect(decodeText(bytes("ab", [0xc3]), true)).toEqual({ text: "ab", encoding: "utf-8" });
    // Not partial: the same bytes are not UTF-8.
    expect(decodeText(bytes("ab", [0xc3]))?.encoding).toBe("windows-1252");
  });

  it("refuses a file with a NUL in its head, and UTF-32", () => {
    expect(decodeText(bytes("text", [0], "more"))).toBeNull();
    // One NUL among many characters, too few for the control-character ratio to catch.
    expect(decodeText(bytes("ordinary words ".repeat(200), [0], "and more words"))).toBeNull();
    expect(decodeText(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]))).toBeNull();
    expect(decodeText(Uint8Array.from([0xff, 0xfe, 0, 0, 0x41, 0, 0, 0]))).toBeNull();
    expect(decodeText(Uint8Array.from([0, 0, 0xfe, 0xff, 0, 0, 0, 0x41]))).toBeNull();
    // UTF-16 without a mark is all NULs for ASCII: not guessed.
    expect(decodeText(Uint8Array.from([0x68, 0, 0x69, 0]))).toBeNull();
  });

  it("refuses bytes that are mostly control characters even with no NUL", () => {
    const noise = Uint8Array.from({ length: 1000 }, (_, i) => 1 + (i % 7));
    expect(decodeText(noise)).toBeNull();
    // A few stray controls in a text are still a text.
    expect(decodeText(bytes("a log line\u001b[0m\n".repeat(50)))).not.toBeNull();
  });

  it("accepts an empty file", () => {
    expect(decodeText(new Uint8Array())).toEqual({ text: "", encoding: "utf-8" });
  });
});

describe("sanitize", () => {
  it("makes every bidirectional override, embedding and isolate visible", () => {
    const hidden = [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069];
    const text = `if (admin ${hidden.map(ch).join("")}) { // end`;
    const out = sanitize(text);
    for (const c of hidden) {
      expect(out.includes(ch(c)), c.toString(16)).toBe(false);
      expect(out).toContain(`<U+${c.toString(16).toUpperCase()}>`);
    }
    // The text around them is as it was.
    expect(out.startsWith("if (admin ")).toBe(true);
    expect(out.endsWith(") { // end")).toBe(true);
  });

  it("shows C0 controls and DEL as their Control Pictures, and C1 and separators as code points", () => {
    expect(sanitize("a\u0001b")).toBe(`a${ch(0x2401)}b`);
    expect(sanitize("a\u0000b")).toBe(`a${ch(0x2400)}b`);
    expect(sanitize(`a${ch(0x7f)}b`)).toBe(`a${ch(0x2421)}b`);
    expect(sanitize(`a${ch(0x85)}b`)).toBe("a<U+0085>b");
    expect(sanitize(`a${ch(0x2028)}b${ch(0x2029)}c`)).toBe("a<U+2028>b<U+2029>c");
  });

  it("leaves tabs, line breaks and ordinary text, right-to-left included, alone", () => {
    const text = "a\tb\r\nc\nd שלום مرحبا 日本語 😀";
    expect(sanitize(text)).toBe(text);
  });
});

describe("splitLines", () => {
  it("splits on LF, CRLF and CR", () => {
    expect(splitLines("a\nb\r\nc\rd").lines).toEqual(["a", "b", "c", "d"]);
    expect(splitLines("a\n\nb").lines).toEqual(["a", "", "b"]);
    expect(splitLines("").lines).toEqual([""]);
    expect(splitLines("a\n").lines).toEqual(["a", ""]);
  });

  it("stops at the cap and says there was more", () => {
    const text = Array.from({ length: 10 }, (_, i) => `l${i}`).join("\n");
    expect(splitLines(text, 4)).toEqual({ lines: ["l0", "l1", "l2", "l3"], more: true });
    expect(splitLines(text, 10).more).toBe(false);
    expect(splitLines(text, 10).lines).toHaveLength(10);
    // The newline that ends the text does not start a line.
    expect(splitLines("a\nb\n", 2)).toEqual({ lines: ["a", "b"], more: false });
    expect(splitLines("a\nb\nc", 2)).toEqual({ lines: ["a", "b"], more: true });
  });

  it("handles a million newlines in linear time", () => {
    const t = performance.now();
    const r = splitLines("\n".repeat(1_000_000), 50_000);
    expect(r.lines).toHaveLength(50_000);
    expect(r.more).toBe(true);
    expect(performance.now() - t).toBeLessThan(1000);
  });
});

describe("clip", () => {
  it("leaves a line that fits and cuts one that does not, with an ellipsis", () => {
    expect(clip("abc", 3)).toBe("abc");
    expect(clip("abcd", 3)).toBe("abc…");
    expect(clip("x".repeat(MAX_LINE + 1)).length).toBe(MAX_LINE + 1);
  });

  it("does not cut a surrogate pair in two", () => {
    const s = "ab😀cd";
    expect(clip(s, 3)).toBe("ab…");
    expect(clip(s, 4)).toBe("ab😀…");
  });
});
